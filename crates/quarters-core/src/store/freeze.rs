//! Cooperative freeze policy for stable-identity spaces.

use super::{Store, epoch_millis, read_private_file, sync_directory, write_private_file};
use crate::store_policy::validate_private_file;
use crate::{ErrorKind, QuartersError, Result, Space, SpaceId, SpaceName};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const FREEZE_SCHEMA_VERSION: u32 = 1;
const FREEZE_PREFIX: &str = ".freeze-";
const FREEZE_SUFFIX: &str = ".json";
const MAX_FREEZE_MARKER_BYTES: usize = 4 * 1_024;

/// Observable cooperative freeze state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeState {
    /// The legacy space has no stable identity for an identity-bound marker.
    UnsupportedLegacy,
    /// New managed process/agent launches and space lifecycle mutations are permitted.
    Unfrozen,
    /// New managed process/agent launches and space lifecycle mutations are refused.
    Frozen,
}

impl FreezeState {
    /// Stable lowercase representation used in human and machine output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedLegacy => "unsupported_legacy",
            Self::Unfrozen => "unfrozen",
            Self::Frozen => "frozen",
        }
    }
}

/// Result of changing one cooperative freeze marker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FreezeReport {
    /// Space display name at the time of the operation.
    pub name: String,
    /// Stable identity bound to the marker.
    pub space_id: String,
    /// Resulting cooperative policy state.
    pub state: FreezeState,
    /// Whether persistent marker state changed.
    pub changed: bool,
    /// Exact behavior Quarters enforces.
    pub scope: &'static str,
    /// Authority that remains outside this feature.
    pub boundary: &'static str,
}

#[derive(Deserialize)]
struct FreezeHeader {
    schema_version: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FreezeMarker {
    schema_version: u32,
    space_id: SpaceId,
    created_unix_ms: u128,
    writer_version: String,
}

impl Store {
    /// Persist a cooperative freeze marker without stopping existing activity.
    ///
    /// # Errors
    ///
    /// Returns an error for legacy identity, unsafe marker state or failed durability.
    pub fn freeze(&self, name: &SpaceName) -> Result<FreezeReport> {
        let management = self.begin_mutation()?;
        let space = self.open(name)?;
        let id = require_stable_id(&space)?;
        let spaces = management.layout().spaces_root();
        let path = freeze_path(spaces, id);
        if read_marker(&path, id)?.is_some() {
            sync_freeze_directory(spaces, name, true)?;
            return report(&space, FreezeState::Frozen, false);
        }
        let marker = FreezeMarker {
            schema_version: FREEZE_SCHEMA_VERSION,
            space_id: id.clone(),
            created_unix_ms: epoch_millis()?,
            writer_version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        write_marker(&path, &marker)?;
        read_marker(&path, id)?
            .ok_or_else(|| QuartersError::new(ErrorKind::System, "the freeze marker disappeared after publication"))?;
        sync_freeze_directory(spaces, name, true)?;
        report(&space, FreezeState::Frozen, true)
    }

    /// Remove one valid cooperative freeze marker.
    ///
    /// # Errors
    ///
    /// Returns an error for legacy identity, unsafe marker state or failed durability.
    pub fn unfreeze(&self, name: &SpaceName) -> Result<FreezeReport> {
        let management = self.begin_mutation()?;
        let space = self.open(name)?;
        let id = require_stable_id(&space)?;
        let spaces = management.layout().spaces_root();
        let path = freeze_path(spaces, id);
        cleanup_marker_temporary(&path.with_extension("tmp"))?;
        let changed = match read_marker(&path, id) {
            Ok(None) => false,
            Ok(Some(_marker)) => {
                remove_marker(&path)?;
                true
            }
            Err(parse_error) => {
                remove_invalid_confirmed_marker(&path, parse_error)?;
                true
            }
        };
        sync_freeze_directory(spaces, name, false)?;
        report(&space, FreezeState::Unfrozen, changed)
    }

    /// Inspect a space's identity-bound cooperative freeze marker.
    ///
    /// # Errors
    ///
    /// Returns an error when existing marker state is unsafe or unsupported.
    pub fn freeze_state(&self, space: &Space) -> Result<FreezeState> {
        let Some(id) = space.id() else {
            return Ok(FreezeState::UnsupportedLegacy);
        };
        let spaces = self.layout()?.spaces_root().to_path_buf();
        Ok(if read_marker(&freeze_path(&spaces, id), id)?.is_some() {
            FreezeState::Frozen
        } else {
            FreezeState::Unfrozen
        })
    }

    pub(crate) fn ensure_not_frozen(&self, space: &Space) -> Result<()> {
        if self.freeze_state(space)? != FreezeState::Frozen {
            return Ok(());
        }
        let name = &space.manifest().name;
        Err(QuartersError::new(
            ErrorKind::SpaceActive,
            format!("space '{name}' is cooperatively frozen"),
        )
        .with_hint(format!(
            "run 'quarters unfreeze {name} --confirm {name}' before starting or mutating it"
        )))
    }
}

fn require_stable_id(space: &Space) -> Result<&SpaceId> {
    space.id().ok_or_else(|| {
        let name = &space.manifest().name;
        QuartersError::new(
            ErrorKind::Unsupported,
            "cooperative freeze requires a stable space identity",
        )
        .with_hint(format!("run 'quarters upgrade {name} --preview' first"))
    })
}

fn freeze_path(spaces: &Path, id: &SpaceId) -> PathBuf {
    spaces.join(format!("{FREEZE_PREFIX}{id}{FREEZE_SUFFIX}"))
}

fn read_marker(path: &Path, expected: &SpaceId) -> Result<Option<FreezeMarker>> {
    match fs::symlink_metadata(path) {
        Ok(_metadata) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(QuartersError::io("inspect cooperative freeze marker", path, error)),
    }
    let bytes = match read_private_file(path) {
        Ok(bytes) => bytes,
        Err(_error) if path_is_missing(path) => return Ok(None),
        Err(error) => return Err(actionable_marker_error(path, error)),
    };
    if bytes.len() > MAX_FREEZE_MARKER_BYTES {
        return Err(actionable_marker_error(
            path,
            QuartersError::new(
                ErrorKind::ResourceLimit,
                "the cooperative freeze marker exceeds 4096 bytes",
            ),
        ));
    }
    let header: FreezeHeader = serde_json::from_slice(&bytes).map_err(|error| {
        actionable_marker_error(
            path,
            QuartersError::new(
                ErrorKind::CorruptState,
                "the cooperative freeze marker header is invalid",
            )
            .with_source(error),
        )
    })?;
    if header.schema_version > FREEZE_SCHEMA_VERSION {
        return Err(QuartersError::new(
            ErrorKind::Unsupported,
            format!(
                "the cooperative freeze schema {} is newer than this Quarters build supports",
                header.schema_version
            ),
        )
        .with_hint(format!(
            "upgrade Quarters to preserve newer policy state, or explicitly clear it with 'quarters unfreeze NAME --confirm NAME'; marker: {}",
            path.display()
        )));
    }
    let marker: FreezeMarker = serde_json::from_slice(&bytes).map_err(|error| {
        actionable_marker_error(
            path,
            QuartersError::new(ErrorKind::CorruptState, "the cooperative freeze marker is invalid").with_source(error),
        )
    })?;
    validate_marker(&marker, expected).map_err(|error| actionable_marker_error(path, error))?;
    Ok(Some(marker))
}

fn validate_marker(marker: &FreezeMarker, expected: &SpaceId) -> Result<()> {
    let version_is_safe = !marker.writer_version.is_empty()
        && marker.writer_version.len() <= 64
        && marker
            .writer_version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'));
    if marker.schema_version == FREEZE_SCHEMA_VERSION
        && marker.space_id == *expected
        && u64::try_from(marker.created_unix_ms).is_ok()
        && version_is_safe
    {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "the cooperative freeze marker fields are inconsistent",
    ))
}

fn write_marker(path: &Path, marker: &FreezeMarker) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(marker).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not serialize cooperative freeze state").with_source(error)
    })?;
    bytes.push(b'\n');
    let temporary = path.with_extension("tmp");
    cleanup_marker_temporary(&temporary)?;
    write_private_file(&temporary, &bytes)?;
    fs::rename(&temporary, path)
        .map_err(|error| QuartersError::io("publish cooperative freeze marker", &temporary, error))?;
    sync_directory(
        path.parent()
            .ok_or_else(|| QuartersError::new(ErrorKind::System, "the cooperative freeze marker has no parent"))?,
    )
}

fn cleanup_marker_temporary(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(QuartersError::io("inspect freeze marker temporary file", path, error)),
    };
    validate_private_file(path, &metadata).map_err(|error| {
        error.with_hint(format!(
            "inspect and remove only the exact unsafe freeze temporary {}; then retry",
            path.display()
        ))
    })?;
    fs::remove_file(path).map_err(|error| QuartersError::io("remove freeze marker temporary file", path, error))
}

fn remove_marker(path: &Path) -> Result<()> {
    fs::remove_file(path).map_err(|error| QuartersError::io("remove cooperative freeze marker", path, error))
}

fn remove_invalid_confirmed_marker(path: &Path, parse_error: QuartersError) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect invalid cooperative freeze marker", path, error))?;
    validate_private_file(path, &metadata).map_err(|validation| {
        parse_error.with_hint(format!(
            "refusing to remove unsafe marker {}; inspect it without following links: {}",
            path.display(),
            validation.message()
        ))
    })?;
    remove_marker(path)
}

fn path_is_missing(path: &Path) -> bool {
    fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn actionable_marker_error(path: &Path, error: QuartersError) -> QuartersError {
    error.with_hint(format!(
        "inspect {}; remove only this identity-bound marker with 'quarters unfreeze NAME --confirm NAME'",
        path.display()
    ))
}

fn sync_freeze_directory(spaces: &Path, name: &SpaceName, frozen: bool) -> Result<()> {
    sync_directory(spaces).map_err(|error| {
        let visibility = if frozen {
            "has a visible freeze marker"
        } else {
            "has no visible freeze marker"
        };
        error.with_hint(format!(
            "space '{name}' {visibility}, but its directory durability is uncertain; inspect status before retrying"
        ))
    })
}

fn report(space: &Space, state: FreezeState, changed: bool) -> Result<FreezeReport> {
    let id = require_stable_id(space)?;
    Ok(FreezeReport {
        name: space.manifest().name.as_str().to_owned(),
        space_id: id.as_str().to_owned(),
        state,
        changed,
        scope: "blocks new managed process/agent launches and space lifecycle mutation; existing activity continues",
        boundary: "same-UID processes can alter files or the marker; this is not immutability, confinement or encryption",
    })
}

#[cfg(test)]
mod tests {
    use super::{FreezeState, freeze_path};
    use crate::{ErrorKind, SpaceName, Store};
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn fixture() -> TestResult<(tempfile::TempDir, Store, SpaceName)> {
        let temporary = tempfile::tempdir()?;
        let store = Store::new(temporary.path().join("store"))?;
        let name = SpaceName::parse("studio")?;
        store.create(name.clone(), PathBuf::from("/bin/sh"))?;
        Ok((temporary, store, name))
    }

    fn error_kind<T>(result: crate::Result<T>, context: &'static str) -> TestResult<ErrorKind> {
        match result {
            Ok(_value) => Err(context.into()),
            Err(error) => Ok(error.kind()),
        }
    }

    #[test]
    fn freeze_succeeds_during_existing_activity_and_blocks_only_new_managed_leases() -> TestResult {
        let (_temporary, store, name) = fixture()?;
        let space = store.open(&name)?;
        let existing = store.lease(&space)?;

        assert!(store.freeze(&name)?.changed);
        assert_eq!(store.freeze_state(&space)?, FreezeState::Frozen);
        assert_eq!(
            error_kind(store.lease(&space), "new lease succeeded while frozen")?,
            ErrorKind::SpaceActive
        );
        assert!(store.maintenance_lease(&space).is_ok());

        assert!(store.unfreeze(&name)?.changed);
        drop(existing);
        assert!(store.lease(&space).is_ok());
        Ok(())
    }

    #[test]
    fn hostile_marker_shapes_fail_closed() -> TestResult {
        let (temporary, store, name) = fixture()?;
        let space = store.open(&name)?;
        store.freeze(&name)?;
        let marker = freeze_path(
            store.layout()?.spaces_root(),
            space.id().ok_or("space has no stable id")?,
        );
        let extra = temporary.path().join("extra-link");
        fs::hard_link(&marker, &extra)?;
        assert_eq!(
            error_kind(store.freeze_state(&space), "linked marker was accepted")?,
            ErrorKind::CorruptState
        );
        fs::remove_file(&extra)?;

        fs::set_permissions(&marker, fs::Permissions::from_mode(0o644))?;
        assert_eq!(
            error_kind(store.freeze_state(&space), "broad marker mode was accepted")?,
            ErrorKind::CorruptState
        );
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))?;

        let mut unknown = fs::read_to_string(&marker)?;
        let close = unknown.rfind('}').ok_or("marker object has no close")?;
        unknown.insert_str(close, ",\n  \"unexpected\": true\n");
        fs::remove_file(&marker)?;
        fs::write(&marker, unknown)?;
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            error_kind(store.freeze_state(&space), "unknown marker field was accepted")?,
            ErrorKind::CorruptState
        );
        fs::remove_file(&marker)?;
        store.freeze(&name)?;
        store.unfreeze(&name)?;

        let target = temporary.path().join("target");
        fs::write(&target, b"{}\n")?;
        symlink(&target, &marker)?;
        assert_eq!(
            error_kind(store.freeze_state(&space), "symlink marker was accepted")?,
            ErrorKind::CorruptState
        );
        fs::remove_file(&marker)?;

        fs::write(&marker, vec![b'x'; 4_097])?;
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))?;
        let oversized = match store.freeze_state(&space) {
            Ok(_state) => return Err("oversized marker was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(oversized.kind(), ErrorKind::ResourceLimit);
        assert!(
            oversized
                .hint()
                .is_some_and(|hint| hint.contains(&marker.to_string_lossy().to_string()))
        );
        fs::remove_file(&marker)?;

        fs::write(&marker, b"{\"schema_version\":2}\n")?;
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))?;
        let newer = match store.freeze_state(&space) {
            Ok(_state) => return Err("newer marker was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(newer.kind(), ErrorKind::Unsupported);
        assert!(
            newer
                .hint()
                .is_some_and(|hint| hint.contains("unfreeze NAME --confirm NAME"))
        );
        Ok(())
    }

    #[test]
    fn interrupted_publication_is_retryable_and_invalid_final_is_removable() -> TestResult {
        let (_temporary, store, name) = fixture()?;
        let space = store.open(&name)?;
        let marker = freeze_path(
            store.layout()?.spaces_root(),
            space.id().ok_or("space has no stable id")?,
        );
        let temporary = marker.with_extension("tmp");
        fs::write(&temporary, b"")?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;

        let summary = store.recovery_summary()?;
        assert_eq!(summary.freeze_marker_temps, 1);
        assert_eq!(summary.unknown_entries_at_least, 0);
        let recovered = store.recover()?;
        assert_eq!(recovered.freeze_marker_temps, 1);
        assert!(!temporary.exists());

        fs::write(&temporary, b"")?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;

        assert!(store.freeze(&name)?.changed);
        assert!(!temporary.exists());
        assert_eq!(store.freeze_state(&space)?, FreezeState::Frozen);

        fs::write(&marker, b"")?;
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))?;
        assert!(store.unfreeze(&name)?.changed);
        assert_eq!(store.freeze_state(&space)?, FreezeState::Unfrozen);
        assert!(store.lease(&space).is_ok());
        Ok(())
    }

    #[test]
    fn unsafe_temporary_blocks_unfreeze_before_the_final_marker_is_removed() -> TestResult {
        let (temporary, store, name) = fixture()?;
        let space = store.open(&name)?;
        store.freeze(&name)?;
        let marker = freeze_path(
            store.layout()?.spaces_root(),
            space.id().ok_or("space has no stable id")?,
        );
        let marker_temporary = marker.with_extension("tmp");
        let target = temporary.path().join("target");
        fs::write(&target, b"preserve")?;
        symlink(&target, &marker_temporary)?;

        assert_eq!(
            error_kind(store.unfreeze(&name), "unsafe temporary was ignored")?,
            ErrorKind::CorruptState
        );
        assert_eq!(store.freeze_state(&space)?, FreezeState::Frozen);
        assert_eq!(fs::read(&target)?, b"preserve");
        fs::remove_file(&marker_temporary)?;
        assert!(store.unfreeze(&name)?.changed);
        Ok(())
    }
}
