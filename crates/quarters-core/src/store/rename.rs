//! Recoverable stable-identity space rename transaction.

use super::artifact::SourceIdentity;
use super::create::replace_manifest;
use super::scan::ScanBudget;
use super::{Store, entry_exists, read_private_file, sync_directory, write_private_file};
use crate::store_lock::acquire_lifecycle_lease;
use crate::store_policy::validate_private_file;
use crate::{ErrorKind, QuartersError, Result, Space, SpaceId, SpaceName};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const RENAME_SCHEMA_VERSION: u32 = 1;
const RENAME_PREFIX: &str = ".rename-";
const RENAME_SUFFIX: &str = ".json";
const MAX_RENAMES: usize = 128;

/// Preview or result of changing one stable-identity space display name.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SpaceRenameReport {
    /// Previous display name.
    pub previous: String,
    /// New display name.
    pub name: String,
    /// Stable identity retained across the rename.
    pub space_id: String,
    /// Whether the transaction executed.
    pub changed: bool,
    /// Activity evidence used before mutation.
    pub activity: &'static str,
    /// Authority boundary unaffected by rename.
    pub boundary: &'static str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RenameMarker {
    schema_version: u32,
    transaction_id: SpaceId,
    previous: SpaceName,
    name: SpaceName,
    source_identity: SourceIdentity,
}

#[derive(Default)]
struct RenameScan {
    marker_count: usize,
    issues: usize,
}

pub(crate) struct RenameRecovery {
    pub(crate) recovered: usize,
    pub(crate) issues: usize,
}

impl Store {
    /// Validate an inactive stable-identity rename without changing state.
    ///
    /// # Errors
    ///
    /// Returns an error for legacy identity, collisions, activity or recovery state.
    pub fn rename_plan(&self, previous: &SpaceName, name: &SpaceName) -> Result<SpaceRenameReport> {
        validate_distinct_names(previous, name)?;
        self.ensure_no_rename_target(previous)?;
        self.ensure_no_rename_target(name)?;
        self.ensure_no_rollback_target(previous)?;
        self.ensure_no_rollback_target(name)?;
        let source = self.open(previous)?;
        self.ensure_not_frozen(&source)?;
        reject_legacy(&source)?;
        reject_legacy_artifact_bindings(self, &source)?;
        reject_destination(self.layout()?.spaces_root(), name)?;
        let _lease = acquire_lifecycle_lease(&source, previous.as_str())?;
        rename_report(&source, previous, name, false)
    }

    /// Rename one inactive stable-identity space through a durable marker.
    ///
    /// # Errors
    ///
    /// Returns an error without guessing when publication or recovery state is ambiguous.
    pub fn rename_space(&self, previous: &SpaceName, name: &SpaceName) -> Result<SpaceRenameReport> {
        self.ensure_layout()?;
        validate_distinct_names(previous, name)?;
        let management = self.begin_mutation()?;
        self.ensure_no_rename_target(previous)?;
        self.ensure_no_rename_target(name)?;
        self.ensure_no_rollback_target(previous)?;
        self.ensure_no_rollback_target(name)?;
        let source = self.open(previous)?;
        self.ensure_not_frozen(&source)?;
        reject_legacy(&source)?;
        reject_destination(management.layout().spaces_root(), name)?;
        let _lease = acquire_lifecycle_lease(&source, previous.as_str())?;
        reject_legacy_artifact_bindings(self, &source)?;
        crate::platform::migrate_existing_legacy_runtime(&source, &crate::HostEnvironment::capture())?;
        let marker = RenameMarker {
            schema_version: RENAME_SCHEMA_VERSION,
            transaction_id: SpaceId::generate()?,
            previous: previous.clone(),
            name: name.clone(),
            source_identity: source_identity(&source),
        };
        let spaces = management.layout().spaces_root().to_path_buf();
        let marker_path = marker_path(&spaces, &marker.transaction_id);
        write_marker(&marker_path, &marker)?;
        sync_directory(&spaces)?;
        let destination = spaces.join(name.as_str());
        if let Err(error) = fs::rename(source.root(), &destination) {
            let _cleanup = fs::remove_file(&marker_path);
            let _sync = sync_directory(&spaces);
            return Err(QuartersError::io("move space for rename", source.root(), error));
        }
        sync_directory(&spaces).map_err(|error| rename_recovery_error(error, &marker_path))?;
        complete_moved_rename(&destination, &marker).map_err(|error| rename_recovery_error(error, &marker_path))?;
        fs::remove_file(&marker_path)
            .map_err(|error| QuartersError::io("remove completed rename marker", &marker_path, error))?;
        sync_directory(&spaces)?;
        let renamed = self.open(name)?;
        rename_report(&renamed, previous, name, true)
    }

    pub(crate) fn ensure_no_rename_target(&self, name: &SpaceName) -> Result<()> {
        if rename_target_exists(self.layout()?.spaces_root(), name)? {
            return Err(QuartersError::new(
                ErrorKind::SpaceActive,
                format!("space '{name}' has an interrupted rename transaction"),
            )
            .with_hint("run 'quarters doctor', then 'quarters recover --confirm stale-state'"));
        }
        Ok(())
    }

    pub(crate) fn rename_recovery_count(&self) -> Result<usize> {
        Ok(rename_scan(self.layout()?.spaces_root())?.marker_count)
    }

    pub(crate) fn rename_recovery_issue_count(&self) -> Result<usize> {
        Ok(rename_scan(self.layout()?.spaces_root())?.issues)
    }

    pub(crate) fn recover_renames(&self) -> Result<RenameRecovery> {
        let management = self.begin_mutation()?;
        let spaces = management.layout().spaces_root().to_path_buf();
        let recovery = recover_rename_batch(&spaces)?;
        sync_directory(&spaces)?;
        Ok(recovery)
    }
}

fn reject_legacy_artifact_bindings(store: &Store, source: &Space) -> Result<()> {
    let bindings = store.legacy_artifact_bindings(source)?;
    if bindings == 0 {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        format!(
            "space '{}' has {bindings} artifact binding(s) captured before stable identity upgrade",
            source.manifest().name
        ),
    )
    .with_hint("retain the current name, or recreate and explicitly remove those legacy templates and snapshots before renaming"))
}

fn recover_one(spaces: &Path, marker_path: &Path, marker: &RenameMarker) -> Result<()> {
    let source_path = spaces.join(marker.previous.as_str());
    let destination = spaces.join(marker.name.as_str());
    let source_exists = entry_exists(&source_path)?;
    let destination_exists = entry_exists(&destination)?;
    match (source_exists, destination_exists) {
        (true, false) => {
            let source = Store::open_relocated_path(source_path, &marker.previous)?;
            validate_marker_identity(marker, &source)?;
        }
        (false, true) => {
            let moved = Store::open_relocated_path(destination.clone(), &marker.previous)
                .or_else(|_| Store::open_relocated_path(destination.clone(), &marker.name))?;
            validate_marker_identity(marker, &moved)?;
            if moved.manifest().name == marker.previous {
                cleanup_manifest_temporary(&destination)?;
                complete_moved_rename(&destination, marker)?;
            }
        }
        (true, true) | (false, false) => {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                format!(
                    "rename marker {} has ambiguous source and destination state",
                    marker_path.display()
                ),
            )
            .with_hint("retain both entries and the marker for manual inspection; Quarters will not guess"));
        }
    }
    fs::remove_file(marker_path)
        .map_err(|error| QuartersError::io("remove recovered rename marker", marker_path, error))
}

fn complete_moved_rename(destination: &Path, marker: &RenameMarker) -> Result<()> {
    let moved = Store::open_relocated_path(destination.to_path_buf(), &marker.previous)?;
    validate_marker_identity(marker, &moved)?;
    let mut manifest = moved.manifest().clone();
    manifest.name = marker.name.clone();
    replace_manifest(destination, &manifest, "rename")
}

fn cleanup_manifest_temporary(root: &Path) -> Result<()> {
    let path = root.join(".quarters-rename.tmp");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(QuartersError::io("inspect rename manifest temporary", &path, error)),
    };
    validate_private_file(&path, &metadata)?;
    fs::remove_file(&path).map_err(|error| QuartersError::io("remove rename manifest temporary", &path, error))
}

fn rename_scan(spaces: &Path) -> Result<RenameScan> {
    let entries = match fs::read_dir(spaces) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(RenameScan::default()),
        Err(error) => return Err(QuartersError::io("read rename recovery namespace", spaces, error)),
    };
    let mut scan = RenameScan::default();
    let mut work = ScanBudget::new("the spaces directory while inspecting rename recovery");
    for entry in entries {
        let entry = entry.map_err(|error| QuartersError::io("read rename recovery entry", spaces, error))?;
        work.observe()?;
        let Some(id) = parse_marker_name(&entry.file_name()) else {
            continue;
        };
        let Ok(bytes) = read_private_file(&entry.path()) else {
            scan.issues = scan.issues.saturating_add(1);
            continue;
        };
        let Ok(marker) = serde_json::from_slice::<RenameMarker>(&bytes) else {
            scan.issues = scan.issues.saturating_add(1);
            continue;
        };
        if validate_marker(&marker, &id).is_err() {
            scan.issues = scan.issues.saturating_add(1);
            continue;
        }
        scan.marker_count = scan.marker_count.saturating_add(1);
    }
    Ok(scan)
}

fn recover_rename_batch(spaces: &Path) -> Result<RenameRecovery> {
    let entries =
        fs::read_dir(spaces).map_err(|error| QuartersError::io("read rename recovery namespace", spaces, error))?;
    let mut recovery = RenameRecovery {
        recovered: 0,
        issues: 0,
    };
    let mut work = ScanBudget::new("the spaces directory while recovering renames");
    for entry in entries {
        let entry = entry.map_err(|error| QuartersError::io("read rename recovery entry", spaces, error))?;
        work.observe()?;
        let Some((path, marker)) = valid_marker_entry(&entry) else {
            continue;
        };
        if recovery.recovered >= MAX_RENAMES {
            continue;
        }
        if recover_one(spaces, &path, &marker).is_ok() {
            recovery.recovered = recovery.recovered.saturating_add(1);
        } else {
            recovery.issues = recovery.issues.saturating_add(1);
        }
    }
    Ok(recovery)
}

fn valid_marker_entry(entry: &fs::DirEntry) -> Option<(PathBuf, RenameMarker)> {
    let id = parse_marker_name(&entry.file_name())?;
    let path = entry.path();
    let bytes = read_private_file(&path).ok()?;
    let marker = serde_json::from_slice::<RenameMarker>(&bytes).ok()?;
    validate_marker(&marker, &id).ok()?;
    Some((path, marker))
}

fn rename_target_exists(spaces: &Path, name: &SpaceName) -> Result<bool> {
    let entries = match fs::read_dir(spaces) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(QuartersError::io("read rename recovery namespace", spaces, error)),
    };
    let mut work = ScanBudget::new("the spaces directory while matching rename targets");
    for entry in entries {
        let entry = entry.map_err(|error| QuartersError::io("read rename recovery entry", spaces, error))?;
        work.observe()?;
        let Some(id) = parse_marker_name(&entry.file_name()) else {
            continue;
        };
        let Ok(bytes) = read_private_file(&entry.path()) else {
            continue;
        };
        let Ok(marker) = serde_json::from_slice::<RenameMarker>(&bytes) else {
            continue;
        };
        if validate_marker(&marker, &id).is_ok() && (marker.previous == *name || marker.name == *name) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn write_marker(path: &Path, marker: &RenameMarker) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(marker).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not serialize rename state").with_source(error)
    })?;
    bytes.push(b'\n');
    write_private_file(path, &bytes)
}

fn parse_marker_name(name: &std::ffi::OsStr) -> Option<SpaceId> {
    let name = name.to_str()?;
    let value = name.strip_prefix(RENAME_PREFIX)?.strip_suffix(RENAME_SUFFIX)?;
    SpaceId::parse(value.to_owned()).ok()
}

fn validate_marker(marker: &RenameMarker, id: &SpaceId) -> Result<()> {
    if marker.schema_version == RENAME_SCHEMA_VERSION
        && marker.transaction_id == *id
        && marker.previous != marker.name
        && marker.source_identity.space_id.is_some()
    {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "rename marker fields are inconsistent",
    ))
}

fn validate_marker_identity(marker: &RenameMarker, space: &Space) -> Result<()> {
    if marker.source_identity.matches(space) {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "rename source identity changed after the transaction was prepared",
    ))
}

fn source_identity(space: &Space) -> SourceIdentity {
    SourceIdentity {
        schema_version: space.manifest().schema_version,
        name: space.manifest().name.clone(),
        created_unix_ms: space.manifest().created_unix_ms,
        space_id: space.id().cloned(),
    }
}

fn marker_path(spaces: &Path, id: &SpaceId) -> PathBuf {
    spaces.join(format!("{RENAME_PREFIX}{id}{RENAME_SUFFIX}"))
}

fn reject_destination(spaces: &Path, name: &SpaceName) -> Result<()> {
    if !entry_exists(&spaces.join(name.as_str()))? {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::AlreadyExists,
        format!("space '{name}' already exists"),
    ))
}

fn reject_legacy(space: &Space) -> Result<()> {
    if space.id().is_some() {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "legacy spaces must receive a stable identity before rename",
    )
    .with_hint(format!("run 'quarters upgrade {} --preview'", space.manifest().name)))
}

fn validate_distinct_names(previous: &SpaceName, name: &SpaceName) -> Result<()> {
    if previous != name {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::InvalidInput,
        "the new space name must differ from the current name",
    ))
}

fn rename_report(space: &Space, previous: &SpaceName, name: &SpaceName, changed: bool) -> Result<SpaceRenameReport> {
    let id = space
        .id()
        .ok_or_else(|| QuartersError::new(ErrorKind::Unsupported, "rename requires a stable space identity"))?;
    Ok(SpaceRenameReport {
        previous: previous.as_str().to_owned(),
        name: name.as_str().to_owned(),
        space_id: id.as_str().to_owned(),
        changed,
        activity: "cooperative lease was free; detached same-UID processes remain unknown",
        boundary: "display-name mutation does not change host-account authority or containment",
    })
}

fn rename_recovery_error(error: QuartersError, marker: &Path) -> QuartersError {
    error.with_hint(format!(
        "rename recovery state remains at {}; run 'quarters doctor', then confirmed recovery",
        marker.display()
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture() -> (tempfile::TempDir, Store, Space, SpaceName) {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        let source = store
            .create(
                SpaceName::parse("before").expect("source name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create source");
        let destination = SpaceName::parse("after").expect("destination name");
        (temporary, store, source, destination)
    }

    fn marker(source: &Space, destination: &SpaceName) -> RenameMarker {
        RenameMarker {
            schema_version: RENAME_SCHEMA_VERSION,
            transaction_id: SpaceId::generate().expect("transaction ID"),
            previous: source.manifest().name.clone(),
            name: destination.clone(),
            source_identity: source_identity(source),
        }
    }

    #[test]
    fn recovery_aborts_a_pre_move_rename() {
        let (_temporary, store, source, destination) = fixture();
        let marker = marker(&source, &destination);
        let path = marker_path(
            store.layout().expect("store layout").spaces_root(),
            &marker.transaction_id,
        );
        write_marker(&path, &marker).expect("write marker");
        assert_eq!(store.rename_recovery_count().expect("inspect markers"), 1);
        assert_eq!(store.recover_renames().expect("recover marker").recovered, 1);
        assert_eq!(store.rename_recovery_count().expect("inspect recovered"), 0);
        assert!(store.open(&marker.previous).is_ok());
        assert!(store.open(&destination).is_err());
    }

    #[test]
    fn interrupted_rename_blocks_only_its_source_and_destination_names() {
        let (_temporary, store, source, destination) = fixture();
        let marker = marker(&source, &destination);
        let path = marker_path(
            store.layout().expect("store layout").spaces_root(),
            &marker.transaction_id,
        );
        write_marker(&path, &marker).expect("write marker");
        let unrelated = SpaceName::parse("unrelated").expect("unrelated name");
        store
            .create(unrelated.clone(), PathBuf::from("/bin/sh"))
            .expect("create unrelated space");

        assert!(store.inspect_named(&marker.previous).is_err());
        assert!(store.create(destination.clone(), PathBuf::from("/bin/sh")).is_err());
        assert!(store.remove(marker.previous.as_str()).is_err());
        assert!(store.inspect_named(&unrelated).is_ok());
    }

    #[test]
    fn recovery_completes_a_moved_space_before_removing_its_marker() {
        let (_temporary, store, source, destination) = fixture();
        let marker = marker(&source, &destination);
        let path = marker_path(
            store.layout().expect("store layout").spaces_root(),
            &marker.transaction_id,
        );
        write_marker(&path, &marker).expect("write marker");
        fs::rename(
            source.root(),
            store.layout().expect("store layout").space_path(&destination),
        )
        .expect("move source");
        assert!(store.open(&destination).is_err());
        assert_eq!(store.recover_renames().expect("complete rename").recovered, 1);
        let renamed = store.open(&destination).expect("open renamed space");
        assert_eq!(renamed.id(), source.id());
        assert_eq!(renamed.manifest().name, destination);
        assert!(!path.exists());
    }

    #[test]
    fn malformed_marker_is_retained_without_blocking_unrelated_spaces() {
        let (_temporary, store, _source, _destination) = fixture();
        let unrelated = SpaceName::parse("unrelated").expect("unrelated name");
        store
            .create(unrelated.clone(), PathBuf::from("/bin/sh"))
            .expect("create unrelated space");
        let id = SpaceId::generate().expect("marker ID");
        let path = marker_path(store.layout().expect("store layout").spaces_root(), &id);
        write_private_file(&path, b"{not-json\n").expect("write malformed marker");

        store.inspect_named(&unrelated).expect("inspect unrelated space");
        let summary = store.recovery_summary().expect("inspect malformed marker");
        assert_eq!(summary.rename_transactions, 0);
        assert_eq!(summary.rename_issues, 1);
        assert_eq!(store.recover_renames().expect("retain malformed marker").recovered, 0);
        assert!(path.exists());
    }

    #[test]
    fn ambiguous_marker_does_not_block_an_unrelated_recovery() {
        let (_temporary, store, source, destination) = fixture();
        let ambiguous = marker(&source, &destination);
        let ambiguous_path = marker_path(
            store.layout().expect("store layout").spaces_root(),
            &ambiguous.transaction_id,
        );
        write_marker(&ambiguous_path, &ambiguous).expect("write ambiguous marker");
        crate::store::create_private_dir(&store.layout().expect("store layout").space_path(&destination))
            .expect("create colliding destination");

        let other_name = SpaceName::parse("other").expect("other name");
        let other = store
            .create(other_name, PathBuf::from("/bin/sh"))
            .expect("create other source");
        let final_name = SpaceName::parse("final").expect("final name");
        let actionable = marker(&other, &final_name);
        let actionable_path = marker_path(
            store.layout().expect("store layout").spaces_root(),
            &actionable.transaction_id,
        );
        write_marker(&actionable_path, &actionable).expect("write actionable marker");

        let recovery = store.recover_renames().expect("recover independent marker");
        assert_eq!(recovery.recovered, 1);
        assert_eq!(recovery.issues, 1);
        assert!(ambiguous_path.exists());
        assert!(!actionable_path.exists());
    }

    #[test]
    fn recovery_drains_valid_markers_in_bounded_batches() {
        let (_temporary, store, source, _destination) = fixture();
        for index in 0..=MAX_RENAMES {
            let destination = SpaceName::parse(format!("destination-{index}")).expect("destination name");
            let marker = marker(&source, &destination);
            let path = marker_path(
                store.layout().expect("store layout").spaces_root(),
                &marker.transaction_id,
            );
            write_marker(&path, &marker).expect("write marker");
        }
        assert_eq!(store.rename_recovery_count().expect("count every marker"), 129);
        assert!(store.inspect_named(&source.manifest().name).is_err());
        assert_eq!(store.recover_renames().expect("first recovery batch").recovered, 128);
        assert_eq!(store.rename_recovery_count().expect("count remainder"), 1);
        assert_eq!(store.recover_renames().expect("second recovery batch").recovered, 1);
        assert_eq!(store.rename_recovery_count().expect("recovery complete"), 0);
    }

    #[test]
    fn ambiguous_markers_cannot_starve_an_actionable_recovery() {
        let (_temporary, store, source, destination) = fixture();
        crate::store::create_private_dir(&store.layout().expect("store layout").space_path(&destination))
            .expect("create colliding destination");
        for _index in 0..MAX_RENAMES {
            let marker = marker(&source, &destination);
            let path = marker_path(
                store.layout().expect("store layout").spaces_root(),
                &marker.transaction_id,
            );
            write_marker(&path, &marker).expect("write ambiguous marker");
        }
        let other = store
            .create(
                SpaceName::parse("other-source").expect("other name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create actionable source");
        let actionable = marker(
            &other,
            &SpaceName::parse("other-destination").expect("actionable destination"),
        );
        let actionable_path = marker_path(
            store.layout().expect("store layout").spaces_root(),
            &actionable.transaction_id,
        );
        write_marker(&actionable_path, &actionable).expect("write actionable marker");

        let recovery = store.recover_renames().expect("scan beyond ambiguous markers");
        assert_eq!(recovery.recovered, 1);
        assert_eq!(recovery.issues, MAX_RENAMES);
        assert!(!actionable_path.exists());
    }
}
