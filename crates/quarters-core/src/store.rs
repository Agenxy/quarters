//! Atomic private storage for spaces.

pub(crate) mod artifact;
mod create;
mod host_fork;
mod layout;
pub(crate) mod lifecycle;
mod remove;
mod rename;
pub(crate) mod scan;
mod upgrade;

pub use host_fork::{HostForkFile, HostForkIneligible, HostForkMode, HostForkOptions, HostForkPolicy, HostForkReport};
pub(crate) use layout::StoreLayout;
pub use rename::SpaceRenameReport;
pub use upgrade::SpaceUpgradeReport;

use crate::store_lock::lock_shared_bounded;
use crate::store_policy::{validate_private_dir, validate_private_file, validate_stored_manifest};
use crate::{
    ErrorKind, LATEST_SCHEMA_VERSION, PROFILE_SCHEMA_VERSION, QuartersError, Result, SUPPORTED_SCHEMA_VERSIONS, Space,
    SpaceManifest, SpaceName,
};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MANIFEST_FILE: &str = ".quarters.json";
const MAX_MANIFEST_BYTES: u64 = 16 * 1_024;
pub(crate) const OBSERVATION_LOCK_FILE: &str = ".observe";
static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(serde::Deserialize)]
struct ManifestHeader {
    schema_version: u32,
}

/// Root storage manager.
#[derive(Clone, Debug)]
pub struct Store {
    pub(crate) root: PathBuf,
}

/// A held shared lease proving a space is in use.
#[derive(Debug)]
pub struct SpaceLease {
    _file: File,
}

/// Observable state of Quarters' cooperative activity lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseState {
    /// No Quarters supervisor or management transaction currently holds the lease.
    Free,
    /// A Quarters supervisor or management transaction currently holds the lease.
    Held,
    /// The backing filesystem could not report advisory-lock state.
    Unknown,
}

impl LeaseState {
    /// Stable lowercase representation used in machine output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Held => "held",
            Self::Unknown => "unknown",
        }
    }
}

/// One independently inspected entry in the spaces directory.
#[derive(Debug)]
pub enum SpaceInspection {
    /// The space and all control anchors passed validation.
    Healthy(Space),
    /// The entry exists but cannot safely be used as a space.
    Unhealthy {
        /// Directory-entry name, represented lossily only when it is not UTF-8.
        name: String,
        /// Whether the displayed name is a lossy stand-in for non-UTF-8 bytes.
        name_was_lossy: bool,
        /// Exact validation failure.
        error: QuartersError,
    },
}

impl SpaceInspection {
    /// Name used to sort and present this entry.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Healthy(space) => space.manifest().name.as_str(),
            Self::Unhealthy { name, .. } => name,
        }
    }
}

impl Store {
    /// Create a store rooted at an absolute path.
    ///
    /// # Errors
    ///
    /// Returns an error when `root` is not absolute.
    pub fn new(root: PathBuf) -> Result<Self> {
        if !root.is_absolute() {
            return Err(QuartersError::new(
                ErrorKind::InvalidInput,
                "the Quarters root must be an absolute path",
            ));
        }
        Ok(Self { root })
    }

    /// Resolve the root from `QUARTERS_ROOT` or the host home.
    ///
    /// # Errors
    ///
    /// Returns an error when neither an absolute override nor `HOME` can
    /// provide a usable root.
    pub fn from_environment() -> Result<Self> {
        if let Some(root) = std::env::var_os("QUARTERS_ROOT") {
            return Self::new(PathBuf::from(root));
        }
        let home = std::env::var_os("HOME").ok_or_else(|| {
            QuartersError::new(
                ErrorKind::InvalidInput,
                "HOME is unset, so the default Quarters root cannot be resolved",
            )
            .with_hint("set QUARTERS_ROOT to an absolute private directory")
        })?;
        Self::new(PathBuf::from(home).join(".quarters"))
    }

    /// Storage root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Open and validate a named space.
    ///
    /// # Errors
    ///
    /// Returns an error when the space is absent or its stored state is
    /// unreadable, malformed or inconsistent with its path.
    pub fn open(&self, name: &SpaceName) -> Result<Space> {
        match self.inspect_named(name)? {
            SpaceInspection::Healthy(space) => Ok(space),
            SpaceInspection::Unhealthy { error, .. } => Err(error),
        }
    }

    /// List all valid spaces in name order.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be read or any published
    /// space has invalid metadata.
    pub fn list(&self) -> Result<Vec<Space>> {
        self.inspect()?
            .into_iter()
            .map(|inspection| match inspection {
                SpaceInspection::Healthy(space) => Ok(space),
                SpaceInspection::Unhealthy { error, .. } => Err(error),
            })
            .collect()
    }

    /// Inspect every published entry without letting one unhealthy space hide
    /// healthy siblings.
    ///
    /// # Errors
    ///
    /// Returns an error when the store layout itself cannot be inspected.
    pub fn inspect(&self) -> Result<Vec<SpaceInspection>> {
        self.inspect_with_limit(None)
    }

    /// Inspect no more than `maximum` published entries.
    ///
    /// This is intended for bounded protocol and UI surfaces. It returns no
    /// partial result when the store is larger than the declared budget.
    ///
    /// # Errors
    ///
    /// Returns an error when the store layout cannot be inspected, `maximum`
    /// is zero, or more visible entries exist than the caller can safely hold.
    pub fn inspect_at_most(&self, maximum: usize) -> Result<Vec<SpaceInspection>> {
        if maximum == 0 {
            return Err(QuartersError::new(
                ErrorKind::InvalidInput,
                "the inspection entry limit must be greater than zero",
            ));
        }
        self.inspect_with_limit(Some(maximum))
    }

    fn inspect_with_limit(&self, maximum: Option<usize>) -> Result<Vec<SpaceInspection>> {
        let Some(spaces_root) = self.existing_spaces_root()? else {
            return Ok(Vec::new());
        };
        let entries =
            fs::read_dir(&spaces_root).map_err(|error| QuartersError::io("read spaces", &spaces_root, error))?;
        let mut inspections = Vec::new();
        let mut scan = scan::ScanBudget::new("the spaces directory");
        for entry in entries {
            let entry = entry.map_err(|error| QuartersError::io("read a space entry", &spaces_root, error))?;
            scan.observe()?;
            let file_name = entry.file_name();
            if file_name.to_string_lossy().starts_with('.') {
                continue;
            }
            if let Some(maximum) = maximum
                && inspections.len() >= maximum
            {
                return Err(QuartersError::new(
                    ErrorKind::ResourceLimit,
                    format!("the store contains more than {maximum} visible spaces"),
                )
                .with_hint("inspect one exact space by name, or use the human CLI outside an MCP transcript"));
            }
            inspections.push(Self::inspect_path(
                entry.path(),
                file_name.to_string_lossy().into_owned(),
                file_name.to_str().is_none(),
            ));
        }
        inspections.sort_by(|left, right| left.name().cmp(right.name()));
        Ok(inspections)
    }

    /// Inspect one named entry, preserving validation failures as report data.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is absent or the store layout itself
    /// cannot be inspected.
    pub fn inspect_named(&self, name: &SpaceName) -> Result<SpaceInspection> {
        self.ensure_no_rename_target(name)?;
        self.ensure_no_rollback_target(name)?;
        self.inspect_named_without_rollback(name)
    }

    pub(crate) fn inspect_named_without_rollback(&self, name: &SpaceName) -> Result<SpaceInspection> {
        let Some(spaces_root) = self.existing_spaces_root()? else {
            return Err(space_not_found(name.as_str()));
        };
        let path = spaces_root.join(name.as_str());
        match fs::symlink_metadata(&path) {
            Ok(_metadata) => Ok(Self::inspect_path(path, name.as_str().to_owned(), false)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(space_not_found(name.as_str())),
            Err(error) => Err(QuartersError::io("inspect space entry", &path, error)),
        }
    }

    /// Hold a shared activity lease until the returned guard is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error when the lock file cannot be opened or locked.
    pub fn lease(&self, space: &Space) -> Result<SpaceLease> {
        let _observation = self.management_guard()?;
        let file = open_private_lock(&space.lock_path())?;
        lock_shared_bounded(&file, &space.lock_path())?;
        Ok(SpaceLease { _file: file })
    }

    fn open_path(path: PathBuf) -> Result<Space> {
        let expected_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| QuartersError::new(ErrorKind::CorruptState, "space directory name is not valid UTF-8"))?
            .to_owned();
        Self::open_path_with_expected_name(path, &expected_name)
    }

    pub(crate) fn open_relocated_path(path: PathBuf, expected_name: &SpaceName) -> Result<Space> {
        Self::open_path_with_expected_name(path, expected_name.as_str())
    }

    fn open_path_with_expected_name(path: PathBuf, expected_name: &str) -> Result<Space> {
        validate_space_anchors(&path)?;
        let manifest = read_validated_manifest(&path, expected_name)?;
        Ok(Space::new(path, manifest))
    }

    pub(crate) fn identity_for_removal(&self, name: &SpaceName) -> Result<Option<Space>> {
        let Some(spaces_root) = self.existing_spaces_root()? else {
            return Ok(None);
        };
        let path = spaces_root.join(name.as_str());
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(QuartersError::io("inspect removal identity", &path, error)),
        }
        validate_removal_anchors(&path)?;
        let manifest = read_validated_manifest(&path, name.as_str())?;
        Ok(Some(Space::new(path, manifest)))
    }

    fn inspect_path(path: PathBuf, name: String, name_was_lossy: bool) -> SpaceInspection {
        match Self::open_path(path) {
            Ok(space) => SpaceInspection::Healthy(space),
            Err(error) => SpaceInspection::Unhealthy {
                name,
                name_was_lossy,
                error,
            },
        }
    }
}

fn read_validated_manifest(path: &Path, expected_name: &str) -> Result<SpaceManifest> {
    let manifest_path = path.join(MANIFEST_FILE);
    let bytes = read_private_file(&manifest_path)?;
    let header: ManifestHeader = serde_json::from_slice(&bytes).map_err(|error| {
        QuartersError::new(
            ErrorKind::CorruptState,
            format!("space manifest header is invalid at {}", manifest_path.display()),
        )
        .with_source(error)
    })?;
    if !SUPPORTED_SCHEMA_VERSIONS.contains(&header.schema_version) {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            format!(
                "space uses schema {}, but this build supports schemas {} through {}",
                header.schema_version, PROFILE_SCHEMA_VERSION, LATEST_SCHEMA_VERSION
            ),
        )
        .with_hint("upgrade Quarters before opening this space; do not delete or rewrite its manifest"));
    }
    let manifest: SpaceManifest = serde_json::from_slice(&bytes).map_err(|error| {
        QuartersError::new(
            ErrorKind::CorruptState,
            format!("space manifest is invalid at {}", manifest_path.display()),
        )
        .with_source(error)
    })?;
    validate_stored_manifest(&manifest)?;
    if expected_name != manifest.name.as_str() {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "space directory and manifest names differ",
        ));
    }
    Ok(manifest)
}

pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| QuartersError::io("create private file", path, error))?;
    file.write_all(bytes)
        .map_err(|error| QuartersError::io("write private file", path, error))?;
    file.sync_all()
        .map_err(|error| QuartersError::io("sync private file", path, error))
}

pub(crate) fn read_private_file(path: &Path) -> Result<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| missing_private_file(path, error))?;
    validate_private_file(path, &path_metadata)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|error| QuartersError::io("open private file", path, error))?;
    let file_metadata = file
        .metadata()
        .map_err(|error| QuartersError::io("inspect private file", path, error))?;
    validate_private_file(path, &file_metadata)?;
    if file_metadata.len() > MAX_MANIFEST_BYTES {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            format!(
                "private metadata file is larger than {MAX_MANIFEST_BYTES} bytes: {}",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| QuartersError::io("read private file", path, error))?;
    let maximum_size = usize::try_from(MAX_MANIFEST_BYTES).map_err(|error| {
        QuartersError::new(ErrorKind::System, "manifest size limit does not fit this platform").with_source(error)
    })?;
    if bytes.len() > maximum_size {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            format!(
                "private metadata file grew beyond {MAX_MANIFEST_BYTES} bytes: {}",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

pub(crate) fn open_private_lock(path: &Path) -> Result<File> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| missing_private_file(path, error))?;
    validate_private_file(path, &path_metadata)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|error| QuartersError::io("open activity lock", path, error))?;
    validate_private_file(
        path,
        &file
            .metadata()
            .map_err(|error| QuartersError::io("inspect activity lock", path, error))?,
    )?;
    Ok(file)
}

pub(crate) fn open_or_create_private_lock(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    match options.open(path) {
        Ok(file) => {
            let metadata = file
                .metadata()
                .map_err(|error| QuartersError::io("inspect created observation lock", path, error))?;
            validate_private_file(path, &metadata)?;
            Ok(file)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => open_private_lock(path),
        Err(error) => Err(QuartersError::io("create observation lock", path, error)),
    }
}

fn missing_private_file(path: &Path, error: std::io::Error) -> QuartersError {
    if error.kind() == std::io::ErrorKind::NotFound {
        return QuartersError::new(
            ErrorKind::CorruptState,
            format!("required private file is missing: {}", path.display()),
        )
        .with_hint("inspect the containing space before recreating any control file");
    }
    QuartersError::io("inspect private file", path, error)
}

fn validate_space_anchors(path: &Path) -> Result<()> {
    validate_removal_anchors(path)?;
    let home = path.join("home");
    let home_metadata =
        fs::symlink_metadata(&home).map_err(|error| QuartersError::io("inspect space home", &home, error))?;
    validate_private_dir(&home, &home_metadata)
}

fn validate_removal_anchors(path: &Path) -> Result<()> {
    let root_metadata =
        fs::symlink_metadata(path).map_err(|error| QuartersError::io("inspect space directory", path, error))?;
    validate_private_dir(path, &root_metadata)?;
    drop(open_private_lock(&path.join(".active"))?);
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => return validate_private_dir(path, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(QuartersError::io("inspect private directory", path, error)),
    }
    let mut builder = DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .map_err(|error| QuartersError::io("create private directory", path, error))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect created private directory", path, error))?;
    validate_private_dir(path, &metadata)
}

pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect directory before syncing", path, error))?;
    validate_private_dir(path, &metadata)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW);
    let directory = options
        .open(path)
        .map_err(|error| QuartersError::io("open directory for syncing", path, error))?;
    directory
        .sync_all()
        .map_err(|error| QuartersError::io("sync directory", path, error))
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        QuartersError::new(
            ErrorKind::InvalidInput,
            format!("path has no parent directory: {}", path.display()),
        )
    })?;
    sync_directory(parent)
}

pub(crate) fn entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_metadata) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(QuartersError::io("inspect path", path, error)),
    }
}

pub(crate) fn epoch_millis() -> Result<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|error| {
            QuartersError::new(ErrorKind::System, "system clock is before the Unix epoch").with_source(error)
        })
}

fn space_not_found(name: &str) -> QuartersError {
    QuartersError::new(ErrorKind::NotFound, format!("space '{name}' does not exist"))
        .with_hint("run 'quarters list' to see available spaces")
}

pub(crate) fn unique_suffix() -> Result<String> {
    let counter = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(format!("{}-{}-{counter}", std::process::id(), epoch_millis()?))
}

#[cfg(test)]
// Test assertions intentionally use `expect` to preserve failure context.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use fs4::FileExt;
    #[cfg(target_os = "linux")]
    use std::ffi::OsString;
    #[cfg(target_os = "linux")]
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn test_store() -> (TempDir, Store) {
        let temporary = TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        (temporary, store)
    }

    #[test]
    fn create_and_list_round_trip() {
        let (_temporary, store) = test_store();
        let name = SpaceName::parse("work").expect("valid name");
        let created = store.create(name, PathBuf::from("/bin/sh")).expect("create space");
        assert_eq!(created.manifest().name.as_str(), "work");
        assert_eq!(store.list().expect("list spaces").len(), 1);
        assert!(created.home().join(".gitconfig").is_file());
        let zshrc = fs::read_to_string(created.home().join(".zshrc")).expect("read zsh startup file");
        assert!(zshrc.contains("quarters shell-init zsh 2>/dev/null"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn non_utf8_entry_names_are_explicitly_lossy_and_unusable() {
        let (_temporary, store) = test_store();
        store.ensure_layout().expect("store layout");
        let name = OsString::from_vec(vec![b'b', 0xff, b'd']);
        fs::create_dir(store.root.join("spaces").join(name)).expect("rogue entry");
        let inspections = store.inspect().expect("inspect store");
        assert!(matches!(
            inspections.as_slice(),
            [SpaceInspection::Unhealthy {
                name_was_lossy: true,
                ..
            }]
        ));
    }

    #[test]
    fn bounded_inspection_returns_no_partial_result() {
        let (_temporary, store) = test_store();
        store.ensure_layout().expect("store layout");
        for index in 0..4 {
            fs::create_dir(store.root.join("spaces").join(format!("entry{index}"))).expect("rogue entry");
        }
        let error = store.inspect_at_most(3).expect_err("entry limit must fail");
        assert_eq!(error.kind(), ErrorKind::ResourceLimit);
    }

    #[test]
    fn bounded_inspection_separates_hidden_work_from_visible_results() {
        let (_temporary, store) = test_store();
        store.ensure_layout().expect("create layout");
        for name in [".ignored-one", ".ignored-two"] {
            fs::write(store.layout().spaces_root().join(name), b"").expect("create ignored entry");
        }

        let inspections = store.inspect_at_most(1).expect("hidden entries are not results");
        assert!(inspections.is_empty());
    }

    #[test]
    fn existing_empty_root_lists_no_spaces() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().to_path_buf()).expect("valid store");
        assert!(store.list().expect("empty listing").is_empty());
    }

    #[test]
    fn remove_requires_inactive_lease() {
        let (_temporary, store) = test_store();
        let name = SpaceName::parse("busy").expect("valid name");
        let space = store
            .create(name.clone(), PathBuf::from("/bin/sh"))
            .expect("create space");
        let lease = store.lease(&space).expect("lease space");
        assert_eq!(
            store
                .remove(name.as_str())
                .expect_err("active removal must fail")
                .kind(),
            ErrorKind::SpaceActive
        );
        drop(lease);
        store.remove(name.as_str()).expect("remove inactive space");
    }

    #[test]
    fn activity_probe_tracks_the_supervisor_lease() {
        let (_temporary, store) = test_store();
        let space = store
            .create(
                SpaceName::parse("observed").expect("valid name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create space");
        assert_eq!(store.lease_state(&space).expect("inspect free space"), LeaseState::Free);
        let lease = store.lease(&space).expect("lease space");
        assert_eq!(store.lease_state(&space).expect("inspect held space"), LeaseState::Held);
        drop(lease);
        assert_eq!(
            store.lease_state(&space).expect("inspect released space"),
            LeaseState::Free
        );
    }

    #[test]
    fn symlinked_space_home_is_rejected() {
        let (temporary, store) = test_store();
        let name = SpaceName::parse("redirected").expect("valid name");
        let space = store
            .create(name.clone(), PathBuf::from("/bin/sh"))
            .expect("create space");
        let real_home = temporary.path().join("real-home");
        fs::rename(space.home(), &real_home).expect("move home");
        symlink(&real_home, space.home()).expect("link home");

        let error = store.open(&name).expect_err("linked home must fail closed");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
        assert!(matches!(
            store.inspect_named(&name).expect("inspect unhealthy entry"),
            SpaceInspection::Unhealthy { .. }
        ));
        store.remove(name.as_str()).expect("remove entry with unhealthy home");
        assert!(real_home.exists());
    }

    #[test]
    fn symlinked_activity_lock_is_rejected() {
        let (_temporary, store) = test_store();
        let space = store
            .create(
                SpaceName::parse("linked-lock").expect("valid name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create space");
        let lock = space.lock_path();
        let real_lock = space.root().join("real-lock");
        fs::rename(&lock, &real_lock).expect("move lock");
        symlink(&real_lock, &lock).expect("link lock");

        let error = store
            .open(&SpaceName::parse("linked-lock").expect("valid name"))
            .expect_err("linked lock must fail closed");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
    }

    #[test]
    fn hard_linked_manifest_is_rejected() {
        let (_temporary, store) = test_store();
        let space = store
            .create(
                SpaceName::parse("linked-manifest").expect("valid name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create space");
        let manifest = space.root().join(MANIFEST_FILE);
        fs::hard_link(&manifest, space.root().join("manifest-copy")).expect("link manifest");
        let error = store
            .open(&SpaceName::parse("linked-manifest").expect("valid name"))
            .expect_err("multiply linked manifest must fail closed");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
    }

    #[test]
    fn broad_manifest_permissions_are_rejected() {
        let (_temporary, store) = test_store();
        let space = store
            .create(SpaceName::parse("broad").expect("valid name"), PathBuf::from("/bin/sh"))
            .expect("create space");
        let manifest = space.root().join(MANIFEST_FILE);
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o644)).expect("broaden manifest");
        let error = store
            .open(&SpaceName::parse("broad").expect("valid name"))
            .expect_err("broad manifest must fail closed");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
    }
    #[test]
    fn manifest_semantics_are_validated_before_a_space_is_healthy() {
        let (_temporary, store) = test_store();
        let name = SpaceName::parse("semantic").expect("valid name");
        let space = store
            .create(name.clone(), PathBuf::from("/bin/sh"))
            .expect("create space");
        let manifest_path = space.root().join(MANIFEST_FILE);
        let bytes = fs::read(&manifest_path).expect("read manifest");
        let mut manifest: serde_json::Value = serde_json::from_slice(&bytes).expect("parse manifest");
        manifest["authority_model"] = serde_json::Value::String("container".to_owned());
        fs::write(&manifest_path, serde_json::to_vec(&manifest).expect("encode manifest")).expect("replace manifest");
        assert_eq!(
            store.open(&name).expect_err("authority mismatch must fail").kind(),
            ErrorKind::CorruptState
        );
        manifest["authority_model"] = serde_json::Value::String("host-account-state-profile".to_owned());
        manifest["default_shell"] = serde_json::Value::String("relative-shell".to_owned());
        fs::write(&manifest_path, serde_json::to_vec(&manifest).expect("encode manifest")).expect("replace manifest");
        assert_eq!(
            store.open(&name).expect_err("relative shell must fail").kind(),
            ErrorKind::CorruptState
        );
    }

    #[test]
    fn manifest_schema_is_probed_before_strict_deserialization() {
        let (_temporary, store) = test_store();
        let name = SpaceName::parse("future").expect("valid name");
        let space = store
            .create(name.clone(), PathBuf::from("/bin/sh"))
            .expect("create space");
        let manifest_path = space.root().join(MANIFEST_FILE);
        let bytes = fs::read(&manifest_path).expect("read manifest");
        let mut manifest: serde_json::Value = serde_json::from_slice(&bytes).expect("parse manifest");
        manifest["schema_version"] = serde_json::json!(4);
        manifest["layout"] = serde_json::json!("workspace");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).expect("encode manifest")).expect("replace manifest");

        let error = store.open(&name).expect_err("future schema must fail closed");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
        assert!(error.message().contains("space uses schema 4"));
        assert!(error.hint().is_some_and(|hint| hint.contains("upgrade Quarters")));
    }

    #[test]
    fn unknown_manifest_fields_fail_strict_deserialization() {
        let (_temporary, store) = test_store();
        let name = SpaceName::parse("strict").expect("valid name");
        let space = store
            .create(name.clone(), PathBuf::from("/bin/sh"))
            .expect("create space");
        let manifest_path = space.root().join(MANIFEST_FILE);
        let bytes = fs::read(&manifest_path).expect("read manifest");
        let mut manifest: serde_json::Value = serde_json::from_slice(&bytes).expect("parse manifest");
        manifest["unexpected"] = serde_json::json!(true);
        fs::write(&manifest_path, serde_json::to_vec(&manifest).expect("encode manifest")).expect("replace manifest");

        let error = store.open(&name).expect_err("unknown field must fail closed");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
        assert!(error.message().contains("space manifest is invalid"));
    }

    #[test]
    fn new_profile_manifests_have_stable_identity() {
        let (_temporary, store) = test_store();
        let space = store
            .create(
                SpaceName::parse("profile").expect("valid name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create profile");
        let bytes = fs::read(space.root().join(MANIFEST_FILE)).expect("read manifest");
        let manifest: serde_json::Value = serde_json::from_slice(&bytes).expect("parse manifest");
        assert_eq!(manifest["schema_version"], serde_json::json!(LATEST_SCHEMA_VERSION));
        assert_eq!(manifest["layout"], serde_json::json!("profile"));
        assert_eq!(manifest["space_id"].as_str().map(str::len), Some(32));
        assert_eq!(space.layout(), crate::SpaceLayout::Profile);
        assert!(space.id().is_some());
    }

    #[test]
    fn workspace_manifests_have_stable_identity_and_private_directories() {
        let (_temporary, store) = test_store();
        let space = store
            .create_with_layout(
                SpaceName::parse("workspace").expect("valid name"),
                PathBuf::from("/bin/sh"),
                crate::SpaceLayout::Workspace,
            )
            .expect("create workspace");
        assert_eq!(space.manifest().schema_version, LATEST_SCHEMA_VERSION);
        assert_eq!(space.layout(), crate::SpaceLayout::Workspace);
        assert_eq!(space.id().expect("workspace ID").as_str().len(), 32);
        for relative in ["Desktop", "Documents", "Downloads", "Pictures", "Templates"] {
            let directory = space.home().join(relative);
            let metadata = fs::symlink_metadata(directory).expect("inspect workspace directory");
            assert!(metadata.is_dir());
            assert_eq!(metadata.mode() & 0o777, 0o700);
        }
        #[cfg(target_os = "macos")]
        for relative in [
            "Applications",
            "Library/Application Support",
            "Library/Preferences",
            "Movies",
        ] {
            let directory = space.home().join(relative);
            let metadata = fs::symlink_metadata(directory).expect("inspect macOS workspace directory");
            assert!(metadata.is_dir());
            assert_eq!(metadata.mode() & 0o777, 0o700);
        }
        let reopened = store
            .open(&SpaceName::parse("workspace").expect("valid name"))
            .expect("reopen workspace");
        assert_eq!(reopened.id(), space.id());
    }

    #[test]
    fn schema_two_requires_workspace_layout_and_stable_identity() {
        let (_temporary, store) = test_store();
        let name = SpaceName::parse("invalid-v2").expect("valid name");
        let space = store
            .create(name.clone(), PathBuf::from("/bin/sh"))
            .expect("create profile");
        let manifest_path = space.root().join(MANIFEST_FILE);
        let bytes = fs::read(&manifest_path).expect("read manifest");
        let mut manifest: serde_json::Value = serde_json::from_slice(&bytes).expect("parse manifest");
        manifest["schema_version"] = serde_json::json!(crate::WORKSPACE_SCHEMA_VERSION);
        manifest["layout"] = serde_json::json!("workspace");
        manifest.as_object_mut().expect("manifest object").remove("space_id");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).expect("encode manifest")).expect("replace manifest");
        let error = store.open(&name).expect_err("missing stable ID must fail closed");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
        assert!(error.message().contains("stable identity"));
    }

    #[test]
    fn activity_observation_has_a_bounded_wait() {
        let (_temporary, store) = test_store();
        let space = store
            .create(
                SpaceName::parse("bounded").expect("valid name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create space");
        assert_eq!(
            store.lease_state(&space).expect("create observation lock"),
            LeaseState::Free
        );
        let observation_path = store.root.join(OBSERVATION_LOCK_FILE);
        let observation = open_private_lock(&observation_path).expect("open observation lock");
        <File as FileExt>::lock(&observation).expect("hold observation lock");

        let started = Instant::now();
        assert_eq!(
            store.lease_state(&space).expect("bounded observation"),
            LeaseState::Unknown
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            store.lease(&space).expect_err("lease must fail closed").kind(),
            ErrorKind::ResourceLimit
        );
    }

    #[test]
    fn aggregate_activity_observation_has_one_deadline() {
        let (_temporary, store) = test_store();
        let space = store
            .create(
                SpaceName::parse("aggregate").expect("valid name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create space");
        assert_eq!(
            store.lease_state(&space).expect("create observation lock"),
            LeaseState::Free
        );
        let observation_path = store.root.join(OBSERVATION_LOCK_FILE);
        let observation = open_private_lock(&observation_path).expect("open observation lock");
        <File as FileExt>::lock(&observation).expect("hold observation lock");
        let spaces = vec![&space; 128];

        let started = Instant::now();
        let states = store.lease_states(&spaces).expect("bounded aggregate observation");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(states.len(), spaces.len());
        assert!(states.into_iter().all(|state| state == LeaseState::Unknown));
    }

    #[test]
    fn activity_lease_has_a_bounded_wait() {
        let (_temporary, store) = test_store();
        let space = store
            .create(
                SpaceName::parse("bounded-lease").expect("valid name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create space");
        let activity = open_private_lock(&space.lock_path()).expect("open activity lock");
        <File as FileExt>::lock(&activity).expect("hold activity lock");

        let started = Instant::now();
        assert_eq!(
            store.lease(&space).expect_err("lease must have a deadline").kind(),
            ErrorKind::ResourceLimit
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn existing_root_is_never_chmodded() {
        let temporary = TempDir::new().expect("temporary directory");
        let root = temporary.path().join("existing-root");
        fs::create_dir(&root).expect("create root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("set broad mode");
        let store = Store::new(root.clone()).expect("valid absolute root");
        store
            .create(SpaceName::parse("work").expect("valid name"), PathBuf::from("/bin/sh"))
            .expect("protected existing root is usable");
        let mode = fs::symlink_metadata(root).expect("inspect root").mode() & 0o777;
        assert_eq!(mode, 0o755, "Quarters must not chmod an existing root");
    }

    #[test]
    fn existing_group_writable_root_fails_closed_without_chmod() {
        let temporary = TempDir::new().expect("temporary directory");
        let root = temporary.path().join("shared-root");
        fs::create_dir(&root).expect("create root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).expect("set shared mode");
        let store = Store::new(root.clone()).expect("valid absolute root");
        let error = store
            .create(SpaceName::parse("work").expect("valid name"), PathBuf::from("/bin/sh"))
            .expect_err("other-writable root must fail closed");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
        let mode = fs::symlink_metadata(root).expect("inspect root").mode() & 0o777;
        assert_eq!(mode, 0o770, "Quarters must not chmod a rejected root");
    }
}
