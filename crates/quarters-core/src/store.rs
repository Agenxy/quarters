//! Atomic private storage for spaces.

use crate::store_lock::lock_shared_bounded;
use crate::store_policy::{
    validate_private_dir, validate_private_file, validate_removal_entry_name, validate_shell, validate_store_root,
    validate_stored_manifest,
};
use crate::{ErrorKind, QuartersError, Result, SCHEMA_VERSION, Space, SpaceManifest, SpaceName};
use fs4::FileExt;
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

    /// Create a new private space and publish it with one rename.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid shell, an existing or unfinished
    /// target, or any filesystem or manifest failure.
    pub fn create(&self, name: SpaceName, default_shell: PathBuf) -> Result<Space> {
        self.ensure_layout()?;
        validate_shell(&default_shell)?;
        let destination = self.space_path(&name);
        if entry_exists(&destination)? {
            return Err(QuartersError::new(
                ErrorKind::AlreadyExists,
                format!("space '{name}' already exists"),
            ));
        }
        let temporary = self.temporary_path(&name)?;
        if entry_exists(&temporary)? {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                format!("unfinished creation path exists at {}", temporary.display()),
            )
            .with_hint("inspect and remove only that unfinished directory, then retry"));
        }
        let setup_observation = self.management_guard()?;
        create_private_dir(&temporary)?;
        let creation_lock_path = temporary.join(crate::store_recovery::CREATION_LOCK_FILE);
        let creation_lock = match open_or_create_private_lock(&creation_lock_path) {
            Ok(file) => file,
            Err(error) => {
                let _cleanup = fs::remove_dir_all(&temporary);
                return Err(error);
            }
        };
        if let Err(error) = <File as FileExt>::try_lock(&creation_lock) {
            let _cleanup = fs::remove_dir_all(&temporary);
            return Err(match error {
                fs4::TryLockError::WouldBlock => {
                    QuartersError::new(ErrorKind::CorruptState, "a new creation lock was already held")
                }
                fs4::TryLockError::Error(error) => QuartersError::io("lock space creation", &creation_lock_path, error),
            });
        }
        drop(setup_observation);
        let requested_name = name.as_str().to_owned();
        let result = Self::populate_space(&temporary, name, default_shell);
        if let Err(error) = result {
            let _cleanup = fs::remove_dir_all(&temporary);
            return Err(error);
        }
        let _publish_observation = match self.management_guard() {
            Ok(observation) => observation,
            Err(error) => {
                let _cleanup = fs::remove_dir_all(&temporary);
                return Err(error);
            }
        };
        match entry_exists(&destination) {
            Ok(false) => {}
            Ok(true) => {
                let _cleanup = fs::remove_dir_all(&temporary);
                return Err(QuartersError::new(
                    ErrorKind::AlreadyExists,
                    format!("space '{requested_name}' already exists"),
                ));
            }
            Err(error) => {
                let _cleanup = fs::remove_dir_all(&temporary);
                return Err(error);
            }
        }
        if let Err(error) = fs::remove_file(&creation_lock_path) {
            let failure = QuartersError::io("remove creation marker", &creation_lock_path, error);
            let _cleanup = fs::remove_dir_all(&temporary);
            return Err(failure);
        }
        if let Err(error) = fs::rename(&temporary, &destination) {
            let failure = QuartersError::io("publish space", &destination, error);
            let _cleanup = fs::remove_dir_all(&temporary);
            return Err(failure);
        }
        drop(creation_lock);
        Self::open_path(destination)
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
        for entry in entries {
            let entry = entry.map_err(|error| QuartersError::io("read a space entry", &spaces_root, error))?;
            let file_name = entry.file_name();
            if file_name.to_string_lossy().starts_with('.') {
                continue;
            }
            if let Some(maximum) = maximum
                && inspections.len() >= maximum
            {
                return Err(QuartersError::new(
                    ErrorKind::ResourceLimit,
                    format!("the store contains more than {maximum} visible space entries"),
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

    /// Remove an inactive space using rename-then-delete.
    ///
    /// # Errors
    ///
    /// Returns an error when the space is active or an exact filesystem
    /// operation fails.
    pub fn remove(&self, name: &str) -> Result<()> {
        validate_removal_entry_name(name)?;
        let Some(spaces_root) = self.existing_spaces_root()? else {
            return Err(space_not_found(name));
        };
        let _observation = self.management_guard()?;
        let space_path = spaces_root.join(name);
        let metadata = match fs::symlink_metadata(&space_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(space_not_found(name)),
            Err(error) => return Err(QuartersError::io("inspect removal target", &space_path, error)),
        };
        validate_private_dir(&space_path, &metadata)?;
        let lock_path = space_path.join(".active");
        let file = open_private_lock(&lock_path)?;
        <File as FileExt>::try_lock(&file).map_err(|error| match error {
            fs4::TryLockError::WouldBlock => QuartersError::new(
                ErrorKind::SpaceActive,
                format!("space '{name}' has a held cooperative lease"),
            )
            .with_hint(format!(
                "run 'quarters status {name}', exit supervised and detached processes, then retry"
            )),
            fs4::TryLockError::Error(error) => QuartersError::io("lock space for removal", &lock_path, error),
        })?;
        let trash_root = self.root.join("trash");
        create_private_dir(&trash_root)?;
        let retired = trash_root.join(format!(".retired-{}", unique_suffix()?));
        fs::rename(&space_path, &retired).map_err(|error| QuartersError::io("retire space", &space_path, error))?;
        fs::remove_dir_all(&retired).map_err(|error| QuartersError::io("delete retired space", &retired, error))
    }

    pub(crate) fn ensure_layout(&self) -> Result<()> {
        ensure_store_root(&self.root)?;
        create_private_dir(&self.root.join("spaces"))?;
        create_private_dir(&self.root.join("trash"))
    }

    fn existing_spaces_root(&self) -> Result<Option<PathBuf>> {
        let root_metadata = match fs::symlink_metadata(&self.root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(QuartersError::io("inspect Quarters root", &self.root, error)),
        };
        validate_store_root(&self.root, &root_metadata)?;
        let spaces_root = self.root.join("spaces");
        let spaces_metadata = match fs::symlink_metadata(&spaces_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(QuartersError::io("inspect spaces directory", &spaces_root, error)),
        };
        validate_private_dir(&spaces_root, &spaces_metadata)?;
        Ok(Some(spaces_root))
    }

    fn populate_space(root: &Path, name: SpaceName, default_shell: PathBuf) -> Result<()> {
        let home = root.join("home");
        create_private_dir(&home)?;
        for relative in private_directories() {
            create_private_dir(&home.join(relative))?;
        }
        create_shell_files(&home)?;
        create_git_config(&home)?;
        write_private_file(
            &home.join(".ssh/config"),
            b"# Quarters-owned SSH configuration. Add only identities for this space.\nHost *\n  AddKeysToAgent no\n  IdentitiesOnly yes\n",
        )?;
        write_private_file(&root.join(".active"), b"")?;
        let manifest = SpaceManifest {
            schema_version: SCHEMA_VERSION,
            name,
            created_unix_ms: epoch_millis()?,
            default_shell,
            authority_model: "host-account-state-profile".to_owned(),
        };
        write_manifest(root, &manifest)
    }

    fn open_path(path: PathBuf) -> Result<Space> {
        let manifest_path = path.join(MANIFEST_FILE);
        validate_space_anchors(&path)?;
        let bytes = read_private_file(&manifest_path)?;
        let manifest: SpaceManifest = serde_json::from_slice(&bytes).map_err(|error| {
            QuartersError::new(
                ErrorKind::CorruptState,
                format!("space manifest is invalid at {}", manifest_path.display()),
            )
            .with_source(error)
        })?;
        if manifest.schema_version != SCHEMA_VERSION {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                format!(
                    "space uses schema {}, but this build supports {}",
                    manifest.schema_version, SCHEMA_VERSION
                ),
            ));
        }
        validate_stored_manifest(&manifest)?;
        let expected_name = path.file_name().and_then(|value| value.to_str());
        if expected_name != Some(manifest.name.as_str()) {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "space directory and manifest names differ",
            ));
        }
        Ok(Space::new(path, manifest))
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

    fn space_path(&self, name: &SpaceName) -> PathBuf {
        self.root.join("spaces").join(name.as_str())
    }

    fn temporary_path(&self, name: &SpaceName) -> Result<PathBuf> {
        Ok(self
            .root
            .join("spaces")
            .join(format!(".creating-{name}-{}", unique_suffix()?)))
    }
}

fn private_directories() -> &'static [&'static str] {
    &[
        ".cache",
        ".cargo",
        ".claude",
        ".codex",
        ".config/gh",
        ".config/npm",
        ".gnupg",
        ".local/bin",
        ".local/share",
        ".local/state/shell",
        ".ssh",
    ]
}

fn create_shell_files(home: &Path) -> Result<()> {
    write_private_file(
        &home.join(".zshrc"),
        b"# Quarters-owned starting point. This file belongs to this space.\nexport HISTFILE=\"${XDG_STATE_HOME:-$HOME/.local/state}/shell/zsh_history\"\nsetopt APPEND_HISTORY INC_APPEND_HISTORY SHARE_HISTORY\nif [[ -n \"$QUARTERS_SPACE\" ]]; then\n  PROMPT=\"[$QUARTERS_SPACE] %~ %# \"\nfi\n",
    )?;
    write_private_file(
        &home.join(".bashrc"),
        b"# Quarters-owned starting point. This file belongs to this space.\nHISTFILE=\"${XDG_STATE_HOME:-$HOME/.local/state}/shell/bash_history\"\nexport HISTFILE\nif [ -n \"${QUARTERS_SPACE:-}\" ]; then\n  PS1=\"[$QUARTERS_SPACE] \\w \\$ \"\nfi\n",
    )
}

fn create_git_config(home: &Path) -> Result<()> {
    write_private_file(
        &home.join(".gitconfig"),
        b"# Host credential helpers are deliberately cleared.\n[credential]\n\thelper =\n\tuseHttpPath = true\n",
    )
}

fn write_manifest(root: &Path, manifest: &SpaceManifest) -> Result<()> {
    let path = root.join(MANIFEST_FILE);
    let mut bytes = serde_json::to_vec_pretty(manifest).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not serialize the space manifest").with_source(error)
    })?;
    bytes.push(b'\n');
    write_private_file(&path, &bytes)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
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

fn read_private_file(path: &Path) -> Result<Vec<u8>> {
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
    let root_metadata =
        fs::symlink_metadata(path).map_err(|error| QuartersError::io("inspect space directory", path, error))?;
    validate_private_dir(path, &root_metadata)?;
    let home = path.join("home");
    let home_metadata =
        fs::symlink_metadata(&home).map_err(|error| QuartersError::io("inspect space home", &home, error))?;
    validate_private_dir(&home, &home_metadata)?;
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

pub(crate) fn entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_metadata) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(QuartersError::io("inspect path", path, error)),
    }
}

fn ensure_store_root(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_store_root(path, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_private_dir(path),
        Err(error) => Err(QuartersError::io("inspect Quarters root", path, error)),
    }
}

fn epoch_millis() -> Result<u128> {
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

fn unique_suffix() -> Result<String> {
    let counter = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(format!("{}-{}-{counter}", std::process::id(), epoch_millis()?))
}

#[cfg(test)]
// Test assertions intentionally use `expect` to preserve failure context.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
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
        let (_temporary, store) = test_store();
        let name = SpaceName::parse("redirected").expect("valid name");
        let space = store
            .create(name.clone(), PathBuf::from("/bin/sh"))
            .expect("create space");
        let real_home = space.root().join("real-home");
        fs::rename(space.home(), &real_home).expect("move home");
        symlink(&real_home, space.home()).expect("link home");

        let error = store.open(&name).expect_err("linked home must fail closed");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
        assert!(matches!(
            store.inspect_named(&name).expect("inspect unhealthy entry"),
            SpaceInspection::Unhealthy { .. }
        ));
        store.remove(name.as_str()).expect("remove entry with unhealthy home");
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
