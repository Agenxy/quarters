//! Atomic private storage for spaces.

use crate::{ErrorKind, QuartersError, Result, SCHEMA_VERSION, Space, SpaceManifest, SpaceName};
use fs4::FileExt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MANIFEST_FILE: &str = ".quarters.json";

/// Root storage manager.
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
}

/// A held shared lease proving a space is in use.
#[derive(Debug)]
pub struct SpaceLease {
    _file: File,
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
        if destination.exists() {
            return Err(QuartersError::new(
                ErrorKind::AlreadyExists,
                format!("space '{name}' already exists"),
            ));
        }
        let temporary = self.temporary_path(&name);
        if temporary.exists() {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                format!("unfinished creation path exists at {}", temporary.display()),
            )
            .with_hint("inspect and remove only that unfinished directory, then retry"));
        }
        create_private_dir(&temporary)?;
        let result = Self::populate_space(&temporary, name, default_shell);
        if let Err(error) = result {
            let _cleanup = fs::remove_dir_all(&temporary);
            return Err(error);
        }
        fs::rename(&temporary, &destination)
            .map_err(|error| QuartersError::io("publish space", &destination, error))?;
        Self::open_path(destination)
    }

    /// Open and validate a named space.
    ///
    /// # Errors
    ///
    /// Returns an error when the space is absent or its stored state is
    /// unreadable, malformed or inconsistent with its path.
    pub fn open(&self, name: &SpaceName) -> Result<Space> {
        let path = self.space_path(name);
        if !path.exists() {
            return Err(
                QuartersError::new(ErrorKind::NotFound, format!("space '{name}' does not exist"))
                    .with_hint("run 'quarters list' to see available spaces"),
            );
        }
        Self::open_path(path)
    }

    /// List all valid spaces in name order.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be read or any published
    /// space has invalid metadata.
    pub fn list(&self) -> Result<Vec<Space>> {
        let spaces_root = self.root.join("spaces");
        if !spaces_root.exists() {
            return Ok(Vec::new());
        }
        let entries =
            fs::read_dir(&spaces_root).map_err(|error| QuartersError::io("read spaces", &spaces_root, error))?;
        let mut spaces = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| QuartersError::io("read a space entry", &spaces_root, error))?;
            if entry.file_name().to_string_lossy().starts_with('.') || !entry.path().is_dir() {
                continue;
            }
            spaces.push(Self::open_path(entry.path())?);
        }
        spaces.sort_by(|left, right| left.manifest().name.cmp(&right.manifest().name));
        Ok(spaces)
    }

    /// Hold a shared activity lease until the returned guard is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error when the lock file cannot be opened or locked.
    pub fn lease(&self, space: &Space) -> Result<SpaceLease> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(space.lock_path())
            .map_err(|error| QuartersError::io("open activity lock", &space.lock_path(), error))?;
        <File as FileExt>::lock_shared(&file)
            .map_err(|error| QuartersError::io("lock active space", &space.lock_path(), error))?;
        Ok(SpaceLease { _file: file })
    }

    /// Remove an inactive space using rename-then-delete.
    ///
    /// # Errors
    ///
    /// Returns an error when the space is active or an exact filesystem
    /// operation fails.
    pub fn remove(&self, space: &Space) -> Result<()> {
        let lock_path = space.lock_path();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| QuartersError::io("open activity lock", &lock_path, error))?;
        <File as FileExt>::try_lock(&file).map_err(|error| match error {
            fs4::TryLockError::WouldBlock => QuartersError::new(
                ErrorKind::SpaceActive,
                format!("space '{}' is active", space.manifest().name),
            )
            .with_hint("exit every process launched by this space, then retry"),
            fs4::TryLockError::Error(error) => QuartersError::io("lock space for removal", &lock_path, error),
        })?;
        let trash_root = self.root.join("trash");
        create_private_dir(&trash_root)?;
        let retired = trash_root.join(format!("{}-{}", space.manifest().name, unique_suffix()));
        fs::rename(space.root(), &retired).map_err(|error| QuartersError::io("retire space", space.root(), error))?;
        fs::remove_dir_all(&retired).map_err(|error| QuartersError::io("delete retired space", &retired, error))
    }

    fn ensure_layout(&self) -> Result<()> {
        create_private_dir(&self.root)?;
        create_private_dir(&self.root.join("spaces"))?;
        create_private_dir(&self.root.join("trash"))
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
        File::create(root.join(".active")).map_err(|error| QuartersError::io("create activity lock", root, error))?;
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
        let bytes = fs::read(&manifest_path)
            .map_err(|error| QuartersError::io("read space manifest", &manifest_path, error))?;
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
        let expected_name = path.file_name().and_then(|value| value.to_str());
        if expected_name != Some(manifest.name.as_str()) {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "space directory and manifest names differ",
            ));
        }
        Ok(Space::new(path, manifest))
    }

    fn space_path(&self, name: &SpaceName) -> PathBuf {
        self.root.join("spaces").join(name.as_str())
    }

    fn temporary_path(&self, name: &SpaceName) -> PathBuf {
        self.root
            .join("spaces")
            .join(format!(".creating-{name}-{}", unique_suffix()))
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

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|error| QuartersError::io("create private directory", path, error))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| QuartersError::io("set private directory permissions", path, error))
}

fn validate_shell(shell: &Path) -> Result<()> {
    if shell.is_absolute() && shell.is_file() {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::InvalidInput,
        format!("default shell must be an existing absolute file: {}", shell.display()),
    ))
}

fn epoch_millis() -> Result<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|error| {
            QuartersError::new(ErrorKind::System, "system clock is before the Unix epoch").with_source(error)
        })
}

fn unique_suffix() -> String {
    format!("{}-{}", std::process::id(), epoch_millis().unwrap_or_default())
}

#[cfg(test)]
// Test assertions intentionally use `expect` to preserve failure context.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
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
    fn remove_requires_inactive_lease() {
        let (_temporary, store) = test_store();
        let space = store
            .create(SpaceName::parse("busy").expect("valid name"), PathBuf::from("/bin/sh"))
            .expect("create space");
        let lease = store.lease(&space).expect("lease space");
        assert_eq!(
            store.remove(&space).expect_err("active removal must fail").kind(),
            ErrorKind::SpaceActive
        );
        drop(lease);
        store.remove(&space).expect("remove inactive space");
    }
}
