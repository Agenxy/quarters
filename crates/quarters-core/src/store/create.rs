//! Atomic space creation transaction and initial user-state files.

use super::{
    MANIFEST_FILE, Store, create_private_dir, entry_exists, epoch_millis, open_or_create_private_lock, sync_directory,
    sync_parent_directory, write_private_file,
};
use crate::store_policy::validate_shell;
use crate::{
    ErrorKind, PROFILE_SCHEMA_VERSION, QuartersError, Result, Space, SpaceId, SpaceLayout, SpaceManifest, SpaceName,
    WORKSPACE_SCHEMA_VERSION,
};
use fs4::FileExt;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

impl Store {
    /// Create a new private space and publish it with one rename.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid shell, an existing or unfinished
    /// target, or any filesystem or manifest failure.
    pub fn create(&self, name: SpaceName, default_shell: PathBuf) -> Result<Space> {
        self.create_with_layout(name, default_shell, SpaceLayout::Profile)
    }

    /// Create a new private space with an explicit user-directory layout.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid shell, an existing or unfinished
    /// target, unavailable system randomness, or any filesystem or manifest
    /// failure.
    pub fn create_with_layout(&self, name: SpaceName, default_shell: PathBuf, layout: SpaceLayout) -> Result<Space> {
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
        reject_unfinished_path(&temporary)?;
        let setup_observation = self.management_guard()?;
        create_private_dir(&temporary)?;
        let creation_lock_path = temporary.join(crate::store_recovery::CREATION_LOCK_FILE);
        let creation_lock = acquire_creation_lock(&temporary, &creation_lock_path)?;
        drop(setup_observation);
        let requested_name = name.as_str().to_owned();
        if let Err(error) = populate_space(&temporary, name, default_shell, layout) {
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
        reject_publish_collision(&destination, &temporary, &requested_name)?;
        if let Err(error) = fs::remove_file(&creation_lock_path) {
            let failure = QuartersError::io("remove creation marker", &creation_lock_path, error);
            let _cleanup = fs::remove_dir_all(&temporary);
            return Err(failure);
        }
        if let Err(error) = sync_directory(&temporary) {
            let _cleanup = fs::remove_dir_all(&temporary);
            return Err(error);
        }
        if let Err(error) = fs::rename(&temporary, &destination) {
            let failure = QuartersError::io("publish space", &destination, error);
            let _cleanup = fs::remove_dir_all(&temporary);
            return Err(failure);
        }
        if let Err(error) = sync_parent_directory(&destination) {
            drop(creation_lock);
            return Err(error.with_hint(format!(
                "space '{requested_name}' was published completely, but directory durability could not be confirmed; inspect it before retrying"
            )));
        }
        drop(creation_lock);
        Self::open_path(destination)
    }
}

fn reject_unfinished_path(path: &Path) -> Result<()> {
    if !entry_exists(path)? {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        format!("unfinished creation path exists at {}", path.display()),
    )
    .with_hint("inspect and remove only that unfinished directory, then retry"))
}

fn acquire_creation_lock(temporary: &Path, lock_path: &Path) -> Result<File> {
    let creation_lock = match open_or_create_private_lock(lock_path) {
        Ok(file) => file,
        Err(error) => {
            let _cleanup = fs::remove_dir_all(temporary);
            return Err(error);
        }
    };
    if let Err(error) = <File as FileExt>::try_lock(&creation_lock) {
        let _cleanup = fs::remove_dir_all(temporary);
        return Err(match error {
            fs4::TryLockError::WouldBlock => {
                QuartersError::new(ErrorKind::CorruptState, "a new creation lock was already held")
            }
            fs4::TryLockError::Error(error) => QuartersError::io("lock space creation", lock_path, error),
        });
    }
    Ok(creation_lock)
}

fn reject_publish_collision(destination: &Path, temporary: &Path, name: &str) -> Result<()> {
    match entry_exists(destination) {
        Ok(false) => Ok(()),
        Ok(true) => {
            let _cleanup = fs::remove_dir_all(temporary);
            Err(QuartersError::new(
                ErrorKind::AlreadyExists,
                format!("space '{name}' already exists"),
            ))
        }
        Err(error) => {
            let _cleanup = fs::remove_dir_all(temporary);
            Err(error)
        }
    }
}

fn populate_space(root: &Path, name: SpaceName, default_shell: PathBuf, layout: SpaceLayout) -> Result<()> {
    let home = root.join("home");
    create_private_dir(&home)?;
    for relative in private_directories() {
        create_private_dir(&home.join(relative))?;
    }
    if layout == SpaceLayout::Workspace {
        for relative in workspace_directories() {
            create_private_dir(&home.join(relative))?;
        }
        for relative in crate::platform::workspace_directories() {
            create_private_dir(&home.join(relative))?;
        }
    }
    create_shell_files(&home)?;
    create_git_config(&home)?;
    write_private_file(
        &home.join(".ssh/config"),
        b"# Quarters-owned SSH configuration. Add only identities for this space.\nHost *\n  AddKeysToAgent no\n  IdentitiesOnly yes\n",
    )?;
    write_private_file(&root.join(".active"), b"")?;
    let (schema_version, declared_layout, space_id) = match layout {
        SpaceLayout::Profile => (PROFILE_SCHEMA_VERSION, None, None),
        SpaceLayout::Workspace => (
            WORKSPACE_SCHEMA_VERSION,
            Some(SpaceLayout::Workspace),
            Some(SpaceId::generate()?),
        ),
    };
    let manifest = SpaceManifest {
        schema_version,
        layout: declared_layout,
        space_id,
        name,
        created_unix_ms: epoch_millis()?,
        default_shell,
        authority_model: "host-account-state-profile".to_owned(),
    };
    write_manifest(root, &manifest)
}

fn workspace_directories() -> &'static [&'static str] {
    &[
        "Desktop",
        "Documents",
        "Downloads",
        "Music",
        "Pictures",
        "Public",
        "Templates",
        "Videos",
    ]
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
        b"# Quarters-owned starting point. This file belongs to this space.\nexport HISTFILE=\"${XDG_STATE_HOME:-$HOME/.local/state}/shell/zsh_history\"\nsetopt APPEND_HISTORY INC_APPEND_HISTORY SHARE_HISTORY\nif command -v quarters >/dev/null 2>&1; then\n  eval \"$(quarters shell-init zsh 2>/dev/null)\"\nfi\n",
    )?;
    write_private_file(
        &home.join(".bashrc"),
        b"# Quarters-owned starting point. This file belongs to this space.\nHISTFILE=\"${XDG_STATE_HOME:-$HOME/.local/state}/shell/bash_history\"\nexport HISTFILE\nif command -v quarters >/dev/null 2>&1; then\n  eval \"$(quarters shell-init bash 2>/dev/null)\"\nfi\n",
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
