//! Identity-bound space retirement and deletion.

use super::{
    Store, create_private_dir, lifecycle, open_private_lock, space_not_found, sync_parent_directory, unique_suffix,
};
use crate::store_policy::{validate_private_dir, validate_removal_entry_name};
use crate::{ErrorKind, QuartersError, Result, SpaceName};
use fs4::FileExt;
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

impl Store {
    /// Remove an inactive space using identity-bound rename-then-delete.
    ///
    /// # Errors
    ///
    /// Returns an error when the space is active, unhealthy, replaced during
    /// removal, or an exact filesystem operation fails.
    pub fn remove(&self, name: &str) -> Result<()> {
        validate_removal_entry_name(name)?;
        let host = crate::HostEnvironment::capture();
        let removable_space = if let Ok(validated_name) = SpaceName::parse(name.to_owned()) {
            self.ensure_no_rename_target(&validated_name)?;
            self.ensure_no_rollback_target(&validated_name)?;
            let identity = self.open_identity_for_removal(&validated_name).map_err(|error| {
                QuartersError::new(
                    ErrorKind::CorruptState,
                    format!("cannot prove private SSH-agent state is absent for space '{name}'"),
                )
                .with_hint("repair the protected control files before removal")
                .with_source(error)
            })?;
            self.ensure_no_agent_for_removal(&identity, &host)?;
            Some(identity)
        } else {
            None
        };
        let Some(spaces_root) = self.existing_spaces_root()? else {
            return Err(space_not_found(name));
        };
        let retired = {
            let _observation = self.management_guard()?;
            retire_space(self, &spaces_root, name)?
        };
        delete_retired_space(&retired, name)?;
        if let Some(space) = removable_space {
            crate::platform::remove_runtime_directory(&space, &host).map_err(|error| {
                error.with_hint(format!(
                    "space '{name}' was removed, but its exact private runtime directory was retained for inspection"
                ))
            })?;
        }
        Ok(())
    }
}

struct RetiredSpace {
    path: PathBuf,
    identity: lifecycle::PathIdentity,
}

fn retire_space(store: &Store, spaces_root: &Path, name: &str) -> Result<RetiredSpace> {
    let space_path = spaces_root.join(name);
    let metadata = removal_metadata(&space_path, name)?;
    validate_private_dir(&space_path, &metadata)?;
    let identity = lifecycle::PathIdentity::from_metadata(&metadata);
    let lock_path = space_path.join(".active");
    let file = open_private_lock(&lock_path)?;
    lock_for_removal(&file, &lock_path, name)?;
    verify_held_lock(&file, &lock_path)?;
    let trash_root = store.layout().trash_root().to_path_buf();
    create_private_dir(&trash_root)?;
    let retired = trash_root.join(format!(".retired-{}", unique_suffix()?));
    identity.verify_directory(&space_path, "reinspect removal target")?;
    fs::rename(&space_path, &retired).map_err(|error| QuartersError::io("retire space", &space_path, error))?;
    identity.verify_directory(&retired, "verify retired space")?;
    sync_retirement(&space_path, &retired)?;
    Ok(RetiredSpace {
        path: retired,
        identity,
    })
}

fn removal_metadata(path: &Path, name: &str) -> Result<fs::Metadata> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(space_not_found(name)),
        Err(error) => Err(QuartersError::io("inspect removal target", path, error)),
    }
}

fn lock_for_removal(file: &File, lock_path: &Path, name: &str) -> Result<()> {
    <File as FileExt>::try_lock(file).map_err(|error| match error {
        fs4::TryLockError::WouldBlock => QuartersError::new(
            ErrorKind::SpaceActive,
            format!("space '{name}' has a held cooperative lease"),
        )
        .with_hint(format!(
            "run 'quarters status {name}', exit supervised and detached processes, then retry"
        )),
        fs4::TryLockError::Error(error) => QuartersError::io("lock space for removal", lock_path, error),
    })
}

fn verify_held_lock(file: &File, lock_path: &Path) -> Result<()> {
    let held = file
        .metadata()
        .map_err(|error| QuartersError::io("inspect held removal lock", lock_path, error))?;
    let current = fs::symlink_metadata(lock_path)
        .map_err(|error| QuartersError::io("reinspect removal lock", lock_path, error))?;
    if held.dev() == current.dev() && held.ino() == current.ino() {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "the space activity lock changed before removal",
    ))
}

fn sync_retirement(original: &Path, retired: &Path) -> Result<()> {
    let hint = "the space was retired from use; run 'quarters doctor' and recover validated stale state";
    sync_parent_directory(original).map_err(|error| error.with_hint(hint))?;
    sync_parent_directory(retired).map_err(|error| error.with_hint(hint))
}

fn delete_retired_space(retired: &RetiredSpace, name: &str) -> Result<()> {
    let hint = "the space was retired from use; run 'quarters doctor' and recover validated stale state";
    retired
        .identity
        .verify_directory(&retired.path, "reinspect retired space")?;
    lifecycle::remove_exact_tree_restoring_owner_access(&retired.path, retired.identity)
        .map_err(|error| error.with_hint(hint))?;
    sync_parent_directory(&retired.path).map_err(|error| {
        error.with_hint(format!(
            "space '{name}' was removed, but directory durability could not be confirmed; inspect status before retrying"
        ))
    })
}
