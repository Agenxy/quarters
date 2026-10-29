// SPDX-License-Identifier: GPL-3.0-or-later
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
        if self.existing_spaces_root()?.is_none() {
            return Err(space_not_found(name));
        }
        let host = crate::HostEnvironment::capture();
        let management = self.begin_mutation()?;
        let removable_space = if let Ok(validated_name) = SpaceName::parse(name.to_owned()) {
            self.ensure_no_rename_target(&validated_name)?;
            self.ensure_no_rollback_target(&validated_name)?;
            let identity = self
                .identity_for_removal(&validated_name)
                .map_err(|error| {
                    QuartersError::new(
                        ErrorKind::CorruptState,
                        format!("cannot prove private SSH-agent state is absent for space '{name}'"),
                    )
                    .with_hint("repair the protected control files before removal")
                    .with_source(error)
                })?
                .ok_or_else(|| space_not_found(name))?;
            self.ensure_not_frozen(&identity)?;
            self.ensure_no_agent_for_removal(&identity, &host)?;
            Some(identity)
        } else {
            None
        };
        let spaces_root = management.layout().spaces_root();
        let trash_root = management.layout().trash_root();
        let retired = retire_space(spaces_root, trash_root, name)?;
        drop(management);
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

fn retire_space(spaces_root: &Path, trash_root: &Path, name: &str) -> Result<RetiredSpace> {
    let space_path = spaces_root.join(name);
    let metadata = removal_metadata(&space_path, name)?;
    validate_private_dir(&space_path, &metadata)?;
    let identity = lifecycle::PathIdentity::from_metadata(&metadata);
    let lock_path = space_path.join(".active");
    let file = open_private_lock(&lock_path)?;
    lock_for_removal(&file, &lock_path, name)?;
    verify_held_lock(&file, &lock_path)?;
    lifecycle::ensure_cleanup_depth(&space_path)?;
    create_private_dir(trash_root)?;
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

#[cfg(test)]
mod tests {
    use crate::{ErrorKind, HostEnvironment, SpaceName, Store};
    use std::error::Error;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn store_with_space(root: &Path, name: &str) -> Result<(Store, crate::Space), Box<dyn Error>> {
        let store = Store::new(root.join("root"))?;
        let space = store.create(SpaceName::parse(name)?, PathBuf::from("/bin/sh"))?;
        Ok((store, space))
    }

    #[test]
    fn removal_clears_a_read_only_module_cache_larger_than_any_entry_bound() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::TempDir::new()?;
        let (store, space) = store_with_space(temporary.path(), "gocache")?;
        let host = HostEnvironment::capture();
        let runtime = crate::platform::runtime_directory(&space, &host)?;
        // Go keeps its module cache read-only, and a large one holds more
        // than 131,072 entries, the bound removal used to stop at.
        let cache = space.home().join("go/pkg/mod");
        for module in 0..132 {
            let directory = cache.join(format!("example.com/m{module}@v1.0.0"));
            fs::create_dir_all(&directory)?;
            for file in 0..1_000 {
                fs::File::create(directory.join(format!("f{file}.go")))?;
            }
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o555))?;
        }
        fs::set_permissions(cache.join("example.com"), fs::Permissions::from_mode(0o555))?;
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o555))?;

        store.remove("gocache")?;

        assert!(!store.root().join("spaces/gocache").exists());
        assert_eq!(fs::read_dir(store.root().join("trash"))?.count(), 0);
        assert!(!runtime.exists());
        Ok(())
    }

    #[test]
    fn an_overdeep_space_fails_in_place_instead_of_stranding_in_trash() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::TempDir::new()?;
        let (store, space) = store_with_space(temporary.path(), "deep")?;
        let mut nested = space.home().clone();
        for _ in 0..=256 {
            nested.push("d");
        }
        fs::create_dir_all(&nested)?;

        let error = store.remove("deep").err().ok_or("over-deep removal must fail")?;

        assert_eq!(error.kind(), ErrorKind::ResourceLimit);
        assert!(store.root().join("spaces/deep/.quarters.json").is_file());
        let trash = store.root().join("trash");
        assert!(!trash.exists() || fs::read_dir(trash)?.count() == 0);
        Ok(())
    }
}
