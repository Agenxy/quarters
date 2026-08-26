//! Bounded inspection and cleanup of reserved recovery directories.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use serde::Serialize;

use fs4::FileExt;

use crate::store::lifecycle::remove_tree_restoring_owner_access;
use crate::store::{StoreLayout, entry_exists, open_private_lock, sync_directory, unique_suffix};
use crate::store_policy::{validate_private_dir, validate_store_root};
use crate::{ErrorKind, QuartersError, Result, Store};

const CREATING_PREFIX: &[u8] = b".creating-";
const MAX_RECOVERY_ENTRIES: usize = 1_024;
const RECLAIMING_PREFIX: &[u8] = b".reclaiming-";
const RETIRED_PREFIX: &[u8] = b".retired-";
pub(crate) const CREATION_LOCK_FILE: &str = ".creating.lock";

/// Counts of reserved internal directories awaiting safe cleanup.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RecoverySummary {
    /// Creation operations currently holding their private working lock.
    pub active_creations: usize,
    /// Unpublished space skeletons left by an interrupted creation.
    pub unfinished_creations: usize,
    /// Retired space directories left by an interrupted deletion.
    pub retired_entries: usize,
}

struct CreationCandidate {
    path: std::path::PathBuf,
    _lock: Option<File>,
}

impl Store {
    /// Inspect abandoned internal creation and retirement state.
    ///
    /// # Errors
    ///
    /// Returns an error when the store or its bounded observation lock cannot
    /// be inspected safely.
    pub fn recovery_summary(&self) -> Result<RecoverySummary> {
        let root_metadata = match fs::symlink_metadata(&self.root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RecoverySummary::default());
            }
            Err(error) => return Err(QuartersError::io("inspect Quarters root", &self.root, error)),
        };
        validate_store_root(&self.root, &root_metadata)?;
        let layout = self.layout();
        let spaces_present = entry_exists(layout.spaces_root())?;
        let trash_present = entry_exists(layout.trash_root())?;
        if !spaces_present && !trash_present {
            return Ok(RecoverySummary::default());
        }
        validate_layout(&self.root, &layout)?;
        let _observation = self.observation_guard()?;
        inspect(&self.root, &layout)
    }

    /// Remove abandoned internal creation and retirement state.
    ///
    /// Active creation and removal operations use the same management lock or
    /// a private per-creation lock, so active working paths are never removed.
    ///
    /// # Errors
    ///
    /// Returns an error before deletion when an internal entry is not a
    /// validated private directory or the management lock is unavailable.
    pub fn recover(&self) -> Result<RecoverySummary> {
        self.ensure_layout()?;
        let layout = self.layout();
        let (summary, reclaiming) = {
            let _observation = self.management_guard()?;
            prepare_recovery(&self.root, &layout)?
        };
        let mut first_failure = None;
        for path in &reclaiming {
            if let Err(error) = remove_tree_restoring_owner_access(path)
                && first_failure.is_none()
            {
                first_failure = Some(error);
            }
        }
        let sync_result = sync_directory(layout.trash_root());
        if let Some(error) = first_failure {
            return Err(error.with_hint(
                "recovery attempted every retired entry; inspect the remaining reclaiming state and retry",
            ));
        }
        sync_result?;
        Ok(summary)
    }
}

fn inspect(root: &Path, layout: &StoreLayout) -> Result<RecoverySummary> {
    validate_layout(root, layout)?;
    let (unfinished, active) = classify_creations(layout.spaces_root())?;
    Ok(RecoverySummary {
        active_creations: active,
        unfinished_creations: unfinished.len(),
        retired_entries: matching_entries(layout.trash_root(), &[RETIRED_PREFIX, RECLAIMING_PREFIX])?.len(),
    })
}

fn prepare_recovery(root: &Path, layout: &StoreLayout) -> Result<(RecoverySummary, Vec<std::path::PathBuf>)> {
    validate_layout(root, layout)?;
    let (creations, active_creations) = classify_creations(layout.spaces_root())?;
    let retired = matching_entries(layout.trash_root(), &[RETIRED_PREFIX, RECLAIMING_PREFIX])?;
    for path in &retired {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(QuartersError::io("inspect recovery directory", path, error)),
        };
        validate_private_dir(path, &metadata)?;
    }
    let mut reclaiming = Vec::new();
    for path in creations.iter().map(|candidate| &candidate.path).chain(&retired) {
        let target = layout.trash_root().join(format!(".reclaiming-{}", unique_suffix()?));
        match fs::rename(path, &target) {
            Ok(()) => reclaiming.push(target),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(QuartersError::io("retire recovery directory", path, error)),
        }
    }
    sync_directory(layout.spaces_root())?;
    sync_directory(layout.trash_root())?;
    let summary = RecoverySummary {
        active_creations,
        unfinished_creations: creations.len(),
        retired_entries: retired.len(),
    };
    Ok((summary, reclaiming))
}

fn classify_creations(parent: &Path) -> Result<(Vec<CreationCandidate>, usize)> {
    let mut stale = Vec::new();
    let mut active = 0;
    for path in matching_entries(parent, &[CREATING_PREFIX])? {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(QuartersError::io("inspect creation directory", &path, error)),
        };
        validate_private_dir(&path, &metadata)?;
        let lock_path = path.join(CREATION_LOCK_FILE);
        match fs::symlink_metadata(&lock_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                stale.push(CreationCandidate { path, _lock: None });
                continue;
            }
            Ok(_metadata) => {}
            Err(error) => return Err(QuartersError::io("inspect creation lock", &lock_path, error)),
        }
        let file = match open_private_lock(&lock_path) {
            Ok(file) => file,
            Err(_error)
                if fs::symlink_metadata(&path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        match <File as FileExt>::try_lock(&file) {
            Ok(()) => stale.push(CreationCandidate {
                path,
                _lock: Some(file),
            }),
            Err(fs4::TryLockError::WouldBlock) => active += 1,
            Err(fs4::TryLockError::Error(error)) => {
                return Err(QuartersError::io("inspect creation lock", &lock_path, error));
            }
        }
    }
    Ok((stale, active))
}

fn validate_layout(root: &Path, layout: &StoreLayout) -> Result<()> {
    let metadata =
        fs::symlink_metadata(root).map_err(|error| QuartersError::io("inspect Quarters root", root, error))?;
    validate_store_root(root, &metadata)?;
    for path in [layout.spaces_root(), layout.trash_root()] {
        let metadata =
            fs::symlink_metadata(path).map_err(|error| QuartersError::io("inspect recovery parent", path, error))?;
        validate_private_dir(path, &metadata)?;
    }
    Ok(())
}

fn matching_entries(parent: &Path, prefixes: &[&[u8]]) -> Result<Vec<std::path::PathBuf>> {
    let mut matches = Vec::new();
    let entries = fs::read_dir(parent).map_err(|error| QuartersError::io("read recovery parent", parent, error))?;
    for entry in entries {
        let entry = entry.map_err(|error| QuartersError::io("read recovery entry", parent, error))?;
        if !prefixes.iter().any(|prefix| has_prefix(&entry.file_name(), prefix)) {
            continue;
        }
        if matches.len() >= MAX_RECOVERY_ENTRIES {
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                "the store contains more than 1024 reserved recovery entries",
            )
            .with_hint("inspect the protected store root before attempting recovery"));
        }
        matches.push(entry.path());
    }
    Ok(matches)
}

fn has_prefix(name: &OsStr, prefix: &[u8]) -> bool {
    name.as_bytes().starts_with(prefix)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    #[test]
    fn active_creation_is_reported_and_never_recovered() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        store.recover().expect("initialize store");
        let creation = store.root.join("spaces/.creating-live");
        fs::create_dir(&creation).expect("create working directory");
        fs::set_permissions(&creation, fs::Permissions::from_mode(0o700)).expect("protect working directory");
        let lock_path = creation.join(CREATION_LOCK_FILE);
        fs::write(&lock_path, b"").expect("create working lock");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).expect("protect working lock");
        let lock = open_private_lock(&lock_path).expect("open working lock");
        <File as FileExt>::lock(&lock).expect("hold working lock");

        let summary = store.recovery_summary().expect("inspect live creation");
        assert_eq!(summary.active_creations, 1);
        assert_eq!(summary.unfinished_creations, 0);
        let recovered = store.recover().expect("skip live creation");
        assert_eq!(recovered.active_creations, 1);
        assert!(creation.is_dir());

        drop(lock);
        let recovered = store.recover().expect("recover stale creation");
        assert_eq!(recovered.unfinished_creations, 1);
        assert!(!creation.exists());
    }

    #[test]
    fn symbolic_link_recovery_entry_fails_closed() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        store.recover().expect("initialize store");
        let external = temporary.path().join("external");
        fs::create_dir(&external).expect("create external directory");
        symlink(&external, store.root.join("spaces/.creating-linked")).expect("link recovery entry");

        let error = store.recover().expect_err("linked recovery entry must fail");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
        assert!(external.is_dir());
    }

    #[test]
    fn nested_read_only_directory_is_recoverable() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        store.recover().expect("initialize store");
        let creation = store.root.join("spaces/.creating-read-only");
        let nested = creation.join("nested");
        fs::create_dir_all(&nested).expect("create stale tree");
        fs::set_permissions(&creation, fs::Permissions::from_mode(0o700)).expect("protect staging root");
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o000)).expect("remove nested access");

        let summary = store.recover().expect("recover read-only tree");
        assert_eq!(summary.unfinished_creations, 1);
        assert!(!creation.exists());
        assert_eq!(
            store.recovery_summary().expect("inspect recovery"),
            RecoverySummary::default()
        );
    }

    #[test]
    fn recovery_attempts_later_entries_after_one_cleanup_failure() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        store.recover().expect("initialize store");
        let deep = store.root.join("trash/.retired-deep");
        fs::create_dir(&deep).expect("create deep retired root");
        fs::set_permissions(&deep, fs::Permissions::from_mode(0o700)).expect("protect deep root");
        let mut nested = deep;
        for _ in 0..=256 {
            nested.push("d");
            fs::create_dir(&nested).expect("create deep retired directory");
        }
        let ordinary = store.root.join("trash/.retired-ordinary");
        fs::create_dir(&ordinary).expect("create ordinary retired root");
        fs::set_permissions(&ordinary, fs::Permissions::from_mode(0o700)).expect("protect ordinary root");

        let error = store.recover().expect_err("one over-deep cleanup must fail");
        assert_eq!(error.kind(), ErrorKind::ResourceLimit);
        assert_eq!(store.recovery_summary().expect("inspect residue").retired_entries, 1);
    }
}
