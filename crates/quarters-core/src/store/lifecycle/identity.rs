//! Retained filesystem identities for private lifecycle staging roots.

use super::cleanup::remove_exact_tree_restoring_owner_access;
use crate::{ErrorKind, QuartersError, Result};
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Device/inode identity for one no-follow filesystem observation.
pub(crate) struct PathIdentity {
    device: u64,
    inode: u64,
}

impl PathIdentity {
    pub(crate) fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    pub(crate) fn matches(self, metadata: &fs::Metadata) -> bool {
        self == Self::from_metadata(metadata)
    }

    pub(crate) fn verify_directory(self, path: &Path, action: &str) -> Result<()> {
        let metadata = fs::symlink_metadata(path).map_err(|error| QuartersError::io(action, path, error))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() && self.matches(&metadata) {
            return Ok(());
        }
        Err(identity_error("directory generation"))
    }
}

/// Identity retained from creation through staging publication or cleanup.
pub(crate) struct StagingIdentity {
    root: PathIdentity,
    lock: PathIdentity,
}

impl StagingIdentity {
    /// Capture the exact private root and held creation-lock generations.
    pub(crate) fn capture(root: &Path, lock: &File) -> Result<Self> {
        let root_metadata = fs::symlink_metadata(root)
            .map_err(|error| QuartersError::io("capture lifecycle staging root", root, error))?;
        let lock_metadata = lock
            .metadata()
            .map_err(|error| QuartersError::io("capture lifecycle creation lock", root, error))?;
        Ok(Self {
            root: PathIdentity::from_metadata(&root_metadata),
            lock: PathIdentity::from_metadata(&lock_metadata),
        })
    }

    /// Require the pathname and lock entry to name the retained generations.
    pub(crate) fn verify(&self, root: &Path, lock_path: &Path) -> Result<()> {
        self.verify_root(root)?;
        let lock_metadata = fs::symlink_metadata(lock_path)
            .map_err(|error| QuartersError::io("reinspect lifecycle creation lock", lock_path, error))?;
        if lock_metadata.file_type().is_file() && self.lock.matches(&lock_metadata) {
            return Ok(());
        }
        Err(identity_error("creation lock"))
    }

    /// Require a pathname to name the retained staging root generation.
    pub(crate) fn verify_root(&self, root: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(root)
            .map_err(|error| QuartersError::io("reinspect lifecycle staging root", root, error))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() && self.root.matches(&metadata) {
            return Ok(());
        }
        Err(identity_error("staging root"))
    }

    /// Delete only the exact retained staging generation.
    pub(crate) fn cleanup(&self, root: &Path) -> Result<()> {
        remove_exact_tree_restoring_owner_access(root, self.root)
    }
}

fn identity_error(component: &str) -> QuartersError {
    QuartersError::new(
        ErrorKind::CorruptState,
        format!("the lifecycle {component} changed during the transaction"),
    )
    .with_hint("the mismatched filesystem state was preserved for manual inspection")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    #[test]
    fn replacement_staging_root_is_preserved() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let root = temporary.path().join("staging");
        fs::create_dir(&root).expect("create staging");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("protect staging");
        let lock_path = root.join(".creation.lock");
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .expect("create lock");
        let identity = StagingIdentity::capture(&root, &lock).expect("capture identity");
        let original = temporary.path().join("original");
        fs::rename(&root, &original).expect("move original staging");
        fs::create_dir(&root).expect("create replacement");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("protect replacement");

        let error = identity.cleanup(&root).expect_err("replacement must be preserved");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
        assert!(root.exists());
        assert!(original.exists());
    }
}
