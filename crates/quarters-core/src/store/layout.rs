//! Legacy store-layout resolution shared by every storage operation.

use super::{Store, create_private_dir, unique_suffix};
use crate::store_policy::{validate_private_dir, validate_store_root};
use crate::{QuartersError, Result, SpaceName};
use std::fs;
use std::path::{Path, PathBuf};

/// Resolved paths for the current on-disk store layout.
#[derive(Clone, Debug)]
pub(crate) struct StoreLayout {
    spaces_root: PathBuf,
    trash_root: PathBuf,
}

impl StoreLayout {
    fn legacy(root: &Path) -> Self {
        Self {
            spaces_root: root.join("spaces"),
            trash_root: root.join("trash"),
        }
    }

    /// Published spaces directory.
    pub(crate) fn spaces_root(&self) -> &Path {
        &self.spaces_root
    }

    /// Retired-state directory.
    pub(crate) fn trash_root(&self) -> &Path {
        &self.trash_root
    }
}

impl Store {
    /// Resolve the only layout this release reads and writes.
    pub(crate) fn layout(&self) -> StoreLayout {
        StoreLayout::legacy(&self.root)
    }

    pub(crate) fn ensure_layout(&self) -> Result<()> {
        ensure_store_root(&self.root)?;
        let layout = self.layout();
        create_private_dir(layout.spaces_root())?;
        create_private_dir(layout.trash_root())
    }

    pub(super) fn existing_spaces_root(&self) -> Result<Option<PathBuf>> {
        let root_metadata = match fs::symlink_metadata(&self.root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(QuartersError::io("inspect Quarters root", &self.root, error)),
        };
        validate_store_root(&self.root, &root_metadata)?;
        let spaces_root = self.layout().spaces_root().to_path_buf();
        let spaces_metadata = match fs::symlink_metadata(&spaces_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(QuartersError::io("inspect spaces directory", &spaces_root, error)),
        };
        validate_private_dir(&spaces_root, &spaces_metadata)?;
        Ok(Some(spaces_root))
    }

    pub(super) fn space_path(&self, name: &SpaceName) -> PathBuf {
        self.layout().spaces_root().join(name.as_str())
    }

    pub(super) fn temporary_path(&self, name: &SpaceName) -> Result<PathBuf> {
        Ok(self
            .layout()
            .spaces_root()
            .join(format!(".creating-{name}-{}", unique_suffix()?)))
    }
}

fn ensure_store_root(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_store_root(path, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_private_dir(path),
        Err(error) => Err(QuartersError::io("inspect Quarters root", path, error)),
    }
}
