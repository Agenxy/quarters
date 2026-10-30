// SPDX-License-Identifier: GPL-3.0-or-later
//! Working directories validated once and entered by identity.

use crate::{ErrorKind, QuartersError, Result};
use serde::{Serialize, Serializer};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// A directory accepted for `--workdir`.
///
/// It records the device and inode it had when it was validated, and
/// [`WorkingDirectory::enter`] changes into a descriptor with that identity,
/// so a path replaced after validation is refused rather than followed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkingDirectory {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl WorkingDirectory {
    /// Record `path` as the entry path, identified by the directory at
    /// `source`. The two differ only where a home view will later mount
    /// `source` at `path`.
    pub(super) fn identified(path: PathBuf, source: &Path) -> Result<Self> {
        let directory = open_directory(source)
            .map_err(|error| QuartersError::io("open requested working directory", source, error))?;
        let metadata = directory
            .metadata()
            .map_err(|error| QuartersError::io("inspect requested working directory", source, error))?;
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    /// The path the launched process sees as its working directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Change the current process into this directory through a descriptor
    /// whose identity matches the validated one.
    ///
    /// # Errors
    ///
    /// Returns an error when the path no longer opens as a directory, now
    /// names a different directory, or cannot be entered.
    pub fn enter(&self) -> Result<()> {
        let directory = open_directory(&self.path)
            .map_err(|error| QuartersError::io("reopen requested working directory", &self.path, error))?;
        let metadata = directory
            .metadata()
            .map_err(|error| QuartersError::io("reinspect requested working directory", &self.path, error))?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "the requested working directory was replaced after validation",
            )
            .with_hint("Quarters will not enter a substituted directory; retry once the path is stable"));
        }
        nix::unistd::fchdir(&directory).map_err(|error| {
            QuartersError::new(ErrorKind::System, "could not enter the requested working directory").with_source(error)
        })
    }
}

impl Serialize for WorkingDirectory {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.path.serialize(serializer)
    }
}

fn open_directory(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(super::platform_directory_open_flags())
        .open(path)
}
