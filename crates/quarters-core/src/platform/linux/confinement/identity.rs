//! Descriptor ancestry checks for policy aliases.

use crate::{ErrorKind, QuartersError, Result};
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::Mode;
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const MAX_ANCESTORS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Inode {
    device: u64,
    number: u64,
}

impl From<&Metadata> for Inode {
    fn from(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            number: metadata.ino(),
        }
    }
}

pub(super) struct Anchor {
    pub(super) metadata: Metadata,
    inode: Inode,
    ancestry: Vec<Inode>,
    // Hold every inspected directory so inode recycling cannot create a match.
    _descriptors: Vec<File>,
}

impl Anchor {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let descriptor = open_path(path)?;
        let metadata = inspect(&descriptor, path)?;
        let inode = Inode::from(&metadata);
        let mut ancestry = vec![inode];
        let mut descriptors = Vec::new();
        let mut directory = if metadata.is_dir() {
            descriptor
        } else {
            descriptors.push(descriptor);
            open_path(
                path.parent()
                    .ok_or_else(|| QuartersError::new(ErrorKind::Unsupported, "policy file has no parent directory"))?,
            )?
        };
        for _ in 0..MAX_ANCESTORS {
            let current = Inode::from(&inspect(&directory, path)?);
            if ancestry.last() != Some(&current) {
                ancestry.push(current);
            }
            let parent = openat(
                &directory,
                "..",
                OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(|error| QuartersError::io("open policy anchor ancestor", path, error.into()))?;
            let parent_inode = Inode::from(&inspect(&parent, path)?);
            descriptors.push(directory);
            if current == parent_inode {
                descriptors.push(parent);
                return Ok(Self {
                    metadata,
                    inode,
                    ancestry,
                    _descriptors: descriptors,
                });
            }
            directory = parent;
        }
        Err(QuartersError::new(
            ErrorKind::ResourceLimit,
            "filesystem policy ancestry exceeds 256 directories",
        ))
    }

    pub(super) fn overlaps(&self, other: &Self) -> bool {
        self.ancestry.contains(&other.inode) || other.ancestry.contains(&self.inode)
    }

    pub(super) fn verify(&self, path: &Path, device: u64, inode: u64) -> Result<()> {
        if self.inode == (Inode { device, number: inode }) {
            return Ok(());
        }
        Err(QuartersError::new(
            ErrorKind::Unsupported,
            "a filesystem policy anchor changed during overlap validation",
        )
        .with_hint(format!("retry after changes to {} have stopped", path.display())))
    }
}

fn open_path(path: &Path) -> Result<File> {
    open(
        path,
        OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| QuartersError::io("open filesystem policy identity", path, error.into()))
}

fn inspect(file: &File, path: &Path) -> Result<Metadata> {
    file.metadata()
        .map_err(|error| QuartersError::io("inspect filesystem policy identity", path, error))
}

pub(super) fn existing_anchors(paths: &[PathBuf]) -> Result<Vec<Anchor>> {
    let mut anchors = Vec::new();
    for path in paths {
        match std::fs::symlink_metadata(path) {
            Ok(_) => anchors.push(Anchor::open(path)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(QuartersError::io("inspect reserved policy identity", path, error)),
        }
    }
    Ok(anchors)
}

#[cfg(test)]
mod tests {
    use super::Anchor;
    use std::error::Error;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn identity_overlap_is_bidirectional_and_siblings_are_disjoint() -> Result<(), Box<dyn Error>> {
        let tree = tempfile::tempdir()?;
        let nested = tree.path().join("nested");
        let sibling = tree.path().join("sibling");
        fs::create_dir(&nested)?;
        fs::create_dir(&sibling)?;
        let parent = Anchor::open(tree.path())?;
        let child = Anchor::open(&nested)?;
        assert!(parent.overlaps(&child));
        assert!(child.overlaps(&parent));
        assert!(!child.overlaps(&Anchor::open(&sibling)?));
        Ok(())
    }

    #[test]
    fn hard_link_alias_matches_the_reserved_file_inode() -> Result<(), Box<dyn Error>> {
        let tree = tempfile::tempdir()?;
        let reserved = tree.path().join("reserved");
        let alias = tree.path().join("alias");
        fs::write(&reserved, b"protected")?;
        fs::hard_link(&reserved, &alias)?;
        let root = Anchor::open(&reserved)?;
        let link = Anchor::open(&alias)?;
        assert!(root.overlaps(&link));
        assert!(link.overlaps(&root));
        assert_eq!(link.metadata.nlink(), 2);
        Ok(())
    }
}
