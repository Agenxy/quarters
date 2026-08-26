//! Recovery-safe removal for private owner-controlled staging trees.

use crate::store_policy::validate_private_dir;
use crate::{QuartersError, Result};
use nix::dir::Dir;
use nix::fcntl::OFlag;
use nix::sys::stat::{FchmodatFlags, Mode, SFlag, fchmod, fchmodat, fstat, lstat};
use nix::unistd::Uid;
use std::fs;
use std::path::Path;

const MAX_PRIVATE_REMOVAL_DEPTH: u32 = 256;
const MAX_PRIVATE_REMOVAL_DIRECTORIES: usize = 131_072;

pub(crate) fn remove_tree_restoring_owner_access(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(QuartersError::io("inspect private removal tree", path, error)),
    };
    validate_private_dir(path, &metadata)?;
    restore_tree_access(path)?;
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(QuartersError::io("remove private recovery tree", path, error)),
    }
}

fn restore_tree_access(root: &Path) -> Result<()> {
    let mut pending = vec![(root.to_path_buf(), 0_u32)];
    let mut observed = 0_usize;
    while let Some((path, depth)) = pending.pop() {
        if depth > MAX_PRIVATE_REMOVAL_DEPTH {
            return Err(cleanup_limit_error("directory depth"));
        }
        if !restore_directory_access(&path)? {
            continue;
        }
        collect_child_directories(&path, depth, &mut pending, &mut observed)?;
    }
    Ok(())
}

fn restore_directory_access(path: &Path) -> Result<bool> {
    let expected = match lstat(path) {
        Ok(metadata) => metadata,
        Err(nix::errno::Errno::ENOENT) => return Ok(false),
        Err(error) => {
            return Err(
                QuartersError::new(crate::ErrorKind::System, "could not inspect private removal entry")
                    .with_source(error),
            );
        }
    };
    if SFlag::from_bits_truncate(expected.st_mode) != SFlag::S_IFDIR {
        return Ok(false);
    }
    if expected.st_uid != Uid::current().as_raw() {
        return Err(QuartersError::new(
            crate::ErrorKind::CorruptState,
            "a private removal tree contains a directory owned by another user",
        ));
    }
    let mode = Mode::from_bits_truncate(expected.st_mode);
    let needs_access = !mode.contains(Mode::S_IRWXU);
    let directory = match open_cleanup_directory(path) {
        Ok(directory) => directory,
        Err(nix::errno::Errno::ENOENT) => return Ok(false),
        Err(nix::errno::Errno::EACCES) if needs_access => {
            if !restore_path_access_nofollow(path, mode)? {
                return Ok(false);
            }
            match open_cleanup_directory(path) {
                Ok(directory) => directory,
                Err(nix::errno::Errno::ENOENT) => return Ok(false),
                Err(error) => {
                    return Err(QuartersError::new(
                        crate::ErrorKind::System,
                        "could not open restored cleanup directory",
                    )
                    .with_source(error));
                }
            }
        }
        Err(error) => {
            return Err(
                QuartersError::new(crate::ErrorKind::System, "could not open private cleanup directory")
                    .with_source(error),
            );
        }
    };
    let actual = fstat(&directory).map_err(|error| {
        QuartersError::new(crate::ErrorKind::System, "could not inspect private cleanup directory").with_source(error)
    })?;
    if actual.st_dev != expected.st_dev
        || actual.st_ino != expected.st_ino
        || actual.st_uid != expected.st_uid
        || SFlag::from_bits_truncate(actual.st_mode) != SFlag::S_IFDIR
    {
        return Err(QuartersError::new(
            crate::ErrorKind::CorruptState,
            "a private cleanup directory changed while it was being inspected",
        ));
    }
    if needs_access {
        fchmod(&directory, mode | Mode::S_IRWXU).map_err(|error| {
            QuartersError::new(crate::ErrorKind::System, "could not restore owner access for cleanup")
                .with_source(error)
        })?;
    }
    Ok(true)
}

fn collect_child_directories(
    path: &Path,
    depth: u32,
    pending: &mut Vec<(std::path::PathBuf, u32)>,
    observed: &mut usize,
) -> Result<()> {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(QuartersError::io("read private removal tree", path, error)),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(QuartersError::io("read private removal entry", path, error)),
        };
        let entry_metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(QuartersError::io("inspect private removal entry", &entry.path(), error)),
        };
        if entry_metadata.file_type().is_dir() {
            *observed = observed.saturating_add(1);
            if *observed > MAX_PRIVATE_REMOVAL_DIRECTORIES {
                return Err(cleanup_limit_error("directory count"));
            }
            pending.push((entry.path(), depth.saturating_add(1)));
        }
    }
    Ok(())
}

fn cleanup_limit_error(limit: &str) -> QuartersError {
    QuartersError::new(
        crate::ErrorKind::ResourceLimit,
        format!("private cleanup tree exceeds the supported {limit}"),
    )
    .with_hint("inspect the retained retired directory and remove it manually only after confirming its exact path")
}

fn open_cleanup_directory(path: &Path) -> nix::Result<Dir> {
    Dir::open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
}

fn restore_path_access_nofollow(path: &Path, mode: Mode) -> Result<bool> {
    let parent_path = path.parent().ok_or_else(|| {
        QuartersError::new(
            crate::ErrorKind::CorruptState,
            "private cleanup path has no parent directory",
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        QuartersError::new(
            crate::ErrorKind::CorruptState,
            "private cleanup path has no final component",
        )
    })?;
    let parent = match open_cleanup_directory(parent_path) {
        Ok(parent) => parent,
        Err(nix::errno::Errno::ENOENT) => return Ok(false),
        Err(error) => {
            return Err(
                QuartersError::new(crate::ErrorKind::System, "could not open private cleanup parent")
                    .with_source(error),
            );
        }
    };
    match fchmodat(&parent, name, mode | Mode::S_IRWXU, FchmodatFlags::NoFollowSymlink) {
        Ok(()) => Ok(true),
        Err(nix::errno::Errno::ENOENT) => Ok(false),
        Err(error) => Err(
            QuartersError::new(crate::ErrorKind::System, "could not restore no-follow cleanup access")
                .with_source(error),
        ),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn cleanup_depth_is_bounded_without_deleting_the_root() {
        let temporary = TempDir::new().expect("temporary directory");
        let root = temporary.path().join("private");
        fs::create_dir(&root).expect("create private root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("protect private root");
        let mut nested = root.clone();
        for _ in 0..=MAX_PRIVATE_REMOVAL_DEPTH {
            nested.push("d");
            fs::create_dir(&nested).expect("create deep private directory");
        }

        let error = remove_tree_restoring_owner_access(&root).expect_err("deep cleanup must fail closed");
        assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit);
        assert!(root.is_dir());
    }
}
