//! Private bundle authentication-key creation and loading.

use super::super::ArtifactId;
use super::model::{ExportKeyReport, FileGeneration};
use crate::{ErrorKind, QuartersError, Result, Store};
use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{Mode, SFlag, fchmod, fstat, fstatat};
use nix::unistd::{UnlinkatFlags, linkat, unlinkat};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

pub(super) const KEY_BYTES: usize = 32;

/// Create and no-clobber publish one private 32-byte bundle authentication key.
///
/// # Errors
///
/// Fails when the absolute destination, private parent, randomness source,
/// filesystem generation or durable publication contract cannot be satisfied.
fn create_export_key(destination: &ExternalPath) -> Result<ExportKeyReport> {
    let parent = &destination.parent;
    let name = &destination.name;
    let temporary = OsString::from(format!(".quarters-key-{}", ArtifactId::generate()?));
    let owned = openat(
        parent,
        temporary.as_os_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| key_error("could not create private key staging", error))?;
    let mut file = File::from(owned);
    let staged = fstat(&file).map_err(|error| key_error("could not inspect private key staging", error))?;
    fchmod(&file, Mode::from_bits_truncate(0o600))
        .map_err(|error| key_error("could not protect private key staging", error))?;
    let result = publish_key(parent, name.as_os_str(), temporary.as_os_str(), &mut file, &staged);
    if result.is_err() {
        let _ignored = unlink_exact(parent, temporary.as_os_str(), &staged);
    }
    let publication_warning = result?;
    Ok(ExportKeyReport {
        created: true,
        bytes: u32::try_from(KEY_BYTES)
            .map_err(|error| QuartersError::new(ErrorKind::System, "key size is unsupported").with_source(error))?,
        publication_warning,
    })
}

impl Store {
    /// Create a private bundle key outside the active Quarters store.
    ///
    /// # Errors
    ///
    /// Fails without publication when the path is unsafe, inside the store or
    /// already exists, or when durable no-clobber publication cannot begin.
    pub fn create_export_key(&self, path: &Path) -> Result<ExportKeyReport> {
        let destination = validate_external_store_path(self, path, "export key")?;
        create_export_key(&destination)
    }
}

fn publish_key(
    parent: &Dir,
    name: &OsStr,
    temporary: &OsStr,
    file: &mut File,
    staged: &nix::sys::stat::FileStat,
) -> Result<Option<String>> {
    let mut bytes = [0_u8; KEY_BYTES];
    getrandom::fill(&mut bytes).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not obtain randomness for an export key").with_source(error)
    })?;
    file.write_all(&bytes)
        .map_err(|error| key_error("could not write private export key", error))?;
    file.sync_all()
        .map_err(|error| key_error("could not sync private export key", error))?;
    linkat(parent, temporary, parent, name, AtFlags::empty()).map_err(|error| {
        let kind = if error == nix::errno::Errno::EEXIST {
            ErrorKind::AlreadyExists
        } else {
            ErrorKind::System
        };
        QuartersError::new(kind, "export key destination already exists or cannot be published").with_source(error)
    })?;
    Ok(complete_link_publication(parent, temporary, staged))
}

pub(super) fn complete_link_publication(
    parent: &Dir,
    temporary: &OsStr,
    staged: &nix::sys::stat::FileStat,
) -> Option<String> {
    let faults = publication_test_faults();
    let cleanup_failed = faults & 0b01 != 0 || unlink_exact(parent, temporary, staged).is_err();
    let durability_failed = faults & 0b10 != 0 || nix::unistd::fsync(parent).is_err();
    match (durability_failed, cleanup_failed) {
        (false, false) => None,
        (true, false) => {
            Some("destination is visible, but parent-directory durability could not be confirmed".to_owned())
        }
        (false, true) => Some("destination is durable, but its hidden staging link could not be removed".to_owned()),
        (true, true) => Some(
            "destination is visible, but parent-directory durability and hidden-staging cleanup could not be confirmed"
                .to_owned(),
        ),
    }
}

#[cfg(test)]
static TEST_PUBLICATION_FAULTS: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(test)]
pub(super) fn set_test_publication_faults(faults: u8) {
    TEST_PUBLICATION_FAULTS.store(faults, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
fn publication_test_faults() -> u8 {
    TEST_PUBLICATION_FAULTS.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(not(test))]
const fn publication_test_faults() -> u8 {
    0
}

pub(super) fn load_key(source: &ExternalPath) -> Result<[u8; KEY_BYTES]> {
    let owned = openat(
        &source.parent,
        source.name.as_os_str(),
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| key_error("could not open export authentication key", error))?;
    let mut file = File::from(owned);
    let before = fstat(&file).map_err(|error| key_error("could not inspect export authentication key", error))?;
    validate_key_metadata(&before)?;
    let mut bytes = [0_u8; KEY_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|error| key_error("could not read export authentication key", error))?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| key_error("could not finish reading export authentication key", error))?
        != 0
    {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "export authentication keys must contain exactly 32 bytes",
        ));
    }
    let after = fstat(&file).map_err(|error| key_error("could not recheck export authentication key", error))?;
    if generation(&before)? != generation(&after)? {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "export authentication key changed while it was read",
        ));
    }
    Ok(bytes)
}

pub(super) fn external_destination(path: &Path) -> Result<(PathBuf, OsString)> {
    if !path.is_absolute() {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "export and key destinations must be absolute paths",
        ));
    }
    let name = path.file_name().ok_or_else(|| {
        QuartersError::new(
            ErrorKind::InvalidInput,
            "destination must have one final path component",
        )
    })?;
    if name.is_empty() || matches!(name.as_bytes(), b"." | b"..") {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "destination must have one ordinary final path component",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| QuartersError::new(ErrorKind::InvalidInput, "destination parent could not be resolved"))?;
    let canonical = parent.canonicalize().map_err(|error| {
        QuartersError::new(ErrorKind::InvalidInput, "destination parent is unavailable").with_source(error)
    })?;
    Ok((canonical, name.to_os_string()))
}

pub(super) fn open_safe_parent(path: &Path) -> Result<Dir> {
    let parent = Dir::open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| key_error("could not retain destination parent", error))?;
    let metadata = fstat(&parent).map_err(|error| key_error("could not inspect destination parent", error))?;
    let current_uid = nix::unistd::Uid::current().as_raw();
    if SFlag::from_bits_truncate(metadata.st_mode) != SFlag::S_IFDIR
        || metadata.st_uid != current_uid
        || metadata.st_mode & 0o022 != 0
    {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "destination parent must be a current-user directory that is not group- or world-writable",
        ));
    }
    Ok(parent)
}

pub(super) struct ExternalPath {
    pub(super) parent: Dir,
    pub(super) name: OsString,
}

pub(super) fn validate_external_store_path(store: &Store, path: &Path, label: &'static str) -> Result<ExternalPath> {
    let (parent, name) = external_destination(path)?;
    let root = resolve_prospective_path(store.root())?;
    if parent == root || parent.starts_with(&root) || parent.join(&name) == root {
        return Err(in_store_error(label));
    }
    let retained = open_safe_parent(&parent)?;
    if descriptor_is_within_store(store, &retained)? {
        return Err(in_store_error(label));
    }
    Ok(ExternalPath { parent: retained, name })
}

fn resolve_prospective_path(path: &Path) -> Result<PathBuf> {
    match path.canonicalize() {
        Ok(resolved) => return Ok(resolved),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(
                QuartersError::new(ErrorKind::CorruptState, "Quarters root could not be resolved").with_source(error),
            );
        }
    }
    let normalized = normalize_absolute(path)?;
    let mut cursor = normalized.as_path();
    let mut missing = Vec::new();
    loop {
        match cursor.canonicalize() {
            Ok(mut resolved) => {
                for component in missing.iter().rev() {
                    resolved.push(component);
                }
                return normalize_absolute(&resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = cursor.file_name().ok_or_else(|| {
                    QuartersError::new(ErrorKind::CorruptState, "Quarters root could not be resolved")
                })?;
                missing.push(name.to_os_string());
                cursor = cursor.parent().ok_or_else(|| {
                    QuartersError::new(ErrorKind::CorruptState, "Quarters root could not be resolved")
                })?;
            }
            Err(error) => {
                return Err(
                    QuartersError::new(ErrorKind::CorruptState, "Quarters root could not be resolved")
                        .with_source(error),
                );
            }
        }
    }
}

fn normalize_absolute(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                let _removed = normalized.pop();
            }
            Component::Normal(value) => normalized.push(value),
            Component::Prefix(_) => {
                return Err(QuartersError::new(
                    ErrorKind::CorruptState,
                    "Quarters root uses an unsupported path prefix",
                ));
            }
        }
    }
    Ok(normalized)
}

fn descriptor_is_within_store(store: &Store, parent: &Dir) -> Result<bool> {
    let root_metadata = match std::fs::symlink_metadata(store.root()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(key_error("could not inspect the active Quarters root", error)),
    };
    crate::store_policy::validate_store_root(store.root(), &root_metadata)?;
    let root = match Dir::open(
        store.root(),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(root) => root,
        Err(Errno::ENOENT) => return Ok(false),
        Err(error) => return Err(key_error("could not retain the active Quarters root", error)),
    };
    let root_stat = fstat(&root).map_err(|error| key_error("could not inspect the active Quarters root", error))?;
    let owned = openat(
        parent,
        OsStr::new("."),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| key_error("could not retain the external parent identity", error))?;
    let mut current =
        Dir::from_fd(owned).map_err(|error| key_error("could not inspect the external parent identity", error))?;
    for _depth in 0..1_024 {
        let current_stat = fstat(&current).map_err(|error| key_error("could not inspect parent ancestry", error))?;
        if same_directory(&current_stat, &root_stat) {
            return Ok(true);
        }
        let owned_parent = openat(
            &current,
            OsStr::new(".."),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| key_error("could not walk parent ancestry", error))?;
        let next = Dir::from_fd(owned_parent).map_err(|error| key_error("could not retain parent ancestry", error))?;
        let next_stat = fstat(&next).map_err(|error| key_error("could not inspect parent ancestry", error))?;
        if same_directory(&current_stat, &next_stat) {
            return Ok(false);
        }
        current = next;
    }
    Err(QuartersError::new(
        ErrorKind::ResourceLimit,
        "destination parent ancestry exceeds the fixed inspection limit",
    ))
}

fn same_directory(left: &nix::sys::stat::FileStat, right: &nix::sys::stat::FileStat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn in_store_error(label: &'static str) -> QuartersError {
    let message = if label == "export key" {
        "export keys must live outside the Quarters store".to_owned()
    } else {
        format!("{label} destinations must be outside the Quarters store")
    };
    QuartersError::new(ErrorKind::InvalidInput, message)
}

pub(super) fn generation(stat: &nix::sys::stat::FileStat) -> Result<FileGeneration> {
    Ok(FileGeneration {
        device: device_number(stat.st_dev),
        inode: stat.st_ino,
        length: u64::try_from(stat.st_size).map_err(|error| {
            QuartersError::new(ErrorKind::CorruptState, "file has an invalid length").with_source(error)
        })?,
        modified_seconds: stat.st_mtime,
        modified_nanoseconds: stat.st_mtime_nsec,
        changed_seconds: stat.st_ctime,
        changed_nanoseconds: stat.st_ctime_nsec,
    })
}

#[cfg(target_os = "linux")]
pub(super) const fn device_number(value: nix::libc::dev_t) -> u64 {
    value
}

#[cfg(target_os = "macos")]
pub(super) fn device_number(value: nix::libc::dev_t) -> u64 {
    u64::from(value.cast_unsigned())
}

fn validate_key_metadata(stat: &nix::sys::stat::FileStat) -> Result<()> {
    let kind = SFlag::from_bits_truncate(stat.st_mode);
    let valid_length = usize::try_from(stat.st_size).ok() == Some(KEY_BYTES);
    if kind == SFlag::S_IFREG
        && stat.st_uid == nix::unistd::Uid::current().as_raw()
        && stat.st_nlink == 1
        && stat.st_mode & 0o777 == 0o600
        && valid_length
    {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::InvalidInput,
        "export authentication key must be a current-user, single-link, mode-0600 regular file containing exactly 32 bytes",
    ))
}

pub(super) fn unlink_exact(parent: &Dir, name: &OsStr, expected: &nix::sys::stat::FileStat) -> Result<()> {
    let current = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|error| key_error("could not recheck private staging", error))?;
    if current.st_dev != expected.st_dev || current.st_ino != expected.st_ino {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "private staging path changed; it was retained for inspection",
        ));
    }
    unlinkat(parent, name, UnlinkatFlags::NoRemoveDir)
        .map_err(|error| key_error("could not remove private staging link", error))
}

fn key_error(message: &'static str, error: impl std::error::Error + Send + Sync + 'static) -> QuartersError {
    QuartersError::new(ErrorKind::System, message).with_source(error)
}

use std::os::unix::ffi::OsStrExt;
