//! Descriptor-relative canonical artifact verification.

use super::model::{ArtifactCounts, ContentIntegrity, INTEGRITY_ALGORITHM};
use crate::store::lifecycle::CloneLimits;
use crate::text::escape_untrusted_text_bounded_bytes;
use crate::{ErrorKind, QuartersError, Result};
use nix::dir::Dir;
use nix::fcntl::{AtFlags, FcntlArg, OFlag, fcntl, openat, readlinkat};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat};
use nix::unistd::Uid;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const CONTEXT: &str = "org.agenxy.quarters.artifact.quarters-canonical-v1";
const TAG_ROOT: u8 = 0x52;
const TAG_DIRECTORY: u8 = 0x44;
const TAG_FILE: u8 = 0x46;
const TAG_SYMLINK: u8 = 0x4c;
const TAG_TERMINAL: u8 = 0x00;

pub(super) fn digest_home(home: &Path) -> Result<ContentIntegrity> {
    let root = Dir::open(
        home,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| QuartersError::new(ErrorKind::CorruptState, "could not open artifact home").with_source(error))?;
    let root_metadata = fstat(&root).map_err(|error| artifact_error("inspect artifact home", &[], error))?;
    verify_owner(&root_metadata, &[])?;
    let mut verifier = Verifier {
        hasher: blake3::Hasher::new_derive_key(CONTEXT),
        counts: ArtifactCounts::default(),
        limits: CloneLimits::ALPHA,
        buffered_entries: 0,
        current_uid: Uid::current().as_raw(),
    };
    verifier.hasher.update(&[TAG_ROOT]);
    verifier.hash_mode(root_metadata.st_mode);
    verifier.walk_directory(root, &[], 0)?;
    verifier.hash_terminal();
    Ok(ContentIntegrity {
        algorithm: INTEGRITY_ALGORITHM.to_owned(),
        digest: verifier.hasher.finalize().to_hex().to_string(),
        counts: verifier.counts,
    })
}

pub(super) fn verify_home(home: &Path, expected: &ContentIntegrity) -> Result<()> {
    if expected.algorithm != INTEGRITY_ALGORITHM {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            format!("unsupported artifact integrity algorithm '{}'", expected.algorithm),
        ));
    }
    let actual = digest_home(home)?;
    if actual == *expected {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "artifact content does not match its canonical integrity record",
    )
    .with_hint("do not instantiate or roll back from this artifact; preserve it for inspection"))
}

struct Verifier {
    hasher: blake3::Hasher,
    counts: ArtifactCounts,
    limits: CloneLimits,
    buffered_entries: u64,
    current_uid: u32,
}

impl Verifier {
    fn walk_directory(&mut self, mut directory: Dir, relative: &[OsString], depth: u32) -> Result<()> {
        let names = self.directory_names(&mut directory, relative)?;
        for name in names {
            self.buffered_entries = self.buffered_entries.saturating_sub(1);
            let path = self.child_path(relative, &name)?;
            let metadata = fstatat(&directory, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|error| artifact_error("inspect artifact entry", &path, error))?;
            verify_owner_with_uid(&metadata, &path, self.current_uid)?;
            let kind = SFlag::from_bits_truncate(metadata.st_mode);
            if kind == SFlag::S_IFDIR {
                self.visit_directory(&directory, &name, &path, depth, &metadata)?;
            } else if kind == SFlag::S_IFREG {
                self.visit_file(&directory, &name, &path, &metadata)?;
            } else if kind == SFlag::S_IFLNK {
                self.visit_symlink(&directory, &name, &path, &metadata)?;
            } else {
                return Err(entry_error("artifact contains an unsupported special entry", &path));
            }
        }
        Ok(())
    }

    fn visit_directory(
        &mut self,
        parent: &Dir,
        name: &OsStr,
        path: &[OsString],
        depth: u32,
        expected: &FileStat,
    ) -> Result<()> {
        let next_depth = depth.saturating_add(1);
        if next_depth > self.limits.depth {
            return Err(limit_error(
                "artifact directory depth",
                u64::from(next_depth),
                u64::from(self.limits.depth),
            ));
        }
        let directory = Dir::openat(
            parent,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| artifact_error("open artifact directory", path, error))?;
        let opened =
            fstat(&directory).map_err(|error| artifact_error("inspect opened artifact directory", path, error))?;
        verify_identity(expected, &opened, SFlag::S_IFDIR, path)?;
        self.note_entry()?;
        self.counts.directories = self.counts.directories.saturating_add(1);
        self.hasher.update(&[TAG_DIRECTORY]);
        self.hash_path(path)?;
        self.hash_mode(expected.st_mode);
        self.walk_directory(directory, path, next_depth)?;
        let after = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|error| artifact_error("recheck artifact directory", path, error))?;
        verify_identity(expected, &after, SFlag::S_IFDIR, path)
    }

    fn visit_file(&mut self, parent: &Dir, name: &OsStr, path: &[OsString], expected: &FileStat) -> Result<()> {
        if expected.st_nlink != 1 {
            return Err(entry_error("artifact contains a multiply-linked regular file", path));
        }
        let length = u64::try_from(expected.st_size)
            .map_err(|error| entry_error("artifact file has an invalid logical length", path).with_source(error))?;
        if length > self.limits.file_bytes {
            return Err(limit_error("artifact file bytes", length, self.limits.file_bytes));
        }
        self.add_logical_bytes(length)?;
        let owned = openat(
            parent,
            name,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| artifact_error("open artifact file", path, error))?;
        let opened = fstat(&owned).map_err(|error| artifact_error("inspect opened artifact file", path, error))?;
        verify_identity(expected, &opened, SFlag::S_IFREG, path)?;
        let flags = fcntl(&owned, FcntlArg::F_GETFL)
            .map(OFlag::from_bits_truncate)
            .map_err(|error| artifact_error("inspect artifact file flags", path, error))?;
        fcntl(&owned, FcntlArg::F_SETFL(flags - OFlag::O_NONBLOCK))
            .map_err(|error| artifact_error("prepare artifact file", path, error))?;
        self.note_entry()?;
        self.counts.files = self.counts.files.saturating_add(1);
        self.hasher.update(&[TAG_FILE]);
        self.hash_path(path)?;
        self.hash_mode(expected.st_mode);
        self.hasher.update(&length.to_be_bytes());
        let mut file = File::from(owned);
        self.hash_file(&mut file, length, path)?;
        let after = fstat(&file).map_err(|error| artifact_error("recheck artifact file", path, error))?;
        verify_identity(expected, &after, SFlag::S_IFREG, path)
    }

    fn visit_symlink(&mut self, parent: &Dir, name: &OsStr, path: &[OsString], expected: &FileStat) -> Result<()> {
        let target = readlinkat(parent, name).map_err(|error| artifact_error("read artifact symlink", path, error))?;
        let length = u64::try_from(target.as_bytes().len()).map_err(conversion_error)?;
        if length > self.limits.symlink_target_bytes {
            return Err(limit_error(
                "artifact symlink-target bytes",
                length,
                self.limits.symlink_target_bytes,
            ));
        }
        self.add_logical_bytes(length)?;
        self.note_entry()?;
        self.counts.symlinks = self.counts.symlinks.saturating_add(1);
        self.hasher.update(&[TAG_SYMLINK]);
        self.hash_path(path)?;
        self.hasher.update(&length.to_be_bytes());
        self.hasher.update(target.as_bytes());
        let after = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|error| artifact_error("recheck artifact symlink", path, error))?;
        verify_identity(expected, &after, SFlag::S_IFLNK, path)
    }

    fn directory_names(&mut self, directory: &mut Dir, relative: &[OsString]) -> Result<Vec<OsString>> {
        let accounted = self.counts.entries.saturating_add(self.buffered_entries);
        let available = self.limits.entries.saturating_sub(accounted);
        let maximum = usize::try_from(available).map_err(conversion_error)?;
        let mut names = Vec::new();
        for entry in directory.iter() {
            let entry = entry.map_err(|error| artifact_error("read artifact directory", relative, error))?;
            let bytes = entry.file_name().to_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            if names.len() >= maximum {
                return Err(limit_error(
                    "artifact entries",
                    accounted
                        .saturating_add(u64::try_from(names.len()).map_err(conversion_error)?)
                        .saturating_add(1),
                    self.limits.entries,
                ));
            }
            names.try_reserve(1).map_err(|error| {
                QuartersError::new(ErrorKind::ResourceLimit, "could not reserve artifact directory listing")
                    .with_source(error)
            })?;
            names.push(OsStr::from_bytes(bytes).to_os_string());
        }
        names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        self.buffered_entries = self
            .buffered_entries
            .saturating_add(u64::try_from(names.len()).map_err(conversion_error)?);
        Ok(names)
    }

    fn child_path(&self, parent: &[OsString], name: &OsStr) -> Result<Vec<OsString>> {
        let component = u64::try_from(name.as_bytes().len()).map_err(conversion_error)?;
        if component > self.limits.component_bytes {
            return Err(limit_error(
                "artifact path-component bytes",
                component,
                self.limits.component_bytes,
            ));
        }
        let mut child = parent.to_vec();
        child.push(name.to_os_string());
        let length = raw_path(&child)?.len();
        let length = u64::try_from(length).map_err(conversion_error)?;
        if length > self.limits.relative_path_bytes {
            return Err(limit_error(
                "artifact relative-path bytes",
                length,
                self.limits.relative_path_bytes,
            ));
        }
        Ok(child)
    }

    fn note_entry(&mut self) -> Result<()> {
        let entries = self.counts.entries.saturating_add(1);
        if entries > self.limits.entries {
            return Err(limit_error("artifact entries", entries, self.limits.entries));
        }
        self.counts.entries = entries;
        Ok(())
    }

    fn add_logical_bytes(&mut self, amount: u64) -> Result<()> {
        let total = self
            .counts
            .logical_bytes
            .checked_add(amount)
            .ok_or_else(|| limit_error("artifact logical bytes", u64::MAX, self.limits.logical_bytes))?;
        if total > self.limits.logical_bytes {
            return Err(limit_error("artifact logical bytes", total, self.limits.logical_bytes));
        }
        self.counts.logical_bytes = total;
        Ok(())
    }

    fn hash_file(&mut self, file: &mut File, expected: u64, path: &[OsString]) -> Result<()> {
        let mut observed = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| entry_error("could not read artifact file", path).with_source(error))?;
            if read == 0 {
                break;
            }
            observed = observed.saturating_add(u64::try_from(read).map_err(conversion_error)?);
            if observed > expected {
                return Err(entry_error("artifact file grew during verification", path));
            }
            self.hasher.update(&buffer[..read]);
        }
        if observed == expected {
            return Ok(());
        }
        Err(entry_error("artifact file changed length during verification", path))
    }

    fn hash_path(&mut self, path: &[OsString]) -> Result<()> {
        let bytes = raw_path(path)?;
        let length = u64::try_from(bytes.len()).map_err(conversion_error)?;
        self.hasher.update(&length.to_be_bytes());
        self.hasher.update(&bytes);
        Ok(())
    }

    fn hash_mode(&mut self, raw_mode: nix::libc::mode_t) {
        let mode = normalized_mode(raw_mode);
        self.hasher.update(&mode.to_be_bytes());
    }

    fn hash_terminal(&mut self) {
        self.hasher.update(&[TAG_TERMINAL]);
        self.hasher.update(&self.counts.entries.to_be_bytes());
        self.hasher.update(&self.counts.directories.to_be_bytes());
        self.hasher.update(&self.counts.files.to_be_bytes());
        self.hasher.update(&self.counts.symlinks.to_be_bytes());
        self.hasher.update(&self.counts.logical_bytes.to_be_bytes());
    }
}

#[cfg(target_os = "linux")]
fn normalized_mode(raw_mode: nix::libc::mode_t) -> u32 {
    raw_mode & 0o777
}

#[cfg(target_os = "macos")]
fn normalized_mode(raw_mode: nix::libc::mode_t) -> u32 {
    u32::from(raw_mode & 0o777)
}

fn raw_path(path: &[OsString]) -> Result<Vec<u8>> {
    let length = path
        .iter()
        .map(|component| component.as_bytes().len())
        .sum::<usize>()
        .saturating_add(path.len().saturating_sub(1));
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| {
        QuartersError::new(ErrorKind::ResourceLimit, "could not reserve canonical artifact path").with_source(error)
    })?;
    for (index, component) in path.iter().enumerate() {
        if index != 0 {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(component.as_bytes());
    }
    Ok(bytes)
}

fn verify_owner(metadata: &FileStat, path: &[OsString]) -> Result<()> {
    verify_owner_with_uid(metadata, path, Uid::current().as_raw())
}

fn verify_owner_with_uid(metadata: &FileStat, path: &[OsString], uid: u32) -> Result<()> {
    if metadata.st_uid == uid {
        return Ok(());
    }
    Err(entry_error("artifact contains an entry owned by another user", path))
}

fn verify_identity(expected: &FileStat, actual: &FileStat, kind: SFlag, path: &[OsString]) -> Result<()> {
    let same = expected.st_dev == actual.st_dev
        && expected.st_ino == actual.st_ino
        && expected.st_uid == actual.st_uid
        && expected.st_gid == actual.st_gid
        && expected.st_mode == actual.st_mode
        && expected.st_nlink == actual.st_nlink
        && expected.st_size == actual.st_size
        && expected.st_mtime == actual.st_mtime
        && expected.st_mtime_nsec == actual.st_mtime_nsec
        && expected.st_ctime == actual.st_ctime
        && expected.st_ctime_nsec == actual.st_ctime_nsec
        && SFlag::from_bits_truncate(actual.st_mode) == kind;
    if same {
        return Ok(());
    }
    Err(entry_error("artifact entry changed during verification", path))
}

fn entry_error(message: &str, path: &[OsString]) -> QuartersError {
    QuartersError::new(ErrorKind::CorruptState, format!("{message} at {}", relative_text(path)))
}

fn artifact_error(message: &str, path: &[OsString], source: nix::errno::Errno) -> QuartersError {
    entry_error(message, path).with_source(source)
}

fn relative_text(path: &[OsString]) -> String {
    let joined = path
        .iter()
        .map(|component| component.to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    escape_untrusted_text_bounded_bytes(&joined, 512)
}

fn limit_error(label: &str, observed: u64, allowed: u64) -> QuartersError {
    QuartersError::new(
        ErrorKind::ResourceLimit,
        format!("{label} {observed} exceeds the limit {allowed}"),
    )
}

fn conversion_error(error: impl std::error::Error + Send + Sync + 'static) -> QuartersError {
    QuartersError::new(
        ErrorKind::System,
        "numeric conversion failed during artifact verification",
    )
    .with_source(error)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    #[test]
    fn canonical_digest_changes_for_bound_content_and_mode() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        fs::write(temporary.path().join("a"), b"one")?;
        fs::set_permissions(temporary.path().join("a"), fs::Permissions::from_mode(0o600))?;
        symlink("a", temporary.path().join("link"))?;
        let first = digest_home(temporary.path())?;
        fs::write(temporary.path().join("a"), b"two")?;
        let second = digest_home(temporary.path())?;
        assert_ne!(first.digest, second.digest);
        assert_eq!(first.counts.entries, 2);
        fs::set_permissions(temporary.path().join("a"), fs::Permissions::from_mode(0o640))?;
        let third = digest_home(temporary.path())?;
        assert_ne!(second.digest, third.digest);
        assert_eq!(second.counts, third.counts);
        Ok(())
    }

    #[test]
    fn verification_rejects_multiply_linked_files() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        fs::write(temporary.path().join("a"), b"state")?;
        fs::hard_link(temporary.path().join("a"), temporary.path().join("b"))?;
        let error = digest_home(temporary.path()).expect_err("hard link must fail");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
        Ok(())
    }
}
