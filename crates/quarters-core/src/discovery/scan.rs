// SPDX-License-Identifier: GPL-3.0-or-later
use super::{DiscoveryLimits, DiscoverySelector, EntryIdentity, EntryRecord, RootIdentity, Snapshot};
use crate::{ErrorKind, QuartersError, Result};
use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat};
use nix::unistd::Uid;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Instant;

pub(super) fn scan(roots: &[(DiscoverySelector, &Path)], limits: DiscoveryLimits) -> Result<Snapshot> {
    let mut combined = Snapshot::default();
    for (selector, root) in roots {
        let mut scanner = Scanner::new(limits);
        let (mut directory, identity, expected) = open_root(root, *selector)?;
        scanner.snapshot.root_identities.insert(*selector, identity);
        scanner.walk(&mut directory, *selector, &[], 0)?;
        scanner.recheck_directory(&directory, &expected);
        let count = u64::try_from(scanner.snapshot.entries.len()).unwrap_or(u64::MAX);
        scanner.snapshot.roots.insert(*selector, count);
        scanner
            .snapshot
            .root_complete
            .insert(*selector, scanner.snapshot.complete);
        scanner
            .snapshot
            .root_bounds_exceeded
            .insert(*selector, scanner.snapshot.bounds_exceeded);
        merge(&mut combined, scanner.snapshot)?;
    }
    Ok(combined)
}

fn merge(combined: &mut Snapshot, part: Snapshot) -> Result<()> {
    combined.entries.try_reserve(part.entries.len()).map_err(|error| {
        QuartersError::new(ErrorKind::ResourceLimit, "could not reserve combined discovery entries").with_source(error)
    })?;
    for (key, record) in part.entries {
        if combined.entries.insert(key, record).is_some() {
            combined.entry_key_collisions = combined.entry_key_collisions.saturating_add(1);
            combined.complete = false;
        }
    }
    combined.roots.extend(part.roots);
    combined.root_identities.extend(part.root_identities);
    combined.root_complete.extend(part.root_complete);
    combined.root_bounds_exceeded.extend(part.root_bounds_exceeded);
    combined.complete &= part.complete;
    combined.bounds_exceeded |= part.bounds_exceeded;
    combined.unreadable_directories = combined
        .unreadable_directories
        .saturating_add(part.unreadable_directories);
    combined
        .unreadable_classes
        .saturating_add_assign(&part.unreadable_classes);
    combined.unstable_entries = combined.unstable_entries.saturating_add(part.unstable_entries);
    combined.foreign_owned = combined.foreign_owned.saturating_add(part.foreign_owned);
    combined.metadata_errors = combined.metadata_errors.saturating_add(part.metadata_errors);
    combined.entry_key_collisions = combined.entry_key_collisions.saturating_add(part.entry_key_collisions);
    Ok(())
}

struct Scanner {
    limits: DiscoveryLimits,
    started: Instant,
    snapshot: Snapshot,
    pending_names: u64,
    pending_name_bytes: u64,
}

impl Scanner {
    fn new(limits: DiscoveryLimits) -> Self {
        Self {
            limits,
            started: Instant::now(),
            snapshot: Snapshot::default(),
            pending_names: 0,
            pending_name_bytes: 0,
        }
    }

    fn walk(
        &mut self,
        directory: &mut Dir,
        selector: DiscoverySelector,
        relative: &[OsString],
        depth: u32,
    ) -> Result<()> {
        let names = self.names(directory)?;
        for name in names {
            self.release_pending_name(&name);
            if self.limit_reached(relative, &name, depth) {
                return Ok(());
            }
            let mut path = relative.to_vec();
            path.push(name.clone());
            let metadata = match fstatat(&*directory, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
                Ok(metadata) => metadata,
                Err(Errno::ENOENT | Errno::ELOOP | Errno::ENOTDIR) => {
                    self.snapshot.unstable_entries = self.snapshot.unstable_entries.saturating_add(1);
                    self.snapshot.complete = false;
                    continue;
                }
                Err(_error) => {
                    self.snapshot.metadata_errors = self.snapshot.metadata_errors.saturating_add(1);
                    self.snapshot.complete = false;
                    continue;
                }
            };
            self.record(selector, &path, &metadata)?;
            if SFlag::from_bits_truncate(metadata.st_mode) == SFlag::S_IFDIR {
                self.visit_directory(&*directory, selector, &name, &path, depth, &metadata)?;
            }
        }
        Ok(())
    }

    fn names(&mut self, directory: &mut Dir) -> Result<Vec<OsString>> {
        if self.snapshot.bounds_exceeded {
            return Ok(Vec::new());
        }
        let recorded = u64::try_from(self.snapshot.entries.len()).unwrap_or(u64::MAX);
        let remaining = self
            .limits
            .entries
            .saturating_sub(recorded.saturating_add(self.pending_names));
        let capacity = usize::try_from(remaining.min(1_024)).unwrap_or(0);
        let mut names = Vec::new();
        names.try_reserve(capacity).map_err(|error| {
            QuartersError::new(ErrorKind::ResourceLimit, "could not reserve bounded discovery memory")
                .with_source(error)
        })?;
        for entry in directory.iter() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_error) => {
                    self.snapshot.metadata_errors = self.snapshot.metadata_errors.saturating_add(1);
                    self.snapshot.complete = false;
                    break;
                }
            };
            let bytes = entry.file_name().to_bytes();
            if !matches!(bytes, b"." | b"..") {
                let name_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                let timed_out = self.started.elapsed().as_millis() >= u128::from(self.limits.phase_milliseconds);
                let exceeds_entries = u64::try_from(names.len()).unwrap_or(u64::MAX) >= remaining;
                let exceeds_name_bytes =
                    self.pending_name_bytes.saturating_add(name_bytes) > self.limits.pending_name_bytes;
                if timed_out || exceeds_entries || exceeds_name_bytes {
                    self.snapshot.bounds_exceeded = true;
                    self.snapshot.complete = false;
                    break;
                }
                names.try_reserve(1).map_err(|error| {
                    QuartersError::new(ErrorKind::ResourceLimit, "could not reserve bounded discovery names")
                        .with_source(error)
                })?;
                names.push(OsStr::from_bytes(bytes).to_os_string());
                self.pending_names = self.pending_names.saturating_add(1);
                self.pending_name_bytes = self.pending_name_bytes.saturating_add(name_bytes);
            }
        }
        Ok(names)
    }

    fn release_pending_name(&mut self, name: &OsStr) {
        self.pending_names = self.pending_names.saturating_sub(1);
        self.pending_name_bytes = self
            .pending_name_bytes
            .saturating_sub(u64::try_from(name.as_bytes().len()).unwrap_or(u64::MAX));
    }

    fn limit_reached(&mut self, parent: &[OsString], name: &OsStr, depth: u32) -> bool {
        let path_bytes = parent
            .iter()
            .map(|value| value.as_bytes().len().saturating_add(1))
            .sum::<usize>()
            .saturating_add(name.as_bytes().len());
        let timed_out = self.started.elapsed().as_millis() >= u128::from(self.limits.phase_milliseconds);
        let exceeded = self.snapshot.bounds_exceeded
            || u64::try_from(self.snapshot.entries.len()).unwrap_or(u64::MAX) >= self.limits.entries
            || depth.saturating_add(1) > self.limits.depth
            || u64::try_from(path_bytes).unwrap_or(u64::MAX) > self.limits.relative_path_bytes
            || timed_out;
        if exceeded {
            self.snapshot.bounds_exceeded = true;
            self.snapshot.complete = false;
        }
        exceeded
    }

    fn record(&mut self, selector: DiscoverySelector, path: &[OsString], metadata: &FileStat) -> Result<()> {
        if metadata.st_uid != Uid::current().as_raw() {
            self.snapshot.foreign_owned = self.snapshot.foreign_owned.saturating_add(1);
        }
        self.snapshot.entries.try_reserve(1).map_err(|error| {
            QuartersError::new(ErrorKind::ResourceLimit, "could not reserve bounded discovery entries")
                .with_source(error)
        })?;
        let key = entry_key(selector, path);
        let class = super::classify::classify(selector, path, metadata.st_mode);
        let collision = self
            .snapshot
            .entries
            .insert(
                key,
                EntryRecord {
                    class,
                    identity: EntryIdentity::from_stat(metadata),
                },
            )
            .is_some();
        if collision {
            self.snapshot.entry_key_collisions = self.snapshot.entry_key_collisions.saturating_add(1);
            self.snapshot.complete = false;
        }
        Ok(())
    }

    fn visit_directory(
        &mut self,
        parent: &Dir,
        selector: DiscoverySelector,
        name: &OsStr,
        path: &[OsString],
        depth: u32,
        metadata: &FileStat,
    ) -> Result<()> {
        if metadata.st_mode & 0o500 != 0o500 {
            self.note_unreadable(selector, path, metadata.st_mode);
            self.snapshot.complete = false;
            return Ok(());
        }
        let mut child = match Dir::openat(
            parent,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(child) => child,
            Err(Errno::EACCES) => {
                self.note_unreadable(selector, path, metadata.st_mode);
                self.snapshot.complete = false;
                return Ok(());
            }
            Err(Errno::ENOENT | Errno::ELOOP | Errno::ENOTDIR) => {
                self.snapshot.unstable_entries = self.snapshot.unstable_entries.saturating_add(1);
                self.snapshot.complete = false;
                return Ok(());
            }
            Err(_error) => {
                self.snapshot.metadata_errors = self.snapshot.metadata_errors.saturating_add(1);
                self.snapshot.complete = false;
                return Ok(());
            }
        };
        let opened = match fstat(&child) {
            Ok(opened) => opened,
            Err(_error) => {
                self.snapshot.metadata_errors = self.snapshot.metadata_errors.saturating_add(1);
                self.snapshot.complete = false;
                return Ok(());
            }
        };
        let expected = EntryIdentity::from_stat(metadata);
        let same_directory = EntryIdentity::from_stat(&opened) == expected
            && SFlag::from_bits_truncate(opened.st_mode) == SFlag::S_IFDIR;
        if !same_directory {
            self.snapshot.unstable_entries = self.snapshot.unstable_entries.saturating_add(1);
            self.snapshot.complete = false;
            return Ok(());
        }
        self.walk(&mut child, selector, path, depth.saturating_add(1))?;
        self.recheck_directory(&child, &expected);
        Ok(())
    }

    fn recheck_directory(&mut self, directory: &Dir, expected: &EntryIdentity) {
        match fstat(directory) {
            Ok(after) if EntryIdentity::from_stat(&after) == *expected => {}
            Ok(_after) => {
                self.snapshot.unstable_entries = self.snapshot.unstable_entries.saturating_add(1);
                self.snapshot.complete = false;
            }
            Err(_error) => {
                self.snapshot.metadata_errors = self.snapshot.metadata_errors.saturating_add(1);
                self.snapshot.complete = false;
            }
        }
    }

    fn note_unreadable(&mut self, selector: DiscoverySelector, path: &[OsString], mode: nix::libc::mode_t) {
        self.snapshot.unreadable_directories = self.snapshot.unreadable_directories.saturating_add(1);
        self.snapshot
            .unreadable_classes
            .increment(super::classify::classify(selector, path, mode));
    }
}

fn open_root(path: &Path, selector: DiscoverySelector) -> Result<(Dir, RootIdentity, EntryIdentity)> {
    let directory = Dir::open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| root_error(selector, error))?;
    let metadata = fstat(&directory).map_err(|error| root_error(selector, error))?;
    let private = metadata.st_mode & 0o777 == 0o700;
    let directory_kind = SFlag::from_bits_truncate(metadata.st_mode) == SFlag::S_IFDIR;
    if directory_kind && metadata.st_uid == Uid::current().as_raw() && private {
        let root_identity = RootIdentity::from_stat(&metadata);
        let scan_identity = EntryIdentity::from_stat(&metadata);
        Ok((directory, root_identity, scan_identity))
    } else {
        Err(QuartersError::new(
            ErrorKind::CorruptState,
            format!(
                "the {} discovery root is not a private current-user directory",
                selector.as_str()
            ),
        ))
    }
}

fn root_error(selector: DiscoverySelector, source: Errno) -> QuartersError {
    QuartersError::new(
        ErrorKind::System,
        format!("could not open the {} discovery root", selector.as_str()),
    )
    .with_source(source)
}

fn entry_key(selector: DiscoverySelector, path: &[OsString]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"quarters-discovery-entry-v1\0");
    hasher.update(selector.as_str().as_bytes());
    for component in path {
        let bytes = component.as_bytes();
        hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(bytes);
    }
    *hasher.finalize().as_bytes()
}
