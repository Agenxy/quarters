//! Descriptor-relative lifecycle tree walk.

mod support;
#[cfg(test)]
pub(super) mod test_support;

use super::policy::CloneReport;
use crate::text::escape_untrusted_text_bounded_bytes;
use crate::{ErrorKind, QuartersError, Result};
use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{AtFlags, FcntlArg, OFlag, fcntl, openat, readlinkat};
use nix::sys::stat::{FileStat, Mode, SFlag, fchmod, fstat, fstatat, mkdirat};
use nix::unistd::{Uid, fsync, symlinkat};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use support::{child_path, directory_names};

pub(crate) fn walk_home(
    source_home: &Path,
    destination_home: Option<&Path>,
    report: &mut CloneReport,
    control: &WalkControl,
) -> Result<()> {
    let source = open_root(source_home, "open source home")?;
    let destination = destination_home
        .map(|path| open_root(path, "open staging home"))
        .transpose()?;
    let mut walker = Walker::new(report, control);
    let _root_post_read = walker.walk_directory(source, destination, &[], 0)?;
    walker.finish();
    Ok(())
}

pub(crate) struct WalkControl {
    pub(crate) artifact_source: bool,
    pub(crate) recreate_cache_roots: bool,
    #[cfg(test)]
    pub(super) abort_mid_copy: bool,
    #[cfg(test)]
    pub(super) mutation: Option<test_support::TestMutation>,
}

impl Default for WalkControl {
    fn default() -> Self {
        Self {
            artifact_source: false,
            recreate_cache_roots: true,
            #[cfg(test)]
            abort_mid_copy: false,
            #[cfg(test)]
            mutation: None,
        }
    }
}

impl WalkControl {
    pub(crate) fn for_artifact() -> Self {
        Self {
            artifact_source: true,
            recreate_cache_roots: false,
            #[cfg(test)]
            abort_mid_copy: false,
            #[cfg(test)]
            mutation: None,
        }
    }
}

struct Walker<'a> {
    report: &'a mut CloneReport,
    cache_roots: Vec<Vec<OsString>>,
    excluded_cache_roots: BTreeSet<Vec<OsString>>,
    symlinks_by_cache_root: BTreeMap<Vec<OsString>, u64>,
    buffered_entries: u64,
    current_uid: u32,
    control: &'a WalkControl,
}

impl<'a> Walker<'a> {
    fn new(report: &'a mut CloneReport, control: &'a WalkControl) -> Self {
        let mut cache_roots = vec![vec![OsString::from(".cache")]];
        cache_roots.extend(
            crate::platform::derived_cache_directories()
                .iter()
                .map(|path| path.split('/').map(OsString::from).collect()),
        );
        Self {
            report,
            cache_roots,
            excluded_cache_roots: BTreeSet::new(),
            symlinks_by_cache_root: BTreeMap::new(),
            buffered_entries: 0,
            current_uid: Uid::current().as_raw(),
            control,
        }
    }

    fn walk_directory(
        &mut self,
        mut source: Dir,
        destination: Option<Dir>,
        relative: &[OsString],
        depth: u32,
    ) -> Result<FileStat> {
        let accounted = self.report.counts.entries.saturating_add(self.buffered_entries);
        let available = self.report.limits.entries.saturating_sub(accounted);
        let names = directory_names(&mut source, relative, available, accounted, self.report.limits.entries)?;
        self.buffered_entries = self
            .buffered_entries
            .saturating_add(u64::try_from(names.len()).map_err(conversion_error)?);
        for name in names {
            self.buffered_entries = self.buffered_entries.saturating_sub(1);
            let path = child_path(relative, &name, self.report)?;
            let metadata = entry_metadata(&source, &name, &path)?;
            #[cfg(test)]
            if let Some(mutation) = &self.control.mutation {
                mutation.apply_before_open_if_selected(&path)?;
            }
            self.note_entry()?;
            if self.is_excluded_cache(&path) {
                self.exclude_cache(destination.as_ref(), &name, &path)?;
                #[cfg(test)]
                self.maybe_abort_after_entry()?;
                continue;
            }
            if metadata.st_uid != self.current_uid {
                self.report.exclusions.foreign_owned += 1;
                #[cfg(test)]
                self.maybe_abort_after_entry()?;
                continue;
            }
            let kind = SFlag::from_bits_truncate(metadata.st_mode);
            if kind == SFlag::S_IFDIR {
                self.visit_directory(&source, destination.as_ref(), &name, &path, depth, &metadata)?;
            } else if kind == SFlag::S_IFREG {
                self.visit_file(&source, destination.as_ref(), &name, &path, &metadata)?;
            } else if kind == SFlag::S_IFLNK {
                self.visit_symlink(&source, destination.as_ref(), &name, relative, &path, &metadata)?;
            } else {
                self.visit_special(kind, &path)?;
            }
            #[cfg(test)]
            self.maybe_abort_after_entry()?;
        }
        if let Some(destination) = destination {
            apply_directory_mode(&destination, directory_mode(&source, relative)?, relative)?;
        }
        fstat(&source).map_err(|error| nix_error("recheck source directory", relative, error))
    }

    fn visit_directory(
        &mut self,
        source_parent: &Dir,
        destination_parent: Option<&Dir>,
        name: &OsStr,
        path: &[OsString],
        depth: u32,
        metadata: &FileStat,
    ) -> Result<()> {
        if self.control.artifact_source && metadata.st_mode & 0o500 != 0o500 {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                format!(
                    "artifact source directory is not owner-readable and traversable at {}",
                    relative_text(path)
                ),
            )
            .with_hint("grant the owner read and execute permission on this directory, then retry"));
        }
        let next_depth = depth.saturating_add(1);
        if next_depth > self.report.limits.depth {
            return Err(limit_error(
                "directory depth",
                u64::from(next_depth),
                u64::from(self.report.limits.depth),
                path,
            ));
        }
        let source = open_directory_at(source_parent, name, metadata, path)?;
        let destination = destination_parent
            .map(|parent| create_directory_at(parent, name, path))
            .transpose()?;
        self.report.counts.directories += 1;
        let post_read = self.walk_directory(source, destination, path, next_depth)?;
        verify_identity(metadata, &post_read, SFlag::S_IFDIR, path)?;
        let linked = entry_metadata(source_parent, name, path)?;
        verify_identity(metadata, &linked, SFlag::S_IFDIR, path)
    }

    fn visit_file(
        &mut self,
        source_parent: &Dir,
        destination_parent: Option<&Dir>,
        name: &OsStr,
        path: &[OsString],
        metadata: &FileStat,
    ) -> Result<()> {
        let expected_length = file_length(metadata, path)?;
        if expected_length > self.report.limits.file_bytes {
            return Err(limit_error(
                "regular-file bytes",
                expected_length,
                self.report.limits.file_bytes,
                path,
            ));
        }
        let source = open_regular_at(source_parent, name, metadata, path)?;
        #[cfg(test)]
        if let Some(mutation) = &self.control.mutation {
            mutation.apply_after_open_if_selected(path)?;
        }
        let (actual, post_read) = if let Some(parent) = destination_parent {
            copy_regular(
                source,
                parent,
                name,
                Mode::from_bits_truncate(metadata.st_mode),
                self.report,
                path,
            )?
        } else {
            let post_read = fstat(&source).map_err(|error| nix_error("recheck source file", path, error))?;
            (expected_length, post_read)
        };
        verify_identity(metadata, &post_read, SFlag::S_IFREG, path)?;
        let linked = entry_metadata(source_parent, name, path)?;
        verify_identity(metadata, &linked, SFlag::S_IFREG, path)?;
        self.add_logical_bytes(actual, path)?;
        self.report.counts.files += 1;
        if metadata.st_nlink > 1 {
            self.report.exclusions.hard_linked_files_copied_independently += 1;
        }
        Ok(())
    }

    fn visit_symlink(
        &mut self,
        source_parent: &Dir,
        destination_parent: Option<&Dir>,
        name: &OsStr,
        parent_path: &[OsString],
        path: &[OsString],
        metadata: &FileStat,
    ) -> Result<()> {
        let target =
            readlinkat(source_parent, name).map_err(|error| source_entry_error("read symbolic link", path, error))?;
        let target_bytes = u64::try_from(target.as_bytes().len()).map_err(conversion_error)?;
        if target_bytes > self.report.limits.symlink_target_bytes {
            return Err(limit_error(
                "symbolic-link target bytes",
                target_bytes,
                self.report.limits.symlink_target_bytes,
                path,
            ));
        }
        recheck_symlink(source_parent, name, metadata, path)?;
        if is_managed_command_link(path, &target) {
            self.report.exclusions.managed_command_links += 1;
            return Ok(());
        }
        let resolved = resolve_relative_link_target(parent_path, &target).ok_or_else(|| escaping_symlink(path))?;
        self.add_logical_bytes(target_bytes, path)?;
        if let Some(parent) = destination_parent {
            symlinkat(target.as_os_str(), parent, name)
                .map_err(|error| nix_error("create symbolic link", path, error))?;
        }
        for root in &self.cache_roots {
            if resolved.starts_with(root) {
                let count = self.symlinks_by_cache_root.entry(root.clone()).or_default();
                *count = count.saturating_add(1);
            }
        }
        self.report.counts.symlinks += 1;
        Ok(())
    }

    fn visit_special(&mut self, kind: SFlag, path: &[OsString]) -> Result<()> {
        if kind == SFlag::S_IFSOCK {
            self.report.exclusions.sockets += 1;
        } else if kind == SFlag::S_IFIFO {
            self.report.exclusions.fifos += 1;
        } else if matches!(kind, SFlag::S_IFCHR | SFlag::S_IFBLK) {
            self.report.exclusions.devices += 1;
        } else {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                format!("unsupported entry type at {}", relative_text(path)),
            ));
        }
        Ok(())
    }

    fn note_entry(&mut self) -> Result<()> {
        let observed = self.report.counts.entries.saturating_add(1);
        if observed > self.report.limits.entries {
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                format!(
                    "clone entry count {observed} exceeds the limit {}",
                    self.report.limits.entries
                ),
            ));
        }
        self.report.counts.entries = observed;
        Ok(())
    }

    fn add_logical_bytes(&mut self, bytes: u64, path: &[OsString]) -> Result<()> {
        let observed = self
            .report
            .counts
            .logical_bytes
            .checked_add(bytes)
            .ok_or_else(|| limit_error("logical bytes", u64::MAX, self.report.limits.logical_bytes, path))?;
        if observed > self.report.limits.logical_bytes {
            return Err(limit_error(
                "logical bytes",
                observed,
                self.report.limits.logical_bytes,
                path,
            ));
        }
        self.report.counts.logical_bytes = observed;
        Ok(())
    }

    fn finish(&mut self) {
        self.report.exclusions.symlinks_into_omitted_cache_roots = self
            .excluded_cache_roots
            .iter()
            .filter_map(|root| self.symlinks_by_cache_root.get(root))
            .fold(0_u64, |total, count| total.saturating_add(*count));
    }

    fn is_excluded_cache(&self, path: &[OsString]) -> bool {
        !self.report.policy.include_cache && self.cache_roots.iter().any(|root| root == path)
    }

    fn exclude_cache(&mut self, destination: Option<&Dir>, name: &OsStr, path: &[OsString]) -> Result<()> {
        self.report.exclusions.cache_roots += 1;
        self.excluded_cache_roots.insert(path.to_vec());
        if self.control.recreate_cache_roots
            && let Some(parent) = destination
        {
            create_empty_cache(parent, name, path)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn maybe_abort_after_entry(&self) -> Result<()> {
        if self.control.abort_mid_copy {
            return Err(QuartersError::new(
                ErrorKind::System,
                "injected lifecycle failure during copy",
            ));
        }
        Ok(())
    }
}

fn is_managed_command_link(path: &[OsString], target: &OsStr) -> bool {
    if path.len() != 3 || path[0] != ".local" || path[1] != "bin" {
        return false;
    }
    let name = &path[2];
    if name == "quarters" {
        let target = Path::new(target);
        return target.is_absolute() && target.file_name() == Some(OsStr::new("quarters"));
    }
    matches!(name.to_str(), Some("ssh" | "scp" | "sftp" | "ssh-add")) && target == "quarters"
}

fn open_root(path: &Path, label: &str) -> Result<Dir> {
    Dir::open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| root_access_error(label, error))
}

fn entry_metadata(parent: &Dir, name: &OsStr, path: &[OsString]) -> Result<FileStat> {
    fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|error| source_entry_error("inspect source entry", path, error))
}

fn directory_mode(directory: &Dir, path: &[OsString]) -> Result<Mode> {
    fstat(directory)
        .map(|metadata| Mode::from_bits_truncate(metadata.st_mode))
        .map_err(|error| nix_error("inspect source directory", path, error))
}

fn open_directory_at(parent: &Dir, name: &OsStr, expected: &FileStat, path: &[OsString]) -> Result<Dir> {
    let directory = Dir::openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| source_entry_error("open source directory", path, error))?;
    let actual = fstat(&directory).map_err(|error| nix_error("inspect opened source directory", path, error))?;
    verify_identity(expected, &actual, SFlag::S_IFDIR, path)?;
    Ok(directory)
}

fn create_directory_at(parent: &Dir, name: &OsStr, path: &[OsString]) -> Result<Dir> {
    mkdirat(parent, name, Mode::from_bits_truncate(0o700))
        .map_err(|error| nix_error("create staging directory", path, error))?;
    Dir::openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| nix_error("open staging directory", path, error))
}

fn create_empty_cache(parent: &Dir, name: &OsStr, path: &[OsString]) -> Result<()> {
    let directory = create_directory_at(parent, name, path)?;
    fsync(&directory).map_err(|error| nix_error("sync empty cache directory", path, error))
}

fn open_regular_at(parent: &Dir, name: &OsStr, expected: &FileStat, path: &[OsString]) -> Result<OwnedFd> {
    let file = openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| source_entry_error("open source file", path, error))?;
    let actual = fstat(&file).map_err(|error| nix_error("inspect opened source file", path, error))?;
    verify_identity(expected, &actual, SFlag::S_IFREG, path)?;
    let flags = fcntl(&file, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_truncate)
        .map_err(|error| nix_error("inspect source file flags", path, error))?;
    fcntl(&file, FcntlArg::F_SETFL(flags - OFlag::O_NONBLOCK))
        .map_err(|error| nix_error("prepare source file for reading", path, error))?;
    Ok(file)
}

fn copy_regular(
    source: OwnedFd,
    destination_parent: &Dir,
    name: &OsStr,
    source_mode: Mode,
    report: &CloneReport,
    path: &[OsString],
) -> Result<(u64, FileStat)> {
    let destination = openat(
        destination_parent,
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| nix_error("create staging file", path, error))?;
    let mut source = File::from(source);
    let mut destination = File::from(destination);
    let copied = copy_bounded(&mut source, &mut destination, report, path)?;
    fchmod(&destination, source_mode & Mode::from_bits_truncate(0o777))
        .map_err(|error| nix_error("apply staging file mode", path, error))?;
    fsync(&destination).map_err(|error| nix_error("sync staging file", path, error))?;
    let post_read = fstat(&source).map_err(|error| nix_error("recheck source file", path, error))?;
    Ok((copied, post_read))
}

fn copy_bounded(source: &mut File, destination: &mut File, report: &CloneReport, path: &[OsString]) -> Result<u64> {
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|error| io_error("read source file", path, error))?;
        if read == 0 {
            return Ok(copied);
        }
        let read = u64::try_from(read).map_err(conversion_error)?;
        copied = copied
            .checked_add(read)
            .ok_or_else(|| limit_error("regular-file bytes", u64::MAX, report.limits.file_bytes, path))?;
        if copied > report.limits.file_bytes {
            return Err(limit_error(
                "regular-file bytes",
                copied,
                report.limits.file_bytes,
                path,
            ));
        }
        let aggregate = report
            .counts
            .logical_bytes
            .checked_add(copied)
            .ok_or_else(|| limit_error("logical bytes", u64::MAX, report.limits.logical_bytes, path))?;
        if aggregate > report.limits.logical_bytes {
            return Err(limit_error(
                "logical bytes",
                aggregate,
                report.limits.logical_bytes,
                path,
            ));
        }
        let write_len = usize::try_from(read).map_err(conversion_error)?;
        destination
            .write_all(&buffer[..write_len])
            .map_err(|error| io_error("write staging file", path, error))?;
    }
}

fn apply_directory_mode(directory: &Dir, source_mode: Mode, path: &[OsString]) -> Result<()> {
    fchmod(directory, source_mode & Mode::from_bits_truncate(0o777))
        .map_err(|error| nix_error("apply staging directory mode", path, error))?;
    fsync(directory).map_err(|error| nix_error("sync staging directory", path, error))
}

fn recheck_symlink(parent: &Dir, name: &OsStr, expected: &FileStat, path: &[OsString]) -> Result<()> {
    let actual = entry_metadata(parent, name, path)?;
    verify_identity(expected, &actual, SFlag::S_IFLNK, path)
}

fn verify_identity(expected: &FileStat, actual: &FileStat, kind: SFlag, path: &[OsString]) -> Result<()> {
    let actual_kind = SFlag::from_bits_truncate(actual.st_mode);
    if expected.st_dev == actual.st_dev
        && expected.st_ino == actual.st_ino
        && expected.st_uid == actual.st_uid
        && expected.st_gid == actual.st_gid
        && expected.st_mode == actual.st_mode
        && expected.st_nlink == actual.st_nlink
        && expected.st_size == actual.st_size
        && same_timestamps(expected, actual)
        && actual_kind == kind
    {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        format!("source entry changed during clone at {}", relative_text(path)),
    )
    .with_hint("stop processes writing to the source Quarter and retry the preview"))
}

fn same_timestamps(expected: &FileStat, actual: &FileStat) -> bool {
    expected.st_mtime == actual.st_mtime
        && expected.st_mtime_nsec == actual.st_mtime_nsec
        && expected.st_ctime == actual.st_ctime
        && expected.st_ctime_nsec == actual.st_ctime_nsec
}

fn file_length(metadata: &FileStat, path: &[OsString]) -> Result<u64> {
    u64::try_from(metadata.st_size).map_err(|error| {
        QuartersError::new(
            ErrorKind::CorruptState,
            format!("source file has an invalid logical length at {}", relative_text(path)),
        )
        .with_source(error)
    })
}

pub(crate) fn resolve_relative_link_target(parent: &[OsString], target: &OsStr) -> Option<Vec<OsString>> {
    let target_path = Path::new(target);
    if target_path.is_absolute() {
        return None;
    }
    let mut resolved = parent.to_vec();
    for component in target_path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => resolved.push(value.to_os_string()),
            Component::ParentDir => {
                resolved.pop()?;
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(resolved)
}

fn escaping_symlink(path: &[OsString]) -> QuartersError {
    QuartersError::new(
        ErrorKind::CorruptState,
        format!("symbolic link escapes the source home at {}", relative_text(path)),
    )
    .with_hint("replace it with a relative link whose lexical target stays inside the Quarter, then retry")
}

fn limit_error(label: &str, observed: u64, allowed: u64, path: &[OsString]) -> QuartersError {
    QuartersError::new(
        ErrorKind::ResourceLimit,
        format!(
            "clone {label} {observed} exceeds the limit {allowed} at {}",
            relative_text(path)
        ),
    )
    .with_hint("run 'quarters clone SOURCE DESTINATION --preview' after reducing the source tree")
}

fn entry_limit_error(observed: u64, allowed: u64) -> QuartersError {
    QuartersError::new(
        ErrorKind::ResourceLimit,
        format!("clone entry count {observed} exceeds the limit {allowed}"),
    )
}

fn source_access_error(operation: &str, path: &[OsString], error: Errno) -> QuartersError {
    let failure = nix_error(operation, path, error);
    if error == Errno::EACCES {
        return failure.with_hint(
            "grant the current user read permission on the entry and search permission on its parent; Quarters never changes source permissions",
        );
    }
    failure
}

fn root_access_error(operation: &str, error: Errno) -> QuartersError {
    let failure = nix_error(operation, &[], error);
    if error != Errno::EACCES {
        return failure;
    }
    if operation == "open source home" {
        return failure.with_hint(
            "grant the current user read and search permission on the source home; Quarters never changes source permissions",
        );
    }
    failure.with_hint("inspect the private staging directory permissions and retry the clone")
}

fn source_entry_error(operation: &str, path: &[OsString], error: Errno) -> QuartersError {
    if matches!(error, Errno::ENOENT | Errno::ELOOP | Errno::ENOTDIR) {
        return QuartersError::new(
            ErrorKind::CorruptState,
            format!("source entry changed during clone at {}", relative_text(path)),
        )
        .with_hint("stop processes writing to the source Quarter and retry the preview");
    }
    source_access_error(operation, path, error)
}

fn nix_error(operation: &str, path: &[OsString], source: Errno) -> QuartersError {
    let message = if path.is_empty() {
        format!("could not {operation}")
    } else {
        format!("could not {operation} at {}", relative_text(path))
    };
    QuartersError::new(ErrorKind::System, message).with_source(source)
}

fn io_error(operation: &str, path: &[OsString], source: std::io::Error) -> QuartersError {
    QuartersError::new(
        ErrorKind::System,
        format!("could not {operation} {}", relative_text(path)),
    )
    .with_source(source)
}

fn relative_text(path: &[OsString]) -> String {
    if path.is_empty() {
        return "source home".to_owned();
    }
    let joined = path
        .iter()
        .map(|value| value.to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    escape_untrusted_text_bounded_bytes(&joined, 512)
}

fn conversion_error(source: std::num::TryFromIntError) -> QuartersError {
    QuartersError::new(
        ErrorKind::ResourceLimit,
        "filesystem size cannot be represented by this build",
    )
    .with_source(source)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod identity_tests {
    use super::{FileStat, SFlag, entry_metadata, verify_identity};
    use nix::dir::Dir;
    use nix::fcntl::OFlag;
    use nix::sys::stat::Mode;
    use std::ffi::OsString;
    use std::fs;
    use tempfile::TempDir;

    type Mutation = fn(&mut FileStat);

    #[test]
    fn metadata_changes_on_the_same_inode_are_rejected() {
        let temporary = TempDir::new().expect("temporary directory");
        fs::write(temporary.path().join("state"), b"state").expect("write fixture");
        let directory = Dir::open(temporary.path(), OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty())
            .expect("open fixture directory");
        let path = [OsString::from("state")];
        let expected = entry_metadata(&directory, &path[0], &path).expect("fixture metadata");
        verify_identity(&expected, &expected, SFlag::S_IFREG, &path).expect("unchanged metadata must be accepted");
        let cases: [(&str, Mutation); 8] = [
            ("GID", |value| value.st_gid = value.st_gid.saturating_add(1)),
            ("mode", |value| value.st_mode ^= 0o100),
            ("link count", |value| value.st_nlink = value.st_nlink.saturating_add(1)),
            ("size", |value| value.st_size = value.st_size.saturating_add(1)),
            ("mtime seconds", |value| {
                value.st_mtime = value.st_mtime.saturating_add(1);
            }),
            ("mtime nanoseconds", |value| {
                value.st_mtime_nsec = value.st_mtime_nsec.saturating_add(1);
            }),
            ("ctime seconds", |value| {
                value.st_ctime = value.st_ctime.saturating_add(1);
            }),
            ("ctime nanoseconds", |value| {
                value.st_ctime_nsec = value.st_ctime_nsec.saturating_add(1);
            }),
        ];
        for (label, mutate) in cases {
            let mut changed = expected;
            mutate(&mut changed);
            let error = verify_identity(&expected, &changed, SFlag::S_IFREG, &path).expect_err(label);
            assert!(error.message().contains("source entry changed during clone"));
        }
    }
}
