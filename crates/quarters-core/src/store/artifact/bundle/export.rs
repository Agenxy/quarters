//! Descriptor-relative authenticated bundle export.

use super::super::{Artifact, ArtifactCounts, ArtifactId, ArtifactKind, ArtifactName, ContentIntegrity};
use super::format::BundleWriter;
use super::key::{ExternalPath, complete_link_publication, load_key, unlink_exact, validate_external_store_path};
use super::model::{BUNDLE_ALGORITHM, BUNDLE_VERSION, BundleExportReport, BundleHeader};
use crate::store::epoch_millis;
use crate::store::lifecycle::resolve_relative_link_target;
use crate::{CloneLimits, CloneMode, ErrorKind, QuartersError, Result, Store};
use nix::dir::Dir;
use nix::fcntl::{AtFlags, FcntlArg, OFlag, fcntl, openat, readlinkat};
use nix::sys::stat::{FileStat, Mode, SFlag, fchmod, fstat, fstatat};
use nix::unistd::{Uid, linkat};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const CANONICAL_CONTEXT: &str = "org.agenxy.quarters.artifact.quarters-canonical-v1";
const CANONICAL_ROOT: u8 = 0x52;
const CANONICAL_DIRECTORY: u8 = 0x44;
const CANONICAL_FILE: u8 = 0x46;
const CANONICAL_SYMLINK: u8 = 0x4c;
const CANONICAL_TERMINAL: u8 = 0x00;

impl Store {
    /// Preview export of a verified named template or snapshot.
    ///
    /// # Errors
    ///
    /// Fails when the artifact, destination or key contract is invalid.
    pub fn bundle_export_plan(
        &self,
        kind: ArtifactKind,
        name: &ArtifactName,
        destination: &Path,
        key_path: &Path,
    ) -> Result<BundleExportReport> {
        let artifact = self.verify_artifact(kind, name)?;
        let key_source = validate_external_store_path(self, key_path, "export key")?;
        let _key = load_key(&key_source)?;
        validate_external_destination(self, destination)?;
        Ok(export_report(&artifact, destination, CloneMode::Preview, None, None))
    }

    /// Export a verified artifact into one authenticated plaintext bundle.
    ///
    /// # Errors
    ///
    /// Fails without publishing the final path when any source, destination,
    /// key, limit, integrity or filesystem-generation check fails.
    pub fn export_bundle(
        &self,
        kind: ArtifactKind,
        name: &ArtifactName,
        destination: &Path,
        key_path: &Path,
    ) -> Result<BundleExportReport> {
        let artifact = self.verify_artifact(kind, name)?;
        let key_source = validate_external_store_path(self, key_path, "export key")?;
        let key = load_key(&key_source)?;
        let destination_anchor = validate_external_destination(self, destination)?;
        let parent = &destination_anchor.parent;
        let destination_name = &destination_anchor.name;
        let export_id = ArtifactId::generate()?;
        let temporary = OsString::from(format!(".quarters-export-{export_id}"));
        let owned = openat(
            parent,
            temporary.as_os_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|error| export_error("could not create private export staging", error))?;
        let mut file = File::from(owned);
        let staged = fstat(&file).map_err(|error| export_error("could not inspect export staging", error))?;
        fchmod(&file, Mode::from_bits_truncate(0o600))
            .map_err(|error| export_error("could not protect export staging", error))?;
        let mut target = ExportTarget {
            parent,
            destination: destination_name.as_os_str(),
            temporary: temporary.as_os_str(),
            file: &mut file,
            staged: &staged,
        };
        let result = write_and_publish(&artifact, &key, &export_id, &mut target);
        if result.is_err() {
            let _ignored = unlink_exact(parent, temporary.as_os_str(), &staged);
        }
        let publication_warning = result?;
        Ok(export_report(
            &artifact,
            destination,
            CloneMode::Execute,
            Some(&export_id),
            publication_warning,
        ))
    }
}

fn write_and_publish(
    artifact: &Artifact,
    key: &[u8; 32],
    export_id: &ArtifactId,
    target: &mut ExportTarget<'_>,
) -> Result<Option<String>> {
    let source_identity = artifact
        .manifest()
        .source_identity
        .clone()
        .or_else(|| {
            artifact
                .manifest()
                .imported_bundle
                .as_ref()
                .map(|provenance| provenance.source_identity.clone())
        })
        .ok_or_else(|| QuartersError::new(ErrorKind::CorruptState, "artifact has no exportable source provenance"))?;
    let header = BundleHeader {
        schema_version: BUNDLE_VERSION,
        export_id: export_id.clone(),
        created_unix_ms: epoch_millis()?,
        source_kind: artifact.manifest().kind,
        source_artifact_id: artifact.manifest().artifact_id.clone(),
        source_name: artifact.manifest().name.clone(),
        source_identity,
        source_layout: artifact.manifest().source_layout,
        source_platform: artifact.manifest().source_platform.clone(),
        default_shell: artifact.manifest().default_shell.clone(),
        include_cache: artifact.manifest().include_cache,
        includes_sensitive_state: true,
        content_integrity: artifact.manifest().content_integrity.clone(),
        authentication: BUNDLE_ALGORITHM.to_owned(),
    };
    let root = Dir::open(
        &artifact.home(),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| export_error("could not retain artifact home for export", error))?;
    let root_stat = fstat(&root).map_err(|error| export_error("could not inspect artifact home for export", error))?;
    verify_owner(&root_stat, &[])?;
    let mut writer = BundleWriter::begin(target.file, key, &header)?;
    let mut canonical = Canonical::new(root_stat.st_mode);
    whole_tree_test_hook();
    export_directory(root, &[], &mut writer, &mut canonical, 0)?;
    let actual = canonical.finish();
    if actual != artifact.manifest().content_integrity {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "artifact changed while its authenticated bundle was written",
        ));
    }
    let _tag = writer.finish()?;
    target
        .file
        .sync_all()
        .map_err(|error| export_error("could not sync authenticated bundle", error))?;
    linkat(
        target.parent,
        target.temporary,
        target.parent,
        target.destination,
        AtFlags::empty(),
    )
    .map_err(|error| {
        let kind = if error == nix::errno::Errno::EEXIST {
            ErrorKind::AlreadyExists
        } else {
            ErrorKind::System
        };
        QuartersError::new(kind, "bundle destination already exists or cannot be published").with_source(error)
    })?;
    Ok(complete_link_publication(
        target.parent,
        target.temporary,
        target.staged,
    ))
}

struct ExportTarget<'a> {
    parent: &'a Dir,
    destination: &'a OsStr,
    temporary: &'a OsStr,
    file: &'a mut File,
    staged: &'a FileStat,
}

fn export_directory(
    mut directory: Dir,
    relative: &[OsString],
    writer: &mut BundleWriter<'_>,
    canonical: &mut Canonical,
    depth: u32,
) -> Result<()> {
    let mut names = Vec::new();
    for entry in directory.iter() {
        let entry = entry.map_err(|error| export_error("could not read artifact directory", error))?;
        let bytes = entry.file_name().to_bytes();
        if !matches!(bytes, b"." | b"..") {
            names.push(OsStr::from_bytes(bytes).to_os_string());
        }
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    for name in names {
        let mut path = relative.to_vec();
        path.push(name.clone());
        Canonical::validate_path(&path)?;
        let stat = fstatat(&directory, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|error| export_error("could not inspect artifact export entry", error))?;
        verify_owner(&stat, &path)?;
        match SFlag::from_bits_truncate(stat.st_mode) {
            SFlag::S_IFDIR => export_child_directory(&directory, &name, &path, &stat, writer, canonical, depth)?,
            SFlag::S_IFREG => export_file(&directory, &name, &path, &stat, writer, canonical)?,
            SFlag::S_IFLNK => export_symlink(&directory, &name, &path, &stat, writer, canonical)?,
            _ => return Err(entry_error("artifact contains an unsupported export entry", &path)),
        }
    }
    Ok(())
}

fn export_child_directory(
    parent: &Dir,
    name: &OsStr,
    path: &[OsString],
    expected: &FileStat,
    writer: &mut BundleWriter<'_>,
    canonical: &mut Canonical,
    depth: u32,
) -> Result<()> {
    if depth.saturating_add(1) > CloneLimits::ALPHA.depth {
        return Err(entry_error("artifact export directory exceeds the depth limit", path));
    }
    let child = Dir::openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| export_error("could not open artifact export directory", error))?;
    verify_identity(
        expected,
        &fstat(&child).map_err(|error| export_error("could not inspect opened export directory", error))?,
        SFlag::S_IFDIR,
        path,
    )?;
    canonical.directory(path, expected.st_mode)?;
    writer.directory(&raw_path(path), normalized_mode(expected.st_mode))?;
    export_directory(child, path, writer, canonical, depth.saturating_add(1))?;
    let after = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|error| export_error("could not recheck export directory", error))?;
    verify_identity(expected, &after, SFlag::S_IFDIR, path)
}

fn export_file(
    parent: &Dir,
    name: &OsStr,
    path: &[OsString],
    expected: &FileStat,
    writer: &mut BundleWriter<'_>,
    canonical: &mut Canonical,
) -> Result<()> {
    if expected.st_nlink != 1 {
        return Err(entry_error("artifact export contains a multiply-linked file", path));
    }
    let length = u64::try_from(expected.st_size)
        .map_err(|error| entry_error("artifact export file length is invalid", path).with_source(error))?;
    canonical.file_prefix(path, expected.st_mode, length)?;
    let owned = openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| export_error("could not open artifact export file", error))?;
    verify_identity(
        expected,
        &fstat(&owned).map_err(|error| export_error("could not inspect opened export file", error))?,
        SFlag::S_IFREG,
        path,
    )?;
    let flags = fcntl(&owned, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_truncate)
        .map_err(|error| export_error("could not inspect export file flags", error))?;
    fcntl(&owned, FcntlArg::F_SETFL(flags - OFlag::O_NONBLOCK))
        .map_err(|error| export_error("could not prepare export file", error))?;
    let mut file = File::from(owned);
    writer.file(
        &raw_path(path),
        normalized_mode(expected.st_mode),
        &mut file,
        length,
        &mut canonical.hasher,
    )?;
    let after = fstat(&file).map_err(|error| export_error("could not recheck exported file", error))?;
    verify_identity(expected, &after, SFlag::S_IFREG, path)
}

fn export_symlink(
    parent: &Dir,
    name: &OsStr,
    path: &[OsString],
    expected: &FileStat,
    writer: &mut BundleWriter<'_>,
    canonical: &mut Canonical,
) -> Result<()> {
    let target =
        readlinkat(parent, name).map_err(|error| export_error("could not read artifact export link", error))?;
    let parent_path = &path[..path.len().saturating_sub(1)];
    if resolve_relative_link_target(parent_path, &target).is_none() {
        return Err(entry_error("artifact export symbolic link escapes its root", path));
    }
    canonical.symlink(path, target.as_bytes())?;
    writer.symlink(&raw_path(path), target.as_bytes())?;
    let after = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|error| export_error("could not recheck exported link", error))?;
    verify_identity(expected, &after, SFlag::S_IFLNK, path)
}

struct Canonical {
    hasher: blake3::Hasher,
    counts: ArtifactCounts,
}

impl Canonical {
    fn new(root_mode: nix::libc::mode_t) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(CANONICAL_CONTEXT);
        hasher.update(&[CANONICAL_ROOT]);
        hasher.update(&normalized_mode(root_mode).to_be_bytes());
        Self {
            hasher,
            counts: ArtifactCounts::default(),
        }
    }

    fn validate_path(path: &[OsString]) -> Result<()> {
        if path
            .last()
            .is_none_or(|name| name.as_bytes().len() as u64 > CloneLimits::ALPHA.component_bytes)
            || raw_path(path).len() as u64 > CloneLimits::ALPHA.relative_path_bytes
        {
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                "artifact export path exceeds fixed limits",
            ));
        }
        Ok(())
    }

    fn directory(&mut self, path: &[OsString], mode: nix::libc::mode_t) -> Result<()> {
        self.note_entry()?;
        self.counts.directories = self.counts.directories.saturating_add(1);
        self.hasher.update(&[CANONICAL_DIRECTORY]);
        self.hash_path(path);
        self.hasher.update(&normalized_mode(mode).to_be_bytes());
        Ok(())
    }

    fn file_prefix(&mut self, path: &[OsString], mode: nix::libc::mode_t, length: u64) -> Result<()> {
        if length > CloneLimits::ALPHA.file_bytes {
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                "artifact export file exceeds fixed limits",
            ));
        }
        self.note_entry()?;
        self.add_bytes(length)?;
        self.counts.files = self.counts.files.saturating_add(1);
        self.hasher.update(&[CANONICAL_FILE]);
        self.hash_path(path);
        self.hasher.update(&normalized_mode(mode).to_be_bytes());
        self.hasher.update(&length.to_be_bytes());
        Ok(())
    }

    fn symlink(&mut self, path: &[OsString], target: &[u8]) -> Result<()> {
        if target.len() as u64 > CloneLimits::ALPHA.symlink_target_bytes {
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                "artifact export link exceeds fixed limits",
            ));
        }
        self.note_entry()?;
        self.add_bytes(target.len() as u64)?;
        self.counts.symlinks = self.counts.symlinks.saturating_add(1);
        self.hasher.update(&[CANONICAL_SYMLINK]);
        self.hash_path(path);
        self.hasher.update(&(target.len() as u64).to_be_bytes());
        self.hasher.update(target);
        Ok(())
    }

    fn note_entry(&mut self) -> Result<()> {
        self.counts.entries = self.counts.entries.saturating_add(1);
        if self.counts.entries > CloneLimits::ALPHA.entries {
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                "artifact export exceeds the entry limit",
            ));
        }
        Ok(())
    }

    fn add_bytes(&mut self, amount: u64) -> Result<()> {
        self.counts.logical_bytes = self.counts.logical_bytes.checked_add(amount).ok_or_else(|| {
            QuartersError::new(
                ErrorKind::ResourceLimit,
                "artifact export logical-byte count overflowed",
            )
        })?;
        if self.counts.logical_bytes > CloneLimits::ALPHA.logical_bytes {
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                "artifact export exceeds the byte limit",
            ));
        }
        Ok(())
    }

    fn hash_path(&mut self, path: &[OsString]) {
        let bytes = raw_path(path);
        self.hasher.update(&(bytes.len() as u64).to_be_bytes());
        self.hasher.update(&bytes);
    }

    fn finish(mut self) -> ContentIntegrity {
        self.hasher.update(&[CANONICAL_TERMINAL]);
        self.hasher.update(&self.counts.entries.to_be_bytes());
        self.hasher.update(&self.counts.directories.to_be_bytes());
        self.hasher.update(&self.counts.files.to_be_bytes());
        self.hasher.update(&self.counts.symlinks.to_be_bytes());
        self.hasher.update(&self.counts.logical_bytes.to_be_bytes());
        ContentIntegrity {
            algorithm: "blake3-256:quarters-canonical-v1".to_owned(),
            digest: self.hasher.finalize().to_hex().to_string(),
            counts: self.counts,
        }
    }
}

fn validate_external_destination(store: &Store, destination: &Path) -> Result<ExternalPath> {
    validate_external_store_path(store, destination, "bundle")
}

fn export_report(
    artifact: &Artifact,
    destination: &Path,
    mode: CloneMode,
    export_id: Option<&ArtifactId>,
    publication_warning: Option<String>,
) -> BundleExportReport {
    BundleExportReport {
        mode,
        source_kind: artifact.manifest().kind,
        source_name: artifact.manifest().name.as_str().to_owned(),
        export_id: export_id.map(ToString::to_string),
        destination: destination.to_path_buf(),
        content_integrity: artifact.manifest().content_integrity.clone(),
        limits: CloneLimits::ALPHA,
        includes_sensitive_state: true,
        security_boundary: "authenticated plaintext; not encryption, confinement, or content-safety review".to_owned(),
        publication_warning,
    }
}

fn raw_path(path: &[OsString]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (index, component) in path.iter().enumerate() {
        if index > 0 {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(component.as_bytes());
    }
    bytes
}

fn verify_owner(stat: &FileStat, path: &[OsString]) -> Result<()> {
    if stat.st_uid == Uid::current().as_raw() {
        return Ok(());
    }
    Err(entry_error("artifact export contains a foreign-owned entry", path))
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
        Ok(())
    } else {
        Err(entry_error("artifact export entry changed during streaming", path))
    }
}

#[cfg(target_os = "linux")]
fn normalized_mode(raw: nix::libc::mode_t) -> u32 {
    raw & 0o777
}

#[cfg(target_os = "macos")]
fn normalized_mode(raw: nix::libc::mode_t) -> u32 {
    u32::from(raw & 0o777)
}

fn entry_error(message: &str, path: &[OsString]) -> QuartersError {
    let text = path
        .iter()
        .map(|component| component.to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    QuartersError::new(
        ErrorKind::CorruptState,
        format!(
            "{message} at {}",
            crate::text::escape_untrusted_text_bounded_bytes(&text, 512)
        ),
    )
}

fn export_error(message: &'static str, error: impl std::error::Error + Send + Sync + 'static) -> QuartersError {
    QuartersError::new(ErrorKind::System, message).with_source(error)
}

#[cfg(test)]
static TEST_BARRIER: std::sync::Mutex<Option<std::sync::Arc<std::sync::Barrier>>> = std::sync::Mutex::new(None);

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(super) fn set_test_barrier(barrier: Option<std::sync::Arc<std::sync::Barrier>>) {
    *TEST_BARRIER.lock().expect("export test barrier lock") = barrier;
}

#[cfg(test)]
#[allow(clippy::expect_used)]
fn whole_tree_test_hook() {
    let barrier = TEST_BARRIER.lock().expect("export test barrier lock").clone();
    if let Some(barrier) = barrier {
        barrier.wait();
        barrier.wait();
    }
}

#[cfg(not(test))]
const fn whole_tree_test_hook() {}
