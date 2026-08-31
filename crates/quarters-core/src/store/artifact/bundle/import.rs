//! Two-pass authenticated bundle import into a fresh template.

use super::super::catalog::{ArtifactStaging, prepare_artifact_staging, write_artifact_manifest};
use super::super::integrity::digest_home;
use super::super::model::IMPORTED_ARTIFACT_SCHEMA_VERSION;
use super::super::{ArtifactKind, ArtifactManifest, ArtifactName, ArtifactOrigin, ImportedBundleProvenance};
use super::format::{EntrySink, NoopSink, parse_bundle};
use super::key::{device_number, generation, load_key, validate_external_store_path};
use super::model::{AuthenticatedBundle, BundleHeader, BundleImportReport, FileGeneration};
use crate::store::{entry_exists, epoch_millis, sync_directory};
use crate::{CloneMode, ErrorKind, QuartersError, Result, Store};
use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{Mode, fchmod, fstat, fstatat, mkdirat};
use nix::unistd::{Uid, symlinkat};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const PLAN_DOMAIN: &str = "org.agenxy.quarters.bundle.import-plan-v1";

impl Store {
    /// Authenticate and preview import of one bundle as a fresh template.
    ///
    /// # Errors
    ///
    /// Fails for invalid key, bundle framing, authentication, destination or
    /// resource bounds without creating store state.
    pub fn bundle_import_plan(
        &self,
        bundle_path: &Path,
        destination: &ArtifactName,
        key_path: &Path,
    ) -> Result<BundleImportReport> {
        self.require_artifact_name_available(ArtifactKind::Template, destination)?;
        let key_source = validate_external_store_path(self, key_path, "export key")?;
        let key = load_key(&key_source)?;
        let mut file = open_bundle(bundle_path)?;
        let authenticated = authenticate(&mut file, &key)?;
        import_report(&authenticated, destination, CloneMode::Preview, None, None)
    }

    /// Authenticate and import one bundle as a schema-2 template.
    ///
    /// # Errors
    ///
    /// Fails without publication when the plan, bundle generation, extraction,
    /// content identity, destination or staging transaction changes.
    pub fn import_bundle(
        &self,
        bundle_path: &Path,
        destination: &ArtifactName,
        key_path: &Path,
        confirmation: &str,
    ) -> Result<BundleImportReport> {
        let key_source = validate_external_store_path(self, key_path, "export key")?;
        self.ensure_layout()?;
        let key = load_key(&key_source)?;
        let mut file = open_bundle(bundle_path)?;
        let authenticated = authenticate(&mut file, &key)?;
        let expected_plan = plan_digest(&authenticated, destination)?;
        if confirmation != expected_plan {
            return Err(QuartersError::new(
                ErrorKind::InvalidInput,
                "--confirm-plan must exactly match the authenticated import preview digest",
            ));
        }
        self.require_artifact_name_available(ArtifactKind::Template, destination)?;
        let staging = {
            let _management = self.begin_mutation()?;
            self.require_artifact_name_available(ArtifactKind::Template, destination)?;
            prepare_artifact_staging(self, ArtifactKind::Template)?
        };
        let result = self.extract_and_publish(&mut file, &key, &authenticated, destination, &staging);
        if let Err(original) = &result
            && let Err(cleanup) = staging.identity.cleanup(&staging.temporary)
        {
            return Err(QuartersError::new(
                original.kind(),
                format!(
                    "bundle import failed and staging cleanup also failed: {}",
                    original.message()
                ),
            )
            .with_hint("run 'quarters doctor', then recover only validated stale state")
            .with_source(cleanup));
        }
        let publication_warning = result?;
        import_report(
            &authenticated,
            destination,
            CloneMode::Execute,
            Some(staging.id.as_str()),
            publication_warning,
        )
    }

    fn extract_and_publish(
        &self,
        file: &mut File,
        key: &[u8; 32],
        authenticated: &AuthenticatedBundle,
        destination: &ArtifactName,
        staging: &ArtifactStaging,
    ) -> Result<Option<String>> {
        verify_generation(file, authenticated.generation)?;
        let mut extractor = Extractor::new(&staging.temporary.join("home"))?;
        whole_tree_test_hook();
        let (header, tag) = parse_bundle(file, key, &mut extractor)?;
        if header != authenticated.header || tag != authenticated.tag {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "authenticated bundle changed between import passes",
            ));
        }
        verify_generation(file, authenticated.generation)?;
        let integrity = digest_home(&staging.temporary.join("home"))?;
        if integrity != header.content_integrity {
            return Err(QuartersError::new(
                ErrorKind::Unsupported,
                "destination filesystem changed the imported filename representation",
            )
            .with_hint("import on a case-sensitive, byte-preserving filesystem"));
        }
        let manifest = imported_manifest(staging, destination, &header, tag)?;
        write_artifact_manifest(&staging.temporary, &manifest)?;
        sync_directory(&staging.temporary.join("home"))?;
        sync_directory(&staging.temporary)?;
        let staged = Self::open_artifact_path(ArtifactKind::Template, staging.temporary.clone())?;
        if staged.manifest() != &manifest {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "staged imported-template manifest changed before publication",
            ));
        }
        self.publish_imported_template(staging, &manifest)
    }

    fn publish_imported_template(
        &self,
        staging: &ArtifactStaging,
        manifest: &ArtifactManifest,
    ) -> Result<Option<String>> {
        let _management = self.begin_mutation()?;
        self.require_artifact_name_available(ArtifactKind::Template, &manifest.name)?;
        if entry_exists(&staging.destination)? {
            return Err(QuartersError::new(
                ErrorKind::AlreadyExists,
                "generated imported-template ID already exists",
            ));
        }
        staging
            .identity
            .verify(&staging.temporary, &staging.creation_lock_path)?;
        fs::remove_file(&staging.creation_lock_path).map_err(|error| {
            QuartersError::io(
                "remove imported-template staging lock",
                &staging.creation_lock_path,
                error,
            )
        })?;
        sync_directory(&staging.temporary)?;
        let staged = Self::open_artifact_path(ArtifactKind::Template, staging.temporary.clone())?;
        if staged.manifest() != manifest {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "imported template controls changed before publication",
            ));
        }
        fs::rename(&staging.temporary, &staging.destination)
            .map_err(|error| QuartersError::io("publish imported template", &staging.temporary, error))?;
        Ok(sync_import_publication(&staging.root)
            .err()
            .map(|_error| "template is visible, but artifact-root durability could not be confirmed".to_owned()))
    }
}

fn sync_import_publication(path: &Path) -> Result<()> {
    #[cfg(test)]
    if TEST_IMPORT_SYNC_FAILURE.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(QuartersError::new(
            ErrorKind::System,
            "injected imported-template publication sync failure",
        ));
    }
    sync_directory(path)
}

#[cfg(test)]
static TEST_IMPORT_SYNC_FAILURE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub(super) fn set_test_import_sync_failure(fail: bool) {
    TEST_IMPORT_SYNC_FAILURE.store(fail, std::sync::atomic::Ordering::SeqCst);
}

fn authenticate(file: &mut File, key: &[u8; 32]) -> Result<AuthenticatedBundle> {
    let before = bundle_generation(file)?;
    let (header, tag) = parse_bundle(file, key, &mut NoopSink)?;
    let after = bundle_generation(file)?;
    if before != after {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "bundle changed while it was authenticated",
        ));
    }
    Ok(AuthenticatedBundle {
        header,
        tag,
        generation: before,
    })
}

fn open_bundle(path: &Path) -> Result<File> {
    let owned = nix::fcntl::open(
        path,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| import_error("could not open authenticated bundle", error))?;
    let file = File::from(owned);
    let stat = fstat(&file).map_err(|error| import_error("could not inspect authenticated bundle", error))?;
    let regular = nix::sys::stat::SFlag::from_bits_truncate(stat.st_mode) == nix::sys::stat::SFlag::S_IFREG;
    if !regular || stat.st_uid != Uid::current().as_raw() || stat.st_nlink != 1 || stat.st_mode & 0o077 != 0 {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "bundle must be a current-user, single-link regular file with no group or world access",
        ));
    }
    Ok(file)
}

fn bundle_generation(file: &File) -> Result<FileGeneration> {
    let stat = fstat(file).map_err(|error| import_error("could not inspect bundle generation", error))?;
    generation(&stat)
}

fn verify_generation(file: &File, expected: FileGeneration) -> Result<()> {
    if bundle_generation(file)? == expected {
        Ok(())
    } else {
        Err(QuartersError::new(
            ErrorKind::CorruptState,
            "bundle generation changed after preview",
        ))
    }
}

fn imported_manifest(
    staging: &ArtifactStaging,
    destination: &ArtifactName,
    header: &BundleHeader,
    tag: blake3::Hash,
) -> Result<ArtifactManifest> {
    Ok(ArtifactManifest {
        schema_version: IMPORTED_ARTIFACT_SCHEMA_VERSION,
        artifact_id: staging.id.clone(),
        kind: ArtifactKind::Template,
        name: destination.clone(),
        created_unix_ms: epoch_millis()?,
        source_identity: None,
        source_layout: header.source_layout,
        source_platform: header.source_platform.clone(),
        default_shell: header.default_shell.clone(),
        include_cache: header.include_cache,
        includes_sensitive_state: true,
        origin: ArtifactOrigin::ImportedBundle,
        imported_bundle: Some(ImportedBundleProvenance {
            format_version: header.schema_version,
            export_id: header.export_id.clone(),
            source_artifact_id: header.source_artifact_id.clone(),
            source_artifact_kind: header.source_kind,
            source_identity: header.source_identity.clone(),
            authenticated_tag: tag.to_hex().to_string(),
            import_platform: crate::platform::capabilities().platform,
        }),
        content_integrity: header.content_integrity.clone(),
    })
}

fn import_report(
    authenticated: &AuthenticatedBundle,
    destination: &ArtifactName,
    mode: CloneMode,
    artifact_id: Option<&str>,
    publication_warning: Option<String>,
) -> Result<BundleImportReport> {
    Ok(BundleImportReport {
        mode,
        destination: destination.as_str().to_owned(),
        plan_digest: plan_digest(authenticated, destination)?,
        artifact_id: artifact_id.map(str::to_owned),
        export_id: authenticated.header.export_id.as_str().to_owned(),
        source_kind: authenticated.header.source_kind,
        source_name: authenticated.header.source_name.as_str().to_owned(),
        source_platform: authenticated.header.source_platform.clone(),
        default_shell: authenticated.header.default_shell.clone(),
        content_integrity: authenticated.header.content_integrity.clone(),
        authentication: authenticated.header.authentication.clone(),
        content_safety: "authenticated bytes remain untrusted and may execute when a created space starts".to_owned(),
        publication_warning,
    })
}

fn plan_digest(authenticated: &AuthenticatedBundle, destination: &ArtifactName) -> Result<String> {
    let header = serde_json::to_vec(&authenticated.header).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not encode authenticated import plan").with_source(error)
    })?;
    let mut hasher = blake3::Hasher::new_derive_key(PLAN_DOMAIN);
    hasher.update(&(destination.as_str().len() as u64).to_be_bytes());
    hasher.update(destination.as_str().as_bytes());
    hasher.update(&(header.len() as u64).to_be_bytes());
    hasher.update(&header);
    hasher.update(authenticated.tag.as_bytes());
    let generation = authenticated.generation;
    for value in [generation.device, generation.inode, generation.length] {
        hasher.update(&value.to_be_bytes());
    }
    for value in [
        generation.modified_seconds,
        generation.modified_nanoseconds,
        generation.changed_seconds,
        generation.changed_nanoseconds,
    ] {
        hasher.update(&value.to_be_bytes());
    }
    Ok(hasher.finalize().to_hex().to_string())
}

struct Extractor {
    root: Dir,
    current_file: Option<File>,
    directories: Vec<DirectoryRecord>,
}

struct DirectoryRecord {
    path: Vec<u8>,
    mode: u32,
    children: Vec<CreatedChild>,
}

struct CreatedChild {
    name: Vec<u8>,
    device: u64,
    inode: u64,
}

impl Extractor {
    fn new(root: &Path) -> Result<Self> {
        let root = Dir::open(
            root,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| import_error("could not retain import staging home", error))?;
        Ok(Self {
            root,
            current_file: None,
            directories: vec![DirectoryRecord {
                path: Vec::new(),
                mode: 0o700,
                children: Vec::new(),
            }],
        })
    }

    fn parent_and_name(&self, path: &[u8]) -> Result<(Dir, Vec<u8>, Vec<u8>)> {
        let (parent_path, name) = path.iter().rposition(|byte| *byte == b'/').map_or_else(
            || (Vec::new(), path.to_vec()),
            |index| (path[..index].to_vec(), path[index + 1..].to_vec()),
        );
        let parent = self.open_directory(&parent_path)?;
        Ok((parent, parent_path, name))
    }

    fn open_directory(&self, path: &[u8]) -> Result<Dir> {
        let mut current = Dir::openat(
            &self.root,
            OsStr::new("."),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| import_error("could not retain import root traversal", error))?;
        if path.is_empty() {
            return Ok(current);
        }
        for component in path.split(|byte| *byte == b'/') {
            current = Dir::openat(
                &current,
                OsStr::from_bytes(component),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| import_error("could not traverse import staging directory", error))?;
        }
        Ok(current)
    }

    fn record_child(&mut self, parent: &[u8], name: &[u8], stat: &nix::sys::stat::FileStat) -> Result<()> {
        let directory = self
            .directories
            .last_mut()
            .ok_or_else(|| QuartersError::new(ErrorKind::CorruptState, "bundle extraction parent was not declared"))?;
        if directory.path != parent {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "bundle extraction parent differs from its open directory",
            ));
        }
        directory.children.try_reserve(1).map_err(|error| {
            QuartersError::new(
                ErrorKind::ResourceLimit,
                "could not reserve imported directory metadata",
            )
            .with_source(error)
        })?;
        directory.children.push(CreatedChild {
            name: name.to_vec(),
            device: device_number(stat.st_dev),
            inode: stat.st_ino,
        });
        Ok(())
    }

    fn close_directory(&mut self, path: &[u8]) -> Result<()> {
        let record = self
            .directories
            .pop()
            .ok_or_else(|| QuartersError::new(ErrorKind::CorruptState, "bundle directory stack underflowed"))?;
        if record.path != path {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "bundle closed a directory outside canonical order",
            ));
        }
        let mut directory = self.open_directory(path)?;
        verify_directory_children(&mut directory, &record.children)?;
        fchmod(&directory, import_mode(record.mode)?)
            .map_err(|error| import_error("could not apply imported directory permissions", error))?;
        nix::unistd::fsync(&directory).map_err(|error| import_error("could not sync imported directory", error))
    }
}

fn verify_directory_children(directory: &mut Dir, expected: &[CreatedChild]) -> Result<()> {
    let mut names = Vec::new();
    names.try_reserve(expected.len()).map_err(|error| {
        QuartersError::new(
            ErrorKind::ResourceLimit,
            "could not reserve imported filename verification",
        )
        .with_source(error)
    })?;
    for entry in directory.iter() {
        let entry = entry.map_err(|error| import_error("could not inspect imported directory names", error))?;
        let name = entry.file_name().to_bytes();
        if !matches!(name, b"." | b"..") {
            names.push(name.to_vec());
        }
    }
    let mut observed = Vec::new();
    observed.try_reserve(expected.len()).map_err(|error| {
        QuartersError::new(
            ErrorKind::ResourceLimit,
            "could not reserve imported filename verification",
        )
        .with_source(error)
    })?;
    for name in names {
        let stat = fstatat(&*directory, OsStr::from_bytes(&name), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|error| import_error("could not inspect imported directory entry", error))?;
        observed.push((name, device_number(stat.st_dev), stat.st_ino));
    }
    if observed.len() == expected.len()
        && expected.iter().all(|child| {
            observed
                .iter()
                .any(|(name, device, inode)| name == &child.name && *device == child.device && *inode == child.inode)
        })
    {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "destination filesystem changed an imported filename representation",
    )
    .with_hint("import on a case-sensitive, byte-preserving filesystem"))
}

impl EntrySink for Extractor {
    fn close_directory(&mut self, path: &[u8]) -> Result<()> {
        self.close_directory(path)
    }

    fn directory(&mut self, path: &[u8], mode: u32) -> Result<()> {
        if mode & 0o500 != 0o500 {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "bundle directory lacks owner read and search permission",
            ));
        }
        let (parent, parent_path, name) = self.parent_and_name(path)?;
        if let Err(error) = mkdirat(&parent, OsStr::from_bytes(&name), Mode::from_bits_truncate(0o700)) {
            return Err(creation_error(error));
        }
        let stat = fstatat(&parent, OsStr::from_bytes(&name), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|error| import_error("could not inspect imported directory", error))?;
        self.record_child(&parent_path, &name, &stat)?;
        self.directories.try_reserve(1).map_err(|error| {
            QuartersError::new(ErrorKind::ResourceLimit, "could not reserve imported directory stack")
                .with_source(error)
        })?;
        self.directories.push(DirectoryRecord {
            path: path.to_vec(),
            mode,
            children: Vec::new(),
        });
        Ok(())
    }

    fn file_start(&mut self, path: &[u8], mode: u32, _length: u64) -> Result<()> {
        if mode & 0o400 == 0 {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "bundle file lacks owner read permission",
            ));
        }
        let (parent, parent_path, name) = self.parent_and_name(path)?;
        let owned = openat(
            &parent,
            OsStr::from_bytes(&name),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(creation_error)?;
        let file = File::from(owned);
        let stat = fstat(&file).map_err(|error| import_error("could not inspect imported file", error))?;
        self.record_child(&parent_path, &name, &stat)?;
        fchmod(&file, import_mode(mode)?)
            .map_err(|error| import_error("could not apply imported file permissions", error))?;
        self.current_file = Some(file);
        Ok(())
    }

    fn file_chunk(&mut self, bytes: &[u8]) -> Result<()> {
        self.current_file
            .as_mut()
            .ok_or_else(|| QuartersError::new(ErrorKind::System, "bundle parser has no active destination file"))?
            .write_all(bytes)
            .map_err(|error| import_error("could not write imported file", error))
    }

    fn file_end(&mut self) -> Result<()> {
        let file = self
            .current_file
            .take()
            .ok_or_else(|| QuartersError::new(ErrorKind::System, "bundle parser ended an absent destination file"))?;
        file.sync_all()
            .map_err(|error| import_error("could not sync imported file", error))
    }

    fn symlink(&mut self, path: &[u8], target: &[u8]) -> Result<()> {
        let (parent, parent_path, name) = self.parent_and_name(path)?;
        symlinkat(OsStr::from_bytes(target), &parent, OsStr::from_bytes(&name)).map_err(creation_error)?;
        let stat = fstatat(&parent, OsStr::from_bytes(&name), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|error| import_error("could not inspect imported symbolic link", error))?;
        self.record_child(&parent_path, &name, &stat)
    }

    fn finish(&mut self) -> Result<()> {
        if self.current_file.is_some() {
            return Err(QuartersError::new(
                ErrorKind::System,
                "bundle extraction ended with an unfinished file",
            ));
        }
        if self.directories.len() != 1 {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "bundle extraction ended with open directories",
            ));
        }
        self.close_directory(&[])
    }
}

fn creation_error(error: Errno) -> QuartersError {
    if error == Errno::EEXIST {
        return QuartersError::new(
            ErrorKind::Unsupported,
            "destination filesystem has a byte-distinct imported-name collision",
        )
        .with_hint("import on a case-sensitive, byte-preserving filesystem");
    }
    import_error("could not create imported bundle entry", error)
}

fn import_error(message: &'static str, error: impl std::error::Error + Send + Sync + 'static) -> QuartersError {
    QuartersError::new(ErrorKind::System, message).with_source(error)
}

fn import_mode(mode: u32) -> Result<Mode> {
    let native = nix::libc::mode_t::try_from(mode).map_err(|error| {
        QuartersError::new(ErrorKind::CorruptState, "bundle mode is not supported on this platform").with_source(error)
    })?;
    Ok(Mode::from_bits_truncate(native))
}

#[cfg(test)]
static TEST_BARRIER: std::sync::Mutex<Option<std::sync::Arc<std::sync::Barrier>>> = std::sync::Mutex::new(None);

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(super) fn set_test_barrier(barrier: Option<std::sync::Arc<std::sync::Barrier>>) {
    *TEST_BARRIER.lock().expect("import test barrier lock") = barrier;
}

#[cfg(test)]
#[allow(clippy::expect_used)]
fn whole_tree_test_hook() {
    let barrier = TEST_BARRIER.lock().expect("import test barrier lock").clone();
    if let Some(barrier) = barrier {
        barrier.wait();
        barrier.wait();
    }
}

#[cfg(not(test))]
const fn whole_tree_test_hook() {}
