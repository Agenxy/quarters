//! Descriptor-anchored, content-free host-fork planning.

use super::model::{HostForkFile, HostForkIneligible, HostForkMode, HostForkPolicy, HostForkReport};
use crate::{ErrorKind, HostEnvironment, QuartersError, Result, SpaceLayout, SpaceName, Store};
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;
use nix::unistd::{Uid, dup};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

const PLAN_DOMAIN: &[u8] = b"org.agenxy.quarters.hostfork.plan-v1";
const MAX_EXPLICIT_PATHS: usize = 32;
const MAX_FILE_BYTES: u64 = 1_048_576;
const MAX_TOTAL_BYTES: u64 = 8_388_608;
const MAX_RELATIVE_BYTES: usize = 512;
const MAX_COMPONENTS: usize = 32;

const SHELL_PATHS: &[&str] = &[
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".inputrc",
    ".editorconfig",
];

const EXCLUDED_CATEGORIES: &[&str] = &["credentials", "history", "runtime", "cache", "agent-state"];

pub(super) struct PreparedHostFork {
    pub(super) report: HostForkReport,
    pub(super) sources: Vec<SourceFile>,
    anchor: HomeAnchor,
}

pub(super) struct SourceFile {
    pub(super) relative: PathBuf,
    pub(super) file: File,
    pub(super) metadata: SourceMetadata,
    parents: Vec<DirectoryIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SourceMetadata {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

struct HomeAnchor {
    path: PathBuf,
    file: File,
    identity: DirectoryIdentity,
}

pub(super) struct PrepareRequest<'a> {
    pub(super) host: &'a HostEnvironment,
    pub(super) destination: &'a SpaceName,
    pub(super) shell: &'a Path,
    pub(super) layout: SpaceLayout,
    pub(super) policy: HostForkPolicy,
    pub(super) explicit_paths: &'a [PathBuf],
    pub(super) replace_generated: bool,
    pub(super) mode: HostForkMode,
}

pub(super) fn prepare(store: &Store, request: &PrepareRequest<'_>) -> Result<PreparedHostFork> {
    reject_nested_fork(request.host)?;
    validate_request(request)?;
    let anchor = open_home_anchor(store, request.host)?;
    let candidates = candidate_paths(request.policy, request.explicit_paths)?;
    let mut sources = Vec::new();
    let mut absent = Vec::new();
    let mut ineligible = Vec::new();
    let mut logical_bytes = 0_u64;
    for (relative, selection) in candidates {
        match open_source(&anchor, &relative) {
            Ok(source) => {
                if sources
                    .iter()
                    .any(|existing: &SourceFile| existing.metadata.same_file(source.metadata))
                {
                    return Err(QuartersError::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "two selected host paths resolve to the same file: {}",
                            relative.display()
                        ),
                    ));
                }
                logical_bytes = logical_bytes
                    .checked_add(source.metadata.length)
                    .ok_or_else(size_limit_error)?;
                if logical_bytes > MAX_TOTAL_BYTES {
                    return Err(size_limit_error());
                }
                sources.push(source);
            }
            Err(OpenSourceError::Missing) if !selection.required => absent.push(relative),
            Err(OpenSourceError::Missing) => {
                return Err(QuartersError::new(
                    ErrorKind::NotFound,
                    format!("selected host path does not exist: {}", relative.display()),
                ));
            }
            Err(OpenSourceError::Quarters(error)) if !selection.required => {
                ineligible.push(HostForkIneligible {
                    path: relative,
                    reason: ineligible_reason(&error),
                });
            }
            Err(OpenSourceError::Quarters(error)) => return Err(error),
        }
    }
    let digest = plan_digest(request, &anchor, &sources, &absent, &ineligible);
    let files = sources.iter().map(source_view).collect::<Vec<_>>();
    let report = HostForkReport {
        schema_version: 1,
        mode: request.mode,
        destination: request.destination.as_str().to_owned(),
        layout: request.layout,
        policy: request.policy,
        plan_digest: digest,
        source_home: anchor.path.clone(),
        file_count: files.len(),
        logical_bytes,
        files,
        absent,
        ineligible,
        excluded_categories: EXCLUDED_CATEGORIES.to_vec(),
        content_uninspected: true,
        may_include_sensitive_content: true,
        replace_generated: request.replace_generated,
        destination_space_id: None,
        warning: "selected files are uninspected and may contain secrets; entering may execute startup code, but creation never evaluates it",
        authority_boundary: "copied state is separate, but the real host account and same-UID filesystem authority remain",
        publication_model: "nothing or one complete atomically published Quarter",
    };
    Ok(PreparedHostFork {
        report,
        sources,
        anchor,
    })
}

impl PreparedHostFork {
    pub(super) fn verify_sources(&self) -> Result<()> {
        self.anchor.verify_path()?;
        for expected in &self.sources {
            let actual = open_relative(&self.anchor.file, &expected.relative)?;
            if actual.metadata != expected.metadata || actual.parents != expected.parents {
                return Err(source_changed_error(&expected.relative));
            }
        }
        Ok(())
    }
}

impl SourceMetadata {
    pub(super) fn matches_file(&self, file: &File) -> Result<bool> {
        let metadata = file
            .metadata()
            .map_err(|error| QuartersError::io("reinspect selected host file", Path::new("<descriptor>"), error))?;
        Ok(*self == Self::from_metadata(&metadata))
    }

    pub(super) const fn length(self) -> u64 {
        self.length
    }

    const fn same_file(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }

    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
        }
    }

    fn validate(self, path: &Path) -> Result<()> {
        let owner = Uid::current().as_raw();
        if self.uid == owner && self.mode & 0o022 == 0 && self.mode & 0o170_000 == 0o040_000 {
            return Ok(());
        }
        Err(QuartersError::new(
            ErrorKind::CorruptState,
            format!(
                "host-fork directory is not a protected current-user directory: {}",
                path.display()
            ),
        ))
    }
}

impl HomeAnchor {
    fn verify_path(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| QuartersError::io("reinspect host home", &self.path, error))?;
        if self.identity == DirectoryIdentity::from_metadata(&metadata) {
            return Ok(());
        }
        Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the host-home anchor changed after the plan was prepared",
        ))
    }
}

fn reject_nested_fork(host: &HostEnvironment) -> Result<()> {
    if host.get("QUARTERS_SPACE").is_none() && host.get("QUARTERS_NO_HOST_ESCAPE").is_none() {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "host-state forking is unavailable inside a Quarter",
    )
    .with_hint("exit to the host shell, preview the exact source plan there, then retry"))
}

fn validate_request(request: &PrepareRequest<'_>) -> Result<()> {
    crate::store_policy::validate_shell(request.shell)?;
    if request.explicit_paths.len() > MAX_EXPLICIT_PATHS {
        return Err(QuartersError::new(
            ErrorKind::ResourceLimit,
            format!("host fork accepts at most {MAX_EXPLICIT_PATHS} explicit paths"),
        ));
    }
    Ok(())
}

fn open_home_anchor(store: &Store, host: &HostEnvironment) -> Result<HomeAnchor> {
    let path = host
        .get("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| QuartersError::new(ErrorKind::InvalidInput, "host fork requires an absolute HOME"))?;
    if path.starts_with(store.root()) {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "host HOME cannot be inside the Quarters store",
        ));
    }
    let metadata = fs::symlink_metadata(&path).map_err(|error| QuartersError::io("inspect host home", &path, error))?;
    let identity = DirectoryIdentity::from_metadata(&metadata);
    identity.validate(&path)?;
    if metadata.mode() & 0o200 == 0 {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "host HOME is not owner-writable",
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW);
    let file = options
        .open(&path)
        .map_err(|error| QuartersError::io("open host home", &path, error))?;
    let opened = file
        .metadata()
        .map_err(|error| QuartersError::io("inspect opened host home", &path, error))?;
    if identity != DirectoryIdentity::from_metadata(&opened) {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the host-home anchor changed while it was being opened",
        ));
    }
    Ok(HomeAnchor { path, file, identity })
}

#[derive(Clone, Copy)]
struct CandidateSelection {
    required: bool,
}

fn candidate_paths(policy: HostForkPolicy, explicit: &[PathBuf]) -> Result<BTreeMap<PathBuf, CandidateSelection>> {
    let mut paths = BTreeMap::new();
    match policy {
        HostForkPolicy::Shell => {
            for path in SHELL_PATHS {
                paths.insert(PathBuf::from(path), CandidateSelection { required: false });
            }
        }
    }
    for path in explicit {
        validate_relative_path(path)?;
        reject_sensitive_path(path)?;
        paths.insert(path.clone(), CandidateSelection { required: true });
    }
    Ok(paths)
}

fn validate_relative_path(path: &Path) -> Result<()> {
    let components = path.components().collect::<Vec<_>>();
    let valid = !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path.as_os_str().as_bytes().len() <= MAX_RELATIVE_BYTES
        && components.len() <= MAX_COMPONENTS
        && components
            .iter()
            .all(|component| matches!(component, Component::Normal(_)))
        && path.to_str().is_some();
    if valid {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::InvalidInput,
        "--from-host-path requires a bounded UTF-8 relative path with only normal components",
    ))
}

fn reject_sensitive_path(path: &Path) -> Result<()> {
    let value = path.to_str().unwrap_or_default().to_ascii_lowercase();
    let sensitive = [
        ".aws",
        ".azure",
        ".bash_history",
        ".cache",
        ".cargo/credentials",
        ".cargo/credentials.toml",
        ".claude",
        ".codex",
        ".config/gh",
        ".config/gcloud",
        ".docker",
        ".env",
        ".git-credentials",
        ".gnupg",
        ".kube",
        ".lesshst",
        ".local/state/shell",
        ".netrc",
        ".node_repl_history",
        ".npmrc",
        ".python_history",
        ".pypirc",
        ".sqlite_history",
        ".ssh",
        ".zsh_history",
    ]
    .into_iter()
    .any(|prefix| value == prefix || value.starts_with(&format!("{prefix}/")))
        || value.starts_with(".env.");
    if !sensitive {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        format!("known sensitive host path is outside this phase: {}", path.display()),
    )
    .with_hint("copy credentials only through a future typed credential adapter with separate review"))
}

enum OpenSourceError {
    Missing,
    Quarters(QuartersError),
}

fn open_source(anchor: &HomeAnchor, relative: &Path) -> std::result::Result<SourceFile, OpenSourceError> {
    validate_relative_path(relative).map_err(OpenSourceError::Quarters)?;
    let opened = match open_relative(&anchor.file, relative) {
        Ok(opened) => opened,
        Err(error) if error.kind() == ErrorKind::NotFound => return Err(OpenSourceError::Missing),
        Err(error) => return Err(OpenSourceError::Quarters(error)),
    };
    if opened.metadata.length > MAX_FILE_BYTES {
        return Err(OpenSourceError::Quarters(QuartersError::new(
            ErrorKind::ResourceLimit,
            format!(
                "selected host file exceeds {MAX_FILE_BYTES} bytes: {}",
                relative.display()
            ),
        )));
    }
    Ok(opened)
}

fn open_relative(anchor: &File, relative: &Path) -> Result<SourceFile> {
    let components = relative.components().collect::<Vec<_>>();
    let mut directory =
        dup(anchor).map_err(|error| descriptor_error("duplicate host-home descriptor", relative, error))?;
    let mut parents = Vec::new();
    for component in &components[..components.len().saturating_sub(1)] {
        let Component::Normal(name) = component else {
            return Err(invalid_component_error());
        };
        directory = open_component(&directory, name, true, relative)?;
        let metadata = File::from(
            dup(&directory).map_err(|error| descriptor_error("duplicate source directory", relative, error))?,
        )
        .metadata()
        .map_err(|error| QuartersError::io("inspect selected host directory", relative, error))?;
        let identity = DirectoryIdentity::from_metadata(&metadata);
        identity.validate(relative)?;
        parents.push(identity);
    }
    let Some(Component::Normal(name)) = components.last() else {
        return Err(invalid_component_error());
    };
    let descriptor = open_component(&directory, name, false, relative)?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|error| QuartersError::io("inspect selected host file", relative, error))?;
    validate_source_file(relative, &metadata)?;
    Ok(SourceFile {
        relative: relative.to_path_buf(),
        file,
        metadata: SourceMetadata::from_metadata(&metadata),
        parents,
    })
}

fn open_component(directory: &OwnedFd, name: &std::ffi::OsStr, is_directory: bool, relative: &Path) -> Result<OwnedFd> {
    let mut flags = OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK;
    if is_directory {
        flags |= OFlag::O_DIRECTORY;
    }
    openat(directory, name, flags, Mode::empty()).map_err(|error| {
        if error == nix::errno::Errno::ENOENT {
            return QuartersError::new(ErrorKind::NotFound, "selected host path is absent");
        }
        if error == nix::errno::Errno::ELOOP {
            return QuartersError::new(
                ErrorKind::Unsupported,
                format!("selected host path is a symbolic link: {}", relative.display()),
            );
        }
        descriptor_error("open selected host path without following links", relative, error)
    })
}

fn validate_source_file(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    let safe = metadata.file_type().is_file()
        && metadata.uid() == Uid::current().as_raw()
        && metadata.mode() & 0o022 == 0
        && metadata.nlink() == 1;
    if safe {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        format!(
            "selected host path is not a protected single-link regular file: {}",
            path.display()
        ),
    ))
}

fn source_view(source: &SourceFile) -> HostForkFile {
    HostForkFile {
        path: source.relative.clone(),
        category: if SHELL_PATHS.iter().any(|path| Path::new(path) == source.relative) {
            "shell"
        } else {
            "explicit"
        },
        bytes: source.metadata.length,
        generated_conflict: generated_conflict(&source.relative),
        transformation: startup_transformation(&source.relative),
    }
}

pub(super) fn generated_conflict(path: &Path) -> bool {
    matches!(path.to_str(), Some(".zshrc" | ".bashrc" | ".gitconfig" | ".ssh/config"))
}

pub(super) fn startup_transformation(path: &Path) -> &'static str {
    match path.to_str() {
        Some(".zshrc" | ".bashrc") => "append-managed-state-and-prompt-tail",
        _ => "exact-bytes-private-mode",
    }
}

fn plan_digest(
    request: &PrepareRequest<'_>,
    anchor: &HomeAnchor,
    sources: &[SourceFile],
    absent: &[PathBuf],
    ineligible: &[HostForkIneligible],
) -> String {
    let mut hasher = blake3::Hasher::new();
    put_bytes(&mut hasher, PLAN_DOMAIN);
    put_bytes(&mut hasher, request.destination.as_str().as_bytes());
    put_bytes(&mut hasher, request.shell.as_os_str().as_bytes());
    put_bytes(&mut hasher, request.layout.to_string().as_bytes());
    put_bytes(&mut hasher, request.policy.as_str().as_bytes());
    put_u64(&mut hasher, u64::from(request.replace_generated));
    put_bytes(&mut hasher, anchor.path.as_os_str().as_bytes());
    put_directory(&mut hasher, anchor.identity);
    put_u64(&mut hasher, u64::try_from(sources.len()).unwrap_or(u64::MAX));
    for source in sources {
        put_bytes(&mut hasher, source.relative.as_os_str().as_bytes());
        put_source(&mut hasher, source.metadata);
        put_u64(&mut hasher, u64::try_from(source.parents.len()).unwrap_or(u64::MAX));
        for parent in &source.parents {
            put_directory(&mut hasher, *parent);
        }
    }
    put_u64(&mut hasher, u64::try_from(absent.len()).unwrap_or(u64::MAX));
    for path in absent {
        put_bytes(&mut hasher, path.as_os_str().as_bytes());
    }
    put_u64(&mut hasher, u64::try_from(ineligible.len()).unwrap_or(u64::MAX));
    for entry in ineligible {
        put_bytes(&mut hasher, entry.path.as_os_str().as_bytes());
        put_bytes(&mut hasher, entry.reason.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn put_bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    put_u64(hasher, u64::try_from(value.len()).unwrap_or(u64::MAX));
    hasher.update(value);
}

fn put_u64(hasher: &mut blake3::Hasher, value: u64) {
    hasher.update(&value.to_le_bytes());
}

fn put_i64(hasher: &mut blake3::Hasher, value: i64) {
    hasher.update(&value.to_le_bytes());
}

fn put_directory(hasher: &mut blake3::Hasher, value: DirectoryIdentity) {
    for number in [value.device, value.inode, u64::from(value.uid), u64::from(value.mode)] {
        put_u64(hasher, number);
    }
}

fn put_source(hasher: &mut blake3::Hasher, value: SourceMetadata) {
    for number in [
        value.device,
        value.inode,
        u64::from(value.uid),
        u64::from(value.mode),
        value.links,
        value.length,
    ] {
        put_u64(hasher, number);
    }
    for number in [
        value.modified_seconds,
        value.modified_nanoseconds,
        value.changed_seconds,
        value.changed_nanoseconds,
    ] {
        put_i64(hasher, number);
    }
}

fn descriptor_error(action: &'static str, path: &Path, error: nix::errno::Errno) -> QuartersError {
    QuartersError::io(action, path, std::io::Error::from(error))
}

fn invalid_component_error() -> QuartersError {
    QuartersError::new(
        ErrorKind::InvalidInput,
        "selected host path contains a non-normal component",
    )
}

fn source_changed_error(path: &Path) -> QuartersError {
    QuartersError::new(
        ErrorKind::CorruptState,
        format!("selected host path changed after confirmation: {}", path.display()),
    )
    .with_hint("run the preview again and confirm only its new plan digest")
}

fn size_limit_error() -> QuartersError {
    QuartersError::new(
        ErrorKind::ResourceLimit,
        format!("selected host files exceed the {MAX_TOTAL_BYTES}-byte plan limit"),
    )
}

fn ineligible_reason(error: &QuartersError) -> &'static str {
    match error.kind() {
        ErrorKind::ResourceLimit => "resource-limit",
        ErrorKind::CorruptState => "unsafe-metadata",
        ErrorKind::Unsupported => "unsupported-file-type-or-link",
        _ => "unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_identity_is_device_and_inode_scoped() {
        let first = metadata(7, 11, 100);
        let same_file_changed = metadata(7, 11, 200);
        let other_file = metadata(7, 12, 100);
        assert!(first.same_file(same_file_changed));
        assert!(!first.same_file(other_file));
    }

    #[test]
    fn sensitive_path_filter_is_case_insensitive_and_history_aware() {
        for path in [".SSH/config", ".Env.Local", ".ZSH_HISTORY", ".CACHE/tool"] {
            assert!(reject_sensitive_path(Path::new(path)).is_err(), "accepted {path}");
        }
        assert!(reject_sensitive_path(Path::new(".config/theme")).is_ok());
    }

    const fn metadata(device: u64, inode: u64, length: u64) -> SourceMetadata {
        SourceMetadata {
            device,
            inode,
            uid: 501,
            mode: 0o100_600,
            links: 1,
            length,
            modified_seconds: 1,
            modified_nanoseconds: 2,
            changed_seconds: 3,
            changed_nanoseconds: 4,
        }
    }
}
