//! Platform capability and environment adapters.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("Quarters currently supports macOS and Linux only");

use crate::{ErrorKind, HostEnvironment, QuartersError, Result, Space};
use nix::unistd::Uid;
use serde::Serialize;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

/// Host feature inventory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Capabilities {
    /// Platform name.
    pub platform: String,
    /// Portable HOME and XDG redirection.
    pub environment_profile: bool,
    /// Expanded home-directory conventions and their compatibility boundary.
    pub workspace_profile: CapabilityStatus,
    /// Best-effort CoreFoundation home redirection on macOS.
    pub core_foundation_home: bool,
    /// Opt-in bind-mounted passwd-home view.
    pub home_view: CapabilityStatus,
    /// Opt-in filesystem confinement.
    pub confinement: CapabilityStatus,
    /// Plain explanation of the authority boundary.
    pub authority_boundary: String,
}

/// One optional capability and its current reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityStatus {
    /// Whether this build and host can attempt the capability.
    pub available: bool,
    /// Stability level: stable, experimental, unavailable or not-implemented.
    pub status: String,
    /// Human-readable evidence or limitation.
    pub detail: String,
}

/// One filesystem hierarchy admitted by an opt-in confinement policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConfinementGrant {
    /// Canonical path used to anchor the kernel rule.
    pub path: PathBuf,
    /// Stable access class: `read-file`, `read`, `read-execute`, `read-write` or `device`.
    pub access: String,
    /// Stable reason for the grant, including derived resolver targets.
    pub source: String,
    /// Whether policy construction fails when this path is unavailable.
    pub required: bool,
}

/// Non-mutating description of the Linux filesystem-confinement policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConfinementPlan {
    /// Requested backend name.
    pub mode: String,
    /// Oldest Landlock ABI whose complete rights are required.
    pub minimum_abi: u32,
    /// Directory selected as the launched process working directory.
    pub working_directory: PathBuf,
    /// Exact rules that would be applied.
    pub grants: Vec<ConfinementGrant>,
    /// Optional fixed paths absent or unavailable on this host.
    pub omitted_paths: Vec<PathBuf>,
    /// Ordered PATH entries used inside the confined process tree.
    pub executable_path: Vec<PathBuf>,
    /// Number of resolvable host PATH entries intentionally excluded.
    pub omitted_host_path_entries: usize,
    /// Stable, explicit limitations on the protection claim.
    pub limitations: Vec<String>,
}

/// Opaque Linux ruleset whose filesystem anchors have already been opened.
pub struct PreparedConfinement {
    inner: PlatformPreparedConfinement,
}

/// Inspect current platform features.
#[must_use]
pub fn capabilities() -> Capabilities {
    platform_capabilities()
}

/// Add platform-specific environment compatibility values.
pub(crate) fn extend_environment(values: &mut BTreeMap<OsString, OsString>, home: &Path) {
    platform_extend_environment(values, home);
}

/// Platform-specific relative directories for expanded workspace spaces.
#[must_use]
pub(crate) fn workspace_directories() -> &'static [&'static str] {
    platform_workspace_directories()
}

/// Platform-specific home-relative cache roots omitted by default lifecycle copies.
#[must_use]
pub(crate) fn derived_cache_directories() -> &'static [&'static str] {
    platform_derived_cache_directories()
}

/// Create and return a short private per-space runtime directory.
pub(crate) fn runtime_directory(space: &Space, host: &HostEnvironment) -> Result<PathBuf> {
    let uid = Uid::current().as_raw();
    let namespace_root = runtime_namespace(host, uid);
    ensure_owned_private_directory(&namespace_root, uid)?;
    migrate_existing_legacy_runtime(space, host)?;
    let runtime = namespace_root.join(runtime_identity(space));
    for directory in [
        &runtime,
        &runtime.join("bin"),
        &runtime.join("tmp"),
        &runtime.join("tmux"),
    ] {
        ensure_owned_private_directory(directory, uid)?;
    }
    Ok(runtime)
}

/// Return an existing per-space runtime directory without creating state.
pub(crate) fn existing_runtime_directory(space: &Space, host: &HostEnvironment) -> Result<Option<PathBuf>> {
    let uid = Uid::current().as_raw();
    let namespace_root = runtime_namespace(host, uid);
    if !existing_valid_runtime_directory(&namespace_root, uid)? {
        return Ok(None);
    }
    let mut existing = Vec::new();
    for path in runtime_candidates(space, &namespace_root) {
        if existing_valid_runtime_directory(&path, uid)? {
            existing.push(path);
        }
    }
    match existing.as_slice() {
        [] => Ok(None),
        [path] => Ok(Some(path.clone())),
        _ => Err(QuartersError::new(
            ErrorKind::CorruptState,
            "multiple private runtime directories exist for one space",
        )
        .with_hint("inspect the exact private runtime paths; Quarters will not guess which state is authoritative")),
    }
}

/// Re-key an existing released or transitional legacy runtime.
pub(crate) fn migrate_existing_legacy_runtime(space: &Space, host: &HostEnvironment) -> Result<()> {
    let uid = Uid::current().as_raw();
    let namespace_root = runtime_namespace(host, uid);
    if !existing_valid_runtime_directory(&namespace_root, uid)? {
        return Ok(());
    }
    let destination = namespace_root.join(runtime_identity(space));
    let destination_exists = existing_valid_runtime_directory(&destination, uid)?;
    let mut sources = Vec::new();
    for source in legacy_runtime_fallbacks(space, &namespace_root) {
        if existing_valid_runtime_directory(&source, uid)? {
            sources.push(source);
        }
    }
    match (destination_exists, sources.as_slice()) {
        (_, []) => return Ok(()),
        (false, [source]) => {
            fs::rename(source, &destination)
                .map_err(|error| QuartersError::io("re-key legacy private runtime directory", source, error))?;
            return crate::store::sync_directory(&namespace_root);
        }
        _ => {}
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "legacy private runtime migration found multiple authoritative candidates",
    )
    .with_hint("inspect the exact private runtime paths; Quarters will not merge or delete ambiguous state"))
}

/// Remove the exact private runtime tree after its owning space is gone.
pub(crate) fn remove_runtime_directory(space: &Space, host: &HostEnvironment) -> Result<()> {
    let Some(runtime) = existing_runtime_directory(space, host)? else {
        return Ok(());
    };
    let parent = runtime.parent().ok_or_else(|| {
        QuartersError::new(
            ErrorKind::CorruptState,
            "the private runtime directory has no namespace parent",
        )
    })?;
    crate::store::lifecycle::remove_tree_restoring_owner_access(&runtime)?;
    crate::store::sync_directory(parent)
}

fn ensure_owned_private_directory(path: &Path, uid: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => return validate_runtime_directory(path, uid, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(QuartersError::io("inspect runtime directory", path, error)),
    }
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(QuartersError::io("create runtime directory", path, error)),
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect created runtime directory", path, error))?;
    validate_runtime_directory(path, uid, &metadata)
}

fn existing_valid_runtime_directory(path: &Path, uid: u32) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_runtime_directory(path, uid, &metadata).map(|()| true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(QuartersError::io("inspect runtime directory", path, error)),
    }
}

fn validate_runtime_directory(path: &Path, uid: u32, metadata: &fs::Metadata) -> Result<()> {
    let private = metadata.mode() & 0o777 == 0o700;
    if !metadata.file_type().is_dir() || metadata.uid() != uid || !private {
        let issue = if metadata.file_type().is_symlink() {
            "it is a symbolic link"
        } else if !metadata.file_type().is_dir() {
            "it is not a directory"
        } else if metadata.uid() != uid {
            "it is owned by another user"
        } else {
            "its mode is not 0700"
        };
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            format!("invalid private runtime directory {}: {issue}", path.display()),
        )
        .with_hint("inspect the path without following links; Quarters never repairs existing runtime permissions"));
    }
    Ok(())
}

fn runtime_identity(space: &Space) -> String {
    if let Some(id) = space.id() {
        return id.as_str().to_owned();
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"quarters-runtime-legacy-v1\0");
    hash.update(&space.manifest().schema_version.to_le_bytes());
    hash.update(space.manifest().name.as_str().as_bytes());
    hash.update(&space.manifest().created_unix_ms.to_le_bytes());
    let digest = hash.finalize();
    format!("legacy-{}", &digest.to_hex()[..32])
}

fn legacy_runtime_identity(space: &Space) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"quarters-runtime-legacy-v1\0");
    hash.update(&crate::PROFILE_SCHEMA_VERSION.to_le_bytes());
    hash.update(space.manifest().name.as_str().as_bytes());
    hash.update(&space.manifest().created_unix_ms.to_le_bytes());
    let digest = hash.finalize();
    format!("legacy-{}", &digest.to_hex()[..32])
}

fn runtime_candidates(space: &Space, namespace_root: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![namespace_root.join(runtime_identity(space))];
    candidates.extend(legacy_runtime_fallbacks(space, namespace_root));
    candidates
}

fn legacy_runtime_fallbacks(space: &Space, namespace_root: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::with_capacity(2);
    if space.id().is_some() {
        candidates.push(namespace_root.join(legacy_runtime_identity(space)));
    }
    candidates.push(namespace_root.join(pre_alpha4_runtime_identity(space)));
    candidates
}

fn pre_alpha4_runtime_identity(space: &Space) -> String {
    format!("{}-{:016x}", space.manifest().name, path_fingerprint(space.root()))
}

fn path_fingerprint(path: &Path) -> u64 {
    let mut hash = 14_695_981_039_346_656_037_u64;
    for byte in path.as_os_str().as_encoded_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(1_099_511_628_211);
    }
    hash
}

fn runtime_namespace(host: &HostEnvironment, uid: u32) -> PathBuf {
    platform_runtime_base(host).join(format!("quarters-{uid}"))
}

/// Enter the Linux-only bind-mounted home view in the current process.
///
/// # Errors
///
/// Returns an error on unsupported platforms, blocked namespace policy,
/// invalid paths, identity-map failure or mount failure.
pub fn enter_home_view(space_home: &Path, host_home: &Path) -> Result<()> {
    platform_enter_home_view(space_home, host_home)
}

/// Describe a requested Linux Landlock filesystem policy without applying it.
///
/// # Errors
///
/// Returns an error when the platform, kernel ABI or required path cannot
/// support the complete policy.
pub fn confinement_plan(
    space_home: &Path,
    effective_home: &Path,
    runtime: &Path,
    host_path: Option<&OsString>,
) -> Result<ConfinementPlan> {
    platform_confinement_plan(space_home, effective_home, runtime, host_path)
}

/// Open every anchor and prepare the complete Linux filesystem policy.
///
/// # Errors
///
/// Returns an error unless every ABI-v3 right and rule can be prepared.
pub fn prepare_filesystem_confinement(plan: &ConfinementPlan) -> Result<PreparedConfinement> {
    platform_prepare_filesystem_confinement(plan).map(|inner| PreparedConfinement { inner })
}

/// Apply a prepared Linux filesystem policy to the calling launcher thread.
///
/// # Errors
///
/// Returns an error unless the complete prepared policy is fully enforced.
pub fn enter_filesystem_confinement(prepared: PreparedConfinement) -> Result<()> {
    platform_enter_filesystem_confinement(prepared.inner)
}

/// Resolve and validate an executable against the confinement policy.
///
/// # Errors
///
/// Returns an error for relative paths containing a separator, unresolved
/// names or paths outside an executable grant.
pub fn resolve_confined_executable(
    program: &std::ffi::OsStr,
    search_path: &std::ffi::OsStr,
    plan: &ConfinementPlan,
) -> Result<PathBuf> {
    platform_resolve_confined_executable(program, search_path, plan)
}

#[cfg(target_os = "linux")]
use linux::{
    PlatformPreparedConfinement, platform_capabilities, platform_confinement_plan, platform_derived_cache_directories,
    platform_enter_filesystem_confinement, platform_enter_home_view, platform_extend_environment,
    platform_prepare_filesystem_confinement, platform_resolve_confined_executable, platform_runtime_base,
    platform_workspace_directories,
};
#[cfg(target_os = "macos")]
use macos::{
    PlatformPreparedConfinement, platform_capabilities, platform_confinement_plan, platform_derived_cache_directories,
    platform_enter_filesystem_confinement, platform_enter_home_view, platform_extend_environment,
    platform_prepare_filesystem_confinement, platform_resolve_confined_executable, platform_runtime_base,
    platform_workspace_directories,
};

#[cfg(target_os = "macos")]
fn unsupported_home_view() -> QuartersError {
    QuartersError::new(
        ErrorKind::Unsupported,
        "a bind-mounted passwd-home view is unavailable on this platform",
    )
    .with_hint("omit --home-view; HOME and user-state redirection remain available")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use nix::unistd::Uid;

    use super::ensure_owned_private_directory;

    #[test]
    fn existing_runtime_permissions_are_never_repaired() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let broad = directory.path().join("broad");
        std::fs::create_dir(&broad)?;
        std::fs::set_permissions(&broad, std::fs::Permissions::from_mode(0o777))?;
        assert!(ensure_owned_private_directory(&broad, Uid::current().as_raw()).is_err());
        assert_eq!(std::fs::symlink_metadata(&broad)?.permissions().mode() & 0o777, 0o777);

        let target = directory.path().join("target");
        std::fs::create_dir(&target)?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
        let link = directory.path().join("link");
        symlink(&target, &link)?;
        assert!(ensure_owned_private_directory(&link, Uid::current().as_raw()).is_err());
        assert_eq!(std::fs::symlink_metadata(&target)?.permissions().mode() & 0o777, 0o755);
        Ok(())
    }
}
