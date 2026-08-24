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

/// Create and return a short private per-space runtime directory.
pub(crate) fn runtime_directory(space: &Space, host: &HostEnvironment) -> Result<PathBuf> {
    let base = platform_runtime_base(host);
    let uid = Uid::current().as_raw();
    let fingerprint = path_fingerprint(space.root());
    let namespace_root = base.join(format!("quarters-{uid}"));
    let runtime = namespace_root.join(format!("{}-{fingerprint:016x}", space.manifest().name));
    for directory in [
        &namespace_root,
        &runtime,
        &runtime.join("bin"),
        &runtime.join("tmp"),
        &runtime.join("tmux"),
    ] {
        ensure_owned_private_directory(directory, uid)?;
    }
    Ok(runtime)
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

fn path_fingerprint(path: &Path) -> u64 {
    let mut hash = 14_695_981_039_346_656_037_u64;
    for byte in path.as_os_str().as_encoded_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(1_099_511_628_211);
    }
    hash
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

#[cfg(target_os = "linux")]
use linux::{
    platform_capabilities, platform_enter_home_view, platform_extend_environment, platform_runtime_base,
    platform_workspace_directories,
};
#[cfg(target_os = "macos")]
use macos::{
    platform_capabilities, platform_enter_home_view, platform_extend_environment, platform_runtime_base,
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
