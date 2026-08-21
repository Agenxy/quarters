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
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Host feature inventory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Capabilities {
    /// Platform name.
    pub platform: String,
    /// Portable HOME and XDG redirection.
    pub environment_profile: bool,
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
    /// Stability level: stable, experimental or unavailable.
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

/// Create and return a short private per-space runtime directory.
pub(crate) fn runtime_directory(space: &Space, host: &HostEnvironment) -> Result<PathBuf> {
    let base = platform_runtime_base(host);
    let uid = Uid::current().as_raw();
    let fingerprint = path_fingerprint(space.root());
    let namespace_root = base.join(format!("quarters-{uid}"));
    let runtime = namespace_root.join(format!("{}-{fingerprint:08x}", space.manifest().name));
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
    fs::create_dir_all(path).map_err(|error| QuartersError::io("create runtime directory", path, error))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|error| QuartersError::io("inspect runtime directory", path, error))?;
    if !metadata.file_type().is_dir() || metadata.uid() != uid {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            format!(
                "runtime path is not a directory owned by the current user: {}",
                path.display()
            ),
        )
        .with_hint("inspect the path without following symlinks, then remove it only if it is safe"));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| QuartersError::io("set runtime directory permissions", path, error))
}

fn path_fingerprint(path: &Path) -> u32 {
    let mut hash = 2_166_136_261_u32;
    for byte in path.as_os_str().as_encoded_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16_777_619);
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
use linux::{platform_capabilities, platform_enter_home_view, platform_extend_environment, platform_runtime_base};
#[cfg(target_os = "macos")]
use macos::{platform_capabilities, platform_enter_home_view, platform_extend_environment, platform_runtime_base};

#[cfg(target_os = "macos")]
fn unsupported_home_view() -> QuartersError {
    QuartersError::new(
        ErrorKind::Unsupported,
        "a bind-mounted passwd-home view is unavailable on this platform",
    )
    .with_hint("omit --home-view; HOME and user-state redirection remain available")
}
