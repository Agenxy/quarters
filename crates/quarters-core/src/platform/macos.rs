//! macOS profile backend.

use super::{Capabilities, CapabilityStatus, ConfinementPlan, ConfinementRequest, unsupported_home_view};
use crate::{ErrorKind, HostEnvironment, QuartersError, Result};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub(super) struct PlatformPreparedConfinement;

pub(super) fn platform_capabilities() -> Capabilities {
    let seatbelt = Path::new("/usr/bin/sandbox-exec").is_file();
    Capabilities {
        platform: "macos".to_owned(),
        environment_profile: true,
        workspace_profile: CapabilityStatus {
            available: true,
            status: "experimental".to_owned(),
            detail: "creates private macOS user-directory conventions; applications may still use host-bound APIs"
                .to_owned(),
        },
        core_foundation_home: true,
        home_view: CapabilityStatus {
            available: false,
            status: "unavailable".to_owned(),
            detail: "macOS has no per-process mount namespace".to_owned(),
        },
        confinement: CapabilityStatus {
            available: false,
            status: "not-implemented".to_owned(),
            detail: if seatbelt {
                "deprecated sandbox-exec exists, but this alpha has no reviewed Seatbelt policy"
            } else {
                "sandbox-exec is absent and this alpha has no Seatbelt backend"
            }
            .to_owned(),
        },
        authority_boundary: "real macOS account, permissions, keychain, TCC and login session remain in force"
            .to_owned(),
    }
}

pub(super) fn platform_extend_environment(values: &mut BTreeMap<OsString, OsString>, home: &Path) {
    values.insert("CFFIXED_USER_HOME".into(), home.as_os_str().to_owned());
}

pub(super) fn platform_runtime_base(_host: &HostEnvironment) -> PathBuf {
    PathBuf::from("/tmp")
}

pub(super) fn platform_workspace_directories() -> &'static [&'static str] {
    &[
        "Applications",
        "Library/Application Support",
        "Library/Caches",
        "Library/Logs",
        "Library/Preferences",
        "Movies",
    ]
}

pub(super) fn platform_derived_cache_directories() -> &'static [&'static str] {
    &["Library/Caches"]
}

pub(super) fn platform_enter_home_view(_space_home: &Path, _host_home: &Path) -> Result<()> {
    Err(unsupported_home_view())
}

pub(super) fn platform_confinement_plan(_request: &ConfinementRequest<'_>) -> Result<ConfinementPlan> {
    Err(unsupported_confinement())
}

pub(super) fn platform_prepare_filesystem_confinement(_plan: &ConfinementPlan) -> Result<PlatformPreparedConfinement> {
    Err(unsupported_confinement())
}

pub(super) fn platform_enter_filesystem_confinement(_prepared: PlatformPreparedConfinement) -> Result<()> {
    Err(unsupported_confinement())
}

pub(super) fn platform_resolve_confined_executable(
    _program: &std::ffi::OsStr,
    _search_path: &std::ffi::OsStr,
    _plan: &ConfinementPlan,
) -> Result<crate::platform::ConfinedExecutable> {
    Err(unsupported_confinement())
}

fn unsupported_confinement() -> QuartersError {
    QuartersError::new(ErrorKind::Unsupported, "filesystem confinement is unavailable on macOS")
        .with_hint("omit --confinement filesystem; portable state redirection remains available")
}

#[cfg(test)]
mod tests {
    use super::platform_capabilities;

    #[test]
    fn seatbelt_presence_does_not_claim_unimplemented_confinement() {
        let confinement = platform_capabilities().confinement;
        assert!(!confinement.available);
        assert_eq!(confinement.status, "not-implemented");
    }
}
