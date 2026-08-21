//! macOS profile backend.

use super::{Capabilities, CapabilityStatus, unsupported_home_view};
use crate::{HostEnvironment, Result};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub(super) fn platform_capabilities() -> Capabilities {
    let seatbelt = Path::new("/usr/bin/sandbox-exec").is_file();
    Capabilities {
        platform: "macos".to_owned(),
        environment_profile: true,
        core_foundation_home: true,
        home_view: CapabilityStatus {
            available: false,
            status: "unavailable".to_owned(),
            detail: "macOS has no per-process mount namespace".to_owned(),
        },
        confinement: CapabilityStatus {
            available: seatbelt,
            status: "capability-only".to_owned(),
            detail: if seatbelt {
                "deprecated sandbox-exec exists, but this alpha does not claim a reviewed Seatbelt policy"
            } else {
                "sandbox-exec is absent"
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

pub(super) fn platform_enter_home_view(_space_home: &Path, _host_home: &Path) -> Result<()> {
    Err(unsupported_home_view())
}
