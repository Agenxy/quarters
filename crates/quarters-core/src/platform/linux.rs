//! Linux profile and opt-in mount-home backend.

use super::{Capabilities, CapabilityStatus};
use crate::{ErrorKind, HostEnvironment, QuartersError, Result};
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{Gid, Uid, getgroups};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn platform_capabilities() -> Capabilities {
    let userns = user_namespace_status();
    Capabilities {
        platform: "linux".to_owned(),
        environment_profile: true,
        core_foundation_home: false,
        home_view: userns,
        confinement: CapabilityStatus {
            available: false,
            status: "not-implemented".to_owned(),
            detail: "Landlock policy is intentionally not claimed by this alpha".to_owned(),
        },
        authority_boundary:
            "real Linux account and DAC permissions remain; --home-view changes paths but disables ordinary sudo"
                .to_owned(),
    }
}

pub(super) fn platform_extend_environment(_values: &mut BTreeMap<OsString, OsString>, _home: &Path) {}

pub(super) fn platform_runtime_base(host: &HostEnvironment) -> PathBuf {
    let home = host.get("HOME").map(Path::new);
    host.get("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|runtime| runtime.is_absolute() && home.is_none_or(|home| !runtime.starts_with(home)))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

pub(super) fn platform_enter_home_view(space_home: &Path, host_home: &Path) -> Result<()> {
    validate_home_view_paths(space_home, host_home)?;
    ensure_no_extra_groups()?;
    let uid = Uid::current().as_raw();
    let gid = Gid::current().as_raw();
    unshare(CloneFlags::CLONE_NEWUSER).map_err(|error| namespace_error("create a user namespace", error))?;
    write_namespace_map(Path::new("/proc/self/uid_map"), format!("{uid} {uid} 1\n"))?;
    if let Err(error) = fs::write("/proc/self/setgroups", "deny\n")
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(QuartersError::io(
            "disable setgroups in the user namespace",
            Path::new("/proc/self/setgroups"),
            error,
        ));
    }
    write_namespace_map(Path::new("/proc/self/gid_map"), format!("{gid} {gid} 1\n"))?;
    unshare(CloneFlags::CLONE_NEWNS).map_err(|error| namespace_error("create a mount namespace", error))?;
    mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)
        .map_err(|error| namespace_error("make mounts private", error))?;
    mount(
        Some(space_home),
        host_home,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|error| namespace_error("bind the space home over the passwd home", error))?;
    std::env::set_current_dir(host_home).map_err(|error| QuartersError::io("enter the mounted home", host_home, error))
}

fn user_namespace_status() -> CapabilityStatus {
    if let Some(detail) = supplementary_group_block() {
        return CapabilityStatus {
            available: false,
            status: "unavailable".to_owned(),
            detail,
        };
    }
    let apparmor_restricted = read_boolean_sysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns");
    let namespaces = fs::read_to_string("/proc/sys/user/max_user_namespaces")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok());
    let available = apparmor_restricted != Some(true) && namespaces != Some(0);
    let detail = if apparmor_restricted == Some(true) {
        "AppArmor restricts unprivileged user namespaces"
    } else if namespaces == Some(0) {
        "user.max_user_namespaces is zero"
    } else {
        "kernel policy does not show a known user-namespace block; launch still verifies the syscall"
    };
    CapabilityStatus {
        available,
        status: if available { "experimental" } else { "unavailable" }.to_owned(),
        detail: detail.to_owned(),
    }
}

fn ensure_no_extra_groups() -> Result<()> {
    if let Some(detail) = supplementary_group_block() {
        return Err(QuartersError::new(ErrorKind::Unsupported, detail)
            .with_hint("omit --home-view to preserve the host's complete group authority"));
    }
    Ok(())
}

fn supplementary_group_block() -> Option<String> {
    match getgroups() {
        Ok(groups) => {
            let count = extra_group_count(&groups, Gid::current());
            (count > 0).then(|| {
                format!(
                    "the account has {count} supplementary group(s), which an unprivileged home view cannot preserve"
                )
            })
        }
        Err(error) => Some(format!("could not inspect supplementary groups: {error}")),
    }
}

fn extra_group_count(groups: &[Gid], primary: Gid) -> usize {
    groups.iter().filter(|group| **group != primary).count()
}

fn read_boolean_sysctl(path: &str) -> Option<bool> {
    fs::read_to_string(path).ok().map(|value| value.trim() == "1")
}

fn validate_home_view_paths(space_home: &Path, host_home: &Path) -> Result<()> {
    if !space_home.is_absolute() || !space_home.is_dir() {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "space home must be an existing absolute directory",
        ));
    }
    if !host_home.is_absolute() || !host_home.is_dir() {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "host home must be an existing absolute directory",
        ));
    }
    if space_home == host_home {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "space and host home paths must differ",
        ));
    }
    Ok(())
}

fn write_namespace_map(path: &Path, contents: String) -> Result<()> {
    fs::write(path, contents).map_err(|error| QuartersError::io("write a user-namespace identity map", path, error))
}

fn namespace_error(operation: &str, source: nix::errno::Errno) -> QuartersError {
    QuartersError::new(ErrorKind::Unsupported, format!("could not {operation}"))
        .with_hint("omit --home-view for the portable environment-profile mode")
        .with_source(source)
}

#[cfg(test)]
mod tests {
    use super::extra_group_count;
    use nix::unistd::Gid;

    #[test]
    fn primary_group_is_not_treated_as_supplementary_authority() {
        let primary = Gid::from_raw(20);
        assert_eq!(extra_group_count(&[primary], primary), 0);
        assert_eq!(extra_group_count(&[primary, Gid::from_raw(80)], primary), 1);
    }
}
