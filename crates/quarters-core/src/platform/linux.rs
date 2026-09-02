//! Linux profile and opt-in mount-home backend.

mod confinement;

use super::{Capabilities, CapabilityStatus, ConfinementPlan, ConfinementRequest};
use crate::{ErrorKind, HostEnvironment, QuartersError, Result};
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{Gid, Uid, getgroups};
use rustix::mount::{MoveMountFlags, OpenTreeFlags, move_mount, open_tree};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(super) struct PlatformPreparedConfinement(confinement::PreparedConfinement);

pub(super) fn platform_capabilities() -> Capabilities {
    let userns = user_namespace_status();
    Capabilities {
        platform: "linux".to_owned(),
        environment_profile: true,
        workspace_profile: CapabilityStatus {
            available: true,
            status: "experimental".to_owned(),
            detail:
                "creates conventional user directories beneath the alternate HOME; applications may ignore HOME/XDG"
                    .to_owned(),
        },
        core_foundation_home: false,
        home_view: userns,
        confinement: confinement::capability_status(),
        authority_boundary:
            "real Linux account and DAC permissions remain; --home-view changes paths but disables ordinary sudo"
                .to_owned(),
    }
}

pub(super) fn platform_confinement_plan(request: &ConfinementRequest<'_>) -> Result<ConfinementPlan> {
    confinement::plan(request)
}

pub(super) fn platform_prepare_filesystem_confinement(plan: &ConfinementPlan) -> Result<PlatformPreparedConfinement> {
    confinement::prepare(plan).map(PlatformPreparedConfinement)
}

pub(super) fn platform_enter_filesystem_confinement(prepared: PlatformPreparedConfinement) -> Result<()> {
    confinement::restrict_current_thread(prepared.0)
}

pub(super) fn platform_resolve_confined_executable(
    program: &OsStr,
    search_path: &OsStr,
    plan: &ConfinementPlan,
) -> Result<crate::platform::ConfinedExecutable> {
    confinement::resolve_executable(program, search_path, plan)
}

pub(super) fn platform_extend_environment(_values: &mut BTreeMap<OsString, OsString>, _home: &Path) {}

pub(super) fn platform_runtime_base(host: &HostEnvironment) -> PathBuf {
    let environment_home = host.get("HOME").map(Path::new);
    let passwd_home = nix::unistd::User::from_uid(Uid::current())
        .ok()
        .flatten()
        .map(|user| user.dir);
    host.original_xdg_runtime()
        .map(PathBuf::from)
        .filter(|runtime| runtime_is_outside_homes(runtime, environment_home, passwd_home.as_deref()))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn runtime_is_outside_homes(runtime: &Path, environment_home: Option<&Path>, passwd_home: Option<&Path>) -> bool {
    runtime.is_absolute()
        && environment_home.is_none_or(|home| !runtime.starts_with(home))
        && passwd_home.is_none_or(|home| !runtime.starts_with(home))
}

pub(super) fn platform_workspace_directories() -> &'static [&'static str] {
    &[]
}

pub(super) fn platform_derived_cache_directories() -> &'static [&'static str] {
    &[]
}

pub(super) fn platform_enter_home_view(space_home: &Path, host_home: &Path) -> Result<()> {
    let (space_descriptor, host_descriptor) = validate_home_view_paths(space_home, host_home)?;
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
    attach_home_view(&space_descriptor, &host_descriptor)?;
    std::env::set_current_dir(host_home)
        .map_err(|error| QuartersError::io("enter the mounted home", host_home, error))?;
    verify_current_directory(&space_descriptor)
}

fn attach_home_view(space_descriptor: &File, host_descriptor: &File) -> Result<()> {
    let tree = open_tree(
        space_descriptor,
        "",
        OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::AT_EMPTY_PATH
            | OpenTreeFlags::AT_RECURSIVE,
    )
    .map_err(|error| mount_api_error("clone the space-home mount tree", error))?;
    move_mount(
        &tree,
        "",
        host_descriptor,
        "",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
    .map_err(|error| mount_api_error("attach the space home over the passwd home", error))
}

fn verify_current_directory(space_descriptor: &File) -> Result<()> {
    let expected = space_descriptor
        .metadata()
        .map_err(|error| QuartersError::io("inspect the space home descriptor", Path::new("."), error))?;
    let actual = fs::metadata(".")
        .map_err(|error| QuartersError::io("inspect the mounted current directory", Path::new("."), error))?;
    if expected.dev() == actual.dev() && expected.ino() == actual.ino() {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "the mounted current directory does not match the requested space home",
    ))
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

fn validate_home_view_paths(space_home: &Path, host_home: &Path) -> Result<(File, File)> {
    if space_home == host_home {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "space and host home paths must differ",
        ));
    }
    let space = open_owned_home_directory(space_home, "space")?;
    let host = open_owned_home_directory(host_home, "account")?;
    Ok((space, host))
}

fn open_owned_home_directory(path: &Path, label: &str) -> Result<File> {
    if !path.is_absolute() {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            format!("{label} home must be an existing absolute directory"),
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|error| QuartersError::io("open home-view directory", path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| QuartersError::io("inspect home-view directory", path, error))?;
    if metadata.is_dir() && metadata.uid() == Uid::current().as_raw() {
        return Ok(file);
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        format!("{label} home is not a current-user directory"),
    ))
}

fn write_namespace_map(path: &Path, contents: String) -> Result<()> {
    fs::write(path, contents).map_err(|error| QuartersError::io("write a user-namespace identity map", path, error))
}

fn namespace_error(operation: &str, source: nix::errno::Errno) -> QuartersError {
    QuartersError::new(ErrorKind::Unsupported, format!("could not {operation}"))
        .with_hint("omit --home-view for the portable environment-profile mode")
        .with_source(source)
}

fn mount_api_error(operation: &str, source: rustix::io::Errno) -> QuartersError {
    QuartersError::new(ErrorKind::Unsupported, format!("could not {operation}"))
        .with_hint("omit --home-view for the portable environment-profile mode")
        .with_source(source)
}

#[cfg(test)]
mod tests {
    use super::{extra_group_count, runtime_is_outside_homes};
    use nix::unistd::Gid;
    use std::path::Path;

    #[test]
    fn primary_group_is_not_treated_as_supplementary_authority() {
        let primary = Gid::from_raw(20);
        assert_eq!(extra_group_count(&[primary], primary), 0);
        assert_eq!(extra_group_count(&[primary, Gid::from_raw(80)], primary), 1);
    }

    #[test]
    fn runtime_remains_outside_environment_and_passwd_homes() {
        let environment_home = Path::new("/tmp/profile-home");
        let passwd_home = Path::new("/home/person");
        assert!(!runtime_is_outside_homes(
            Path::new("/home/person/runtime"),
            Some(environment_home),
            Some(passwd_home),
        ));
        assert!(runtime_is_outside_homes(
            Path::new("/run/user/1000"),
            Some(environment_home),
            Some(passwd_home),
        ));
    }
}
