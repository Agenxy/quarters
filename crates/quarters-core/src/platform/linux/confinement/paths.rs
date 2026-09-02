//! Policy path discovery, reporting and executable resolution.

use crate::platform::{ConfinedExecutable, ConfinementGrant, ConfinementPlan, ConfinementRequest, UserGrantAccess};
use crate::{ErrorKind, QuartersError, Result};
use nix::unistd::Uid;
use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const MAX_USER_GRANTS: usize = 32;

const EXECUTABLE_ROOTS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/opt",
    "/nix/store",
    "/run/current-system/sw",
    "/nix/var/nix/profiles/default",
];
const DEVICE_PATHS: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/ptmx",
    "/dev/pts",
];

pub(super) fn build_plan(request: &ConfinementRequest<'_>) -> Result<ConfinementPlan> {
    validate_private_directory(request.space_home, "Quarter home")?;
    validate_private_directory(request.runtime, "Quarter runtime")?;
    let mut grants = Vec::new();
    let mut omitted = Vec::new();
    push_canonical(&mut grants, request.space_home, "read-write", "quarter-home", true)?;
    push_canonical(&mut grants, request.runtime, "read-write", "quarter-runtime", true)?;
    for path in EXECUTABLE_ROOTS {
        push_optional(
            &mut grants,
            &mut omitted,
            Path::new(path),
            "read-execute",
            "system-executable-root",
        )?;
    }
    push_canonical(&mut grants, Path::new("/etc"), "read", "system-configuration", true)?;
    push_canonical(&mut grants, Path::new("/proc"), "read", "process-compatibility", true)?;
    add_resolver_target(&mut grants, &mut omitted)?;
    ensure_store_disjoint(request.store_root, request.space_home, &grants)?;
    for path in DEVICE_PATHS {
        let required = *path == "/dev/null";
        if required {
            push_canonical(&mut grants, Path::new(path), "device", "compatibility-device", true)?;
        } else if *path == "/dev/tty" {
            push_optional_terminal(&mut grants, &mut omitted, Path::new(path))?;
        } else {
            push_optional(
                &mut grants,
                &mut omitted,
                Path::new(path),
                "device",
                "compatibility-device",
            )?;
        }
    }
    add_user_grants(request, &mut grants)?;
    deduplicate_grants(&mut grants);
    if !grants.iter().any(|grant| grant.access == "read-execute") {
        return Err(QuartersError::new(
            ErrorKind::Unsupported,
            "filesystem confinement found no executable system root",
        ));
    }
    let quarter_command_root = request
        .effective_home
        .canonicalize()
        .map_err(|error| QuartersError::io("resolve confined Quarter command root", request.effective_home, error))?;
    let executable_path = reconstructed_path(request.effective_home, request.runtime, &grants, request.host_path);
    let omitted_host_path_entries = omitted_path_count(request.host_path, &executable_path);
    let legacy_tiocsti = legacy_tiocsti_status();
    let limitations = limitations(!request.user_grants.is_empty(), &legacy_tiocsti);
    Ok(ConfinementPlan {
        mode: "filesystem".to_owned(),
        minimum_abi: 3,
        working_directory: resolve_working_directory(request, &grants, &quarter_command_root)?,
        quarter_command_root,
        grants,
        omitted_paths: omitted,
        executable_path,
        omitted_host_path_entries,
        legacy_tiocsti,
        limitations,
    })
}

pub(super) fn resolve_executable(
    program: &OsStr,
    search_path: &OsStr,
    plan: &ConfinementPlan,
) -> Result<ConfinedExecutable> {
    let path = Path::new(program);
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else if path.components().count() == 1 && matches!(path.components().next(), Some(Component::Normal(_))) {
        resolve_name(program, search_path)?
    } else {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "confined commands must use an absolute path or a bare command name",
        )
        .with_hint("install the command inside the Quarter or name it through the confined PATH"));
    };
    let canonical = candidate
        .canonicalize()
        .map_err(|error| QuartersError::io("resolve confined executable", &candidate, error))?;
    let allowed = canonical.starts_with(&plan.quarter_command_root)
        || plan.grants.iter().any(|grant| {
            matches!(grant.access.as_str(), "read-execute" | "read-write") && canonical.starts_with(&grant.path)
        });
    let metadata = fs::metadata(&canonical)
        .map_err(|error| QuartersError::io("inspect confined executable", &canonical, error))?;
    if !allowed || !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(QuartersError::new(
            ErrorKind::Unsupported,
            "the requested executable is outside the confined executable roots",
        )
        .with_hint(
            "install it inside the Quarter or use a system executable reported by 'quarters env --confinement filesystem'",
        ));
    }
    let descriptor = open_stable_executable(&canonical, &metadata)?;
    Ok(ConfinedExecutable {
        path: canonical,
        descriptor,
    })
}

fn open_stable_executable(path: &Path, expected: &fs::Metadata) -> Result<File> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;

    let descriptor = open(
        path,
        OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| QuartersError::io("open confined executable", path, error.into()))?;
    let descriptor = File::from(descriptor);
    let observed = descriptor
        .metadata()
        .map_err(|error| QuartersError::io("inspect opened confined executable", path, error))?;
    if observed.dev() == expected.dev() && observed.ino() == expected.ino() && observed.is_file() {
        return Ok(descriptor);
    }
    Err(QuartersError::new(
        ErrorKind::System,
        "the confined executable changed while it was being opened",
    )
    .with_hint("retry after concurrent changes to the executable have stopped"))
}

fn validate_private_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect filesystem policy directory", path, error))?;
    let private = metadata.permissions().mode() & 0o777 == 0o700;
    if metadata.is_dir() && !metadata.file_type().is_symlink() && metadata.uid() == Uid::current().as_raw() && private {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        format!("{label} is not a protected current-user directory"),
    ))
}

fn push_canonical(
    grants: &mut Vec<ConfinementGrant>,
    path: &Path,
    access: &str,
    source: &str,
    required: bool,
) -> Result<()> {
    let canonical = path
        .canonicalize()
        .map_err(|error| QuartersError::io("resolve required filesystem policy path", path, error))?;
    let metadata = fs::metadata(&canonical)
        .map_err(|error| QuartersError::io("inspect required filesystem policy path", &canonical, error))?;
    grants.push(ConfinementGrant {
        path: canonical,
        access: access.to_owned(),
        source: source.to_owned(),
        required,
        anchor_device: metadata.dev(),
        anchor_inode: metadata.ino(),
    });
    Ok(())
}

fn push_optional(
    grants: &mut Vec<ConfinementGrant>,
    omitted: &mut Vec<PathBuf>,
    path: &Path,
    access: &str,
    source: &str,
) -> Result<()> {
    match path.canonicalize() {
        Ok(canonical) => {
            let metadata = fs::metadata(&canonical)
                .map_err(|error| QuartersError::io("inspect optional filesystem policy path", &canonical, error))?;
            grants.push(ConfinementGrant {
                path: canonical,
                access: access.to_owned(),
                source: source.to_owned(),
                required: false,
                anchor_device: metadata.dev(),
                anchor_inode: metadata.ino(),
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => omitted.push(path.to_path_buf()),
        Err(error) => {
            return Err(QuartersError::io(
                "resolve optional filesystem policy path",
                path,
                error,
            ));
        }
    }
    Ok(())
}

fn push_optional_terminal(grants: &mut Vec<ConfinementGrant>, omitted: &mut Vec<PathBuf>, path: &Path) -> Result<()> {
    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(descriptor) => {
            drop(descriptor);
            push_optional(grants, omitted, path, "device", "compatibility-device")
        }
        Err(error) if terminal_is_unavailable(&error) => {
            omitted.push(path.to_path_buf());
            Ok(())
        }
        Err(error) => Err(QuartersError::io("probe optional terminal device", path, error)),
    }
}

fn terminal_is_unavailable(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(nix::libc::ENXIO) || error.kind() == std::io::ErrorKind::NotFound
}

fn add_resolver_target(grants: &mut Vec<ConfinementGrant>, omitted: &mut Vec<PathBuf>) -> Result<()> {
    let resolver = Path::new("/etc/resolv.conf");
    match resolver.canonicalize() {
        Ok(target) if !target.starts_with("/etc") => {
            push_canonical(grants, &target, "read-file", "derived-resolver-target", false)?;
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => omitted.push(resolver.to_path_buf()),
        Err(error) => return Err(QuartersError::io("resolve DNS configuration", resolver, error)),
    }
    Ok(())
}

fn add_user_grants(request: &ConfinementRequest<'_>, grants: &mut Vec<ConfinementGrant>) -> Result<()> {
    if request.user_grants.len() > MAX_USER_GRANTS {
        return Err(QuartersError::new(
            ErrorKind::ResourceLimit,
            format!("filesystem confinement accepts at most {MAX_USER_GRANTS} user grants"),
        ));
    }
    let reserved = reserved_paths(request)?;
    let mut user_paths = BTreeSet::<PathBuf>::new();
    for requested in request.user_grants {
        if !requested.path.is_absolute() {
            return Err(QuartersError::new(
                ErrorKind::InvalidInput,
                "--grant-path requires an existing absolute path",
            ));
        }
        let canonical = requested
            .path
            .canonicalize()
            .map_err(|error| QuartersError::io("resolve user-granted path", &requested.path, error))?;
        if user_paths.contains(&canonical) {
            return Err(QuartersError::new(
                ErrorKind::InvalidInput,
                "multiple --grant-path options resolve to the same path",
            )
            .with_hint("select one access level for each canonical data path"));
        }
        if user_paths.iter().any(|path| paths_overlap(path, &canonical)) {
            return Err(QuartersError::new(
                ErrorKind::InvalidInput,
                "overlapping --grant-path options are ambiguous",
            )
            .with_hint("select distinct, non-nested canonical data roots"));
        }
        user_paths.insert(canonical.clone());
        reject_reserved_grant(&canonical, &reserved)?;
        reject_built_in_grant_overlap(&canonical, grants)?;
        let metadata = fs::metadata(&canonical)
            .map_err(|error| QuartersError::io("inspect user-granted path", &canonical, error))?;
        let access = user_access_class(requested.access, &metadata, &canonical)?;
        grants.push(ConfinementGrant {
            path: canonical,
            access: access.to_owned(),
            source: "user-granted".to_owned(),
            required: true,
            anchor_device: metadata.dev(),
            anchor_inode: metadata.ino(),
        });
    }
    Ok(())
}

fn reject_built_in_grant_overlap(path: &Path, grants: &[ConfinementGrant]) -> Result<()> {
    if grants.iter().all(|grant| !paths_overlap(path, &grant.path)) {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "user grant overlaps a built-in confinement root",
    )
    .with_hint("select a distinct data path outside every root reported by the confinement plan"))
}

fn user_access_class(access: UserGrantAccess, metadata: &fs::Metadata, path: &Path) -> Result<&'static str> {
    match (metadata.is_dir(), metadata.is_file(), access) {
        (true, _, UserGrantAccess::ReadOnly) => Ok("data-read"),
        (true, _, UserGrantAccess::ReadWrite) => Ok("data-read-write"),
        (_, true, UserGrantAccess::ReadOnly) => Ok("data-read-file"),
        (_, true, UserGrantAccess::ReadWrite) => Ok("data-read-write-file"),
        _ => Err(QuartersError::new(
            ErrorKind::Unsupported,
            format!(
                "user-granted path is not a regular file or directory: {}",
                path.display()
            ),
        )),
    }
}

fn reserved_paths(request: &ConfinementRequest<'_>) -> Result<Vec<PathBuf>> {
    let mut reserved = Vec::new();
    for (path, operation) in [
        (request.store_root, "resolve the Quarters store root"),
        (request.runtime, "resolve the Quarter runtime"),
        (request.current_executable, "resolve the running Quarters executable"),
    ] {
        reserved.push(
            path.canonicalize()
                .map_err(|error| QuartersError::io(operation, path, error))?,
        );
    }
    if let Some(path) = request.request_executable {
        reserved.push(
            path.canonicalize()
                .map_err(|error| QuartersError::io("resolve the request executable", path, error))?,
        );
    }
    let user = nix::unistd::User::from_uid(Uid::current())
        .map_err(|error| {
            QuartersError::new(ErrorKind::System, "could not resolve the current account").with_source(error)
        })?
        .ok_or_else(|| QuartersError::new(ErrorKind::Unsupported, "the current account has no passwd record"))?;
    let passwd_home = user
        .dir
        .canonicalize()
        .map_err(|error| QuartersError::io("resolve the current account home", &user.dir, error))?;
    for name in [".ssh", ".gnupg"] {
        let lexical = passwd_home.join(name);
        reserved.push(lexical.canonicalize().unwrap_or_else(|_error| lexical.clone()));
        reserved.push(lexical);
    }
    if request.home_view {
        reserved.push(passwd_home);
    }
    Ok(reserved)
}

fn reject_reserved_grant(grant: &Path, reserved: &[PathBuf]) -> Result<()> {
    if reserved.iter().all(|path| !paths_overlap(grant, path)) {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "user grant overlaps Quarters management, runtime, executable, credential, or home-view state",
    )
    .with_hint("select a narrower data path outside the reported protected roots"))
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn resolve_working_directory(
    request: &ConfinementRequest<'_>,
    grants: &[ConfinementGrant],
    effective: &Path,
) -> Result<PathBuf> {
    let Some(requested) = request.working_directory else {
        return Ok(effective.to_path_buf());
    };
    if !requested.is_absolute() {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "--workdir requires an existing absolute directory",
        ));
    }
    let canonical = if request.home_view {
        crate::platform::resolve_home_view_working_directory(requested, request.space_home, request.effective_home)?
    } else {
        requested
            .canonicalize()
            .map_err(|error| QuartersError::io("resolve requested working directory", requested, error))?
    };
    if !canonical.is_dir() {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "--workdir must identify an existing directory",
        ));
    }
    let space = request
        .space_home
        .canonicalize()
        .map_err(|error| QuartersError::io("resolve Quarter home for working directory", request.space_home, error))?;
    if request.home_view && canonical.starts_with(effective) {
        return Ok(canonical);
    }
    if !request.home_view && canonical.starts_with(&space) {
        return Ok(canonical);
    }
    let data_granted = grants.iter().any(|grant| {
        grant.source == "user-granted"
            && matches!(grant.access.as_str(), "data-read" | "data-read-write")
            && canonical.starts_with(&grant.path)
    });
    if data_granted {
        return Ok(canonical);
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "a confined --workdir outside the Quarter home requires an explicit data grant",
    )
    .with_hint("repeat --grant-path for the working directory with :ro or :rw"))
}

fn ensure_store_disjoint(store_root: &Path, space_home: &Path, grants: &[ConfinementGrant]) -> Result<()> {
    let store = store_root
        .canonicalize()
        .map_err(|error| QuartersError::io("resolve confinement store root", store_root, error))?;
    let home = space_home
        .canonicalize()
        .map_err(|error| QuartersError::io("resolve confinement Quarter home", space_home, error))?;
    let overlaps = overlaps_executable_root(&store, &home, grants);
    if !overlaps {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "the Quarters store overlaps a protected host hierarchy admitted by confinement",
    )
    .with_hint("move --root outside the system, configuration, and compatibility roots in the confinement plan"))
}

fn overlaps_executable_root(store: &Path, home: &Path, grants: &[ConfinementGrant]) -> bool {
    grants.iter().any(|grant| {
        matches!(
            grant.source.as_str(),
            "system-executable-root" | "system-configuration" | "process-compatibility"
        ) && (store.starts_with(&grant.path) || home.starts_with(&grant.path))
    })
}

fn deduplicate_grants(grants: &mut Vec<ConfinementGrant>) {
    let mut seen = BTreeSet::new();
    grants.retain(|grant| seen.insert((grant.path.clone(), grant.access.clone())));
    grants.sort_by(|left, right| left.path.cmp(&right.path).then(left.access.cmp(&right.access)));
}

fn reconstructed_path(
    home: &Path,
    runtime: &Path,
    grants: &[ConfinementGrant],
    host_path: Option<&OsString>,
) -> Vec<PathBuf> {
    let mut paths = vec![
        runtime.join("bin"),
        home.join(".local/bin"),
        home.join(".cargo/bin"),
        home.join(".local/share/npm/bin"),
        home.join(".local/share/uv/tools/bin"),
        home.join(".nix-profile/bin"),
    ];
    for grant in grants.iter().filter(|grant| grant.access == "read-execute") {
        for suffix in ["bin", "sbin"] {
            let candidate = grant.path.join(suffix);
            if candidate.is_dir() {
                paths.push(candidate);
            }
        }
        if grant.path.file_name() == Some(OsStr::new("bin")) {
            paths.push(grant.path.clone());
        }
    }
    if let Some(host_path) = host_path {
        paths.extend(env::split_paths(host_path).filter_map(|entry| {
            let canonical = entry.canonicalize().ok()?;
            let granted = grants
                .iter()
                .any(|grant| grant.access == "read-execute" && canonical.starts_with(&grant.path));
            (canonical.is_dir() && granted).then_some(canonical)
        }));
    }
    let mut seen = BTreeSet::new();
    paths.retain(|path| seen.insert(path.clone()));
    paths
}

fn omitted_path_count(host_path: Option<&OsString>, allowed: &[PathBuf]) -> usize {
    let allowed: BTreeSet<PathBuf> = allowed.iter().cloned().collect();
    host_path.map_or(0, |value| {
        env::split_paths(value)
            .filter_map(|entry| entry.canonicalize().ok())
            .filter(|entry| !allowed.contains(entry))
            .count()
    })
}

fn resolve_name(program: &OsStr, search_path: &OsStr) -> Result<PathBuf> {
    for directory in env::split_paths(search_path) {
        let candidate = directory.join(program);
        if fs::metadata(&candidate)
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        {
            return Ok(candidate);
        }
    }
    Err(QuartersError::new(
        ErrorKind::NotFound,
        format!(
            "command is unavailable on the confined PATH: {}",
            program.to_string_lossy()
        ),
    )
    .with_hint("install it inside the Quarter or choose a system command"))
}

fn limitations(has_user_grants: bool, legacy_tiocsti: &crate::platform::LegacyTiocstiStatus) -> Vec<String> {
    let mut items = vec![
        "known-path metadata, stat, readlink, access checks and O_PATH remain observable",
        "the policy grants /proc for compatibility; process visibility also depends on kernel ptrace policy",
        "network, IPC and device isolation are not provided",
        "inherited standard streams and already-open file descriptors remain usable",
        "no_new_privs disables set-id elevation such as ordinary sudo",
        "same-UID unconfined processes retain their normal access to Quarter state",
        "/sys and /dev/shm are omitted, which can affect topology probes and multiprocessing",
        "descriptor-bound interpreter scripts can observe a /dev/fd source path and inherit one readless O_PATH handle",
    ];
    if has_user_grants {
        items.push(
            "user-granted host paths are exposed to the confined process tree; Quarters does not inspect their content",
        );
        items.push(
            "Landlock combines overlapping rules by union; Quarters rejects overlap between explicit grants and all other explicit or built-in roots",
        );
    }
    if legacy_tiocsti.state != "disabled" {
        items.push(
            "legacy TIOCSTI terminal injection is not proven disabled; a shared controlling terminal can cross the filesystem boundary",
        );
    }
    items.into_iter().map(str::to_owned).collect()
}

fn legacy_tiocsti_status() -> crate::platform::LegacyTiocstiStatus {
    let path = Path::new("/proc/sys/dev/tty/legacy_tiocsti");
    legacy_tiocsti_status_from(&fs::read_to_string(path))
}

fn legacy_tiocsti_status_from(value: &std::io::Result<String>) -> crate::platform::LegacyTiocstiStatus {
    match value.as_deref().map(str::trim) {
        Ok("0") => crate::platform::LegacyTiocstiStatus {
            probed: true,
            state: "disabled".to_owned(),
            detail: "dev.tty.legacy_tiocsti is 0; legacy TIOCSTI injection is disabled".to_owned(),
        },
        Ok("1") => crate::platform::LegacyTiocstiStatus {
            probed: true,
            state: "enabled".to_owned(),
            detail: "dev.tty.legacy_tiocsti is 1; Landlock ABI 3 does not mediate this terminal ioctl".to_owned(),
        },
        Ok(_) => crate::platform::LegacyTiocstiStatus {
            probed: false,
            state: "unknown".to_owned(),
            detail: "dev.tty.legacy_tiocsti returned an unrecognized value".to_owned(),
        },
        Err(error) => crate::platform::LegacyTiocstiStatus {
            probed: false,
            state: "unreadable".to_owned(),
            detail: format!("dev.tty.legacy_tiocsti could not be read: {error}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConfinementGrant, legacy_tiocsti_status_from, limitations, omitted_path_count, overlaps_executable_root,
        terminal_is_unavailable,
    };
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    #[test]
    fn merged_usr_aliases_are_not_reported_as_omitted() -> std::io::Result<()> {
        let bin = Path::new("/bin").canonicalize()?;
        let host = OsString::from("/bin:/definitely-missing-quarters-path");
        assert_eq!(omitted_path_count(Some(&host), &[bin]), 0);
        Ok(())
    }

    #[test]
    fn store_beneath_an_executable_root_is_rejected() {
        let grant = ConfinementGrant {
            path: PathBuf::from("/opt"),
            access: "read-execute".to_owned(),
            source: "system-executable-root".to_owned(),
            required: false,
            anchor_device: 0,
            anchor_inode: 0,
        };
        assert!(overlaps_executable_root(
            Path::new("/opt/quarters"),
            Path::new("/opt/quarters/spaces/demo/home"),
            &[grant],
        ));
        let configuration = ConfinementGrant {
            path: PathBuf::from("/etc"),
            access: "read".to_owned(),
            source: "system-configuration".to_owned(),
            required: true,
            anchor_device: 0,
            anchor_inode: 0,
        };
        assert!(overlaps_executable_root(
            Path::new("/etc/quarters"),
            Path::new("/etc/quarters/spaces/demo/home"),
            &[configuration],
        ));
    }

    #[test]
    fn terminal_omission_is_limited_to_absence_and_no_controlling_terminal() {
        for code in [nix::libc::ENOENT, nix::libc::ENXIO] {
            assert!(terminal_is_unavailable(&std::io::Error::from_raw_os_error(code)));
        }
        for code in [nix::libc::EACCES, nix::libc::EMFILE, nix::libc::ENOMEM] {
            assert!(!terminal_is_unavailable(&std::io::Error::from_raw_os_error(code)));
        }
    }

    #[test]
    fn unreadable_tiocsti_policy_is_explicitly_unsafe() {
        let result = Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        let status = legacy_tiocsti_status_from(&result);
        assert!(!status.probed);
        assert_eq!(status.state, "unreadable");
        assert!(
            limitations(false, &status)
                .iter()
                .any(|item| item.contains("not proven disabled"))
        );
    }
}
