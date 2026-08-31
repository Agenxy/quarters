//! Policy path discovery, reporting and executable resolution.

use crate::platform::{ConfinementGrant, ConfinementPlan};
use crate::{ErrorKind, QuartersError, Result};
use nix::unistd::Uid;
use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

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

pub(super) fn build_plan(
    space_home: &Path,
    effective_home: &Path,
    runtime: &Path,
    host_path: Option<&OsString>,
) -> Result<ConfinementPlan> {
    validate_private_directory(space_home, "Quarter home")?;
    validate_private_directory(runtime, "Quarter runtime")?;
    let mut grants = Vec::new();
    let mut omitted = Vec::new();
    push_canonical(&mut grants, space_home, "read-write", "quarter-home", true)?;
    push_canonical(&mut grants, runtime, "read-write", "quarter-runtime", true)?;
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
    ensure_store_disjoint(space_home, &grants)?;
    for path in DEVICE_PATHS {
        let required = *path == "/dev/null";
        if required {
            push_canonical(&mut grants, Path::new(path), "device", "compatibility-device", true)?;
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
    deduplicate_grants(&mut grants);
    if !grants.iter().any(|grant| grant.access == "read-execute") {
        return Err(QuartersError::new(
            ErrorKind::Unsupported,
            "filesystem confinement found no executable system root",
        ));
    }
    let executable_path = reconstructed_path(effective_home, runtime, &grants, host_path);
    let omitted_host_path_entries = omitted_path_count(host_path, &executable_path);
    Ok(ConfinementPlan {
        mode: "filesystem".to_owned(),
        minimum_abi: 3,
        working_directory: effective_home
            .canonicalize()
            .map_err(|error| QuartersError::io("resolve confinement working directory", effective_home, error))?,
        grants,
        omitted_paths: omitted,
        executable_path,
        omitted_host_path_entries,
        limitations: limitations(),
    })
}

pub(super) fn resolve_executable(program: &OsStr, search_path: &OsStr, plan: &ConfinementPlan) -> Result<PathBuf> {
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
    let allowed = canonical.starts_with(&plan.working_directory)
        || plan.grants.iter().any(|grant| {
            matches!(grant.access.as_str(), "read-execute" | "read-write") && canonical.starts_with(&grant.path)
        });
    let executable =
        fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0);
    if allowed && executable {
        return Ok(canonical);
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "the requested executable is outside the confined executable roots",
    )
    .with_hint(
        "install it inside the Quarter or use a system executable reported by 'quarters env --confinement filesystem'",
    ))
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
    grants.push(ConfinementGrant {
        path: canonical,
        access: access.to_owned(),
        source: source.to_owned(),
        required,
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
            grants.push(ConfinementGrant {
                path: canonical,
                access: access.to_owned(),
                source: source.to_owned(),
                required: false,
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

fn ensure_store_disjoint(space_home: &Path, grants: &[ConfinementGrant]) -> Result<()> {
    let store = space_home
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| QuartersError::new(ErrorKind::CorruptState, "Quarter home has no store root"))?
        .canonicalize()
        .map_err(|error| QuartersError::io("resolve confinement store root", space_home, error))?;
    let home = space_home
        .canonicalize()
        .map_err(|error| QuartersError::io("resolve confinement Quarter home", space_home, error))?;
    let overlaps = overlaps_executable_root(&store, &home, grants);
    if !overlaps {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "the Quarters store overlaps a system executable hierarchy admitted by confinement",
    )
    .with_hint("move --root outside /usr, /opt, /nix/store and other reported executable roots"))
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

fn limitations() -> Vec<String> {
    [
        "known-path metadata, stat, readlink, access checks and O_PATH remain observable",
        "the policy grants /proc for compatibility; process visibility also depends on kernel ptrace policy",
        "network, IPC and device isolation are not provided",
        "inherited standard streams and already-open file descriptors remain usable",
        "no_new_privs disables set-id elevation such as ordinary sudo",
        "same-UID unconfined processes retain their normal access to Quarter state",
        "/sys and /dev/shm are omitted, which can affect topology probes and multiprocessing",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::{ConfinementGrant, omitted_path_count, overlaps_executable_root};
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
        };
        assert!(overlaps_executable_root(
            Path::new("/etc/quarters"),
            Path::new("/etc/quarters/spaces/demo/home"),
            &[configuration],
        ));
    }
}
