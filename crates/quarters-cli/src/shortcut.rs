//! Distribution-aware managed command shortcuts.

use crate::cli::{ShortcutArgs, ShortcutCommand, ShortcutTargetArgs};
use quarters_core::{ErrorKind, QuartersError, Result, executable_matches};
use std::env;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

const PARENT_SHELL_LIMITATION: &str =
    "a child process cannot inspect transient aliases or functions in its parent shell";
type ShortcutIdentity = (u64, u64);
type EntryInspection = (ShortcutState, Option<PathBuf>, Option<ShortcutIdentity>);

/// Shortcut operation used by presentation code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShortcutAction {
    /// Read current resolution.
    Status,
    /// Create a managed link.
    Install,
    /// Remove a managed link.
    Remove,
}

impl ShortcutAction {
    /// Stable action name.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Install => "install",
            Self::Remove => "remove",
        }
    }
}

/// Observed shortcut state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShortcutState {
    /// No entry or command match exists.
    Absent,
    /// The target is a verified managed link.
    Managed,
    /// The link has Quarters' managed shape but targets an older live launcher.
    Relocated,
    /// The link has Quarters' managed shape but its launcher is now absent.
    Stale,
    /// Another filesystem or PATH entry owns the command.
    Collision,
    /// The name is a shell builtin or reserved word.
    Reserved,
    /// Inspection could not resolve its environment.
    Unavailable,
}

impl ShortcutState {
    /// Stable state name.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Managed => "managed",
            Self::Relocated => "relocated",
            Self::Stale => "stale",
            Self::Collision => "collision",
            Self::Reserved => "reserved",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Complete bounded shortcut inspection.
#[derive(Clone, Debug)]
pub(crate) struct ShortcutReport {
    /// Validated command name.
    pub(crate) name: String,
    /// Host or baseline-space environment inspected.
    pub(crate) context: &'static str,
    /// Current managed/collision state.
    pub(crate) state: ShortcutState,
    /// Intended link directory, when resolvable.
    pub(crate) directory: Option<PathBuf>,
    /// Intended link entry, when resolvable.
    pub(crate) entry: Option<PathBuf>,
    /// Current symlink target, if the entry is a symlink.
    pub(crate) link_target: Option<PathBuf>,
    entry_device: Option<u64>,
    entry_inode: Option<u64>,
    /// Every executable match for the shortcut in PATH order.
    pub(crate) shortcut_matches: Vec<PathBuf>,
    /// Every executable `quarters` match in PATH order.
    pub(crate) quarters_matches: Vec<PathBuf>,
    /// Whether the intended directory participates in PATH resolution.
    pub(crate) directory_on_path: bool,
    /// Exact parent-shell check the user can run.
    pub(crate) parent_shell_check: String,
    /// Honest parent-shell inspection limitation.
    pub(crate) limitation: &'static str,
    /// Inspection failure when state is unavailable.
    pub(crate) issue: Option<String>,
}

/// Execute one shortcut command.
pub(crate) fn run(arguments: &ShortcutArgs) -> Result<(ShortcutAction, ShortcutReport)> {
    match &arguments.command {
        ShortcutCommand::Status(target) => inspect(target).map(|report| (ShortcutAction::Status, report)),
        ShortcutCommand::Install(target) => install(target).map(|report| (ShortcutAction::Install, report)),
        ShortcutCommand::Remove(target) => remove(target).map(|report| (ShortcutAction::Remove, report)),
    }
}

/// Inspect the recommended shortcuts for doctor output without mutating state.
pub(crate) fn default_reports() -> Vec<ShortcutReport> {
    ["qts", "q"]
        .into_iter()
        .map(|name| {
            let target = ShortcutTargetArgs {
                name: name.to_owned(),
                directory: None,
            };
            inspect(&target).unwrap_or_else(|error| unavailable_report(name, &error))
        })
        .collect()
}

fn install(arguments: &ShortcutTargetArgs) -> Result<ShortcutReport> {
    refuse_space_mutation("install")?;
    let report = inspect(arguments)?;
    ensure_installable(&report)?;
    if report.state == ShortcutState::Managed {
        return Ok(report);
    }
    let directory = report.directory.as_deref().ok_or_else(missing_directory_error)?;
    validate_install_directory(directory)?;
    let entry = report.entry.as_deref().ok_or_else(missing_directory_error)?;
    let target = managed_target(directory, &stable_executable_matches("quarters")).ok_or_else(|| {
        QuartersError::new(ErrorKind::NotFound, "no installed 'quarters' command was found on PATH")
            .with_hint("install Quarters on the host PATH, then retry shortcut installation")
    })?;
    symlink(&target, entry).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            return QuartersError::new(
                ErrorKind::AlreadyExists,
                format!("shortcut entry already exists: {}", entry.display()),
            )
            .with_hint(format!(
                "run 'type -a {}' and 'quarters shortcut status {}'",
                report.name, report.name
            ));
        }
        QuartersError::io("install shortcut", entry, error)
    })?;
    sync_directory(directory).map_err(|error| {
        error.with_hint(format!(
            "shortcut '{}' was created, but directory durability could not be confirmed; inspect it before retrying",
            report.name
        ))
    })?;
    inspect(arguments)
}

fn remove(arguments: &ShortcutTargetArgs) -> Result<ShortcutReport> {
    refuse_space_mutation("remove")?;
    let report = inspect(arguments)?;
    match report.state {
        ShortcutState::Absent => return Ok(report),
        ShortcutState::Managed | ShortcutState::Relocated | ShortcutState::Stale => {}
        ShortcutState::Collision | ShortcutState::Reserved | ShortcutState::Unavailable => {
            return Err(collision_error(&report, "remove"));
        }
    }
    let directory = report.directory.as_deref().ok_or_else(missing_directory_error)?;
    validate_install_directory(directory)?;
    let entry = report.entry.as_deref().ok_or_else(missing_directory_error)?;
    let target = report
        .link_target
        .as_deref()
        .ok_or_else(|| collision_error(&report, "remove"))?;
    let device = report.entry_device.ok_or_else(|| collision_error(&report, "remove"))?;
    let inode = report.entry_inode.ok_or_else(|| collision_error(&report, "remove"))?;
    remove_exact_shortcut(directory, entry, target, device, inode)?;
    sync_directory(directory).map_err(|error| {
        error.with_hint(format!(
            "shortcut '{}' was removed, but directory durability could not be confirmed; inspect it before retrying",
            report.name
        ))
    })?;
    inspect(arguments)
}

fn inspect(arguments: &ShortcutTargetArgs) -> Result<ShortcutReport> {
    let name = validate_name(&arguments.name)?;
    let directory = resolve_directory(arguments.directory.as_deref())?;
    let entry = directory.join(&name);
    let quarters_matches = executable_matches("quarters");
    let shortcut_matches = executable_matches(&name);
    let desired = managed_target(&directory, &stable_executable_matches("quarters"));
    let (entry_state, link_target, identity) = inspect_entry(&entry, &directory, desired.as_deref())?;
    let state = if is_shell_reserved(&name) {
        ShortcutState::Reserved
    } else if matches!(
        entry_state,
        ShortcutState::Managed | ShortcutState::Relocated | ShortcutState::Stale
    ) {
        entry_state
    } else if entry_state == ShortcutState::Collision || !shortcut_matches.is_empty() {
        ShortcutState::Collision
    } else {
        ShortcutState::Absent
    };
    Ok(ShortcutReport {
        name: name.clone(),
        context: context(),
        state,
        directory_on_path: directory_is_on_path(&directory),
        directory: Some(directory),
        entry: Some(entry),
        link_target,
        entry_device: identity.map(|value| value.0),
        entry_inode: identity.map(|value| value.1),
        shortcut_matches,
        quarters_matches,
        parent_shell_check: format!("type -a {name}"),
        limitation: PARENT_SHELL_LIMITATION,
        issue: None,
    })
}

fn inspect_entry(entry: &Path, directory: &Path, desired: Option<&Path>) -> Result<EntryInspection> {
    let metadata = match fs::symlink_metadata(entry) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((ShortcutState::Absent, None, None));
        }
        Err(error) => return Err(QuartersError::io("inspect shortcut entry", entry, error)),
    };
    if !metadata.file_type().is_symlink() {
        return Ok((ShortcutState::Collision, None, Some((metadata.dev(), metadata.ino()))));
    }
    let target = fs::read_link(entry).map_err(|error| QuartersError::io("read shortcut link", entry, error))?;
    let state = if desired == Some(target.as_path()) {
        ShortcutState::Managed
    } else if is_managed_launcher_shape(&target) && launcher_is_executable(directory, &target) {
        ShortcutState::Relocated
    } else if is_managed_launcher_shape(&target) {
        ShortcutState::Stale
    } else {
        ShortcutState::Collision
    };
    let identity = nix::sys::stat::lstat(entry)
        .ok()
        .map(|status| (normalized_device(status.st_dev), status.st_ino));
    Ok((state, Some(target), identity))
}

fn remove_exact_shortcut(directory: &Path, entry: &Path, target: &Path, device: u64, inode: u64) -> Result<()> {
    let name = entry
        .file_name()
        .ok_or_else(|| QuartersError::new(ErrorKind::InvalidInput, "shortcut entry has no file name"))?;
    let directory_file = open_install_directory(directory)?;
    let metadata = nix::sys::stat::fstatat(&directory_file, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|error| QuartersError::io("reinspect shortcut", entry, std::io::Error::from(error)))?;
    let link_type = nix::sys::stat::SFlag::from_bits_truncate(metadata.st_mode);
    let actual = nix::fcntl::readlinkat(&directory_file, name)
        .map(PathBuf::from)
        .map_err(|error| QuartersError::io("reinspect shortcut target", entry, std::io::Error::from(error)))?;
    if link_type != nix::sys::stat::SFlag::S_IFLNK
        || normalized_device(metadata.st_dev) != device
        || metadata.st_ino != inode
        || actual != target
    {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            format!("shortcut changed before removal: {}", entry.display()),
        ));
    }
    nix::unistd::unlinkat(&directory_file, name, nix::unistd::UnlinkatFlags::NoRemoveDir)
        .map_err(|error| QuartersError::io("remove shortcut", entry, std::io::Error::from(error)))
}

#[cfg(target_os = "linux")]
const fn normalized_device(device: nix::libc::dev_t) -> u64 {
    device
}

#[cfg(target_os = "macos")]
fn normalized_device(device: nix::libc::dev_t) -> u64 {
    u64::from(device.cast_unsigned())
}

fn open_install_directory(directory: &Path) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW);
    options
        .open(directory)
        .map_err(|error| QuartersError::io("open shortcut directory", directory, error))
}

fn is_managed_launcher_shape(target: &Path) -> bool {
    target == Path::new("quarters")
        || (target.is_absolute() && target.file_name() == Some(std::ffi::OsStr::new("quarters")))
}

fn launcher_is_executable(directory: &Path, target: &Path) -> bool {
    let launcher = if target.is_absolute() {
        target.to_path_buf()
    } else {
        directory.join(target)
    };
    launcher
        .metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

fn ensure_installable(report: &ShortcutReport) -> Result<()> {
    if !report.directory_on_path {
        let directory = report.directory.as_deref().ok_or_else(missing_directory_error)?;
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            format!("shortcut directory is not on PATH: {}", directory.display()),
        )
        .with_hint("choose an existing absolute PATH directory with --dir, or add ~/.local/bin to PATH first"));
    }
    match report.state {
        ShortcutState::Absent | ShortcutState::Managed => Ok(()),
        ShortcutState::Relocated
        | ShortcutState::Stale
        | ShortcutState::Collision
        | ShortcutState::Reserved
        | ShortcutState::Unavailable => Err(collision_error(report, "install")),
    }
}

fn collision_error(report: &ShortcutReport, operation: &str) -> QuartersError {
    QuartersError::new(
        ErrorKind::AlreadyExists,
        format!(
            "cannot {operation} shortcut '{}': command resolution is {}",
            report.name,
            report.state.as_str()
        ),
    )
    .with_hint(format!(
        "run '{}' in the parent shell; Quarters never overwrites or removes an unverified command",
        report.parent_shell_check
    ))
}

fn managed_target(directory: &Path, quarters_matches: &[PathBuf]) -> Option<PathBuf> {
    let command = quarters_matches.first()?;
    if command.parent() == Some(directory) {
        return Some(PathBuf::from("quarters"));
    }
    Some(command.clone())
}

fn stable_executable_matches(name: &str) -> Vec<PathBuf> {
    let absolute_directories = env::var_os("PATH")
        .map(|path| {
            env::split_paths(&path)
                .filter(|directory| directory.is_absolute())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    executable_matches(name)
        .into_iter()
        .filter(|candidate| {
            candidate
                .parent()
                .is_some_and(|parent| absolute_directories.iter().any(|directory| directory == parent))
        })
        .collect()
}

fn resolve_directory(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(directory) = explicit {
        if directory.is_absolute() {
            return Ok(directory.to_path_buf());
        }
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            format!("shortcut directory must be absolute: {}", directory.display()),
        ));
    }
    let home = env::var_os("HOME").map(PathBuf::from).filter(|path| path.is_absolute());
    home.map(|path| path.join(".local/bin"))
        .ok_or_else(missing_directory_error)
}

fn validate_install_directory(directory: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| QuartersError::io("inspect shortcut directory", directory, error))?;
    let private_enough = metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == nix::unistd::Uid::current().as_raw()
        && metadata.permissions().mode() & 0o022 == 0;
    if private_enough {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        format!(
            "shortcut directory must be a user-owned directory that is not group- or other-writable: {}",
            directory.display()
        ),
    ))
}

fn directory_is_on_path(directory: &Path) -> bool {
    let Ok(expected) = fs::canonicalize(directory) else {
        return false;
    };
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    let current = env::current_dir().ok();
    env::split_paths(&path).any(|candidate| {
        let candidate = if candidate.is_absolute() {
            candidate
        } else if let Some(current) = &current {
            current.join(candidate)
        } else {
            return false;
        };
        fs::canonicalize(candidate).is_ok_and(|candidate| candidate == expected)
    })
}

fn sync_directory(directory: &Path) -> Result<()> {
    validate_install_directory(directory)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW);
    let file = options
        .open(directory)
        .map_err(|error| QuartersError::io("open shortcut directory for syncing", directory, error))?;
    file.sync_all()
        .map_err(|error| QuartersError::io("sync shortcut directory", directory, error))
}

fn validate_name(name: &str) -> Result<String> {
    let valid = (1..=32).contains(&name.len())
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        return Ok(name.to_owned());
    }
    Err(QuartersError::new(
        ErrorKind::InvalidInput,
        "shortcut names must be 1-32 ASCII letters, numbers, hyphens or underscores and cannot start with a hyphen",
    ))
}

fn is_shell_reserved(name: &str) -> bool {
    matches!(
        name,
        "alias"
            | "autoload"
            | "bg"
            | "bind"
            | "bindkey"
            | "break"
            | "builtin"
            | "case"
            | "cd"
            | "command"
            | "compgen"
            | "complete"
            | "continue"
            | "declare"
            | "dirs"
            | "disown"
            | "do"
            | "done"
            | "elif"
            | "else"
            | "emulate"
            | "enable"
            | "esac"
            | "eval"
            | "echo"
            | "exec"
            | "exit"
            | "export"
            | "false"
            | "fc"
            | "fg"
            | "fi"
            | "for"
            | "function"
            | "getopts"
            | "hash"
            | "history"
            | "if"
            | "jobs"
            | "kill"
            | "let"
            | "local"
            | "logout"
            | "mapfile"
            | "noglob"
            | "popd"
            | "print"
            | "printf"
            | "pushd"
            | "pwd"
            | "read"
            | "readarray"
            | "readonly"
            | "return"
            | "sched"
            | "set"
            | "setopt"
            | "shift"
            | "shopt"
            | "source"
            | "suspend"
            | "test"
            | "then"
            | "time"
            | "times"
            | "trap"
            | "true"
            | "type"
            | "typeset"
            | "ulimit"
            | "umask"
            | "unalias"
            | "unset"
            | "until"
            | "wait"
            | "while"
            | "whence"
            | "where"
            | "which"
            | "zcompile"
            | "zformat"
            | "zle"
            | "zmodload"
            | "zparseopts"
            | "zregexparse"
            | "zstyle"
    )
}

fn refuse_space_mutation(operation: &str) -> Result<()> {
    if env::var_os("QUARTERS_SPACE").is_none() && env::var_os("QUARTERS_NO_HOST_ESCAPE").is_none() {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        format!("shortcut {operation} is unavailable inside a Quarter"),
    )
    .with_hint("exit to the host shell, verify command resolution there, then retry"))
}

fn context() -> &'static str {
    if env::var_os("QUARTERS_NO_HOST_ESCAPE").is_some() {
        "home-view"
    } else if env::var_os("QUARTERS_SPACE").is_some() {
        "space"
    } else {
        "host"
    }
}

fn unavailable_report(name: &str, error: &QuartersError) -> ShortcutReport {
    ShortcutReport {
        name: name.to_owned(),
        context: context(),
        state: ShortcutState::Unavailable,
        directory: None,
        entry: None,
        link_target: None,
        entry_device: None,
        entry_inode: None,
        shortcut_matches: Vec::new(),
        quarters_matches: executable_matches("quarters"),
        directory_on_path: false,
        parent_shell_check: format!("type -a {name}"),
        limitation: PARENT_SHELL_LIMITATION,
        issue: Some(error.message().to_owned()),
    }
}

fn missing_directory_error() -> QuartersError {
    QuartersError::new(
        ErrorKind::InvalidInput,
        "the shortcut directory could not be resolved from an absolute HOME",
    )
    .with_hint("run from the host shell with HOME set, or pass an existing absolute PATH directory with --dir")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    #[test]
    fn shortcut_names_are_path_safe() {
        for name in ["qts", "q", "quarters-short"] {
            assert!(validate_name(name).is_ok());
        }
        for name in ["", "-q", "../q", "q/name", "q name"] {
            assert!(validate_name(name).is_err());
        }
    }

    #[test]
    fn known_shell_words_are_reserved() {
        for name in [
            "alias", "cd", "declare", "echo", "eval", "setopt", "shopt", "time", "while", "zstyle",
        ] {
            assert!(is_shell_reserved(name));
        }
        assert!(!is_shell_reserved("qts"));
        assert!(!is_shell_reserved("q"));
    }

    #[test]
    fn replacement_shortcut_is_never_removed() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let directory = temporary.path().join("bin");
        fs::create_dir(&directory).expect("create directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("protect directory");
        let entry = directory.join("q");
        symlink("quarters", &entry).expect("create managed shortcut");
        let metadata = fs::symlink_metadata(&entry).expect("inspect shortcut");
        fs::remove_file(&entry).expect("remove original shortcut");
        fs::write(&entry, b"replacement").expect("create replacement");

        assert!(
            remove_exact_shortcut(
                &directory,
                &entry,
                Path::new("quarters"),
                metadata.dev(),
                metadata.ino()
            )
            .is_err()
        );
        assert_eq!(fs::read(&entry).expect("replacement retained"), b"replacement");
    }

    #[test]
    fn replacement_symlink_is_never_removed() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let directory = temporary.path().join("bin");
        fs::create_dir(&directory).expect("create directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("protect directory");
        let entry = directory.join("q");
        symlink("quarters", &entry).expect("create managed shortcut");
        let metadata = nix::sys::stat::lstat(&entry).expect("inspect shortcut");
        fs::remove_file(&entry).expect("remove original shortcut");
        symlink("quarters", &entry).expect("create replacement shortcut");

        assert!(
            remove_exact_shortcut(
                &directory,
                &entry,
                Path::new("quarters"),
                normalized_device(metadata.st_dev),
                metadata.st_ino
            )
            .is_err()
        );
        assert_eq!(
            fs::read_link(&entry).expect("replacement retained"),
            Path::new("quarters")
        );
    }
}
