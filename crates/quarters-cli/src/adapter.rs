//! Collision-safe OpenSSH invocation adapters.

pub(crate) use quarters_core::CommandLinkReport as AdapterReport;
use quarters_core::{
    CommandLinkState, ErrorKind, QuartersError, Result, Space, SpaceName, Store, ToolProbe, inspect_command_links,
};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

const TOOLS: [&str; 4] = ["ssh", "scp", "sftp", "ssh-add"];

pub(crate) fn invoked_adapter() -> Option<&'static str> {
    let executable = env::args_os().next()?;
    let name = Path::new(&executable).file_name()?;
    TOOLS.into_iter().find(|candidate| name == OsStr::new(candidate))
}

pub(crate) fn dispatch(tool: &str) -> Result<i32> {
    if direct_adapter_recursion() {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "a managed OpenSSH adapter resolved back to Quarters",
        )
        .with_hint(
            "inspect QUARTERS_HOST_PATH and the space's managed command links; recursive dispatch was stopped",
        ));
    }
    let home = validated_space_home()?;
    let host_path = env::var_os("QUARTERS_HOST_PATH").ok_or_else(|| {
        QuartersError::new(
            ErrorKind::Unsupported,
            "an OpenSSH adapter may run only inside a verified Quarter environment",
        )
    })?;
    let executable = resolve_host_tool(tool, &host_path)?;
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let mut command = Command::new(executable);
    command.env("QUARTERS_ADAPTER_PARENT_PID", std::process::id().to_string());
    if tool == "ssh-add" {
        reject_implicit_or_host_bound_ssh_add(&arguments)?;
    } else {
        reject_config_override(tool, &arguments)?;
        let config = home.join(".ssh/config");
        validate_private_config(&config)?;
        command.arg("-F").arg(config);
        add_state_overrides(&mut command, &home)?;
    }
    let status = command.args(arguments).status().map_err(|error| {
        QuartersError::new(ErrorKind::System, format!("could not run the host {tool} tool")).with_source(error)
    })?;
    Ok(status.code().unwrap_or(1))
}

fn direct_adapter_recursion() -> bool {
    env::var("QUARTERS_ADAPTER_PARENT_PID")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .is_some_and(|pid| pid == nix::unistd::getppid().as_raw())
}

fn add_state_overrides(command: &mut Command, home: &Path) -> Result<()> {
    let known_hosts_option = quoted_path_option("UserKnownHostsFile", &home.join(".ssh/known_hosts"))?;
    command
        .arg("-o")
        .arg(known_hosts_option)
        .arg("-o")
        .arg("IdentityFile=none")
        .arg("-o")
        .arg("IdentitiesOnly=no");
    Ok(())
}

fn quoted_path_option(name: &str, path: &Path) -> Result<OsString> {
    let path = path.as_os_str().as_bytes();
    if path.contains(&b'\n') || path.contains(&b'\r') {
        return Err(QuartersError::new(
            ErrorKind::Unsupported,
            "the space path contains a line break that OpenSSH options cannot represent safely",
        ));
    }
    let mut option = Vec::with_capacity(name.len() + path.len() + 3);
    option.extend_from_slice(name.as_bytes());
    option.extend_from_slice(b"=\"");
    for byte in path {
        if matches!(byte, b'\\' | b'"') {
            option.push(b'\\');
        }
        option.push(*byte);
    }
    option.push(b'"');
    Ok(OsString::from_vec(option))
}

pub(crate) fn inspect(space: &Space) -> Result<AdapterReport> {
    inspect_command_links(space)
}

pub(crate) fn tool_probes(report: Option<&AdapterReport>) -> Vec<ToolProbe> {
    let mut probes = quarters_core::tool_probes();
    let Some(report) = report else {
        return probes;
    };
    let managed = report.launcher.state == CommandLinkState::Managed
        && report
            .tools
            .iter()
            .all(|entry| entry.state == CommandLinkState::Managed);
    let summary = if managed {
        "verified managed links select the per-space OpenSSH configuration".to_owned()
    } else {
        let states = std::iter::once(&report.launcher)
            .chain(report.tools.iter())
            .map(|entry| format!("{}={}", entry.tool, entry.state.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        format!("managed OpenSSH route is incomplete ({states}); PATH may fall through to host tools")
    };
    if let Some(probe) = probes.iter_mut().find(|probe| probe.tool == "ssh") {
        probe.mechanism = summary;
    }
    probes
}

pub(crate) fn warn_if_incomplete(space: &Space) {
    let summary = inspect(space).map_or_else(
        |_error| Some("command-link state could not be verified".to_owned()),
        |report| {
            let incomplete = std::iter::once(&report.launcher)
                .chain(report.tools.iter())
                .filter(|entry| entry.state != CommandLinkState::Managed)
                .map(|entry| format!("{}={}", entry.tool, entry.state.as_str()))
                .collect::<Vec<_>>();
            (!incomplete.is_empty()).then(|| incomplete.join(", "))
        },
    );
    if let Some(summary) = summary {
        eprintln!(
            "quarters: warning: managed command route is incomplete ({summary}); OpenSSH names may resolve to host tools"
        );
        eprintln!("Try: quarters adapter status {}", space.manifest().name.as_str());
    }
}

pub(crate) fn install(store: &Store, space: &Space) -> Result<AdapterReport> {
    let executable = current_launcher()?;
    store.install_space_command_links(&space.manifest().name, &executable)
}

fn current_launcher() -> Result<PathBuf> {
    let executable = env::current_exe().map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not resolve the Quarters executable").with_source(error)
    })?;
    fs::canonicalize(&executable)
        .map_err(|error| QuartersError::io("resolve the stable Quarters executable", &executable, error))
}

pub(crate) fn remove(store: &Store, space: &Space) -> Result<AdapterReport> {
    store.remove_space_command_links(&space.manifest().name)
}

fn resolve_host_tool(tool: &str, path: &OsStr) -> Result<PathBuf> {
    let current = current_executable_identity()?;
    for directory in env::split_paths(path).filter(|directory| directory.is_absolute()) {
        let candidate = directory.join(tool);
        let Ok(resolved) = fs::canonicalize(candidate) else {
            continue;
        };
        if resolved.file_name() == Some(OsStr::new("quarters")) {
            continue;
        }
        if resolved
            .metadata()
            .is_ok_and(|metadata| metadata.is_file() && (metadata.dev(), metadata.ino()) != current)
            && nix::unistd::faccessat(
                nix::fcntl::AT_FDCWD,
                &resolved,
                nix::unistd::AccessFlags::X_OK,
                nix::fcntl::AtFlags::AT_EACCESS,
            )
            .is_ok()
        {
            return Ok(resolved);
        }
    }
    Err(QuartersError::new(
        ErrorKind::NotFound,
        format!("the host PATH has no executable '{tool}' for the managed adapter"),
    ))
}

fn current_executable_identity() -> Result<(u64, u64)> {
    let executable = env::current_exe().map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not identify the running Quarters executable").with_source(error)
    })?;
    let metadata = executable
        .metadata()
        .map_err(|error| QuartersError::io("inspect the running Quarters executable", &executable, error))?;
    Ok((metadata.dev(), metadata.ino()))
}

fn reject_config_override(tool: &str, arguments: &[OsString]) -> Result<()> {
    if leading_options_contain_config_override(tool, arguments) {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "the managed OpenSSH adapter does not accept a competing -F configuration",
        )
        .with_hint("use 'quarters host -- ssh ...' for an intentional host-configuration escape"));
    }
    Ok(())
}

fn leading_options_contain_config_override(tool: &str, arguments: &[OsString]) -> bool {
    let mut expects_value = false;
    for argument in arguments {
        let bytes = argument.as_encoded_bytes();
        if expects_value {
            expects_value = false;
            continue;
        }
        if bytes == b"--" || !bytes.starts_with(b"-") || bytes == b"-" {
            break;
        }
        for (index, byte) in bytes[1..].iter().copied().enumerate() {
            if byte == b'F' {
                return true;
            }
            if option_takes_value(tool, byte) {
                expects_value = index + 2 == bytes.len();
                break;
            }
        }
    }
    false
}

fn option_takes_value(tool: &str, option: u8) -> bool {
    match tool {
        "ssh" => b"BbcDEeFIiJLlmOoPpQRSWw".contains(&option),
        "scp" => b"cDFiJloPSX".contains(&option),
        "sftp" => b"BbcDFiJloPRSsX".contains(&option),
        _ => false,
    }
}

fn reject_implicit_or_host_bound_ssh_add(arguments: &[OsString]) -> Result<()> {
    if arguments.iter().any(|argument| {
        let bytes = argument.as_encoded_bytes();
        bytes.starts_with(b"--apple-")
            || (bytes.starts_with(b"-") && bytes[1..].iter().any(|byte| matches!(byte, b'A' | b'K')))
    }) {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "the managed ssh-add adapter does not import host keychain identities",
        )
        .with_hint(
            "name one per-space key explicitly, or use 'quarters host -- ssh-add ...' for an intentional host import",
        ));
    }
    if ssh_add_has_explicit_input_or_safe_action(arguments) {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::InvalidInput,
        "bare ssh-add would search default identity files through the host account home",
    )
    .with_hint("name a key beneath the Quarter explicitly, for example 'ssh-add ~/.ssh/id_ed25519'"))
}

fn ssh_add_has_explicit_input_or_safe_action(arguments: &[OsString]) -> bool {
    let mut expects_value = false;
    let mut explicit_target_option = false;
    let mut safe_action = false;
    for argument in arguments {
        let bytes = argument.as_encoded_bytes();
        if expects_value {
            expects_value = false;
            if explicit_target_option {
                return true;
            }
            explicit_target_option = false;
            continue;
        }
        if bytes == b"--" {
            continue;
        }
        if !bytes.starts_with(b"-") || bytes == b"-" {
            return true;
        }
        for (index, option) in bytes[1..].iter().copied().enumerate() {
            safe_action |= b"DLlQxX".contains(&option);
            if b"EHhSestT".contains(&option) {
                explicit_target_option = b"esT".contains(&option);
                expects_value = index + 2 == bytes.len();
                if !expects_value && explicit_target_option {
                    return true;
                }
                break;
            }
        }
    }
    safe_action
}

fn required_absolute_environment_path(name: &str) -> Result<PathBuf> {
    let path = env::var_os(name).map(PathBuf::from).filter(|path| path.is_absolute());
    path.ok_or_else(|| {
        QuartersError::new(
            ErrorKind::Unsupported,
            format!("the OpenSSH adapter requires a verified {name} value"),
        )
    })
}

fn validated_space_home() -> Result<PathBuf> {
    let home = required_absolute_environment_path("QUARTERS_SPACE_HOME")?;
    #[cfg(target_os = "linux")]
    if env::var_os("QUARTERS_NO_HOST_ESCAPE").as_deref() == Some(OsStr::new("home-view")) {
        return Ok(home);
    }
    let root = required_absolute_environment_path("QUARTERS_ROOT")?;
    let name = env::var("QUARTERS_SPACE").map_err(|error| {
        QuartersError::new(ErrorKind::Unsupported, "the OpenSSH adapter has no space name").with_source(error)
    })?;
    let name = SpaceName::parse(name)?;
    let store = Store::new(root)?;
    let space = store.open(&name)?;
    if space.home() == home {
        return Ok(home);
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "the OpenSSH adapter environment does not match the validated space home",
    ))
}

fn validate_private_config(path: &Path) -> Result<()> {
    validate_private_ssh_directory(path.parent().ok_or_else(|| {
        QuartersError::new(
            ErrorKind::CorruptState,
            "the per-space OpenSSH configuration has no parent directory",
        )
    })?)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect per-space OpenSSH configuration", path, error))?;
    let valid = metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == nix::unistd::Uid::current().as_raw()
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o022 == 0;
    if valid {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "the per-space OpenSSH configuration is not a protected current-user regular file",
    ))
}

fn validate_private_ssh_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect per-space OpenSSH directory", path, error))?;
    if metadata.file_type().is_dir()
        && metadata.uid() == nix::unistd::Uid::current().as_raw()
        && metadata.permissions().mode() & 0o022 == 0
    {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "the per-space OpenSSH directory is not a protected current-user directory",
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        leading_options_contain_config_override, quoted_path_option, resolve_host_tool,
        ssh_add_has_explicit_input_or_safe_action,
    };
    use std::ffi::{OsStr, OsString};
    use std::os::unix::fs::symlink;
    use std::path::Path;

    #[test]
    fn openssh_path_options_quote_spaces_and_metacharacters() -> quarters_core::Result<()> {
        let option = quoted_path_option("UserKnownHostsFile", Path::new("/tmp/a b/quote\"and\\slash"))?;
        assert_eq!(
            option,
            OsStr::new("UserKnownHostsFile=\"/tmp/a b/quote\\\"and\\\\slash\"")
        );
        Ok(())
    }

    #[test]
    fn config_override_scan_understands_clusters_and_stops_at_destination() {
        for arguments in [
            ["-4F", "/tmp/config", "host"],
            ["-vF/tmp/config", "host", ""],
            ["-p", "22", "-F"],
        ] {
            let arguments = arguments.into_iter().map(OsString::from).collect::<Vec<_>>();
            assert!(leading_options_contain_config_override("ssh", &arguments));
        }
        let remote = ["host", "grep", "-F", "pattern"]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        assert!(!leading_options_contain_config_override("ssh", &remote));
    }

    #[test]
    fn config_override_scan_uses_each_openssh_tools_option_grammar() {
        for (tool, raw) in [
            ("ssh", ["-D", "1080", "-F", "/tmp/config"]),
            ("ssh", ["-X", "-F", "/tmp/config", "host"]),
            ("sftp", ["-s", "internal-sftp", "-F", "/tmp/config"]),
        ] {
            let arguments = raw.into_iter().map(OsString::from).collect::<Vec<_>>();
            assert!(leading_options_contain_config_override(tool, &arguments));
        }
    }

    #[test]
    fn ssh_add_requires_an_explicit_identity_or_safe_non_loading_action() {
        assert!(!ssh_add_has_explicit_input_or_safe_action(&[]));
        assert!(!ssh_add_has_explicit_input_or_safe_action(&[
            OsString::from("-t"),
            OsString::from("1h")
        ]));
        assert!(ssh_add_has_explicit_input_or_safe_action(&[OsString::from("-l")]));
        assert!(ssh_add_has_explicit_input_or_safe_action(&[
            OsString::from("-q"),
            OsString::from("key")
        ]));
        assert!(ssh_add_has_explicit_input_or_safe_action(&[
            OsString::from("-T"),
            OsString::from("key.pub")
        ]));
    }

    #[test]
    fn host_tool_resolution_skips_symlink_and_hardlink_spellings() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        symlink(std::env::current_exe()?, temporary.path().join("ssh"))?;
        let host_path = std::env::join_paths([temporary.path()])?;
        let Err(error) = resolve_host_tool("ssh", &host_path) else {
            return Err("recursive adapter was not skipped".into());
        };
        assert_eq!(error.kind(), quarters_core::ErrorKind::NotFound);
        let executable = std::env::current_exe()?;
        let parent = executable.parent().ok_or("test executable has no parent")?;
        let same_filesystem = tempfile::tempdir_in(parent)?;
        std::fs::hard_link(&executable, same_filesystem.path().join("scp"))?;
        let host_path = std::env::join_paths([same_filesystem.path()])?;
        let Err(error) = resolve_host_tool("scp", &host_path) else {
            return Err("hard-linked adapter was not skipped".into());
        };
        assert_eq!(error.kind(), quarters_core::ErrorKind::NotFound);
        Ok(())
    }

    #[test]
    fn host_tool_resolution_skips_a_distinct_runtime_launcher_link() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let managed = temporary.path().join("managed");
        let fallback = temporary.path().join("fallback");
        std::fs::create_dir(&managed)?;
        std::fs::create_dir(&fallback)?;
        std::fs::copy(std::env::current_exe()?, managed.join("quarters"))?;
        symlink(managed.join("quarters"), managed.join("ssh"))?;
        std::fs::copy(std::env::current_exe()?, fallback.join("ssh"))?;
        let host_path = std::env::join_paths([managed.as_path(), fallback.as_path()])?;

        assert_eq!(
            resolve_host_tool("ssh", &host_path)?,
            std::fs::canonicalize(fallback.join("ssh"))?
        );
        Ok(())
    }
}
