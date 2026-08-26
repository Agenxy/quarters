//! Process launch and identity checks for the managed OpenSSH agent.

use super::model::StoredAgentState;
use super::registry;
use crate::{ErrorKind, HostEnvironment, QuartersError, Result, Space, Store};
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SSH_AGENT: &str = "/usr/bin/ssh-agent";
const HELPER_WAIT: Duration = Duration::from_secs(5);
const SOCKET_PATH_LIMIT: usize = 100;

pub(super) fn validate_launch(runtime: &Path) -> Result<()> {
    validate_socket_path(&registry::socket_path(runtime))?;
    validate_agent_executable(Path::new(SSH_AGENT))
}

pub(super) fn spawn_helper(store: &Store, space: &Space, token: &str) -> Result<Child> {
    let executable = std::env::current_exe().map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not resolve the Quarters executable").with_source(error)
    })?;
    let mut command = Command::new(executable);
    command
        .arg("--root")
        .arg(store.root())
        .arg("__agent-launch")
        .arg("--space")
        .arg(space.manifest().name.as_str())
        .env("QUARTERS_AGENT_TOKEN", token)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    command.spawn().map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not start the private-agent launcher").with_source(error)
    })
}

pub(super) fn run_helper(host: &HostEnvironment, space: &Space, token: &str) -> Result<i32> {
    let runtime = crate::platform::runtime_directory(space, host)?;
    let socket = registry::socket_path(&runtime);
    validate_socket_path(&socket)?;
    let pid = std::process::id();
    wait_for_ownership(&runtime, space, token, pid)?;
    validate_agent_executable(Path::new(SSH_AGENT))?;
    let mut command = Command::new(SSH_AGENT);
    command
        .arg("-D")
        .arg("-a")
        .arg(&socket)
        .env_clear()
        .env("TMPDIR", runtime.join("tmp"));
    let error = command.exec();
    Err(QuartersError::new(
        ErrorKind::System,
        "could not replace the launcher with the OpenSSH agent",
    )
    .with_source(error))
}

pub(super) fn process_is_alive(pid: u32) -> Result<bool> {
    let pid = validated_pid(pid)?;
    match kill(pid, None) {
        Ok(()) | Err(Errno::EPERM) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(error) => {
            Err(QuartersError::new(ErrorKind::System, "could not inspect the private-agent process").with_source(error))
        }
    }
}

pub(super) fn terminate(pid: u32) -> Result<()> {
    let pid = validated_pid(pid)?;
    match kill(pid, Signal::SIGTERM) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => {
            Err(QuartersError::new(ErrorKind::System, "could not stop the verified private agent").with_source(error))
        }
    }
}

pub(super) fn remove_matching_socket(path: &Path, device: u64, inode: u64) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(QuartersError::io("inspect stopped SSH-agent socket", path, error)),
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != nix::unistd::Uid::current().as_raw()
        || metadata.dev() != device
        || metadata.ino() != inode
    {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the SSH-agent socket changed before cleanup; it was not removed",
        ));
    }
    fs::remove_file(path).map_err(|error| QuartersError::io("remove stopped SSH-agent socket", path, error))
}

fn wait_for_ownership(runtime: &Path, space: &Space, token: &str, pid: u32) -> Result<()> {
    let deadline = Instant::now() + HELPER_WAIT;
    loop {
        if let Some(record) = registry::read(runtime, space)?
            && record.token == token
            && record.pid == pid
            && record.state == StoredAgentState::Starting
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                "the private-agent launcher did not receive its ownership record in time",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn validate_agent_executable(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|error| {
        QuartersError::new(ErrorKind::Unsupported, "the platform OpenSSH agent is unavailable")
            .with_hint("install OpenSSH at /usr/bin/ssh-agent, then retry")
            .with_source(error)
    })?;
    if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "the platform OpenSSH agent is not an executable file",
    ))
}

fn validate_socket_path(path: &Path) -> Result<()> {
    if path.as_os_str().as_encoded_bytes().len() <= SOCKET_PATH_LIMIT {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "the private SSH-agent socket path exceeds the portable Unix limit",
    )
    .with_hint("choose a shorter XDG_RUNTIME_DIR or Quarters root"))
}

fn validated_pid(pid: u32) -> Result<Pid> {
    let raw = i32::try_from(pid).map_err(|error| {
        QuartersError::new(
            ErrorKind::CorruptState,
            "the private-agent PID does not fit this platform",
        )
        .with_source(error)
    })?;
    if raw <= 1 {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the private-agent PID is reserved",
        ));
    }
    Ok(Pid::from_raw(raw))
}
