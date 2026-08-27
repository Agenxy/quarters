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

pub(super) fn terminate_unreaped_child(pid: u32) -> Result<()> {
    let pid = validated_pid(pid)?;
    match kill(pid, Signal::SIGTERM) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => {
            Err(QuartersError::new(ErrorKind::System, "could not stop the private-agent launcher").with_source(error))
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) struct SignalTarget {
    pidfd: rustix::fd::OwnedFd,
}

#[cfg(target_os = "macos")]
pub(super) struct SignalTarget {
    pid: Pid,
    started_seconds: u64,
    started_microseconds: u64,
}

#[cfg(target_os = "linux")]
impl SignalTarget {
    pub(super) fn capture(pid: u32) -> Result<Self> {
        let pid = validated_pid(pid)?;
        let rustix_pid = rustix::process::Pid::from_raw(pid.as_raw())
            .ok_or_else(|| QuartersError::new(ErrorKind::CorruptState, "the private-agent PID is invalid"))?;
        let pidfd = rustix::process::pidfd_open(rustix_pid, rustix::process::PidfdFlags::empty()).map_err(|error| {
            QuartersError::new(ErrorKind::System, "could not capture the private-agent process handle")
                .with_source(error)
        })?;
        Ok(Self { pidfd })
    }

    pub(super) fn terminate(&self) -> Result<()> {
        match rustix::process::pidfd_send_signal(&self.pidfd, rustix::process::Signal::TERM) {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::SRCH) => Ok(()),
            Err(error) => Err(
                QuartersError::new(ErrorKind::System, "could not stop the verified private agent").with_source(error),
            ),
        }
    }

    pub(super) fn has_exited(&self) -> Result<bool> {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        use std::os::fd::AsFd;

        let mut descriptors = [PollFd::new(self.pidfd.as_fd(), PollFlags::POLLIN)];
        let ready = poll(&mut descriptors, PollTimeout::ZERO).map_err(|error| {
            QuartersError::new(ErrorKind::System, "could not poll the verified private agent").with_source(error)
        })?;
        if ready == 0 {
            return Ok(false);
        }
        let events = descriptors[0].revents().ok_or_else(|| {
            QuartersError::new(
                ErrorKind::System,
                "the private-agent process handle returned unknown poll events",
            )
        })?;
        if events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
            return Ok(true);
        }
        Err(QuartersError::new(
            ErrorKind::System,
            "the private-agent process handle returned an unexpected poll event",
        ))
    }
}

#[cfg(target_os = "macos")]
impl SignalTarget {
    pub(super) fn capture(pid: u32) -> Result<Self> {
        let pid = validated_pid(pid)?;
        let info = macos_process_info(pid)?;
        Ok(Self {
            pid,
            started_seconds: info.pbi_start_tvsec,
            started_microseconds: info.pbi_start_tvusec,
        })
    }

    pub(super) fn terminate(&self) -> Result<()> {
        let current = macos_process_info(self.pid)?;
        if current.pbi_start_tvsec != self.started_seconds || current.pbi_start_tvusec != self.started_microseconds {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "the private-agent process generation changed before shutdown",
            ));
        }
        match kill(self.pid, Signal::SIGTERM) {
            Ok(()) | Err(Errno::ESRCH) => Ok(()),
            Err(error) => Err(
                QuartersError::new(ErrorKind::System, "could not stop the verified private agent").with_source(error),
            ),
        }
    }

    pub(super) fn has_exited(&self) -> Result<bool> {
        let Some(current) = macos_process_info_optional(self.pid)? else {
            return Ok(true);
        };
        if current.pbi_start_tvsec == self.started_seconds && current.pbi_start_tvusec == self.started_microseconds {
            return Ok(false);
        }
        Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the private-agent process generation changed during shutdown",
        ))
    }
}

#[cfg(target_os = "macos")]
fn macos_process_info(pid: Pid) -> Result<proc_pidinfo::ProcBSDInfo> {
    macos_process_info_optional(pid)?
        .ok_or_else(|| QuartersError::new(ErrorKind::NotFound, "the private-agent process no longer exists"))
}

#[cfg(target_os = "macos")]
fn macos_process_info_optional(pid: Pid) -> Result<Option<proc_pidinfo::ProcBSDInfo>> {
    let raw = u32::try_from(pid.as_raw()).map_err(|error| {
        QuartersError::new(ErrorKind::CorruptState, "the private-agent PID is invalid").with_source(error)
    })?;
    proc_pidinfo::proc_pidinfo::<proc_pidinfo::ProcBSDInfo>(proc_pidinfo::Pid(raw)).map_err(|error| {
        QuartersError::new(
            ErrorKind::System,
            "could not inspect the private-agent process generation",
        )
        .with_source(error)
    })
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

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::expect_used)]
mod linux_tests {
    use super::*;

    const ORPHAN_PID_PATH: &str = "QUARTERS_TEST_ORPHAN_PID_PATH";

    #[test]
    fn orphan_process_helper() {
        let Some(path) = std::env::var_os(ORPHAN_PID_PATH) else {
            return;
        };
        let child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn orphan target");
        fs::write(path, format!("{}\n", child.id())).expect("publish orphan PID");
    }

    #[test]
    fn pidfd_poll_observes_a_non_child_process_exit() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let pid_path = temporary.path().join("pid");
        let executable = std::env::current_exe().expect("test executable");
        let status = Command::new(executable)
            .args(["--exact", "agent::process::linux_tests::orphan_process_helper"])
            .env(ORPHAN_PID_PATH, &pid_path)
            .status()
            .expect("run orphan helper");
        assert!(status.success());
        let pid = fs::read_to_string(&pid_path)
            .expect("read orphan PID")
            .trim()
            .parse::<u32>()
            .expect("parse orphan PID");
        assert_ne!(
            linux_parent_pid(pid).expect("read orphan parent PID"),
            std::process::id()
        );
        let target = SignalTarget::capture(pid).expect("capture non-child pidfd");

        target.terminate().expect("signal non-child through pidfd");
        let deadline = Instant::now() + Duration::from_secs(3);
        while !target.has_exited().expect("poll non-child pidfd") && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(target.has_exited().expect("observe non-child exit"));
    }

    fn linux_parent_pid(pid: u32) -> std::io::Result<u32> {
        let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
        status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:\t"))
            .ok_or_else(|| std::io::Error::other("process status omitted PPid"))?
            .trim()
            .parse::<u32>()
            .map_err(std::io::Error::other)
    }
}
