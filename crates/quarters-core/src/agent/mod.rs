//! Explicit, verified private SSH-agent lifecycle.

mod model;
mod process;
mod protocol;
mod registry;
mod startup;

pub use model::{AgentState, AgentStatus};

use crate::store::{open_or_create_private_lock, sync_directory};
use crate::{ErrorKind, HostEnvironment, QuartersError, Result, Space, Store};
use fs4::FileExt;
use model::{AgentFailure, AgentRecord, StoredAgentState};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

pub(super) const STOP_TIMEOUT: Duration = Duration::from_secs(3);
const LOCK_TIMEOUT: Duration = Duration::from_secs(8);
const LOCK_OVERHEAD_BUDGET: Duration = Duration::from_secs(2);

const _: () = assert!(
    LOCK_TIMEOUT.as_millis()
        >= STOP_TIMEOUT.as_millis()
            + (2 * protocol::MAXIMUM_VERIFICATION_WAIT.as_millis())
            + LOCK_OVERHEAD_BUDGET.as_millis(),
    "the agent lock deadline must dominate verified shutdown work",
);

impl Store {
    pub(crate) fn ensure_no_agent_for_removal(&self, space: &Space, host: &HostEnvironment) -> Result<()> {
        let status = self.ssh_agent_status(space, host)?;
        if status.state == AgentState::Unset {
            return Ok(());
        }
        let name = &space.manifest().name;
        Err(QuartersError::new(
            ErrorKind::SpaceActive,
            format!("space '{name}' has private SSH-agent state ({})", status.state.as_str()),
        )
        .with_hint(format!(
            "run 'quarters agent stop {name}' or confirmed recovery before removal"
        )))
    }

    /// Inspect the private SSH-agent state for one stable-identity space.
    ///
    /// # Errors
    ///
    /// Returns an error when runtime anchors or registry metadata are unsafe.
    pub fn ssh_agent_status(&self, space: &Space, host: &HostEnvironment) -> Result<AgentStatus> {
        inspect(space, host)
    }

    /// Start or reuse one verified private OpenSSH agent.
    ///
    /// # Errors
    ///
    /// Returns an error on legacy identity, stale state, launch failure or timeout.
    pub fn start_ssh_agent(&self, space: &Space, host: &HostEnvironment) -> Result<AgentStatus> {
        startup::start(self, space, host)
    }

    /// Stop one identity-verified private OpenSSH agent.
    ///
    /// # Errors
    ///
    /// Returns an error when ownership cannot be proven or shutdown is incomplete.
    pub fn stop_ssh_agent(&self, space: &Space, host: &HostEnvironment) -> Result<AgentStatus> {
        self.ensure_no_rename_target(&space.manifest().name)?;
        self.ensure_no_rollback_target(&space.manifest().name)?;
        let _lease = self.maintenance_lease(space)?;
        let Some(runtime) = crate::platform::existing_runtime_directory(space, host)? else {
            return Ok(AgentStatus::unset(space));
        };
        let _lock = agent_lock(&runtime)?;
        let status = inspect_at(space, &runtime)?;
        if status.state == AgentState::Unset {
            return Ok(status);
        }
        if status.state != AgentState::Active {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                format!("private SSH-agent state is {}; stop refused", status.state.as_str()),
            )
            .with_hint("Quarters will not signal a process whose complete ownership record cannot be verified"));
        }
        stop_agent(space, &runtime)
    }

    /// Recover only private-agent state whose live ownership is unambiguous.
    ///
    /// # Errors
    ///
    /// Returns an error without signaling or unlinking when ownership cannot be proven.
    pub fn recover_ssh_agent(&self, space: &Space, host: &HostEnvironment) -> Result<AgentStatus> {
        self.ensure_no_rename_target(&space.manifest().name)?;
        self.ensure_no_rollback_target(&space.manifest().name)?;
        let _lease = self.maintenance_lease(space)?;
        let Some(runtime) = crate::platform::existing_runtime_directory(space, host)? else {
            return Ok(AgentStatus::unset(space));
        };
        let starting = {
            let _lock = agent_lock(&runtime)?;
            let current = inspect_at(space, &runtime)?;
            match current.state {
                AgentState::Unset | AgentState::Active => return Ok(current),
                AgentState::Starting => registry::read(&runtime, space)?.ok_or_else(missing_registry)?,
                AgentState::Stopping | AgentState::Failed | AgentState::Stale => {
                    return recover_inactive_state(space, &runtime);
                }
            }
        };
        startup::reconcile(space, &runtime, &starting)
    }
}

/// Return the socket only after full process, inode and protocol verification.
pub(crate) fn active_socket(space: &Space, host: &HostEnvironment) -> Result<Option<PathBuf>> {
    let status = inspect(space, host)?;
    match status.state {
        AgentState::Active => {
            status.socket.map(PathBuf::from).map(Some).ok_or_else(|| {
                QuartersError::new(ErrorKind::System, "active private SSH-agent status omitted its socket")
            })
        }
        AgentState::Unset | AgentState::Failed => Ok(None),
        AgentState::Starting | AgentState::Stopping | AgentState::Stale => Err(QuartersError::new(
            ErrorKind::CorruptState,
            format!(
                "private SSH-agent state is {}; process launch refused",
                status.state.as_str()
            ),
        )
        .with_hint(format!(
            "inspect 'quarters agent status {}', then recover only with 'quarters agent recover {} --confirm {}'",
            space.manifest().name,
            space.manifest().name,
            space.manifest().name
        ))),
    }
}

/// Run the hidden launcher which becomes the fixed OpenSSH agent executable.
///
/// # Errors
///
/// Returns an error when ownership handoff or exec fails.
pub fn run_ssh_agent_helper(host: &HostEnvironment, space: &Space, token: &str) -> Result<i32> {
    if space.id().is_none() {
        return Err(legacy_agent_error());
    }
    process::run_helper(host, space, token)
}

fn recover_inactive_state(space: &Space, runtime: &Path) -> Result<AgentStatus> {
    let Some(record) = registry::read(runtime, space)? else {
        return reject_unowned_socket(runtime).map(|()| AgentStatus::unset(space));
    };
    let alive = process::process_is_alive(record.pid)?;
    if alive && record.state == StoredAgentState::Stopping {
        let expected = recorded_socket_identity(&record)?;
        if protocol::recoverable_disconnected_socket(&registry::socket_path(runtime), expected)? {
            return recover_inactive_record(space, runtime, &record);
        }
        return finish_stopping(space, runtime, &record).map_err(|error| {
            error.with_hint(format!(
                "the stopping record was retained; inspect the exact socket, then retry 'quarters agent recover {} --confirm {}'",
                space.manifest().name,
                space.manifest().name
            ))
        });
    }
    if alive && record.state == StoredAgentState::Active {
        let expected = recorded_socket_identity(&record)?;
        if protocol::recoverable_disconnected_socket(&registry::socket_path(runtime), expected)? {
            return recover_inactive_record(space, runtime, &record);
        }
    }
    if alive {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the recorded private-agent process is still alive; recovery refused",
        )
        .with_hint("Quarters will not signal a process unless active socket ownership is fully verified"));
    }
    recover_inactive_record(space, runtime, &record)
}

fn recorded_socket_identity(record: &AgentRecord) -> Result<protocol::SocketIdentity> {
    record
        .socket_device
        .zip(record.socket_inode)
        .map(|(device, inode)| protocol::SocketIdentity { device, inode })
        .ok_or_else(|| QuartersError::new(ErrorKind::CorruptState, "agent record omitted socket identity"))
}

fn recover_inactive_record(space: &Space, runtime: &Path, record: &AgentRecord) -> Result<AgentStatus> {
    match record.socket_device.zip(record.socket_inode) {
        Some((device, inode)) => process::remove_matching_socket(&registry::socket_path(runtime), device, inode)?,
        None => reject_unowned_socket(runtime)?,
    }
    registry::remove(runtime, record)?;
    Ok(AgentStatus::unset(space))
}

fn stop_agent(space: &Space, runtime: &Path) -> Result<AgentStatus> {
    let active = registry::read(runtime, space)?.ok_or_else(missing_registry)?;
    let mut stopping = active.clone();
    stopping.state = StoredAgentState::Stopping;
    registry::replace(runtime, &active, &stopping)?;
    finish_stopping(space, runtime, &stopping)
}

fn finish_stopping(space: &Space, runtime: &Path, stopping: &AgentRecord) -> Result<AgentStatus> {
    let inode = stopping.socket_inode.ok_or_else(|| {
        QuartersError::new(
            ErrorKind::CorruptState,
            "stopping SSH-agent ownership omitted the socket inode",
        )
    })?;
    let device = stopping.socket_device.ok_or_else(|| {
        QuartersError::new(
            ErrorKind::CorruptState,
            "stopping SSH-agent ownership omitted the socket device",
        )
    })?;
    let target = process::SignalTarget::capture(stopping.pid)?;
    let verified = protocol::verified_socket_identity(&registry::socket_path(runtime), stopping.pid)?;
    if verified.device != device || verified.inode != inode {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the private SSH-agent socket changed immediately before shutdown",
        ));
    }
    target.terminate()?;
    let deadline = Instant::now() + STOP_TIMEOUT;
    while !target.has_exited()? && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    if !target.has_exited()? {
        return Err(QuartersError::new(
            ErrorKind::ResourceLimit,
            "the verified SSH-agent process did not stop within three seconds",
        ));
    }
    process::remove_matching_socket(&registry::socket_path(runtime), device, inode)?;
    registry::remove(runtime, stopping)?;
    sync_directory(runtime)?;
    Ok(AgentStatus::unset(space))
}

fn inspect(space: &Space, host: &HostEnvironment) -> Result<AgentStatus> {
    let Some(runtime) = crate::platform::existing_runtime_directory(space, host)? else {
        return Ok(AgentStatus::unset(space));
    };
    inspect_at(space, &runtime)
}

fn inspect_at(space: &Space, runtime: &Path) -> Result<AgentStatus> {
    let socket = registry::socket_path(runtime);
    let Some(record) = registry::read(runtime, space)? else {
        return match protocol::existing_socket_identity(&socket) {
            Ok(None) => Ok(AgentStatus::unset(space)),
            Ok(Some(_)) | Err(_) => Ok(status(
                space,
                AgentState::Stale,
                None,
                None,
                "an unowned socket occupies the private agent path",
            )),
        };
    };
    let alive = process::process_is_alive(record.pid)?;
    match record.state {
        StoredAgentState::Starting if alive => Ok(status(
            space,
            AgentState::Starting,
            Some(record.pid),
            None,
            "the verified launcher has not completed protocol activation",
        )),
        StoredAgentState::Active => Ok(inspect_active(space, &record, &socket, alive)),
        StoredAgentState::Stopping if alive => Ok(status(
            space,
            AgentState::Stopping,
            Some(record.pid),
            None,
            "the verified agent is shutting down",
        )),
        StoredAgentState::Failed => Ok(status(
            space,
            AgentState::Failed,
            Some(record.pid),
            None,
            failure_detail(record.failure),
        )),
        StoredAgentState::Starting | StoredAgentState::Stopping => Ok(status(
            space,
            AgentState::Stale,
            Some(record.pid),
            None,
            "the recorded private-agent process is no longer alive",
        )),
    }
}

fn failure_detail(failure: Option<AgentFailure>) -> &'static str {
    match failure {
        Some(AgentFailure::ExecutableUnavailable) => "the OpenSSH agent executable was unavailable",
        Some(AgentFailure::LaunchExited) => "the private-agent launcher exited before activation",
        Some(AgentFailure::StartupTimeout) => "the private-agent launcher timed out before activation",
        Some(AgentFailure::ProtocolRejected) => "the private-agent endpoint failed SSH protocol verification",
        None => "the last private-agent startup failed without a recorded cause",
    }
}

fn inspect_active(space: &Space, record: &AgentRecord, socket: &Path, alive: bool) -> AgentStatus {
    let expected = record
        .socket_device
        .zip(record.socket_inode)
        .map(|(device, inode)| protocol::SocketIdentity { device, inode });
    let verified =
        alive && expected.is_some() && protocol::verified_socket_identity(socket, record.pid).ok() == expected;
    if verified {
        return status(
            space,
            AgentState::Active,
            Some(record.pid),
            Some(socket),
            "process, socket identity, peer PID and SSH-agent protocol verified",
        );
    }
    status(
        space,
        AgentState::Stale,
        Some(record.pid),
        None,
        "the recorded process, socket identity, peer PID and protocol no longer agree",
    )
}

fn status(space: &Space, state: AgentState, pid: Option<u32>, socket: Option<&Path>, detail: &str) -> AgentStatus {
    AgentStatus {
        space: space.manifest().name.as_str().to_owned(),
        state,
        pid,
        socket: socket.map(|value| value.to_string_lossy().into_owned()),
        detail: detail.to_owned(),
    }
}

fn reject_unowned_socket(runtime: &Path) -> Result<()> {
    if protocol::existing_socket_identity(&registry::socket_path(runtime))?.is_none() {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "an unowned socket already occupies the private SSH-agent path",
    ))
}

fn agent_lock(runtime: &Path) -> Result<File> {
    let path = runtime.join(registry::LOCK_FILE);
    let file = open_or_create_private_lock(&path)?;
    let deadline = Instant::now() + LOCK_TIMEOUT;
    loop {
        match <File as FileExt>::try_lock(&file) {
            Ok(()) => return Ok(file),
            Err(fs4::TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(fs4::TryLockError::WouldBlock) => {
                return Err(QuartersError::new(
                    ErrorKind::ResourceLimit,
                    "the private-agent lifecycle lock did not become available within eight seconds",
                ));
            }
            Err(fs4::TryLockError::Error(error)) => {
                return Err(QuartersError::io("lock private-agent lifecycle", &path, error));
            }
        }
    }
}

fn legacy_agent_error() -> QuartersError {
    QuartersError::new(
        ErrorKind::Unsupported,
        "this legacy space has no stable identity for a private agent",
    )
    .with_hint("clone it into a new Quarter before starting a private agent")
}

fn missing_registry() -> QuartersError {
    QuartersError::new(
        ErrorKind::CorruptState,
        "the private SSH-agent ownership registry disappeared",
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::SpaceName;
    use crate::store::epoch_millis;
    use model::REGISTRY_SCHEMA_VERSION;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    #[test]
    fn status_does_not_create_runtime_state() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        let space = store
            .create(
                SpaceName::parse("read-only-status").expect("space name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create space");
        let host = HostEnvironment::capture();
        assert!(
            crate::platform::existing_runtime_directory(&space, &host)
                .expect("inspect runtime")
                .is_none()
        );

        let status = store.ssh_agent_status(&space, &host).expect("inspect agent");

        assert_eq!(status.state, AgentState::Unset);
        assert!(
            crate::platform::existing_runtime_directory(&space, &host)
                .expect("inspect runtime again")
                .is_none()
        );
    }

    #[test]
    fn legacy_start_fails_before_creating_runtime_state() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        let name = SpaceName::parse("legacy-agent").expect("space name");
        let created = store
            .create(name.clone(), PathBuf::from("/bin/sh"))
            .expect("create space");
        let mut manifest = created.manifest().clone();
        manifest.schema_version = crate::PROFILE_SCHEMA_VERSION;
        manifest.layout = None;
        manifest.space_id = None;
        let bytes = serde_json::to_vec_pretty(&manifest).expect("serialize legacy manifest");
        std::fs::write(created.root().join(".quarters.json"), bytes).expect("write legacy manifest");
        let space = store.open(&name).expect("open legacy space");
        let host = HostEnvironment::capture();

        let error = store
            .start_ssh_agent(&space, &host)
            .expect_err("legacy start must fail");

        assert_eq!(error.kind(), ErrorKind::Unsupported);
        assert!(
            crate::platform::existing_runtime_directory(&space, &host)
                .expect("inspect runtime")
                .is_none()
        );
    }

    #[test]
    fn recovery_removes_only_a_dead_socketless_failed_record() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        let space = store
            .create(
                SpaceName::parse("agent-recovery").expect("space name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create space");
        let host = HostEnvironment::capture();
        let runtime = crate::platform::runtime_directory(&space, &host).expect("runtime");
        let mut child = std::process::Command::new("/usr/bin/true")
            .spawn()
            .expect("spawn completed process");
        let pid = child.id();
        child.wait().expect("reap completed process");
        let record = AgentRecord {
            schema_version: REGISTRY_SCHEMA_VERSION,
            state: StoredAgentState::Failed,
            space_id: space.id().cloned().expect("stable ID"),
            token: "0123456789abcdef0123456789abcdef".to_owned(),
            pid,
            created_unix_ms: epoch_millis().expect("clock"),
            socket_inode: None,
            socket_device: None,
            failure: Some(AgentFailure::LaunchExited),
        };
        registry::create(&runtime, &record).expect("create failed record");

        let recovered = store.recover_ssh_agent(&space, &host).expect("recover dead record");
        assert_eq!(recovered.state, AgentState::Unset);
        assert!(registry::read(&runtime, &space).expect("inspect registry").is_none());
    }

    #[test]
    fn restart_retains_a_dead_failed_record_when_an_unowned_socket_path_exists() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        let space = store
            .create(
                SpaceName::parse("failed-restart").expect("space name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create space");
        let host = HostEnvironment::capture();
        let runtime = crate::platform::runtime_directory(&space, &host).expect("runtime");
        let mut child = std::process::Command::new("/usr/bin/true")
            .spawn()
            .expect("spawn completed process");
        let pid = child.id();
        child.wait().expect("reap completed process");
        let record = dead_failed_record(&space, pid);
        registry::create(&runtime, &record).expect("create failed record");
        symlink("/tmp", registry::socket_path(&runtime)).expect("plant unowned link");

        let error = store
            .start_ssh_agent(&space, &host)
            .expect_err("unsafe restart must fail");

        assert_eq!(error.kind(), ErrorKind::CorruptState);
        assert!(registry::read(&runtime, &space).expect("inspect registry").is_some());
        assert!(std::fs::symlink_metadata(registry::socket_path(&runtime)).is_ok());
    }

    #[test]
    fn recovery_completes_an_interrupted_verified_stop() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        let space = store
            .create(
                SpaceName::parse("stopping-recovery").expect("space name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create space");
        let host = HostEnvironment::capture();
        let runtime = crate::platform::runtime_directory(&space, &host).expect("runtime");
        let socket = registry::socket_path(&runtime);
        let mut child = std::process::Command::new("/usr/bin/ssh-agent")
            .args(["-D", "-a"])
            .arg(&socket)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn test agent");
        let pid = child.id();
        let identity = (0..100)
            .find_map(|_attempt| {
                let identity = protocol::verified_socket_identity(&socket, pid).ok();
                if identity.is_none() {
                    std::thread::sleep(Duration::from_millis(10));
                }
                identity
            })
            .expect("test agent protocol ready");
        let active = AgentRecord {
            schema_version: REGISTRY_SCHEMA_VERSION,
            state: StoredAgentState::Active,
            space_id: space.id().cloned().expect("stable ID"),
            token: "abcdef0123456789abcdef0123456789".to_owned(),
            pid,
            created_unix_ms: epoch_millis().expect("clock"),
            socket_inode: Some(identity.inode),
            socket_device: Some(identity.device),
            failure: None,
        };
        registry::create(&runtime, &active).expect("create active record");
        let mut stopping = active.clone();
        stopping.state = StoredAgentState::Stopping;
        registry::replace(&runtime, &active, &stopping).expect("record interrupted stop");
        let waiter = std::thread::spawn(move || child.wait());

        let recovered = store
            .recover_ssh_agent(&space, &host)
            .expect("complete interrupted stop");
        waiter.join().expect("join agent waiter").expect("reap test agent");
        assert_eq!(recovered.state, AgentState::Unset);
        assert!(registry::read(&runtime, &space).expect("inspect registry").is_none());
    }

    #[test]
    fn recovery_removes_a_dead_active_record_and_its_exact_disconnected_socket() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        let space = store
            .create(
                SpaceName::parse("dead-active-recovery").expect("space name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create space");
        let host = HostEnvironment::capture();
        let runtime = crate::platform::runtime_directory(&space, &host).expect("runtime");
        let socket = registry::socket_path(&runtime);
        let identity = disconnected_socket(&socket);
        let mut child = std::process::Command::new("/usr/bin/true")
            .spawn()
            .expect("spawn completed process");
        let pid = child.id();
        child.wait().expect("reap completed process");
        registry::create(&runtime, &active_record(&space, pid, identity)).expect("create active record");

        let recovered = store
            .recover_ssh_agent(&space, &host)
            .expect("recover dead active record");

        assert_eq!(recovered.state, AgentState::Unset);
        assert!(std::fs::symlink_metadata(&socket).is_err());
        assert!(registry::read(&runtime, &space).expect("inspect registry").is_none());
    }

    #[test]
    fn recovery_never_signals_a_reused_live_pid_with_an_exact_disconnected_socket() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        let space = store
            .create(
                SpaceName::parse("reused-pid-recovery").expect("space name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create space");
        let host = HostEnvironment::capture();
        let runtime = crate::platform::runtime_directory(&space, &host).expect("runtime");
        let socket = registry::socket_path(&runtime);
        let identity = disconnected_socket(&socket);
        let mut unrelated = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn unrelated process");
        registry::create(&runtime, &active_record(&space, unrelated.id(), identity))
            .expect("create recycled-pid record");

        let recovered = store
            .recover_ssh_agent(&space, &host)
            .expect("recover without signaling recycled PID");
        let still_alive = unrelated.try_wait().expect("inspect unrelated process").is_none();
        unrelated.kill().expect("stop unrelated test process");
        unrelated.wait().expect("reap unrelated test process");

        assert_eq!(recovered.state, AgentState::Unset);
        assert!(still_alive);
        assert!(std::fs::symlink_metadata(&socket).is_err());
        assert!(registry::read(&runtime, &space).expect("inspect registry").is_none());
    }

    #[test]
    fn stopping_recovery_never_signals_a_reused_live_pid_with_a_disconnected_socket() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        let space = store
            .create(
                SpaceName::parse("stopping-reused-pid").expect("space name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create space");
        let host = HostEnvironment::capture();
        let runtime = crate::platform::runtime_directory(&space, &host).expect("runtime");
        let socket = registry::socket_path(&runtime);
        let identity = disconnected_socket(&socket);
        let mut unrelated = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn unrelated process");
        let mut record = active_record(&space, unrelated.id(), identity);
        record.state = StoredAgentState::Stopping;
        registry::create(&runtime, &record).expect("create stopping record");

        let recovered = store
            .recover_ssh_agent(&space, &host)
            .expect("recover without signaling recycled PID");
        let still_alive = unrelated.try_wait().expect("inspect unrelated process").is_none();
        unrelated.kill().expect("stop unrelated test process");
        unrelated.wait().expect("reap unrelated test process");

        assert_eq!(recovered.state, AgentState::Unset);
        assert!(still_alive);
        assert!(registry::read(&runtime, &space).expect("inspect registry").is_none());
    }

    #[test]
    fn removal_refuses_a_live_private_agent_then_reclaims_its_runtime_after_stop() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        let space = store
            .create(
                SpaceName::parse("remove-agent-guard").expect("space name"),
                PathBuf::from("/bin/sh"),
            )
            .expect("create space");
        let host = HostEnvironment::capture();
        let runtime = crate::platform::runtime_directory(&space, &host).expect("runtime");
        let socket = registry::socket_path(&runtime);
        let mut child = std::process::Command::new("/usr/bin/ssh-agent")
            .args(["-D", "-a"])
            .arg(&socket)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn test agent");
        let identity = (0..100)
            .find_map(|_attempt| {
                let identity = protocol::verified_socket_identity(&socket, child.id()).ok();
                if identity.is_none() {
                    std::thread::sleep(Duration::from_millis(10));
                }
                identity
            })
            .expect("test agent protocol ready");
        registry::create(&runtime, &active_record(&space, child.id(), identity)).expect("create active record");

        let preserved_home = space.root().join("preserved-home");
        std::fs::rename(space.home(), &preserved_home).expect("move home");
        std::os::unix::fs::symlink(&preserved_home, space.home()).expect("replace home with symlink");

        let error = store
            .remove(space.manifest().name.as_str())
            .expect_err("active agent must block removal even when home is corrupt");
        assert_eq!(error.kind(), ErrorKind::SpaceActive);
        assert!(space.root().is_dir());

        std::fs::remove_file(space.home()).expect("remove home symlink");
        std::fs::rename(&preserved_home, space.home()).expect("restore home");

        let waiter = std::thread::spawn(move || child.wait());
        store.stop_ssh_agent(&space, &host).expect("stop private agent");
        waiter.join().expect("join agent waiter").expect("reap private agent");
        store
            .remove(space.manifest().name.as_str())
            .expect("remove inactive space");

        assert!(!space.root().exists());
        assert!(!runtime.exists());
    }

    fn disconnected_socket(path: &Path) -> protocol::SocketIdentity {
        let listener = UnixListener::bind(path).expect("bind disconnected socket");
        let metadata = listener
            .local_addr()
            .and_then(|_| std::fs::symlink_metadata(path))
            .expect("socket metadata");
        let identity = protocol::SocketIdentity {
            device: std::os::unix::fs::MetadataExt::dev(&metadata),
            inode: std::os::unix::fs::MetadataExt::ino(&metadata),
        };
        drop(listener);
        identity
    }

    fn active_record(space: &Space, pid: u32, identity: protocol::SocketIdentity) -> AgentRecord {
        AgentRecord {
            schema_version: REGISTRY_SCHEMA_VERSION,
            state: StoredAgentState::Active,
            space_id: space.id().cloned().expect("stable ID"),
            token: "abcdef0123456789abcdef0123456789".to_owned(),
            pid,
            created_unix_ms: epoch_millis().expect("clock"),
            socket_inode: Some(identity.inode),
            socket_device: Some(identity.device),
            failure: None,
        }
    }

    fn dead_failed_record(space: &Space, pid: u32) -> AgentRecord {
        AgentRecord {
            schema_version: REGISTRY_SCHEMA_VERSION,
            state: StoredAgentState::Failed,
            space_id: space.id().cloned().expect("stable ID"),
            token: "0123456789abcdef0123456789abcdef".to_owned(),
            pid,
            created_unix_ms: epoch_millis().expect("clock"),
            socket_inode: None,
            socket_device: None,
            failure: Some(AgentFailure::LaunchExited),
        }
    }
}
