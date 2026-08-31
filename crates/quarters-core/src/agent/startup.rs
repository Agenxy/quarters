//! Concurrent private-agent startup without holding the lifecycle lock while waiting.

use super::model::{AgentFailure, AgentRecord, REGISTRY_SCHEMA_VERSION, StoredAgentState};
use super::{
    STOP_TIMEOUT, agent_lock, inspect_at, legacy_agent_error, missing_registry, process, protocol,
    recover_inactive_record, registry, reject_unowned_socket,
};
use crate::store::epoch_millis;
use crate::{AgentState, AgentStatus, ErrorKind, HostEnvironment, QuartersError, Result, Space, Store};
use fs4::FileExt;
use std::fs::File;
use std::path::Path;
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_TOTAL_STARTUP_WAIT: Duration = Duration::from_secs(10);
const MAXIMUM_LAUNCH_ATTEMPTS: usize = 2;
pub(super) fn start(store: &Store, space: &Space, host: &HostEnvironment) -> Result<AgentStatus> {
    store.ensure_no_rename_target(&space.manifest().name)?;
    store.ensure_no_rollback_target(&space.manifest().name)?;
    if space.id().is_none() {
        return Err(legacy_agent_error());
    }
    let _lease = store.lease(space)?;
    let runtime = crate::platform::runtime_directory(space, host)?;
    let reservation = {
        let _lock = agent_lock(&runtime)?;
        reserve(store, space, &runtime)?
    };
    match reservation {
        Reservation::Active(status) => Ok(status),
        Reservation::Observe(starting) => reconcile(space, &runtime, &starting),
        Reservation::Spawned { child, starting, owner } => {
            await_spawned(store, space, &runtime, child, starting, owner)
        }
        Reservation::Cleanup {
            mut child,
            error,
            owner: _owner,
        } => {
            if let Err(cleanup) = cleanup_spawned_child(&runtime, &mut child) {
                return Err(error.with_hint(format!("private-agent launcher cleanup also failed: {cleanup}")));
            }
            Err(error)
        }
    }
}

pub(super) fn reconcile(space: &Space, runtime: &Path, starting: &AgentRecord) -> Result<AgentStatus> {
    validate_starting(starting)?;
    let mut current_starting = starting.clone();
    let absolute_deadline = Instant::now() + MAXIMUM_TOTAL_STARTUP_WAIT;
    let mut deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        let observed = protocol::verified_socket_identity(&registry::socket_path(runtime), current_starting.pid).ok();
        let alive = process::process_is_alive(current_starting.pid)?;
        match reconcile_orphan(space, runtime, &current_starting, observed, alive)? {
            ReconcileStep::Ready(status) => return Ok(status),
            ReconcileStep::Follow(replacement) => {
                current_starting = replacement;
                deadline = (Instant::now() + STARTUP_TIMEOUT).min(absolute_deadline);
            }
            ReconcileStep::Pending => {}
        }
        if Instant::now() >= deadline {
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                "the recorded private-agent launcher is alive but did not become ready",
            )
            .with_hint("run 'quarters agent status NAME'; Quarters will not signal an incompletely verified process"));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn reconcile_orphan(
    space: &Space,
    runtime: &Path,
    starting: &AgentRecord,
    observed: Option<protocol::SocketIdentity>,
    alive: bool,
) -> Result<ReconcileStep> {
    let _lock = agent_lock(runtime)?;
    let record = registry::read(runtime, space)?.ok_or_else(missing_registry)?;
    if record.state == StoredAgentState::Active {
        let current = inspect_at(space, runtime)?;
        return if current.state == AgentState::Active && current.pid == Some(record.pid) {
            Ok(ReconcileStep::Ready(current))
        } else {
            Ok(ReconcileStep::Pending)
        };
    }
    if record.state == StoredAgentState::Starting && record != *starting {
        return Ok(ReconcileStep::Follow(record));
    }
    if record != *starting {
        return Err(changed_startup_error());
    }
    let Some(_orphan_guard) = orphan_startup_guard(runtime)? else {
        return Ok(ReconcileStep::Pending);
    };
    if let Some(observed) = observed {
        let verified = protocol::verified_socket_identity(&registry::socket_path(runtime), starting.pid)?;
        if verified != observed {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "the private SSH-agent socket changed before orphan activation",
            ));
        }
        let mut active = starting.clone();
        active.state = StoredAgentState::Active;
        active.socket_inode = Some(verified.inode);
        active.socket_device = Some(verified.device);
        registry::replace(runtime, starting, &active)?;
        return inspect_at(space, runtime).map(ReconcileStep::Ready);
    }
    if alive {
        return Ok(ReconcileStep::Pending);
    }
    recover_inactive_record(space, runtime, starting).map(ReconcileStep::Ready)
}

fn reserve(store: &Store, space: &Space, runtime: &Path) -> Result<Reservation> {
    let current = inspect_at(space, runtime)?;
    match current.state {
        AgentState::Active => return Ok(Reservation::Active(current)),
        AgentState::Starting => {
            let starting = registry::read(runtime, space)?.ok_or_else(missing_registry)?;
            return Ok(Reservation::Observe(starting));
        }
        AgentState::Failed
            if current
                .pid
                .is_some_and(|pid| !process::process_is_alive(pid).unwrap_or(true)) =>
        {
            let record = registry::read(runtime, space)?.ok_or_else(missing_registry)?;
            recover_inactive_record(space, runtime, &record)?;
        }
        AgentState::Unset => {}
        AgentState::Stale => {
            if let Some(record) = registry::read(runtime, space)?
                && record.state == StoredAgentState::Starting
                && orphan_startup_guard(runtime)?.is_none()
            {
                return Ok(Reservation::Observe(record));
            }
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                format!("private SSH-agent state is {}; start refused", current.state.as_str()),
            )
            .with_hint("run 'quarters agent status NAME' and resolve the reported state before retrying"));
        }
        AgentState::Stopping | AgentState::Failed => {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                format!("private SSH-agent state is {}; start refused", current.state.as_str()),
            )
            .with_hint("run 'quarters agent status NAME' and resolve the reported state before retrying"));
        }
    }
    reject_unowned_socket(runtime)?;
    process::validate_launch(runtime)?;
    reserve_new(store, space, runtime)
}

fn reserve_new(store: &Store, space: &Space, runtime: &Path) -> Result<Reservation> {
    let id = space.id().cloned().ok_or_else(legacy_agent_error)?;
    let token = generate_token()?;
    let created_unix_ms = epoch_millis()?;
    let owner = startup_owner_guard(runtime)?;
    let child = process::spawn_helper(store, space, &token)?;
    let starting = AgentRecord {
        schema_version: REGISTRY_SCHEMA_VERSION,
        state: StoredAgentState::Starting,
        space_id: id,
        token,
        pid: child.id(),
        created_unix_ms,
        socket_inode: None,
        socket_device: None,
        failure: None,
    };
    if let Err(error) = registry::create(runtime, &starting) {
        return Ok(Reservation::Cleanup { child, error, owner });
    }
    Ok(Reservation::Spawned { child, starting, owner })
}

fn await_spawned(
    store: &Store,
    space: &Space,
    runtime: &Path,
    mut child: Child,
    mut starting: AgentRecord,
    _owner: File,
) -> Result<AgentStatus> {
    let mut attempts = 1_usize;
    let mut deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Ok(identity) = protocol::verified_socket_identity(&registry::socket_path(runtime), starting.pid) {
            return match commit_activation(space, runtime, &starting, identity) {
                Ok(status) => Ok(status),
                Err(error) => abort_spawned(space, runtime, &mut child, &starting, error),
            };
        }
        if child
            .try_wait()
            .map_err(|error| {
                QuartersError::new(ErrorKind::System, "could not inspect agent startup").with_source(error)
            })?
            .is_some()
        {
            if attempts < MAXIMUM_LAUNCH_ATTEMPTS {
                cleanup_exited_socket(runtime)?;
                match retry_exited_launch(store, space, runtime, &starting) {
                    Ok(RetryLaunch::Active(status)) => return Ok(status),
                    Ok(RetryLaunch::Spawned(replacement_child, replacement_starting)) => {
                        child = replacement_child;
                        starting = replacement_starting;
                        attempts += 1;
                        deadline = Instant::now() + STARTUP_TIMEOUT;
                        continue;
                    }
                    Err(error) => {
                        return match commit_failure(space, runtime, &starting, AgentFailure::LaunchExited) {
                            Ok(Some(active)) => Ok(active),
                            Ok(None) => Err(error),
                            Err(failure) => Err(error.with_hint(format!(
                                "replacement launch failed and its ownership record could not be finalized: {failure}"
                            ))),
                        };
                    }
                }
            }
            match commit_failure(space, runtime, &starting, AgentFailure::LaunchExited) {
                Ok(Some(active)) => return Ok(active),
                Ok(None) => {}
                Err(error) => return abort_spawned(space, runtime, &mut child, &starting, error),
            }
            return Err(QuartersError::new(
                ErrorKind::System,
                "the OpenSSH agent exited before its protocol became ready",
            ));
        }
        if Instant::now() >= deadline {
            match commit_failure(space, runtime, &starting, AgentFailure::StartupTimeout) {
                Ok(Some(active)) => return Ok(active),
                Ok(None) => {}
                Err(error) => return abort_spawned(space, runtime, &mut child, &starting, error),
            }
            let cleanup = cleanup_spawned_child(runtime, &mut child);
            if let Err(error) = cleanup {
                return Err(error.with_hint("the failed ownership record was retained for confirmed recovery"));
            }
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                "the private SSH agent did not become ready within five seconds",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn retry_exited_launch(store: &Store, space: &Space, runtime: &Path, starting: &AgentRecord) -> Result<RetryLaunch> {
    let token = generate_token()?;
    let created_unix_ms = epoch_millis()?;
    let _lock = agent_lock(runtime)?;
    let current = inspect_at(space, runtime)?;
    if current.state == AgentState::Active && current.pid == Some(starting.pid) {
        return Ok(RetryLaunch::Active(current));
    }
    let record = registry::read(runtime, space)?.ok_or_else(missing_registry)?;
    if record != *starting {
        return Err(changed_startup_error());
    }
    let mut child = process::spawn_helper(store, space, &token)?;
    let replacement = AgentRecord {
        schema_version: REGISTRY_SCHEMA_VERSION,
        state: StoredAgentState::Starting,
        space_id: starting.space_id.clone(),
        token,
        pid: child.id(),
        created_unix_ms,
        socket_inode: None,
        socket_device: None,
        failure: None,
    };
    if let Err(error) = registry::replace(runtime, starting, &replacement) {
        if registry::read(runtime, space)?.as_ref() == Some(&replacement) {
            return Ok(RetryLaunch::Spawned(child, replacement));
        }
        if let Err(cleanup) = cleanup_spawned_child(runtime, &mut child) {
            return Err(error.with_hint(format!("replacement launcher cleanup also failed: {cleanup}")));
        }
        return Err(error);
    }
    Ok(RetryLaunch::Spawned(child, replacement))
}

fn abort_spawned(
    space: &Space,
    runtime: &Path,
    child: &mut Child,
    starting: &AgentRecord,
    original: QuartersError,
) -> Result<AgentStatus> {
    if let Ok(current) = inspect_at(space, runtime)
        && current.state == AgentState::Active
        && current.pid == Some(starting.pid)
    {
        return Ok(current);
    }
    if let Ok(_lock) = agent_lock(runtime) {
        if let Ok(current) = inspect_at(space, runtime)
            && current.state == AgentState::Active
            && current.pid == Some(starting.pid)
        {
            return Ok(current);
        }
        if let Ok(Some(current)) = registry::read(runtime, space) {
            if same_activation(&current, starting) {
                return Err(original.with_hint(
                    "the activation record was committed; the owned launcher was retained for confirmed recovery",
                ));
            }
            if current == *starting {
                let mut failed = starting.clone();
                failed.state = StoredAgentState::Failed;
                failed.failure = Some(AgentFailure::ProtocolRejected);
                let _replace = registry::replace(runtime, starting, &failed);
            }
        }
    }
    if let Err(cleanup) = cleanup_spawned_child(runtime, child) {
        return Err(original.with_hint(format!("private-agent launcher cleanup also failed: {cleanup}")));
    }
    Err(original)
}

fn same_activation(current: &AgentRecord, starting: &AgentRecord) -> bool {
    current.state == StoredAgentState::Active
        && current.schema_version == starting.schema_version
        && current.space_id == starting.space_id
        && current.token == starting.token
        && current.pid == starting.pid
        && current.created_unix_ms == starting.created_unix_ms
}

fn commit_activation(
    space: &Space,
    runtime: &Path,
    starting: &AgentRecord,
    observed: protocol::SocketIdentity,
) -> Result<AgentStatus> {
    let _lock = agent_lock(runtime)?;
    let current = inspect_at(space, runtime)?;
    if current.state == AgentState::Active && current.pid == Some(starting.pid) {
        return Ok(current);
    }
    let record = registry::read(runtime, space)?.ok_or_else(missing_registry)?;
    if record != *starting {
        return Err(changed_startup_error());
    }
    let verified = protocol::verified_socket_identity(&registry::socket_path(runtime), starting.pid)?;
    if verified != observed {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the private SSH-agent socket changed before startup activation",
        ));
    }
    let mut active = starting.clone();
    active.state = StoredAgentState::Active;
    active.socket_inode = Some(verified.inode);
    active.socket_device = Some(verified.device);
    registry::replace(runtime, starting, &active)?;
    inspect_at(space, runtime)
}

fn commit_failure(
    space: &Space,
    runtime: &Path,
    starting: &AgentRecord,
    failure: AgentFailure,
) -> Result<Option<AgentStatus>> {
    let _lock = agent_lock(runtime)?;
    let current = inspect_at(space, runtime)?;
    if current.state == AgentState::Active && current.pid == Some(starting.pid) {
        return Ok(Some(current));
    }
    let record = registry::read(runtime, space)?.ok_or_else(missing_registry)?;
    if record != *starting {
        return Err(changed_startup_error());
    }
    let mut failed = starting.clone();
    failed.state = StoredAgentState::Failed;
    failed.failure = Some(failure);
    registry::replace(runtime, starting, &failed)?;
    Ok(None)
}

fn validate_starting(starting: &AgentRecord) -> Result<()> {
    if starting.state == StoredAgentState::Starting {
        return Ok(());
    }
    Err(changed_startup_error())
}

fn changed_startup_error() -> QuartersError {
    QuartersError::new(
        ErrorKind::CorruptState,
        "private-agent state changed before startup reconciliation",
    )
}

fn stop_spawned_child(child: &mut Child) -> Result<()> {
    process::terminate_unreaped_child(child.id())?;
    let deadline = Instant::now() + STOP_TIMEOUT;
    loop {
        if child
            .try_wait()
            .map_err(|error| QuartersError::new(ErrorKind::System, "could not reap agent launcher").with_source(error))?
            .is_some()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            child.kill().map_err(|error| {
                QuartersError::new(ErrorKind::System, "could not kill an unresponsive agent launcher")
                    .with_source(error)
            })?;
            child.wait().map_err(|error| {
                QuartersError::new(ErrorKind::System, "could not reap the killed agent launcher").with_source(error)
            })?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn cleanup_spawned_child(runtime: &Path, child: &mut Child) -> Result<()> {
    let socket = registry::socket_path(runtime);
    let observed = protocol::existing_socket_identity(&socket).ok().flatten();
    stop_spawned_child(child)?;
    if let Some(identity) = observed {
        process::remove_matching_socket(&socket, identity.device, identity.inode)?;
    }
    Ok(())
}

fn cleanup_exited_socket(runtime: &Path) -> Result<()> {
    let socket = registry::socket_path(runtime);
    let Some(identity) = protocol::existing_socket_identity(&socket)? else {
        return Ok(());
    };
    process::remove_matching_socket(&socket, identity.device, identity.inode)
}

fn generate_token() -> Result<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not obtain randomness for agent ownership").with_source(error)
    })?;
    let mut token = String::with_capacity(32);
    for byte in random {
        token.push(char::from(HEX[usize::from(byte >> 4)]));
        token.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(token)
}

fn startup_owner_guard(runtime: &Path) -> Result<File> {
    let path = runtime.join(registry::STARTUP_OWNER_LOCK_FILE);
    let file = crate::store::open_or_create_private_lock(&path)?;
    match <File as FileExt>::try_lock(&file) {
        Ok(()) => Ok(file),
        Err(fs4::TryLockError::WouldBlock) => Err(QuartersError::new(
            ErrorKind::ResourceLimit,
            "a previous private-agent startup is still finishing cleanup",
        )
        .with_hint("retry after the previous startup releases its bounded owner lease")),
        Err(fs4::TryLockError::Error(error)) => {
            Err(QuartersError::io("lock private-agent startup owner", &path, error))
        }
    }
}

fn orphan_startup_guard(runtime: &Path) -> Result<Option<File>> {
    let path = runtime.join(registry::STARTUP_OWNER_LOCK_FILE);
    let file = crate::store::open_or_create_private_lock(&path)?;
    match <File as FileExt>::try_lock_shared(&file) {
        Ok(()) => Ok(Some(file)),
        Err(fs4::TryLockError::WouldBlock) => Ok(None),
        Err(fs4::TryLockError::Error(error)) => {
            Err(QuartersError::io("inspect private-agent startup owner", &path, error))
        }
    }
}

enum Reservation {
    Active(AgentStatus),
    Observe(AgentRecord),
    Spawned {
        child: Child,
        starting: AgentRecord,
        owner: File,
    },
    Cleanup {
        child: Child,
        error: QuartersError,
        owner: File,
    },
}

enum ReconcileStep {
    Ready(AgentStatus),
    Follow(AgentRecord),
    Pending,
}

enum RetryLaunch {
    Active(AgentStatus),
    Spawned(Child, AgentRecord),
}
