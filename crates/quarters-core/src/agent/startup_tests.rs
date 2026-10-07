// SPDX-License-Identifier: GPL-3.0-or-later
//! Private-agent startup convergence regression tests.

#![allow(clippy::expect_used)]

use super::model::{AgentFailure, AgentRecord, REGISTRY_SCHEMA_VERSION, StoredAgentState};
use super::{process, registry, startup};
use crate::store::epoch_millis;
use crate::{ErrorKind, HostEnvironment, Space, SpaceName, Store};
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

#[test]
fn an_observer_recovers_a_dead_failed_replacement() {
    let fixture = Fixture::new("observer-recovery");
    let starting = fixture.dead_record(StoredAgentState::Starting, None);
    let failed = fixture.dead_record(StoredAgentState::Failed, Some(AgentFailure::LaunchExited));
    registry::create(&fixture.runtime, &failed).expect("publish failed replacement");

    let result = startup::reconcile(
        &fixture.space,
        &fixture.runtime,
        &starting,
        Instant::now() + startup::MAXIMUM_TOTAL_STARTUP_WAIT,
    )
    .expect("recover failed replacement");

    assert!(matches!(result, startup::Reconciled::Recovered));
    assert!(
        registry::read(&fixture.runtime, &fixture.space)
            .expect("inspect registry")
            .is_none()
    );
}

#[test]
fn an_observer_refuses_to_recover_a_live_failed_replacement() {
    let fixture = Fixture::new("observer-live-guard");
    let starting = fixture.dead_record(StoredAgentState::Starting, None);
    let mut unrelated = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("spawn unrelated process");
    let generation = process::process_generation(unrelated.id()).expect("capture process generation");
    let failed = fixture.record(
        StoredAgentState::Failed,
        unrelated.id(),
        Some(generation),
        Some(AgentFailure::LaunchExited),
    );
    registry::create(&fixture.runtime, &failed).expect("publish live failed replacement");

    let error = startup::reconcile(
        &fixture.space,
        &fixture.runtime,
        &starting,
        Instant::now() + startup::MAXIMUM_TOTAL_STARTUP_WAIT,
    )
    .expect_err("live failed replacement must remain owned");
    let still_alive = unrelated.try_wait().expect("inspect unrelated process").is_none();
    unrelated.kill().expect("stop unrelated process");
    unrelated.wait().expect("reap unrelated process");

    assert_eq!(error.kind(), ErrorKind::CorruptState);
    assert!(still_alive);
    assert_eq!(
        registry::read(&fixture.runtime, &fixture.space).expect("inspect registry"),
        Some(failed)
    );
}

#[test]
fn an_observer_recovers_a_reused_pid_without_signalling_its_process() {
    let fixture = Fixture::new("observer-reused-pid");
    let starting = fixture.dead_record(StoredAgentState::Starting, None);
    let mut unrelated = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("spawn unrelated process");
    let generation = process::process_generation(unrelated.id()).expect("capture process generation");
    let failed = fixture.record(
        StoredAgentState::Failed,
        unrelated.id(),
        Some(generation ^ 1),
        Some(AgentFailure::LaunchExited),
    );
    registry::create(&fixture.runtime, &failed).expect("publish reused-PID replacement");

    let result = startup::reconcile(
        &fixture.space,
        &fixture.runtime,
        &starting,
        Instant::now() + startup::MAXIMUM_TOTAL_STARTUP_WAIT,
    )
    .expect("recover reused-PID replacement");
    let still_alive = unrelated.try_wait().expect("inspect unrelated process").is_none();
    unrelated.kill().expect("stop unrelated process");
    unrelated.wait().expect("reap unrelated process");

    assert!(matches!(result, startup::Reconciled::Recovered));
    assert!(still_alive);
    assert!(
        registry::read(&fixture.runtime, &fixture.space)
            .expect("inspect registry")
            .is_none()
    );
}

#[test]
fn a_dead_starting_record_requests_rereservation_instead_of_unset_success() {
    let fixture = Fixture::new("starting-rereservation");
    let starting = fixture.dead_record(StoredAgentState::Starting, None);
    registry::create(&fixture.runtime, &starting).expect("publish abandoned startup");

    let result = startup::reconcile(
        &fixture.space,
        &fixture.runtime,
        &starting,
        Instant::now() + startup::MAXIMUM_TOTAL_STARTUP_WAIT,
    )
    .expect("recover abandoned startup");

    assert!(matches!(result, startup::Reconciled::Recovered));
    assert!(
        registry::read(&fixture.runtime, &fixture.space)
            .expect("inspect registry")
            .is_none()
    );
}

#[test]
fn status_and_recovery_reject_a_recycled_starting_pid_generation() {
    let fixture = Fixture::new("status-recycled-pid");
    let mut unrelated = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("spawn unrelated process");
    let generation = process::process_generation(unrelated.id()).expect("capture process generation");
    let starting = fixture.record(StoredAgentState::Starting, unrelated.id(), Some(generation ^ 1), None);
    registry::create(&fixture.runtime, &starting).expect("publish reused-PID startup");

    let status = fixture
        .store
        .ssh_agent_status(&fixture.space, &fixture.host)
        .expect("inspect reused-PID startup");
    let recovered = fixture
        .store
        .recover_ssh_agent(&fixture.space, &fixture.host)
        .expect("recover reused-PID startup");
    let still_alive = unrelated.try_wait().expect("inspect unrelated process").is_none();
    unrelated.kill().expect("stop unrelated process");
    unrelated.wait().expect("reap unrelated process");

    assert_eq!(status.state, crate::AgentState::Stale);
    assert_eq!(recovered.state, crate::AgentState::Unset);
    assert!(still_alive);
}

#[test]
fn reservation_defers_while_a_failed_owner_finishes_cleanup() {
    let fixture = Fixture::new("failed-owner-cleanup");
    let failed = fixture.dead_record(StoredAgentState::Failed, Some(AgentFailure::LaunchExited));
    registry::create(&fixture.runtime, &failed).expect("publish failed startup");
    let owner_path = fixture.runtime.join(registry::STARTUP_OWNER_LOCK_FILE);
    let owner = crate::store::open_or_create_private_lock(&owner_path).expect("open owner lock");
    <std::fs::File as fs4::FileExt>::lock(&owner).expect("hold owner lock");

    let pending = startup::reserve_waits_for_active_owner(&fixture.store, &fixture.space, &fixture.runtime)
        .expect("inspect failed owner cleanup");

    assert!(pending);
    drop(owner);
}

#[test]
fn reservation_defers_while_an_owner_has_not_published_a_record() {
    let fixture = Fixture::new("unpublished-owner-cleanup");
    let owner_path = fixture.runtime.join(registry::STARTUP_OWNER_LOCK_FILE);
    let owner = crate::store::open_or_create_private_lock(&owner_path).expect("open owner lock");
    <std::fs::File as fs4::FileExt>::lock(&owner).expect("hold owner lock");

    let pending = startup::reserve_waits_for_active_owner(&fixture.store, &fixture.space, &fixture.runtime)
        .expect("inspect unpublished owner cleanup");

    assert!(pending);
    drop(owner);
}

struct Fixture {
    _temporary: tempfile::TempDir,
    store: Store,
    space: Space,
    host: HostEnvironment,
    runtime: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        let space = store
            .create(SpaceName::parse(name).expect("space name"), PathBuf::from("/bin/sh"))
            .expect("create space");
        let host = HostEnvironment::capture();
        let runtime = crate::platform::runtime_directory(&space, &host).expect("runtime");
        Self {
            _temporary: temporary,
            store,
            space,
            host,
            runtime,
        }
    }

    fn dead_record(&self, state: StoredAgentState, failure: Option<AgentFailure>) -> AgentRecord {
        let mut child = Command::new("/usr/bin/true").spawn().expect("spawn completed process");
        let pid = child.id();
        let generation = process::process_generation(pid).expect("capture process generation");
        child.wait().expect("reap completed process");
        self.record(state, pid, Some(generation), failure)
    }

    fn record(
        &self,
        state: StoredAgentState,
        pid: u32,
        process_generation: Option<u128>,
        failure: Option<AgentFailure>,
    ) -> AgentRecord {
        AgentRecord {
            schema_version: REGISTRY_SCHEMA_VERSION,
            state,
            space_id: self.space.id().cloned().expect("stable ID"),
            token: "0123456789abcdef0123456789abcdef".to_owned(),
            pid,
            process_generation,
            created_unix_ms: epoch_millis().expect("clock"),
            socket_inode: None,
            socket_device: None,
            failure,
        }
    }
}
