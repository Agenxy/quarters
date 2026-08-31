//! Bounded advisory-lock acquisition for store coordination.

use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use fs4::FileExt;

use crate::store::{OBSERVATION_LOCK_FILE, RootFormat, StoreLayout, open_or_create_private_lock, open_private_lock};
use crate::{ErrorKind, LeaseState, QuartersError, Result, Space, Store};

const ACTIVE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);
const MANAGEMENT_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const OBSERVATION_LOCK_TIMEOUT: Duration = Duration::from_millis(500);
static RETRY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Non-cloneable ownership token for a store-wide mutation lease.
pub(crate) struct RawManagementGuard {
    _file: File,
}

/// Non-cloneable proof that the current store layout is writable.
pub(crate) struct MutationGuard {
    _management: RawManagementGuard,
    layout: StoreLayout,
}

impl MutationGuard {
    pub(crate) const fn new(management: RawManagementGuard, layout: StoreLayout) -> Self {
        Self {
            _management: management,
            layout,
        }
    }

    pub(crate) const fn layout(&self) -> &StoreLayout {
        &self.layout
    }
}

/// Non-cloneable ownership token for a store-wide observation lease.
pub(crate) struct ObservationGuard {
    _file: File,
}

/// Non-cloneable ownership token for one space lifecycle lease.
pub(crate) struct LifecycleLease {
    _file: File,
}

impl Store {
    pub(crate) fn observation_guard(&self) -> Result<ObservationGuard> {
        let path = self.root.join(OBSERVATION_LOCK_FILE);
        let layout = self.layout()?;
        let file = if layout.root_format() == RootFormat::Dotted {
            open_existing_observation_lock(&path)?
        } else {
            open_or_create_private_lock(&path)?
        };
        lock_bounded(
            &file,
            &path,
            LockMode::Exclusive,
            OBSERVATION_LOCK_TIMEOUT,
            "store observation",
        )?;
        Ok(ObservationGuard { _file: file })
    }

    fn root_guard(&self, timeout: Duration) -> Result<File> {
        let path = self.root.join(OBSERVATION_LOCK_FILE);
        let file = open_or_create_private_lock(&path)?;
        lock_bounded(&file, &path, LockMode::Exclusive, timeout, "store observation")?;
        Ok(file)
    }

    /// Observe whether Quarters' cooperative space lease is free or held.
    ///
    /// Detached descendants can outlive that lease, so this is activity
    /// evidence rather than process discovery.
    ///
    /// # Errors
    ///
    /// Returns an error when the lock file cannot be opened or inspected.
    pub fn lease_state(&self, space: &Space) -> Result<LeaseState> {
        let mut states = self.lease_states(&[space])?;
        states.pop().ok_or_else(|| {
            QuartersError::new(
                ErrorKind::System,
                "the activity observer returned no state for one requested space",
            )
        })
    }

    /// Observe several cooperative leases under one bounded store snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when an activity lock cannot be opened safely. Store
    /// observation contention yields `Unknown` for every requested space.
    pub fn lease_states(&self, spaces: &[&Space]) -> Result<Vec<LeaseState>> {
        let _observation = match self.observation_guard() {
            Ok(observation) => observation,
            Err(error) if error.kind() == ErrorKind::ResourceLimit => {
                return Ok(vec![LeaseState::Unknown; spaces.len()]);
            }
            Err(error) => return Err(error),
        };
        spaces
            .iter()
            .map(|space| lease_state_without_observation(space))
            .collect()
    }
}

fn open_existing_observation_lock(path: &Path) -> Result<File> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => open_private_lock(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(QuartersError::new(
            ErrorKind::ResourceLimit,
            "the inspection-only dotted store has no existing observation lock",
        )
        .with_hint("activity is unknown; this Quarters build will not create control state in a dotted store")),
        Err(error) => Err(QuartersError::io("inspect dotted-store observation lock", path, error)),
    }
}

pub(crate) fn raw_management_guard(store: &Store) -> Result<RawManagementGuard> {
    store
        .root_guard(MANAGEMENT_LOCK_TIMEOUT)
        .map(|file| RawManagementGuard { _file: file })
}

fn lease_state_without_observation(space: &Space) -> Result<LeaseState> {
    let lock_path = space.lock_path();
    let file = open_private_lock(&lock_path)?;
    match <File as FileExt>::try_lock(&file) {
        Ok(()) => Ok(LeaseState::Free),
        Err(fs4::TryLockError::WouldBlock) => Ok(LeaseState::Held),
        Err(fs4::TryLockError::Error(_error)) => Ok(LeaseState::Unknown),
    }
}

pub(crate) fn lock_shared_bounded(file: &File, path: &Path) -> Result<()> {
    lock_bounded(file, path, LockMode::Shared, ACTIVE_LOCK_TIMEOUT, "space activity")
}

pub(crate) fn acquire_lifecycle_lease(space: &Space, name: &str) -> Result<LifecycleLease> {
    let path = space.lock_path();
    let file = open_private_lock(&path)?;
    lock_exclusive_bounded_for_lifecycle(&file, &path, name)?;
    Ok(LifecycleLease { _file: file })
}

fn lock_exclusive_bounded_for_lifecycle(file: &File, path: &Path, name: &str) -> Result<()> {
    let deadline = Instant::now() + ACTIVE_LOCK_TIMEOUT;
    let mut attempt = 0_u32;
    loop {
        match try_lock(file, LockMode::Exclusive) {
            Ok(()) => return Ok(()),
            Err(fs4::TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(retry_delay(attempt));
                attempt = attempt.saturating_add(1);
            }
            Err(fs4::TryLockError::WouldBlock) => {
                return Err(QuartersError::new(
                    ErrorKind::SpaceActive,
                    format!("space '{name}' has a held cooperative lease"),
                )
                .with_hint(format!(
                    "run 'quarters status {name}', exit supervised and detached processes, then retry"
                )));
            }
            Err(fs4::TryLockError::Error(error)) => {
                return Err(QuartersError::io("lock space for lifecycle operation", path, error));
            }
        }
    }
}

fn lock_bounded(file: &File, path: &Path, mode: LockMode, timeout: Duration, label: &str) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut attempt = 0_u32;
    loop {
        match try_lock(file, mode) {
            Ok(()) => return Ok(()),
            Err(fs4::TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(retry_delay(attempt));
                attempt = attempt.saturating_add(1);
            }
            Err(fs4::TryLockError::WouldBlock) => {
                return Err(lock_timeout(label, timeout)
                    .with_hint("another Quarters operation may be busy; retry after it finishes"));
            }
            Err(fs4::TryLockError::Error(error)) => {
                let operation = match mode {
                    LockMode::Exclusive => "serialize lease observation",
                    LockMode::Shared => "lock active space",
                };
                return Err(QuartersError::io(operation, path, error));
            }
        }
    }
}

fn try_lock(file: &File, mode: LockMode) -> std::result::Result<(), fs4::TryLockError> {
    match mode {
        LockMode::Exclusive => <File as FileExt>::try_lock(file),
        LockMode::Shared => <File as FileExt>::try_lock_shared(file),
    }
}

fn retry_delay(attempt: u32) -> Duration {
    let exponential = 1_u64 << attempt.min(4);
    let jitter = RETRY_SEQUENCE.fetch_add(1, Ordering::Relaxed) % 5;
    Duration::from_millis(exponential + jitter)
}

fn lock_timeout(label: &str, timeout: Duration) -> QuartersError {
    QuartersError::new(
        ErrorKind::ResourceLimit,
        format!(
            "the {label} lock did not become available within {} ms",
            timeout.as_millis()
        ),
    )
}

#[derive(Clone, Copy)]
enum LockMode {
    Exclusive,
    Shared,
}
