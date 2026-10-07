// SPDX-License-Identifier: GPL-3.0-or-later
//! Privacy-bounded metadata deltas for one directly executed process.

mod classify;
mod report;
mod scan;
#[cfg(test)]
mod tests;

pub use report::{
    CredentialShapeDisclosure, DiscoveryChild, DiscoveryClassCounts, DiscoveryDelta, DiscoveryObservation,
    DiscoveryPreview, DiscoveryReport, DiscoveryRootReport, DiscoveryTotals, HostStateAccess,
};

use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
/// A Quarter-owned root included in one discovery measurement.
pub enum DiscoverySelector {
    /// The virtual home directory.
    Home,
    /// The per-Quarter XDG runtime directory.
    Runtime,
}

impl DiscoverySelector {
    /// Returns the stable machine-readable selector name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Home => "home",
            Self::Runtime => "runtime",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Hard resource bounds applied independently to each metadata scan phase.
pub struct DiscoveryLimits {
    /// Maximum entries retained for each selected root.
    pub entries: u64,
    /// Maximum traversal depth below a selected root.
    pub depth: u32,
    /// Maximum relative path size processed for an entry.
    pub relative_path_bytes: u64,
    /// Maximum wall-clock duration for each selected root in one scan phase.
    pub phase_milliseconds: u64,
    /// Maximum aggregate bytes retained for pending directory-entry names.
    pub pending_name_bytes: u64,
}

impl DiscoveryLimits {
    /// Largest supported recursive traversal depth for library callers.
    pub const MAXIMUM_DEPTH: u32 = 256;

    /// Fixed limits for the alpha discovery contract.
    pub const ALPHA: Self = Self {
        entries: 262_144,
        depth: 64,
        relative_path_bytes: 4_096,
        phase_milliseconds: 5_000,
        pending_name_bytes: 16 * 1_024 * 1_024,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiscoveryClass {
    Configuration,
    Data,
    State,
    Cache,
    CredentialShaped,
    RuntimeSocket,
    Runtime,
    Unclassified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EntryIdentity {
    kind: nix::libc::mode_t,
    device: nix::libc::dev_t,
    inode: nix::libc::ino_t,
    mode: nix::libc::mode_t,
    uid: nix::libc::uid_t,
    gid: nix::libc::gid_t,
    links: nix::libc::nlink_t,
    size: nix::libc::off_t,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl EntryIdentity {
    fn from_stat(value: &nix::sys::stat::FileStat) -> Self {
        Self {
            kind: value.st_mode & nix::libc::S_IFMT,
            device: value.st_dev,
            inode: value.st_ino,
            mode: value.st_mode & 0o7777,
            uid: value.st_uid,
            gid: value.st_gid,
            links: value.st_nlink,
            size: value.st_size,
            modified_seconds: value.st_mtime,
            modified_nanoseconds: value.st_mtime_nsec,
            changed_seconds: value.st_ctime,
            changed_nanoseconds: value.st_ctime_nsec,
        }
    }

    fn same_object(&self, other: &Self) -> bool {
        self.kind == other.kind && self.device == other.device && self.inode == other.inode
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EntryRecord {
    class: DiscoveryClass,
    identity: EntryIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RootIdentity {
    device: nix::libc::dev_t,
    inode: nix::libc::ino_t,
    kind: nix::libc::mode_t,
    uid: nix::libc::uid_t,
    gid: nix::libc::gid_t,
}

impl RootIdentity {
    fn from_stat(value: &nix::sys::stat::FileStat) -> Self {
        Self {
            device: value.st_dev,
            inode: value.st_ino,
            kind: value.st_mode & nix::libc::S_IFMT,
            uid: value.st_uid,
            gid: value.st_gid,
        }
    }
}

struct Snapshot {
    entries: HashMap<[u8; 32], EntryRecord>,
    roots: BTreeMap<DiscoverySelector, u64>,
    root_identities: BTreeMap<DiscoverySelector, RootIdentity>,
    root_complete: BTreeMap<DiscoverySelector, bool>,
    root_bounds_exceeded: BTreeMap<DiscoverySelector, bool>,
    complete: bool,
    bounds_exceeded: bool,
    unreadable_directories: u64,
    unreadable_classes: DiscoveryClassCounts,
    unstable_entries: u64,
    foreign_owned: u64,
    metadata_errors: u64,
    entry_key_collisions: u64,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            roots: BTreeMap::new(),
            root_identities: BTreeMap::new(),
            root_complete: BTreeMap::new(),
            root_bounds_exceeded: BTreeMap::new(),
            complete: true,
            bounds_exceeded: false,
            unreadable_directories: 0,
            unreadable_classes: DiscoveryClassCounts::default(),
            unstable_entries: 0,
            foreign_owned: 0,
            metadata_errors: 0,
            entry_key_collisions: 0,
        }
    }
}

/// An opaque, content-free snapshot of Quarter-owned entry metadata.
pub struct DiscoverySnapshot(Snapshot);

/// Captures a bounded metadata-only snapshot of selected Quarter-owned roots.
///
/// # Errors
///
/// Returns an error when a selected root cannot be safely opened or bounded
/// scan resources cannot be reserved.
pub fn snapshot(
    home: &Path,
    runtime: &Path,
    selectors: &[DiscoverySelector],
    limits: DiscoveryLimits,
) -> crate::Result<DiscoverySnapshot> {
    if limits.depth > DiscoveryLimits::MAXIMUM_DEPTH {
        return Err(crate::QuartersError::new(
            crate::ErrorKind::InvalidInput,
            format!(
                "discovery depth {} exceeds the supported maximum {}",
                limits.depth,
                DiscoveryLimits::MAXIMUM_DEPTH
            ),
        ));
    }
    let mut unique = selectors.to_vec();
    unique.sort_unstable();
    unique.dedup();
    let roots = unique
        .iter()
        .map(|selector| {
            (
                *selector,
                match selector {
                    DiscoverySelector::Home => home,
                    DiscoverySelector::Runtime => runtime,
                },
            )
        })
        .collect::<Vec<_>>();
    scan::scan(&roots, limits).map(DiscoverySnapshot)
}

/// Builds a non-mutating preview of discovery scope and classification rules.
#[must_use]
pub fn preview(space: &str, selectors: &[DiscoverySelector], limits: DiscoveryLimits) -> DiscoveryPreview {
    report::preview(space, selectors, limits)
}

/// Compares pre- and post-execution snapshots without exposing entry paths.
#[must_use]
pub fn report(
    space: &str,
    pre: &DiscoverySnapshot,
    post: Option<&DiscoverySnapshot>,
    child: DiscoveryChild,
    limits: DiscoveryLimits,
) -> DiscoveryReport {
    report::report(space, &pre.0, post.map(|value| &value.0), child, limits)
}

fn diff(pre: &Snapshot, post: &Snapshot) -> DiscoveryDelta {
    let mut delta = DiscoveryDelta::default();
    for (key, after) in &post.entries {
        match pre.entries.get(key) {
            None => delta.created.increment(after.class),
            Some(before) if before.identity == after.identity => {}
            Some(before) if before.identity.same_object(&after.identity) => delta.modified.increment(after.class),
            Some(_before) => delta.replaced.increment(after.class),
        }
    }
    for (key, before) in &pre.entries {
        if !post.entries.contains_key(key) {
            delta.deleted.increment(before.class);
        }
    }
    delta
}

pub(crate) use classify::credential_shaped_path;
