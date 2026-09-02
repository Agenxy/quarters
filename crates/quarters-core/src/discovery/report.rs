use super::{DiscoveryClass, DiscoveryLimits, DiscoverySelector, Snapshot};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Counts changed entries by privacy-preserving semantic class.
pub struct DiscoveryClassCounts {
    /// Shell and application configuration entries.
    pub configuration: u64,
    /// User data and executable entries.
    pub data: u64,
    /// Persistent state entries.
    pub state: u64,
    /// Rebuildable cache entries.
    pub cache: u64,
    /// Entries whose path shape resembles credential storage.
    pub credential_shaped: u64,
    /// Runtime socket entries.
    pub runtime_socket: u64,
    /// Other entries in the selected runtime root.
    pub runtime: u64,
    /// Entries not covered by another class.
    pub unclassified: u64,
}

impl DiscoveryClassCounts {
    pub(super) fn increment(&mut self, class: DiscoveryClass) {
        let count = match class {
            DiscoveryClass::Configuration => &mut self.configuration,
            DiscoveryClass::Data => &mut self.data,
            DiscoveryClass::State => &mut self.state,
            DiscoveryClass::Cache => &mut self.cache,
            DiscoveryClass::CredentialShaped => &mut self.credential_shaped,
            DiscoveryClass::RuntimeSocket => &mut self.runtime_socket,
            DiscoveryClass::Runtime => &mut self.runtime,
            DiscoveryClass::Unclassified => &mut self.unclassified,
        };
        *count = count.saturating_add(1);
    }

    fn total(&self) -> u64 {
        self.configuration
            .saturating_add(self.data)
            .saturating_add(self.state)
            .saturating_add(self.cache)
            .saturating_add(self.credential_shaped)
            .saturating_add(self.runtime_socket)
            .saturating_add(self.runtime)
            .saturating_add(self.unclassified)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Entry-class counts for each observed change kind.
pub struct DiscoveryDelta {
    /// Paths absent before and present afterward.
    pub created: DiscoveryClassCounts,
    /// Paths whose metadata changed while retaining object identity.
    pub modified: DiscoveryClassCounts,
    /// Paths whose object identity changed.
    pub replaced: DiscoveryClassCounts,
    /// Paths present before and absent afterward.
    pub deleted: DiscoveryClassCounts,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Aggregate counts for each observed change kind.
pub struct DiscoveryTotals {
    /// Total created entries.
    pub created: u64,
    /// Total modified entries.
    pub modified: u64,
    /// Total replaced entries.
    pub replaced: u64,
    /// Total deleted entries.
    pub deleted: u64,
}

impl From<&DiscoveryDelta> for DiscoveryTotals {
    fn from(delta: &DiscoveryDelta) -> Self {
        Self {
            created: delta.created.total(),
            modified: delta.modified.total(),
            replaced: delta.replaced.total(),
            deleted: delta.deleted.total(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Native child termination status preserved by discovery.
pub struct DiscoveryChild {
    /// Exit code when the child exited normally.
    pub exit_code: Option<i32>,
    /// Terminating signal on Unix when the child was signaled.
    pub signal: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Entry counts observed for one selected root.
pub struct DiscoveryRootReport {
    /// Selected root.
    pub selector: DiscoverySelector,
    /// Entries retained in the pre-execution snapshot.
    pub entries_pre: u64,
    /// Entries retained afterward, absent when the post-scan failed.
    pub entries_post: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Limits of credential-shaped path classification.
pub struct CredentialShapeDisclosure {
    /// Stable classification basis.
    pub basis: String,
    /// Whether any contents were inspected.
    pub contents_inspected: bool,
    /// Whether benign paths may match.
    pub false_positives_expected: bool,
    /// Whether credential paths may be missed.
    pub false_negatives_expected: bool,
    /// Version of the disclosed pattern set.
    pub pattern_set_version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Evidence about scan completeness and cooperative concurrency.
pub struct DiscoveryObservation {
    /// Cooperative concurrency mechanism used.
    pub concurrency_evidence: String,
    /// Evidence available for detached writers.
    pub detached_writers: String,
    /// Stable description of scanner behavior.
    pub scan: String,
    /// Directories that could not be traversed.
    pub unreadable_directories: u64,
    /// Entries that vanished during metadata observation.
    pub vanished_entries: u64,
    /// Entries not owned by the current UID.
    pub foreign_owned: u64,
    /// Whether a selected root's filesystem identity changed between phases.
    pub root_identity_changed: bool,
    /// Metadata or directory-stream errors not otherwise classified.
    pub metadata_errors: u64,
    /// Duplicate opaque entry keys observed within one phase.
    pub entry_key_collisions: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Explicit boundary for host-state access measurement.
pub struct HostStateAccess {
    /// State roots that were measured.
    pub measured: String,
    /// Access surfaces the instrument cannot observe.
    pub unknown: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Privacy-bounded result of one discovery execution.
pub struct DiscoveryReport {
    /// Space name.
    pub space: String,
    /// Stable measurement state.
    pub state: String,
    /// Whether the delta is sound within the documented observation boundary.
    pub sound: bool,
    /// Whether both scans completed within bounds without observation gaps.
    pub complete: bool,
    /// Preserved child termination status.
    pub child: DiscoveryChild,
    /// Per-root entry counts without paths.
    pub roots: Vec<DiscoveryRootReport>,
    /// Classified delta, absent whenever measurement is incomplete.
    pub delta: Option<DiscoveryDelta>,
    /// Aggregate delta, absent whenever measurement is incomplete.
    pub totals: Option<DiscoveryTotals>,
    /// Credential-path classification disclosure.
    pub credential_shaped: CredentialShapeDisclosure,
    /// Observation-quality evidence and counters.
    pub observation: DiscoveryObservation,
    /// Resource bounds used for both scan phases.
    pub limits: DiscoveryLimits,
    /// Explicit host-write observation status.
    pub host_writes_observed: String,
    /// Explicit boundary for host-state access observation.
    pub host_state_access: HostStateAccess,
    /// Human-readable limits that prevent overclaiming.
    pub limitations: Vec<String>,
    /// Scanner-owned path classes deliberately omitted from traversal.
    pub exclusions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Non-executing disclosure of discovery scope and classification rules.
pub struct DiscoveryPreview {
    /// Space name.
    pub space: String,
    /// Stable preview state.
    pub state: String,
    /// Roots that were inspected.
    pub selectors: Vec<DiscoverySelector>,
    /// Entry count for each selected root.
    pub entries: BTreeMap<DiscoverySelector, u64>,
    /// Resource bounds used for the preview scan.
    pub limits: DiscoveryLimits,
    /// Version of the credential-shaped path rules.
    pub credential_pattern_set_version: u32,
    /// Exact path patterns used for credential-shaped classification.
    pub credential_patterns: Vec<String>,
    /// Whether file contents were inspected.
    pub contents_inspected: bool,
    /// Explicit host-write observation status.
    pub host_writes_observed: String,
    /// Explicit boundary for host-state access observation.
    pub host_state_access: HostStateAccess,
    /// Scanner-owned path classes deliberately omitted from traversal.
    pub exclusions: Vec<String>,
}

pub(super) fn preview(space: &str, snapshot: &Snapshot, limits: DiscoveryLimits) -> DiscoveryPreview {
    DiscoveryPreview {
        space: space.to_owned(),
        state: if snapshot.bounds_exceeded {
            "bounds-exceeded"
        } else if !snapshot.complete {
            "observation-gap"
        } else {
            "ready"
        }
        .to_owned(),
        selectors: snapshot.roots.keys().copied().collect(),
        entries: snapshot.roots.clone(),
        limits,
        credential_pattern_set_version: 1,
        credential_patterns: super::classify::CREDENTIAL_PATTERNS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        contents_inspected: false,
        host_writes_observed: "not-measured".to_owned(),
        host_state_access: host_state_access(),
        exclusions: exclusions(snapshot),
    }
}

pub(super) fn report(
    space: &str,
    pre: &Snapshot,
    post: Option<&Snapshot>,
    child: DiscoveryChild,
    limits: DiscoveryLimits,
) -> DiscoveryReport {
    let post_failed = post.is_none();
    let bounds_exceeded = pre.bounds_exceeded || post.is_some_and(|value| value.bounds_exceeded);
    let root_identity_changed = post.is_some_and(|value| pre.root_identities != value.root_identities);
    let observation_gap = !pre.complete || post.is_some_and(|value| !value.complete) || root_identity_changed;
    let delta = match post {
        Some(post) if !bounds_exceeded && !observation_gap => Some(super::diff(pre, post)),
        Some(_) | None => None,
    };
    let roots = pre
        .roots
        .iter()
        .map(|(selector, count)| DiscoveryRootReport {
            selector: *selector,
            entries_pre: *count,
            entries_post: post.and_then(|value| value.roots.get(selector)).copied(),
        })
        .collect();
    let complete =
        post.is_some_and(|value| pre.complete && value.complete && !bounds_exceeded && !root_identity_changed);
    let state = if post_failed {
        "post-scan-failed"
    } else if bounds_exceeded {
        "bounds-exceeded"
    } else if root_identity_changed {
        "root-identity-changed"
    } else if observation_gap {
        "observation-gap"
    } else {
        "measured"
    };
    let observation = DiscoveryObservation {
        concurrency_evidence: "exclusive-cooperative-lease".to_owned(),
        detached_writers: "unknown".to_owned(),
        scan: "metadata-only; no regular file was opened and no symbolic link was resolved".to_owned(),
        unreadable_directories: pre
            .unreadable_directories
            .saturating_add(post.map_or(0, |value| value.unreadable_directories)),
        vanished_entries: pre
            .vanished_entries
            .saturating_add(post.map_or(0, |value| value.vanished_entries)),
        foreign_owned: pre
            .foreign_owned
            .saturating_add(post.map_or(0, |value| value.foreign_owned)),
        root_identity_changed,
        metadata_errors: pre
            .metadata_errors
            .saturating_add(post.map_or(0, |value| value.metadata_errors)),
        entry_key_collisions: pre
            .entry_key_collisions
            .saturating_add(post.map_or(0, |value| value.entry_key_collisions)),
    };
    let totals = delta.as_ref().map(DiscoveryTotals::from);
    DiscoveryReport {
        space: space.to_owned(),
        state: state.to_owned(),
        sound: complete,
        complete,
        child,
        roots,
        delta,
        totals,
        credential_shaped: credential_disclosure(),
        observation,
        limits,
        host_writes_observed: "not-measured".to_owned(),
        host_state_access: host_state_access(),
        limitations: limitations(),
        exclusions: exclusions(pre),
    }
}

fn credential_disclosure() -> CredentialShapeDisclosure {
    CredentialShapeDisclosure {
        basis: "path-shape-only".to_owned(),
        contents_inspected: false,
        false_positives_expected: true,
        false_negatives_expected: true,
        pattern_set_version: 1,
    }
}

fn host_state_access() -> HostStateAccess {
    HostStateAccess {
        measured: "Quarter-owned roots only".to_owned(),
        unknown: [
            "reads of any file, including files inside scanned roots",
            "host paths outside the selected Quarter-owned roots",
            "content of paths admitted by --grant-path",
            "network, IPC, device and process access",
            "macOS Keychain, TCC and login-session state",
            "writes by detached descendants after Quarters exits",
            "writes preserving every compared metadata field",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    }
}

fn limitations() -> Vec<String> {
    [
        "No Quarter-owned state change is not evidence that host state was left alone.",
        "Reads, file contents, symlink targets and host paths are not observed.",
        "The caller-selected report sink is written after the post-scan and is outside the measured delta.",
        "The exclusive lease excludes only cooperating Quarters processes.",
        "LaunchServices GUI applications are outside this instrument.",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn exclusions(snapshot: &Snapshot) -> Vec<String> {
    if snapshot.roots.contains_key(&DiscoverySelector::Runtime) {
        vec!["runtime/bin contents (Quarters-prepared launcher and managed links)".to_owned()]
    } else {
        Vec::new()
    }
}
