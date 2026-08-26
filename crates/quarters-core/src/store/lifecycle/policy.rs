//! Stable clone policy, limits and result schema.

use crate::SpaceLayout;
use serde::Serialize;

/// Whether a clone request is observational or mutating.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CloneMode {
    /// Inspect the included tree without publishing a destination.
    Preview,
    /// Copy and atomically publish a destination.
    Execute,
}

/// Fixed alpha limits for one lifecycle walk.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CloneLimits {
    /// Maximum directory entries examined.
    pub entries: u64,
    /// Maximum included logical bytes.
    pub logical_bytes: u64,
    /// Maximum bytes in one regular file.
    pub file_bytes: u64,
    /// Maximum directory depth.
    pub depth: u32,
    /// Maximum bytes in one path component.
    pub component_bytes: u64,
    /// Maximum bytes in one engine-relative path.
    pub relative_path_bytes: u64,
    /// Maximum bytes in one symbolic-link target.
    pub symlink_target_bytes: u64,
}

impl CloneLimits {
    pub(crate) const ALPHA: Self = Self {
        entries: 100_000,
        logical_bytes: 10 * 1_024 * 1_024 * 1_024,
        file_bytes: 2 * 1_024 * 1_024 * 1_024,
        depth: 64,
        component_bytes: 255,
        relative_path_bytes: 4_096,
        symlink_target_bytes: 4_096,
    };
}

/// Declared inclusion behavior for one clone.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ClonePolicy {
    /// Whether derived cache contents are copied.
    pub include_cache: bool,
    /// Arbitrary included files may contain credentials and private state.
    pub includes_sensitive_state: bool,
}

/// Counts of included persistent state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CloneCounts {
    /// Entries examined, including excluded entries.
    pub entries: u64,
    /// Included regular files.
    pub files: u64,
    /// Included directories.
    pub directories: u64,
    /// Included safe relative symbolic links.
    pub symlinks: u64,
    /// Included logical bytes, including symlink target text.
    pub logical_bytes: u64,
}

/// Aggregate exclusions and topology changes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CloneExclusions {
    /// Derived cache roots recreated empty.
    pub cache_roots: u64,
    /// Unix sockets omitted.
    pub sockets: u64,
    /// FIFOs omitted.
    pub fifos: u64,
    /// Character and block devices omitted.
    pub devices: u64,
    /// Entries not owned by the current UID omitted.
    pub foreign_owned: u64,
    /// Multiply linked files copied as independent files.
    pub hard_linked_files_copied_independently: u64,
    /// Preserved links whose targets are omitted cache roots.
    pub symlinks_into_omitted_cache_roots: u64,
}

/// Stable human- and machine-readable clone result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CloneReport {
    /// Source space name.
    pub source: String,
    /// Requested destination name.
    pub destination: String,
    /// Preview or execute.
    pub mode: CloneMode,
    /// Source and destination directory layout.
    pub layout: SpaceLayout,
    /// New destination identity when the schema supports one.
    pub destination_space_id: Option<String>,
    /// Inclusion policy.
    pub policy: ClonePolicy,
    /// Fixed resource limits.
    pub limits: CloneLimits,
    /// Included-state counts.
    pub counts: CloneCounts,
    /// Aggregate exclusions and topology changes.
    pub exclusions: CloneExclusions,
    /// Metadata classes intentionally not preserved.
    pub metadata_not_preserved: Vec<String>,
    /// Cooperative locking cannot discover detached processes.
    pub detached_processes: String,
    /// Embedded absolute paths are copied without rewriting.
    pub embedded_absolute_paths: String,
}

impl CloneReport {
    pub(crate) fn new(source: &str, destination: &str, mode: CloneMode, layout: SpaceLayout, cache: bool) -> Self {
        Self {
            source: source.to_owned(),
            destination: destination.to_owned(),
            mode,
            layout,
            destination_space_id: None,
            policy: ClonePolicy {
                include_cache: cache,
                includes_sensitive_state: true,
            },
            limits: CloneLimits::ALPHA,
            counts: CloneCounts::default(),
            exclusions: CloneExclusions::default(),
            metadata_not_preserved: [
                "timestamps",
                "ACLs",
                "extended attributes",
                "filesystem flags",
                "set-user-ID, set-group-ID and sticky mode bits",
                "sparse extent layout",
                "hard-link relationships",
            ]
            .map(str::to_owned)
            .to_vec(),
            detached_processes: "unknown".to_owned(),
            embedded_absolute_paths: "copied without rewriting and may still select source state".to_owned(),
        }
    }
}
