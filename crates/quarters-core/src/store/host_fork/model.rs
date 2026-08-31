//! Public, content-free host-fork plan and result model.

use crate::SpaceLayout;
use serde::Serialize;
use std::path::PathBuf;

/// Borrowed selection options shared by host-fork execution.
#[derive(Clone, Copy, Debug)]
pub struct HostForkOptions<'a> {
    /// Supported closed policy.
    pub policy: HostForkPolicy,
    /// Additional explicit regular files beneath host HOME.
    pub explicit_paths: &'a [PathBuf],
    /// Whether generated destination files may be replaced.
    pub replace_generated: bool,
}

/// Supported source policy for a host-state fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HostForkPolicy {
    /// Selected shell startup and editor convention files.
    Shell,
}

impl HostForkPolicy {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Shell => "shell",
        }
    }
}

/// Whether a host-fork report describes a preview or committed execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HostForkMode {
    /// No destination state was created.
    Preview,
    /// One complete destination was atomically published.
    Execute,
}

/// One selected source file, without content or secret-derived hashes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HostForkFile {
    /// Relative path beneath both host and destination homes.
    pub path: PathBuf,
    /// Closed selection category.
    pub category: &'static str,
    /// Source logical length.
    pub bytes: u64,
    /// Whether the generated clean-space file occupies this destination.
    pub generated_conflict: bool,
    /// Deterministic destination transformation, if any.
    pub transformation: &'static str,
}

/// One optional preset path that was present but unsafe or unavailable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HostForkIneligible {
    /// Relative preset path beneath host HOME.
    pub path: PathBuf,
    /// Stable content-free reason code.
    pub reason: &'static str,
}

/// Complete bounded plan or result for selected host-state import.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HostForkReport {
    /// Stable report schema.
    pub schema_version: u32,
    /// Preview or execution.
    pub mode: HostForkMode,
    /// Destination space name.
    pub destination: String,
    /// Destination layout.
    pub layout: SpaceLayout,
    /// Selected closed policy.
    pub policy: HostForkPolicy,
    /// Confirmation digest bound to policy, anchors and source metadata.
    pub plan_digest: String,
    /// Host home used as the descriptor anchor.
    pub source_home: PathBuf,
    /// Selected files in deterministic relative-path order.
    pub files: Vec<HostForkFile>,
    /// Absent optional preset paths.
    pub absent: Vec<PathBuf>,
    /// Present optional preset paths refused by source validation.
    pub ineligible: Vec<HostForkIneligible>,
    /// Categories deliberately excluded from this phase.
    pub excluded_categories: Vec<&'static str>,
    /// Whether selected bytes are deliberately not interpreted or classified.
    pub content_uninspected: bool,
    /// Whether selected files can embed secrets despite path exclusions.
    pub may_include_sensitive_content: bool,
    /// Number of selected regular files.
    pub file_count: usize,
    /// Sum of selected source logical lengths.
    pub logical_bytes: u64,
    /// Whether generated destination files may be replaced.
    pub replace_generated: bool,
    /// New stable destination identity after execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_space_id: Option<String>,
    /// Startup-content execution warning.
    pub warning: &'static str,
    /// Honest authority boundary.
    pub authority_boundary: &'static str,
    /// Atomic publication contract.
    pub publication_model: &'static str,
}

impl HostForkReport {
    pub(crate) fn set_mode(&mut self, mode: HostForkMode) {
        self.mode = mode;
    }
}
