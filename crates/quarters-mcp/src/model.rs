//! Stable MCP presentation types.

use quarters_core::{
    CompatibilityTier, ErrorKind, QuartersError, RollbackIssue, ToolProbe, escape_untrusted_text_bounded,
};
use schemars::JsonSchema;
use serde::Serialize;

/// Machine-readable failure returned inside a tool result.
#[derive(Debug, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Diagnostic {
    /// Stable Quarters error category.
    pub(crate) code: String,
    /// Safe, actionable explanation.
    pub(crate) message: String,
    /// Whether retrying after external state changes may succeed.
    pub(crate) retryable: bool,
}

impl From<&QuartersError> for Diagnostic {
    fn from(error: &QuartersError) -> Self {
        Self {
            code: error.kind().as_str().to_owned(),
            message: escape_untrusted_text_bounded(error.message(), 512),
            retryable: matches!(
                error.kind(),
                ErrorKind::AlreadyExists | ErrorKind::SpaceActive | ErrorKind::System
            ),
        }
    }
}

impl Diagnostic {
    pub(crate) fn for_unhealthy_entry(error: &QuartersError) -> Self {
        Self {
            code: error.kind().as_str().to_owned(),
            message: "an untrusted store entry failed Quarters control-anchor validation".to_owned(),
            retryable: false,
        }
    }
}

/// One healthy or unhealthy space entry.
#[derive(Debug, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SpaceView {
    /// Directory-entry or validated manifest name.
    pub(crate) name: String,
    /// `healthy` only when every trusted control anchor validates.
    pub(crate) health: String,
    /// Optional transitional state, absent for ordinary entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) state: Option<String>,
    /// Whether the name passed the portable grammar or is untrusted directory data.
    pub(crate) name_trust: String,
    /// UTF-8 fidelity of the directory-entry name.
    pub(crate) name_encoding: String,
    /// Folder-backed alternate home, when healthy.
    pub(crate) home: Option<String>,
    /// Creation identity used to guard destructive operations, when healthy.
    pub(crate) created_unix_ms: Option<u64>,
    /// Stored default shell, when healthy.
    pub(crate) default_shell: Option<String>,
    /// Effective user-directory layout, when healthy.
    pub(crate) layout: Option<String>,
    /// Stable opaque identity for schema-2 spaces, when healthy.
    pub(crate) space_id: Option<String>,
    /// Cooperative Quarters lease state, when healthy.
    pub(crate) lease_state: Option<String>,
    /// Whether this server process identifies itself as inside the space.
    pub(crate) current: bool,
    /// Validation failure for an unhealthy entry.
    pub(crate) issue: Option<Diagnostic>,
}

/// Bounded status snapshot.
#[derive(Debug, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatusData {
    /// Evidence model used for activity.
    pub(crate) observation_scope: String,
    /// Detached same-user descendants remain undiscoverable.
    pub(crate) detached_processes: String,
    /// Name self-reported by this process and validated against the store.
    pub(crate) current_space: Option<String>,
    /// Independently validated entries.
    pub(crate) spaces: Vec<SpaceView>,
    /// Retained markers that cannot be recovered automatically.
    pub(crate) rollback_issues: Vec<RollbackIssueView>,
}

/// Bounded agent-safe view of one retained rollback issue.
#[derive(Debug, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RollbackIssueView {
    pub(crate) marker: String,
    pub(crate) target: Option<String>,
    pub(crate) code: String,
    pub(crate) message: String,
}

impl From<&RollbackIssue> for RollbackIssueView {
    fn from(issue: &RollbackIssue) -> Self {
        Self {
            marker: issue.marker.clone(),
            target: issue.target.as_ref().map(ToString::to_string),
            code: issue.code.clone(),
            message: escape_untrusted_text_bounded(&issue.message, 512),
        }
    }
}

/// One platform capability.
#[derive(Debug, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapabilityView {
    /// Capability name.
    pub(crate) name: String,
    /// Whether this host can attempt it.
    pub(crate) available: bool,
    /// Stability or implementation state.
    pub(crate) status: String,
    /// Honest mechanism or limitation.
    pub(crate) detail: String,
}

/// One representative local-tool compatibility assessment.
#[derive(Debug, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeView {
    /// Display and executable name.
    pub(crate) tool: String,
    /// Whether an executable was found without running it.
    pub(crate) installed: bool,
    /// A, B, C or D compatibility class.
    pub(crate) tier: String,
    /// Environment or adapter mechanism.
    pub(crate) mechanism: String,
    /// Limitation that remains.
    pub(crate) limitation: Option<String>,
}

impl From<ToolProbe> for ProbeView {
    fn from(probe: ToolProbe) -> Self {
        let tier = match probe.tier {
            CompatibilityTier::A => "A",
            CompatibilityTier::B => "B",
            CompatibilityTier::C => "C",
            CompatibilityTier::D => "D",
        };
        Self {
            tool: probe.tool,
            installed: probe.installed,
            tier: tier.to_owned(),
            mechanism: probe.mechanism,
            limitation: probe.limitation,
        }
    }
}

/// Capability and compatibility report.
#[derive(Debug, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DoctorData {
    /// Host platform.
    pub(crate) platform: String,
    /// Plain authority boundary.
    pub(crate) authority_boundary: String,
    /// Platform mechanisms and declared gaps.
    pub(crate) capabilities: Vec<CapabilityView>,
    /// Side-effect-free executable discovery and declared compatibility.
    pub(crate) tools: Vec<ProbeView>,
    /// Space whose environment was constructed successfully, when requested.
    pub(crate) validated_space: Option<String>,
}

/// Result of creating one space.
#[derive(Debug, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateData {
    /// Created and re-opened space.
    pub(crate) space: SpaceView,
}
