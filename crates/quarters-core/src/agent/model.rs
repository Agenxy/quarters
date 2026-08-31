//! Public and persisted SSH-agent lifecycle models.

use crate::{Space, SpaceId};
use serde::{Deserialize, Serialize};

pub(super) const REGISTRY_SCHEMA_VERSION: u32 = 1;

/// Observable state of a private per-space SSH agent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentState {
    /// No registry or socket exists.
    Unset,
    /// A verified launcher is preparing the agent.
    Starting,
    /// The process, socket identity, peer PID and SSH-agent protocol passed.
    Active,
    /// A verified stop is in progress.
    Stopping,
    /// Startup failed without a usable agent.
    Failed,
    /// Stored ownership or live state no longer agrees.
    Stale,
}

impl AgentState {
    /// Stable lowercase representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unset => "unset",
            Self::Starting => "starting",
            Self::Active => "active",
            Self::Stopping => "stopping",
            Self::Failed => "failed",
            Self::Stale => "stale",
        }
    }
}

/// Stable inspection result for CLI, doctor and MCP observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AgentStatus {
    /// Space display name.
    pub space: String,
    /// Current lifecycle state.
    pub state: AgentState,
    /// Verified agent PID when one is recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Private socket path when it is safe to disclose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket: Option<String>,
    /// Concise evidence or recovery guidance.
    pub detail: String,
}

impl AgentStatus {
    pub(super) fn unset(space: &Space) -> Self {
        Self {
            space: space.manifest().name.as_str().to_owned(),
            state: AgentState::Unset,
            pid: None,
            socket: None,
            detail: "no private SSH agent is configured".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentRecord {
    pub schema_version: u32,
    pub state: StoredAgentState,
    pub space_id: SpaceId,
    pub token: String,
    pub pid: u32,
    pub created_unix_ms: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_inode: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_device: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<AgentFailure>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum StoredAgentState {
    Starting,
    Active,
    Stopping,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum AgentFailure {
    ExecutableUnavailable,
    LaunchExited,
    StartupTimeout,
    ProtocolRejected,
}
