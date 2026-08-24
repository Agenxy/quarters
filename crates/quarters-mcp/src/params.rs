//! Strict MCP tool parameters.

use schemars::JsonSchema;
use serde::Deserialize;

/// Closed user-directory layout accepted by MCP creation.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CreateLayout {
    /// Minimal shell and CLI state profile.
    Profile,
    /// Expanded home with common personal and platform directories.
    Workspace,
}

impl From<CreateLayout> for quarters_core::SpaceLayout {
    fn from(value: CreateLayout) -> Self {
        match value {
            CreateLayout::Profile => Self::Profile,
            CreateLayout::Workspace => Self::Workspace,
        }
    }
}

/// Maximum entries returned by one all-space status request.
pub(crate) const MAX_STATUS_ENTRIES: usize = 128;

/// Status parameters. Omit `name` to inspect the bounded collection.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatusParams {
    /// Exact portable space name, or omission for every space.
    #[serde(default)]
    #[schemars(length(min = 1, max = 32))]
    #[schemars(regex(pattern = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$"))]
    pub(crate) name: Option<String>,
}

/// Parameters for a capability and compatibility check.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DoctorParams {
    /// Also validate this exact space and prepare its private runtime paths.
    #[serde(default)]
    #[schemars(length(min = 1, max = 32))]
    #[schemars(regex(pattern = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$"))]
    pub(crate) name: Option<String>,
}

/// Parameters for idempotent-by-failure space creation.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateParams {
    /// Portable space name: 1-32 ASCII letters, numbers, hyphens or underscores.
    #[schemars(length(min = 1, max = 32))]
    #[schemars(regex(pattern = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$"))]
    pub(crate) name: String,
    /// User-directory layout. Omission preserves the minimal profile default.
    #[serde(default)]
    pub(crate) layout: Option<CreateLayout>,
}
