//! Portable state-profile primitives for Quarters.

mod environment;
mod error;
mod model;
mod probe;
mod store;
#[cfg(test)]
mod store_concurrency_tests;
mod store_lock;
mod store_policy;
mod store_recovery;
mod text;

pub mod platform;

pub use environment::{EnvironmentPlan, HostEnvironment, host_command_environment};
pub use error::{ErrorKind, QuartersError, Result};
pub use model::{
    LATEST_SCHEMA_VERSION, PROFILE_SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSIONS, Space, SpaceId, SpaceLayout,
    SpaceManifest, SpaceName, WORKSPACE_SCHEMA_VERSION,
};
pub use platform::{Capabilities, CapabilityStatus};
pub use probe::{CompatibilityTier, ToolProbe, executable_matches, tool_probes};
pub use store::{LeaseState, SpaceInspection, SpaceLease, Store};
pub use store_recovery::RecoverySummary;
pub use text::{encode_untrusted_text_hex_bounded, escape_untrusted_text, escape_untrusted_text_bounded};
