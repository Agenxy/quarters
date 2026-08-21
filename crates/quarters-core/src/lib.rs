//! Portable state-profile primitives for Quarters.

mod environment;
mod error;
mod model;
mod probe;
mod store;

pub mod platform;

pub use environment::{EnvironmentPlan, HostEnvironment, host_command_environment};
pub use error::{ErrorKind, QuartersError, Result};
pub use model::{SCHEMA_VERSION, Space, SpaceManifest, SpaceName};
pub use platform::{Capabilities, CapabilityStatus};
pub use probe::{CompatibilityTier, ToolProbe, tool_probes};
pub use store::{SpaceLease, Store};
