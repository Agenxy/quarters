//! Bounded lifecycle-copy transactions.

mod cleanup;
mod copy;
mod identity;
mod policy;
mod walk;

#[cfg(test)]
mod tests;

pub(crate) use cleanup::{remove_exact_tree_restoring_owner_access, remove_tree_restoring_owner_access};
pub(crate) use identity::{PathIdentity, StagingIdentity};
pub use policy::{CloneCounts, CloneExclusions, CloneLimits, CloneMode, ClonePolicy, CloneReport};
pub(crate) use walk::{WalkControl, walk_home};
