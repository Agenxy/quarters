//! Bounded lifecycle-copy transactions.

mod cleanup;
mod copy;
mod policy;
mod walk;

#[cfg(test)]
mod tests;

pub(crate) use cleanup::remove_tree_restoring_owner_access;
pub use policy::{CloneCounts, CloneExclusions, CloneLimits, CloneMode, ClonePolicy, CloneReport};
