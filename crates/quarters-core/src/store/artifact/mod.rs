//! Persistent named lifecycle artifacts.

mod binding;
mod catalog;
mod integrity;
mod model;
mod rollback;

pub use model::{
    Artifact, ArtifactCounts, ArtifactId, ArtifactInspection, ArtifactKind, ArtifactManifest, ArtifactMutationReport,
    ArtifactName, ArtifactOrigin, ArtifactReport, ContentIntegrity, RollbackInventory, RollbackIssue, RollbackMode,
    RollbackObservation, RollbackRecoveryAction, RollbackReport, SourceIdentity, SourceStatus, TemplateUseReport,
};

pub(crate) use rollback::rollback_retired_entry_is_actionable;
