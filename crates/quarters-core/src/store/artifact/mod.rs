//! Persistent named lifecycle artifacts.

mod active;
mod binding;
mod bundle;
mod catalog;
mod integrity;
mod model;
mod rollback;

pub use bundle::{BundleExportReport, BundleHeader, BundleImportReport, ExportKeyReport};
pub use model::{
    Artifact, ArtifactCounts, ArtifactId, ArtifactInspection, ArtifactKind, ArtifactManifest, ArtifactMutationReport,
    ArtifactName, ArtifactOrigin, ArtifactReport, ContentIntegrity, ImportedBundleProvenance, RollbackInventory,
    RollbackIssue, RollbackMode, RollbackObservation, RollbackRecoveryAction, RollbackReport, SourceIdentity,
    SourceQuiescence, SourceStatus, TemplateUseReport,
};

pub(crate) use rollback::rollback_retired_entry_is_actionable;
