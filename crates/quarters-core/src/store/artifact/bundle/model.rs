//! Stable authenticated-bundle models and reports.

use super::super::{ArtifactId, ArtifactKind, ArtifactName, ContentIntegrity, SourceIdentity};
use crate::{CloneLimits, CloneMode, SpaceLayout};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub(super) const BUNDLE_VERSION: u32 = 1;
pub(super) const BUNDLE_ALGORITHM: &str = "blake3-keyed-256:quarters-bundle-v1";

/// Strict authenticated bundle header.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleHeader {
    /// Format schema.
    pub schema_version: u32,
    /// Stable export-operation identity.
    pub export_id: ArtifactId,
    /// Export creation time.
    pub created_unix_ms: u128,
    /// Exported artifact category.
    pub source_kind: ArtifactKind,
    /// Exported artifact identity.
    pub source_artifact_id: ArtifactId,
    /// Exported artifact display name.
    pub source_name: ArtifactName,
    /// Historical source generation.
    pub source_identity: SourceIdentity,
    /// Original layout.
    pub source_layout: SpaceLayout,
    /// Exporting host family.
    pub source_platform: String,
    /// Carried default shell path.
    pub default_shell: PathBuf,
    /// Whether derived caches are present.
    pub include_cache: bool,
    /// Arbitrary private state may contain credentials.
    pub includes_sensitive_state: bool,
    /// Canonical tree identity.
    pub content_integrity: ContentIntegrity,
    /// Bundle authentication algorithm.
    pub authentication: String,
}

/// Export preview or execution report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BundleExportReport {
    /// Preview or execute.
    pub mode: CloneMode,
    /// Template or snapshot.
    pub source_kind: ArtifactKind,
    /// Exported artifact name.
    pub source_name: String,
    /// Export identity after execution.
    pub export_id: Option<String>,
    /// Destination selected by the user.
    pub destination: PathBuf,
    /// Canonical content record.
    pub content_integrity: ContentIntegrity,
    /// Fixed resource limits.
    pub limits: CloneLimits,
    /// Plaintext sensitive-state disclosure.
    pub includes_sensitive_state: bool,
    /// Stable security boundary statement.
    pub security_boundary: String,
    /// Post-commit durability or hidden-staging warning.
    pub publication_warning: Option<String>,
}

/// Authenticated import preview or execution report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BundleImportReport {
    /// Preview or execute.
    pub mode: CloneMode,
    /// Destination template name.
    pub destination: String,
    /// Digest required for execution after preview.
    pub plan_digest: String,
    /// Imported local artifact identity after execution.
    pub artifact_id: Option<String>,
    /// Authenticated export identity.
    pub export_id: String,
    /// Original artifact category.
    pub source_kind: ArtifactKind,
    /// Original artifact name.
    pub source_name: String,
    /// Exporting host family.
    pub source_platform: String,
    /// Authenticated default shell path.
    pub default_shell: PathBuf,
    /// Canonical content record.
    pub content_integrity: ContentIntegrity,
    /// Bundle authentication algorithm.
    pub authentication: String,
    /// Stable safety statement.
    pub content_safety: String,
    /// Post-commit directory durability warning.
    pub publication_warning: Option<String>,
}

/// Key-creation result with no key path or bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExportKeyReport {
    /// Whether a fresh key was published.
    pub created: bool,
    /// Required private key byte length.
    pub bytes: u32,
    /// Post-commit durability or hidden-staging warning.
    pub publication_warning: Option<String>,
}

/// Parsed and authenticated bundle evidence.
#[derive(Clone, Debug)]
pub(super) struct AuthenticatedBundle {
    pub(super) header: BundleHeader,
    pub(super) tag: blake3::Hash,
    pub(super) generation: FileGeneration,
}

/// Exact retained regular-file generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FileGeneration {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) length: u64,
    pub(super) modified_seconds: i64,
    pub(super) modified_nanoseconds: i64,
    pub(super) changed_seconds: i64,
    pub(super) changed_nanoseconds: i64,
}
