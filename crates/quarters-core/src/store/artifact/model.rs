//! Versioned artifact model and validated identifiers.

use crate::{
    CloneCounts, CloneExclusions, CloneLimits, CloneMode, ErrorKind, QuartersError, Result, Space, SpaceId,
    SpaceLayout, SpaceName,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};

pub(super) const ARTIFACT_SCHEMA_VERSION: u32 = 1;
pub(super) const INTEGRITY_ALGORITHM: &str = "blake3-256:quarters-canonical-v1";

/// Opaque 128-bit artifact identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ArtifactId(String);

impl ArtifactId {
    /// Parse a lowercase 128-bit hexadecimal ID.
    ///
    /// # Errors
    ///
    /// Returns an error unless the input is exactly 32 lowercase hex bytes.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let valid = value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if valid {
            return Ok(Self(value));
        }
        Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "artifact IDs must be exactly 32 lowercase hexadecimal characters",
        ))
    }

    /// Generate an unpredictable artifact ID.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating system cannot provide randomness.
    pub fn generate() -> Result<Self> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|error| {
            QuartersError::new(ErrorKind::System, "could not obtain randomness for an artifact ID").with_source(error)
        })?;
        let mut encoded = String::with_capacity(32);
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Self::parse(encoded)
    }

    /// Borrow the validated ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ArtifactId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.pad(&self.0)
    }
}

impl<'de> Deserialize<'de> for ArtifactId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Validated portable display name for an artifact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ArtifactName(String);

impl ArtifactName {
    /// Parse the portable 1--32 byte artifact-name grammar.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe or non-portable names.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let valid = (1..=32).contains(&value.len())
            && value.bytes().next().is_some_and(|byte| byte.is_ascii_alphanumeric())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        if valid {
            return Ok(Self(value));
        }
        Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "artifact names must be 1-32 ASCII letters, numbers, hyphens or underscores and start with a letter or number",
        ))
    }

    /// Borrow the validated display name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ArtifactName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.pad(&self.0)
    }
}

impl<'de> Deserialize<'de> for ArtifactName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Persisted artifact category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactKind {
    /// Reusable named creation source.
    Template,
    /// Named point-in-time recovery source.
    Snapshot,
}

impl ArtifactKind {
    /// Stable lowercase category.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Template => "template",
            Self::Snapshot => "snapshot",
        }
    }
}

/// Why an artifact exists.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactOrigin {
    /// Explicitly created by the user.
    User,
    /// Automatically captured before rollback.
    AutomaticRollbackRecovery,
}

/// Stable source identity recorded by an artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    /// Source manifest schema.
    pub schema_version: u32,
    /// Source display name at capture time.
    pub name: SpaceName,
    /// Source creation timestamp.
    pub created_unix_ms: u128,
    /// Stable source ID when its schema supports one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
}

impl SourceIdentity {
    pub(super) fn for_space(space: &Space) -> Self {
        Self {
            schema_version: space.manifest().schema_version,
            name: space.manifest().name.clone(),
            created_unix_ms: space.manifest().created_unix_ms,
            space_id: space.id().cloned(),
        }
    }

    /// Whether this identity names the exact stored space generation.
    #[must_use]
    pub fn matches(&self, space: &Space) -> bool {
        *self == Self::for_space(space)
    }
}

/// Counts bound into the canonical content digest.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactCounts {
    /// Stored directories, excluding the home root.
    pub directories: u64,
    /// Stored regular files.
    pub files: u64,
    /// Stored symbolic links.
    pub symlinks: u64,
    /// Sum of the preceding entry classes.
    pub entries: u64,
    /// Regular-file bytes plus symlink-target bytes.
    pub logical_bytes: u64,
}

/// Canonical digest metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentIntegrity {
    /// Exact canonical algorithm name.
    pub algorithm: String,
    /// Lowercase BLAKE3-256 digest.
    pub digest: String,
    /// Counts included in the terminal record.
    pub counts: ArtifactCounts,
}

/// Strict artifact manifest schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    /// Artifact schema version.
    pub schema_version: u32,
    /// Stable physical identity.
    pub artifact_id: ArtifactId,
    /// Artifact category.
    pub kind: ArtifactKind,
    /// Mutable display name.
    pub name: ArtifactName,
    /// Capture timestamp in Unix milliseconds.
    pub created_unix_ms: u128,
    /// Exact source generation.
    pub source_identity: SourceIdentity,
    /// Source space layout.
    pub source_layout: SpaceLayout,
    /// Host family that created the artifact.
    pub source_platform: String,
    /// Validated default shell carried by templates.
    pub default_shell: PathBuf,
    /// Whether derived cache contents were captured.
    pub include_cache: bool,
    /// Arbitrary persistent state may contain secrets.
    pub includes_sensitive_state: bool,
    /// User-created or automatic recovery origin.
    pub origin: ArtifactOrigin,
    /// Canonical content integrity evidence.
    pub content_integrity: ContentIntegrity,
}

impl ArtifactManifest {
    pub(super) fn validate(&self, expected_kind: ArtifactKind) -> Result<()> {
        if self.schema_version != ARTIFACT_SCHEMA_VERSION {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                format!("unsupported artifact schema {}", self.schema_version),
            ));
        }
        if self.kind != expected_kind {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "artifact kind and store root differ",
            ));
        }
        if self.created_unix_ms == 0 || self.source_identity.created_unix_ms == 0 {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "artifact timestamps must be positive Unix milliseconds",
            ));
        }
        validate_source_identity(self)?;
        if !matches!(self.source_platform.as_str(), "macos" | "linux") {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "artifact source platform must be 'macos' or 'linux'",
            ));
        }
        if !self.default_shell.is_absolute() {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "artifact default shell must be an absolute path",
            ));
        }
        if !self.includes_sensitive_state {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "artifact sensitive-state disclosure cannot be disabled",
            ));
        }
        if self.origin == ArtifactOrigin::AutomaticRollbackRecovery && self.kind != ArtifactKind::Snapshot {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "automatic rollback recovery origin is valid only for snapshots",
            ));
        }
        if self.content_integrity.algorithm != INTEGRITY_ALGORITHM {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                format!(
                    "unsupported artifact integrity algorithm '{}'",
                    self.content_integrity.algorithm
                ),
            ));
        }
        if !valid_digest(&self.content_integrity.digest) {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "artifact digest is not lowercase BLAKE3-256",
            ));
        }
        validate_counts(self.content_integrity.counts)?;
        Ok(())
    }
}

fn validate_source_identity(manifest: &ArtifactManifest) -> Result<()> {
    let source = &manifest.source_identity;
    let valid = match manifest.source_layout {
        SpaceLayout::Profile => source.schema_version == 1 && source.space_id.is_none(),
        SpaceLayout::Workspace => source.schema_version == 2 && source.space_id.is_some(),
    };
    if valid {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "artifact source identity and layout are inconsistent",
    ))
}

fn validate_counts(counts: ArtifactCounts) -> Result<()> {
    let entries = counts
        .directories
        .checked_add(counts.files)
        .and_then(|value| value.checked_add(counts.symlinks));
    if entries == Some(counts.entries) {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "artifact terminal entry counts are inconsistent",
    ))
}

/// One validated published artifact.
#[derive(Clone, Debug)]
pub struct Artifact {
    root: PathBuf,
    manifest: ArtifactManifest,
}

impl Artifact {
    pub(super) fn new(root: PathBuf, manifest: ArtifactManifest) -> Self {
        Self { root, manifest }
    }

    /// Published artifact directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Stored content home.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    /// Validated manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ArtifactManifest {
        &self.manifest
    }
}

/// Whether the source generation still resolves in the current store.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceStatus {
    /// Exact source generation exists.
    Present,
    /// Source is absent or a same-name replacement has a different identity.
    Orphaned,
}

/// One independently inspected artifact entry.
#[derive(Debug)]
pub enum ArtifactInspection {
    /// Manifest and control anchors are healthy.
    Healthy {
        /// Validated artifact.
        artifact: Box<Artifact>,
        /// Whether the exact source generation still exists.
        source_status: SourceStatus,
    },
    /// Entry exists but violates artifact invariants.
    Unhealthy {
        /// Physical directory-entry name.
        id: String,
        /// Exact validation failure.
        error: QuartersError,
    },
}

/// Stable report for artifact preview and creation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactReport {
    /// Template or snapshot.
    pub kind: ArtifactKind,
    /// Preview or execution.
    pub mode: CloneMode,
    /// Source space name.
    pub source: String,
    /// Requested artifact display name.
    pub name: String,
    /// Published ID after execution.
    pub artifact_id: Option<String>,
    /// Whether derived caches are included.
    pub include_cache: bool,
    /// Arbitrary included state can contain credentials.
    pub includes_sensitive_state: bool,
    /// Entries examined by the creation-source walker.
    pub examined_counts: CloneCounts,
    /// Safe source exclusions and topology changes.
    pub exclusions: CloneExclusions,
    /// Canonical stored counts after execution.
    pub stored_counts: Option<ArtifactCounts>,
    /// Fixed walk limits.
    pub limits: CloneLimits,
    /// Cooperative activity does not discover detached writers.
    pub detached_processes: String,
}

/// Stable report for template instantiation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TemplateUseReport {
    /// Template display name.
    pub template: String,
    /// Template physical identity.
    pub artifact_id: String,
    /// New destination space.
    pub destination: String,
    /// Preview or execution.
    pub mode: CloneMode,
    /// New stable destination ID when schema 2 supports it.
    pub destination_space_id: Option<String>,
    /// Source layout restored into the destination.
    pub layout: SpaceLayout,
    /// Whether the artifact contains derived caches.
    pub include_cache: bool,
    /// Canonical counts verified before use.
    pub stored_counts: ArtifactCounts,
    /// Embedded paths are not rewritten.
    pub embedded_absolute_paths: String,
    /// Host account authority remains unchanged.
    pub authority_boundary: String,
}

/// Stable report for artifact rename or removal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactMutationReport {
    /// Artifact category.
    pub kind: ArtifactKind,
    /// Stable physical identity.
    pub artifact_id: String,
    /// Previous display name.
    pub previous_name: String,
    /// New display name for rename; absent after removal.
    pub name: Option<String>,
    /// Operation performed.
    pub operation: String,
}

/// Preview or execution mode for rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RollbackMode {
    /// Validate every source without mutation.
    Preview,
    /// Capture recovery and replace the target.
    Execute,
}

/// Stable rollback preview and execution result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RollbackReport {
    /// Preview or execution.
    pub mode: RollbackMode,
    /// Target Quarter whose identity is retained.
    pub target: String,
    /// Selected recovery-point display name.
    pub snapshot: String,
    /// Selected recovery-point physical identity.
    pub snapshot_id: String,
    /// Required automatic recovery snapshot name.
    pub recovery_name: String,
    /// Published recovery snapshot identity after execution.
    pub recovery_snapshot_id: Option<String>,
    /// Whether recovery capture includes cache contents.
    pub recovery_includes_cache: bool,
    /// Target stable identity where supported.
    pub target_space_id: Option<String>,
    /// Snapshot counts verified before replacement.
    pub restored_counts: ArtifactCounts,
    /// Detached writers remain unknowable.
    pub detached_processes: String,
    /// Portable publication has three observable states.
    pub publication_model: String,
    /// Host authority remains unchanged.
    pub authority_boundary: String,
}

/// Deterministic action for one interrupted rollback.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RollbackRecoveryAction {
    /// Keep the old target and discard unused staging.
    Abort,
    /// Restore the retired old target and discard staging.
    RestoreOld,
    /// Keep the published new target and reclaim retired state.
    CompleteNew,
}

/// Bounded doctor view of one durable rollback marker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackObservation {
    /// Transaction ID.
    pub transaction_id: ArtifactId,
    /// Validated target name.
    pub target: SpaceName,
    /// Durable marker state.
    pub state: String,
    /// Deterministic recovery direction.
    pub action: RollbackRecoveryAction,
}

/// One retained rollback marker that cannot be recovered automatically.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackIssue {
    /// Exact validated marker entry name.
    pub marker: String,
    /// Validated target when the marker body reveals one safely.
    pub target: Option<SpaceName>,
    /// Stable failure class.
    pub code: String,
    /// Bounded operator-facing failure detail.
    pub message: String,
    /// Bounded manual inspection guidance.
    pub hint: Option<String>,
}

/// One lock-consistent view of actionable and ambiguous rollback state.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackInventory {
    /// Transactions with one deterministic recovery action.
    pub observations: Vec<RollbackObservation>,
    /// Retained markers that require manual reconciliation.
    pub issues: Vec<RollbackIssue>,
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{ArtifactId, ArtifactName};

    #[test]
    fn artifact_names_and_ids_are_strict() {
        assert!(ArtifactName::parse("daily-1").is_ok());
        assert!(ArtifactName::parse("../daily").is_err());
        assert!(ArtifactId::parse("0123456789abcdef0123456789abcdef").is_ok());
        assert!(ArtifactId::parse("0123456789ABCDEF0123456789ABCDEF").is_err());
    }
}
