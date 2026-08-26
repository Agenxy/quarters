//! Stored space model and validated names.

use crate::{ErrorKind, QuartersError, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};

/// Legacy profile-layout manifest schema.
pub const PROFILE_SCHEMA_VERSION: u32 = 1;
/// Expanded workspace-layout manifest schema.
pub const WORKSPACE_SCHEMA_VERSION: u32 = 2;
/// Stable-identity manifest schema for every user-directory layout.
pub const STABLE_SCHEMA_VERSION: u32 = 3;
/// Newest on-disk manifest schema supported by this build.
pub const LATEST_SCHEMA_VERSION: u32 = STABLE_SCHEMA_VERSION;
/// Every on-disk manifest schema supported by this build.
pub const SUPPORTED_SCHEMA_VERSIONS: [u32; 3] =
    [PROFILE_SCHEMA_VERSION, WORKSPACE_SCHEMA_VERSION, STABLE_SCHEMA_VERSION];

/// User-state directory layout created for a space.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SpaceLayout {
    /// Minimal shell and CLI state profile.
    Profile,
    /// Expanded user workspace with common personal directories.
    Workspace,
}

impl SpaceLayout {
    /// Stable lowercase representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Workspace => "workspace",
        }
    }
}

impl Display for SpaceLayout {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.pad(self.as_str())
    }
}

/// Stable opaque identity for schema-2 and newer spaces.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SpaceId(String);

impl SpaceId {
    /// Parse a 128-bit lowercase hexadecimal identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the identifier is not exactly 32 lowercase
    /// hexadecimal ASCII characters.
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
            "space IDs must be exactly 32 lowercase hexadecimal characters",
        ))
    }

    /// Borrow the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn generate() -> Result<Self> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|error| {
            QuartersError::new(ErrorKind::System, "could not obtain randomness for a stable space ID")
                .with_source(error)
        })?;
        let mut encoded = String::with_capacity(32);
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Self::parse(encoded)
    }
}

impl Display for SpaceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.pad(&self.0)
    }
}

impl<'de> Deserialize<'de> for SpaceId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// A validated portable space name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SpaceName(String);

impl SpaceName {
    /// Parse a name safe for paths, prompts and short Unix socket roots.
    ///
    /// # Errors
    ///
    /// Returns an error when the value violates the portable name grammar.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let valid_length = (1..=32).contains(&value.len());
        let valid_start = value.bytes().next().is_some_and(|byte| byte.is_ascii_alphanumeric());
        let valid_body = value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        if valid_length && valid_start && valid_body {
            return Ok(Self(value));
        }
        Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "space names must be 1-32 ASCII letters, numbers, hyphens or underscores and start with a letter or number",
        ))
    }

    /// Borrow the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for SpaceName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.pad(&self.0)
    }
}

impl<'de> Deserialize<'de> for SpaceName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Schema-versioned metadata stored inside each space.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceManifest {
    /// On-disk schema version.
    pub schema_version: u32,
    /// Explicit layout for schemas that require one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<SpaceLayout>,
    /// Stable opaque identity for schemas that require one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    /// Validated space name.
    pub name: SpaceName,
    /// Creation time as Unix epoch milliseconds.
    pub created_unix_ms: u128,
    /// Default absolute shell path.
    pub default_shell: PathBuf,
    /// Honest product boundary shown by inspection tools.
    pub authority_model: String,
}

impl SpaceManifest {
    /// Effective directory layout after schema validation.
    #[must_use]
    pub fn effective_layout(&self) -> SpaceLayout {
        self.layout.unwrap_or(SpaceLayout::Profile)
    }
}

/// An existing folder-backed state profile.
#[derive(Clone, Debug)]
pub struct Space {
    root: PathBuf,
    manifest: SpaceManifest,
}

impl Space {
    /// Construct a verified existing space.
    #[must_use]
    pub(crate) fn new(root: PathBuf, manifest: SpaceManifest) -> Self {
        Self { root, manifest }
    }

    /// Root directory containing all persistent space state.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Alternate home directory.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    /// Activity lock file.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.root.join(".active")
    }

    /// Stored metadata.
    #[must_use]
    pub const fn manifest(&self) -> &SpaceManifest {
        &self.manifest
    }

    /// Validated directory layout.
    #[must_use]
    pub fn layout(&self) -> SpaceLayout {
        self.manifest.effective_layout()
    }

    /// Stable opaque identity when supported by the manifest schema.
    #[must_use]
    pub fn id(&self) -> Option<&SpaceId> {
        self.manifest.space_id.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::{SpaceId, SpaceName};

    #[test]
    fn deserialization_enforces_the_name_grammar() {
        assert!(serde_json::from_str::<SpaceName>(r#""work_2""#).is_ok());
        assert!(serde_json::from_str::<SpaceName>(r#""\u001b[31mrogue""#).is_err());
        assert!(serde_json::from_str::<SpaceName>(r#""name-that-is-more-than-thirty-two-characters""#).is_err());
    }

    #[test]
    fn stable_ids_are_strict_lowercase_hex() {
        assert!(SpaceId::parse("0123456789abcdef0123456789abcdef").is_ok());
        assert!(SpaceId::parse("0123456789ABCDEF0123456789ABCDEF").is_err());
        assert!(SpaceId::parse("abc").is_err());
    }

    #[test]
    fn generated_ids_are_valid_and_distinct() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let first = SpaceId::generate()?;
        let second = SpaceId::generate()?;
        assert_ne!(first, second);
        assert_eq!(first.as_str().len(), 32);
        Ok(())
    }
}
