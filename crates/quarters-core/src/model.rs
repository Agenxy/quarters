//! Stored space model and validated names.

use crate::{ErrorKind, QuartersError, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};

/// Current on-disk manifest schema.
pub const SCHEMA_VERSION: u32 = 1;

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
pub struct SpaceManifest {
    /// On-disk schema version.
    pub schema_version: u32,
    /// Validated space name.
    pub name: SpaceName,
    /// Creation time as Unix epoch milliseconds.
    pub created_unix_ms: u128,
    /// Default absolute shell path.
    pub default_shell: PathBuf,
    /// Honest product boundary shown by inspection tools.
    pub authority_model: String,
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
}

#[cfg(test)]
mod tests {
    use super::SpaceName;

    #[test]
    fn deserialization_enforces_the_name_grammar() {
        assert!(serde_json::from_str::<SpaceName>(r#""work_2""#).is_ok());
        assert!(serde_json::from_str::<SpaceName>(r#""\u001b[31mrogue""#).is_err());
        assert!(serde_json::from_str::<SpaceName>(r#""name-that-is-more-than-thirty-two-characters""#).is_err());
    }
}
