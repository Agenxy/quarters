//! Versioned store-layout resolution shared by every storage operation.

mod marker;

use super::{Store, create_private_dir, unique_suffix};
use crate::store_lock::{MutationGuard, raw_management_guard};
use crate::store_policy::{validate_private_dir, validate_store_root};
use crate::{QuartersError, Result, SpaceName};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) use marker::RootFormat;

/// Non-mutating diagnosis of the store's root-format control state.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StoreLayoutDiagnosis {
    /// Stable diagnosis state.
    pub state: String,
    /// Authoritative category layout when it can be established.
    pub root_format: Option<String>,
    /// Whether this build may mutate the resolved layout.
    pub writable: bool,
    /// Whether a valid marker publication awaits exact staging cleanup.
    pub interrupted_publication: bool,
    /// Raw root-format marker classification.
    pub marker: String,
    /// Raw category families observed, each `visible` or `dotted`.
    pub category_entries: Vec<String>,
    /// Bounded, presentation-safe reserved staging entry identifiers.
    pub staging_entries: Vec<String>,
    /// Lower bound on all reserved staging entries observed.
    pub staging_entries_at_least: usize,
    /// Stable staging-specific error category, when present.
    pub staging_error_kind: Option<String>,
    /// Bounded staging-specific issue, when present.
    pub staging_issue: Option<String>,
    /// Exact stable error category when resolution fails.
    pub error_kind: Option<String>,
    /// Actionable diagnosis without an OS path dump.
    pub issue: Option<String>,
    /// Operator action associated with the issue.
    pub hint: Option<String>,
}

/// Resolved paths for the current on-disk store layout.
#[derive(Clone, Debug)]
pub(crate) struct StoreLayout {
    spaces_root: PathBuf,
    trash_root: PathBuf,
    root_format: RootFormat,
}

impl StoreLayout {
    fn visible(root: &Path) -> Self {
        Self {
            spaces_root: root.join("spaces"),
            trash_root: root.join("trash"),
            root_format: RootFormat::Visible,
        }
    }

    fn dotted(root: &Path) -> Self {
        Self {
            spaces_root: root.join(".spaces"),
            trash_root: root.join(".trash"),
            root_format: RootFormat::Dotted,
        }
    }

    /// Published spaces directory.
    pub(crate) fn spaces_root(&self) -> &Path {
        &self.spaces_root
    }

    /// Retired-state directory.
    pub(crate) fn trash_root(&self) -> &Path {
        &self.trash_root
    }

    pub(crate) fn space_path(&self, name: &SpaceName) -> PathBuf {
        self.spaces_root.join(name.as_str())
    }

    pub(crate) fn temporary_path(&self, name: &SpaceName) -> Result<PathBuf> {
        Ok(self.spaces_root.join(format!(".creating-{name}-{}", unique_suffix()?)))
    }

    pub(crate) const fn root_format(&self) -> RootFormat {
        self.root_format
    }

    fn require_writable(&self) -> Result<()> {
        if self.root_format() == RootFormat::Visible {
            return Ok(());
        }
        Err(marker::dotted_read_only_error())
    }

    fn validate_categories(&self) -> Result<()> {
        let spaces = fs::symlink_metadata(&self.spaces_root)
            .map_err(|error| QuartersError::io("inspect store spaces directory", &self.spaces_root, error))?;
        validate_private_dir(&self.spaces_root, &spaces)?;
        match fs::symlink_metadata(&self.trash_root) {
            Ok(metadata) => validate_private_dir(&self.trash_root, &metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(QuartersError::io(
                "inspect store trash directory",
                &self.trash_root,
                error,
            )),
        }
    }
}

impl Store {
    /// Resolve the authoritative layout for one bounded operation.
    pub(crate) fn layout(&self) -> Result<StoreLayout> {
        marker::resolve(&self.root)
    }

    /// Inspect root-format state without creating or repairing any entry.
    #[must_use]
    pub fn layout_diagnosis(&self) -> StoreLayoutDiagnosis {
        marker::diagnose(&self.root)
    }

    pub(crate) fn begin_mutation(&self) -> Result<MutationGuard> {
        let preliminary = self.layout()?;
        preliminary.require_writable()?;
        let management = raw_management_guard(self)?;
        marker::recover_interrupted_publication(&self.root)?;
        let layout = self.layout()?;
        layout.require_writable()?;
        layout.validate_categories()?;
        Ok(MutationGuard::new(management, layout))
    }

    pub(crate) fn ensure_layout(&self) -> Result<()> {
        ensure_store_root(&self.root)?;
        let preliminary = self.layout()?;
        preliminary.require_writable()?;
        let _management = raw_management_guard(self)?;
        marker::recover_interrupted_publication(&self.root)?;
        let layout = self.layout()?;
        layout.require_writable()?;
        create_private_dir(layout.spaces_root())?;
        create_private_dir(layout.trash_root())?;
        marker::attempt_visible_marker(&self.root)
    }

    pub(super) fn existing_spaces_root(&self) -> Result<Option<PathBuf>> {
        let root_metadata = match fs::symlink_metadata(&self.root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(QuartersError::io("inspect Quarters root", &self.root, error)),
        };
        validate_store_root(&self.root, &root_metadata)?;
        let spaces_root = self.layout()?.spaces_root().to_path_buf();
        let spaces_metadata = match fs::symlink_metadata(&spaces_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(QuartersError::io("inspect spaces directory", &spaces_root, error)),
        };
        validate_private_dir(&spaces_root, &spaces_metadata)?;
        Ok(Some(spaces_root))
    }
}

fn ensure_store_root(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_store_root(path, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_private_dir(path),
        Err(error) => Err(QuartersError::io("inspect Quarters root", path, error)),
    }
}
