//! Atomic legacy-manifest upgrade to stable space identity.

use super::create::replace_manifest;
use crate::store_lock::acquire_lifecycle_lease;
use crate::{
    ErrorKind, PROFILE_SCHEMA_VERSION, QuartersError, Result, STABLE_SCHEMA_VERSION, SpaceId, SpaceLayout, SpaceName,
    Store,
};
use serde::Serialize;

/// Preview or result of assigning a stable identity to one legacy space.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SpaceUpgradeReport {
    /// Space display name.
    pub name: String,
    /// Manifest schema before the operation.
    pub previous_schema: u32,
    /// Manifest schema after execution, or proposed by preview.
    pub schema: u32,
    /// Existing or newly assigned stable identity.
    pub space_id: Option<String>,
    /// Whether execution would change legacy metadata.
    pub would_change: bool,
    /// Whether persistent metadata changed.
    pub changed: bool,
    /// Cooperative lease evidence used by the operation.
    pub activity: &'static str,
    /// Same-UID authority remains unchanged.
    pub boundary: &'static str,
}

impl Store {
    /// Preview a legacy manifest upgrade without changing state.
    ///
    /// # Errors
    ///
    /// Returns an error when the space is active, corrupt or unsupported.
    pub fn upgrade_plan(&self, name: &SpaceName) -> Result<SpaceUpgradeReport> {
        self.ensure_no_rename_target(name)?;
        self.ensure_no_rollback_target(name)?;
        let space = self.open(name)?;
        let _lease = acquire_lifecycle_lease(&space, name.as_str())?;
        Ok(report(&space))
    }

    /// Atomically assign a stable identity to a legacy schema-1 profile.
    ///
    /// # Errors
    ///
    /// Returns an error when the space is active, changed, corrupt or cannot
    /// durably replace its manifest.
    pub fn upgrade_space(&self, name: &SpaceName) -> Result<SpaceUpgradeReport> {
        self.ensure_no_rename_target(name)?;
        self.ensure_no_rollback_target(name)?;
        let _management = self.begin_mutation()?;
        let space = self.open(name)?;
        let _lease = acquire_lifecycle_lease(&space, name.as_str())?;
        if space.id().is_some() {
            crate::platform::migrate_existing_legacy_runtime(&space, &crate::HostEnvironment::capture())?;
            return Ok(report(&space));
        }
        if space.manifest().schema_version != PROFILE_SCHEMA_VERSION || space.layout() != SpaceLayout::Profile {
            return Err(QuartersError::new(
                ErrorKind::Unsupported,
                "only a valid legacy schema-1 profile can be upgraded",
            ));
        }
        let mut manifest = space.manifest().clone();
        manifest.schema_version = STABLE_SCHEMA_VERSION;
        manifest.layout = Some(SpaceLayout::Profile);
        manifest.space_id = Some(SpaceId::generate()?);
        replace_manifest(space.root(), &manifest, "upgrade")?;
        let upgraded = self.open(name)?;
        crate::platform::migrate_existing_legacy_runtime(&upgraded, &crate::HostEnvironment::capture())?;
        let id = upgraded.id().ok_or_else(|| {
            QuartersError::new(
                ErrorKind::System,
                "the upgraded space did not retain its stable identity",
            )
        })?;
        Ok(SpaceUpgradeReport {
            name: upgraded.manifest().name.as_str().to_owned(),
            previous_schema: PROFILE_SCHEMA_VERSION,
            schema: STABLE_SCHEMA_VERSION,
            space_id: Some(id.as_str().to_owned()),
            would_change: true,
            changed: true,
            activity: "cooperative lease was free; detached same-UID processes remain unknown",
            boundary: "stable identity changes metadata, not host-account authority or containment",
        })
    }
}

fn report(space: &crate::Space) -> SpaceUpgradeReport {
    let (schema, id, would_change) = if let Some(id) = space.id() {
        (space.manifest().schema_version, Some(id.as_str().to_owned()), false)
    } else {
        (STABLE_SCHEMA_VERSION, None, true)
    };
    SpaceUpgradeReport {
        name: space.manifest().name.as_str().to_owned(),
        previous_schema: space.manifest().schema_version,
        schema,
        space_id: id,
        would_change,
        changed: false,
        activity: "cooperative lease was free; detached same-UID processes remain unknown",
        boundary: "stable identity changes metadata, not host-account authority or containment",
    }
}
