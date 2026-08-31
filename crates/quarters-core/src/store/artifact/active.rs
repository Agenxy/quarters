//! Immediate artifact capture from an active, cooperatively frozen Quarter.

use super::catalog::{ArtifactSetup, artifact_walk_control, prepare_artifact_staging, report_from_clone};
use super::{ArtifactKind, ArtifactName, ArtifactOrigin, ArtifactReport, SourceQuiescence};
use crate::store::lifecycle::{CloneMode, walk_home};
use crate::store_lock::require_held_lifecycle_lease;
use crate::store_policy::validate_shell;
use crate::{ErrorKind, FreezeState, QuartersError, Result, SpaceName, Store};

impl Store {
    /// Preview capture from a currently active, cooperatively frozen source.
    ///
    /// # Errors
    ///
    /// Fails unless the source is healthy, stable-identity and frozen against
    /// new Quarters-managed launches and lifecycle mutations.
    pub fn active_artifact_plan(
        &self,
        kind: ArtifactKind,
        source: &SpaceName,
        name: &ArtifactName,
        include_cache: bool,
    ) -> Result<ArtifactReport> {
        let setup = ArtifactSetup::prepare_active(self, kind, source, name, CloneMode::Preview)?;
        let mut clone = setup.clone_report(include_cache);
        walk_home(&setup.source.home(), None, &mut clone, &artifact_walk_control())?;
        Ok(report_from_clone(
            kind,
            name,
            &clone,
            SourceQuiescence::FrozenActive,
            None,
            None,
        ))
    }

    /// Capture from a currently active, cooperatively frozen source.
    ///
    /// # Errors
    ///
    /// Fails without publication when freeze evidence, copying, verification
    /// or an exact filesystem operation fails.
    pub fn create_artifact_from_active(
        &self,
        kind: ArtifactKind,
        source: &SpaceName,
        name: ArtifactName,
        include_cache: bool,
        origin: ArtifactOrigin,
    ) -> Result<ArtifactReport> {
        let mut setup = ArtifactSetup::prepare_active(self, kind, source, &name, CloneMode::Execute)?;
        let result = self.execute_artifact(&mut setup, name, include_cache, origin);
        cleanup_failed_capture(&setup, result)
    }
}

impl ArtifactSetup {
    pub(super) fn prepare_active(
        store: &Store,
        kind: ArtifactKind,
        source: &SpaceName,
        name: &ArtifactName,
        mode: CloneMode,
    ) -> Result<Self> {
        if mode == CloneMode::Execute {
            store.ensure_layout()?;
        }
        let management = store.begin_mutation()?;
        let source_space = store.open(source)?;
        validate_shell(&source_space.manifest().default_shell)?;
        if store.freeze_state(&source_space)? != FreezeState::Frozen {
            return Err(QuartersError::new(
                ErrorKind::SpaceActive,
                format!("active capture requires cooperatively frozen space '{source}'"),
            )
            .with_hint(format!("run 'quarters freeze {source}', then retry the active capture")));
        }
        require_held_lifecycle_lease(&source_space, source.as_str())?;
        let active_lock = Store::shared_lease(&source_space)?;
        store.require_artifact_name_available(kind, name)?;
        let staging = if mode == CloneMode::Execute {
            Some(prepare_artifact_staging(store, kind)?)
        } else {
            None
        };
        drop(management);
        Ok(Self {
            kind,
            source_manifest: source_space.manifest().clone(),
            source: source_space,
            _activity_lock: None,
            _active_lock: Some(active_lock),
            source_quiescence: SourceQuiescence::FrozenActive,
            mode,
            name: name.clone(),
            staging,
        })
    }
}

fn cleanup_failed_capture(setup: &ArtifactSetup, result: Result<ArtifactReport>) -> Result<ArtifactReport> {
    if let Err(original) = &result
        && let Some(staging) = &setup.staging
        && let Err(cleanup) = staging.identity.cleanup(&staging.temporary)
    {
        return Err(QuartersError::new(
            original.kind(),
            format!(
                "active artifact capture failed and staging cleanup also failed: {}",
                original.message()
            ),
        )
        .with_hint("run 'quarters doctor', then recover only validated stale state")
        .with_source(cleanup));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::artifact::ArtifactInspection;
    use std::path::PathBuf;

    #[test]
    fn publication_rejects_a_freeze_removed_during_active_capture()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let store = Store::new(temporary.path().join("root"))?;
        let source = SpaceName::parse("work")?;
        let space = store.create(source.clone(), PathBuf::from("/bin/sh"))?;
        let activity = store.lease(&space)?;
        store.freeze(&source)?;
        let name = ArtifactName::parse("captured")?;
        let mut setup =
            ArtifactSetup::prepare_active(&store, ArtifactKind::Template, &source, &name, CloneMode::Execute)?;
        store.unfreeze(&source)?;

        let capture = store.execute_artifact(&mut setup, name, false, ArtifactOrigin::User);
        assert!(matches!(capture, Err(error) if error.kind() == ErrorKind::SpaceActive));
        assert!(
            store
                .inspect_artifacts(ArtifactKind::Template)?
                .iter()
                .all(|inspection| !matches!(inspection, ArtifactInspection::Healthy { .. }))
        );
        drop(activity);
        Ok(())
    }
}
