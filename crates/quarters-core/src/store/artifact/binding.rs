//! Stable-name safety for artifacts captured before space IDs existed.

use super::{ArtifactInspection, ArtifactKind};
use crate::{Result, Space, Store};

impl Store {
    pub(crate) fn legacy_artifact_bindings(&self, space: &Space) -> Result<usize> {
        let mut bindings = 0_usize;
        for kind in [ArtifactKind::Template, ArtifactKind::Snapshot] {
            for inspection in self.inspect_artifacts(kind)? {
                if let ArtifactInspection::Healthy { artifact, .. } = inspection {
                    let source = &artifact.manifest().source_identity;
                    if source.space_id.is_none()
                        && source.name == space.manifest().name
                        && source.created_unix_ms == space.manifest().created_unix_ms
                    {
                        bindings = bindings.saturating_add(1);
                    }
                }
            }
        }
        Ok(bindings)
    }
}
