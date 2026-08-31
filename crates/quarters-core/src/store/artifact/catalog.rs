//! Artifact catalog inspection and atomic creation.

use super::integrity::{digest_home, verify_home};
use super::model::{
    Artifact, ArtifactId, ArtifactInspection, ArtifactKind, ArtifactManifest, ArtifactMutationReport, ArtifactName,
    ArtifactOrigin, ArtifactReport, IMPORTED_ARTIFACT_SCHEMA_VERSION, LEGACY_LOCAL_ARTIFACT_SCHEMA_VERSION,
    LOCAL_ARTIFACT_SCHEMA_VERSION, SourceIdentity, SourceQuiescence, SourceStatus, TemplateUseReport,
};
use crate::store::create::{acquire_creation_lock, ensure_directory_skeleton, write_manifest};
use crate::store::lifecycle::{
    CloneMode, CloneReport, StagingIdentity, WalkControl, remove_tree_restoring_owner_access, walk_home,
};
use crate::store::scan::ScanBudget;
use crate::store_lock::{LifecycleLease, acquire_lifecycle_lease};
use crate::store_policy::{validate_private_dir, validate_shell};
use crate::{
    ErrorKind, FreezeState, QuartersError, Result, STABLE_SCHEMA_VERSION, SpaceId, SpaceManifest, SpaceName, Store,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use crate::store::{
    create_private_dir, entry_exists, epoch_millis, read_private_file, sync_directory, write_private_file,
};

const ARTIFACT_MANIFEST: &str = ".quarters-artifact.json";
const MAX_ARTIFACTS: usize = 4_096;

#[derive(Deserialize)]
struct ArtifactHeader {
    schema_version: u32,
}

impl Store {
    /// Preview creation of a named template or snapshot.
    ///
    /// # Errors
    ///
    /// Fails for invalid source state, a held source lease, a duplicate name or
    /// a source tree outside lifecycle limits.
    pub fn artifact_plan(
        &self,
        kind: ArtifactKind,
        source: &SpaceName,
        name: &ArtifactName,
        include_cache: bool,
    ) -> Result<ArtifactReport> {
        let setup = ArtifactSetup::prepare(self, kind, source, name, CloneMode::Preview)?;
        let mut clone = setup.clone_report(include_cache);
        walk_home(&setup.source.home(), None, &mut clone, &artifact_walk_control())?;
        Ok(report_from_clone(
            kind,
            name,
            &clone,
            SourceQuiescence::Inactive,
            None,
            None,
        ))
    }

    /// Create and atomically publish a named lifecycle artifact.
    ///
    /// # Errors
    ///
    /// Fails without publication when validation, copying, verification or an
    /// exact filesystem operation fails.
    pub fn create_artifact(
        &self,
        kind: ArtifactKind,
        source: &SpaceName,
        name: ArtifactName,
        include_cache: bool,
        origin: ArtifactOrigin,
    ) -> Result<ArtifactReport> {
        let mut setup = ArtifactSetup::prepare(self, kind, source, &name, CloneMode::Execute)?;
        let result = self.execute_artifact(&mut setup, name, include_cache, origin);
        if let Err(original) = &result
            && let Some(staging) = &setup.staging
            && let Err(cleanup) = staging.identity.cleanup(&staging.temporary)
        {
            return Err(QuartersError::new(
                original.kind(),
                format!(
                    "artifact creation failed and staging cleanup also failed: {}",
                    original.message()
                ),
            )
            .with_hint("run 'quarters doctor', then recover only validated stale state")
            .with_source(cleanup));
        }
        result
    }

    pub(super) fn create_artifact_with_held_source(
        &self,
        kind: ArtifactKind,
        source: &crate::Space,
        name: ArtifactName,
        include_cache: bool,
        origin: ArtifactOrigin,
    ) -> Result<ArtifactReport> {
        let mut setup = ArtifactSetup::prepare_with_held_source(self, kind, source, &name)?;
        let result = self.execute_artifact(&mut setup, name, include_cache, origin);
        if let Err(original) = &result
            && let Some(staging) = &setup.staging
            && let Err(cleanup) = staging.identity.cleanup(&staging.temporary)
        {
            return Err(QuartersError::new(
                original.kind(),
                format!(
                    "recovery snapshot failed and staging cleanup also failed: {}",
                    original.message()
                ),
            )
            .with_source(cleanup));
        }
        result
    }

    /// Inspect all published artifacts of one kind.
    ///
    /// # Errors
    ///
    /// Fails when the category root cannot be validated or exceeds its bound.
    pub fn inspect_artifacts(&self, kind: ArtifactKind) -> Result<Vec<ArtifactInspection>> {
        let Some(root) = existing_artifact_root(self, kind)? else {
            return Ok(Vec::new());
        };
        let rollback_inventory = match self.existing_spaces_root()? {
            Some(spaces) => Self::rollback_inventory_unlocked(&spaces)?,
            None => super::RollbackInventory::default(),
        };
        let rollback_targets = rollback_inventory
            .observations
            .into_iter()
            .map(|observation| observation.target)
            .chain(rollback_inventory.issues.into_iter().filter_map(|issue| issue.target))
            .collect::<BTreeSet<_>>();
        let stable_sources = self
            .inspect()?
            .into_iter()
            .filter_map(|inspection| match inspection {
                crate::SpaceInspection::Healthy(space) => space.id().map(|id| {
                    (
                        id.as_str().to_owned(),
                        space.manifest().created_unix_ms,
                        space.manifest().schema_version,
                    )
                }),
                crate::SpaceInspection::Unhealthy { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        let mut inspections = Vec::new();
        let entries = fs::read_dir(&root).map_err(|error| QuartersError::io("read artifact catalog", &root, error))?;
        let mut scan = ScanBudget::new("the artifact catalog");
        for entry in entries {
            let entry = entry.map_err(|error| QuartersError::io("read artifact entry", &root, error))?;
            scan.observe()?;
            let id = entry.file_name().to_string_lossy().into_owned();
            if id.starts_with('.') {
                continue;
            }
            if inspections.len() >= MAX_ARTIFACTS {
                return Err(QuartersError::new(
                    ErrorKind::ResourceLimit,
                    format!(
                        "the {} catalog contains more than {MAX_ARTIFACTS} entries",
                        kind.as_str()
                    ),
                ));
            }
            let inspection = match Self::open_artifact_path(kind, entry.path()) {
                Ok(artifact) => ArtifactInspection::Healthy {
                    source_status: source_status(self, &artifact, &rollback_targets, &stable_sources),
                    artifact: Box::new(artifact),
                },
                Err(error) => ArtifactInspection::Unhealthy { id, error },
            };
            inspections.push(inspection);
        }
        inspections.sort_by(|left, right| inspection_name(left).cmp(inspection_name(right)));
        Ok(inspections)
    }

    /// Resolve one artifact by its display name.
    ///
    /// # Errors
    ///
    /// Fails when absent, duplicated or corrupt.
    pub fn open_artifact(&self, kind: ArtifactKind, name: &ArtifactName) -> Result<Artifact> {
        self.open_artifact_with_status(kind, name)
            .map(|(artifact, _status)| artifact)
    }

    /// Resolve one artifact and its source status in one bounded catalog pass.
    ///
    /// # Errors
    ///
    /// Fails when absent, duplicated or corrupt.
    pub fn open_artifact_with_status(
        &self,
        kind: ArtifactKind,
        name: &ArtifactName,
    ) -> Result<(Artifact, SourceStatus)> {
        let mut found = None;
        for inspection in self.inspect_artifacts(kind)? {
            match inspection {
                ArtifactInspection::Healthy {
                    artifact,
                    source_status,
                } if artifact.manifest().name == *name => {
                    if found.is_some() {
                        return Err(QuartersError::new(
                            ErrorKind::CorruptState,
                            format!("duplicate {} name '{}'", kind.as_str(), name),
                        ));
                    }
                    found = Some((*artifact, source_status));
                }
                ArtifactInspection::Healthy { .. } | ArtifactInspection::Unhealthy { .. } => {}
            }
        }
        found.ok_or_else(|| artifact_not_found(kind, name))
    }

    /// Recompute and compare one artifact's canonical integrity record.
    ///
    /// # Errors
    ///
    /// Fails when the artifact is absent, corrupt or changed.
    pub fn verify_artifact(&self, kind: ArtifactKind, name: &ArtifactName) -> Result<Artifact> {
        let artifact = self.open_artifact(kind, name)?;
        verify_home(&artifact.home(), &artifact.manifest().content_integrity)?;
        Ok(artifact)
    }

    /// Preview creation of a space from a template.
    ///
    /// # Errors
    ///
    /// Fails when the template is invalid, its content changed, the shell is
    /// unusable or the destination exists.
    pub fn template_use_plan(
        &self,
        name: &ArtifactName,
        destination: &SpaceName,
        shell: Option<PathBuf>,
    ) -> Result<TemplateUseReport> {
        let template = self.verify_artifact(ArtifactKind::Template, name)?;
        let selected_shell = shell.unwrap_or_else(|| template.manifest().default_shell.clone());
        validate_shell(&selected_shell)
            .map_err(|error| error.with_hint("choose an absolute shell available on this host with --shell PATH"))?;
        reject_space_destination(self, destination)?;
        Ok(template_use_report(&template, destination, CloneMode::Preview, None))
    }

    /// Create a fresh space from a verified named template.
    ///
    /// # Errors
    ///
    /// Fails without publication when validation, copying or publication fails.
    pub fn use_template(
        &self,
        name: &ArtifactName,
        destination: &SpaceName,
        shell: Option<PathBuf>,
    ) -> Result<TemplateUseReport> {
        self.ensure_layout()?;
        let template = self.verify_artifact(ArtifactKind::Template, name)?;
        let selected_shell = shell.unwrap_or_else(|| template.manifest().default_shell.clone());
        validate_shell(&selected_shell)
            .map_err(|error| error.with_hint("choose an absolute shell available on this host with --shell PATH"))?;
        let staging = prepare_space_staging(self, destination)?;
        let result = self.execute_template_use(&template, destination, &selected_shell, &staging);
        if let Err(original) = &result
            && let Err(cleanup) = staging.identity.cleanup(&staging.temporary)
        {
            return Err(QuartersError::new(
                original.kind(),
                format!(
                    "template use failed and staging cleanup also failed: {}",
                    original.message()
                ),
            )
            .with_source(cleanup));
        }
        result
    }

    /// Rename an artifact without moving its content directory.
    ///
    /// # Errors
    ///
    /// Fails when either name is absent, duplicated or cannot be persisted.
    pub fn rename_artifact(
        &self,
        kind: ArtifactKind,
        previous: &ArtifactName,
        name: &ArtifactName,
    ) -> Result<ArtifactMutationReport> {
        let verified = self.verify_artifact(kind, previous)?;
        let _management = self.begin_mutation()?;
        let current = self.open_artifact(kind, previous)?;
        if current.manifest() != verified.manifest() {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "artifact changed during rename",
            ));
        }
        self.require_artifact_name_available(kind, name)?;
        let mut manifest = current.manifest().clone();
        manifest.name = name.clone();
        replace_artifact_manifest(current.root(), &manifest)?;
        Ok(ArtifactMutationReport {
            kind,
            artifact_id: manifest.artifact_id.as_str().to_owned(),
            previous_name: previous.as_str().to_owned(),
            name: Some(name.as_str().to_owned()),
            operation: "rename".to_owned(),
        })
    }

    /// Retire and remove one complete artifact.
    ///
    /// # Errors
    ///
    /// Fails when the artifact is absent, corrupt or cannot be retired safely.
    pub fn remove_artifact(&self, kind: ArtifactKind, name: &ArtifactName) -> Result<ArtifactMutationReport> {
        let verified = self.verify_artifact(kind, name)?;
        let (retired, report) = {
            let _management = self.begin_mutation()?;
            let current = self.open_artifact(kind, name)?;
            if current.manifest() != verified.manifest() {
                return Err(QuartersError::new(
                    ErrorKind::CorruptState,
                    "artifact changed during removal",
                ));
            }
            let root = artifact_root(self, kind);
            let retired = root.join(format!(".reclaiming-{}", current.manifest().artifact_id));
            if entry_exists(&retired)? {
                return Err(QuartersError::new(
                    ErrorKind::CorruptState,
                    "artifact reclaiming path already exists",
                ));
            }
            fs::rename(current.root(), &retired)
                .map_err(|error| QuartersError::io("retire artifact", current.root(), error))?;
            sync_directory(&root)?;
            let report = ArtifactMutationReport {
                kind,
                artifact_id: current.manifest().artifact_id.as_str().to_owned(),
                previous_name: name.as_str().to_owned(),
                name: None,
                operation: "remove".to_owned(),
            };
            (retired, report)
        };
        remove_tree_restoring_owner_access(&retired)?;
        sync_directory(&artifact_root(self, kind))?;
        Ok(report)
    }

    pub(super) fn execute_artifact(
        &self,
        setup: &mut ArtifactSetup,
        name: ArtifactName,
        include_cache: bool,
        origin: ArtifactOrigin,
    ) -> Result<ArtifactReport> {
        let staging = setup
            .staging
            .as_ref()
            .ok_or_else(|| QuartersError::new(ErrorKind::System, "artifact execution has no staging directory"))?;
        let mut clone = setup.clone_report(include_cache);
        walk_home(
            &setup.source.home(),
            Some(&staging.temporary.join("home")),
            &mut clone,
            &artifact_walk_control(),
        )?;
        let integrity = digest_home(&staging.temporary.join("home"))?;
        let manifest = ArtifactManifest {
            schema_version: LOCAL_ARTIFACT_SCHEMA_VERSION,
            artifact_id: staging.id.clone(),
            kind: setup.kind,
            name,
            created_unix_ms: epoch_millis()?,
            source_identity: Some(SourceIdentity::for_space(&setup.source)),
            source_layout: setup.source.layout(),
            source_platform: crate::platform::capabilities().platform,
            default_shell: setup.source.manifest().default_shell.clone(),
            include_cache,
            includes_sensitive_state: true,
            origin,
            imported_bundle: None,
            source_quiescence: Some(setup.source_quiescence),
            content_integrity: integrity.clone(),
        };
        write_artifact_manifest(&staging.temporary, &manifest)?;
        sync_directory(&staging.temporary.join("home"))?;
        sync_directory(&staging.temporary)?;
        let staged = Self::open_artifact_path(setup.kind, staging.temporary.clone())?;
        verify_home(&staged.home(), &staged.manifest().content_integrity)?;
        self.publish_artifact(setup, &manifest)?;
        Ok(report_from_clone(
            setup.kind,
            &manifest.name,
            &clone,
            setup.source_quiescence,
            Some(&manifest.artifact_id),
            Some(integrity.counts),
        ))
    }

    fn execute_template_use(
        &self,
        template: &Artifact,
        destination: &SpaceName,
        shell: &Path,
        staging: &SpaceStaging,
    ) -> Result<TemplateUseReport> {
        let mut clone = CloneReport::new(
            template.manifest().name.as_str(),
            destination.as_str(),
            CloneMode::Execute,
            template.manifest().source_layout,
            true,
        );
        walk_home(
            &template.home(),
            Some(&staging.temporary.join("home")),
            &mut clone,
            &WalkControl::default(),
        )?;
        ensure_directory_skeleton(&staging.temporary.join("home"), template.manifest().source_layout)?;
        let manifest = fresh_template_space_manifest(template.manifest(), destination.clone(), shell.to_path_buf())?;
        write_private_file(&staging.temporary.join(".active"), b"")?;
        write_manifest(&staging.temporary, &manifest)?;
        write_template_provenance(&staging.temporary, template)?;
        sync_directory(&staging.temporary.join("home"))?;
        sync_directory(&staging.temporary)?;
        self.verify_artifact(ArtifactKind::Template, &template.manifest().name)?;
        self.publish_template_space(template, &manifest, staging)?;
        Ok(template_use_report(
            template,
            destination,
            CloneMode::Execute,
            manifest.space_id.as_ref(),
        ))
    }

    fn publish_template_space(
        &self,
        template: &Artifact,
        manifest: &SpaceManifest,
        staging: &SpaceStaging,
    ) -> Result<()> {
        let management = self.begin_mutation()?;
        let current = self.open_artifact(ArtifactKind::Template, &template.manifest().name)?;
        if current.manifest() != template.manifest() {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "template changed during use",
            ));
        }
        reject_space_destination_at(self, &manifest.name, &management.layout().space_path(&manifest.name))?;
        staging
            .identity
            .verify(&staging.temporary, &staging.creation_lock_path)?;
        fs::remove_file(&staging.creation_lock_path)
            .map_err(|error| QuartersError::io("remove template staging lock", &staging.creation_lock_path, error))?;
        sync_directory(&staging.temporary)?;
        super::super::validate_space_anchors(&staging.temporary)?;
        fs::rename(&staging.temporary, &staging.destination)
            .map_err(|error| QuartersError::io("publish template destination", &staging.temporary, error))?;
        sync_directory(management.layout().spaces_root())
    }

    fn publish_artifact(&self, setup: &ArtifactSetup, manifest: &ArtifactManifest) -> Result<()> {
        let staging = setup
            .staging
            .as_ref()
            .ok_or_else(|| QuartersError::new(ErrorKind::System, "artifact publication has no staging state"))?;
        let _management = self.begin_mutation()?;
        let current = self.open(&setup.source.manifest().name)?;
        if current.manifest() != &setup.source_manifest {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "source manifest changed during artifact creation",
            ));
        }
        if setup.source_quiescence == SourceQuiescence::FrozenActive
            && self.freeze_state(&current)? != FreezeState::Frozen
        {
            return Err(QuartersError::new(
                ErrorKind::SpaceActive,
                "the cooperative freeze was removed during active artifact capture",
            )
            .with_hint("freeze the source again and repeat the capture; nothing was published"));
        }
        self.require_artifact_name_available(setup.kind, &manifest.name)?;
        if entry_exists(&staging.destination)? {
            return Err(QuartersError::new(
                ErrorKind::AlreadyExists,
                "generated artifact ID already exists",
            ));
        }
        staging
            .identity
            .verify(&staging.temporary, &staging.creation_lock_path)?;
        fs::remove_file(&staging.creation_lock_path)
            .map_err(|error| QuartersError::io("remove artifact staging lock", &staging.creation_lock_path, error))?;
        sync_directory(&staging.temporary)?;
        let staged = Self::open_artifact_path(setup.kind, staging.temporary.clone())?;
        if staged.manifest() != manifest {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "staged artifact controls changed before publish",
            ));
        }
        fs::rename(&staging.temporary, &staging.destination)
            .map_err(|error| QuartersError::io("publish artifact", &staging.temporary, error))?;
        sync_directory(&staging.root)
    }
}

impl Store {
    pub(super) fn require_artifact_name_available(&self, kind: ArtifactKind, name: &ArtifactName) -> Result<()> {
        match self.open_artifact(kind, name) {
            Ok(_artifact) => Err(QuartersError::new(
                ErrorKind::AlreadyExists,
                format!("{} '{}' already exists", kind.as_str(), name),
            )),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(super) fn open_artifact_path(kind: ArtifactKind, path: PathBuf) -> Result<Artifact> {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| QuartersError::io("inspect artifact directory", &path, error))?;
        validate_private_dir(&path, &metadata)?;
        let home = path.join("home");
        let home_metadata =
            fs::symlink_metadata(&home).map_err(|error| QuartersError::io("inspect artifact home", &home, error))?;
        validate_private_dir(&home, &home_metadata)?;
        let bytes = read_private_file(&path.join(ARTIFACT_MANIFEST))?;
        let header: ArtifactHeader = serde_json::from_slice(&bytes).map_err(|error| {
            QuartersError::new(ErrorKind::CorruptState, "artifact manifest header is invalid").with_source(error)
        })?;
        if !matches!(
            header.schema_version,
            LEGACY_LOCAL_ARTIFACT_SCHEMA_VERSION | IMPORTED_ARTIFACT_SCHEMA_VERSION | LOCAL_ARTIFACT_SCHEMA_VERSION
        ) {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                format!(
                    "artifact uses schema {}, but this build supports schemas {} through {}",
                    header.schema_version, LEGACY_LOCAL_ARTIFACT_SCHEMA_VERSION, LOCAL_ARTIFACT_SCHEMA_VERSION
                ),
            ));
        }
        let manifest: ArtifactManifest = serde_json::from_slice(&bytes).map_err(|error| {
            QuartersError::new(ErrorKind::CorruptState, "artifact manifest is invalid").with_source(error)
        })?;
        manifest.validate(kind)?;
        if path.file_name().and_then(|value| value.to_str()) != Some(manifest.artifact_id.as_str())
            && path
                .file_name()
                .and_then(|value| value.to_str())
                .is_none_or(|value| value != format!(".creating-{}", manifest.artifact_id))
        {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "artifact directory and manifest IDs differ",
            ));
        }
        Ok(Artifact::new(path, manifest))
    }
}

fn existing_artifact_root(store: &Store, kind: ArtifactKind) -> Result<Option<PathBuf>> {
    let root = artifact_root(store, kind);
    let metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(QuartersError::io("inspect artifact root", &root, error)),
    };
    validate_private_dir(&root, &metadata)?;
    Ok(Some(root))
}

fn source_status(
    store: &Store,
    artifact: &Artifact,
    rollback_targets: &BTreeSet<SpaceName>,
    stable_sources: &BTreeSet<(String, u128, u32)>,
) -> SourceStatus {
    let Some(identity) = &artifact.manifest().source_identity else {
        return SourceStatus::External;
    };
    if rollback_targets.contains(&identity.name) {
        return SourceStatus::Orphaned;
    }
    if let Some(space_id) = &identity.space_id {
        let present = stable_sources.contains(&(
            space_id.as_str().to_owned(),
            identity.created_unix_ms,
            identity.schema_version,
        ));
        return if present {
            SourceStatus::Present
        } else {
            SourceStatus::Orphaned
        };
    }
    match store.inspect_named_without_rollback(&identity.name) {
        Ok(crate::SpaceInspection::Healthy(space)) if identity.matches(&space) => SourceStatus::Present,
        Ok(crate::SpaceInspection::Healthy(_) | crate::SpaceInspection::Unhealthy { .. }) | Err(_) => {
            SourceStatus::Orphaned
        }
    }
}

pub(super) struct ArtifactSetup {
    pub(super) kind: ArtifactKind,
    pub(super) source: crate::Space,
    pub(super) source_manifest: crate::SpaceManifest,
    pub(super) _activity_lock: Option<LifecycleLease>,
    pub(super) _active_lock: Option<crate::SpaceLease>,
    pub(super) source_quiescence: SourceQuiescence,
    pub(super) mode: CloneMode,
    pub(super) name: ArtifactName,
    pub(super) staging: Option<ArtifactStaging>,
}

pub(super) struct SpaceStaging {
    pub(super) temporary: PathBuf,
    pub(super) destination: PathBuf,
    pub(super) creation_lock_path: PathBuf,
    pub(super) identity: StagingIdentity,
    pub(super) _creation_lock: File,
}

pub(super) struct ArtifactStaging {
    pub(super) id: ArtifactId,
    pub(super) root: PathBuf,
    pub(super) temporary: PathBuf,
    pub(super) destination: PathBuf,
    pub(super) creation_lock_path: PathBuf,
    pub(super) identity: StagingIdentity,
    _creation_lock: File,
}

impl ArtifactSetup {
    fn prepare(
        store: &Store,
        kind: ArtifactKind,
        source: &SpaceName,
        name: &ArtifactName,
        mode: CloneMode,
    ) -> Result<Self> {
        if mode == CloneMode::Execute {
            store.ensure_layout()?;
        }
        store.ensure_no_rename_target(source)?;
        let management = store.begin_mutation()?;
        let source_space = store.open(source)?;
        validate_shell(&source_space.manifest().default_shell)?;
        let activity_lock = acquire_lifecycle_lease(&source_space, source.as_str())?;
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
            _activity_lock: Some(activity_lock),
            _active_lock: None,
            source_quiescence: SourceQuiescence::Inactive,
            mode,
            name: name.clone(),
            staging,
        })
    }

    fn prepare_with_held_source(
        store: &Store,
        kind: ArtifactKind,
        source: &crate::Space,
        name: &ArtifactName,
    ) -> Result<Self> {
        store.ensure_layout()?;
        let management = store.begin_mutation()?;
        let current = store.open(&source.manifest().name)?;
        if current.manifest() != source.manifest() {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "held rollback source identity changed",
            ));
        }
        store.require_artifact_name_available(kind, name)?;
        let staging = Some(prepare_artifact_staging(store, kind)?);
        drop(management);
        Ok(Self {
            kind,
            source: source.clone(),
            source_manifest: source.manifest().clone(),
            _activity_lock: None,
            _active_lock: None,
            source_quiescence: SourceQuiescence::Inactive,
            mode: CloneMode::Execute,
            name: name.clone(),
            staging,
        })
    }

    pub(super) fn clone_report(&self, include_cache: bool) -> CloneReport {
        CloneReport::new(
            self.source.manifest().name.as_str(),
            self.name.as_str(),
            self.mode,
            self.source.layout(),
            include_cache,
        )
    }
}

pub(super) fn prepare_artifact_staging(store: &Store, kind: ArtifactKind) -> Result<ArtifactStaging> {
    let root = artifact_root(store, kind);
    create_private_dir(&root)?;
    let id = ArtifactId::generate()?;
    let temporary = root.join(format!(".creating-{id}"));
    let destination = root.join(id.as_str());
    if entry_exists(&temporary)? || entry_exists(&destination)? {
        return Err(QuartersError::new(
            ErrorKind::AlreadyExists,
            "generated artifact staging path already exists",
        ));
    }
    create_private_dir(&temporary)?;
    let creation_lock_path = temporary.join(crate::store_recovery::CREATION_LOCK_FILE);
    let creation_lock = acquire_creation_lock(&temporary, &creation_lock_path)?;
    let identity = StagingIdentity::capture(&temporary, &creation_lock)?;
    if let Err(error) = create_private_dir(&temporary.join("home")) {
        let _cleanup = identity.cleanup(&temporary);
        return Err(error);
    }
    Ok(ArtifactStaging {
        id,
        root,
        temporary,
        destination,
        creation_lock_path,
        identity,
        _creation_lock: creation_lock,
    })
}

pub(super) fn prepare_space_staging(store: &Store, destination: &SpaceName) -> Result<SpaceStaging> {
    let management = store.begin_mutation()?;
    let layout = management.layout();
    let destination_path = layout.space_path(destination);
    reject_space_destination_at(store, destination, &destination_path)?;
    let temporary = layout.temporary_path(destination)?;
    if entry_exists(&temporary)? {
        return Err(
            QuartersError::new(ErrorKind::CorruptState, "reserved template staging path already exists")
                .with_hint("run 'quarters doctor' and recover only validated stale state"),
        );
    }
    create_private_dir(&temporary)?;
    let creation_lock_path = temporary.join(crate::store_recovery::CREATION_LOCK_FILE);
    let creation_lock = acquire_creation_lock(&temporary, &creation_lock_path)?;
    let identity = StagingIdentity::capture(&temporary, &creation_lock)?;
    if let Err(error) = create_private_dir(&temporary.join("home")) {
        let _cleanup = identity.cleanup(&temporary);
        return Err(error);
    }
    Ok(SpaceStaging {
        destination: destination_path,
        temporary,
        creation_lock_path,
        identity,
        _creation_lock: creation_lock,
    })
}

pub(super) fn reject_space_destination(store: &Store, destination: &SpaceName) -> Result<()> {
    let path = store.layout()?.space_path(destination);
    reject_space_destination_at(store, destination, &path)
}

fn reject_space_destination_at(store: &Store, destination: &SpaceName, path: &Path) -> Result<()> {
    store.ensure_no_rename_target(destination)?;
    store.ensure_no_rollback_target(destination)?;
    if entry_exists(path)? {
        return Err(QuartersError::new(
            ErrorKind::AlreadyExists,
            format!("space '{destination}' already exists"),
        ));
    }
    Ok(())
}

fn fresh_template_space_manifest(
    template: &ArtifactManifest,
    name: SpaceName,
    default_shell: PathBuf,
) -> Result<SpaceManifest> {
    Ok(SpaceManifest {
        schema_version: STABLE_SCHEMA_VERSION,
        layout: Some(template.source_layout),
        space_id: Some(SpaceId::generate()?),
        name,
        created_unix_ms: epoch_millis()?,
        default_shell,
        authority_model: "host-account-state-profile".to_owned(),
    })
}

#[derive(Serialize)]
struct TemplateProvenance<'a> {
    schema_version: u32,
    operation: &'static str,
    artifact_id: &'a ArtifactId,
    template: &'a ArtifactName,
    created_unix_ms: u128,
    includes_sensitive_state: bool,
}

fn write_template_provenance(root: &Path, template: &Artifact) -> Result<()> {
    let provenance = TemplateProvenance {
        schema_version: 1,
        operation: "template-use",
        artifact_id: &template.manifest().artifact_id,
        template: &template.manifest().name,
        created_unix_ms: epoch_millis()?,
        includes_sensitive_state: true,
    };
    let mut bytes = serde_json::to_vec_pretty(&provenance).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not serialize template provenance").with_source(error)
    })?;
    bytes.push(b'\n');
    write_private_file(&root.join(".quarters-provenance.json"), &bytes)
}

fn template_use_report(
    template: &Artifact,
    destination: &SpaceName,
    mode: CloneMode,
    destination_id: Option<&SpaceId>,
) -> TemplateUseReport {
    TemplateUseReport {
        template: template.manifest().name.as_str().to_owned(),
        artifact_id: template.manifest().artifact_id.as_str().to_owned(),
        destination: destination.as_str().to_owned(),
        mode,
        destination_space_id: destination_id.map(|value| value.as_str().to_owned()),
        layout: template.manifest().source_layout,
        include_cache: template.manifest().include_cache,
        stored_counts: template.manifest().content_integrity.counts,
        embedded_absolute_paths: "copied without rewriting and may still select captured state".to_owned(),
        authority_boundary: "host account authority is unchanged; this is not containment".to_owned(),
    }
}

fn replace_artifact_manifest(root: &Path, manifest: &ArtifactManifest) -> Result<()> {
    let temporary = root.join(format!(".manifest-{}.tmp", manifest.artifact_id));
    if entry_exists(&temporary)? {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "reserved artifact manifest temporary file already exists",
        ));
    }
    let mut bytes = serde_json::to_vec_pretty(manifest).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not serialize renamed artifact manifest").with_source(error)
    })?;
    bytes.push(b'\n');
    write_private_file(&temporary, &bytes)?;
    fs::rename(&temporary, root.join(ARTIFACT_MANIFEST))
        .map_err(|error| QuartersError::io("replace artifact manifest", &temporary, error))?;
    sync_directory(root)
}

pub(super) fn write_artifact_manifest(root: &Path, manifest: &ArtifactManifest) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(manifest).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not serialize artifact manifest").with_source(error)
    })?;
    bytes.push(b'\n');
    write_private_file(&root.join(ARTIFACT_MANIFEST), &bytes)
}

pub(super) fn report_from_clone(
    kind: ArtifactKind,
    name: &ArtifactName,
    clone: &CloneReport,
    source_quiescence: SourceQuiescence,
    id: Option<&ArtifactId>,
    stored_counts: Option<super::ArtifactCounts>,
) -> ArtifactReport {
    ArtifactReport {
        kind,
        mode: clone.mode,
        source: clone.source.clone(),
        name: name.as_str().to_owned(),
        artifact_id: id.map(|value| value.as_str().to_owned()),
        include_cache: clone.policy.include_cache,
        includes_sensitive_state: true,
        examined_counts: clone.counts,
        exclusions: clone.exclusions,
        stored_counts,
        source_quiescence,
        limits: clone.limits,
        detached_processes: "unknown".to_owned(),
    }
}

pub(super) fn artifact_walk_control() -> WalkControl {
    WalkControl::for_artifact()
}

pub(super) fn artifact_root(store: &Store, kind: ArtifactKind) -> PathBuf {
    store.root.join(match kind {
        ArtifactKind::Template => ".templates",
        ArtifactKind::Snapshot => ".snapshots",
    })
}

fn artifact_not_found(kind: ArtifactKind, name: &ArtifactName) -> QuartersError {
    QuartersError::new(
        ErrorKind::NotFound,
        format!("{} '{}' does not exist", kind.as_str(), name),
    )
}

fn inspection_name(inspection: &ArtifactInspection) -> &str {
    match inspection {
        ArtifactInspection::Healthy { artifact, .. } => artifact.manifest().name.as_str(),
        ArtifactInspection::Unhealthy { id, .. } => id,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn snapshot_round_trip_verifies() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let store = Store::new(temporary.path().join("root"))?;
        store.create(SpaceName::parse("work")?, PathBuf::from("/bin/sh"))?;
        fs::write(store.open(&SpaceName::parse("work")?)?.home().join("state"), b"value")?;
        let report = store.create_artifact(
            ArtifactKind::Snapshot,
            &SpaceName::parse("work")?,
            ArtifactName::parse("before")?,
            true,
            ArtifactOrigin::User,
        )?;
        assert_eq!(report.mode, CloneMode::Execute);
        let artifact = store.verify_artifact(ArtifactKind::Snapshot, &ArtifactName::parse("before")?)?;
        assert_eq!(artifact.manifest().name.as_str(), "before");
        Ok(())
    }

    #[test]
    fn template_use_rename_and_remove_are_coherent() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let store = Store::new(temporary.path().join("root"))?;
        let source = SpaceName::parse("source")?;
        store.create(source.clone(), PathBuf::from("/bin/sh"))?;
        fs::write(store.open(&source)?.home().join("state"), b"portable")?;
        let template = ArtifactName::parse("starter")?;
        store.create_artifact(
            ArtifactKind::Template,
            &source,
            template.clone(),
            false,
            ArtifactOrigin::User,
        )?;
        let destination = SpaceName::parse("copy")?;
        let report = store.use_template(&template, &destination, None)?;
        assert_eq!(report.destination, "copy");
        assert_eq!(
            fs::read(store.open(&SpaceName::parse("copy")?)?.home().join("state"))?,
            b"portable"
        );
        let renamed = ArtifactName::parse("renamed")?;
        let mutation = store.rename_artifact(ArtifactKind::Template, &template, &renamed)?;
        assert_eq!(mutation.name.as_deref(), Some("renamed"));
        store.verify_artifact(ArtifactKind::Template, &renamed)?;
        store.remove_artifact(ArtifactKind::Template, &renamed)?;
        assert_eq!(
            store
                .open_artifact(ArtifactKind::Template, &renamed)
                .expect_err("removed")
                .kind(),
            ErrorKind::NotFound
        );
        Ok(())
    }
}
