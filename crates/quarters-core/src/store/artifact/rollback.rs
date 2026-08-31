//! Guarded three-state rollback transaction.

use super::catalog::SpaceStaging;
use super::model::{
    ArtifactId, ArtifactKind, ArtifactName, ArtifactOrigin, RollbackInventory, RollbackIssue, RollbackMode,
    RollbackObservation, RollbackRecoveryAction, RollbackReport, SourceIdentity,
};
use crate::store::create::{acquire_creation_lock, ensure_directory_skeleton, write_manifest};
use crate::store::lifecycle::{CloneMode, CloneReport, WalkControl, remove_tree_restoring_owner_access, walk_home};
use crate::store::scan::ScanBudget;
use crate::store_lock::{LifecycleLease, acquire_lifecycle_lease};
use crate::store_policy::validate_shell;
use crate::{ErrorKind, QuartersError, Result, Space, SpaceName, Store};
use fs4::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use crate::store::{
    create_private_dir, entry_exists, epoch_millis, open_private_lock, read_private_file, sync_directory,
    unique_suffix, validate_space_anchors, write_private_file,
};
use crate::store_policy::{validate_private_dir, validate_private_file};

const MARKER_SCHEMA_VERSION: u32 = 1;
const MAX_ROLLBACK_MARKERS: usize = 1_024;

/// Durable rollback transaction state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RollbackState {
    Prepared,
    Retired,
    Published,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RollbackMarker {
    schema_version: u32,
    transaction_id: ArtifactId,
    state: RollbackState,
    target: SpaceName,
    target_identity: SourceIdentity,
    staging_entry: String,
    retired_entry: String,
    snapshot_id: ArtifactId,
    recovery_snapshot_id: ArtifactId,
}

impl Store {
    /// Inspect actionable and ambiguous rollback state under one observation lock.
    ///
    /// # Errors
    ///
    /// Fails only when the bounded marker namespace itself cannot be read.
    pub fn rollback_inventory(&self) -> Result<RollbackInventory> {
        let Some(spaces) = self.existing_spaces_root()? else {
            return Ok(RollbackInventory::default());
        };
        let _observation = self.observation_guard()?;
        Self::rollback_inventory_unlocked(&spaces)
    }

    /// Validate a rollback and its automatic recovery capture without mutation.
    ///
    /// # Errors
    ///
    /// Fails for identity, platform, activity, integrity or resource-limit
    /// violations.
    pub fn rollback_plan(
        &self,
        target: &SpaceName,
        snapshot_name: &ArtifactName,
        recovery_name: &ArtifactName,
        recovery_includes_cache: bool,
    ) -> Result<RollbackReport> {
        self.ensure_no_rename_target(target)?;
        let snapshot = self.verify_artifact(ArtifactKind::Snapshot, snapshot_name)?;
        validate_snapshot_target(&snapshot, &self.open(target)?)?;
        require_recovery_name_available(self, recovery_name)?;
        let management = self.begin_mutation()?;
        let target_space = self.open(target)?;
        let activity = acquire_lifecycle_lease(&target_space, target.as_str())?;
        drop(management);
        let mut recovery_walk = CloneReport::new(
            target.as_str(),
            recovery_name.as_str(),
            CloneMode::Preview,
            target_space.layout(),
            recovery_includes_cache,
        );
        walk_home(
            &target_space.home(),
            None,
            &mut recovery_walk,
            &WalkControl::for_artifact(),
        )?;
        drop(activity);
        Ok(rollback_report(
            RollbackMode::Preview,
            &target_space,
            &snapshot,
            recovery_name,
            None,
            recovery_includes_cache,
        ))
    }

    /// Replace a target home from a verified snapshot after capturing recovery.
    ///
    /// # Errors
    ///
    /// Fails before replacement whenever recovery capture, identity validation,
    /// staging or a durable state transition cannot be completed.
    pub fn rollback_space(
        &self,
        target: &SpaceName,
        snapshot_name: &ArtifactName,
        recovery_name: &ArtifactName,
        recovery_includes_cache: bool,
    ) -> Result<RollbackReport> {
        self.ensure_layout()?;
        let snapshot = self.verify_artifact(ArtifactKind::Snapshot, snapshot_name)?;
        let transaction_id = ArtifactId::generate()?;
        let (target_space, activity, staging) =
            self.prepare_rollback(target, &snapshot, recovery_name, &transaction_id)?;
        let recovery = self.create_artifact_with_held_source(
            ArtifactKind::Snapshot,
            &target_space,
            recovery_name.clone(),
            recovery_includes_cache,
            ArtifactOrigin::AutomaticRollbackRecovery,
        )?;
        let recovery_id = recovery
            .artifact_id
            .as_deref()
            .ok_or_else(|| QuartersError::new(ErrorKind::System, "recovery snapshot has no published ID"))
            .and_then(|value| ArtifactId::parse(value.to_owned()))?;
        let result = self.execute_rollback(
            &target_space,
            activity,
            &snapshot,
            &staging,
            &transaction_id,
            &recovery_id,
        );
        if let Err(error) = &result
            && !rollback_marker_path(self, &transaction_id)?.exists()
            && let Err(cleanup) = staging.identity.cleanup(&staging.temporary)
        {
            return Err(QuartersError::new(
                error.kind(),
                format!("rollback failed and staging cleanup also failed: {}", error.message()),
            )
            .with_source(cleanup));
        }
        result?;
        Ok(rollback_report(
            RollbackMode::Execute,
            &target_space,
            &snapshot,
            recovery_name,
            Some(&recovery_id),
            recovery_includes_cache,
        ))
    }

    /// Inspect interrupted rollback markers and their deterministic action.
    ///
    /// # Errors
    ///
    /// Fails only when the bounded marker namespace cannot be read safely.
    pub fn rollback_observations(&self) -> Result<Vec<RollbackObservation>> {
        self.rollback_inventory().map(|inventory| inventory.observations)
    }

    /// Inspect retained rollback markers that require manual reconciliation.
    ///
    /// # Errors
    ///
    /// Fails only when the bounded marker namespace itself cannot be read.
    pub fn rollback_issues(&self) -> Result<Vec<RollbackIssue>> {
        self.rollback_inventory().map(|inventory| inventory.issues)
    }

    /// Find a durable rollback marker for one validated space name.
    ///
    /// # Errors
    ///
    /// Fails when this target has ambiguous state or marker inspection fails.
    pub fn rollback_observation_for(&self, target: &SpaceName) -> Result<Option<RollbackObservation>> {
        let Some(spaces) = self.existing_spaces_root()? else {
            return Ok(None);
        };
        let _observation = self.observation_guard()?;
        Self::rollback_observation_for_unlocked(&spaces, target)
    }

    /// Resolve every validated interrupted rollback and reclaim retired trees.
    ///
    /// # Errors
    ///
    /// Reconciles actionable transactions and preserves every ambiguous tree.
    pub fn recover_rollbacks(&self) -> Result<Vec<RollbackObservation>> {
        self.ensure_layout()?;
        let (observations, reclaiming, trash) = {
            let management = self.begin_mutation()?;
            let spaces = management.layout().spaces_root().to_path_buf();
            let trash = management.layout().trash_root().to_path_buf();
            reclaim_marker_temporaries(&spaces)?;
            let plans = load_recovery_inventory(&spaces, None)?.plans;
            let mut reclaiming = Vec::new();
            let mut observations = Vec::new();
            for plan in plans {
                apply_recovery_plan(self, &spaces, &trash, &plan, &mut reclaiming)?;
                observations.push(plan.observation);
            }
            reclaim_orphan_staging(&spaces, &trash, &mut reclaiming)?;
            sync_directory(&spaces)?;
            sync_directory(&trash)?;
            (observations, reclaiming, trash)
        };
        for path in reclaiming {
            remove_tree_restoring_owner_access(&path)?;
        }
        sync_directory(&trash)?;
        Ok(observations)
    }

    fn prepare_rollback(
        &self,
        target: &SpaceName,
        snapshot: &super::Artifact,
        recovery_name: &ArtifactName,
        transaction_id: &ArtifactId,
    ) -> Result<(Space, LifecycleLease, SpaceStaging)> {
        self.ensure_no_rename_target(target)?;
        let management = self.begin_mutation()?;
        let target_space = self.open(target)?;
        validate_snapshot_target(snapshot, &target_space)?;
        require_recovery_name_available(self, recovery_name)?;
        let activity = acquire_lifecycle_lease(&target_space, target.as_str())?;
        let staging = prepare_rollback_staging(management.layout(), transaction_id)?;
        drop(management);
        Ok((target_space, activity, staging))
    }

    pub(crate) fn ensure_no_rollback_target(&self, target: &SpaceName) -> Result<()> {
        let Some(spaces) = self.existing_spaces_root()? else {
            return Ok(());
        };
        if Self::rollback_observation_for_unlocked(&spaces, target)?.is_some() {
            return Err(rollback_in_progress(target));
        }
        Ok(())
    }

    fn rollback_observation_for_unlocked(spaces: &Path, target: &SpaceName) -> Result<Option<RollbackObservation>> {
        let inventory = load_recovery_inventory(spaces, Some(target))?;
        if let Some(issue) = inventory
            .issues
            .into_iter()
            .find(|issue| issue.view.target.as_ref() == Some(target))
        {
            return Err(issue.error);
        }
        let mut matching = inventory
            .plans
            .into_iter()
            .filter(|plan| plan.observation.target == *target);
        let found = matching.next().map(|plan| plan.observation);
        if matching.next().is_some() {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                format!("multiple rollback markers target space '{target}'"),
            ));
        }
        Ok(found)
    }

    pub(crate) fn rollback_inventory_unlocked(spaces: &Path) -> Result<RollbackInventory> {
        load_recovery_inventory(spaces, None).map(|inventory| RollbackInventory {
            observations: inventory.plans.into_iter().map(|plan| plan.observation).collect(),
            issues: inventory.issues.into_iter().map(|issue| issue.view).collect(),
        })
    }

    fn execute_rollback(
        &self,
        target: &Space,
        activity: LifecycleLease,
        snapshot: &super::Artifact,
        staging: &SpaceStaging,
        transaction_id: &ArtifactId,
        recovery_id: &ArtifactId,
    ) -> Result<()> {
        let mut copy = CloneReport::new(
            snapshot.manifest().name.as_str(),
            target.manifest().name.as_str(),
            CloneMode::Execute,
            target.layout(),
            true,
        );
        walk_home(
            &snapshot.home(),
            Some(&staging.temporary.join("home")),
            &mut copy,
            &WalkControl::default(),
        )?;
        ensure_directory_skeleton(&staging.temporary.join("home"), target.layout())?;
        write_private_file(&staging.temporary.join(".active"), b"")?;
        write_manifest(&staging.temporary, target.manifest())?;
        write_rollback_provenance(&staging.temporary, snapshot, recovery_id)?;
        sync_directory(&staging.temporary.join("home"))?;
        sync_directory(&staging.temporary)?;
        validate_space_anchors(&staging.temporary)?;
        self.verify_artifact(ArtifactKind::Snapshot, &snapshot.manifest().name)?;
        self.publish_rollback(target, activity, snapshot, staging, transaction_id, recovery_id)
    }

    fn publish_rollback(
        &self,
        target: &Space,
        activity: LifecycleLease,
        snapshot: &super::Artifact,
        staging: &SpaceStaging,
        transaction_id: &ArtifactId,
        recovery_id: &ArtifactId,
    ) -> Result<()> {
        let management = self.begin_mutation()?;
        let spaces = management.layout().spaces_root().to_path_buf();
        let marker_path = rollback_marker_path_from_text(&spaces, transaction_id.as_str());
        let retired = spaces.join(format!(".rolled-back-{transaction_id}"));
        let mut marker = RollbackMarker {
            schema_version: MARKER_SCHEMA_VERSION,
            transaction_id: transaction_id.clone(),
            state: RollbackState::Prepared,
            target: target.manifest().name.clone(),
            target_identity: SourceIdentity::for_space(target),
            staging_entry: entry_name(&staging.temporary)?,
            retired_entry: entry_name(&retired)?,
            snapshot_id: snapshot.manifest().artifact_id.clone(),
            recovery_snapshot_id: recovery_id.clone(),
        };
        revalidate_publication(self, target, snapshot, staging)?;
        write_marker_new(&marker_path, &marker)?;
        sync_directory(&spaces)?;
        if read_marker(&marker_path)? != marker {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "rollback marker changed after publication",
            ));
        }
        fs::rename(target.root(), &retired)
            .map_err(|error| QuartersError::io("retire rollback target", target.root(), error))?;
        sync_directory(&spaces)?;
        marker.state = RollbackState::Retired;
        replace_marker(&marker_path, &marker)?;
        staging
            .identity
            .verify(&staging.temporary, &staging.creation_lock_path)?;
        fs::remove_file(&staging.creation_lock_path)
            .map_err(|error| QuartersError::io("remove rollback staging lock", &staging.creation_lock_path, error))?;
        sync_directory(&staging.temporary)?;
        validate_space_anchors(&staging.temporary)?;
        fs::rename(&staging.temporary, target.root())
            .map_err(|error| QuartersError::io("publish rollback target", &staging.temporary, error))?;
        sync_directory(&spaces)?;
        marker.state = RollbackState::Published;
        replace_marker(&marker_path, &marker)?;
        let trash = management.layout().trash_root().to_path_buf();
        create_private_dir(&trash)?;
        let reclaiming = trash.join(format!(".reclaiming-{}", unique_suffix()?));
        fs::rename(&retired, &reclaiming)
            .map_err(|error| QuartersError::io("retire replaced rollback state", &retired, error))?;
        sync_directory(&spaces)?;
        sync_directory(&trash)?;
        fs::remove_file(&marker_path)
            .map_err(|error| QuartersError::io("remove completed rollback marker", &marker_path, error))?;
        let cleanup_hint = format!(
            "rollback of '{}' completed and its recovery snapshot was published; run 'quarters doctor' and recover validated stale state",
            target.manifest().name
        );
        sync_directory(&spaces).map_err(|error| post_commit_cleanup_error(error, &cleanup_hint))?;
        drop(activity);
        drop(management);
        remove_tree_restoring_owner_access(&reclaiming)
            .map_err(|error| post_commit_cleanup_error(error, &cleanup_hint))?;
        sync_directory(&trash).map_err(|error| post_commit_cleanup_error(error, &cleanup_hint))
    }
}

fn post_commit_cleanup_error(error: QuartersError, hint: &str) -> QuartersError {
    QuartersError::new(
        error.kind(),
        format!(
            "rollback completed, but retired-state cleanup failed: {}",
            error.message()
        ),
    )
    .with_hint(hint)
    .with_source(error)
}

pub(crate) fn rollback_in_progress(target: &SpaceName) -> QuartersError {
    QuartersError::new(
        ErrorKind::SpaceActive,
        format!("space '{target}' has a rollback in progress"),
    )
    .with_hint("run 'quarters doctor' to inspect the durable rollback action, then recover confirmed stale state")
}

pub(crate) fn rollback_retired_entry_is_actionable(spaces: &Path, name: &str) -> bool {
    let Some(value) = name.strip_prefix(".rolled-back-") else {
        return false;
    };
    let Ok(id) = ArtifactId::parse(value.to_owned()) else {
        return false;
    };
    let marker_path = spaces.join(format!(".rollback-{id}.json"));
    let Ok(marker) = read_marker(&marker_path) else {
        return false;
    };
    validate_marker_components(&marker, &id).is_ok() && recovery_action(spaces, &marker_path, &marker).is_ok()
}

struct RecoveryPlan {
    marker_path: PathBuf,
    marker: RollbackMarker,
    observation: RollbackObservation,
}

struct RecoveryIssue {
    view: RollbackIssue,
    error: QuartersError,
}

struct RecoveryInventory {
    plans: Vec<RecoveryPlan>,
    issues: Vec<RecoveryIssue>,
}

fn reclaim_marker_temporaries(spaces: &Path) -> Result<()> {
    let entries =
        fs::read_dir(spaces).map_err(|error| QuartersError::io("read rollback marker temporaries", spaces, error))?;
    let mut removed = 0_usize;
    let mut scan = ScanBudget::new("the spaces directory while inspecting rollback temporaries");
    for entry in entries {
        let entry = entry.map_err(|error| QuartersError::io("read rollback temporary entry", spaces, error))?;
        scan.observe()?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(value) = name
            .strip_prefix(".rollback-")
            .and_then(|value| value.strip_suffix(".tmp"))
        else {
            continue;
        };
        if ArtifactId::parse(value.to_owned()).is_err() {
            continue;
        }
        removed = removed.saturating_add(1);
        reject_excess_rollback_entries(removed, "marker temporaries")?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| QuartersError::io("inspect rollback marker temporary file", &entry.path(), error))?;
        validate_private_file(&entry.path(), &metadata)?;
        fs::remove_file(entry.path())
            .map_err(|error| QuartersError::io("remove rollback marker temporary file", &entry.path(), error))?;
    }
    if removed > 0 {
        sync_directory(spaces)?;
    }
    Ok(())
}

fn load_recovery_inventory(spaces: &Path, target: Option<&SpaceName>) -> Result<RecoveryInventory> {
    let entries = fs::read_dir(spaces).map_err(|error| QuartersError::io("read rollback markers", spaces, error))?;
    let mut plans = Vec::new();
    let mut issues = Vec::new();
    let mut scan = ScanBudget::new("the spaces directory while inspecting rollback markers");
    let mut markers = 0_usize;
    for entry in entries {
        let entry = entry.map_err(|error| QuartersError::io("read rollback marker entry", spaces, error))?;
        scan.observe()?;
        let Some(id) = marker_id_from_name(&entry.file_name()) else {
            continue;
        };
        markers = markers.saturating_add(1);
        reject_excess_rollback_entries(markers, "markers")?;
        let marker = match read_marker(&entry.path()) {
            Ok(marker) => marker,
            Err(error) => {
                issues.push(recovery_issue(&entry.path(), None, error)?);
                continue;
            }
        };
        if let Err(error) = validate_marker_components(&marker, &id) {
            issues.push(recovery_issue(&entry.path(), Some(marker.target.clone()), error)?);
            continue;
        }
        if target.is_some_and(|expected| expected != &marker.target) {
            continue;
        }
        let action = match recovery_action(spaces, &entry.path(), &marker) {
            Ok(action) => action,
            Err(error) => {
                issues.push(recovery_issue(&entry.path(), Some(marker.target.clone()), error)?);
                continue;
            }
        };
        plans.push(RecoveryPlan {
            marker_path: entry.path(),
            observation: RollbackObservation {
                transaction_id: marker.transaction_id.clone(),
                target: marker.target.clone(),
                state: marker_state_text(marker.state).to_owned(),
                action,
            },
            marker,
        });
    }
    plans.sort_by(|left, right| left.observation.target.cmp(&right.observation.target));
    reject_duplicate_targets(&mut plans, &mut issues)?;
    issues.sort_by(|left, right| left.view.marker.cmp(&right.view.marker));
    Ok(RecoveryInventory { plans, issues })
}

fn reject_duplicate_targets(plans: &mut Vec<RecoveryPlan>, issues: &mut Vec<RecoveryIssue>) -> Result<()> {
    let mut duplicate_targets = std::collections::BTreeSet::new();
    for adjacent in plans.windows(2) {
        if adjacent[0].observation.target == adjacent[1].observation.target {
            duplicate_targets.insert(adjacent[0].observation.target.clone());
        }
    }
    if duplicate_targets.is_empty() {
        return Ok(());
    }
    let mut retained = Vec::with_capacity(plans.len());
    for plan in plans.drain(..) {
        if duplicate_targets.contains(&plan.observation.target) {
            let error = QuartersError::new(
                ErrorKind::CorruptState,
                format!("multiple rollback markers target space '{}'", plan.observation.target),
            )
            .with_hint("preserve every rollback path and reconcile the duplicate transactions manually");
            issues.push(recovery_issue(
                &plan.marker_path,
                Some(plan.observation.target.clone()),
                error,
            )?);
        } else {
            retained.push(plan);
        }
    }
    *plans = retained;
    Ok(())
}

fn recovery_issue(path: &Path, target: Option<SpaceName>, error: QuartersError) -> Result<RecoveryIssue> {
    let marker = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| QuartersError::new(ErrorKind::System, "generated rollback marker has no UTF-8 name"))?
        .to_owned();
    let view = RollbackIssue {
        marker,
        target,
        code: error.kind().as_str().to_owned(),
        message: crate::escape_untrusted_text_bounded(error.message(), 512),
        hint: error.hint().map(|hint| crate::escape_untrusted_text_bounded(hint, 512)),
    };
    Ok(RecoveryIssue { view, error })
}

fn marker_id_from_name(name: &std::ffi::OsStr) -> Option<ArtifactId> {
    let name = name.to_str()?;
    let value = name
        .strip_prefix(".rollback-")
        .and_then(|value| value.strip_suffix(".json"))?;
    ArtifactId::parse(value.to_owned()).ok()
}

fn validate_marker_components(marker: &RollbackMarker, path_id: &ArtifactId) -> Result<()> {
    let expected_staging = format!(".rollback-staging-{}", marker.transaction_id);
    let expected_retired = format!(".rolled-back-{}", marker.transaction_id);
    if &marker.transaction_id == path_id
        && marker.staging_entry == expected_staging
        && marker.retired_entry == expected_retired
    {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "rollback marker path components do not match its transaction ID",
    ))
}

fn recovery_action(spaces: &Path, marker_path: &Path, marker: &RollbackMarker) -> Result<RollbackRecoveryAction> {
    let target = spaces.join(marker.target.as_str());
    let staging = spaces.join(&marker.staging_entry);
    let retired = spaces.join(&marker.retired_entry);
    let tuple = (entry_exists(&target)?, entry_exists(&staging)?, entry_exists(&retired)?);
    let action = match (marker.state, tuple) {
        (RollbackState::Prepared, (true, true, false)) => RollbackRecoveryAction::Abort,
        (RollbackState::Prepared | RollbackState::Retired, (false, true, true)) => RollbackRecoveryAction::RestoreOld,
        (RollbackState::Retired | RollbackState::Published, (true, false, true))
        | (RollbackState::Published, (true, false, false)) => RollbackRecoveryAction::CompleteNew,
        _ => {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                format!(
                    "rollback '{}' has an ambiguous filesystem tuple: target={}, staging={}, retired={}",
                    marker.target, tuple.0, tuple.1, tuple.2
                ),
            )
            .with_hint(format!(
                "preserve every rollback path; inspect marker {} and entries '{}', '{}' and '{}'; Quarters will not guess",
                marker_path.display(), marker.target, marker.staging_entry, marker.retired_entry
            )));
        }
    };
    let identity_path = match action {
        RollbackRecoveryAction::RestoreOld => &retired,
        RollbackRecoveryAction::Abort | RollbackRecoveryAction::CompleteNew => &target,
    };
    let space = match action {
        RollbackRecoveryAction::RestoreOld => Store::open_relocated_path(identity_path.clone(), &marker.target)?,
        RollbackRecoveryAction::Abort | RollbackRecoveryAction::CompleteNew => Store::open_path(identity_path.clone())?,
    };
    if !marker.target_identity.matches(&space) {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "rollback target identity conflicts with its marker",
        ));
    }
    Ok(action)
}

fn apply_recovery_plan(
    _store: &Store,
    spaces: &Path,
    trash: &Path,
    plan: &RecoveryPlan,
    reclaiming: &mut Vec<PathBuf>,
) -> Result<()> {
    let target = spaces.join(plan.marker.target.as_str());
    let staging = spaces.join(&plan.marker.staging_entry);
    let retired = spaces.join(&plan.marker.retired_entry);
    match plan.observation.action {
        RollbackRecoveryAction::Abort => recover_abort(spaces, trash, plan, &staging, reclaiming),
        RollbackRecoveryAction::RestoreOld => {
            recover_restore_old(spaces, trash, plan, &target, &staging, &retired, reclaiming)
        }
        RollbackRecoveryAction::CompleteNew => recover_complete_new(spaces, trash, plan, &retired, reclaiming),
    }
}

fn recover_abort(
    spaces: &Path,
    trash: &Path,
    plan: &RecoveryPlan,
    staging: &Path,
    reclaiming: &mut Vec<PathBuf>,
) -> Result<()> {
    remove_marker_durable(&plan.marker_path, spaces)?;
    retire_recovery_path(staging, trash, reclaiming)
}

fn recover_restore_old(
    spaces: &Path,
    trash: &Path,
    plan: &RecoveryPlan,
    target: &Path,
    staging: &Path,
    retired: &Path,
    reclaiming: &mut Vec<PathBuf>,
) -> Result<()> {
    transition_marker(plan, RollbackState::Prepared)?;
    fs::rename(retired, target)
        .map_err(|error| QuartersError::io("restore retired rollback target", retired, error))?;
    sync_directory(spaces)?;
    remove_marker_durable(&plan.marker_path, spaces)?;
    retire_recovery_path(staging, trash, reclaiming)
}

fn recover_complete_new(
    spaces: &Path,
    trash: &Path,
    plan: &RecoveryPlan,
    retired: &Path,
    reclaiming: &mut Vec<PathBuf>,
) -> Result<()> {
    transition_marker(plan, RollbackState::Published)?;
    if entry_exists(retired)? {
        retire_recovery_path(retired, trash, reclaiming)?;
        sync_directory(spaces)?;
        sync_directory(trash)?;
    }
    remove_marker_durable(&plan.marker_path, spaces)
}

fn transition_marker(plan: &RecoveryPlan, state: RollbackState) -> Result<()> {
    if plan.marker.state == state {
        return Ok(());
    }
    let mut marker = plan.marker.clone();
    marker.state = state;
    replace_marker(&plan.marker_path, &marker)
}

fn remove_marker_durable(marker: &Path, spaces: &Path) -> Result<()> {
    fs::remove_file(marker).map_err(|error| QuartersError::io("remove recovered rollback marker", marker, error))?;
    sync_directory(spaces)
}

fn retire_recovery_path(path: &Path, trash: &Path, reclaiming: &mut Vec<PathBuf>) -> Result<()> {
    let destination = trash.join(format!(".reclaiming-{}", unique_suffix()?));
    fs::rename(path, &destination).map_err(|error| QuartersError::io("retire rollback recovery path", path, error))?;
    reclaiming.push(destination);
    Ok(())
}

fn reclaim_orphan_staging(spaces: &Path, trash: &Path, reclaiming: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(spaces).map_err(|error| QuartersError::io("read rollback staging", spaces, error))?;
    let mut scan = ScanBudget::new("the spaces directory while inspecting rollback staging");
    let mut staging_count = 0_usize;
    for entry in entries {
        let entry = entry.map_err(|error| QuartersError::io("read rollback staging entry", spaces, error))?;
        scan.observe()?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(id) = name.strip_prefix(".rollback-staging-") else {
            continue;
        };
        if ArtifactId::parse(id.to_owned()).is_err() {
            continue;
        }
        staging_count = staging_count.saturating_add(1);
        reject_excess_rollback_entries(staging_count, "staging entries")?;
        if rollback_marker_path_from_text(spaces, id).exists() {
            continue;
        }
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| QuartersError::io("inspect rollback staging", &path, error))?;
        validate_private_dir(&path, &metadata)?;
        let lock_path = path.join(crate::store_recovery::CREATION_LOCK_FILE);
        let lock = match fs::symlink_metadata(&lock_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Ok(_) => Some(open_private_lock(&lock_path)?),
            Err(error) => return Err(QuartersError::io("inspect rollback staging lock", &lock_path, error)),
        };
        if let Some(lock) = &lock {
            match <File as FileExt>::try_lock(lock) {
                Ok(()) => {}
                Err(fs4::TryLockError::WouldBlock) => continue,
                Err(fs4::TryLockError::Error(error)) => {
                    return Err(QuartersError::io(
                        "lock rollback staging for recovery",
                        &lock_path,
                        error,
                    ));
                }
            }
        }
        retire_recovery_path(&path, trash, reclaiming)?;
    }
    Ok(())
}

fn reject_excess_rollback_entries(count: usize, family: &str) -> Result<()> {
    if count <= MAX_ROLLBACK_MARKERS {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::ResourceLimit,
        format!("the store contains more than {MAX_ROLLBACK_MARKERS} rollback {family}"),
    )
    .with_hint("inspect the protected spaces directory before attempting rollback recovery"))
}

fn rollback_marker_path_from_text(spaces: &Path, id: &str) -> PathBuf {
    spaces.join(format!(".rollback-{id}.json"))
}

const fn marker_state_text(state: RollbackState) -> &'static str {
    match state {
        RollbackState::Prepared => "prepared",
        RollbackState::Retired => "retired",
        RollbackState::Published => "published",
    }
}

fn prepare_rollback_staging(layout: &crate::store::StoreLayout, id: &ArtifactId) -> Result<SpaceStaging> {
    let spaces = layout.spaces_root().to_path_buf();
    let temporary = spaces.join(format!(".rollback-staging-{id}"));
    let destination = temporary.clone();
    if entry_exists(&temporary)? {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "rollback staging path already exists",
        ));
    }
    create_private_dir(&temporary)?;
    let lock_path = temporary.join(crate::store_recovery::CREATION_LOCK_FILE);
    let lock = acquire_creation_lock(&temporary, &lock_path)?;
    let identity = crate::store::lifecycle::StagingIdentity::capture(&temporary, &lock)?;
    if let Err(error) = create_private_dir(&temporary.join("home")) {
        let _cleanup = identity.cleanup(&temporary);
        return Err(error);
    }
    Ok(SpaceStaging {
        temporary,
        destination,
        creation_lock_path: lock_path,
        identity,
        _creation_lock: lock,
    })
}

fn validate_snapshot_target(snapshot: &super::Artifact, target: &Space) -> Result<()> {
    if snapshot.manifest().source_platform != crate::platform::capabilities().platform {
        return Err(QuartersError::new(
            ErrorKind::Unsupported,
            "snapshot platform differs from the current host",
        )
        .with_hint("use a same-platform snapshot; cross-platform template use is the portable adaptation path"));
    }
    if snapshot
        .manifest()
        .source_identity
        .as_ref()
        .is_none_or(|identity| !identity.matches(target))
    {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            format!(
                "snapshot '{}' belongs to a different Quarter identity",
                snapshot.manifest().name
            ),
        ));
    }
    validate_shell(&target.manifest().default_shell)
}

fn require_recovery_name_available(store: &Store, name: &ArtifactName) -> Result<()> {
    store
        .require_artifact_name_available(ArtifactKind::Snapshot, name)
        .map_err(|error| {
            if error.kind() == ErrorKind::AlreadyExists {
                error.with_hint(
                    "a prior attempt may have preserved this recovery snapshot; inspect it, then choose a new name or remove it explicitly",
                )
            } else {
                error
            }
        })
}

fn revalidate_publication(
    store: &Store,
    target: &Space,
    snapshot: &super::Artifact,
    staging: &SpaceStaging,
) -> Result<()> {
    let current = store.open(&target.manifest().name)?;
    if current.manifest() != target.manifest() {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "rollback target identity changed",
        ));
    }
    let current_snapshot = store.open_artifact(ArtifactKind::Snapshot, &snapshot.manifest().name)?;
    if current_snapshot.manifest() != snapshot.manifest() {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "rollback snapshot identity changed",
        ));
    }
    validate_space_anchors(&staging.temporary)
}

#[derive(Serialize)]
struct RollbackProvenance<'a> {
    schema_version: u32,
    operation: &'static str,
    snapshot_id: &'a ArtifactId,
    recovery_snapshot_id: &'a ArtifactId,
    created_unix_ms: u128,
    includes_sensitive_state: bool,
}

fn write_rollback_provenance(root: &Path, snapshot: &super::Artifact, recovery_id: &ArtifactId) -> Result<()> {
    let provenance = RollbackProvenance {
        schema_version: 1,
        operation: "rollback",
        snapshot_id: &snapshot.manifest().artifact_id,
        recovery_snapshot_id: recovery_id,
        created_unix_ms: epoch_millis()?,
        includes_sensitive_state: true,
    };
    let mut bytes = serde_json::to_vec_pretty(&provenance).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not serialize rollback provenance").with_source(error)
    })?;
    bytes.push(b'\n');
    write_private_file(&root.join(".quarters-provenance.json"), &bytes)
}

fn write_marker_new(path: &Path, marker: &RollbackMarker) -> Result<()> {
    if entry_exists(path)? {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "rollback marker already exists before publication",
        ));
    }
    replace_marker(path, marker)
}

fn replace_marker(path: &Path, marker: &RollbackMarker) -> Result<()> {
    let temporary = path.with_extension("tmp");
    if entry_exists(&temporary)? {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "rollback marker temporary file exists",
        ));
    }
    write_private_file(&temporary, &marker_bytes(marker)?)?;
    fs::rename(&temporary, path).map_err(|error| QuartersError::io("replace rollback marker", &temporary, error))?;
    sync_directory(
        path.parent()
            .ok_or_else(|| QuartersError::new(ErrorKind::System, "rollback marker has no parent"))?,
    )
}

fn marker_bytes(marker: &RollbackMarker) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(marker).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not serialize rollback marker").with_source(error)
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn read_marker(path: &Path) -> Result<RollbackMarker> {
    let bytes = read_private_file(path)?;
    let marker: RollbackMarker = serde_json::from_slice(&bytes).map_err(|error| {
        QuartersError::new(ErrorKind::CorruptState, "rollback marker is invalid").with_source(error)
    })?;
    if marker.schema_version != MARKER_SCHEMA_VERSION {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "unsupported rollback marker schema",
        ));
    }
    Ok(marker)
}

pub(crate) fn rollback_marker_path(store: &Store, id: &ArtifactId) -> Result<PathBuf> {
    Ok(store.layout()?.spaces_root().join(format!(".rollback-{id}.json")))
}

fn entry_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(str::to_owned)
        .ok_or_else(|| QuartersError::new(ErrorKind::System, "generated rollback path has no UTF-8 entry name"))
}

fn rollback_report(
    mode: RollbackMode,
    target: &Space,
    snapshot: &super::Artifact,
    recovery_name: &ArtifactName,
    recovery_id: Option<&ArtifactId>,
    recovery_includes_cache: bool,
) -> RollbackReport {
    RollbackReport {
        mode,
        target: target.manifest().name.as_str().to_owned(),
        snapshot: snapshot.manifest().name.as_str().to_owned(),
        snapshot_id: snapshot.manifest().artifact_id.as_str().to_owned(),
        recovery_name: recovery_name.as_str().to_owned(),
        recovery_snapshot_id: recovery_id.map(|value| value.as_str().to_owned()),
        recovery_includes_cache,
        target_space_id: target.id().map(|value| value.as_str().to_owned()),
        restored_counts: snapshot.manifest().content_integrity.counts,
        detached_processes: "unknown".to_owned(),
        publication_model: "old, new, or marked rollback_in_progress".to_owned(),
        authority_boundary: "host account authority is unchanged; this is not containment".to_owned(),
    }
}

#[cfg(test)]
mod tests;
