//! Bounded inspection and cleanup of reserved recovery directories.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use serde::Serialize;

use fs4::FileExt;

use crate::store::artifact::rollback_retired_entry_is_actionable;
use crate::store::lifecycle::remove_tree_restoring_owner_access;
use crate::store::scan::ScanBudget;
use crate::store::{StoreLayout, entry_exists, open_private_lock, sync_directory, unique_suffix};
use crate::store_policy::{validate_private_dir, validate_private_file, validate_store_root};
use crate::{
    ArtifactId, ArtifactInspection, ArtifactKind, ErrorKind, QuartersError, Result, RollbackIssue, RollbackObservation,
    SourceStatus, Store,
};

const CREATING_PREFIX: &[u8] = b".creating-";
const MAX_RECOVERY_ENTRIES: usize = 1_024;
const RECLAIMING_PREFIX: &[u8] = b".reclaiming-";
const RETIRED_PREFIX: &[u8] = b".retired-";
pub(crate) const CREATION_LOCK_FILE: &str = ".creating.lock";

/// Counts of reserved internal directories awaiting safe cleanup.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RecoverySummary {
    /// Creation operations currently holding their private working lock.
    pub active_creations: usize,
    /// Unpublished space skeletons left by an interrupted creation.
    pub unfinished_creations: usize,
    /// Retired space directories left by an interrupted deletion.
    pub retired_entries: usize,
    /// Interrupted rollback transactions with deterministic recovery actions.
    pub rollback_transactions: usize,
    /// Interrupted rename transactions awaiting deterministic recovery.
    pub rename_transactions: usize,
    /// Malformed rename markers retained for manual reconciliation.
    pub rename_issues: usize,
    /// Exact target, marker state and action shown before confirmed recovery.
    pub rollbacks: Vec<RollbackObservation>,
    /// Retained marker failures that require manual reconciliation.
    pub rollback_issues: Vec<RollbackIssue>,
    /// Artifact creations whose private creation lock is still held.
    pub active_artifact_creations: usize,
    /// Interrupted artifact creations safe to reclaim.
    pub unfinished_artifact_creations: usize,
    /// Interrupted artifact deletions safe to finish.
    pub reclaiming_artifacts: usize,
    /// Interrupted manifest replacements safe to discard.
    pub artifact_manifest_temps: usize,
    /// Interrupted cooperative-freeze marker publications safe to discard.
    pub freeze_marker_temps: usize,
    /// Published artifacts whose exact source generation no longer exists.
    pub orphaned_artifacts: usize,
    /// Aggregate canonical bytes stored by templates.
    pub template_logical_bytes: u64,
    /// Aggregate canonical bytes stored by snapshots.
    pub snapshot_logical_bytes: u64,
    /// Hidden entries outside the recovery grammar; never removed.
    pub unknown_entries_at_least: usize,
}

impl RecoverySummary {
    fn apply_artifacts(&mut self, state: &ArtifactRecoveryState) {
        self.active_artifact_creations = state.active_creations;
        self.unfinished_artifact_creations = state.unfinished_creations;
        self.reclaiming_artifacts = state.reclaiming;
        self.artifact_manifest_temps = state.manifest_temps;
        self.orphaned_artifacts = state.orphaned;
        self.template_logical_bytes = state.template_bytes;
        self.snapshot_logical_bytes = state.snapshot_bytes;
        self.unknown_entries_at_least = self.unknown_entries_at_least.saturating_add(state.unknown_entries);
    }
}

#[derive(Default)]
struct ArtifactRecoveryState {
    active_creations: usize,
    unfinished_creations: usize,
    reclaiming: usize,
    manifest_temps: usize,
    orphaned: usize,
    template_bytes: u64,
    snapshot_bytes: u64,
    unknown_entries: usize,
}

struct CreationCandidate {
    path: std::path::PathBuf,
    _lock: Option<File>,
}

struct ArtifactCandidates {
    active: usize,
    stale: Vec<CreationCandidate>,
    reclaiming: Vec<std::path::PathBuf>,
    manifest_temps: Vec<std::path::PathBuf>,
    unknown: usize,
}

impl Store {
    /// Inspect abandoned internal creation and retirement state.
    ///
    /// # Errors
    ///
    /// Returns an error when the store or its bounded observation lock cannot
    /// be inspected safely.
    pub fn recovery_summary(&self) -> Result<RecoverySummary> {
        let root_metadata = match fs::symlink_metadata(&self.root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RecoverySummary::default());
            }
            Err(error) => return Err(QuartersError::io("inspect Quarters root", &self.root, error)),
        };
        validate_store_root(&self.root, &root_metadata)?;
        let layout = self.layout()?;
        let spaces_present = entry_exists(layout.spaces_root())?;
        let trash_present = entry_exists(layout.trash_root())?;
        if !spaces_present && !trash_present {
            return Ok(RecoverySummary::default());
        }
        validate_layout(&self.root, &layout)?;
        let _observation = self.observation_guard()?;
        let rollback_inventory = Self::rollback_inventory_unlocked(layout.spaces_root())?;
        let rename_transactions = self.rename_recovery_count()?;
        let rename_issues = self.rename_recovery_issue_count()?;
        let artifacts = inspect_artifact_state(self)?;
        inspect(
            &self.root,
            &layout,
            rollback_inventory.observations,
            rollback_inventory.issues,
            rename_transactions,
            rename_issues,
            &artifacts,
        )
    }

    /// Remove abandoned internal creation and retirement state.
    ///
    /// Active creation and removal operations use the same management lock or
    /// a private per-creation lock, so active working paths are never removed.
    ///
    /// # Errors
    ///
    /// Returns an error before deletion when an internal entry is not a
    /// validated private directory or the management lock is unavailable.
    pub fn recover(&self) -> Result<RecoverySummary> {
        self.ensure_layout()?;
        let rename_recovery = self.recover_renames()?;
        let rename_transactions = rename_recovery.recovered;
        let rename_issues = self
            .rename_recovery_issue_count()?
            .saturating_add(rename_recovery.issues);
        let rollbacks = self.recover_rollbacks()?;
        let rollback_issues = self.rollback_issues()?;
        let artifacts = inspect_artifact_state(self)?;
        let (summary, reclaiming, trash_root) = {
            let mutation = self.begin_mutation()?;
            let layout = mutation.layout();
            let (mut summary, mut reclaiming) = prepare_recovery(&self.root, layout)?;
            summary.freeze_marker_temps = remove_freeze_marker_temporaries(layout.spaces_root())?;
            let artifact_reclaiming = prepare_artifact_recovery(self, layout.trash_root())?;
            reclaiming.extend(artifact_reclaiming);
            summary.apply_artifacts(&artifacts);
            (summary, reclaiming, layout.trash_root().to_path_buf())
        };
        let mut first_failure = None;
        for path in &reclaiming {
            if let Err(error) = remove_tree_restoring_owner_access(path)
                && first_failure.is_none()
            {
                first_failure = Some(error);
            }
        }
        let sync_result = sync_directory(&trash_root);
        if let Some(error) = first_failure {
            return Err(error.with_hint(
                "recovery attempted every retired entry; inspect the remaining reclaiming state and retry",
            ));
        }
        sync_result?;
        let unknown_entries_at_least = summary
            .unknown_entries_at_least
            .saturating_add(rollback_issues.len())
            .saturating_add(rename_issues);
        Ok(RecoverySummary {
            rollback_transactions: rollbacks.len(),
            rename_transactions,
            rename_issues,
            rollbacks,
            rollback_issues,
            unknown_entries_at_least,
            ..summary
        })
    }
}

fn inspect(
    root: &Path,
    layout: &StoreLayout,
    rollbacks: Vec<RollbackObservation>,
    rollback_issues: Vec<RollbackIssue>,
    rename_transactions: usize,
    rename_issues: usize,
    artifacts: &ArtifactRecoveryState,
) -> Result<RecoverySummary> {
    validate_layout(root, layout)?;
    let (unfinished, active) = classify_creations(layout.spaces_root())?;
    let retired = matching_entries(layout.trash_root(), &[RETIRED_PREFIX])?;
    let reclaiming = matching_entries(layout.trash_root(), &[RECLAIMING_PREFIX])?;
    let unknown_entries_at_least = count_unknown_space_entries(layout.spaces_root())?
        .saturating_add(rollback_issues.len())
        .saturating_add(rename_issues);
    let mut summary = RecoverySummary {
        active_creations: active,
        unfinished_creations: unfinished.len(),
        retired_entries: retired.len().saturating_add(reclaiming.len()),
        rollback_transactions: rollbacks.len(),
        rename_transactions,
        rename_issues,
        rollbacks,
        rollback_issues,
        freeze_marker_temps: freeze_marker_temporaries(layout.spaces_root())?.len(),
        unknown_entries_at_least,
        ..RecoverySummary::default()
    };
    summary.apply_artifacts(artifacts);
    Ok(summary)
}

fn prepare_recovery(root: &Path, layout: &StoreLayout) -> Result<(RecoverySummary, Vec<std::path::PathBuf>)> {
    validate_layout(root, layout)?;
    let (creations, active_creations) = classify_creations(layout.spaces_root())?;
    let retired = matching_entries(layout.trash_root(), &[RETIRED_PREFIX])?;
    let existing_reclaiming = matching_entries(layout.trash_root(), &[RECLAIMING_PREFIX])?;
    for path in retired.iter().chain(&existing_reclaiming) {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(QuartersError::io("inspect recovery directory", path, error)),
        };
        validate_private_dir(path, &metadata)?;
    }
    let mut reclaiming = Vec::new();
    for path in creations
        .iter()
        .map(|candidate| &candidate.path)
        .chain(&retired)
        .chain(&existing_reclaiming)
    {
        let target = layout.trash_root().join(format!(".reclaiming-{}", unique_suffix()?));
        match fs::rename(path, &target) {
            Ok(()) => reclaiming.push(target),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(QuartersError::io("retire recovery directory", path, error)),
        }
    }
    sync_directory(layout.spaces_root())?;
    sync_directory(layout.trash_root())?;
    let summary = RecoverySummary {
        active_creations,
        unfinished_creations: creations.len(),
        retired_entries: retired.len().saturating_add(existing_reclaiming.len()),
        rollback_transactions: 0,
        rename_transactions: 0,
        rollbacks: Vec::new(),
        rollback_issues: Vec::new(),
        unknown_entries_at_least: count_unknown_space_entries(layout.spaces_root())?,
        ..RecoverySummary::default()
    };
    Ok((summary, reclaiming))
}

fn inspect_artifact_state(store: &Store) -> Result<ArtifactRecoveryState> {
    let mut state = ArtifactRecoveryState::default();
    for kind in [ArtifactKind::Template, ArtifactKind::Snapshot] {
        let candidates = artifact_candidates(&store.root.join(artifact_root_name(kind)))?;
        state.active_creations = state.active_creations.saturating_add(candidates.active);
        state.unfinished_creations = state.unfinished_creations.saturating_add(candidates.stale.len());
        state.reclaiming = state.reclaiming.saturating_add(candidates.reclaiming.len());
        state.manifest_temps = state.manifest_temps.saturating_add(candidates.manifest_temps.len());
        state.unknown_entries = state.unknown_entries.saturating_add(candidates.unknown);
        for inspection in store.inspect_artifacts(kind)? {
            if let ArtifactInspection::Healthy {
                artifact,
                source_status,
            } = inspection
            {
                if source_status == SourceStatus::Orphaned {
                    state.orphaned = state.orphaned.saturating_add(1);
                }
                let bytes = artifact.manifest().content_integrity.counts.logical_bytes;
                let aggregate = match kind {
                    ArtifactKind::Template => &mut state.template_bytes,
                    ArtifactKind::Snapshot => &mut state.snapshot_bytes,
                };
                *aggregate = aggregate.checked_add(bytes).ok_or_else(|| {
                    QuartersError::new(ErrorKind::ResourceLimit, "artifact logical-byte aggregate overflowed")
                })?;
            }
        }
    }
    Ok(state)
}

fn prepare_artifact_recovery(store: &Store, trash: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut retired = Vec::new();
    for kind in [ArtifactKind::Template, ArtifactKind::Snapshot] {
        let root = store.root.join(artifact_root_name(kind));
        let candidates = artifact_candidates(&root)?;
        for temporary in candidates.manifest_temps {
            fs::remove_file(&temporary).map_err(|error| {
                QuartersError::io("remove stale artifact manifest temporary file", &temporary, error)
            })?;
        }
        for candidate in candidates.stale {
            retire_artifact_recovery_path(&candidate.path, trash, &mut retired)?;
        }
        for path in candidates.reclaiming {
            retire_artifact_recovery_path(&path, trash, &mut retired)?;
        }
        if root.exists() {
            sync_directory(&root)?;
        }
    }
    sync_directory(trash)?;
    Ok(retired)
}

fn retire_artifact_recovery_path(path: &Path, trash: &Path, retired: &mut Vec<std::path::PathBuf>) -> Result<()> {
    let destination = trash.join(format!(".reclaiming-{}", unique_suffix()?));
    fs::rename(path, &destination).map_err(|error| QuartersError::io("retire artifact recovery state", path, error))?;
    retired.push(destination);
    Ok(())
}

fn artifact_candidates(root: &Path) -> Result<ArtifactCandidates> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ArtifactCandidates {
                active: 0,
                stale: Vec::new(),
                reclaiming: Vec::new(),
                manifest_temps: Vec::new(),
                unknown: 0,
            });
        }
        Err(error) => return Err(QuartersError::io("inspect artifact recovery root", root, error)),
    };
    validate_private_dir(root, &metadata)?;
    let mut candidates = ArtifactCandidates {
        active: 0,
        stale: Vec::new(),
        reclaiming: Vec::new(),
        manifest_temps: Vec::new(),
        unknown: 0,
    };
    let entries = fs::read_dir(root).map_err(|error| QuartersError::io("read artifact recovery root", root, error))?;
    let mut scan = ScanBudget::new("the artifact recovery root");
    for entry in entries {
        let entry = entry.map_err(|error| QuartersError::io("read artifact recovery entry", root, error))?;
        scan.observe()?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            candidates.unknown = candidates.unknown.saturating_add(1);
            continue;
        };
        if parse_reserved_artifact_id(&name, ".creating-").is_some() {
            classify_artifact_creation(entry.path(), &mut candidates)?;
        } else if parse_reserved_artifact_id(&name, ".reclaiming-").is_some() {
            validate_artifact_recovery_directory(&entry.path())?;
            push_bounded(&mut candidates.reclaiming, entry.path(), "artifact reclaiming")?;
        } else if let Ok(id) = ArtifactId::parse(name.clone()) {
            inspect_manifest_temp(&entry.path(), &id, &mut candidates)?;
        } else {
            candidates.unknown = candidates.unknown.saturating_add(1);
        }
    }
    Ok(candidates)
}

fn classify_artifact_creation(path: std::path::PathBuf, candidates: &mut ArtifactCandidates) -> Result<()> {
    validate_artifact_recovery_directory(&path)?;
    let lock_path = path.join(CREATION_LOCK_FILE);
    let lock = match fs::symlink_metadata(&lock_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Ok(_) => Some(open_private_lock(&lock_path)?),
        Err(error) => return Err(QuartersError::io("inspect artifact creation lock", &lock_path, error)),
    };
    if let Some(file) = &lock {
        match <File as FileExt>::try_lock(file) {
            Ok(()) => {}
            Err(fs4::TryLockError::WouldBlock) => {
                candidates.active = candidates.active.saturating_add(1);
                return Ok(());
            }
            Err(fs4::TryLockError::Error(error)) => {
                return Err(QuartersError::io("inspect artifact creation lock", &lock_path, error));
            }
        }
    }
    if candidates.stale.len() >= MAX_RECOVERY_ENTRIES {
        return Err(artifact_recovery_limit("unfinished artifact creations"));
    }
    candidates.stale.push(CreationCandidate { path, _lock: lock });
    Ok(())
}

fn inspect_manifest_temp(path: &Path, id: &ArtifactId, candidates: &mut ArtifactCandidates) -> Result<()> {
    validate_artifact_recovery_directory(path)?;
    let temporary = path.join(format!(".manifest-{id}.tmp"));
    match fs::symlink_metadata(&temporary) {
        Ok(metadata) => {
            validate_private_file(&temporary, &metadata)?;
            push_bounded(
                &mut candidates.manifest_temps,
                temporary,
                "artifact manifest temporary files",
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(QuartersError::io(
            "inspect artifact manifest temporary file",
            &temporary,
            error,
        )),
    }
}

fn validate_artifact_recovery_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect artifact recovery directory", path, error))?;
    validate_private_dir(path, &metadata)
}

fn parse_reserved_artifact_id(name: &str, prefix: &str) -> Option<ArtifactId> {
    ArtifactId::parse(name.strip_prefix(prefix)?.to_owned()).ok()
}

fn artifact_root_name(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::Template => ".templates",
        ArtifactKind::Snapshot => ".snapshots",
    }
}

fn push_bounded<T>(values: &mut Vec<T>, value: T, family: &str) -> Result<()> {
    if values.len() >= MAX_RECOVERY_ENTRIES {
        return Err(artifact_recovery_limit(family));
    }
    values.push(value);
    Ok(())
}

fn artifact_recovery_limit(family: &str) -> QuartersError {
    QuartersError::new(
        ErrorKind::ResourceLimit,
        format!("the store contains more than {MAX_RECOVERY_ENTRIES} {family}"),
    )
    .with_hint("inspect the protected artifact root before attempting recovery")
}

fn classify_creations(parent: &Path) -> Result<(Vec<CreationCandidate>, usize)> {
    let mut stale = Vec::new();
    let mut active = 0;
    for path in matching_entries(parent, &[CREATING_PREFIX])? {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(QuartersError::io("inspect creation directory", &path, error)),
        };
        validate_private_dir(&path, &metadata)?;
        let lock_path = path.join(CREATION_LOCK_FILE);
        match fs::symlink_metadata(&lock_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                stale.push(CreationCandidate { path, _lock: None });
                continue;
            }
            Ok(_metadata) => {}
            Err(error) => return Err(QuartersError::io("inspect creation lock", &lock_path, error)),
        }
        let file = match open_private_lock(&lock_path) {
            Ok(file) => file,
            Err(_error)
                if fs::symlink_metadata(&path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        match <File as FileExt>::try_lock(&file) {
            Ok(()) => stale.push(CreationCandidate {
                path,
                _lock: Some(file),
            }),
            Err(fs4::TryLockError::WouldBlock) => active += 1,
            Err(fs4::TryLockError::Error(error)) => {
                return Err(QuartersError::io("inspect creation lock", &lock_path, error));
            }
        }
    }
    Ok((stale, active))
}

fn validate_layout(root: &Path, layout: &StoreLayout) -> Result<()> {
    let metadata =
        fs::symlink_metadata(root).map_err(|error| QuartersError::io("inspect Quarters root", root, error))?;
    validate_store_root(root, &metadata)?;
    for path in [layout.spaces_root(), layout.trash_root()] {
        let metadata =
            fs::symlink_metadata(path).map_err(|error| QuartersError::io("inspect recovery parent", path, error))?;
        validate_private_dir(path, &metadata)?;
    }
    Ok(())
}

fn matching_entries(parent: &Path, prefixes: &[&[u8]]) -> Result<Vec<std::path::PathBuf>> {
    let mut matches = Vec::new();
    let entries = fs::read_dir(parent).map_err(|error| QuartersError::io("read recovery parent", parent, error))?;
    let mut scan = ScanBudget::new("the store recovery parent");
    for entry in entries {
        let entry = entry.map_err(|error| QuartersError::io("read recovery entry", parent, error))?;
        scan.observe()?;
        if !prefixes.iter().any(|prefix| has_prefix(&entry.file_name(), prefix)) {
            continue;
        }
        if matches.len() >= MAX_RECOVERY_ENTRIES {
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                "the store contains more than 1024 reserved recovery entries",
            )
            .with_hint("inspect the protected store root before attempting recovery"));
        }
        matches.push(entry.path());
    }
    Ok(matches)
}

fn has_prefix(name: &OsStr, prefix: &[u8]) -> bool {
    name.as_bytes().starts_with(prefix)
}

fn count_unknown_space_entries(spaces: &Path) -> Result<usize> {
    let entries =
        fs::read_dir(spaces).map_err(|error| QuartersError::io("read spaces recovery namespace", spaces, error))?;
    let mut unknown = 0_usize;
    let mut scan = ScanBudget::new("the spaces recovery namespace");
    for entry in entries {
        let entry = entry.map_err(|error| QuartersError::io("read spaces recovery entry", spaces, error))?;
        scan.observe()?;
        let name = entry.file_name();
        if name.as_bytes().starts_with(b".") && !is_known_space_hidden_entry(spaces, &name) {
            unknown = unknown.saturating_add(1);
        }
    }
    Ok(unknown)
}

fn freeze_marker_temporaries(spaces: &Path) -> Result<Vec<std::path::PathBuf>> {
    let entries =
        fs::read_dir(spaces).map_err(|error| QuartersError::io("read freeze recovery namespace", spaces, error))?;
    let mut temporaries = Vec::new();
    let mut scan = ScanBudget::new("the freeze recovery namespace");
    for entry in entries {
        let entry = entry.map_err(|error| QuartersError::io("read freeze recovery entry", spaces, error))?;
        scan.observe()?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if parse_wrapped_space_id(&name, ".freeze-", ".tmp") {
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| QuartersError::io("inspect freeze marker temporary file", &entry.path(), error))?;
            validate_private_file(&entry.path(), &metadata).map_err(|error| {
                error.with_hint(format!(
                    "inspect and remove only the exact unsafe freeze temporary {}; then retry recovery",
                    entry.path().display()
                ))
            })?;
            if temporaries.len() >= MAX_RECOVERY_ENTRIES {
                return Err(QuartersError::new(
                    ErrorKind::ResourceLimit,
                    "the store contains more than 1024 freeze marker temporary files",
                )
                .with_hint("inspect the protected spaces root before attempting recovery"));
            }
            temporaries.push(entry.path());
        }
    }
    Ok(temporaries)
}

fn remove_freeze_marker_temporaries(spaces: &Path) -> Result<usize> {
    let temporaries = freeze_marker_temporaries(spaces)?;
    for temporary in &temporaries {
        fs::remove_file(temporary)
            .map_err(|error| QuartersError::io("remove freeze marker temporary file", temporary, error))?;
    }
    if !temporaries.is_empty() {
        sync_directory(spaces)?;
    }
    Ok(temporaries.len())
}

fn is_known_space_hidden_entry(spaces: &Path, name: &OsStr) -> bool {
    if has_prefix(name, CREATING_PREFIX) {
        return true;
    }
    let Some(name) = name.to_str() else {
        return false;
    };
    parse_wrapped_artifact_id(name, ".rollback-", ".json")
        || parse_wrapped_artifact_id(name, ".rollback-", ".tmp")
        || parse_wrapped_space_id(name, ".rename-", ".json")
        || parse_wrapped_space_id(name, ".freeze-", ".json")
        || parse_wrapped_space_id(name, ".freeze-", ".tmp")
        || parse_prefixed_artifact_id(name, ".rollback-staging-")
        || retired_entry_has_marker(spaces, name)
}

fn parse_wrapped_space_id(name: &str, prefix: &str, suffix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .and_then(|value| crate::SpaceId::parse(value.to_owned()).ok())
        .is_some()
}

fn retired_entry_has_marker(spaces: &Path, name: &str) -> bool {
    rollback_retired_entry_is_actionable(spaces, name)
}

fn parse_prefixed_artifact_id(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|value| ArtifactId::parse(value.to_owned()).ok())
        .is_some()
}

fn parse_wrapped_artifact_id(name: &str, prefix: &str, suffix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .and_then(|value| ArtifactId::parse(value.to_owned()).ok())
        .is_some()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    #[test]
    fn active_creation_is_reported_and_never_recovered() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        store.recover().expect("initialize store");
        let creation = store.root.join("spaces/.creating-live");
        fs::create_dir(&creation).expect("create working directory");
        fs::set_permissions(&creation, fs::Permissions::from_mode(0o700)).expect("protect working directory");
        let lock_path = creation.join(CREATION_LOCK_FILE);
        fs::write(&lock_path, b"").expect("create working lock");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).expect("protect working lock");
        let lock = open_private_lock(&lock_path).expect("open working lock");
        <File as FileExt>::lock(&lock).expect("hold working lock");

        let summary = store.recovery_summary().expect("inspect live creation");
        assert_eq!(summary.active_creations, 1);
        assert_eq!(summary.unfinished_creations, 0);
        let recovered = store.recover().expect("skip live creation");
        assert_eq!(recovered.active_creations, 1);
        assert!(creation.is_dir());

        drop(lock);
        let recovered = store.recover().expect("recover stale creation");
        assert_eq!(recovered.unfinished_creations, 1);
        assert!(!creation.exists());
    }

    #[test]
    fn symbolic_link_recovery_entry_fails_closed() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        store.recover().expect("initialize store");
        let external = temporary.path().join("external");
        fs::create_dir(&external).expect("create external directory");
        symlink(&external, store.root.join("spaces/.creating-linked")).expect("link recovery entry");

        let error = store.recover().expect_err("linked recovery entry must fail");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
        assert!(external.is_dir());
    }

    #[test]
    fn nested_read_only_directory_is_recoverable() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        store.recover().expect("initialize store");
        let creation = store.root.join("spaces/.creating-read-only");
        let nested = creation.join("nested");
        fs::create_dir_all(&nested).expect("create stale tree");
        fs::set_permissions(&creation, fs::Permissions::from_mode(0o700)).expect("protect staging root");
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o000)).expect("remove nested access");

        let summary = store.recover().expect("recover read-only tree");
        assert_eq!(summary.unfinished_creations, 1);
        assert!(!creation.exists());
        assert_eq!(
            store.recovery_summary().expect("inspect recovery"),
            RecoverySummary::default()
        );
    }

    #[test]
    fn recovery_attempts_later_entries_after_one_cleanup_failure() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        store.recover().expect("initialize store");
        let deep = store.root.join("trash/.retired-deep");
        fs::create_dir(&deep).expect("create deep retired root");
        fs::set_permissions(&deep, fs::Permissions::from_mode(0o700)).expect("protect deep root");
        let mut nested = deep;
        for _ in 0..=256 {
            nested.push("d");
            fs::create_dir(&nested).expect("create deep retired directory");
        }
        let ordinary = store.root.join("trash/.retired-ordinary");
        fs::create_dir(&ordinary).expect("create ordinary retired root");
        fs::set_permissions(&ordinary, fs::Permissions::from_mode(0o700)).expect("protect ordinary root");

        let error = store.recover().expect_err("one over-deep cleanup must fail");
        assert_eq!(error.kind(), ErrorKind::ResourceLimit);
        assert_eq!(store.recovery_summary().expect("inspect residue").retired_entries, 1);
    }

    #[test]
    fn artifact_recovery_reclaims_only_exact_reserved_forms() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        store.recover().expect("initialize store");
        let root = store.root.join(".templates");
        private_dir(&root);
        let creation_id = ArtifactId::generate().expect("creation ID");
        let creation = root.join(format!(".creating-{creation_id}"));
        private_dir(&creation);
        let reclaiming_id = ArtifactId::generate().expect("reclaiming ID");
        let reclaiming = root.join(format!(".reclaiming-{reclaiming_id}"));
        private_dir(&reclaiming);
        let published_id = ArtifactId::generate().expect("published ID");
        let published = root.join(published_id.as_str());
        private_dir(&published);
        let manifest_temp = published.join(format!(".manifest-{published_id}.tmp"));
        fs::write(&manifest_temp, b"pending").expect("create manifest temporary file");
        fs::set_permissions(&manifest_temp, fs::Permissions::from_mode(0o600)).expect("protect manifest temporary");
        let unknown = root.join(".creating-not-an-id");
        private_dir(&unknown);

        let summary = store.recovery_summary().expect("inspect artifact recovery state");
        assert_eq!(summary.unfinished_artifact_creations, 1);
        assert_eq!(summary.reclaiming_artifacts, 1);
        assert_eq!(summary.artifact_manifest_temps, 1);
        assert_eq!(summary.unknown_entries_at_least, 1);

        let recovered = store.recover().expect("recover exact artifact state");
        assert_eq!(recovered.unfinished_artifact_creations, 1);
        assert_eq!(recovered.reclaiming_artifacts, 1);
        assert_eq!(recovered.artifact_manifest_temps, 1);
        assert!(!creation.exists());
        assert!(!reclaiming.exists());
        assert!(!manifest_temp.exists());
        assert!(unknown.is_dir());
        assert!(published.is_dir());
    }

    #[test]
    fn malformed_space_recovery_names_are_counted_and_retained() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        store.recover().expect("initialize store");
        let malformed_marker = store.root.join("spaces/.rollback-not-an-id.json");
        let malformed_staging = store.root.join("spaces/.rollback-staging-not-an-id");
        fs::write(&malformed_marker, b"unknown").expect("create unknown marker-like entry");
        private_dir(&malformed_staging);

        let summary = store.recovery_summary().expect("inspect unknown entries");
        assert_eq!(summary.unknown_entries_at_least, 2);
        let recovered = store.recover().expect("recover unrelated state");
        assert_eq!(recovered.unknown_entries_at_least, 2);
        assert!(malformed_marker.is_file());
        assert!(malformed_staging.is_dir());
    }

    #[test]
    fn orphaned_retired_rollback_tree_is_counted_and_retained() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        store.recover().expect("initialize store");
        let id = ArtifactId::generate().expect("rollback ID");
        let retired = store.root.join(format!("spaces/.rolled-back-{id}"));
        private_dir(&retired);

        let summary = store.recovery_summary().expect("inspect orphaned retired tree");
        assert_eq!(summary.unknown_entries_at_least, 1);
        let recovered = store.recover().expect("recover unrelated state");
        assert_eq!(recovered.unknown_entries_at_least, 1);
        assert!(retired.is_dir());
    }

    #[test]
    fn trash_recovery_families_have_independent_limits() {
        let temporary = TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        store.recover().expect("initialize store");
        let trash = store.root.join("trash");
        for index in 0..MAX_RECOVERY_ENTRIES {
            private_dir(&trash.join(format!(".retired-{index}")));
        }
        private_dir(&trash.join(".reclaiming-independent"));

        let summary = store.recovery_summary().expect("independent family budgets");
        assert_eq!(summary.retired_entries, MAX_RECOVERY_ENTRIES + 1);

        private_dir(&trash.join(".retired-over-limit"));
        let error = store.recovery_summary().expect_err("retired family must stay bounded");
        assert_eq!(error.kind(), ErrorKind::ResourceLimit);
    }

    fn private_dir(path: &Path) {
        fs::create_dir(path).expect("create private fixture directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("protect fixture directory");
    }
}
