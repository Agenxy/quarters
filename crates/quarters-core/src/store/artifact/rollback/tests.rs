use super::*;
use tempfile::TempDir;

#[test]
fn ordinary_spaces_do_not_consume_the_rollback_marker_limit() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let store = Store::new(temporary.path().join("root"))?;
    store.ensure_layout()?;
    for index in 0..=MAX_ROLLBACK_MARKERS {
        create_private_dir(&store.layout().spaces_root().join(format!("space-{index}")))?;
    }

    let inventory = load_recovery_inventory(store.layout().spaces_root(), None)?;
    assert!(inventory.plans.is_empty());
    assert!(inventory.issues.is_empty());
    Ok(())
}

#[test]
fn rollback_restores_state_and_keeps_recovery() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let store = Store::new(temporary.path().join("root"))?;
    let target = SpaceName::parse("work")?;
    store.create(target.clone(), PathBuf::from("/bin/sh"))?;
    let state = store.open(&target)?.home().join("state");
    fs::write(&state, b"before")?;
    let snapshot = ArtifactName::parse("before")?;
    store.create_artifact(
        ArtifactKind::Snapshot,
        &target,
        snapshot.clone(),
        true,
        ArtifactOrigin::User,
    )?;
    fs::write(&state, b"after")?;
    let recovery = ArtifactName::parse("automatic")?;
    let report = store.rollback_space(&target, &snapshot, &recovery, true)?;
    assert_eq!(report.mode, RollbackMode::Execute);
    assert_eq!(fs::read(store.open(&target)?.home().join("state"))?, b"before");
    let captured = store.verify_artifact(ArtifactKind::Snapshot, &recovery)?;
    assert_eq!(fs::read(captured.home().join("state"))?, b"after");
    Ok(())
}

#[test]
fn prepared_marker_aborts_and_reclaims_unused_staging() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_temporary, store, target, space) = test_space("work")?;
    let id = ArtifactId::generate()?;
    let staging = store.layout().spaces_root().join(format!(".rollback-staging-{id}"));
    create_private_dir(&staging)?;
    let marker = test_marker(&space, &id, RollbackState::Prepared)?;
    let marker_path = rollback_marker_path(&store, &id);
    write_marker_new(&marker_path, &marker)?;
    assert_eq!(store.rollback_observations()?[0].action, RollbackRecoveryAction::Abort);
    store.recover_rollbacks()?;
    assert!(store.open(&target).is_ok());
    assert!(!staging.exists());
    assert!(!marker_path.exists());
    Ok(())
}

#[test]
fn malformed_reserved_looking_names_are_unknown_and_do_not_block_recovery()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_temporary, store, target, _space) = test_space("work")?;
    let malformed_marker = store.layout().spaces_root().join(".rollback-not-an-id.json");
    let malformed_staging = store.layout().spaces_root().join(".rollback-staging-not-an-id");
    write_private_file(&malformed_marker, b"not a marker")?;
    create_private_dir(&malformed_staging)?;
    assert!(store.open(&target).is_ok());
    assert!(store.rollback_observations()?.is_empty());
    store.recover_rollbacks()?;
    assert!(malformed_marker.is_file());
    assert!(malformed_staging.is_dir());
    Ok(())
}

#[test]
fn malformed_exact_marker_is_itemized_without_blocking_unrelated_work()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_temporary, store, healthy, _space) = test_space("healthy")?;
    let id = ArtifactId::generate()?;
    let marker_path = rollback_marker_path(&store, &id);
    write_private_file(&marker_path, b"")?;
    let retired = store.layout().spaces_root().join(format!(".rolled-back-{id}"));
    create_private_dir(&retired)?;
    assert!(store.open(&healthy).is_ok());
    assert!(store.create(SpaceName::parse("new")?, PathBuf::from("/bin/sh")).is_ok());
    assert!(store.rollback_observations()?.is_empty());
    let issues = store.rollback_issues()?;
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].marker, format!(".rollback-{id}.json"));
    assert_eq!(store.recovery_summary()?.unknown_entries_at_least, 2);
    store.recover_rollbacks()?;
    assert!(marker_path.is_file());
    assert!(retired.is_dir());
    Ok(())
}

#[test]
fn orphan_marker_temporary_is_reclaimed_without_a_published_marker()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let store = Store::new(temporary.path().join("root"))?;
    store.ensure_layout()?;
    let id = ArtifactId::generate()?;
    let marker_temp = store.layout().spaces_root().join(format!(".rollback-{id}.tmp"));
    write_private_file(&marker_temp, b"partial")?;
    store.recover_rollbacks()?;
    assert!(!marker_temp.exists());
    Ok(())
}

#[test]
fn ambiguous_marker_blocks_only_its_target_for_normal_operations() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    let (_temporary, store, blocked, blocked_space) = test_space("blocked")?;
    let healthy = SpaceName::parse("healthy")?;
    store.create(healthy.clone(), PathBuf::from("/bin/sh"))?;
    let id = ArtifactId::generate()?;
    let marker = test_marker(&blocked_space, &id, RollbackState::Prepared)?;
    write_marker_new(&rollback_marker_path(&store, &id), &marker)?;
    assert!(store.rollback_observations()?.is_empty());
    assert_eq!(store.rollback_issues()?.len(), 1);
    let Err(error) = store.open(&blocked) else {
        return Err("target did not fail closed".into());
    };
    assert_eq!(error.kind(), ErrorKind::CorruptState);
    assert!(store.open(&healthy).is_ok());
    assert!(store.create(SpaceName::parse("new")?, PathBuf::from("/bin/sh")).is_ok());
    Ok(())
}

#[test]
fn duplicate_actionable_markers_are_retained_as_target_issues() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_temporary, store, target, space) = test_space("blocked")?;
    let mut marker_paths = Vec::new();
    for _index in 0..2 {
        let id = ArtifactId::generate()?;
        let staging = store.layout().spaces_root().join(format!(".rollback-staging-{id}"));
        create_private_dir(&staging)?;
        let marker = test_marker(&space, &id, RollbackState::Prepared)?;
        let marker_path = rollback_marker_path(&store, &id);
        write_marker_new(&marker_path, &marker)?;
        marker_paths.push(marker_path);
    }

    let inventory = store.rollback_inventory()?;
    assert!(inventory.observations.is_empty());
    assert_eq!(inventory.issues.len(), 2);
    assert!(
        inventory
            .issues
            .iter()
            .all(|issue| issue.target.as_ref() == Some(&target))
    );
    assert!(store.open(&target).is_err());
    store.recover_rollbacks()?;
    assert!(marker_paths.iter().all(|path| path.is_file()));
    Ok(())
}

#[test]
fn retired_marker_restores_old_space_and_reclaims_staging() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_temporary, store, target, space) = test_space("work")?;
    let id = ArtifactId::generate()?;
    let staging = store.layout().spaces_root().join(format!(".rollback-staging-{id}"));
    let retired = store.layout().spaces_root().join(format!(".rolled-back-{id}"));
    create_private_dir(&staging)?;
    let marker = test_marker(&space, &id, RollbackState::Retired)?;
    fs::rename(space.root(), &retired)?;
    let marker_path = rollback_marker_path(&store, &id);
    write_marker_new(&marker_path, &marker)?;
    assert_eq!(
        store.rollback_observations()?[0].action,
        RollbackRecoveryAction::RestoreOld
    );
    store.recover_rollbacks()?;
    assert!(store.open(&target).is_ok());
    assert!(!staging.exists());
    assert!(!retired.exists());
    assert!(!marker_path.exists());
    Ok(())
}

#[test]
fn published_marker_without_retired_tree_completes_idempotently() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    let (_temporary, store, target, space) = test_space("work")?;
    let id = ArtifactId::generate()?;
    let marker = test_marker(&space, &id, RollbackState::Published)?;
    let marker_path = rollback_marker_path(&store, &id);
    write_marker_new(&marker_path, &marker)?;
    assert_eq!(
        store.rollback_observations()?[0].action,
        RollbackRecoveryAction::CompleteNew
    );
    store.recover_rollbacks()?;
    assert!(store.open(&target).is_ok());
    assert!(!marker_path.exists());
    Ok(())
}

#[test]
fn pre_marker_staging_is_reclaimed_only_after_lock_disappears() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let store = Store::new(temporary.path().join("root"))?;
    store.ensure_layout()?;
    let id = ArtifactId::generate()?;
    let staging = store.layout().spaces_root().join(format!(".rollback-staging-{id}"));
    create_private_dir(&staging)?;
    store.recover_rollbacks()?;
    assert!(!staging.exists());
    Ok(())
}

#[test]
fn post_commit_cleanup_error_reports_that_rollback_completed() {
    let error = post_commit_cleanup_error(
        QuartersError::new(ErrorKind::System, "cleanup failed"),
        "run doctor and recover",
    );
    assert_eq!(error.kind(), ErrorKind::System);
    assert!(error.message().starts_with("rollback completed, but"));
    assert_eq!(error.hint(), Some("run doctor and recover"));
}

fn test_space(name: &str) -> std::result::Result<(TempDir, Store, SpaceName, Space), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let store = Store::new(temporary.path().join("root"))?;
    let target = SpaceName::parse(name.to_owned())?;
    let space = store.create(target.clone(), PathBuf::from("/bin/sh"))?;
    Ok((temporary, store, target, space))
}

fn test_marker(space: &Space, id: &ArtifactId, state: RollbackState) -> Result<RollbackMarker> {
    Ok(RollbackMarker {
        schema_version: MARKER_SCHEMA_VERSION,
        transaction_id: id.clone(),
        state,
        target: space.manifest().name.clone(),
        target_identity: SourceIdentity::for_space(space),
        staging_entry: format!(".rollback-staging-{id}"),
        retired_entry: format!(".rolled-back-{id}"),
        snapshot_id: ArtifactId::generate()?,
        recovery_snapshot_id: ArtifactId::generate()?,
    })
}
