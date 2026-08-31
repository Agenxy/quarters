//! Cross-thread creation and removal contracts.

#![allow(clippy::expect_used)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

use tempfile::TempDir;

use crate::{ErrorKind, SpaceName, Store};

fn test_store() -> (TempDir, Store) {
    let temporary = TempDir::new().expect("temporary directory");
    let store = Store::new(temporary.path().join("root")).expect("valid store");
    (temporary, store)
}

#[test]
fn concurrent_creations_have_collision_resistant_temporary_paths() {
    let (_temporary, store) = test_store();
    let barrier = Arc::new(Barrier::new(16));
    std::thread::scope(|scope| {
        let handles = (0..16)
            .map(|index| {
                let store = store.clone();
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    let name = SpaceName::parse(format!("space{index}"))?;
                    store.create(name, PathBuf::from("/bin/sh"))
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            let result = handle.join();
            assert!(result.as_ref().is_ok_and(std::result::Result::is_ok), "{result:?}");
        }
    });
    assert_eq!(store.list().expect("list concurrent spaces").len(), 16);
}

#[test]
fn losing_same_name_creations_leave_no_temporary_skeletons() {
    let (_temporary, store) = test_store();
    let barrier = Arc::new(Barrier::new(17));
    let handles = (0..16)
        .map(|_| {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.create(SpaceName::parse("racy").expect("valid name"), PathBuf::from("/bin/sh"))
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("creation thread"))
        .collect::<Vec<_>>();
    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        1,
        "concurrent creation results: {results:?}"
    );
    assert!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|error| error.kind() == ErrorKind::AlreadyExists)
    );
    let entries = fs::read_dir(store.root.join("spaces")).expect("read spaces");
    assert!(
        entries
            .filter_map(std::result::Result::ok)
            .all(|entry| !entry.file_name().to_string_lossy().starts_with(".creating-"))
    );
}

#[test]
fn concurrent_removals_report_one_success_and_one_absence() {
    let (_temporary, store) = test_store();
    store
        .create(
            SpaceName::parse("remove-race").expect("valid name"),
            PathBuf::from("/bin/sh"),
        )
        .expect("create space");
    let barrier = Arc::new(Barrier::new(3));
    let handles = (0..2)
        .map(|_| {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.remove("remove-race")
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("removal thread"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .filter(|error| error.kind() == ErrorKind::NotFound)
            .count(),
        1,
        "concurrent removal results: {results:?}"
    );
}

#[test]
fn removal_reports_corrupt_state_when_the_space_exists_without_a_manifest() {
    let (_temporary, store) = test_store();
    let space = store
        .create(
            SpaceName::parse("missing-manifest").expect("valid name"),
            PathBuf::from("/bin/sh"),
        )
        .expect("create space");
    fs::remove_file(space.root().join(".quarters.json")).expect("remove manifest");

    let error = store
        .remove("missing-manifest")
        .expect_err("missing manifest must fail closed");
    assert_eq!(error.kind(), ErrorKind::CorruptState);
    assert_eq!(error.hint(), Some("repair the protected control files before removal"));
}

#[test]
fn removal_never_follows_present_or_dangling_space_links() {
    let (temporary, store) = test_store();
    store.recover().expect("initialize store");
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside).expect("create outside directory");
    let sentinel = outside.join("sentinel");
    fs::write(&sentinel, b"outside").expect("write outside sentinel");
    let spaces = store.root.join("spaces");

    let present = spaces.join("present-link");
    symlink(&outside, &present).expect("create present space link");
    let present_error = store
        .remove("present-link")
        .expect_err("present space link must fail closed");
    assert_eq!(present_error.kind(), ErrorKind::CorruptState);
    assert!(sentinel.is_file());
    assert!(fs::symlink_metadata(&present).is_ok_and(|metadata| metadata.file_type().is_symlink()));

    let dangling = spaces.join("dangling-link");
    symlink(temporary.path().join("absent"), &dangling).expect("create dangling space link");
    let dangling_error = store
        .remove("dangling-link")
        .expect_err("dangling space link must fail closed");
    assert_eq!(dangling_error.kind(), ErrorKind::CorruptState);
    assert!(fs::symlink_metadata(&dangling).is_ok_and(|metadata| metadata.file_type().is_symlink()));
}

#[test]
fn concurrent_recovery_tolerates_reclaiming_state() {
    let (_temporary, store) = test_store();
    store.recover().expect("initialize store");
    for index in 0..16 {
        let path = store.root.join(format!("spaces/.creating-stale-{index}"));
        fs::create_dir(&path).expect("create stale entry");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("protect stale entry");
    }
    let barrier = Arc::new(Barrier::new(3));
    let handles = (0..2)
        .map(|_| {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.recover()
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    for handle in handles {
        handle.join().expect("recovery thread").expect("concurrent recovery");
    }
    assert_eq!(
        store.recovery_summary().expect("inspect recovery"),
        crate::RecoverySummary::default()
    );
}

#[test]
fn concurrent_same_destination_clones_publish_once_without_staging_leaks() {
    let (_temporary, store) = test_store();
    let source = store
        .create(
            SpaceName::parse("source").expect("valid name"),
            PathBuf::from("/bin/sh"),
        )
        .expect("create source");
    fs::write(source.home().join("payload"), vec![7_u8; 2 * 1_024 * 1_024]).expect("write payload");
    let barrier = Arc::new(Barrier::new(3));
    let handles = (0..2)
        .map(|_| {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.clone_space(
                    &SpaceName::parse("source").expect("valid source"),
                    SpaceName::parse("copy").expect("valid destination"),
                    false,
                )
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("clone thread"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|error| { matches!(error.kind(), ErrorKind::AlreadyExists | ErrorKind::SpaceActive) })
    );
    assert!(
        store
            .open(&SpaceName::parse("copy").expect("valid destination"))
            .is_ok()
    );
    let entries = fs::read_dir(store.root.join("spaces")).expect("read spaces");
    assert!(
        entries
            .filter_map(std::result::Result::ok)
            .all(|entry| !entry.file_name().to_string_lossy().starts_with(".creating-"))
    );
}
