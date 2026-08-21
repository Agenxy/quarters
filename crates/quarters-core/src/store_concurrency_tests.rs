//! Cross-thread creation and removal contracts.

#![allow(clippy::expect_used)]

use std::fs;
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
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
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
        1
    );
}
