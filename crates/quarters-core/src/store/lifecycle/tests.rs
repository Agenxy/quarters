//! Lifecycle transaction tests.

#![allow(clippy::expect_used)]

use super::copy::{LifecycleAbort, compound_cleanup_error};
use super::policy::{CloneLimits, CloneMode};
use super::walk::test_support::{TestMutation, TestMutationAction};
use crate::{ErrorKind, SpaceLayout, SpaceName, Store};
use nix::sys::stat::Mode;
use nix::unistd::{Uid, mkfifo};
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn test_store() -> (TempDir, Store) {
    let temporary = TempDir::new().expect("temporary directory");
    let store = Store::new(temporary.path().join("root")).expect("valid store");
    (temporary, store)
}

fn name(value: &str) -> SpaceName {
    SpaceName::parse(value).expect("valid name")
}

fn create_workspace(store: &Store, value: &str) -> crate::Space {
    store
        .create_with_layout(name(value), PathBuf::from("/bin/sh"), SpaceLayout::Workspace)
        .expect("create workspace")
}

#[test]
fn compound_cleanup_failure_preserves_the_original_error_contract() {
    let original =
        crate::QuartersError::new(ErrorKind::ResourceLimit, "original failure").with_hint("reduce the source tree");
    let cleanup = crate::QuartersError::new(ErrorKind::System, "cleanup failure");
    let combined = compound_cleanup_error(&original, cleanup);
    assert_eq!(combined.kind(), ErrorKind::ResourceLimit);
    assert!(combined.message().contains("original failure"));
    assert!(
        combined
            .hint()
            .is_some_and(|hint| hint.contains("reduce the source tree"))
    );
    assert!(combined.hint().is_some_and(|hint| hint.contains("quarters doctor")));
}

#[test]
fn workspace_clone_has_fresh_controls_and_declared_topology() {
    let (_temporary, store) = test_store();
    let source = create_workspace(&store, "source");
    let proof = source.home().join("proof.txt");
    fs::write(&proof, b"persistent state\n").expect("write proof");
    fs::set_permissions(&proof, fs::Permissions::from_mode(0o4751)).expect("set proof mode");
    fs::hard_link(&proof, source.home().join("proof-hardlink.txt")).expect("create hard link");
    symlink("proof.txt", source.home().join("proof-link")).expect("create relative link");
    fs::write(source.home().join(".cache/derived"), b"cache").expect("write cache");
    symlink(".cache/derived", source.home().join("cache-link")).expect("create cache link");
    let socket_path = source.home().join(".gnupg/S.gpg-agent");
    let _socket = UnixListener::bind(&socket_path).expect("create runtime socket");
    mkfifo(
        &source.home().join(".gnupg/runtime-pipe"),
        Mode::from_bits_truncate(0o600),
    )
    .expect("create runtime FIFO");

    let preview = store
        .clone_plan(&name("source"), &name("copy"), false)
        .expect("preview clone");
    assert_eq!(preview.mode, CloneMode::Preview);
    assert_eq!(preview.exclusions.hard_linked_files_copied_independently, 2);
    assert_eq!(preview.exclusions.sockets, 1);
    assert_eq!(preview.exclusions.fifos, 1);
    assert!(preview.exclusions.cache_roots >= 1);
    assert_eq!(preview.exclusions.symlinks_into_omitted_cache_roots, 1);
    assert!(!source.root().parent().expect("spaces root").join("copy").exists());

    let cloned = store
        .clone_space(&name("source"), name("copy"), false)
        .expect("execute clone");
    assert_eq!(cloned.mode, CloneMode::Execute);
    assert_eq!(cloned.counts, preview.counts);
    assert_eq!(cloned.exclusions, preview.exclusions);
    let copy = store.open(&name("copy")).expect("open cloned space");
    assert_eq!(copy.layout(), SpaceLayout::Workspace);
    assert_ne!(copy.id(), source.id());
    assert_eq!(
        fs::read(copy.home().join("proof.txt")).expect("read proof"),
        b"persistent state\n"
    );
    assert!(!copy.home().join(".cache/derived").exists());
    assert!(copy.home().join(".cache").is_dir());
    assert!(!copy.home().join(".gnupg/S.gpg-agent").exists());
    assert!(!copy.home().join(".gnupg/runtime-pipe").exists());
    assert_eq!(
        fs::read_link(copy.home().join("proof-link")).expect("read link"),
        Path::new("proof.txt")
    );
    let first = fs::metadata(copy.home().join("proof.txt")).expect("first metadata");
    let second = fs::metadata(copy.home().join("proof-hardlink.txt")).expect("second metadata");
    assert_ne!(first.ino(), second.ino());
    assert_eq!(first.permissions().mode() & 0o7777, 0o751);
    let provenance = copy.root().join(".quarters-provenance.json");
    assert_eq!(
        fs::metadata(&provenance)
            .expect("provenance metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(provenance).expect("read provenance")).expect("parse provenance");
    assert_eq!(provenance["operation"], "clone");
    assert_eq!(provenance["source"], "source");
    assert!(provenance.get("source_home").is_none());
}

fn assert_replaced_entry_is_rejected(action: TestMutationAction, fixture: impl FnOnce(&Path)) {
    let (_temporary, store) = test_store();
    let source = store
        .create(name("source"), PathBuf::from("/bin/sh"))
        .expect("create source");
    let relative = Path::new("race-entry");
    fixture(&source.home().join(relative));
    let mutation = TestMutation::new(&source.home(), relative, action);
    let applied = mutation.clone();
    let error = store
        .clone_space_with_mutation(&name("source"), name("copy"), mutation, None)
        .expect_err("entry replacement must fail");
    assert!(applied.was_applied(), "hostile-source mutation must run");
    assert_eq!(error.kind(), ErrorKind::CorruptState);
    assert!(error.message().contains("source entry changed during clone"));
    assert!(!store.root().join("spaces/copy").exists());
    let entries = fs::read_dir(store.root().join("spaces")).expect("read spaces");
    assert!(
        entries
            .filter_map(std::result::Result::ok)
            .all(|entry| { !entry.file_name().to_string_lossy().starts_with(".creating-") })
    );
}

#[test]
fn replaced_regular_file_is_rejected_by_descriptor_identity() {
    assert_replaced_entry_is_rejected(TestMutationAction::ReplaceRegular, |path| {
        fs::write(path, b"original").expect("create file fixture");
    });
}

#[test]
fn replaced_directory_is_rejected_by_descriptor_identity() {
    assert_replaced_entry_is_rejected(TestMutationAction::ReplaceDirectory, |path| {
        fs::create_dir(path).expect("create directory fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("set directory fixture mode");
    });
}

#[test]
fn replaced_symlink_is_rejected_by_descriptor_identity() {
    assert_replaced_entry_is_rejected(TestMutationAction::ReplaceSymlink, |path| {
        symlink("original", path).expect("create link fixture");
    });
}

#[test]
fn deleted_source_entry_has_a_clone_specific_diagnostic() {
    assert_replaced_entry_is_rejected(TestMutationAction::DeleteRegular, |path| {
        fs::write(path, b"original").expect("create deleted-file fixture");
    });
}

#[test]
fn preview_of_an_uninitialized_store_reports_the_missing_space() {
    let (_temporary, store) = test_store();
    let error = store
        .clone_plan(&name("source"), &name("copy"), false)
        .expect_err("uninitialized store has no source");
    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert!(error.message().contains("space 'source' does not exist"));
    assert!(!store.root().exists());
}

#[test]
fn an_existing_destination_is_never_replaced() {
    let (_temporary, store) = test_store();
    store
        .create(name("source"), PathBuf::from("/bin/sh"))
        .expect("create source");
    let destination = store
        .create(name("copy"), PathBuf::from("/bin/sh"))
        .expect("create destination");
    fs::write(destination.home().join("proof"), b"destination").expect("write destination proof");
    let error = store
        .clone_space(&name("source"), name("copy"), false)
        .expect_err("destination collision must fail");
    assert_eq!(error.kind(), ErrorKind::AlreadyExists);
    assert_eq!(
        fs::read(destination.home().join("proof")).expect("read destination proof"),
        b"destination"
    );
}

#[test]
fn a_file_growing_after_stat_is_still_bounded_during_copy() {
    let (_temporary, store) = test_store();
    let source = store
        .create(name("source"), PathBuf::from("/bin/sh"))
        .expect("create source");
    let relative = Path::new("!growing");
    fs::write(source.home().join(relative), b"x").expect("create growing file");
    let mutation = TestMutation::new(&source.home(), relative, TestMutationAction::GrowRegular { bytes: 2 });
    let applied = mutation.clone();
    let error = store
        .clone_space_with_mutation(
            &name("source"),
            name("copy"),
            mutation,
            Some(CloneLimits {
                file_bytes: 2,
                ..CloneLimits::ALPHA
            }),
        )
        .expect_err("growth beyond the limit must fail");
    assert!(applied.was_applied(), "growth mutation must run after open");
    assert_eq!(error.kind(), ErrorKind::ResourceLimit);
    assert!(error.message().contains("regular-file bytes"));
    assert!(error.message().contains("!growing"));
    assert!(!store.root().join("spaces/copy").exists());
}

#[test]
fn one_wide_directory_is_bounded_before_unlimited_collection() {
    let (_temporary, store) = test_store();
    let source = store
        .create(name("source"), PathBuf::from("/bin/sh"))
        .expect("create source");
    let baseline = store
        .clone_plan(&name("source"), &name("baseline"), false)
        .expect("baseline plan")
        .counts
        .entries;
    let wide = source.home().join("zz-wide");
    fs::create_dir(&wide).expect("create wide directory");
    for index in 0..5 {
        fs::write(wide.join(format!("entry-{index}")), b"x").expect("write wide fixture");
    }
    let error = store
        .clone_plan_with_limits(
            &name("source"),
            &name("copy"),
            CloneLimits {
                entries: baseline + 3,
                ..CloneLimits::ALPHA
            },
        )
        .expect_err("wide directory must hit the entry limit while listing");
    assert_eq!(error.kind(), ErrorKind::ResourceLimit);
    assert!(error.message().contains("entry count"));
}

#[test]
fn cache_root_is_recreated_even_when_the_source_root_is_a_link() {
    let (_temporary, store) = test_store();
    let source = store
        .create(name("source"), PathBuf::from("/bin/sh"))
        .expect("create source");
    fs::remove_dir(source.home().join(".cache")).expect("remove empty cache");
    symlink(".local/share", source.home().join(".cache")).expect("link cache root");

    let report = store
        .clone_space(&name("source"), name("copy"), false)
        .expect("clone source");
    assert_eq!(report.exclusions.cache_roots, 1);
    let cache = store.open(&name("copy")).expect("open copy").home().join(".cache");
    assert!(fs::symlink_metadata(cache).expect("cache metadata").is_dir());
}

#[test]
fn cache_inclusion_and_sparse_logical_length_are_explicit() {
    let (_temporary, store) = test_store();
    let source = create_workspace(&store, "source");
    fs::write(source.home().join(".cache/derived"), b"cache").expect("write cache");
    let sparse = File::create(source.home().join("sparse.bin")).expect("create sparse file");
    sparse.set_len(1_048_576).expect("size sparse file");

    let preview = store
        .clone_plan(&name("source"), &name("copy"), true)
        .expect("preview with cache");
    assert_eq!(preview.exclusions.cache_roots, 0);
    assert!(preview.counts.logical_bytes >= 1_048_581);
    store
        .clone_space(&name("source"), name("copy"), true)
        .expect("clone with cache");
    let copy = store.open(&name("copy")).expect("open clone");
    assert_eq!(
        fs::read(copy.home().join(".cache/derived")).expect("read cache"),
        b"cache"
    );
    assert_eq!(
        fs::metadata(copy.home().join("sparse.bin"))
            .expect("sparse metadata")
            .len(),
        1_048_576
    );
}

#[test]
fn held_activity_lease_blocks_preview_with_precise_error_kind() {
    let (_temporary, store) = test_store();
    let source = store
        .create(name("source"), PathBuf::from("/bin/sh"))
        .expect("create source");
    let _lease = store.lease(&source).expect("hold shared lease");
    let error = store
        .clone_plan(&name("source"), &name("copy"), false)
        .expect_err("active source must fail");
    assert_eq!(error.kind(), ErrorKind::SpaceActive);
}

#[test]
fn escaping_links_fail_without_published_or_staged_state() {
    let (_temporary, store) = test_store();
    let source = store
        .create(name("source"), PathBuf::from("/bin/sh"))
        .expect("create source");
    let read_only = source.home().join("a-read-only");
    fs::create_dir(&read_only).expect("create read-only directory");
    fs::write(read_only.join("state"), b"state").expect("write state");
    fs::set_permissions(&read_only, fs::Permissions::from_mode(0o500)).expect("make directory read-only");
    symlink("../host-secret", source.home().join("z-escape")).expect("create escaping link");

    let error = store
        .clone_space(&name("source"), name("copy"), false)
        .expect_err("escaping link must fail");
    assert_eq!(error.kind(), ErrorKind::CorruptState);
    assert!(!store.root().join("spaces/copy").exists());
    let entries = fs::read_dir(store.root().join("spaces")).expect("read spaces");
    assert!(
        entries
            .filter_map(std::result::Result::ok)
            .all(|entry| !entry.file_name().to_string_lossy().starts_with(".creating-"))
    );
    assert_eq!(
        fs::metadata(read_only).expect("source unchanged").permissions().mode() & 0o777,
        0o500
    );
}

#[test]
fn unreadable_source_is_never_repaired_and_errors_are_presentation_safe() {
    if Uid::effective().is_root() {
        return;
    }
    let (_temporary, store) = test_store();
    let source = store
        .create(name("source"), PathBuf::from("/bin/sh"))
        .expect("create source");
    let unreadable = source.home().join("\u{1b}[31m\nprivate");
    fs::create_dir(&unreadable).expect("create unreadable directory");
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).expect("remove source access");

    let error = store
        .clone_plan(&name("source"), &name("copy"), false)
        .expect_err("unreadable source must fail");
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o700)).expect("restore fixture access");
    assert_eq!(error.kind(), ErrorKind::System);
    assert!(!error.message().contains('\u{1b}'));
    assert!(!error.message().contains('\n'));
    assert!(error.message().contains("\\u{1b}"));
    assert!(
        error
            .hint()
            .is_some_and(|hint| hint.contains("never changes source permissions"))
    );
    assert!(!store.root().join("spaces/copy").exists());
}

#[test]
fn absolute_links_fail_closed() {
    let (_temporary, store) = test_store();
    let source = store
        .create(name("source"), PathBuf::from("/bin/sh"))
        .expect("create source");
    symlink("/etc/passwd", source.home().join("absolute")).expect("create absolute link");
    let error = store
        .clone_plan(&name("source"), &name("copy"), false)
        .expect_err("absolute link must fail");
    assert_eq!(error.kind(), ErrorKind::CorruptState);
    assert!(error.message().contains("escapes the source home"));
}

#[test]
fn profile_clone_stays_schema_one_with_fresh_creation_time() {
    let (_temporary, store) = test_store();
    let source = store
        .create(name("source"), PathBuf::from("/bin/sh"))
        .expect("create source");
    let report = store
        .clone_space(&name("source"), name("copy"), false)
        .expect("clone profile");
    let copy = store.open(&name("copy")).expect("open clone");
    assert_eq!(copy.layout(), SpaceLayout::Profile);
    assert!(copy.id().is_none());
    assert!(copy.manifest().created_unix_ms >= source.manifest().created_unix_ms);
    assert!(report.destination_space_id.is_none());
}

#[test]
fn injected_transaction_failures_publish_nothing_or_one_complete_space() {
    let (_temporary, store) = test_store();
    let source = store
        .create(name("source"), PathBuf::from("/bin/sh"))
        .expect("create source");
    fs::write(source.home().join("proof"), b"state").expect("write proof");

    for (index, abort) in [
        LifecycleAbort::BeforeCopy,
        LifecycleAbort::MidCopy,
        LifecycleAbort::BeforeIdentityRecheck,
        LifecycleAbort::BeforePublish,
    ]
    .into_iter()
    .enumerate()
    {
        let destination = name(&format!("failed{index}"));
        let error = store
            .clone_space_with_abort(&name("source"), destination.clone(), abort)
            .expect_err("injected pre-publish failure");
        assert_eq!(error.kind(), ErrorKind::System);
        assert!(!store.root().join("spaces").join(destination.as_str()).exists());
    }

    let error = store
        .clone_space_with_abort(&name("source"), name("published"), LifecycleAbort::AfterPublish)
        .expect_err("injected post-publish failure");
    assert_eq!(error.kind(), ErrorKind::System);
    let published = store.open(&name("published")).expect("published clone is complete");
    assert_eq!(fs::read(published.home().join("proof")).expect("read proof"), b"state");
    let entries = fs::read_dir(store.root().join("spaces")).expect("read spaces");
    assert!(
        entries
            .filter_map(std::result::Result::ok)
            .all(|entry| !entry.file_name().to_string_lossy().starts_with(".creating-"))
    );
}

#[test]
fn every_declared_resource_limit_fails_closed() {
    let (_temporary, store) = test_store();
    let source = store
        .create(name("source"), PathBuf::from("/bin/sh"))
        .expect("create source");
    symlink("target", source.home().join("zz-link")).expect("create link");
    let cases = [
        (
            "entry count",
            CloneLimits {
                entries: 0,
                ..CloneLimits::ALPHA
            },
        ),
        (
            "logical bytes",
            CloneLimits {
                logical_bytes: 1,
                ..CloneLimits::ALPHA
            },
        ),
        (
            "regular-file bytes",
            CloneLimits {
                file_bytes: 1,
                ..CloneLimits::ALPHA
            },
        ),
        (
            "directory depth",
            CloneLimits {
                depth: 0,
                ..CloneLimits::ALPHA
            },
        ),
        (
            "path-component bytes",
            CloneLimits {
                component_bytes: 1,
                ..CloneLimits::ALPHA
            },
        ),
        (
            "relative-path bytes",
            CloneLimits {
                relative_path_bytes: 1,
                ..CloneLimits::ALPHA
            },
        ),
        (
            "symbolic-link target bytes",
            CloneLimits {
                symlink_target_bytes: 1,
                ..CloneLimits::ALPHA
            },
        ),
    ];
    for (index, (label, limits)) in cases.into_iter().enumerate() {
        let destination = name(&format!("limit{index}"));
        let error = store
            .clone_plan_with_limits(&name("source"), &destination, limits)
            .expect_err("limit must fail");
        assert_eq!(error.kind(), ErrorKind::ResourceLimit);
        assert!(error.message().contains(label), "{}", error.message());
        assert!(!store.root().join("spaces").join(destination.as_str()).exists());
    }

    let error = store
        .clone_space_with_limits(
            &name("source"),
            name("execution-limit"),
            CloneLimits {
                entries: 0,
                ..CloneLimits::ALPHA
            },
        )
        .expect_err("executing limit must fail");
    assert_eq!(error.kind(), ErrorKind::ResourceLimit);
    assert!(!store.root().join("spaces/execution-limit").exists());
}
