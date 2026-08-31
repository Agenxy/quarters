#![allow(clippy::expect_used, clippy::panic)]

use super::*;
use crate::Store;
use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use std::fs::OpenOptions;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use tempfile::TempDir;

#[test]
fn missing_root_is_observed_without_materialization() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("store");
    let store = Store::new(root.clone()).expect("store");

    assert_eq!(store.layout().expect("layout").root_format(), RootFormat::Visible);
    assert!(!root.exists());
}

#[test]
fn unmarked_visible_store_remains_readable_and_writable() {
    let (_temporary, root, store) = visible_store();

    assert_eq!(store.layout().expect("layout").root_format(), RootFormat::Visible);
    let _mutation = store.begin_mutation().expect("unmarked visible mutation");
    assert!(!root.join(MARKER_FILE).exists());
}

#[test]
fn ensure_layout_publishes_a_protected_visible_marker() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("store");
    let store = Store::new(root.clone()).expect("store");

    store.ensure_layout().expect("ensure layout");

    let metadata = fs::symlink_metadata(root.join(MARKER_FILE)).expect("marker metadata");
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(read_marker(&root).expect("read marker"), Some(RootFormat::Visible));
}

#[test]
fn protected_restored_root_mode_remains_compatible() {
    let temporary = TempDir::new().expect("temporary directory");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755)).expect("set restored root mode");
    let store = Store::new(temporary.path().to_path_buf()).expect("store");

    store.ensure_layout().expect("ensure restored root layout");

    assert!(temporary.path().join(MARKER_FILE).is_file());
}

#[test]
fn marker_publication_failure_is_reported_without_breaking_visible_compatibility() {
    let (_temporary, root, store) = visible_store();
    protected_file(root.join(crate::store::OBSERVATION_LOCK_FILE), b"", 0o600);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).expect("make marker publication unavailable");

    let error = store.ensure_layout().expect_err("marker publication failure");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("restore test root");

    assert_eq!(error.kind(), ErrorKind::System);
    assert!(!root.join(MARKER_FILE).exists());
    let _mutation = store.begin_mutation().expect("unmarked mutation remains compatible");
}

#[test]
fn missing_trash_directory_does_not_block_an_unrelated_mutation() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = protected_dir(temporary.path().join("store"));
    protected_dir(root.join("spaces"));
    let store = Store::new(root.clone()).expect("store");

    let _mutation = store.begin_mutation().expect("visible mutation without trash");

    assert!(!root.join("trash").exists());
}

#[test]
fn an_existing_trash_directory_must_still_be_private() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = protected_dir(temporary.path().join("store"));
    protected_dir(root.join("spaces"));
    let trash = protected_dir(root.join("trash"));
    fs::set_permissions(&trash, fs::Permissions::from_mode(0o755)).expect("broaden trash fixture");
    let store = Store::new(root).expect("store");

    let Err(error) = store.begin_mutation() else {
        panic!("broad trash must fail closed");
    };

    assert_eq!(error.kind(), ErrorKind::CorruptState);
}

#[test]
fn dotted_marker_is_inspection_only() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = protected_dir(temporary.path().join("store"));
    protected_dir(root.join(".spaces"));
    protected_dir(root.join(".trash"));
    write_marker(&root, 1, "dotted", env!("CARGO_PKG_VERSION"), false);
    let store = Store::new(root).expect("store");

    assert!(store.list().expect("inspect dotted store").is_empty());
    assert_eq!(
        store
            .recovery_summary()
            .expect_err("missing dotted observation lock")
            .kind(),
        ErrorKind::ResourceLimit
    );
    assert!(!store.root().join(crate::store::OBSERVATION_LOCK_FILE).exists());
    let Err(error) = store.begin_mutation() else {
        panic!("dotted mutation must fail");
    };
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    assert_eq!(
        error.message(),
        "this Quarters build opens dotted-format stores for inspection only"
    );
}

#[test]
fn unmarked_dotted_and_dual_layouts_fail_closed() {
    let temporary = TempDir::new().expect("temporary directory");
    let dotted = protected_dir(temporary.path().join("dotted"));
    protected_dir(dotted.join(".spaces"));
    let dotted_store = Store::new(dotted).expect("store");
    assert_eq!(
        dotted_store.layout().expect_err("unmarked dotted").kind(),
        ErrorKind::CorruptState
    );

    let dual = protected_dir(temporary.path().join("dual"));
    protected_dir(dual.join("spaces"));
    protected_dir(dual.join(".spaces"));
    write_marker(&dual, 1, "visible", env!("CARGO_PKG_VERSION"), false);
    let dual_store = Store::new(dual).expect("store");
    assert_eq!(
        dual_store.layout().expect_err("dual layout").kind(),
        ErrorKind::CorruptState
    );
}

#[test]
fn newer_schema_wins_over_unknown_fields() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = protected_dir(temporary.path().join("store"));
    protected_file(
        root.join(MARKER_FILE),
        br#"{"schema_version":2,"future":{"unknown":true}}"#,
        0o600,
    );
    let error = resolve(&root).expect_err("newer schema");
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    assert!(error.message().contains("newer"));
}

#[test]
fn malformed_or_linked_markers_are_never_followed() {
    let temporary = TempDir::new().expect("temporary directory");
    let malformed = protected_dir(temporary.path().join("malformed"));
    protected_file(malformed.join(MARKER_FILE), b"{}", 0o600);
    assert_eq!(
        resolve(&malformed).expect_err("malformed marker").kind(),
        ErrorKind::CorruptState
    );
    let diagnosis = Store::new(malformed.clone())
        .expect("malformed store")
        .layout_diagnosis();
    assert!(
        diagnosis
            .issue
            .as_deref()
            .is_some_and(|issue| !issue.contains(&*malformed.to_string_lossy()))
    );

    let linked = protected_dir(temporary.path().join("linked"));
    let target = protected_file(temporary.path().join("target"), b"{}", 0o600);
    symlink(&target, linked.join(MARKER_FILE)).expect("marker symlink");
    assert_eq!(
        resolve(&linked).expect_err("linked marker").kind(),
        ErrorKind::CorruptState
    );
}

#[test]
fn nonblocking_marker_open_rejects_a_fifo_without_waiting_for_a_writer() {
    let temporary = TempDir::new().expect("temporary directory");
    let fifo = temporary.path().join("marker-fifo");
    mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).expect("create marker fifo");

    let error = read_bounded(&fifo, 0, 1).expect_err("a marker fifo must fail closed");

    assert_eq!(error.kind(), ErrorKind::CorruptState);
}

#[test]
fn migration_marker_blocks_even_an_empty_store() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = protected_dir(temporary.path().join("store"));
    protected_file(root.join(MIGRATION_FILE), b"{}", 0o600);

    let error = resolve(&root).expect_err("active migration");
    assert_eq!(error.kind(), ErrorKind::SpaceActive);
}

#[test]
fn orphan_staging_is_reclaimed_before_marker_publication() {
    let (_temporary, root, store) = visible_store();
    let staging = root.join(format!("{STAGING_PREFIX}1-1234567890123-1{STAGING_SUFFIX}"));
    protected_file(&staging, b"partial", 0o600);

    store.ensure_layout().expect("ensure layout");

    assert!(!staging.exists());
    assert!(root.join(MARKER_FILE).is_file());
}

#[test]
fn invalid_reserved_staging_is_preserved_and_refused() {
    let (_temporary, root, store) = visible_store();
    let staging = root.join(format!("{STAGING_PREFIX}not-ours{STAGING_SUFFIX}"));
    protected_file(&staging, b"partial", 0o600);

    let error = store.ensure_layout().expect_err("invalid staging must fail");

    assert_eq!(error.kind(), ErrorKind::CorruptState);
    assert!(staging.is_file());
    assert!(!root.join(MARKER_FILE).exists());
    let diagnosis = store.layout_diagnosis();
    assert_eq!(diagnosis.state, "unmarked-visible-with-staging-issue");
    assert_eq!(diagnosis.root_format.as_deref(), Some("visible"));
    assert!(diagnosis.writable);
    assert_eq!(diagnosis.error_kind, None);
    assert_eq!(diagnosis.staging_error_kind.as_deref(), Some("corrupt_state"));
    assert_eq!(diagnosis.staging_entries.len(), 1);
    assert!(diagnosis.staging_entries[0].starts_with("hex:"));
}

#[test]
fn orphan_staging_is_reclaimed_even_after_marker_publication() {
    let (_temporary, root, store) = visible_store();
    write_marker(&root, 1, "visible", env!("CARGO_PKG_VERSION"), false);
    let staging = root.join(format!("{STAGING_PREFIX}1-1234567890123-1{STAGING_SUFFIX}"));
    protected_file(&staging, b"orphan", 0o600);

    store.ensure_layout().expect("reclaim orphan beside marker");

    assert!(!staging.exists());
    assert_eq!(read_marker(&root).expect("read marker"), Some(RootFormat::Visible));
}

#[test]
fn interrupted_hard_link_publication_converges() {
    let (_temporary, root, store) = visible_store();
    let staging = root.join(format!("{STAGING_PREFIX}1-1234567890123-1{STAGING_SUFFIX}"));
    write_marker_at(&staging, 1, "visible", env!("CARGO_PKG_VERSION"), false);
    fs::hard_link(&staging, root.join(MARKER_FILE)).expect("publish marker link");

    assert_eq!(
        store.layout().expect("read interrupted marker").root_format(),
        RootFormat::Visible
    );
    let diagnosis = store.layout_diagnosis();
    assert_eq!(diagnosis.state, "interrupted-publication");
    assert!(diagnosis.interrupted_publication);
    assert_eq!(diagnosis.staging_error_kind, None);
    assert!(diagnosis.hint.as_deref().is_some_and(|hint| hint.contains("recover")));

    store.ensure_layout().expect("recover publication");

    assert!(!staging.exists());
    assert_eq!(fs::symlink_metadata(root.join(MARKER_FILE)).expect("marker").nlink(), 1);
}

#[test]
fn an_unlocked_reader_recognizes_exact_publication_convergence() {
    let (_temporary, root, _store) = visible_store();
    let staging = root.join(format!("{STAGING_PREFIX}1-1234567890123-1{STAGING_SUFFIX}"));
    write_marker_at(&staging, 1, "visible", env!("CARGO_PKG_VERSION"), false);
    let marker = root.join(MARKER_FILE);
    fs::hard_link(&staging, &marker).expect("publish marker link");
    let interrupted = fs::symlink_metadata(&marker).expect("interrupted marker");

    fs::remove_file(&staging).expect("finish publication");

    assert!(publication_converged(&marker, &interrupted).expect("recognize convergence"));
    assert_eq!(
        read_marker(&root).expect("read converged marker"),
        Some(RootFormat::Visible)
    );
}

#[test]
fn two_link_dotted_marker_cannot_impersonate_a_writer_publication() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = protected_dir(temporary.path().join("store"));
    protected_dir(root.join(".spaces"));
    protected_dir(root.join(".trash"));
    let staging = root.join(format!("{STAGING_PREFIX}1-1234567890123-1{STAGING_SUFFIX}"));
    write_marker_at(&staging, 1, "dotted", env!("CARGO_PKG_VERSION"), false);
    fs::hard_link(&staging, root.join(MARKER_FILE)).expect("publish counterfeit marker link");

    let error = resolve(&root).expect_err("dotted publication state must fail closed");

    assert_eq!(error.kind(), ErrorKind::CorruptState);
}

#[test]
fn migration_and_newer_schema_keep_priority_over_staging_issues() {
    let temporary = TempDir::new().expect("temporary directory");
    let migrating = protected_dir(temporary.path().join("migrating"));
    protected_file(migrating.join(MIGRATION_FILE), b"{}", 0o600);
    protected_file(
        migrating.join(format!("{STAGING_PREFIX}invalid{STAGING_SUFFIX}")),
        b"partial",
        0o600,
    );
    let migrating = Store::new(migrating).expect("migrating store").layout_diagnosis();
    assert_eq!(migrating.state, "active-migration");
    assert_eq!(migrating.error_kind.as_deref(), Some("space_active"));
    assert_eq!(migrating.staging_error_kind.as_deref(), Some("corrupt_state"));

    let newer = protected_dir(temporary.path().join("newer"));
    protected_file(newer.join(MARKER_FILE), br#"{"schema_version":2,"future":true}"#, 0o600);
    protected_file(
        newer.join(format!("{STAGING_PREFIX}invalid{STAGING_SUFFIX}")),
        b"partial",
        0o600,
    );
    let newer = Store::new(newer).expect("newer store").layout_diagnosis();
    assert_eq!(newer.state, "newer-format");
    assert_eq!(newer.error_kind.as_deref(), Some("unsupported"));
    assert_eq!(newer.staging_error_kind.as_deref(), Some("corrupt_state"));
}

#[test]
fn staging_diagnosis_is_itemized_but_response_bounded() {
    let (_temporary, root, store) = visible_store();
    for index in 0..20 {
        protected_file(
            root.join(format!("{STAGING_PREFIX}invalid-{index}{STAGING_SUFFIX}")),
            b"partial",
            0o600,
        );
    }

    let diagnosis = store.layout_diagnosis();

    assert_eq!(diagnosis.staging_entries.len(), MAX_DIAGNOSED_STAGING_ENTRIES);
    assert_eq!(diagnosis.staging_entries_at_least, 20);
}

#[test]
fn unexplained_second_marker_link_is_preserved() {
    let (_temporary, root, store) = visible_store();
    let marker = root.join(MARKER_FILE);
    write_marker_at(&marker, 1, "visible", env!("CARGO_PKG_VERSION"), false);
    let unexplained = root.join("unexplained-link");
    fs::hard_link(&marker, &unexplained).expect("second marker link");

    let error = store.ensure_layout().expect_err("unexplained link must fail");

    assert_eq!(error.kind(), ErrorKind::CorruptState);
    assert!(marker.is_file());
    assert!(unexplained.is_file());
}

#[test]
fn restored_read_only_marker_mode_is_accepted() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = protected_dir(temporary.path().join("store"));
    write_marker(&root, 1, "visible", env!("CARGO_PKG_VERSION"), true);

    assert_eq!(
        resolve(&root).expect("restored marker").root_format(),
        RootFormat::Visible
    );
}

fn visible_store() -> (TempDir, std::path::PathBuf, Store) {
    let temporary = TempDir::new().expect("temporary directory");
    let root = protected_dir(temporary.path().join("store"));
    protected_dir(root.join("spaces"));
    protected_dir(root.join("trash"));
    let store = Store::new(root.clone()).expect("store");
    (temporary, root, store)
}

fn protected_dir(path: impl AsRef<Path>) -> std::path::PathBuf {
    fs::create_dir(path.as_ref()).expect("create protected directory");
    fs::set_permissions(path.as_ref(), fs::Permissions::from_mode(0o700)).expect("protect directory");
    path.as_ref().to_path_buf()
}

fn protected_file(path: impl AsRef<Path>, bytes: &[u8], mode: u32) -> std::path::PathBuf {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut file = options.open(path.as_ref()).expect("create protected file");
    file.write_all(bytes).expect("write protected file");
    file.sync_all().expect("sync protected file");
    path.as_ref().to_path_buf()
}

fn write_marker(root: &Path, schema: u32, format: &str, writer: &str, restored: bool) {
    write_marker_at(&root.join(MARKER_FILE), schema, format, writer, restored);
}

fn write_marker_at(path: &Path, schema: u32, format: &str, writer: &str, restored: bool) {
    let bytes = format!("{{\"schema_version\":{schema},\"root_format\":\"{format}\",\"writer_version\":\"{writer}\"}}");
    protected_file(path, bytes.as_bytes(), if restored { 0o644 } else { 0o600 });
}
