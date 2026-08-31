//! Strict root-format marker parsing and publication.

use super::{StoreLayout, StoreLayoutDiagnosis};
use crate::store::unique_suffix;
use crate::store_policy::validate_store_root;
use crate::text::escape_untrusted_text_bounded_bytes;
use crate::{ErrorKind, QuartersError, Result};
use nix::dir::Dir;
use nix::fcntl::{AtFlags, FcntlArg, OFlag, fcntl};
use nix::sys::stat::{Mode, fstat, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const MARKER_FILE: &str = ".quarters-store.json";
const MIGRATION_FILE: &str = ".quarters-store-migration.json";
const STAGING_PREFIX: &str = ".quarters-store-staging-";
const STAGING_SUFFIX: &str = ".tmp";
const SCHEMA_VERSION: u32 = 1;
const MAX_MARKER_BYTES: u64 = 4 * 1_024;
const MAX_MARKER_REPLACEMENT_READS: usize = 8;
const MAX_ROOT_ENTRIES: usize = 1_024;
const MAX_DIAGNOSED_STAGING_ENTRIES: usize = 16;

#[derive(Default)]
struct StagingDiagnosis {
    entries: Vec<String>,
    at_least: usize,
    error: Option<QuartersError>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RootFormat {
    Visible,
    Dotted,
}

#[derive(Deserialize)]
struct MarkerHeader {
    schema_version: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreMarker {
    schema_version: u32,
    root_format: RootFormat,
    writer_version: String,
}

pub(super) fn resolve(root: &Path) -> Result<StoreLayout> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(StoreLayout::visible(root)),
        Err(error) => return Err(QuartersError::io("inspect Quarters root", root, error)),
    };
    validate_store_root(root, &metadata)?;
    reject_active_migration(root)?;
    let visible = category_presence(root, "spaces", "trash")?;
    let dotted = category_presence(root, ".spaces", ".trash")?;
    let marker = read_marker(root)?;
    match marker {
        None if dotted => Err(layout_error(
            "dotted store directories exist without an authoritative root-format marker",
        )),
        Some(RootFormat::Visible) if dotted => Err(layout_error(
            "the visible root-format marker conflicts with dotted store directories",
        )),
        None | Some(RootFormat::Visible) => Ok(StoreLayout::visible(root)),
        Some(RootFormat::Dotted) if visible => Err(layout_error(
            "the dotted root-format marker conflicts with visible store directories",
        )),
        Some(RootFormat::Dotted) => Ok(StoreLayout::dotted(root)),
    }
}

pub(super) fn diagnose(root: &Path) -> StoreLayoutDiagnosis {
    let root_metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return absent_diagnosis(),
        Err(error) => {
            return failed_diagnosis(
                &QuartersError::io("inspect Quarters root for diagnosis", root, error),
                root,
                "unavailable",
                false,
                false,
                false,
                StagingDiagnosis::default(),
            );
        }
    };
    if let Err(error) = validate_store_root(root, &root_metadata) {
        return failed_diagnosis(
            &error,
            root,
            "unavailable",
            false,
            false,
            false,
            StagingDiagnosis::default(),
        );
    }
    let visible_entries = raw_category_presence(root, "spaces", "trash");
    let dotted_entries = raw_category_presence(root, ".spaces", ".trash");
    let migration_marker = fs::symlink_metadata(root.join(MIGRATION_FILE)).is_ok();
    let marker = match read_marker(root) {
        Ok(None) => "absent",
        Ok(Some(RootFormat::Visible)) => "visible",
        Ok(Some(RootFormat::Dotted)) => "dotted",
        Err(error) if error.kind() == ErrorKind::Unsupported => "newer-or-unsupported",
        Err(_) => "invalid",
    };
    let staging = diagnose_staging(root);
    let interrupted = interrupted_publication_present(root).unwrap_or(false);
    match resolve(root) {
        Ok(layout) => {
            let staging_error_kind = staging.error.as_ref().map(|error| error.kind().as_str().to_owned());
            let staging_issue = staging
                .error
                .as_ref()
                .map(|error| diagnosis_text(error.message(), root));
            let staging_suffix = if staging.error.is_some() {
                "-with-staging-issue"
            } else {
                ""
            };
            StoreLayoutDiagnosis {
                state: format!(
                    "{}{staging_suffix}",
                    if interrupted {
                        "interrupted-publication"
                    } else if marker == "absent" {
                        "unmarked-visible"
                    } else if layout.root_format() == RootFormat::Visible {
                        "marked-visible"
                    } else {
                        "marked-dotted-read-only"
                    }
                ),
                root_format: Some(root_format_text(layout.root_format()).to_owned()),
                writable: layout.root_format() == RootFormat::Visible,
                interrupted_publication: interrupted,
                marker: marker.to_owned(),
                category_entries: category_entries(visible_entries, dotted_entries),
                migration_marker,
                staging_entries: staging.entries,
                staging_entries_at_least: staging.at_least,
                staging_error_kind,
                staging_issue,
                error_kind: None,
                issue: None,
                hint: interrupted.then(|| {
                    "run 'quarters recover --confirm stale-state' to finish exact root-format staging cleanup"
                        .to_owned()
                }),
            }
        }
        Err(error) => failed_diagnosis(
            &error,
            root,
            marker,
            visible_entries,
            dotted_entries,
            migration_marker,
            staging,
        ),
    }
}

fn absent_diagnosis() -> StoreLayoutDiagnosis {
    StoreLayoutDiagnosis {
        state: "absent".to_owned(),
        root_format: Some("visible".to_owned()),
        writable: true,
        interrupted_publication: false,
        marker: "absent".to_owned(),
        category_entries: Vec::new(),
        migration_marker: false,
        staging_entries: Vec::new(),
        staging_entries_at_least: 0,
        staging_error_kind: None,
        staging_issue: None,
        error_kind: None,
        issue: None,
        hint: None,
    }
}

fn failed_diagnosis(
    error: &QuartersError,
    root: &Path,
    marker: &str,
    visible_entries: bool,
    dotted_entries: bool,
    migration_marker: bool,
    staging: StagingDiagnosis,
) -> StoreLayoutDiagnosis {
    let staging_error_kind = staging.error.as_ref().map(|error| error.kind().as_str().to_owned());
    let staging_issue = staging
        .error
        .as_ref()
        .map(|error| diagnosis_text(error.message(), root));
    StoreLayoutDiagnosis {
        state: if error.kind() == ErrorKind::SpaceActive {
            "active-migration"
        } else if error.kind() == ErrorKind::Unsupported {
            "newer-format"
        } else if visible_entries && dotted_entries {
            "ambiguous-dual-layout"
        } else {
            "invalid"
        }
        .to_owned(),
        root_format: None,
        writable: false,
        interrupted_publication: false,
        marker: marker.to_owned(),
        category_entries: category_entries(visible_entries, dotted_entries),
        migration_marker,
        staging_entries: staging.entries,
        staging_entries_at_least: staging.at_least,
        staging_error_kind,
        staging_issue,
        error_kind: Some(error.kind().as_str().to_owned()),
        issue: Some(diagnosis_text(error.message(), root)),
        hint: error.hint().map(|hint| diagnosis_text(hint, root)),
    }
}

pub(super) fn attempt_visible_marker(root: &Path) -> Result<()> {
    recover_interrupted_publication(root)?;
    reclaim_safe_staging(root)?;
    if read_marker(root)?.is_some() {
        return Ok(());
    }
    let temporary = root.join(format!("{STAGING_PREFIX}{}{STAGING_SUFFIX}", unique_suffix()?));
    let staging = create_visible_staging(root, &temporary)?;
    match publish_visible_marker(root, &temporary, &staging) {
        Ok(()) => Ok(()),
        Err(error) => match marker_exists(root) {
            Ok(true) => Err(error),
            Ok(false) => match unlink_exact(root, temporary.file_name().unwrap_or_default(), &staging) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(QuartersError::new(
                    error.kind(),
                    "root-format publication failed and its exact staging file could not be reclaimed",
                )
                .with_source(cleanup)),
            },
            Err(probe) => Err(error.with_hint(format!(
                "marker presence could not be confirmed after publication failed: {}",
                probe.message()
            ))),
        },
    }
}

pub(super) fn dotted_read_only_error() -> QuartersError {
    QuartersError::new(
        ErrorKind::Unsupported,
        "this Quarters build opens dotted-format stores for inspection only",
    )
    .with_hint("no released Quarters version currently mutates dotted stores; do not create visible store directories")
}

fn read_marker(root: &Path) -> Result<Option<RootFormat>> {
    for _attempt in 0..MAX_MARKER_REPLACEMENT_READS {
        match read_marker_once(root)? {
            MarkerRead::Resolved(format) => return Ok(format),
            MarkerRead::PublicationConverged => std::thread::yield_now(),
        }
    }
    Err(QuartersError::new(
        ErrorKind::ResourceLimit,
        "the root-format marker kept changing during a bounded read",
    ))
}

fn read_marker_once(root: &Path) -> Result<MarkerRead> {
    let path = root.join(MARKER_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(MarkerRead::Resolved(None));
        }
        Err(error) => return Err(QuartersError::io("inspect root-format marker", &path, error)),
    };
    let expected_links = if metadata.nlink() == 2 { 2 } else { 1 };
    validate_marker_metadata(&path, &metadata, expected_links)?;
    if expected_links == 2 && matching_publication_staging(root, &metadata)?.is_none() {
        if publication_converged(&path, &metadata)? {
            return Ok(MarkerRead::PublicationConverged);
        }
        return Err(layout_error(
            "the root-format marker has an unexplained second filesystem link",
        ));
    }
    let bytes = match read_bounded(&path, metadata.len(), expected_links) {
        Ok(bytes) => bytes,
        Err(_error) if expected_links == 2 && publication_converged(&path, &metadata)? => {
            return Ok(MarkerRead::PublicationConverged);
        }
        Err(error) => return Err(error),
    };
    let format = parse_marker(&bytes)?;
    if expected_links == 2 && format != RootFormat::Visible {
        return Err(layout_error(
            "the interrupted root-format publication is not a visible-format marker",
        ));
    }
    Ok(MarkerRead::Resolved(Some(format)))
}

fn publication_converged(path: &Path, previous: &fs::Metadata) -> Result<bool> {
    let current = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(QuartersError::io("reinspect root-format publication", path, error)),
    };
    if current.dev() != previous.dev() || current.ino() != previous.ino() || current.nlink() != 1 {
        return Ok(false);
    }
    validate_marker_metadata(path, &current, 1)?;
    Ok(true)
}

enum MarkerRead {
    Resolved(Option<RootFormat>),
    PublicationConverged,
}

fn parse_marker(bytes: &[u8]) -> Result<RootFormat> {
    let header: MarkerHeader = serde_json::from_slice(bytes).map_err(|error| {
        QuartersError::new(ErrorKind::CorruptState, "the root-format marker header is invalid").with_source(error)
    })?;
    if header.schema_version > SCHEMA_VERSION {
        return Err(QuartersError::new(
            ErrorKind::Unsupported,
            format!(
                "the store root-format schema {} is newer than this Quarters build supports",
                header.schema_version
            ),
        )
        .with_hint("upgrade Quarters before opening this store; do not rewrite its format marker"));
    }
    let marker: StoreMarker = serde_json::from_slice(bytes).map_err(|error| {
        QuartersError::new(ErrorKind::CorruptState, "the root-format marker is invalid").with_source(error)
    })?;
    if marker.schema_version != SCHEMA_VERSION || !valid_writer_version(&marker.writer_version) {
        return Err(layout_error("the root-format marker has unsupported metadata"));
    }
    Ok(marker.root_format)
}

fn validate_marker_metadata(path: &Path, metadata: &fs::Metadata, expected_links: u64) -> Result<()> {
    let current_uid = nix::unistd::Uid::current().as_raw();
    if metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_uid
        && metadata.nlink() == expected_links
        && metadata.mode() & 0o022 == 0
    {
        return Ok(());
    }
    Err(layout_error(&format!(
        "the root-format marker is not a protected current-user file: {}",
        path.display()
    )))
}

fn read_bounded(path: &Path, length: u64, expected_links: u64) -> Result<Vec<u8>> {
    if length > MAX_MARKER_BYTES {
        return Err(QuartersError::new(
            ErrorKind::ResourceLimit,
            "the root-format marker exceeds 4096 bytes",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| QuartersError::io("open root-format marker", path, error))?;
    let opened = file
        .metadata()
        .map_err(|error| QuartersError::io("inspect opened root-format marker", path, error))?;
    validate_marker_metadata(path, &opened, expected_links)?;
    let flags = fcntl(&file, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_truncate)
        .map_err(|error| {
            QuartersError::new(ErrorKind::System, "could not inspect root-format marker flags").with_source(error)
        })?;
    fcntl(&file, FcntlArg::F_SETFL(flags - OFlag::O_NONBLOCK)).map_err(|error| {
        QuartersError::new(
            ErrorKind::System,
            "could not prepare the root-format marker for reading",
        )
        .with_source(error)
    })?;
    let mut bytes = Vec::with_capacity(usize::try_from(length).unwrap_or(0));
    file.take(MAX_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| QuartersError::io("read root-format marker", path, error))?;
    if bytes.len() as u64 > MAX_MARKER_BYTES {
        return Err(QuartersError::new(
            ErrorKind::ResourceLimit,
            "the root-format marker grew beyond 4096 bytes while it was read",
        ));
    }
    Ok(bytes)
}

fn create_visible_staging(root: &Path, temporary: &Path) -> Result<fs::Metadata> {
    let marker = StoreMarker {
        schema_version: SCHEMA_VERSION,
        root_format: RootFormat::Visible,
        writer_version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    let bytes = serde_json::to_vec_pretty(&marker).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not encode the root-format marker").with_source(error)
    })?;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let mut file = options
        .open(temporary)
        .map_err(|error| QuartersError::io("create root-format staging file", temporary, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| QuartersError::io("inspect created root-format staging file", temporary, error))?;
    validate_marker_metadata(temporary, &metadata, 1)?;
    let result = file
        .write_all(&bytes)
        .map_err(|error| QuartersError::io("write root-format staging file", temporary, error))
        .and_then(|()| {
            file.sync_all()
                .map_err(|error| QuartersError::io("sync root-format staging file", temporary, error))
        });
    drop(file);
    if let Err(error) = result {
        return match unlink_exact(root, temporary.file_name().unwrap_or_default(), &metadata) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(QuartersError::new(
                error.kind(),
                "root-format staging failed and its exact file could not be reclaimed",
            )
            .with_source(cleanup)),
        };
    }
    Ok(metadata)
}

fn publish_visible_marker(root: &Path, temporary: &Path, staging: &fs::Metadata) -> Result<()> {
    let current = fs::symlink_metadata(temporary)
        .map_err(|error| QuartersError::io("reinspect root-format staging file", temporary, error))?;
    validate_marker_metadata(temporary, &current, 1)?;
    if current.dev() != staging.dev() || current.ino() != staging.ino() {
        return Err(layout_error("the root-format staging file changed before publication"));
    }
    let destination = root.join(MARKER_FILE);
    fs::hard_link(temporary, &destination)
        .map_err(|error| QuartersError::io("publish root-format marker", &destination, error))?;
    unlink_exact(root, temporary.file_name().unwrap_or_default(), staging)?;
    sync_root(root)?;
    match read_marker(root)? {
        Some(RootFormat::Visible) => Ok(()),
        _ => Err(layout_error(
            "the published root-format marker did not verify as visible",
        )),
    }
}

fn reclaim_safe_staging(root: &Path) -> Result<()> {
    let mut observed = 0_usize;
    for entry in fs::read_dir(root).map_err(|error| QuartersError::io("scan root-format staging", root, error))? {
        observed = observed.saturating_add(1);
        if observed > MAX_ROOT_ENTRIES {
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                "the Quarters root exceeds the bounded root-format staging scan",
            ));
        }
        let entry = entry.map_err(|error| QuartersError::io("read root-format staging entry", root, error))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(STAGING_PREFIX) {
            continue;
        }
        if !valid_staging_name(name) {
            return Err(layout_error("a reserved root-format staging entry has an invalid name"));
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| QuartersError::io("inspect root-format staging", &path, error))?;
        validate_marker_metadata(&path, &metadata, 1)?;
        unlink_exact(root, OsStr::new(name), &metadata)?;
    }
    Ok(())
}

fn valid_staging_name(name: &str) -> bool {
    name.strip_prefix(STAGING_PREFIX)
        .and_then(|value| value.strip_suffix(STAGING_SUFFIX))
        .is_some_and(valid_unique_suffix)
}

fn valid_unique_suffix(value: &str) -> bool {
    let mut components = value.split('-');
    let valid = components.by_ref().take(3).all(|component| {
        !component.is_empty() && component.len() <= 20 && component.bytes().all(|byte| byte.is_ascii_digit())
    });
    valid && value.matches('-').count() == 2 && components.next().is_none()
}

fn valid_writer_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

pub(super) fn recover_interrupted_publication(root: &Path) -> Result<()> {
    let marker_path = root.join(MARKER_FILE);
    let marker_metadata = match fs::symlink_metadata(&marker_path) {
        Ok(metadata) if metadata.nlink() == 1 => return Ok(()),
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(QuartersError::io(
                "inspect interrupted root-format marker",
                &marker_path,
                error,
            ));
        }
    };
    validate_marker_metadata(&marker_path, &marker_metadata, 2)?;
    let bytes = read_bounded(&marker_path, marker_metadata.len(), 2)?;
    if parse_marker(&bytes)? != RootFormat::Visible {
        return Err(layout_error(
            "an interrupted root-format publication did not contain a visible marker",
        ));
    }
    let Some(staging) = matching_publication_staging(root, &marker_metadata)? else {
        return Err(layout_error(
            "the root-format marker has an unexplained second filesystem link",
        ));
    };
    unlink_exact(root, staging.as_os_str(), &marker_metadata)?;
    sync_root(root)?;
    match read_marker(root)? {
        Some(RootFormat::Visible) => Ok(()),
        _ => Err(layout_error(
            "the recovered root-format marker did not verify as visible",
        )),
    }
}

fn matching_publication_staging(root: &Path, marker: &fs::Metadata) -> Result<Option<std::ffi::OsString>> {
    let mut observed = 0_usize;
    let mut matching = None;
    for entry in
        fs::read_dir(root).map_err(|error| QuartersError::io("scan interrupted root-format staging", root, error))?
    {
        observed = observed.saturating_add(1);
        if observed > MAX_ROOT_ENTRIES {
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                "the Quarters root exceeds the bounded interrupted-publication scan",
            ));
        }
        let entry = entry.map_err(|error| QuartersError::io("read interrupted root-format staging", root, error))?;
        let name = entry.file_name();
        let Some(text) = name.to_str() else { continue };
        if !valid_staging_name(text) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| QuartersError::io("inspect interrupted root-format staging", &entry.path(), error))?;
        if metadata.dev() == marker.dev() && metadata.ino() == marker.ino() {
            if matching.is_some() {
                return Err(layout_error(
                    "the interrupted root-format publication has multiple staging links",
                ));
            }
            matching = Some(name);
        }
    }
    Ok(matching)
}

fn unlink_exact(root: &Path, name: &OsStr, expected: &fs::Metadata) -> Result<()> {
    let root_metadata =
        fs::symlink_metadata(root).map_err(|error| QuartersError::io("reinspect Quarters root", root, error))?;
    validate_store_root(root, &root_metadata)?;
    let directory = Dir::open(
        root,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| QuartersError::new(ErrorKind::System, "could not retain the Quarters root").with_source(error))?;
    let held = fstat(&directory).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not inspect the retained Quarters root").with_source(error)
    })?;
    if device_number(held.st_dev) != metadata_device_number(&root_metadata) || held.st_ino != root_metadata.ino() {
        return Err(layout_error("the Quarters root changed during root-format cleanup"));
    }
    let current = fstatat(&directory, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not recheck root-format staging identity").with_source(error)
    })?;
    if device_number(current.st_dev) != metadata_device_number(expected) || current.st_ino != expected.ino() {
        return Err(layout_error("a root-format staging entry changed during cleanup"));
    }
    unlinkat(&directory, name, UnlinkatFlags::NoRemoveDir).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not remove exact root-format staging entry").with_source(error)
    })
}

fn sync_root(root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| QuartersError::io("inspect Quarters root before syncing", root, error))?;
    validate_store_root(root, &metadata)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(root)
        .map_err(|error| QuartersError::io("open Quarters root for syncing", root, error))?;
    directory
        .sync_all()
        .map_err(|error| QuartersError::io("sync Quarters root", root, error))
}

#[cfg(target_os = "linux")]
const fn device_number(value: nix::libc::dev_t) -> u64 {
    value
}

#[cfg(target_os = "macos")]
fn device_number(value: nix::libc::dev_t) -> u64 {
    u64::from(value.cast_unsigned())
}

fn metadata_device_number(metadata: &fs::Metadata) -> u64 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let native = metadata.dev() as nix::libc::dev_t;
    device_number(native)
}

fn reject_active_migration(root: &Path) -> Result<()> {
    let path = root.join(MIGRATION_FILE);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(QuartersError::new(
            ErrorKind::SpaceActive,
            "the store has an active root-format migration marker",
        )
        .with_hint("run 'quarters doctor' to inspect this unsupported marker; do not remove it by hand")),
        Err(error) => Err(QuartersError::io("inspect root-format migration marker", &path, error)),
    }
}

fn category_presence(root: &Path, first: &str, second: &str) -> Result<bool> {
    Ok(entry_exists(&root.join(first))? || entry_exists(&root.join(second))?)
}

fn raw_category_presence(root: &Path, first: &str, second: &str) -> bool {
    fs::symlink_metadata(root.join(first)).is_ok() || fs::symlink_metadata(root.join(second)).is_ok()
}

fn interrupted_publication_present(root: &Path) -> Result<bool> {
    let path = root.join(MARKER_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(QuartersError::io("inspect root-format publication state", &path, error)),
    };
    if metadata.nlink() != 2 {
        return Ok(false);
    }
    read_marker(root).map(|marker| marker.is_some())
}

fn diagnose_staging_metadata(root: &Path, path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect diagnosed root-format staging", path, error))?;
    if metadata.nlink() == 1 {
        return validate_marker_metadata(path, &metadata, 1);
    }
    validate_marker_metadata(path, &metadata, 2)?;
    let marker_path = root.join(MARKER_FILE);
    let marker = fs::symlink_metadata(&marker_path)
        .map_err(|error| QuartersError::io("inspect paired root-format marker", &marker_path, error))?;
    if marker.dev() != metadata.dev() || marker.ino() != metadata.ino() || read_marker(root)?.is_none() {
        return Err(layout_error(
            "a root-format staging entry has an unexplained second filesystem link",
        ));
    }
    Ok(())
}

fn diagnose_staging(root: &Path) -> StagingDiagnosis {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return StagingDiagnosis::default(),
        Err(error) => {
            return StagingDiagnosis {
                error: Some(QuartersError::io("scan root-format diagnosis", root, error)),
                ..StagingDiagnosis::default()
            };
        }
    };
    let mut scanned = 0_usize;
    let mut diagnosis = StagingDiagnosis::default();
    let mut first_issue = None;
    for entry in entries {
        scanned = scanned.saturating_add(1);
        if scanned > MAX_ROOT_ENTRIES {
            diagnosis.error = first_issue.or_else(|| {
                Some(QuartersError::new(
                    ErrorKind::ResourceLimit,
                    "the Quarters root exceeds the bounded root-format diagnosis",
                ))
            });
            return diagnosis;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                diagnosis.error = Some(
                    QuartersError::new(ErrorKind::System, "could not read a root-format diagnosis entry")
                        .with_source(error),
                );
                return diagnosis;
            }
        };
        let bytes = entry.file_name().as_bytes().to_vec();
        if bytes.starts_with(STAGING_PREFIX.as_bytes()) {
            diagnosis.at_least = diagnosis.at_least.saturating_add(1);
            if diagnosis.entries.len() < MAX_DIAGNOSED_STAGING_ENTRIES {
                diagnosis.entries.push(hex_name(&bytes));
            }
            let valid_name = std::str::from_utf8(&bytes).is_ok_and(valid_staging_name);
            if !valid_name && first_issue.is_none() {
                first_issue = Some(layout_error("a reserved root-format staging entry has an invalid name"));
            } else if valid_name && first_issue.is_none() {
                let path = entry.path();
                first_issue = diagnose_staging_metadata(root, &path).err();
            }
        }
    }
    diagnosis.error = first_issue;
    diagnosis
}

fn hex_name(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let retained = bytes.len().min(128);
    let mut encoded = String::with_capacity(4 + retained.saturating_mul(2) + 3);
    encoded.push_str("hex:");
    for byte in &bytes[..retained] {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    if retained < bytes.len() {
        encoded.push_str("...");
    }
    encoded
}

fn diagnosis_text(value: &str, root: &Path) -> String {
    let root = root.to_string_lossy();
    let redacted = value.replace(root.as_ref(), "<quarters-root>");
    escape_untrusted_text_bounded_bytes(&redacted, 512)
}

fn category_entries(visible: bool, dotted: bool) -> Vec<String> {
    let mut entries = Vec::with_capacity(2);
    if visible {
        entries.push("visible".to_owned());
    }
    if dotted {
        entries.push("dotted".to_owned());
    }
    entries
}

const fn root_format_text(format: RootFormat) -> &'static str {
    match format {
        RootFormat::Visible => "visible",
        RootFormat::Dotted => "dotted",
    }
}

fn marker_exists(root: &Path) -> Result<bool> {
    entry_exists(&root.join(MARKER_FILE))
}

fn entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(QuartersError::io("inspect store-format entry", path, error)),
    }
}

fn layout_error(message: &str) -> QuartersError {
    QuartersError::new(ErrorKind::CorruptState, message)
        .with_hint("run 'quarters doctor' for a non-mutating root-format diagnosis")
}

#[cfg(test)]
mod tests;
