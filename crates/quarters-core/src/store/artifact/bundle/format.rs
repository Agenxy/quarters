//! Versioned authenticated bundle framing.

use super::super::model::{valid_source_identity, validate_content_integrity};
use super::model::{BUNDLE_ALGORITHM, BUNDLE_VERSION, BundleHeader};
use crate::store::lifecycle::resolve_relative_link_target;
use crate::{ArtifactCounts, CloneLimits, ErrorKind, QuartersError, Result};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;

const MAGIC: &[u8; 16] = b"QTRS-BUNDLE\0\0\0\0\x01";
const HEADER_LIMIT: usize = 16 * 1_024;
const TAG_DIRECTORY: u8 = 0x44;
const TAG_FILE: u8 = 0x46;
const TAG_SYMLINK: u8 = 0x4c;
const TAG_TERMINAL: u8 = 0x00;
const KEY_DOMAIN: &str = "org.agenxy.quarters.bundle.authentication-key-v1";

pub(super) struct BundleWriter<'a> {
    file: &'a mut File,
    mac: blake3::Hasher,
}

impl<'a> BundleWriter<'a> {
    pub(super) fn begin(file: &'a mut File, key: &[u8; 32], header: &BundleHeader) -> Result<Self> {
        let bytes = serde_json::to_vec(header).map_err(|error| {
            QuartersError::new(ErrorKind::System, "could not encode authenticated bundle header").with_source(error)
        })?;
        if bytes.len() > HEADER_LIMIT {
            return Err(limit_error(
                "bundle header bytes",
                bytes.len() as u64,
                HEADER_LIMIT as u64,
            ));
        }
        let derived = blake3::derive_key(KEY_DOMAIN, key);
        let mut writer = Self {
            file,
            mac: blake3::Hasher::new_keyed(&derived),
        };
        writer.authenticated(MAGIC)?;
        writer.authenticated(&(u32::try_from(bytes.len()).map_err(conversion_error)?).to_be_bytes())?;
        writer.authenticated(&bytes)?;
        Ok(writer)
    }

    pub(super) fn directory(&mut self, path: &[u8], mode: u32) -> Result<()> {
        self.authenticated(&[TAG_DIRECTORY])?;
        self.path(path)?;
        self.authenticated(&(mode & 0o777).to_be_bytes())
    }

    pub(super) fn file(
        &mut self,
        path: &[u8],
        mode: u32,
        source: &mut File,
        length: u64,
        canonical: &mut blake3::Hasher,
    ) -> Result<()> {
        self.authenticated(&[TAG_FILE])?;
        self.path(path)?;
        self.authenticated(&(mode & 0o777).to_be_bytes())?;
        self.authenticated(&length.to_be_bytes())?;
        let mut remaining = length;
        let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
        while remaining > 0 {
            let take = usize::try_from(remaining.min(buffer.len() as u64)).map_err(conversion_error)?;
            source
                .read_exact(&mut buffer[..take])
                .map_err(|error| bundle_error("bundle source file changed or could not be read", error))?;
            self.authenticated(&buffer[..take])?;
            canonical.update(&buffer[..take]);
            remaining -= u64::try_from(take).map_err(conversion_error)?;
        }
        let mut extra = [0_u8; 1];
        if source
            .read(&mut extra)
            .map_err(|error| bundle_error("could not finish reading bundle source file", error))?
            != 0
        {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "bundle source file grew while it was exported",
            ));
        }
        Ok(())
    }

    pub(super) fn symlink(&mut self, path: &[u8], target: &[u8]) -> Result<()> {
        self.authenticated(&[TAG_SYMLINK])?;
        self.path(path)?;
        self.authenticated(&(u32::try_from(target.len()).map_err(conversion_error)?).to_be_bytes())?;
        self.authenticated(target)
    }

    pub(super) fn finish(mut self) -> Result<blake3::Hash> {
        self.authenticated(&[TAG_TERMINAL])?;
        let tag = self.mac.finalize();
        self.file
            .write_all(tag.as_bytes())
            .map_err(|error| bundle_error("could not write bundle authentication tag", error))?;
        Ok(tag)
    }

    fn path(&mut self, path: &[u8]) -> Result<()> {
        self.authenticated(&(u32::try_from(path.len()).map_err(conversion_error)?).to_be_bytes())?;
        self.authenticated(path)
    }

    fn authenticated(&mut self, bytes: &[u8]) -> Result<()> {
        self.file
            .write_all(bytes)
            .map_err(|error| bundle_error("could not write authenticated bundle", error))?;
        self.mac.update(bytes);
        Ok(())
    }
}

pub(super) trait EntrySink {
    fn close_directory(&mut self, path: &[u8]) -> Result<()>;
    fn directory(&mut self, path: &[u8], mode: u32) -> Result<()>;
    fn file_start(&mut self, path: &[u8], mode: u32, length: u64) -> Result<()>;
    fn file_chunk(&mut self, bytes: &[u8]) -> Result<()>;
    fn file_end(&mut self) -> Result<()>;
    fn symlink(&mut self, path: &[u8], target: &[u8]) -> Result<()>;
    fn finish(&mut self) -> Result<()>;
}

pub(super) struct NoopSink;

impl EntrySink for NoopSink {
    fn close_directory(&mut self, _path: &[u8]) -> Result<()> {
        Ok(())
    }
    fn directory(&mut self, _path: &[u8], _mode: u32) -> Result<()> {
        Ok(())
    }
    fn file_start(&mut self, _path: &[u8], _mode: u32, _length: u64) -> Result<()> {
        Ok(())
    }
    fn file_chunk(&mut self, _bytes: &[u8]) -> Result<()> {
        Ok(())
    }
    fn file_end(&mut self) -> Result<()> {
        Ok(())
    }
    fn symlink(&mut self, _path: &[u8], _target: &[u8]) -> Result<()> {
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        Ok(())
    }
}

pub(super) fn parse_bundle(
    file: &mut File,
    key: &[u8; 32],
    sink: &mut impl EntrySink,
) -> Result<(BundleHeader, blake3::Hash)> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| bundle_error("could not seek authenticated bundle", error))?;
    let derived = blake3::derive_key(KEY_DOMAIN, key);
    let mut reader = AuthReader {
        file,
        mac: blake3::Hasher::new_keyed(&derived),
    };
    let magic = reader.fixed::<16>()?;
    if &magic != MAGIC {
        return Err(bundle_input("bundle magic or format version is unsupported"));
    }
    let header_length = usize::try_from(u32::from_be_bytes(reader.fixed::<4>()?)).map_err(conversion_error)?;
    if header_length > HEADER_LIMIT {
        return Err(limit_error(
            "bundle header bytes",
            header_length as u64,
            HEADER_LIMIT as u64,
        ));
    }
    let header_bytes = reader.bytes(header_length)?;
    let mut state = ParseState::new();
    loop {
        let tag = reader.fixed::<1>()?[0];
        match tag {
            TAG_DIRECTORY => parse_directory(&mut reader, sink, &mut state)?,
            TAG_FILE => parse_file(&mut reader, sink, &mut state)?,
            TAG_SYMLINK => parse_symlink(&mut reader, sink, &mut state)?,
            TAG_TERMINAL => break,
            _ => return Err(bundle_input("bundle contains an unknown entry tag")),
        }
    }
    let actual = reader.mac.finalize();
    let expected = blake3::Hash::from_bytes(reader.plain_fixed::<32>()?);
    if actual != expected {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "bundle authentication failed; the key is wrong or the file changed",
        ));
    }
    if reader.plain_byte()? {
        return Err(bundle_input("bundle has trailing bytes after its authentication tag"));
    }
    let header: BundleHeader = serde_json::from_slice(&header_bytes).map_err(|error| {
        QuartersError::new(ErrorKind::CorruptState, "authenticated bundle header is invalid").with_source(error)
    })?;
    validate_header(&header, state.counts)?;
    for path in state.close_all() {
        sink.close_directory(&path)?;
    }
    sink.finish()?;
    Ok((header, expected))
}

fn parse_directory(reader: &mut AuthReader<'_>, sink: &mut impl EntrySink, state: &mut ParseState) -> Result<()> {
    let path = read_path(reader, sink, state, EntryKind::Directory)?;
    let mode = read_mode(reader)?;
    state.note_directory()?;
    sink.directory(&path, mode)
}

fn parse_file(reader: &mut AuthReader<'_>, sink: &mut impl EntrySink, state: &mut ParseState) -> Result<()> {
    let path = read_path(reader, sink, state, EntryKind::File)?;
    let mode = read_mode(reader)?;
    let length = u64::from_be_bytes(reader.fixed::<8>()?);
    state.note_file(length)?;
    sink.file_start(&path, mode, length)?;
    let mut remaining = length;
    let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64)).map_err(conversion_error)?;
        reader.read_into(&mut buffer[..take])?;
        sink.file_chunk(&buffer[..take])?;
        remaining -= u64::try_from(take).map_err(conversion_error)?;
    }
    sink.file_end()
}

fn parse_symlink(reader: &mut AuthReader<'_>, sink: &mut impl EntrySink, state: &mut ParseState) -> Result<()> {
    let path = read_path(reader, sink, state, EntryKind::Symlink)?;
    let length = usize::try_from(u32::from_be_bytes(reader.fixed::<4>()?)).map_err(conversion_error)?;
    if length as u64 > CloneLimits::ALPHA.symlink_target_bytes {
        return Err(limit_error(
            "bundle symlink-target bytes",
            length as u64,
            CloneLimits::ALPHA.symlink_target_bytes,
        ));
    }
    let target = reader.bytes(length)?;
    validate_link_target(&path, &target)?;
    state.note_symlink(length as u64)?;
    sink.symlink(&path, &target)
}

fn read_path(
    reader: &mut AuthReader<'_>,
    sink: &mut impl EntrySink,
    state: &mut ParseState,
    kind: EntryKind,
) -> Result<Vec<u8>> {
    let length = usize::try_from(u32::from_be_bytes(reader.fixed::<4>()?)).map_err(conversion_error)?;
    if length as u64 > CloneLimits::ALPHA.relative_path_bytes {
        return Err(limit_error(
            "bundle relative-path bytes",
            length as u64,
            CloneLimits::ALPHA.relative_path_bytes,
        ));
    }
    let path = reader.bytes(length)?;
    for closed in state.validate_path(&path, kind)? {
        sink.close_directory(&closed)?;
    }
    Ok(path)
}

fn read_mode(reader: &mut AuthReader<'_>) -> Result<u32> {
    let mode = u32::from_be_bytes(reader.fixed::<4>()?);
    if mode & !0o777 != 0 {
        return Err(bundle_input("bundle entry contains unsupported special mode bits"));
    }
    Ok(mode)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EntryKind {
    Directory,
    File,
    Symlink,
}

struct ParseState {
    counts: ArtifactCounts,
    directories: Vec<OpenDirectory>,
}

struct OpenDirectory {
    path: Vec<u8>,
    component: Vec<u8>,
    last_child: Option<Vec<u8>>,
}

impl ParseState {
    fn new() -> Self {
        Self {
            counts: ArtifactCounts::default(),
            directories: vec![OpenDirectory {
                path: Vec::new(),
                component: Vec::new(),
                last_child: None,
            }],
        }
    }

    fn validate_path(&mut self, path: &[u8], kind: EntryKind) -> Result<Vec<Vec<u8>>> {
        let components = split_path(path)?;
        let maximum = CloneLimits::ALPHA
            .depth
            .saturating_add(u32::from(kind != EntryKind::Directory));
        if u32::try_from(components.len()).map_err(conversion_error)? > maximum {
            return Err(bundle_input("bundle path violates component or depth limits"));
        }
        let parent = &components[..components.len() - 1];
        if parent.len() >= self.directories.len()
            || !parent
                .iter()
                .zip(self.directories.iter().skip(1))
                .all(|(component, directory)| component == &directory.component)
        {
            return Err(bundle_input("bundle entry appears outside the open directory path"));
        }
        let mut closed = Vec::new();
        while self.directories.len().saturating_sub(1) > parent.len() {
            let directory = self
                .directories
                .pop()
                .ok_or_else(|| bundle_input("bundle directory stack underflowed"))?;
            closed.push(directory.path);
        }
        let final_component = components.last().ok_or_else(|| bundle_input("bundle path is empty"))?;
        let directory = self
            .directories
            .last_mut()
            .ok_or_else(|| bundle_input("bundle root directory is absent"))?;
        if directory
            .last_child
            .as_ref()
            .is_some_and(|previous| final_component <= previous)
        {
            return Err(bundle_input("bundle siblings are not in strict byte order"));
        }
        directory.last_child = Some(final_component.clone());
        if kind == EntryKind::Directory {
            self.directories.try_reserve(1).map_err(|error| {
                QuartersError::new(ErrorKind::ResourceLimit, "could not reserve bundle directory stack")
                    .with_source(error)
            })?;
            self.directories.push(OpenDirectory {
                path: path.to_vec(),
                component: final_component.clone(),
                last_child: None,
            });
        }
        Ok(closed)
    }

    fn close_all(&mut self) -> Vec<Vec<u8>> {
        let mut closed = Vec::with_capacity(self.directories.len().saturating_sub(1));
        while self.directories.len() > 1 {
            if let Some(directory) = self.directories.pop() {
                closed.push(directory.path);
            }
        }
        closed
    }

    fn note_directory(&mut self) -> Result<()> {
        self.note_entry()?;
        self.counts.directories = self.counts.directories.saturating_add(1);
        Ok(())
    }

    fn note_file(&mut self, length: u64) -> Result<()> {
        if length > CloneLimits::ALPHA.file_bytes {
            return Err(limit_error("bundle file bytes", length, CloneLimits::ALPHA.file_bytes));
        }
        self.note_entry()?;
        self.add_bytes(length)?;
        self.counts.files = self.counts.files.saturating_add(1);
        Ok(())
    }

    fn note_symlink(&mut self, length: u64) -> Result<()> {
        self.note_entry()?;
        self.add_bytes(length)?;
        self.counts.symlinks = self.counts.symlinks.saturating_add(1);
        Ok(())
    }

    fn note_entry(&mut self) -> Result<()> {
        self.counts.entries = self.counts.entries.saturating_add(1);
        if self.counts.entries > CloneLimits::ALPHA.entries {
            return Err(limit_error(
                "bundle entries",
                self.counts.entries,
                CloneLimits::ALPHA.entries,
            ));
        }
        Ok(())
    }

    fn add_bytes(&mut self, length: u64) -> Result<()> {
        self.counts.logical_bytes = self
            .counts
            .logical_bytes
            .checked_add(length)
            .ok_or_else(|| limit_error("bundle logical bytes", u64::MAX, CloneLimits::ALPHA.logical_bytes))?;
        if self.counts.logical_bytes > CloneLimits::ALPHA.logical_bytes {
            return Err(limit_error(
                "bundle logical bytes",
                self.counts.logical_bytes,
                CloneLimits::ALPHA.logical_bytes,
            ));
        }
        Ok(())
    }
}

fn split_path(path: &[u8]) -> Result<Vec<Vec<u8>>> {
    if path.is_empty() || path.starts_with(b"/") || path.contains(&0) {
        return Err(bundle_input("bundle path is not a safe relative path"));
    }
    let components = path.split(|byte| *byte == b'/').map(<[u8]>::to_vec).collect::<Vec<_>>();
    if components.iter().any(|component| {
        component.is_empty()
            || matches!(component.as_slice(), b"." | b"..")
            || component.len() as u64 > CloneLimits::ALPHA.component_bytes
    }) {
        return Err(bundle_input("bundle path violates component or depth limits"));
    }
    Ok(components)
}

fn validate_link_target(path: &[u8], target: &[u8]) -> Result<()> {
    if target.is_empty() || target.starts_with(b"/") || target.contains(&0) {
        return Err(bundle_input("bundle symlink target is not a safe relative path"));
    }
    let components = split_path(path)?;
    let parent = components[..components.len() - 1]
        .iter()
        .map(|component| OsStr::from_bytes(component).to_os_string())
        .collect::<Vec<OsString>>();
    if resolve_relative_link_target(&parent, OsStr::from_bytes(target)).is_none() {
        return Err(bundle_input("bundle symlink target escapes its root"));
    }
    Ok(())
}

fn validate_header(header: &BundleHeader, counts: ArtifactCounts) -> Result<()> {
    if header.schema_version != BUNDLE_VERSION
        || header.created_unix_ms == 0
        || !header.includes_sensitive_state
        || !matches!(header.source_platform.as_str(), "macos" | "linux")
        || !header.default_shell.is_absolute()
        || !valid_source_identity(&header.source_identity, header.source_layout)
        || header.authentication != BUNDLE_ALGORITHM
        || header.content_integrity.counts != counts
        || validate_content_integrity(&header.content_integrity).is_err()
    {
        return Err(bundle_input(
            "authenticated bundle header is inconsistent with its content",
        ));
    }
    Ok(())
}

struct AuthReader<'a> {
    file: &'a mut File,
    mac: blake3::Hasher,
}

impl AuthReader<'_> {
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut bytes = [0_u8; N];
        self.read_into(&mut bytes)?;
        Ok(bytes)
    }

    fn bytes(&mut self, length: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0_u8; length];
        self.read_into(&mut bytes)?;
        Ok(bytes)
    }

    fn read_into(&mut self, bytes: &mut [u8]) -> Result<()> {
        self.file
            .read_exact(bytes)
            .map_err(|error| bundle_error("authenticated bundle is truncated", error))?;
        self.mac.update(bytes);
        Ok(())
    }

    fn plain_fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut bytes = [0_u8; N];
        self.file
            .read_exact(&mut bytes)
            .map_err(|error| bundle_error("bundle authentication tag is truncated", error))?;
        Ok(bytes)
    }

    fn plain_byte(&mut self) -> Result<bool> {
        let mut byte = [0_u8; 1];
        self.file
            .read(&mut byte)
            .map(|read| read != 0)
            .map_err(|error| bundle_error("could not finish reading authenticated bundle", error))
    }
}

fn bundle_input(message: &'static str) -> QuartersError {
    QuartersError::new(ErrorKind::CorruptState, message)
}

fn bundle_error(message: &'static str, error: impl std::error::Error + Send + Sync + 'static) -> QuartersError {
    QuartersError::new(ErrorKind::CorruptState, message).with_source(error)
}

fn limit_error(label: &str, observed: u64, maximum: u64) -> QuartersError {
    QuartersError::new(
        ErrorKind::ResourceLimit,
        format!("{label} {observed} exceeds the supported maximum {maximum}"),
    )
}

fn conversion_error(error: impl std::error::Error + Send + Sync + 'static) -> QuartersError {
    QuartersError::new(ErrorKind::ResourceLimit, "bundle length cannot be represented safely").with_source(error)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{
        ArtifactId, ArtifactKind, ArtifactName, ContentIntegrity, STABLE_SCHEMA_VERSION, SourceIdentity, SpaceId,
        SpaceLayout, SpaceName,
    };
    use tempfile::NamedTempFile;

    #[test]
    fn canonical_recursive_order_accepts_common_prefix_neighbors() -> Result<()> {
        let mut state = ParseState::new();
        state.validate_path(b".ssh", EntryKind::Directory)?;
        state.validate_path(b".ssh/config", EntryKind::File)?;
        state.validate_path(b".ssh-backup", EntryKind::Directory)?;
        state.validate_path(b".ssh-backup/note", EntryKind::File)?;
        Ok(())
    }

    #[test]
    fn returning_to_a_closed_directory_is_rejected() -> Result<()> {
        let mut state = ParseState::new();
        state.validate_path(b"alpha", EntryKind::Directory)?;
        state.validate_path(b"bravo", EntryKind::Directory)?;
        let error = state
            .validate_path(b"alpha/file", EntryKind::File)
            .expect_err("closed directory must reject late child");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
        Ok(())
    }

    #[test]
    fn path_and_link_traversal_are_rejected() {
        for path in [
            b"/absolute".as_slice(),
            b"../escape",
            b"alpha/../escape",
            b"alpha//file",
        ] {
            assert!(split_path(path).is_err(), "accepted path: {path:?}");
        }
        for target in [b"/absolute".as_slice(), b"../escape", b"alpha/../../escape"] {
            assert!(
                validate_link_target(b"link", target).is_err(),
                "accepted target: {target:?}"
            );
        }
        assert!(validate_link_target(b"dir/link", b"../inside").is_ok());
        assert!(validate_link_target(b"dir/link", b"../../outside").is_err());
    }

    #[test]
    fn undeclared_parent_and_duplicate_siblings_are_rejected() -> Result<()> {
        let mut missing = ParseState::new();
        assert!(missing.validate_path(b"parent/file", EntryKind::File).is_err());

        let mut duplicate = ParseState::new();
        duplicate.validate_path(b"same", EntryKind::File)?;
        assert!(duplicate.validate_path(b"same", EntryKind::File).is_err());
        Ok(())
    }

    #[test]
    fn directory_depth_allows_one_deepest_leaf_component() -> Result<()> {
        let mut state = ParseState::new();
        let mut path = Vec::new();
        for _index in 0..CloneLimits::ALPHA.depth {
            if !path.is_empty() {
                path.push(b'/');
            }
            path.push(b'd');
            state.validate_path(&path, EntryKind::Directory)?;
        }
        let mut leaf = path.clone();
        leaf.extend_from_slice(b"/leaf");
        state.validate_path(&leaf, EntryKind::File)?;
        let mut too_deep = path;
        too_deep.extend_from_slice(b"/directory");
        assert!(state.validate_path(&too_deep, EntryKind::Directory).is_err());
        Ok(())
    }

    #[test]
    fn canonical_state_releases_closed_subtrees() -> Result<()> {
        let mut state = ParseState::new();
        state.validate_path(b"alpha", EntryKind::Directory)?;
        state.validate_path(b"alpha/bravo", EntryKind::Directory)?;
        state.validate_path(b"alpha/bravo/file", EntryKind::File)?;
        assert_eq!(state.directories.len(), 3);
        let closed = state.validate_path(b"charlie", EntryKind::Directory)?;
        assert_eq!(closed, vec![b"alpha/bravo".to_vec(), b"alpha".to_vec()]);
        assert_eq!(state.directories.len(), 2);
        Ok(())
    }

    #[test]
    fn authenticated_malformed_header_fails_before_extraction() -> Result<()> {
        let mut bad_digest = test_header()?;
        bad_digest.content_integrity.digest = "not-a-digest".to_owned();
        assert_header_rejection(&bad_digest);

        let mut bad_source = test_header()?;
        bad_source.source_identity.created_unix_ms = 0;
        assert_header_rejection(&bad_source);
        Ok(())
    }

    fn assert_header_rejection(header: &BundleHeader) {
        let error = round_trip_header(header).expect_err("malformed authenticated header must fail");
        assert_eq!(error.kind(), ErrorKind::CorruptState);
        assert_eq!(
            error.message(),
            "authenticated bundle header is inconsistent with its content"
        );
    }

    fn round_trip_header(header: &BundleHeader) -> Result<()> {
        let mut temporary = NamedTempFile::new().map_err(|error| bundle_error("create test bundle", error))?;
        let key = [0x5a; 32];
        BundleWriter::begin(temporary.as_file_mut(), &key, header)?.finish()?;
        parse_bundle(temporary.as_file_mut(), &key, &mut NoopSink).map(|_parsed| ())
    }

    fn test_header() -> Result<BundleHeader> {
        Ok(BundleHeader {
            schema_version: BUNDLE_VERSION,
            export_id: ArtifactId::parse("11111111111111111111111111111111")?,
            created_unix_ms: 42,
            source_kind: ArtifactKind::Template,
            source_artifact_id: ArtifactId::parse("22222222222222222222222222222222")?,
            source_name: ArtifactName::parse("fixture")?,
            source_identity: SourceIdentity {
                schema_version: STABLE_SCHEMA_VERSION,
                name: SpaceName::parse("source")?,
                created_unix_ms: 41,
                space_id: Some(SpaceId::parse("33333333333333333333333333333333")?),
            },
            source_layout: SpaceLayout::Profile,
            source_platform: "macos".to_owned(),
            default_shell: std::path::PathBuf::from("/bin/sh"),
            include_cache: false,
            includes_sensitive_state: true,
            content_integrity: ContentIntegrity {
                algorithm: "blake3-256:quarters-canonical-v1".to_owned(),
                digest: "a".repeat(64),
                counts: ArtifactCounts::default(),
            },
            authentication: BUNDLE_ALGORITHM.to_owned(),
        })
    }
}
