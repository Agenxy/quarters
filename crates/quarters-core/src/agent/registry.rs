//! Private, atomic SSH-agent ownership records.

use super::model::{AgentRecord, REGISTRY_SCHEMA_VERSION};
use crate::store::{sync_directory, unique_suffix, write_private_file};
use crate::store_policy::validate_private_file;
use crate::{ErrorKind, QuartersError, Result, Space};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

const MAXIMUM_REGISTRY_BYTES: u64 = 4 * 1_024;
const MAXIMUM_REPLACEMENT_READS: usize = 8;

pub(super) const REGISTRY_FILE: &str = "ssh-agent.json";
pub(super) const LOCK_FILE: &str = "ssh-agent.lock";
pub(super) const STARTUP_OWNER_LOCK_FILE: &str = "ssh-agent-startup-owner.lock";
pub(super) const SOCKET_FILE: &str = "ssh-agent.sock";

pub(super) fn registry_path(runtime: &Path) -> PathBuf {
    runtime.join(REGISTRY_FILE)
}

pub(super) fn socket_path(runtime: &Path) -> PathBuf {
    runtime.join(SOCKET_FILE)
}

pub(super) fn read(runtime: &Path, space: &Space) -> Result<Option<AgentRecord>> {
    let path = registry_path(runtime);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(QuartersError::io("inspect private SSH-agent registry", &path, error)),
    }
    let bytes = read_registry_file(&path)?;
    let record: AgentRecord = serde_json::from_slice(&bytes).map_err(|error| {
        QuartersError::new(ErrorKind::CorruptState, "the private SSH-agent registry is malformed").with_source(error)
    })?;
    validate(&record, space)?;
    Ok(Some(record))
}

pub(super) fn create(runtime: &Path, record: &AgentRecord) -> Result<()> {
    let path = registry_path(runtime);
    let bytes = serialize(record)?;
    write_private_file(&path, &bytes)?;
    sync_directory(runtime)
}

pub(super) fn replace(runtime: &Path, expected: &AgentRecord, replacement: &AgentRecord) -> Result<()> {
    let current = read_required(runtime)?;
    if current != *expected {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the private SSH-agent registry changed during an ownership transition",
        ));
    }
    let temporary = runtime.join(format!(".ssh-agent-registry-{}.tmp", unique_suffix()?));
    let bytes = serialize(replacement)?;
    if let Err(error) = write_private_file(&temporary, &bytes) {
        cleanup_private_temporary(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary, registry_path(runtime)) {
        cleanup_private_temporary(&temporary);
        return Err(QuartersError::io("replace private SSH-agent registry", runtime, error));
    }
    sync_directory(runtime)
}

fn cleanup_private_temporary(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if validate_private_file(path, &metadata).is_ok() {
        let _cleanup = fs::remove_file(path);
    }
}

pub(super) fn remove(runtime: &Path, expected: &AgentRecord) -> Result<()> {
    let current = read_required(runtime)?;
    if current != *expected {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the private SSH-agent registry changed before cleanup",
        ));
    }
    let path = registry_path(runtime);
    fs::remove_file(&path).map_err(|error| QuartersError::io("remove private SSH-agent registry", &path, error))?;
    sync_directory(runtime)
}

fn read_required(runtime: &Path) -> Result<AgentRecord> {
    let path = registry_path(runtime);
    let bytes = read_registry_file(&path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        QuartersError::new(ErrorKind::CorruptState, "the private SSH-agent registry is malformed").with_source(error)
    })
}

fn validate(record: &AgentRecord, space: &Space) -> Result<()> {
    let id = space.id().ok_or_else(|| {
        QuartersError::new(
            ErrorKind::Unsupported,
            "this legacy space has no stable identity for a private agent",
        )
        .with_hint("clone it into a new Quarter before starting a private agent")
    })?;
    let token_is_valid = record.token.len() == 32
        && record
            .token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    let state_shape = match record.state {
        super::model::StoredAgentState::Starting => {
            record.socket_inode.is_none() && record.socket_device.is_none() && record.failure.is_none()
        }
        super::model::StoredAgentState::Active | super::model::StoredAgentState::Stopping => {
            record.socket_inode.is_some() && record.socket_device.is_some() && record.failure.is_none()
        }
        super::model::StoredAgentState::Failed => {
            record.socket_inode.is_none() && record.socket_device.is_none() && record.failure.is_some()
        }
    };
    if record.schema_version == REGISTRY_SCHEMA_VERSION
        && record.space_id == *id
        && token_is_valid
        && record.pid > 1
        && state_shape
    {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "the private SSH-agent registry does not match this space",
    ))
}

fn serialize(record: &AgentRecord) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(record).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not serialize the private SSH-agent registry").with_source(error)
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read_registry_file(path: &Path) -> Result<Vec<u8>> {
    for _attempt in 0..MAXIMUM_REPLACEMENT_READS {
        match read_registry_once(path)? {
            RegistryRead::Stable(bytes) => return Ok(bytes),
            RegistryRead::Replaced => thread::sleep(Duration::from_millis(1)),
        }
    }
    Err(QuartersError::new(
        ErrorKind::ResourceLimit,
        "the private SSH-agent registry kept changing during a bounded read",
    ))
}

fn read_registry_once(path: &Path) -> Result<RegistryRead> {
    let named = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect private SSH-agent registry", path, error))?;
    validate_private_file(path, &named)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| QuartersError::io("open private SSH-agent registry", path, error))?;
    let opened = file
        .metadata()
        .map_err(|error| QuartersError::io("inspect opened private SSH-agent registry", path, error))?;
    if replacement_evidence(&named, &opened) {
        return Ok(RegistryRead::Replaced);
    }
    validate_private_file(path, &opened)?;
    let bytes = read_bounded_registry(path, file, opened.len())?;
    let current = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(RegistryRead::Replaced),
        Err(error) => return Err(QuartersError::io("reinspect private SSH-agent registry", path, error)),
    };
    validate_private_file(path, &current)?;
    if same_file(&opened, &current) {
        Ok(RegistryRead::Stable(bytes))
    } else {
        Ok(RegistryRead::Replaced)
    }
}

fn replacement_evidence(named: &fs::Metadata, opened: &fs::Metadata) -> bool {
    opened.nlink() == 0 || !same_file(named, opened)
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn read_bounded_registry(path: &Path, file: File, length: u64) -> Result<Vec<u8>> {
    if length > MAXIMUM_REGISTRY_BYTES {
        return Err(registry_size_error());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(length).unwrap_or(0));
    file.take(MAXIMUM_REGISTRY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| QuartersError::io("read private SSH-agent registry", path, error))?;
    if bytes.len() as u64 > MAXIMUM_REGISTRY_BYTES {
        return Err(registry_size_error());
    }
    Ok(bytes)
}

fn registry_size_error() -> QuartersError {
    QuartersError::new(
        ErrorKind::CorruptState,
        "the private SSH-agent registry exceeds 4096 bytes",
    )
}

enum RegistryRead {
    Stable(Vec<u8>),
    Replaced,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use tempfile::TempDir;

    #[test]
    fn an_open_inode_retired_by_atomic_replacement_is_retryable() {
        let temporary = TempDir::new().expect("temporary directory");
        let path = temporary.path().join(REGISTRY_FILE);
        write_private_file(&path, b"old").expect("write registry fixture");
        let named = fs::symlink_metadata(&path).expect("named registry metadata");
        let opened = File::open(&path).expect("open registry fixture");

        fs::remove_file(&path).expect("retire registry fixture");
        let opened = opened.metadata().expect("retired registry metadata");

        assert_eq!(opened.nlink(), 0);
        assert!(replacement_evidence(&named, &opened));
    }

    #[test]
    fn a_real_registry_hard_link_still_fails_closed() {
        let temporary = TempDir::new().expect("temporary directory");
        let path = temporary.path().join(REGISTRY_FILE);
        write_private_file(&path, b"linked").expect("write registry fixture");
        fs::hard_link(&path, temporary.path().join("alias")).expect("link registry fixture");

        let error = read_registry_file(&path).expect_err("linked registry must fail");

        assert_eq!(error.kind(), ErrorKind::CorruptState);
    }
}
