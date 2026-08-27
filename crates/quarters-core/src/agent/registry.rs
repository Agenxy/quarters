//! Private, atomic SSH-agent ownership records.

use super::model::{AgentRecord, REGISTRY_SCHEMA_VERSION};
use crate::store::{read_private_file, sync_directory, unique_suffix, write_private_file};
use crate::store_policy::validate_private_file;
use crate::{ErrorKind, QuartersError, Result, Space};
use std::fs;
use std::path::{Path, PathBuf};

pub(super) const REGISTRY_FILE: &str = "ssh-agent.json";
pub(super) const LOCK_FILE: &str = "ssh-agent.lock";
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
    let bytes = read_private_file(&path)?;
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
    let bytes = read_private_file(&path)?;
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
