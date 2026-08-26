//! Security policy for store anchors and manifest semantics.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use nix::unistd::Uid;

use crate::{
    ErrorKind, PROFILE_SCHEMA_VERSION, QuartersError, Result, SpaceLayout, SpaceManifest, WORKSPACE_SCHEMA_VERSION,
};

pub(crate) fn validate_store_root(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    let protected_from_other_writers = metadata.mode() & 0o022 == 0;
    if metadata.file_type().is_dir() && metadata.uid() == Uid::current().as_raw() && protected_from_other_writers {
        return Ok(());
    }
    let issue = if metadata.file_type().is_symlink() {
        "it is a symbolic link"
    } else if !metadata.file_type().is_dir() {
        "it is not a directory"
    } else if metadata.uid() != Uid::current().as_raw() {
        "it is not owned by the current user"
    } else {
        "it is writable by another user or group"
    };
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        format!("invalid Quarters root {}: {issue}", path.display()),
    )
    .with_hint("choose a dedicated protected root; existing permissions are never changed automatically"))
}

pub(crate) fn validate_private_dir(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    let private_mode = metadata.mode() & 0o777 == 0o700;
    if metadata.file_type().is_dir() && metadata.uid() == Uid::current().as_raw() && private_mode {
        return Ok(());
    }
    let issue = if metadata.file_type().is_symlink() {
        "it is a symbolic link"
    } else if !metadata.file_type().is_dir() {
        "it is not a directory"
    } else if metadata.uid() != Uid::current().as_raw() {
        "it is not owned by the current user"
    } else {
        "its mode is not 0700"
    };
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        format!("invalid private directory {}: {issue}", path.display()),
    )
    .with_hint("choose a dedicated private Quarters root; existing permissions are never changed automatically"))
}

pub(crate) fn validate_private_file(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    let private_mode = metadata.mode() & 0o777 == 0o600;
    let single_link = metadata.nlink() == 1;
    if metadata.file_type().is_file() && metadata.uid() == Uid::current().as_raw() && private_mode && single_link {
        return Ok(());
    }
    let issue = if metadata.file_type().is_symlink() {
        "it is a symbolic link"
    } else if !metadata.file_type().is_file() {
        "it is not a regular file"
    } else if metadata.uid() != Uid::current().as_raw() {
        "it is not owned by the current user"
    } else if !private_mode {
        "its mode is not 0600"
    } else {
        "it has more than one hard link"
    };
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        format!("invalid private file {}: {issue}", path.display()),
    )
    .with_hint("inspect the path without following links; Quarters never repairs stored permissions automatically"))
}

pub(crate) fn validate_shell(shell: &Path) -> Result<()> {
    let executable = fs::metadata(shell).is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0);
    if shell.is_absolute() && executable {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::InvalidInput,
        format!(
            "default shell must be an existing absolute executable file: {}",
            shell.display()
        ),
    ))
}

pub(crate) fn validate_stored_manifest(manifest: &SpaceManifest) -> Result<()> {
    validate_manifest_layout(manifest)?;
    if manifest.authority_model != "host-account-state-profile" {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "space manifest has an unsupported authority model",
        ));
    }
    if u64::try_from(manifest.created_unix_ms).is_err() {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "space creation time cannot be represented by the supported metadata contract",
        ));
    }
    if !manifest.default_shell.is_absolute() {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "stored default shell path is not absolute",
        ));
    }
    Ok(())
}

fn validate_manifest_layout(manifest: &SpaceManifest) -> Result<()> {
    let valid = match manifest.schema_version {
        PROFILE_SCHEMA_VERSION => manifest.layout.is_none() && manifest.space_id.is_none(),
        WORKSPACE_SCHEMA_VERSION => manifest.layout == Some(SpaceLayout::Workspace) && manifest.space_id.is_some(),
        _ => false,
    };
    if valid {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "space manifest layout and stable identity do not match its schema",
    )
    .with_hint("do not edit manifests by hand; use a compatible Quarters build to inspect this space"))
}

pub(crate) fn validate_removal_entry_name(name: &str) -> Result<()> {
    let single_visible_component =
        !name.is_empty() && !name.starts_with('.') && !name.contains('/') && !name.contains('\0');
    if single_visible_component {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::InvalidInput,
        "removal requires one exact visible directory-entry name",
    )
    .with_hint("copy the exact name from 'quarters --json list'; hidden names and path separators are never accepted"))
}
