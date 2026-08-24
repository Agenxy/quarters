//! Bounded directory listing and relative-path validation.

use super::{conversion_error, entry_limit_error, limit_error, nix_error};
use crate::store::lifecycle::policy::CloneReport;
use crate::{ErrorKind, QuartersError, Result};
use nix::dir::Dir;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

pub(super) fn directory_names(
    directory: &mut Dir,
    relative: &[OsString],
    available: u64,
    already_accounted: u64,
    limit: u64,
) -> Result<Vec<OsString>> {
    let available = usize::try_from(available).map_err(conversion_error)?;
    let mut names = Vec::new();
    for entry in directory.iter() {
        let entry = entry.map_err(|error| nix_error("read source directory", relative, error))?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        if names.len() >= available {
            let buffered = u64::try_from(names.len()).map_err(conversion_error)?;
            return Err(entry_limit_error(
                already_accounted.saturating_add(buffered).saturating_add(1),
                limit,
            ));
        }
        reserve_listing_chunk(&mut names, available)?;
        names.push(OsStr::from_bytes(bytes).to_os_string());
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(names)
}

fn reserve_listing_chunk(names: &mut Vec<OsString>, available: usize) -> Result<()> {
    if names.len() < names.capacity() {
        return Ok(());
    }
    let remaining = available.saturating_sub(names.len());
    names.try_reserve_exact(remaining.min(1_024)).map_err(|error| {
        QuartersError::new(
            ErrorKind::ResourceLimit,
            "could not reserve memory for the bounded clone directory listing",
        )
        .with_source(error)
    })
}

pub(super) fn child_path(parent: &[OsString], name: &OsStr, report: &CloneReport) -> Result<Vec<OsString>> {
    let component_bytes = u64::try_from(name.as_bytes().len()).map_err(conversion_error)?;
    let mut child = parent.to_vec();
    child.push(name.to_os_string());
    if component_bytes > report.limits.component_bytes {
        return Err(limit_error(
            "path-component bytes",
            component_bytes,
            report.limits.component_bytes,
            &child,
        ));
    }
    let relative_bytes = relative_byte_length(&child)?;
    if relative_bytes > report.limits.relative_path_bytes {
        return Err(limit_error(
            "relative-path bytes",
            relative_bytes,
            report.limits.relative_path_bytes,
            &child,
        ));
    }
    Ok(child)
}

fn relative_byte_length(path: &[OsString]) -> Result<u64> {
    let mut components = 0_u64;
    for component in path {
        let length = u64::try_from(component.as_bytes().len()).map_err(conversion_error)?;
        components = components.checked_add(length).ok_or_else(|| {
            crate::QuartersError::new(
                crate::ErrorKind::ResourceLimit,
                "relative path length cannot be represented",
            )
        })?;
    }
    let separators = u64::try_from(path.len().saturating_sub(1)).map_err(conversion_error)?;
    components.checked_add(separators).ok_or_else(|| {
        crate::QuartersError::new(
            crate::ErrorKind::ResourceLimit,
            "relative path length cannot be represented",
        )
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn root_open_error_names_the_correct_side_once() {
        let temporary = TempDir::new().expect("temporary directory");
        let error = super::super::open_root(&temporary.path().join("missing"), "open staging home")
            .expect_err("missing staging home must fail");
        assert_eq!(error.message(), "could not open staging home");
    }

    #[test]
    fn staging_access_error_never_blames_source_permissions() {
        if nix::unistd::Uid::effective().is_root() {
            return;
        }
        let temporary = TempDir::new().expect("temporary directory");
        let staging = temporary.path().join("staging");
        fs::create_dir(&staging).expect("create staging directory");
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o000)).expect("remove staging access");
        let error = super::super::open_root(&staging, "open staging home").expect_err("staging open must fail");
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).expect("restore staging access");
        assert!(error.hint().is_some_and(|hint| hint.contains("private staging")));
        assert!(!error.hint().is_some_and(|hint| hint.contains("source")));
    }
}
