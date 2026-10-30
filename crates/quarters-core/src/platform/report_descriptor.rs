// SPDX-License-Identifier: GPL-3.0-or-later
//! Reopening an inherited `--report-fd` descriptor without taking raw-fd
//! ownership; each platform validates what its descriptor may be.

use crate::{ErrorKind, QuartersError, Result};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;

/// Reopen inherited descriptor `descriptor` as a writable, close-on-exec file
/// that refers to the same open file.
///
/// # Errors
///
/// Returns an error when the descriptor is not writable or is a kind of
/// descriptor this platform cannot reopen without losing the report.
pub fn open_report_descriptor(descriptor: i32) -> Result<File> {
    super::platform_open_report_descriptor(descriptor)
}

pub(super) fn writable_options(append: bool, nonblocking: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).append(append);
    let mut flags = nix::libc::O_CLOEXEC;
    if nonblocking {
        flags |= nix::libc::O_NONBLOCK;
    }
    options.custom_flags(flags);
    options
}

pub(super) fn validate_writable(file: &File, descriptor: i32) -> Result<()> {
    if descriptor_flags(file)? & OFlag::O_ACCMODE == OFlag::O_RDONLY {
        Err(not_writable(descriptor))
    } else {
        Ok(())
    }
}

pub(crate) fn descriptor_flags(file: &File) -> Result<OFlag> {
    fcntl(file, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_truncate)
        .map_err(|error| descriptor_system_error("inspect discovery report descriptor flags", error))
}

pub(super) fn not_writable(descriptor: i32) -> QuartersError {
    QuartersError::new(
        ErrorKind::InvalidInput,
        format!("--report-fd {descriptor} is not writable"),
    )
}

pub(super) fn invalid_descriptor(descriptor: i32, source: std::io::Error) -> QuartersError {
    QuartersError::new(
        ErrorKind::InvalidInput,
        format!("--report-fd {descriptor} is not an inherited writable descriptor"),
    )
    .with_source(source)
}

pub(super) fn descriptor_system_error(operation: &str, source: nix::errno::Errno) -> QuartersError {
    QuartersError::new(ErrorKind::System, format!("could not {operation}")).with_source(source)
}
