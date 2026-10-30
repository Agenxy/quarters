// SPDX-License-Identifier: GPL-3.0-or-later
//! Replacing the confined launcher through a held executable descriptor.

use crate::{ErrorKind, QuartersError, Result};
use std::convert::Infallible;
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

pub(in crate::platform) fn platform_exec_descriptor(
    descriptor: &File,
    program: &Path,
    arguments: &[OsString],
) -> Result<Infallible> {
    use nix::errno::Errno;
    use nix::fcntl::{AtFlags, FcntlArg, FdFlag, fcntl};
    use nix::unistd::execveat;

    let argument_storage = std::iter::once(program.as_os_str())
        .chain(arguments.iter().map(OsString::as_os_str))
        .map(execution_c_string)
        .collect::<Result<Vec<_>>>()?;
    let argument_refs = argument_storage.iter().map(CString::as_c_str).collect::<Vec<_>>();
    let environment_storage = std::env::vars_os()
        .map(|(name, value)| {
            let mut entry = name.into_vec();
            entry.push(b'=');
            entry.extend(value.into_vec());
            CString::new(entry).map_err(|error| {
                QuartersError::new(
                    ErrorKind::CorruptState,
                    "process environment contains an invalid NUL byte",
                )
                .with_source(error)
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let environment_refs = environment_storage.iter().map(CString::as_c_str).collect::<Vec<_>>();
    match execveat(
        descriptor,
        c"",
        &argument_refs,
        &environment_refs,
        AtFlags::AT_EMPTY_PATH,
    ) {
        Ok(never) => match never {},
        Err(Errno::ENOENT) => {
            fcntl(descriptor, FcntlArg::F_SETFD(FdFlag::empty())).map_err(|error| {
                QuartersError::new(ErrorKind::System, "could not prepare a script executable descriptor")
                    .with_source(error)
            })?;
            match execveat(
                descriptor,
                c"",
                &argument_refs,
                &environment_refs,
                AtFlags::AT_EMPTY_PATH,
            ) {
                Ok(never) => match never {},
                Err(error) => Err(executable_descriptor_error(program, error)),
            }
        }
        Err(error) => Err(executable_descriptor_error(program, error)),
    }
}

fn execution_c_string(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|error| {
        QuartersError::new(ErrorKind::InvalidInput, "command arguments contain an invalid NUL byte").with_source(error)
    })
}

fn executable_descriptor_error(program: &Path, error: nix::errno::Errno) -> QuartersError {
    QuartersError::new(
        ErrorKind::System,
        format!(
            "could not replace the namespace launcher through its stable descriptor: {}",
            program.to_string_lossy()
        ),
    )
    .with_hint("check that the executable exists and is permitted by the host account")
    .with_source(error)
}
