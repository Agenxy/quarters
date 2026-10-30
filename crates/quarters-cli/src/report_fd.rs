// SPDX-License-Identifier: GPL-3.0-or-later
//! Validated close-on-exec discovery report endpoint.

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use quarters_core::{ErrorKind, QuartersError, Result, platform};
use std::fs::File;
use std::io::Write;

pub(crate) struct ReportWriter {
    file: File,
}

impl ReportWriter {
    pub(crate) fn open(descriptor: i32) -> Result<Self> {
        let file = platform::open_report_descriptor(descriptor)?;
        validate_close_on_exec(&file)?;
        nix::unistd::close(descriptor).map_err(|error| {
            QuartersError::new(
                ErrorKind::System,
                "could not close the original discovery report descriptor before launch",
            )
            .with_source(error)
        })?;
        Ok(Self { file })
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.file.write_all(bytes).map_err(|error| {
            QuartersError::new(ErrorKind::System, "could not write the discovery report descriptor").with_source(error)
        })
    }
}

fn validate_close_on_exec(file: &File) -> Result<()> {
    let flags = fcntl(file, FcntlArg::F_GETFD)
        .map(FdFlag::from_bits_truncate)
        .map_err(|error| {
            QuartersError::new(
                ErrorKind::System,
                "could not inspect discovery report inheritance flags",
            )
            .with_source(error)
        })?;
    if flags.contains(FdFlag::FD_CLOEXEC) {
        Ok(())
    } else {
        Err(QuartersError::new(
            ErrorKind::System,
            "could not make the discovery report descriptor close-on-exec",
        ))
    }
}

#[cfg(test)]
mod common_tests {
    use super::ReportWriter;
    use std::error::Error;
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::process::Command;

    #[test]
    fn reopened_report_sink_is_closed_across_exec() -> Result<(), Box<dyn Error>> {
        let descriptor = tempfile::tempfile()?.into_raw_fd();
        let report = ReportWriter::open(descriptor)?;
        let reopened = report.file.as_raw_fd().to_string();
        let status = Command::new("/bin/sh")
            .args(["-c", "if [ -e \"/dev/fd/$REPORT_FD\" ]; then exit 91; fi"])
            .env("REPORT_FD", reopened)
            .status()?;
        assert!(status.success());
        drop(report);
        Ok(())
    }
}
