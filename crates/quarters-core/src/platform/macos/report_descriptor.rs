// SPDX-License-Identifier: GPL-3.0-or-later
//! macOS `--report-fd` reopening through `/dev/fd`.

use crate::platform::report_descriptor::{descriptor_flags, invalid_descriptor, validate_writable, writable_options};
use crate::{ErrorKind, QuartersError, Result};
use nix::fcntl::OFlag;
use std::fs::File;
use std::path::PathBuf;

pub(in crate::platform) fn platform_open_report_descriptor(descriptor: i32) -> Result<File> {
    let path = PathBuf::from(format!("/dev/fd/{descriptor}"));
    let file = writable_options(false, false)
        .open(path)
        .map_err(|error| invalid_descriptor(descriptor, error))?;
    validate_writable(&file, descriptor)?;
    // Opening /dev/fd duplicates the open file and shares its status flags,
    // so a non-blocking pipe stays non-blocking and a full one would drop the
    // report. Regular files ignore O_NONBLOCK.
    let regular = file
        .metadata()
        .map_err(|error| invalid_descriptor(descriptor, error))?
        .file_type()
        .is_file();
    if !regular && descriptor_flags(&file)?.contains(OFlag::O_NONBLOCK) {
        return Err(QuartersError::new(
            ErrorKind::Unsupported,
            "macOS --report-fd requires a blocking descriptor",
        )
        .with_hint("open a blocking pipe, use a regular file, or use the human stderr report"));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::platform_open_report_descriptor as open_report;
    use std::error::Error;
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::io::Write;
    use std::os::fd::IntoRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    #[test]
    fn writable_named_fifo_is_duplicated_without_inheritance() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("report-fifo");
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)?;
        let mut reader = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(&path)?;
        let descriptor = OpenOptions::new().write(true).open(&path)?.into_raw_fd();
        let mut report = open_report(descriptor)?;
        report.write_all(b"{}")?;
        let mut output = [0_u8; 2];
        reader.read_exact(&mut output)?;
        assert_eq!(output, *b"{}");
        Ok(())
    }

    #[test]
    fn nonblocking_pipe_descriptors_fail_explicitly() -> Result<(), Box<dyn Error>> {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};

        let (reader, writer) = nix::unistd::pipe()?;
        let flags = fcntl(&writer, FcntlArg::F_GETFL).map(OFlag::from_bits_truncate)?;
        fcntl(&writer, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
        let descriptor = writer.into_raw_fd();
        let error = open_report(descriptor).err().ok_or("nonblocking pipe must fail")?;
        assert_eq!(error.kind(), crate::ErrorKind::Unsupported);
        assert!(error.to_string().contains("requires a blocking"));
        nix::unistd::close(descriptor)?;
        drop(reader);
        Ok(())
    }

    #[test]
    fn blocking_pipe_descriptors_are_accepted() -> Result<(), Box<dyn Error>> {
        let (reader, writer) = nix::unistd::pipe()?;
        let descriptor = writer.into_raw_fd();
        let mut report = open_report(descriptor)?;
        report.write_all(b"{}")?;
        nix::unistd::close(descriptor)?;
        drop(reader);
        Ok(())
    }
}
