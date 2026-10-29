// SPDX-License-Identifier: GPL-3.0-or-later
//! Validated close-on-exec discovery report endpoint.

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use quarters_core::{ErrorKind, QuartersError, Result};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

pub(crate) struct ReportWriter {
    file: File,
}

impl ReportWriter {
    pub(crate) fn open(descriptor: i32) -> Result<Self> {
        let file = platform_open(descriptor)?;
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

#[cfg(target_os = "macos")]
fn platform_open(descriptor: i32) -> Result<File> {
    let path = PathBuf::from(format!("/dev/fd/{descriptor}"));
    let file = writable_options(false, false)
        .open(path)
        .map_err(|error| invalid_descriptor(descriptor, error))?;
    validate_writable(&file, descriptor)?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn platform_open(descriptor: i32) -> Result<File> {
    use nix::sys::stat::{SFlag, fstat};
    use std::io::{Seek, SeekFrom};
    use std::os::unix::fs::MetadataExt;

    let info = linux_fd_info(descriptor)?;
    if info.flags & OFlag::O_ACCMODE == OFlag::O_RDONLY {
        return Err(not_writable(descriptor));
    }
    let path = PathBuf::from(format!("/proc/self/fd/{descriptor}"));
    let link = std::fs::read_link(&path).map_err(|error| invalid_descriptor(descriptor, error))?;
    if link.as_os_str().as_encoded_bytes().starts_with(b"socket:") {
        return Err(QuartersError::new(
            ErrorKind::Unsupported,
            "Linux --report-fd does not accept a socket descriptor without unsafe raw-fd ownership",
        )
        .with_hint("use a regular file, pipe, or the human stderr report"));
    }
    let original = std::fs::metadata(&path).map_err(|error| invalid_descriptor(descriptor, error))?;
    if original.ino() != info.inode {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the Linux discovery report descriptor changed during validation",
        ));
    }
    let append = info.flags.contains(OFlag::O_APPEND);
    let anonymous_pipe = link.as_os_str().as_encoded_bytes().starts_with(b"pipe:");
    let named_pipe = original.mode() & nix::libc::S_IFMT == nix::libc::S_IFIFO;
    if named_pipe && !anonymous_pipe {
        return Err(QuartersError::new(
            ErrorKind::Unsupported,
            "Linux --report-fd does not accept a named FIFO because its reader can disconnect before safe reopening",
        )
        .with_hint("use a regular file, blocking anonymous pipe, or the human stderr report"));
    }
    let pipe = anonymous_pipe;
    let originally_nonblocking = info.flags.contains(OFlag::O_NONBLOCK);
    if pipe && originally_nonblocking {
        return Err(QuartersError::new(
            ErrorKind::Unsupported,
            "Linux --report-fd requires a blocking pipe descriptor",
        )
        .with_hint("open a blocking pipe, use a regular file, or use the human stderr report"));
    }
    let mut file = writable_options(append, pipe || originally_nonblocking)
        .open(&path)
        .map_err(|error| invalid_descriptor(descriptor, error))?;
    let metadata =
        fstat(&file).map_err(|error| descriptor_system_error("inspect reopened report descriptor", error))?;
    if metadata.st_dev != original.dev() || metadata.st_ino != original.ino() {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the Linux discovery report descriptor identity changed during validation",
        ));
    }
    if SFlag::from_bits_truncate(metadata.st_mode) == SFlag::S_IFREG && !append {
        file.seek(SeekFrom::Start(info.position)).map_err(|error| {
            QuartersError::new(
                ErrorKind::System,
                "could not restore the Linux report descriptor position",
            )
            .with_source(error)
        })?;
    }
    if pipe && !originally_nonblocking {
        let reopened = descriptor_flags(&file)?;
        fcntl(&file, FcntlArg::F_SETFL(reopened.difference(OFlag::O_NONBLOCK)))
            .map_err(|error| descriptor_system_error("restore report descriptor blocking mode", error))?;
    }
    validate_writable(&file, descriptor)?;
    Ok(file)
}

fn writable_options(append: bool, nonblocking: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).append(append);
    let mut flags = nix::libc::O_CLOEXEC;
    if nonblocking {
        flags |= nix::libc::O_NONBLOCK;
    }
    options.custom_flags(flags);
    options
}

fn validate_writable(file: &File, descriptor: i32) -> Result<()> {
    if descriptor_flags(file)? & OFlag::O_ACCMODE == OFlag::O_RDONLY {
        Err(not_writable(descriptor))
    } else {
        Ok(())
    }
}

fn descriptor_flags(file: &File) -> Result<OFlag> {
    fcntl(file, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_truncate)
        .map_err(|error| descriptor_system_error("inspect discovery report descriptor flags", error))
}

fn validate_close_on_exec(file: &File) -> Result<()> {
    let flags = fcntl(file, FcntlArg::F_GETFD)
        .map(FdFlag::from_bits_truncate)
        .map_err(|error| descriptor_system_error("inspect discovery report inheritance flags", error))?;
    if flags.contains(FdFlag::FD_CLOEXEC) {
        Ok(())
    } else {
        Err(QuartersError::new(
            ErrorKind::System,
            "could not make the discovery report descriptor close-on-exec",
        ))
    }
}

#[cfg(target_os = "linux")]
struct LinuxFdInfo {
    position: u64,
    flags: OFlag,
    inode: u64,
}

#[cfg(target_os = "linux")]
fn linux_fd_info(descriptor: i32) -> Result<LinuxFdInfo> {
    use std::io::Read;

    let path = PathBuf::from(format!("/proc/self/fdinfo/{descriptor}"));
    let file = File::open(&path).map_err(|error| invalid_descriptor(descriptor, error))?;
    let mut text = String::new();
    file.take(4_096).read_to_string(&mut text).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not read Linux report descriptor metadata").with_source(error)
    })?;
    let position = parse_fdinfo(&text, "pos", 10)?;
    let flags = parse_fdinfo(&text, "flags", 8)?;
    let inode = parse_fdinfo(&text, "ino", 10)?;
    Ok(LinuxFdInfo {
        position,
        flags: OFlag::from_bits_truncate(i32::try_from(flags).map_err(fdinfo_range_error)?),
        inode,
    })
}

#[cfg(target_os = "linux")]
fn parse_fdinfo(text: &str, name: &str, radix: u32) -> Result<u64> {
    let value = text.lines().find_map(|line| line.strip_prefix(name)?.strip_prefix(':'));
    let value = value.ok_or_else(|| {
        QuartersError::new(
            ErrorKind::Unsupported,
            format!("Linux report descriptor metadata has no {name} field"),
        )
    })?;
    u64::from_str_radix(value.trim(), radix).map_err(|error| {
        QuartersError::new(
            ErrorKind::Unsupported,
            format!("Linux report descriptor metadata has an invalid {name} field"),
        )
        .with_source(error)
    })
}

#[cfg(target_os = "linux")]
fn fdinfo_range_error(error: impl std::error::Error + Send + Sync + 'static) -> QuartersError {
    QuartersError::new(
        ErrorKind::Unsupported,
        "Linux report descriptor metadata cannot be represented safely",
    )
    .with_source(error)
}

fn not_writable(descriptor: i32) -> QuartersError {
    QuartersError::new(
        ErrorKind::InvalidInput,
        format!("--report-fd {descriptor} is not writable"),
    )
}

fn invalid_descriptor(descriptor: i32, source: std::io::Error) -> QuartersError {
    QuartersError::new(
        ErrorKind::InvalidInput,
        format!("--report-fd {descriptor} is not an inherited writable descriptor"),
    )
    .with_source(source)
}

fn descriptor_system_error(operation: &str, source: nix::errno::Errno) -> QuartersError {
    QuartersError::new(ErrorKind::System, format!("could not {operation}")).with_source(source)
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

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::ReportWriter;
    use std::error::Error;
    use std::fs::OpenOptions;
    use std::io::Read;
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
        let mut report = ReportWriter::open(descriptor)?;
        report.write(b"{}")?;
        let mut output = [0_u8; 2];
        reader.read_exact(&mut output)?;
        assert_eq!(output, *b"{}");
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{ReportWriter, descriptor_flags};
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use std::error::Error;
    use std::fs::OpenOptions;
    use std::os::fd::IntoRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::net::UnixStream;

    #[test]
    fn socket_report_descriptors_fail_explicitly() -> Result<(), Box<dyn Error>> {
        let (stream, peer) = UnixStream::pair()?;
        let descriptor = stream.into_raw_fd();
        let error = ReportWriter::open(descriptor).err().ok_or("socket must fail")?;
        assert_eq!(error.kind(), quarters_core::ErrorKind::Unsupported);
        nix::unistd::close(descriptor)?;
        drop(peer);
        Ok(())
    }

    #[test]
    fn nonblocking_named_pipe_descriptors_fail_explicitly() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("report-fifo");
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)?;
        let reader = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(&path)?;
        let writer = OpenOptions::new()
            .write(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(&path)?;
        let descriptor = writer.into_raw_fd();
        let error = ReportWriter::open(descriptor)
            .err()
            .ok_or("nonblocking fifo must fail")?;
        assert_eq!(error.kind(), quarters_core::ErrorKind::Unsupported);
        nix::unistd::close(descriptor)?;
        drop(reader);
        Ok(())
    }

    #[test]
    fn nonblocking_anonymous_pipe_descriptors_fail_explicitly() -> Result<(), Box<dyn Error>> {
        let (reader, writer) = nix::unistd::pipe()?;
        let flags = fcntl(&writer, FcntlArg::F_GETFL).map(OFlag::from_bits_truncate)?;
        fcntl(&writer, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
        let descriptor = writer.into_raw_fd();
        let error = ReportWriter::open(descriptor)
            .err()
            .ok_or("nonblocking anonymous pipe must fail")?;
        assert_eq!(error.kind(), quarters_core::ErrorKind::Unsupported);
        assert!(error.to_string().contains("requires a blocking pipe"));
        nix::unistd::close(descriptor)?;
        drop(reader);
        Ok(())
    }

    #[test]
    fn blocking_anonymous_pipe_is_reopened_in_blocking_mode() -> Result<(), Box<dyn Error>> {
        let (reader, writer) = nix::unistd::pipe()?;
        let descriptor = writer.into_raw_fd();
        let report = ReportWriter::open(descriptor)?;
        assert!(!descriptor_flags(&report.file)?.contains(OFlag::O_NONBLOCK));
        drop(report);
        drop(reader);
        Ok(())
    }

    #[test]
    fn blocking_named_pipe_descriptors_fail_explicitly() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("report-fifo");
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)?;
        let reader = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(&path)?;
        let writer = OpenOptions::new().write(true).open(&path)?;
        let descriptor = writer.into_raw_fd();
        let error = ReportWriter::open(descriptor).err().ok_or("named fifo must fail")?;
        assert_eq!(error.kind(), quarters_core::ErrorKind::Unsupported);
        assert!(error.to_string().contains("named FIFO"));
        nix::unistd::close(descriptor)?;
        drop(reader);
        Ok(())
    }
}
