//! Bounded SSH-agent protocol liveness checks.

use crate::{ErrorKind, QuartersError, Result};
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{
    AddressFamily, SockFlag, SockType, UnixAddr, connect, getsockopt, socket, sockopt::SocketError,
};
use nix::unistd::Uid;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const REQUEST_IDENTITIES: [u8; 5] = [0, 0, 0, 1, 11];
const IDENTITIES_ANSWER: u8 = 12;
const MAXIMUM_RESPONSE_BYTES: u32 = 1_048_576;
const IO_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SocketIdentity {
    pub device: u64,
    pub inode: u64,
}

pub(super) fn verified_socket_identity(path: &Path, expected_pid: u32) -> Result<SocketIdentity> {
    let before = socket_metadata(path)?;
    let mut stream =
        connect_bounded(path).map_err(|error| QuartersError::io("connect to the private SSH agent", path, error))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| QuartersError::io("set SSH-agent read timeout", path, error))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| QuartersError::io("set SSH-agent write timeout", path, error))?;
    if peer_pid(&stream)? != expected_pid {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the private SSH-agent socket peer PID does not match its ownership record",
        ));
    }
    stream
        .write_all(&REQUEST_IDENTITIES)
        .map_err(|error| QuartersError::io("request SSH-agent identities", path, error))?;
    let mut header = [0_u8; 5];
    stream
        .read_exact(&mut header)
        .map_err(|error| QuartersError::io("read SSH-agent response", path, error))?;
    let declared = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if !(5..=MAXIMUM_RESPONSE_BYTES).contains(&declared) || header[4] != IDENTITIES_ANSWER {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the private agent socket did not return a bounded SSH identities response",
        ));
    }
    let payload_length = usize::try_from(declared - 1).map_err(|error| {
        QuartersError::new(ErrorKind::CorruptState, "the private agent response length is invalid").with_source(error)
    })?;
    let mut payload = vec![0_u8; payload_length];
    stream
        .read_exact(&mut payload)
        .map_err(|error| QuartersError::io("read complete SSH-agent response", path, error))?;
    validate_identities_payload(&payload)?;
    let after = socket_metadata(path)?;
    if before.ino() != after.ino() || before.dev() != after.dev() {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the private SSH-agent socket changed during verification",
        ));
    }
    Ok(SocketIdentity {
        device: after.dev(),
        inode: after.ino(),
    })
}

fn validate_identities_payload(payload: &[u8]) -> Result<()> {
    let mut cursor = PayloadCursor::new(payload);
    let identities = cursor.read_u32()?;
    for _ in 0..identities {
        cursor.read_string()?;
        cursor.read_string()?;
    }
    if cursor.is_empty() {
        return Ok(());
    }
    Err(invalid_identities_payload())
}

struct PayloadCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> PayloadCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_string(&mut self) -> Result<()> {
        let length = usize::try_from(self.read_u32()?).map_err(|error| {
            QuartersError::new(ErrorKind::CorruptState, "the private agent response length is invalid")
                .with_source(error)
        })?;
        self.take(length).map(|_| ())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let (taken, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or_else(invalid_identities_payload)?;
        self.remaining = remaining;
        Ok(taken)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

fn invalid_identities_payload() -> QuartersError {
    QuartersError::new(
        ErrorKind::CorruptState,
        "the private agent socket returned a malformed SSH identities payload",
    )
}

pub(super) fn recoverable_disconnected_socket(path: &Path, expected: SocketIdentity) -> Result<bool> {
    let Some(before) = existing_socket_identity(path)? else {
        return Ok(true);
    };
    if before != expected {
        return Ok(false);
    }
    match connect_bounded(path) {
        Ok(_stream) => Ok(false),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            Ok(existing_socket_identity(path)?.is_none_or(|after| after == expected))
        }
        Err(_error) => Ok(false),
    }
}

fn connect_bounded(path: &Path) -> std::io::Result<UnixStream> {
    let descriptor = socket(AddressFamily::Unix, SockType::Stream, SockFlag::empty(), None).map_err(errno_io)?;
    fcntl(&descriptor, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(errno_io)?;
    fcntl(&descriptor, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).map_err(errno_io)?;
    let address = UnixAddr::new(path).map_err(errno_io)?;
    match connect(descriptor.as_raw_fd(), &address) {
        Ok(()) => {}
        Err(error) if error == Errno::EINPROGRESS || error == Errno::EAGAIN => {
            let mut descriptors = [PollFd::new(descriptor.as_fd(), PollFlags::POLLOUT)];
            let timeout = PollTimeout::try_from(IO_TIMEOUT)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
            if poll(&mut descriptors, timeout).map_err(errno_io)? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "private SSH-agent connect timed out",
                ));
            }
            let pending = getsockopt(&descriptor, SocketError).map_err(errno_io)?;
            if pending != 0 {
                return Err(std::io::Error::from_raw_os_error(pending));
            }
        }
        Err(error) => return Err(errno_io(error)),
    }
    let stream = UnixStream::from(descriptor);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

fn errno_io(error: Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error as i32)
}

#[cfg(target_os = "macos")]
fn peer_pid(stream: &UnixStream) -> Result<u32> {
    let pid = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerPid).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not inspect the private SSH-agent peer PID").with_source(error)
    })?;
    u32::try_from(pid).map_err(|error| {
        QuartersError::new(ErrorKind::CorruptState, "the private SSH-agent peer PID is invalid").with_source(error)
    })
}

#[cfg(target_os = "linux")]
fn peer_pid(stream: &UnixStream) -> Result<u32> {
    let credentials =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials).map_err(|error| {
            QuartersError::new(
                ErrorKind::System,
                "could not inspect the private SSH-agent peer credentials",
            )
            .with_source(error)
        })?;
    u32::try_from(credentials.pid()).map_err(|error| {
        QuartersError::new(ErrorKind::CorruptState, "the private SSH-agent peer PID is invalid").with_source(error)
    })
}

pub(super) fn existing_socket_identity(path: &Path) -> Result<Option<SocketIdentity>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_socket(path, &metadata)?;
            Ok(Some(SocketIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(QuartersError::io("inspect private SSH-agent socket", path, error)),
    }
}

fn socket_metadata(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect private SSH-agent socket", path, error))?;
    validate_socket(path, &metadata)?;
    Ok(metadata)
}

fn validate_socket(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_socket() && metadata.uid() == Uid::current().as_raw() {
        return Ok(());
    }
    let issue = if metadata.file_type().is_symlink() {
        "it is a symbolic link"
    } else if !metadata.file_type().is_socket() {
        "it is not a Unix socket"
    } else {
        "it belongs to another user"
    };
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        format!("invalid private SSH-agent socket {}: {issue}", path.display()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_payload_requires_complete_exact_framing() {
        assert!(validate_identities_payload(&[0, 0, 0, 0]).is_ok());
        assert!(validate_identities_payload(&[0, 0, 0]).is_err());
        assert!(validate_identities_payload(&[0, 0, 0, 0, 0]).is_err());
        assert!(validate_identities_payload(&[0, 0, 0, 1]).is_err());
        assert!(validate_identities_payload(&[0, 0, 0, 1, 0, 0, 0, 1, 42, 0, 0, 0, 0]).is_ok());
    }
}
