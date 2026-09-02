//! Privacy-bounded state discovery orchestration.

use crate::cli::{DiscoverArgs, DiscoveryScanArg};
use crate::{output, process};
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use quarters_core::{DiscoveryLimits, DiscoverySelector, HostEnvironment, QuartersError, Result, Space, Store};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

pub(crate) fn run(
    store: &Store,
    space: &Space,
    host: &HostEnvironment,
    arguments: &DiscoverArgs,
    json: bool,
) -> Result<i32> {
    if json && !arguments.preview {
        return Err(QuartersError::new(
            quarters_core::ErrorKind::InvalidInput,
            "--json is unavailable while discovery executes a command because child stdout must remain unchanged",
        )
        .with_hint("use --report-fd for a machine report, or add --preview to inspect scope as JSON"));
    }
    let mut writer = arguments.report_fd.map(ReportWriter::open).transpose()?;
    let selectors = selectors(&arguments.scans);
    let _lease = store.discovery_lease(space)?;
    let launch = super::app::profile_launch(store, space, host, &arguments.profile);
    let prepared = launch.prepare_process()?;
    let runtime = prepared.runtime_directory()?;
    let limits = DiscoveryLimits::ALPHA;
    let pre = quarters_core::discovery_snapshot(&space.home(), &runtime, &selectors, limits)?;
    if arguments.preview {
        let preview = quarters_core::discovery_preview(space.manifest().name.as_str(), &pre, limits);
        output::print_discovery_preview(&preview, json)?;
        return Ok(0);
    }
    let status = launch.run_prepared(&arguments.command, &prepared)?;
    let code = process::status_code(status);
    let child = process::discovery_child(status);
    let post = match quarters_core::discovery_snapshot(&space.home(), &runtime, &selectors, limits) {
        Ok(snapshot) => Some(snapshot),
        Err(error) => {
            warn(&format!("discovery post-scan failed: {error}"));
            None
        }
    };
    let report = quarters_core::discovery_report(space.manifest().name.as_str(), &pre, post.as_ref(), child, limits);
    let _human_output = output::print_discovery_report(&report);
    if let Some(writer) = writer.as_mut()
        && let Err(error) = output::report_json_bytes(&report).and_then(|bytes| writer.write(&bytes))
    {
        warn(&format!("discovery report descriptor failed: {error}"));
    }
    Ok(code)
}

fn warn(message: &str) {
    let stderr = std::io::stderr();
    let mut output = stderr.lock();
    let _ignored = writeln!(output, "quarters: {message}");
}

fn selectors(requested: &[DiscoveryScanArg]) -> Vec<DiscoverySelector> {
    let mut selectors = if requested.is_empty() {
        vec![DiscoverySelector::Home, DiscoverySelector::Runtime]
    } else {
        requested.iter().copied().map(DiscoverySelector::from).collect()
    };
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

struct ReportWriter {
    file: File,
}

impl ReportWriter {
    fn open(descriptor: i32) -> Result<Self> {
        let path = PathBuf::from(format!("/dev/fd/{descriptor}"));
        let mut options = OpenOptions::new();
        options.write(true).custom_flags(nix::libc::O_CLOEXEC);
        let file = options.open(&path).map_err(|error| {
            QuartersError::new(
                quarters_core::ErrorKind::InvalidInput,
                format!("--report-fd {descriptor} is not an inherited writable descriptor"),
            )
            .with_source(error)
        })?;
        let flags = fcntl(&file, FcntlArg::F_GETFL)
            .map(OFlag::from_bits_truncate)
            .map_err(|error| {
                QuartersError::new(
                    quarters_core::ErrorKind::System,
                    "could not inspect the discovery report descriptor",
                )
                .with_source(error)
            })?;
        if flags & OFlag::O_ACCMODE == OFlag::O_RDONLY {
            return Err(QuartersError::new(
                quarters_core::ErrorKind::InvalidInput,
                format!("--report-fd {descriptor} is not writable"),
            ));
        }
        let descriptor_flags = fcntl(&file, FcntlArg::F_GETFD)
            .map(FdFlag::from_bits_truncate)
            .map_err(|error| {
                QuartersError::new(
                    quarters_core::ErrorKind::System,
                    "could not inspect discovery report inheritance flags",
                )
                .with_source(error)
            })?;
        if !descriptor_flags.contains(FdFlag::FD_CLOEXEC) {
            return Err(QuartersError::new(
                quarters_core::ErrorKind::System,
                "could not make the discovery report descriptor close-on-exec",
            ));
        }
        nix::unistd::close(descriptor).map_err(|error| {
            QuartersError::new(
                quarters_core::ErrorKind::System,
                "could not seal the original discovery report descriptor before launch",
            )
            .with_source(error)
        })?;
        Ok(Self { file })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.file.write_all(bytes).map_err(|error| {
            QuartersError::new(
                quarters_core::ErrorKind::System,
                "could not write the discovery report descriptor",
            )
            .with_source(error)
        })
    }
}
