//! Privacy-bounded state discovery orchestration.

use crate::cli::{DiscoverArgs, DiscoveryScanArg};
use crate::report_fd::ReportWriter;
use crate::{output, process};
use quarters_core::{DiscoveryLimits, DiscoverySelector, HostEnvironment, QuartersError, Result, Space, Store};
use std::io::Write;

pub(crate) fn run(
    store: &Store,
    space: &Space,
    host: &HostEnvironment,
    arguments: &DiscoverArgs,
    mut writer: Option<ReportWriter>,
    json: bool,
) -> Result<i32> {
    let selectors = selectors(&arguments.scans);
    let limits = DiscoveryLimits::ALPHA;
    if arguments.preview {
        let preview = quarters_core::discovery_preview(space.manifest().name.as_str(), &selectors, limits);
        output::print_discovery_preview(&preview, json)?;
        return Ok(0);
    }
    let _lease = store.discovery_lease(space)?;
    let launch = super::app::profile_launch(store, space, host, &arguments.profile);
    let prepared = launch.prepare_process()?;
    let runtime = prepared.runtime_directory()?;
    let pre = quarters_core::discovery_snapshot(&space.home(), &runtime, &selectors, limits)?;
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
    if let Err(error) = output::print_discovery_report(&report) {
        warn(&format!("human discovery report failed: {error}"));
    }
    if let Some(writer) = writer.as_mut()
        && let Err(error) = output::report_json_bytes(&report).and_then(|bytes| writer.write(&bytes))
    {
        warn(&format!("discovery report descriptor failed: {error}"));
    }
    Ok(code)
}

pub(crate) fn prepare_report_writer(arguments: &DiscoverArgs, json: bool) -> Result<Option<ReportWriter>> {
    if json && !arguments.preview {
        return Err(QuartersError::new(
            quarters_core::ErrorKind::InvalidInput,
            "--json is unavailable while discovery executes a command because child stdout must remain unchanged",
        )
        .with_hint("use --report-fd for a machine report, or add --preview to inspect scope as JSON"));
    }
    arguments.report_fd.map(ReportWriter::open).transpose()
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
