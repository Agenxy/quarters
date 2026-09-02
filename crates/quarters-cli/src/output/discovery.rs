use quarters_core::{DiscoveryClassCounts, DiscoveryPreview, DiscoveryReport, QuartersError, Result};
use serde::Serialize;
use serde_json::json;
use std::io::{self, Write};

pub(crate) fn print_preview(preview: &DiscoveryPreview, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", json_text("discover-preview", preview)?);
        return Ok(());
    }
    println!("Discovery preview for {}", preview.space);
    println!("  Scope");
    for selector in &preview.selectors {
        let count = preview.entries.get(selector).copied().unwrap_or(0);
        println!("    {:<8} {count} entries", selector.as_str());
    }
    println!("  Scan     metadata only; file contents and symlink targets are not inspected");
    println!(
        "  Bounds   {} entries, depth {}, {} relative-path bytes, {} ms per phase",
        preview.limits.entries,
        preview.limits.depth,
        preview.limits.relative_path_bytes,
        preview.limits.phase_milliseconds
    );
    println!("  Credential-shaped patterns (path shape only; incomplete by design)");
    for pattern in &preview.credential_patterns {
        println!("    {pattern}");
    }
    for exclusion in &preview.exclusions {
        println!("  Excludes {exclusion}");
    }
    println!("  Host     access and writes are not measured");
    Ok(())
}

pub(crate) fn print_report(report: &DiscoveryReport) -> io::Result<()> {
    let stderr = io::stderr();
    let mut output = stderr.lock();
    writeln!(output, "Discovery for {}: {}", report.space, report.state)?;
    if let Some(totals) = report.totals.as_ref() {
        writeln!(
            output,
            "  Delta    {} created, {} modified, {} replaced, {} deleted",
            totals.created, totals.modified, totals.replaced, totals.deleted
        )?;
        if let Some(delta) = report.delta.as_ref() {
            write_counts(&mut output, "Created", &delta.created)?;
            write_counts(&mut output, "Modified", &delta.modified)?;
            write_counts(&mut output, "Replaced", &delta.replaced)?;
            write_counts(&mut output, "Deleted", &delta.deleted)?;
        }
    } else {
        writeln!(output, "  Delta    unavailable because the observation was incomplete")?;
    }
    writeln!(
        output,
        "  Child    {}",
        report.child.exit_code.map_or_else(
            || report
                .child
                .signal
                .map_or_else(|| "unknown".to_owned(), |signal| format!("signal {signal}")),
            |code| format!("exit {code}")
        )
    )?;
    writeln!(
        output,
        "  Boundary Quarter-owned metadata only; host access and writes were not measured"
    )
}

fn write_counts(output: &mut impl Write, label: &str, counts: &DiscoveryClassCounts) -> io::Result<()> {
    let values = [
        ("configuration", counts.configuration),
        ("data", counts.data),
        ("state", counts.state),
        ("cache", counts.cache),
        ("credential-shaped", counts.credential_shaped),
        ("runtime-socket", counts.runtime_socket),
        ("runtime", counts.runtime),
        ("unclassified", counts.unclassified),
    ];
    if !values.iter().any(|(_name, count)| *count > 0) {
        return Ok(());
    }
    write!(output, "  {label:<8}")?;
    for (name, count) in values.into_iter().filter(|(_name, count)| *count > 0) {
        write!(output, " {name}={count}")?;
    }
    writeln!(output)
}

pub(crate) fn report_json_bytes(report: &DiscoveryReport) -> Result<Vec<u8>> {
    let mut bytes = json_text("discover", report)?.into_bytes();
    bytes.push(b'\n');
    Ok(bytes)
}

fn json_text(command: &str, value: &impl Serialize) -> Result<String> {
    let envelope = json!({
        "schema_version": 1,
        "ok": true,
        "command": command,
        "result": value,
    });
    serde_json::to_string_pretty(&envelope).map_err(serialization_error)
}

fn serialization_error(error: serde_json::Error) -> QuartersError {
    QuartersError::new(
        quarters_core::ErrorKind::System,
        "could not serialize the discovery report",
    )
    .with_source(error)
}
