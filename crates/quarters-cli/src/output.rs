//! Human and machine output contracts.

use clap::error::Error as ClapError;
use quarters_core::{Capabilities, LeaseState, QuartersError, RecoverySummary, Space, SpaceInspection, ToolProbe};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

const OUTPUT_SCHEMA_VERSION: u32 = 1;

pub(crate) fn print_success<T: Serialize>(command: &str, value: &T, json_output: bool) -> quarters_core::Result<()> {
    if json_output {
        let envelope = json!({
            "schema_version": OUTPUT_SCHEMA_VERSION,
            "ok": true,
            "command": command,
            "result": value,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&envelope).map_err(serialization_error)?
        );
    }
    Ok(())
}

pub(crate) fn print_created(space: &Space, json_output: bool) -> quarters_core::Result<()> {
    let result = space_value(space);
    if json_output {
        return print_success("create", &result, true);
    }
    println!("Created {}", space.manifest().name);
    println!("  Home   {}", path_for_human(&space.home()));
    println!("  Model  host account, separate user-owned state");
    Ok(())
}

pub(crate) fn print_recovered(summary: &RecoverySummary, json_output: bool) -> quarters_core::Result<()> {
    if json_output {
        return print_success("recover", summary, true);
    }
    println!(
        "Recovered {} unfinished creation(s) and {} retired entry(s); {} creation(s) remain active",
        summary.unfinished_creations, summary.retired_entries, summary.active_creations
    );
    Ok(())
}

pub(crate) fn print_list(inspections: &[SpaceInspection], json_output: bool) -> quarters_core::Result<()> {
    let values: Vec<Value> = inspections.iter().map(inspection_value).collect();
    if json_output {
        return print_success("list", &values, true);
    }
    if inspections.is_empty() {
        println!("No spaces yet. Create one with: quarters create <name>");
        return Ok(());
    }
    println!("NAME                             HEALTH     HOME");
    for inspection in inspections {
        match inspection {
            SpaceInspection::Healthy(space) => {
                println!(
                    "{:<32} {:<10} {}",
                    space.manifest().name,
                    "healthy",
                    path_for_human(&space.home())
                );
            }
            SpaceInspection::Unhealthy { name, error, .. } => {
                println!("{:<32} {:<10} -", entry_name_for_human(name), "unhealthy");
                print_inspection_issue(error);
            }
        }
    }
    Ok(())
}

pub(crate) enum StatusEntry {
    Healthy {
        space: Space,
        lease_state: LeaseState,
    },
    Unhealthy {
        name: String,
        name_was_lossy: bool,
        error: QuartersError,
    },
}

pub(crate) fn print_status(
    statuses: &[StatusEntry],
    current: Option<&str>,
    json_output: bool,
) -> quarters_core::Result<()> {
    let values: Vec<Value> = statuses.iter().map(|status| status_value(status, current)).collect();
    let result = json!({
        "observation_scope": "quarters-cooperative-lease",
        "detached_processes": "unknown",
        "current_space": current,
        "current_evidence": "self-reported QUARTERS_SPACE, matched to a fully validated healthy space",
        "spaces": values,
    });
    if json_output {
        return print_success("status", &result, true);
    }
    if statuses.is_empty() {
        println!("No spaces yet. Create one with: quarters create <name>");
        return Ok(());
    }
    println!("NAME                             HEALTH     LEASE    CURRENT  HOME");
    for status in statuses {
        print_human_status(status, current);
    }
    if let Some(current) = current {
        println!("Current space claim: {}", entry_name_for_human(current));
    }
    println!();
    println!("Lease state covers Quarters-managed operations; detached processes are unknown.");
    Ok(())
}

pub(crate) fn print_current(current: &str, json_output: bool) -> quarters_core::Result<()> {
    if json_output {
        return print_success("current", &json!({ "space": safe_json_text(current, 64) }), true);
    }
    println!("{}", escape_for_human(current));
    Ok(())
}

pub(crate) fn print_environment(
    space: &Space,
    values: &BTreeMap<String, String>,
    json_output: bool,
) -> quarters_core::Result<()> {
    if json_output {
        let safe_values: BTreeMap<String, String> = values
            .iter()
            .map(|(name, value)| (safe_json_text(name, 128), safe_json_text(value, 512)))
            .collect();
        return print_success(
            "env",
            &json!({
                "space": safe_json_text(space.manifest().name.as_str(), 64),
                "environment": safe_values,
            }),
            true,
        );
    }
    for (name, value) in values {
        println!("{}={}", escape_for_human(name), escape_for_human(value));
    }
    Ok(())
}

pub(crate) fn print_doctor(
    capabilities: &Capabilities,
    tools: &[ToolProbe],
    space: Option<&Space>,
    lease_state: Option<LeaseState>,
    recovery: std::result::Result<&RecoverySummary, &QuartersError>,
    json_output: bool,
) -> quarters_core::Result<()> {
    let recovery_value = recovery.map_or_else(
        |error| {
            json!({
                "status": "unavailable",
                "error": inspection_error_value(error),
            })
        },
        |summary| {
            json!({
                "status": "available",
                "active_creations": summary.active_creations,
                "unfinished_creations": summary.unfinished_creations,
                "retired_entries": summary.retired_entries,
            })
        },
    );
    let result = json!({
        "platform": capabilities,
        "space": space.map(space_value),
        "space_environment_validated": space.map(|_space| true),
        "space_lease_state": lease_state.map(LeaseState::as_str),
        "detached_processes": space.map(|_space| "unknown"),
        "recovery": recovery_value,
        "tools": tools,
        "classification_evidence": "installed executable plus declared state-location contract; no credentials were read",
    });
    if json_output {
        return print_success("doctor", &result, true);
    }
    println!("Quarters doctor");
    println!("  Platform       {}", capabilities.platform);
    println!("  Baseline       available (HOME and user-state profile)");
    println!(
        "  Home view      {}: {}",
        capabilities.home_view.status, capabilities.home_view.detail
    );
    println!(
        "  Confinement    {}: {}",
        capabilities.confinement.status, capabilities.confinement.detail
    );
    println!("  Authority      {}", capabilities.authority_boundary);
    match recovery {
        Ok(summary) => println!(
            "  Recovery       {} active, {} unfinished, {} retired",
            summary.active_creations, summary.unfinished_creations, summary.retired_entries
        ),
        Err(error) => println!("  Recovery       unavailable: {}", escape_for_human(error.message())),
    }
    if let (Some(space), Some(lease_state)) = (space, lease_state) {
        println!(
            "  Space          {} ({})",
            space.manifest().name,
            path_for_human(&space.home())
        );
        println!("  Environment    validated");
        println!("  Lease          {} (detached processes unknown)", lease_state.as_str());
    }
    println!();
    println!("TOOL             CLASS  INSTALLED  STATE ROUTE");
    for tool in tools {
        println!(
            "{:<16} {:<6} {:<10} {}",
            tool.tool,
            format!("{:?}", tool.tier),
            if tool.installed { "yes" } else { "no" },
            tool.mechanism
        );
        if let Some(limitation) = &tool.limitation {
            println!("  limitation: {limitation}");
        }
    }
    Ok(())
}

pub(crate) fn print_removed(name: &str, json_output: bool) -> quarters_core::Result<()> {
    if json_output {
        return print_success("rm", &json!({ "removed": safe_json_text(name, 64) }), true);
    }
    println!("Removed {}", escape_for_human(name));
    Ok(())
}

pub(crate) fn print_error(error: &QuartersError, json_output: bool) {
    if json_output {
        let envelope = error_envelope(error.kind().as_str(), error.message(), error.hint());
        eprintln!(
            "{}",
            serde_json::to_string(&envelope).unwrap_or_else(|_| fallback_error_json())
        );
        return;
    }
    eprintln!("quarters: {}", escape_for_human(error.message()));
    if let Some(hint) = error.hint() {
        eprintln!("Try: {}", escape_for_human(hint));
    }
}

pub(crate) fn print_parse_error(error: &ClapError) {
    let envelope = error_envelope("invalid_command", &error.to_string(), Some("run 'quarters --help'"));
    eprintln!(
        "{}",
        serde_json::to_string(&envelope).unwrap_or_else(|_| fallback_error_json())
    );
}

fn space_value(space: &Space) -> Value {
    json!({
        "name": safe_json_text(space.manifest().name.as_str(), 64),
        "home": safe_json_path(&space.home()),
        "root": safe_json_path(space.root()),
        "created_unix_ms": space.manifest().created_unix_ms,
        "default_shell": safe_json_path(&space.manifest().default_shell),
        "authority_model": space.manifest().authority_model,
    })
}

fn inspection_value(inspection: &SpaceInspection) -> Value {
    match inspection {
        SpaceInspection::Healthy(space) => {
            let mut value = space_value(space);
            value["health"] = Value::String("healthy".to_owned());
            value
        }
        SpaceInspection::Unhealthy {
            name,
            name_was_lossy,
            error,
        } => json!({
            "name": safe_json_text(name, 64),
            "name_encoding": if *name_was_lossy { "lossy_escaped_bounded" } else { "utf8_escaped_bounded" },
            "health": "unhealthy",
            "error": inspection_error_value(error),
        }),
    }
}

fn status_value(status: &StatusEntry, current: Option<&str>) -> Value {
    match status {
        StatusEntry::Healthy { space, lease_state } => {
            let mut value = space_value(space);
            value["health"] = Value::String("healthy".to_owned());
            value["lease_state"] = Value::String(lease_state.as_str().to_owned());
            value["current"] = Value::Bool(current == Some(space.manifest().name.as_str()));
            value
        }
        StatusEntry::Unhealthy {
            name,
            name_was_lossy,
            error,
        } => json!({
            "name": safe_json_text(name, 64),
            "name_encoding": if *name_was_lossy { "lossy_escaped_bounded" } else { "utf8_escaped_bounded" },
            "health": "unhealthy",
            "lease_state": "unknown",
            "current": current == Some(name.as_str()),
            "error": inspection_error_value(error),
        }),
    }
}

fn print_human_status(status: &StatusEntry, current: Option<&str>) {
    match status {
        StatusEntry::Healthy { space, lease_state } => {
            let is_current = current == Some(space.manifest().name.as_str());
            println!(
                "{:<32} {:<10} {:<8} {:<8} {}",
                space.manifest().name,
                "healthy",
                lease_state.as_str(),
                if is_current { "yes" } else { "no" },
                path_for_human(&space.home())
            );
        }
        StatusEntry::Unhealthy { name, error, .. } => {
            let is_current = current == Some(name.as_str());
            println!(
                "{:<32} {:<10} {:<8} {:<8} -",
                entry_name_for_human(name),
                "unhealthy",
                "unknown",
                if is_current { "yes" } else { "no" }
            );
            print_inspection_issue(error);
        }
    }
}

fn print_inspection_issue(error: &QuartersError) {
    println!("  issue: {}", escape_for_human(error.message()));
    if let Some(hint) = error.hint() {
        println!("  hint:  {}", escape_for_human(hint));
    }
}

fn inspection_error_value(error: &QuartersError) -> Value {
    json!({
        "kind": error.kind().as_str(),
        "message": quarters_core::escape_untrusted_text_bounded(error.message(), 512),
        "hint": error.hint().map(|hint| quarters_core::escape_untrusted_text_bounded(hint, 512)),
    })
}

fn entry_name_for_human(name: &str) -> String {
    quarters_core::escape_untrusted_text_bounded(name, 32)
}

fn escape_for_human(value: &str) -> String {
    quarters_core::escape_untrusted_text(value)
}

fn path_for_human(path: &Path) -> String {
    escape_for_human(&path.to_string_lossy())
}

fn safe_json_text(value: &str, maximum: usize) -> String {
    quarters_core::escape_untrusted_text_bounded(value, maximum)
}

fn safe_json_path(path: &Path) -> String {
    safe_json_text(&path.to_string_lossy(), 512)
}

fn error_envelope(kind: &str, message: &str, hint: Option<&str>) -> Value {
    json!({
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "ok": false,
        "error": {
            "kind": kind,
            "message": quarters_core::escape_untrusted_text_bounded(message, 512),
            "hint": hint.map(|value| quarters_core::escape_untrusted_text_bounded(value, 512)),
        },
    })
}

fn serialization_error(error: serde_json::Error) -> QuartersError {
    QuartersError::new(quarters_core::ErrorKind::System, "could not serialize command output").with_source(error)
}

fn fallback_error_json() -> String {
    "{\"schema_version\":1,\"ok\":false,\"error\":{\"kind\":\"system\",\"message\":\"could not serialize error output\",\"hint\":null}}".to_owned()
}

#[cfg(test)]
mod tests {
    use super::escape_for_human;

    #[test]
    fn human_escaping_preserves_printable_unicode_and_quotes() {
        assert_eq!(escape_for_human("café d'été \"work\""), "café d'été \"work\"");
        assert_eq!(escape_for_human("safe\u{1b}[31m"), "safe\\u{1b}[31m");
        assert_eq!(escape_for_human("left\u{202e}right"), "left\\u{202e}right");
    }
}
