//! Human and machine output contracts.

use clap::error::Error as ClapError;
use quarters_core::{Capabilities, QuartersError, Space, ToolProbe};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

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
    println!("  Home   {}", space.home().display());
    println!("  Model  host account, separate user-owned state");
    Ok(())
}

pub(crate) fn print_list(spaces: &[Space], json_output: bool) -> quarters_core::Result<()> {
    let values: Vec<Value> = spaces.iter().map(space_value).collect();
    if json_output {
        return print_success("list", &values, true);
    }
    if spaces.is_empty() {
        println!("No spaces yet. Create one with: quarters create <name>");
        return Ok(());
    }
    println!("NAME                             HOME");
    for space in spaces {
        println!("{:<32} {}", space.manifest().name, space.home().display());
    }
    Ok(())
}

pub(crate) fn print_current(current: &str, json_output: bool) -> quarters_core::Result<()> {
    if json_output {
        return print_success("current", &json!({ "space": current }), true);
    }
    println!("{current}");
    Ok(())
}

pub(crate) fn print_environment(
    space: &Space,
    values: &BTreeMap<String, String>,
    json_output: bool,
) -> quarters_core::Result<()> {
    if json_output {
        return print_success(
            "env",
            &json!({ "space": space.manifest().name, "environment": values }),
            true,
        );
    }
    for (name, value) in values {
        println!("{name}={value}");
    }
    Ok(())
}

pub(crate) fn print_doctor(
    capabilities: &Capabilities,
    tools: &[ToolProbe],
    space: Option<&Space>,
    json_output: bool,
) -> quarters_core::Result<()> {
    let result = json!({
        "platform": capabilities,
        "space": space.map(space_value),
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
    if let Some(space) = space {
        println!(
            "  Space          {} ({})",
            space.manifest().name,
            space.home().display()
        );
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
        return print_success("rm", &json!({ "removed": name }), true);
    }
    println!("Removed {name}");
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
    eprintln!("quarters: {}", error.message());
    if let Some(hint) = error.hint() {
        eprintln!("Try: {hint}");
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
        "name": space.manifest().name,
        "home": space.home(),
        "root": space.root(),
        "created_unix_ms": space.manifest().created_unix_ms,
        "default_shell": space.manifest().default_shell,
        "authority_model": space.manifest().authority_model,
    })
}

fn error_envelope(kind: &str, message: &str, hint: Option<&str>) -> Value {
    json!({
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "ok": false,
        "error": { "kind": kind, "message": message, "hint": hint },
    })
}

fn serialization_error(error: serde_json::Error) -> QuartersError {
    QuartersError::new(quarters_core::ErrorKind::System, "could not serialize command output").with_source(error)
}

fn fallback_error_json() -> String {
    "{\"schema_version\":1,\"ok\":false,\"error\":{\"kind\":\"system\",\"message\":\"could not serialize error output\",\"hint\":null}}".to_owned()
}
