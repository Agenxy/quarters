//! Bounded machine presentation for filesystem-confinement plans.

use super::{bounded_path_for_human, escape_for_human, print_success, safe_json_path, safe_json_text};
use quarters_core::Space;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(crate) fn print_environment(
    space: &Space,
    values: &BTreeMap<String, String>,
    confinement: Option<&quarters_core::ConfinementPlan>,
    json_output: bool,
) -> quarters_core::Result<()> {
    if json_output {
        let safe_values = values
            .iter()
            .map(|(name, value)| (safe_json_text(name, 128), safe_json_text(value, 512)))
            .collect::<BTreeMap<_, _>>();
        return print_success(
            "env",
            &json!({
                "space": safe_json_text(space.manifest().name.as_str(), 64),
                "environment": safe_values,
                "confinement": confinement.map(value),
            }),
            true,
        );
    }
    for (name, value) in values {
        println!("{}={}", escape_for_human(name), escape_for_human(value));
    }
    if let Some(plan) = confinement {
        print_human_plan(plan);
    }
    Ok(())
}

fn print_human_plan(plan: &quarters_core::ConfinementPlan) {
    println!(
        "Confinement=filesystem (Landlock ABI {}+, cwd {})",
        plan.minimum_abi,
        bounded_path_for_human(&plan.working_directory)
    );
    println!("ConfinementGrants={}", plan.grants.len());
    println!("ConfinementOmittedHostPathEntries={}", plan.omitted_host_path_entries);
    println!(
        "ConfinementLegacyTIOCSTI={}",
        escape_for_human(&plan.legacy_tiocsti.state)
    );
}

pub(super) fn value(plan: &quarters_core::ConfinementPlan) -> Value {
    let grants = plan
        .grants
        .iter()
        .map(|grant| {
            let requested_access = match grant.access.as_str() {
                "data-read" | "data-read-file" => Some("ro"),
                "data-read-write" | "data-read-write-file" => Some("rw"),
                _ => None,
            };
            json!({
                "path": safe_json_path(&grant.path),
                "access": safe_json_text(&grant.access, 32),
                "requested_access": requested_access,
                "source": safe_json_text(&grant.source, 64),
                "required": grant.required,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "mode": safe_json_text(&plan.mode, 32),
        "minimum_abi": plan.minimum_abi,
        "working_directory": safe_json_path(&plan.working_directory),
        "quarter_command_root": safe_json_path(&plan.quarter_command_root),
        "grants": grants,
        "omitted_paths": plan.omitted_paths.iter().map(|path| safe_json_path(path)).collect::<Vec<_>>(),
        "executable_path": plan.executable_path.iter().map(|path| safe_json_path(path)).collect::<Vec<_>>(),
        "omitted_host_path_entries": plan.omitted_host_path_entries,
        "legacy_tiocsti": {
            "probed": plan.legacy_tiocsti.probed,
            "state": safe_json_text(&plan.legacy_tiocsti.state, 32),
            "detail": safe_json_text(&plan.legacy_tiocsti.detail, 512),
        },
        "limitations": plan.limitations.iter().map(|item| safe_json_text(item, 512)).collect::<Vec<_>>(),
    })
}
