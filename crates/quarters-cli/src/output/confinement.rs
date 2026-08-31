//! Bounded machine presentation for filesystem-confinement plans.

use super::{safe_json_path, safe_json_text};
use serde_json::{Value, json};

pub(super) fn value(plan: &quarters_core::ConfinementPlan) -> Value {
    let grants = plan
        .grants
        .iter()
        .map(|grant| {
            json!({
                "path": safe_json_path(&grant.path),
                "access": safe_json_text(&grant.access, 32),
                "source": safe_json_text(&grant.source, 64),
                "required": grant.required,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "mode": safe_json_text(&plan.mode, 32),
        "minimum_abi": plan.minimum_abi,
        "working_directory": safe_json_path(&plan.working_directory),
        "grants": grants,
        "omitted_paths": plan.omitted_paths.iter().map(|path| safe_json_path(path)).collect::<Vec<_>>(),
        "executable_path": plan.executable_path.iter().map(|path| safe_json_path(path)).collect::<Vec<_>>(),
        "omitted_host_path_entries": plan.omitted_host_path_entries,
        "limitations": plan.limitations.iter().map(|item| safe_json_text(item, 512)).collect::<Vec<_>>(),
    })
}
