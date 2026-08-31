//! Human and machine output contracts.

mod artifacts;
mod bundles;
mod doctor;

pub(crate) use artifacts::{
    print_artifact, print_artifact_list, print_artifact_mutation, print_artifact_report, print_artifact_verified,
    print_rollback, print_template_use,
};
pub(crate) use bundles::{print_bundle_export, print_bundle_import, print_export_key};

use crate::adapter::AdapterReport;
use crate::shortcut::{ShortcutAction, ShortcutReport};
use clap::error::Error as ClapError;
use quarters_core::{
    AgentStatus, Capabilities, CloneMode, CloneReport, LeaseState, QuartersError, RecoverySummary, RollbackIssue,
    RollbackObservation, Space, SpaceInspection, SpaceRenameReport, SpaceUpgradeReport, ToolProbe,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const OUTPUT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy)]
pub(crate) struct DoctorSpace<'a> {
    pub(crate) requested: Option<&'a str>,
    pub(crate) space: Option<&'a Space>,
    pub(crate) inspection_error: Option<&'a QuartersError>,
    pub(crate) environment_validated: Option<bool>,
    pub(crate) lease_state: Option<LeaseState>,
    pub(crate) agent_status: Option<&'a AgentStatus>,
    pub(crate) adapters: Option<&'a AdapterReport>,
}

pub(crate) fn print_agent(action: &str, status: &AgentStatus, json_output: bool) -> quarters_core::Result<()> {
    if json_output {
        return print_success(&format!("agent.{action}"), status, true);
    }
    println!("Private SSH agent for {}: {}", status.space, status.state.as_str());
    if let Some(pid) = status.pid {
        println!("  PID     {pid}");
    }
    if let Some(socket) = &status.socket {
        println!("  Socket  {}", escape_for_human(socket));
    }
    println!("  Check   {}", status.detail);
    println!("  Scope   separate credential process; host account authority is unchanged");
    Ok(())
}

pub(crate) fn print_adapter(action: &str, report: &AdapterReport, json_output: bool) -> quarters_core::Result<()> {
    if json_output {
        return print_success(&format!("adapter.{action}"), report, true);
    }
    println!("OpenSSH adapters for {}", report.space);
    println!(
        "  quarters {:<10} {}",
        report.launcher.state.as_str(),
        path_for_human(&report.launcher.path)
    );
    for entry in &report.tools {
        println!(
            "  {:<8} {:<10} {}",
            entry.tool,
            entry.state.as_str(),
            path_for_human(&entry.path)
        );
    }
    println!("  Boundary {}", report.boundary);
    Ok(())
}

pub(crate) fn print_upgrade(
    report: &SpaceUpgradeReport,
    preview: bool,
    json_output: bool,
) -> quarters_core::Result<()> {
    if json_output {
        return print_success("upgrade", report, true);
    }
    println!(
        "{} {}",
        if preview { "Upgrade preview" } else { "Upgraded" },
        report.name
    );
    println!("  Schema  {} -> {}", report.previous_schema, report.schema);
    println!(
        "  ID      {}",
        report
            .space_id
            .as_deref()
            .unwrap_or("assigned only during confirmed execution")
    );
    println!("  Activity {}", report.activity);
    println!("  Boundary {}", report.boundary);
    Ok(())
}

pub(crate) fn print_space_rename(
    report: &SpaceRenameReport,
    preview: bool,
    json_output: bool,
) -> quarters_core::Result<()> {
    if json_output {
        return print_success("rename", report, true);
    }
    println!(
        "{} {} -> {}",
        if preview { "Rename preview" } else { "Renamed" },
        report.previous,
        report.name
    );
    println!("  ID       {}", report.space_id);
    println!("  Activity {}", report.activity);
    println!("  Boundary {}", report.boundary);
    Ok(())
}

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
    println!("  Layout {}", space.layout());
    if let Some(space_id) = space.id() {
        println!("  ID     {space_id}");
    }
    println!("  Model  host account, separate user-owned state");
    Ok(())
}

pub(crate) fn print_host_fork(report: &quarters_core::HostForkReport, json_output: bool) -> quarters_core::Result<()> {
    if json_output {
        return print_success("create", report, true);
    }
    println!(
        "{} {} from host {} policy",
        if report.mode == quarters_core::HostForkMode::Preview {
            "Host-fork preview for"
        } else {
            "Created"
        },
        report.destination,
        match report.policy {
            quarters_core::HostForkPolicy::Shell => "shell",
        }
    );
    println!("  Plan       {}", report.plan_digest);
    println!(
        "  Selected   {} files, {} logical bytes",
        report.file_count, report.logical_bytes
    );
    println!("  Missing    {} optional preset files", report.absent.len());
    println!("  Ineligible {} optional preset files", report.ineligible.len());
    for file in &report.files {
        println!(
            "  File       {} ({} bytes, {}, {})",
            path_for_human(&file.path),
            file.bytes,
            file.category,
            file.transformation
        );
    }
    for entry in &report.ineligible {
        println!("  Refused    {} ({})", path_for_human(&entry.path), entry.reason);
    }
    for path in &report.absent {
        println!("  Absent     {}", path_for_human(path));
    }
    println!(
        "  Conflicts  {} generated files{}",
        report.files.iter().filter(|file| file.generated_conflict).count(),
        if report.replace_generated {
            " (approved)"
        } else {
            " (not approved)"
        }
    );
    println!("  Warning    {}", report.warning);
    println!("  Boundary   {}", report.authority_boundary);
    if report.mode == quarters_core::HostForkMode::Preview {
        println!(
            "  Next       repeat the same options with --confirm-plan {}",
            report.plan_digest
        );
    }
    Ok(())
}

pub(crate) fn print_clone(report: &CloneReport, json_output: bool) -> quarters_core::Result<()> {
    if json_output {
        return print_success("clone", report, true);
    }
    let action = match report.mode {
        CloneMode::Preview => "Clone preview",
        CloneMode::Execute => "Cloned",
    };
    println!("{action} {} -> {}", report.source, report.destination);
    println!("  Layout       {}", report.layout);
    println!(
        "  Included     {} files, {} directories, {} links, {} logical bytes",
        report.counts.files, report.counts.directories, report.counts.symlinks, report.counts.logical_bytes,
    );
    println!(
        "  Excluded     {} cache roots, {} sockets, {} FIFOs, {} devices, {} foreign-owned entries",
        report.exclusions.cache_roots,
        report.exclusions.sockets,
        report.exclusions.fifos,
        report.exclusions.devices,
        report.exclusions.foreign_owned,
    );
    println!(
        "  Topology     {} hard-linked files copied independently, {} links into omitted cache roots",
        report.exclusions.hard_linked_files_copied_independently, report.exclusions.symlinks_into_omitted_cache_roots,
    );
    println!(
        "  Commands     {} managed links omitted and recreated for the destination",
        report.exclusions.managed_command_links,
    );
    if let Some(space_id) = &report.destination_space_id {
        println!("  New ID       {space_id}");
    }
    println!("  Sensitive    included; arbitrary state may contain credentials");
    println!("  Activity     detached processes unknown");
    println!("  Paths        embedded absolute paths were not rewritten");
    println!("  Boundary     host account authority is unchanged; this is not containment");
    if report.mode == CloneMode::Preview {
        println!("  Next         repeat the source with --confirm-sensitive-state to execute");
    }
    Ok(())
}

pub(crate) fn print_recovered(summary: &RecoverySummary, json_output: bool) -> quarters_core::Result<()> {
    if json_output {
        return print_success("recover", summary, true);
    }
    println!(
        "Recovered {} unfinished space creation(s), {} retired space entry(s), {} rename transaction(s), {} rollback transaction(s), {} artifact creation(s), {} artifact deletion(s), and {} manifest temporary file(s); {} rename issue(s), {} rollback issue(s), {} space and {} artifact creation(s) remain",
        summary.unfinished_creations,
        summary.retired_entries,
        summary.rename_transactions,
        summary.rollback_transactions,
        summary.unfinished_artifact_creations,
        summary.reclaiming_artifacts,
        summary.artifact_manifest_temps,
        summary.rename_issues,
        summary.rollback_issues.len(),
        summary.active_creations,
        summary.active_artifact_creations
    );
    Ok(())
}

pub(crate) fn print_list(
    inspections: &[SpaceInspection],
    rollbacks: &[RollbackObservation],
    rollback_issues: &[RollbackIssue],
    json_output: bool,
) -> quarters_core::Result<()> {
    let visible = inspections.iter().filter(|inspection| {
        !rollbacks
            .iter()
            .any(|rollback| rollback.target.as_str() == inspection.name())
            && !rollback_issues.iter().any(|issue| {
                issue
                    .target
                    .as_ref()
                    .is_some_and(|target| target.as_str() == inspection.name())
            })
    });
    let mut values: Vec<Value> = visible.clone().map(inspection_value).collect();
    values.extend(rollbacks.iter().map(rollback_space_value));
    let mut represented_issue_targets = rollbacks
        .iter()
        .map(|rollback| rollback.target.clone())
        .collect::<BTreeSet<_>>();
    values.extend(rollback_issues.iter().filter_map(|issue| {
        let target = issue.target.as_ref()?;
        represented_issue_targets
            .insert(target.clone())
            .then(|| rollback_issue_space_value(issue))
            .flatten()
    }));
    if json_output {
        return print_success("list", &values, true);
    }
    if inspections.is_empty() && rollbacks.is_empty() && rollback_issues.iter().all(|issue| issue.target.is_none()) {
        println!("No spaces yet. Create one with: quarters create <name>");
        return Ok(());
    }
    println!("NAME                             HEALTH     LAYOUT     HOME");
    for inspection in visible {
        match inspection {
            SpaceInspection::Healthy(space) => {
                println!(
                    "{:<32} {:<10} {:<10} {}",
                    space.manifest().name,
                    "healthy",
                    space.layout(),
                    path_for_human(&space.home())
                );
            }
            SpaceInspection::Unhealthy { name, error, .. } => {
                println!(
                    "{:<32} {:<10} {:<10} -",
                    entry_name_for_human(name),
                    "unhealthy",
                    "unknown"
                );
                print_inspection_issue(error);
            }
        }
    }
    for rollback in rollbacks {
        println!("{:<32} {:<10} {:<10} -", rollback.target, "rollback", "unknown");
        println!(
            "  issue: rollback {} is in progress; doctor reports recovery action {:?}",
            rollback.state, rollback.action
        );
    }
    let mut represented_issue_targets = rollbacks
        .iter()
        .map(|rollback| rollback.target.clone())
        .collect::<BTreeSet<_>>();
    for issue in rollback_issues {
        let Some(target) = &issue.target else {
            continue;
        };
        if !represented_issue_targets.insert(target.clone()) {
            continue;
        }
        println!("{target:<32} {:<10} {:<10} -", "rollback", "unknown");
        println!("  issue: {}", escape_for_human(&issue.message));
    }
    Ok(())
}

pub(crate) enum StatusEntry {
    Healthy {
        space: Space,
        lease_state: LeaseState,
        agent_state: String,
    },
    Unhealthy {
        name: String,
        name_was_lossy: bool,
        error: QuartersError,
    },
    Rollback {
        observation: RollbackObservation,
    },
    RollbackIssue {
        issue: RollbackIssue,
    },
}

impl StatusEntry {
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Healthy { space, .. } => space.manifest().name.as_str(),
            Self::Unhealthy { name, .. } => name,
            Self::Rollback { observation } => observation.target.as_str(),
            Self::RollbackIssue { issue } => issue
                .target
                .as_ref()
                .map_or(issue.marker.as_str(), quarters_core::SpaceName::as_str),
        }
    }
}

pub(crate) fn print_status(
    statuses: &[StatusEntry],
    current: Option<&str>,
    shortcuts: &[ShortcutReport],
    json_output: bool,
) -> quarters_core::Result<()> {
    let values: Vec<Value> = statuses.iter().map(|status| status_value(status, current)).collect();
    let result = json!({
        "observation_scope": "quarters-cooperative-lease",
        "detached_processes": "unknown",
        "current_space": current,
        "current_evidence": "self-reported QUARTERS_SPACE, matched to a fully validated healthy space",
        "spaces": values,
        "shortcuts": shortcuts.iter().map(shortcut_value).collect::<Vec<_>>(),
    });
    if json_output {
        return print_success("status", &result, true);
    }
    if statuses.is_empty() {
        println!("No spaces yet. Create one with: quarters create <name>");
        print_shortcut_summaries(shortcuts);
        return Ok(());
    }
    println!("NAME                             HEALTH     LAYOUT     LEASE    AGENT      CURRENT  HOME");
    for status in statuses {
        print_human_status(status, current);
    }
    if let Some(current) = current {
        println!("Current space claim: {}", entry_name_for_human(current));
    }
    println!();
    println!("Lease state covers Quarters-managed operations; detached processes are unknown.");
    print_shortcut_summaries(shortcuts);
    Ok(())
}

fn print_shortcut_summaries(shortcuts: &[ShortcutReport]) {
    for shortcut in shortcuts {
        println!(
            "Shortcut {}: {} ({})",
            shortcut.name,
            shortcut.state.as_str(),
            shortcut.context
        );
    }
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
    layout: &quarters_core::StoreLayoutDiagnosis,
    tools: &[ToolProbe],
    shortcuts: &[ShortcutReport],
    context: DoctorSpace<'_>,
    recovery: std::result::Result<&RecoverySummary, &QuartersError>,
    json_output: bool,
) -> quarters_core::Result<()> {
    let DoctorSpace {
        requested,
        space,
        inspection_error,
        environment_validated,
        lease_state,
        agent_status,
        adapters,
    } = context;
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
                "rollback_transactions": summary.rollback_transactions,
                "rename_transactions": summary.rename_transactions,
                "rename_issues": summary.rename_issues,
                "rollbacks": summary.rollbacks,
                "rollback_issues": summary.rollback_issues,
                "active_artifact_creations": summary.active_artifact_creations,
                "unfinished_artifact_creations": summary.unfinished_artifact_creations,
                "reclaiming_artifacts": summary.reclaiming_artifacts,
                "artifact_manifest_temps": summary.artifact_manifest_temps,
                "orphaned_artifacts": summary.orphaned_artifacts,
                "template_logical_bytes": summary.template_logical_bytes,
                "snapshot_logical_bytes": summary.snapshot_logical_bytes,
                "unknown_entries_at_least": summary.unknown_entries_at_least,
            })
        },
    );
    let result = json!({
        "platform": capabilities,
        "store_layout": layout,
        "space_requested": requested.map(|name| safe_json_text(name, 64)),
        "space": space.map(space_value),
        "space_inspection_error": inspection_error.map(inspection_error_value),
        "space_environment_validated": environment_validated,
        "space_lease_state": lease_state.map(LeaseState::as_str),
        "space_ssh_agent": agent_status,
        "space_command_links": adapters,
        "detached_processes": space.map(|_space| "unknown"),
        "recovery": recovery_value,
        "shortcuts": shortcuts.iter().map(shortcut_value).collect::<Vec<_>>(),
        "tools": tools,
        "classification_evidence": "installed executable plus declared state-location contract; no credentials were read",
    });
    if json_output {
        return print_success("doctor", &result, true);
    }
    print_doctor_human(capabilities, layout, tools, shortcuts, context, recovery);
    Ok(())
}

fn print_doctor_human(
    capabilities: &Capabilities,
    layout: &quarters_core::StoreLayoutDiagnosis,
    tools: &[ToolProbe],
    shortcuts: &[ShortcutReport],
    context: DoctorSpace<'_>,
    recovery: std::result::Result<&RecoverySummary, &QuartersError>,
) {
    println!("Quarters doctor");
    println!("  Platform       {}", capabilities.platform);
    doctor::print_store_layout(layout);
    println!("  Baseline       available (HOME and user-state profile)");
    println!(
        "  Workspace      {}: {}",
        capabilities.workspace_profile.status, capabilities.workspace_profile.detail
    );
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
            "  Recovery       {} space active, {} space unfinished, {} retired, {} rename, {} rename issue; {} artifact active, {} artifact unfinished, {} reclaiming, {} manifest temp",
            summary.active_creations,
            summary.unfinished_creations,
            summary.retired_entries,
            summary.rename_transactions,
            summary.rename_issues,
            summary.active_artifact_creations,
            summary.unfinished_artifact_creations,
            summary.reclaiming_artifacts,
            summary.artifact_manifest_temps
        ),
        Err(error) => println!("  Recovery       unavailable: {}", escape_for_human(error.message())),
    }
    if let Ok(summary) = recovery {
        println!(
            "  Artifacts      {} orphaned; {} template bytes, {} snapshot bytes; {} unknown hidden entries retained",
            summary.orphaned_artifacts,
            summary.template_logical_bytes,
            summary.snapshot_logical_bytes,
            summary.unknown_entries_at_least
        );
        for rollback in &summary.rollbacks {
            println!(
                "  Rollback       {} [{}] -> {:?}",
                rollback.target, rollback.state, rollback.action
            );
        }
        for issue in &summary.rollback_issues {
            println!(
                "  Rollback issue {} target={} [{}]: {}",
                entry_name_for_human(&issue.marker),
                issue
                    .target
                    .as_ref()
                    .map_or("unknown", quarters_core::SpaceName::as_str),
                issue.code,
                escape_for_human(&issue.message)
            );
            if let Some(hint) = &issue.hint {
                println!("    Next          {}", escape_for_human(hint));
            }
        }
    }
    for shortcut in shortcuts {
        println!(
            "  Shortcut {:<4} {:<11} ({})",
            shortcut.name,
            shortcut.state.as_str(),
            shortcut.context
        );
    }
    print_doctor_space(context);
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
}

fn print_doctor_space(context: DoctorSpace<'_>) {
    if let (Some(requested), Some(error)) = (context.requested, context.inspection_error) {
        println!("  Space          {} (not inspected)", escape_for_human(requested));
        println!("    issue: {}", escape_for_human(error.message()));
        if let Some(hint) = error.hint() {
            println!("    hint: {}", escape_for_human(hint));
        }
        return;
    }
    let (Some(space), Some(lease_state)) = (context.space, context.lease_state) else {
        return;
    };
    println!(
        "  Space          {} [{}] ({})",
        space.manifest().name,
        space.layout(),
        path_for_human(&space.home())
    );
    if context.environment_validated == Some(false) {
        println!("  Environment    blocked by private-agent state");
        println!(
            "  Next           quarters agent recover {} --confirm {}",
            space.manifest().name,
            space.manifest().name
        );
    } else {
        println!("  Environment    validated");
    }
    println!("  Lease          {} (detached processes unknown)", lease_state.as_str());
    if let Some(agent) = context.agent_status {
        println!("  SSH agent      {} ({})", agent.state.as_str(), agent.detail);
    }
    if let Some(report) = context.adapters {
        println!("  Launcher       {}", report.launcher.state.as_str());
        for entry in &report.tools {
            println!("  Adapter {:<7} {}", entry.tool, entry.state.as_str());
        }
    }
}

pub(crate) fn print_shortcut(
    action: ShortcutAction,
    report: &ShortcutReport,
    json_output: bool,
) -> quarters_core::Result<()> {
    let value = shortcut_value(report);
    if json_output {
        return print_success(&format!("shortcut {}", action.as_str()), &value, true);
    }
    println!("Shortcut {}: {}", report.name, report.state.as_str());
    println!("  Context  {}", report.context);
    if let Some(directory) = &report.directory {
        println!("  Directory {}", path_for_human(directory));
        println!("  On PATH   {}", if report.directory_on_path { "yes" } else { "no" });
    }
    if let Some(target) = &report.link_target {
        println!("  Target    {}", path_for_human(target));
    }
    for command in &report.shortcut_matches {
        println!("  Resolves  {}", path_for_human(command));
    }
    if let Some(issue) = &report.issue {
        println!("  Issue     {}", escape_for_human(issue));
    }
    println!("  Check     {}", report.parent_shell_check);
    println!("  Note      {}", report.limitation);
    Ok(())
}

pub(crate) fn print_removed(
    name: &str,
    surviving_artifacts: Option<(usize, usize)>,
    json_output: bool,
) -> quarters_core::Result<()> {
    let (surviving_templates, surviving_snapshots) = surviving_artifacts.unzip();
    if json_output {
        return print_success(
            "rm",
            &json!({
                "removed": safe_json_text(name, 64),
                "surviving_templates": surviving_templates,
                "surviving_snapshots": surviving_snapshots,
                "artifacts_cascade_removed": false,
            }),
            true,
        );
    }
    println!("Removed {}", escape_for_human(name));
    if let Some((surviving_templates, surviving_snapshots)) = surviving_artifacts
        && (surviving_templates > 0 || surviving_snapshots > 0)
    {
        println!(
            "  Kept {surviving_templates} template(s) and {surviving_snapshots} snapshot(s) from this exact space generation."
        );
        println!("  Remove those artifacts separately with their exact confirmed commands.");
    }
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
        "layout": space.layout().as_str(),
        "space_id": space.id().map(quarters_core::SpaceId::as_str),
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
            "layout": null,
            "space_id": null,
            "error": inspection_error_value(error),
        }),
    }
}

fn status_value(status: &StatusEntry, current: Option<&str>) -> Value {
    match status {
        StatusEntry::Healthy {
            space,
            lease_state,
            agent_state,
        } => {
            let mut value = space_value(space);
            value["health"] = Value::String("healthy".to_owned());
            value["lease_state"] = Value::String(lease_state.as_str().to_owned());
            value["ssh_agent_state"] = Value::String(agent_state.clone());
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
            "layout": null,
            "space_id": null,
            "lease_state": "unknown",
            "current": current == Some(name.as_str()),
            "error": inspection_error_value(error),
        }),
        StatusEntry::Rollback { observation } => rollback_space_value(observation),
        StatusEntry::RollbackIssue { issue } => rollback_issue_space_value(issue).unwrap_or_else(|| {
            json!({
                "name": issue.marker,
                "health": "unhealthy",
                "state": "rollback_issue",
            })
        }),
    }
}

fn print_human_status(status: &StatusEntry, current: Option<&str>) {
    match status {
        StatusEntry::Healthy {
            space,
            lease_state,
            agent_state,
        } => {
            let is_current = current == Some(space.manifest().name.as_str());
            println!(
                "{:<32} {:<10} {:<10} {:<8} {:<10} {:<8} {}",
                space.manifest().name,
                "healthy",
                space.layout(),
                lease_state.as_str(),
                agent_state,
                if is_current { "yes" } else { "no" },
                path_for_human(&space.home())
            );
        }
        StatusEntry::Unhealthy { name, error, .. } => {
            let is_current = current == Some(name.as_str());
            println!(
                "{:<32} {:<10} {:<10} {:<8} {:<10} {:<8} -",
                entry_name_for_human(name),
                "unhealthy",
                "unknown",
                "unknown",
                "unknown",
                if is_current { "yes" } else { "no" }
            );
            print_inspection_issue(error);
        }
        StatusEntry::Rollback { observation } => {
            let is_current = current == Some(observation.target.as_str());
            println!(
                "{:<32} {:<10} {:<10} {:<8} {:<10} {:<8} -",
                observation.target,
                "rollback",
                "unknown",
                "held",
                "unknown",
                if is_current { "yes" } else { "no" }
            );
            println!(
                "  issue: rollback {} is in progress; doctor reports recovery action {:?}",
                observation.state, observation.action
            );
        }
        StatusEntry::RollbackIssue { issue } => {
            let name = issue
                .target
                .as_ref()
                .map_or(issue.marker.as_str(), quarters_core::SpaceName::as_str);
            println!(
                "{:<32} {:<10} {:<10} {:<8} {:<10} {:<8} -",
                entry_name_for_human(name),
                "rollback",
                "unknown",
                "unknown",
                "unknown",
                "no"
            );
            println!("  issue: {}", escape_for_human(&issue.message));
        }
    }
}

fn rollback_space_value(observation: &RollbackObservation) -> Value {
    json!({
        "name": observation.target.as_str(),
        "health": "unhealthy",
        "state": "rollback_in_progress",
        "layout": null,
        "space_id": null,
        "lease_state": "held",
        "rollback": observation,
        "error": {
            "kind": "space_active",
            "message": format!("space '{}' has a rollback in progress", observation.target),
            "hint": "run 'quarters doctor' to inspect the durable recovery action",
        },
    })
}

fn rollback_issue_space_value(issue: &RollbackIssue) -> Option<Value> {
    let target = issue.target.as_ref()?;
    Some(json!({
        "name": target.as_str(),
        "health": "unhealthy",
        "state": "rollback_issue",
        "layout": null,
        "space_id": null,
        "lease_state": "unknown",
        "rollback_issue": issue,
        "error": {
            "kind": issue.code,
            "message": issue.message,
            "hint": issue.hint,
        },
    }))
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

fn shortcut_value(report: &ShortcutReport) -> Value {
    json!({
        "name": safe_json_text(&report.name, 32),
        "context": report.context,
        "state": report.state.as_str(),
        "directory": report.directory.as_deref().map(safe_json_path),
        "entry": report.entry.as_deref().map(safe_json_path),
        "link_target": report.link_target.as_deref().map(safe_json_path),
        "shortcut_matches": report.shortcut_matches.iter().map(|path| safe_json_path(path)).collect::<Vec<_>>(),
        "quarters_matches": report.quarters_matches.iter().map(|path| safe_json_path(path)).collect::<Vec<_>>(),
        "directory_on_path": report.directory_on_path,
        "parent_shell_check": safe_json_text(&report.parent_shell_check, 64),
        "parent_shell_limitation": report.limitation,
        "issue": report.issue.as_deref().map(|issue| safe_json_text(issue, 512)),
    })
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
