//! Lifecycle artifact human and JSON presentation.

use super::print_success;
use quarters_core::{
    Artifact, ArtifactInspection, ArtifactKind, ArtifactMutationReport, ArtifactReport, CloneMode, Result,
    RollbackMode, RollbackReport, SourceStatus, TemplateUseReport, escape_untrusted_text_bounded,
};
use serde_json::{Value, json};

pub(crate) fn print_artifact_report(report: &ArtifactReport, json_output: bool) -> Result<()> {
    let command = format!("{}.create", report.kind.as_str());
    if json_output {
        return print_success(&command, report, true);
    }
    let action = match report.mode {
        CloneMode::Preview => "Artifact preview",
        CloneMode::Execute => "Created artifact",
    };
    println!(
        "{action} {} '{}' from {}",
        report.kind.as_str(),
        report.name,
        report.source
    );
    println!(
        "  Examined     {} entries, {} logical bytes",
        report.examined_counts.entries, report.examined_counts.logical_bytes
    );
    if let Some(counts) = report.stored_counts {
        println!(
            "  Stored       {} files, {} directories, {} links, {} logical bytes",
            counts.files, counts.directories, counts.symlinks, counts.logical_bytes
        );
    }
    println!(
        "  Cache        {}",
        if report.include_cache { "included" } else { "omitted" }
    );
    println!("  Sensitive    included; arbitrary state may contain credentials");
    println!("  Activity     detached processes unknown");
    println!("  Boundary     host account authority is unchanged; this is not containment");
    Ok(())
}

pub(crate) fn print_artifact_list(
    kind: ArtifactKind,
    inspections: &[ArtifactInspection],
    json_output: bool,
) -> Result<()> {
    let values = inspections.iter().map(inspection_value).collect::<Vec<_>>();
    if json_output {
        return print_success(&format!("{}.list", kind.as_str()), &values, true);
    }
    if inspections.is_empty() {
        println!("No {}s yet.", kind.as_str());
        return Ok(());
    }
    println!("NAME                             HEALTH     SOURCE      BYTES");
    for inspection in inspections {
        match inspection {
            ArtifactInspection::Healthy {
                artifact,
                source_status,
            } => println!(
                "{:<32} {:<10} {:<11} {}",
                artifact.manifest().name,
                "healthy",
                source_status_text(*source_status),
                artifact.manifest().content_integrity.counts.logical_bytes
            ),
            ArtifactInspection::Unhealthy { id, error } => {
                let safe_id = escape_untrusted_text_bounded(id, 64);
                let safe_message = escape_untrusted_text_bounded(error.message(), 512);
                println!("{safe_id:<32} {:<10} {:<11} -", "unhealthy", "unknown");
                println!("  issue: {safe_message}");
            }
        }
    }
    Ok(())
}

pub(crate) fn print_artifact(artifact: &Artifact, source_status: SourceStatus, json_output: bool) -> Result<()> {
    let value = artifact_value(artifact, source_status);
    if json_output {
        return print_success(&format!("{}.show", artifact.manifest().kind.as_str()), &value, true);
    }
    println!("{} {}", artifact.manifest().kind.as_str(), artifact.manifest().name);
    println!("  ID           {}", artifact.manifest().artifact_id);
    println!("  Source       {}", artifact.manifest().source_identity.name);
    println!("  Source state {}", source_status_text(source_status));
    println!("  Platform     {}", artifact.manifest().source_platform);
    println!("  Digest       {}", artifact.manifest().content_integrity.digest);
    println!(
        "  Stored       {} entries, {} logical bytes",
        artifact.manifest().content_integrity.counts.entries,
        artifact.manifest().content_integrity.counts.logical_bytes
    );
    println!("  Sensitive    included; arbitrary state may contain credentials");
    println!("  Integrity    accidental-change evidence, not same-account authentication");
    Ok(())
}

pub(crate) fn print_artifact_verified(artifact: &Artifact, json_output: bool) -> Result<()> {
    let value = json!({
        "kind": artifact.manifest().kind.as_str(),
        "name": artifact.manifest().name,
        "artifact_id": artifact.manifest().artifact_id,
        "verified": true,
        "integrity": artifact.manifest().content_integrity,
        "authentication_boundary": "not authenticated against the same host account",
    });
    if json_output {
        return print_success(&format!("{}.verify", artifact.manifest().kind.as_str()), &value, true);
    }
    println!(
        "Verified {} '{}'",
        artifact.manifest().kind.as_str(),
        artifact.manifest().name
    );
    println!("  Digest {}", artifact.manifest().content_integrity.digest);
    println!("  Boundary not authenticated against the same host account");
    Ok(())
}

pub(crate) fn print_template_use(report: &TemplateUseReport, json_output: bool) -> Result<()> {
    if json_output {
        return print_success("template.use", report, true);
    }
    let action = match report.mode {
        CloneMode::Preview => "Template preview",
        CloneMode::Execute => "Created from template",
    };
    println!("{action} {} -> {}", report.template, report.destination);
    println!("  Layout       {}", report.layout);
    println!("  Stored       {} entries", report.stored_counts.entries);
    println!("  Sensitive    included; arbitrary state may contain credentials");
    println!("  Paths        {}", report.embedded_absolute_paths);
    println!("  Boundary     {}", report.authority_boundary);
    Ok(())
}

pub(crate) fn print_rollback(report: &RollbackReport, json_output: bool) -> Result<()> {
    if json_output {
        return print_success("rollback", report, true);
    }
    let action = match report.mode {
        RollbackMode::Preview => "Rollback preview",
        RollbackMode::Execute => "Rolled back",
    };
    println!("{action} {} <- {}", report.target, report.snapshot);
    println!("  Recovery     {}", report.recovery_name);
    if let Some(id) = &report.recovery_snapshot_id {
        println!("  Recovery ID  {id}");
    }
    println!(
        "  Recovery     cache {}",
        if report.recovery_includes_cache {
            "included"
        } else {
            "omitted"
        }
    );
    println!("  Sensitive    recovery snapshot contains arbitrary private state");
    println!("  Activity     detached processes unknown");
    println!("  Publication  {}", report.publication_model);
    println!("  Boundary     {}", report.authority_boundary);
    Ok(())
}

pub(crate) fn print_artifact_mutation(report: &ArtifactMutationReport, json_output: bool) -> Result<()> {
    if json_output {
        return print_success(&format!("{}.{}", report.kind.as_str(), report.operation), report, true);
    }
    match &report.name {
        Some(name) => println!(
            "Renamed {} '{}' -> '{}'",
            report.kind.as_str(),
            report.previous_name,
            name
        ),
        None => println!("Removed {} '{}'", report.kind.as_str(), report.previous_name),
    }
    println!("  ID {}", report.artifact_id);
    Ok(())
}

fn inspection_value(inspection: &ArtifactInspection) -> Value {
    match inspection {
        ArtifactInspection::Healthy {
            artifact,
            source_status,
        } => artifact_value(artifact, *source_status),
        ArtifactInspection::Unhealthy { id, error } => json!({
            "id": escape_untrusted_text_bounded(id, 64),
            "id_encoding": "escaped_bounded",
            "health": "unhealthy",
            "issue": {
                "code": error.kind().as_str(),
                "message": escape_untrusted_text_bounded(error.message(), 512),
                "hint": error.hint().map(|value| escape_untrusted_text_bounded(value, 512)),
            }
        }),
    }
}

fn artifact_value(artifact: &Artifact, source_status: SourceStatus) -> Value {
    json!({
        "health": "healthy",
        "source_status": source_status_text(source_status),
        "manifest": artifact.manifest(),
        "integrity_boundary": "detects accidental or out-of-band modification; not same-account authentication",
    })
}

const fn source_status_text(status: SourceStatus) -> &'static str {
    match status {
        SourceStatus::Present => "present",
        SourceStatus::Orphaned => "orphaned",
    }
}
