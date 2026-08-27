//! Authenticated bundle output contracts.

use super::{path_for_human, print_success, safe_json_path, safe_json_text};
use quarters_core::{BundleExportReport, BundleImportReport, CloneMode, ExportKeyReport, Result};
use serde_json::{Value, json};

pub(crate) fn print_bundle_export(report: &BundleExportReport, json: bool) -> Result<()> {
    if json {
        return print_success("bundle.export", &bundle_export_value(report), true);
    }
    let action = match report.mode {
        CloneMode::Preview => "Export preview",
        CloneMode::Execute => "Exported",
    };
    println!(
        "{action} {} '{}' -> {}",
        report.source_kind.as_str(),
        report.source_name,
        path_for_human(&report.destination)
    );
    if let Some(id) = &report.export_id {
        println!("  Export ID   {id}");
    }
    println!("  Entries     {}", report.content_integrity.counts.entries);
    println!("  Bytes       {}", report.content_integrity.counts.logical_bytes);
    println!("  Sensitive   included in plaintext");
    println!("  Boundary    {}", report.security_boundary);
    if let Some(warning) = &report.publication_warning {
        println!("  Warning     {warning}");
    }
    Ok(())
}

pub(crate) fn print_bundle_import(report: &BundleImportReport, json: bool) -> Result<()> {
    if json {
        return print_success("bundle.import", &bundle_import_value(report), true);
    }
    let action = match report.mode {
        CloneMode::Preview => "Import preview",
        CloneMode::Execute => "Imported template",
    };
    println!("{action} {} -> {}", report.source_name, report.destination);
    println!("  Source kind {}", report.source_kind.as_str());
    println!("  Export ID   {}", report.export_id);
    if let Some(id) = &report.artifact_id {
        println!("  Template ID {id}");
    }
    println!("  Platform    {}", report.source_platform);
    println!("  Shell       {}", safe_json_path(&report.default_shell));
    println!("  Entries     {}", report.content_integrity.counts.entries);
    println!("  Plan digest {}", report.plan_digest);
    println!("  Safety      {}", report.content_safety);
    if let Some(warning) = &report.publication_warning {
        println!("  Warning     {warning}");
    }
    Ok(())
}

pub(crate) fn print_export_key(report: &ExportKeyReport, json: bool) -> Result<()> {
    if json {
        return print_success("bundle.key.create", &report, true);
    }
    println!("Created a private {}-byte export authentication key.", report.bytes);
    println!("  Key bytes and path are intentionally omitted from output.");
    println!("  Keep the key separate from plaintext bundles.");
    if let Some(warning) = &report.publication_warning {
        println!("  Warning: {warning}");
    }
    Ok(())
}

fn bundle_export_value(report: &BundleExportReport) -> Value {
    json!({
        "mode": report.mode,
        "source_kind": report.source_kind,
        "source_name": safe_json_text(&report.source_name, 32),
        "export_id": report.export_id.as_deref().map(|value| safe_json_text(value, 32)),
        "destination": safe_json_path(&report.destination),
        "content_integrity": report.content_integrity,
        "limits": report.limits,
        "includes_sensitive_state": report.includes_sensitive_state,
        "security_boundary": report.security_boundary,
        "publication_warning": report.publication_warning,
    })
}

fn bundle_import_value(report: &BundleImportReport) -> Value {
    json!({
        "mode": report.mode,
        "destination": safe_json_text(&report.destination, 32),
        "plan_digest": safe_json_text(&report.plan_digest, 64),
        "artifact_id": report.artifact_id.as_deref().map(|value| safe_json_text(value, 32)),
        "export_id": safe_json_text(&report.export_id, 32),
        "source_kind": report.source_kind,
        "source_name": safe_json_text(&report.source_name, 32),
        "source_platform": report.source_platform,
        "default_shell": safe_json_path(&report.default_shell),
        "content_integrity": report.content_integrity,
        "authentication": report.authentication,
        "content_safety": report.content_safety,
        "publication_warning": report.publication_warning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quarters_core::{ArtifactCounts, ArtifactKind, ContentIntegrity};
    use std::path::PathBuf;

    #[test]
    fn imported_shell_paths_are_safe_for_json_presentation() -> std::result::Result<(), serde_json::Error> {
        let report = BundleImportReport {
            mode: CloneMode::Preview,
            destination: "destination".to_owned(),
            plan_digest: "a".repeat(64),
            artifact_id: None,
            export_id: "export-id".to_owned(),
            source_kind: ArtifactKind::Template,
            source_name: "source".to_owned(),
            source_platform: "macos".to_owned(),
            default_shell: PathBuf::from(format!("/bin/\u{202e}sh{}", "x".repeat(600))),
            content_integrity: ContentIntegrity {
                algorithm: "test".to_owned(),
                digest: "b".repeat(64),
                counts: ArtifactCounts::default(),
            },
            authentication: "test".to_owned(),
            content_safety: "test".to_owned(),
            publication_warning: None,
        };
        let value = bundle_import_value(&report);
        let shell: String = serde_json::from_value(value["default_shell"].clone())?;
        let human_shell = safe_json_path(&report.default_shell);
        assert!(shell.contains("\\u{202e}"));
        assert!(!shell.contains('\u{202e}'));
        assert!(shell.chars().count() <= 512);
        assert_eq!(human_shell, shell);
        Ok(())
    }
}
