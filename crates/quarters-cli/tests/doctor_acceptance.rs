//! End-to-end acceptance tests for non-mutating store diagnosis.

use serde_json::Value;
use std::error::Error;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn quarters(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_quarters"));
    command.arg("--root").arg(root);
    command
}

fn run(command: &mut Command) -> Result<Output, Box<dyn Error>> {
    let output = command.output()?;
    if output.status.success() {
        return Ok(output);
    }
    Err(format!(
        "command failed with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

fn create(root: &Path, name: &str) -> Result<(), Box<dyn Error>> {
    run(quarters(root).args(["create", name]))?;
    Ok(())
}

#[test]
fn doctor_never_creates_observation_state_through_a_linked_root() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let target = temporary.path().join("target");
    std::fs::create_dir(&target)?;
    let linked = temporary.path().join("linked-root");
    std::os::unix::fs::symlink(&target, &linked)?;

    let doctor = run(quarters(&linked).args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(report["result"]["recovery"]["status"], "unavailable");
    assert!(!target.join(".observe").exists());
    Ok(())
}

#[test]
fn doctor_reports_root_format_without_repairing_it() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let absent = temporary.path().join("absent");
    let doctor = run(quarters(&absent).args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(report["result"]["store_layout"]["state"], "absent");
    assert_eq!(report["result"]["store_layout"]["writable"], true);
    assert!(!absent.exists());

    assert_retired_migration_file_is_inert(temporary.path())?;
    assert_dual_layout_is_ambiguous(temporary.path())?;
    assert_staging_diagnosis_is_bounded(temporary.path())?;
    Ok(())
}

fn assert_retired_migration_file_is_inert(parent: &Path) -> Result<(), Box<dyn Error>> {
    let root = parent.join("stray-retired-migration-file");
    create(&root, "first")?;
    let retired = root.join(".quarters-store-migration.json");
    std::fs::write(&retired, b"{}")?;
    let doctor = run(quarters(&root).args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    let layout = report["result"]["store_layout"]
        .as_object()
        .ok_or("store layout report was not an object")?;
    assert_eq!(layout["state"], "marked-visible");
    assert_eq!(layout["error_kind"], Value::Null);
    assert!(!layout.contains_key("migration_marker"));
    create(&root, "second")?;
    assert!(root.join("spaces/first").is_dir());
    assert!(root.join("spaces/second").is_dir());
    assert!(retired.is_file());
    Ok(())
}

fn assert_dual_layout_is_ambiguous(parent: &Path) -> Result<(), Box<dyn Error>> {
    let root = parent.join("dual");
    create(&root, "work")?;
    std::fs::create_dir(root.join(".spaces"))?;
    std::fs::set_permissions(root.join(".spaces"), std::fs::Permissions::from_mode(0o700))?;
    let doctor = run(quarters(&root).args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(report["result"]["store_layout"]["state"], "ambiguous-dual-layout");
    assert_eq!(report["result"]["store_layout"]["writable"], false);
    assert_eq!(report["result"]["recovery"]["status"], "unavailable");
    assert!(root.join("spaces/work").is_dir());
    assert!(root.join(".spaces").is_dir());
    let named = run(quarters(&root).args(["--json", "doctor", "work"]))?;
    let named: Value = serde_json::from_slice(&named.stdout)?;
    assert_eq!(named["result"]["store_layout"]["state"], "ambiguous-dual-layout");
    assert_eq!(named["result"]["space_requested"], "work");
    assert_eq!(named["result"]["space"], Value::Null);
    assert_eq!(named["result"]["space_inspection_error"]["kind"], "corrupt_state");
    Ok(())
}

fn assert_staging_diagnosis_is_bounded(parent: &Path) -> Result<(), Box<dyn Error>> {
    let root = parent.join("staging");
    create(&root, "work")?;
    for index in 0..20 {
        std::fs::write(
            root.join(format!(".quarters-store-staging-invalid-{index}.tmp")),
            b"reserved",
        )?;
    }
    let doctor = run(quarters(&root).args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(
        report["result"]["store_layout"]["state"],
        "marked-visible-with-staging-issue"
    );
    assert_eq!(report["result"]["store_layout"]["root_format"], "visible");
    assert_eq!(report["result"]["store_layout"]["writable"], true);
    assert_eq!(
        report["result"]["store_layout"]["staging_entries"]
            .as_array()
            .map(Vec::len),
        Some(16)
    );
    assert_eq!(report["result"]["store_layout"]["staging_entries_at_least"], 20);
    for index in 0..20 {
        assert!(
            root.join(format!(".quarters-store-staging-invalid-{index}.tmp"))
                .is_file()
        );
    }
    let doctor = run(quarters(&root).arg("doctor"))?;
    let human = String::from_utf8(doctor.stdout)?;
    assert!(human.contains("staging issue:"));
    assert!(human.contains("showing 16 of at least 20 entries"));
    Ok(())
}
