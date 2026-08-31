//! End-to-end cooperative freeze and active-stationery acceptance tests.

use serde_json::Value;
use std::error::Error;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
fn active_frozen_capture_round_trips_and_records_its_boundary() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("store");
    create(&root, "studio")?;
    std::fs::write(root.join("spaces/studio/home/note.txt"), b"captured\n")?;
    let script = "quarters freeze && \
        quarters template create studio-clean --from-active --preview && \
        quarters template create studio-clean --from-active --confirm-sensitive-state studio && \
        quarters unfreeze --confirm studio";
    run(quarters(&root).args(["exec", "studio", "--", "/bin/sh", "-c", script]))?;

    let shown = run(quarters(&root).args(["--json", "template", "show", "studio-clean"]))?;
    let shown: Value = serde_json::from_slice(&shown.stdout)?;
    assert_eq!(shown["result"]["manifest"]["source_quiescence"], "frozen-active");
    run(quarters(&root).args([
        "template",
        "use",
        "studio-clean",
        "restored",
        "--confirm-sensitive-state",
        "studio-clean",
    ]))?;
    assert_eq!(
        std::fs::read(root.join("spaces/restored/home/note.txt"))?,
        b"captured\n"
    );
    let status = run(quarters(&root).args(["--json", "status", "studio"]))?;
    let status: Value = serde_json::from_slice(&status.stdout)?;
    assert_eq!(status["result"]["spaces"][0]["freeze_state"], "unfrozen");
    Ok(())
}

#[test]
fn active_capture_requires_freeze_and_strict_current_evidence() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("store");
    create(&root, "studio")?;
    let unfrozen = quarters(&root)
        .args([
            "exec",
            "studio",
            "--",
            "quarters",
            "template",
            "create",
            "unsafe",
            "--from-active",
            "--preview",
        ])
        .output()?;
    assert_eq!(unfrozen.status.code(), Some(5));
    assert!(String::from_utf8_lossy(&unfrozen.stderr).contains("active capture requires cooperatively frozen"));

    let forged = quarters(&root)
        .env("QUARTERS_SPACE", "studio")
        .env("QUARTERS_SPACE_ROOT", root.join("spaces/not-studio"))
        .env("QUARTERS_SPACE_HOME", root.join("spaces/studio/home"))
        .args(["template", "create", "forged", "--from-active", "--preview"])
        .output()?;
    assert_eq!(forged.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&forged.stderr).contains("path evidence"));

    run(quarters(&root).args(["freeze", "studio"]))?;
    let inactive = quarters(&root)
        .env("QUARTERS_SPACE", "studio")
        .env("QUARTERS_SPACE_ROOT", root.join("spaces/studio"))
        .env("QUARTERS_SPACE_HOME", root.join("spaces/studio/home"))
        .args(["template", "create", "inactive", "--from-active", "--preview"])
        .output()?;
    assert_eq!(inactive.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&inactive.stderr).contains("existing cooperative lease"));
    Ok(())
}

#[test]
fn frozen_policy_blocks_managed_mutation_but_allows_copy_sources() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("store");
    create(&root, "studio")?;
    run(quarters(&root).args(["agent", "start", "studio"]))?;
    run(quarters(&root).args(["freeze", "studio"]))?;

    for arguments in [
        vec!["exec", "studio", "--", "/usr/bin/true"],
        vec!["enter", "studio", "--shell", "/bin/sh"],
        vec!["agent", "start", "studio"],
        vec!["adapter", "install", "studio"],
        vec!["adapter", "remove", "studio"],
        vec!["rename", "studio", "renamed", "--preview"],
        vec!["upgrade", "studio", "--preview"],
        vec!["rm", "studio", "--confirm", "studio"],
    ] {
        let refused = quarters(&root).args(arguments).output()?;
        assert_eq!(refused.status.code(), Some(5));
        assert!(String::from_utf8_lossy(&refused.stderr).contains("cooperatively frozen"));
    }

    run(quarters(&root).args(["agent", "status", "studio"]))?;
    run(quarters(&root).args(["agent", "stop", "studio"]))?;
    run(quarters(&root).args(["agent", "recover", "studio", "--confirm", "studio"]))?;

    run(quarters(&root).args(["clone", "studio", "copy", "--confirm-sensitive-state", "studio"]))?;
    run(quarters(&root).args([
        "template",
        "create",
        "frozen-source",
        "--from",
        "studio",
        "--confirm-sensitive-state",
        "studio",
    ]))?;
    run(quarters(&root).args([
        "snapshot",
        "create",
        "studio",
        "frozen-snapshot",
        "--confirm-sensitive-state",
        "studio",
    ]))?;
    run(quarters(&root).args(["unfreeze", "studio", "--confirm", "studio"]))?;
    run(quarters(&root).args(["exec", "studio", "--", "/usr/bin/true"]))?;
    Ok(())
}

#[test]
fn refused_frozen_launch_does_not_materialize_runtime_state() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("store");
    create(&root, "studio")?;
    let manifest: Value = serde_json::from_slice(&std::fs::read(root.join("spaces/studio/.quarters.json"))?)?;
    let id = manifest["space_id"]
        .as_str()
        .ok_or("space manifest omitted stable identity")?;
    let uid = std::fs::metadata(&root)?.uid();
    let runtime_base = if cfg!(target_os = "macos") {
        Path::new("/tmp").to_path_buf()
    } else {
        temporary.path().join("runtime-base")
    };
    let runtime = runtime_base.join(format!("quarters-{uid}/{id}"));
    assert!(!runtime.exists());
    run(quarters(&root).args(["freeze", "studio"]))?;

    let refused = quarters(&root)
        .env("XDG_RUNTIME_DIR", &runtime_base)
        .args(["exec", "studio", "--", "/usr/bin/true"])
        .output()?;
    assert_eq!(refused.status.code(), Some(5));
    assert!(!runtime.exists(), "a refused launch created runtime state");
    Ok(())
}

#[test]
fn malformed_freeze_metadata_is_a_bounded_diagnostic() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("store");
    create(&root, "studio")?;
    run(quarters(&root).args(["freeze", "studio"]))?;
    let manifest: Value = serde_json::from_slice(&std::fs::read(root.join("spaces/studio/.quarters.json"))?)?;
    let id = manifest["space_id"]
        .as_str()
        .ok_or("space manifest omitted stable identity")?;
    let marker = root.join(format!("spaces/.freeze-{id}.json"));
    std::fs::write(&marker, b"{\"schema_version\":1,\"unexpected\":true}\n")?;
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600))?;

    let status = run(quarters(&root).args(["--json", "status", "studio"]))?;
    let status: Value = serde_json::from_slice(&status.stdout)?;
    assert_eq!(status["result"]["spaces"][0]["health"], "unhealthy");
    assert_eq!(status["result"]["spaces"][0]["error"]["kind"], "corrupt_state");
    let doctor = run(quarters(&root).args(["--json", "doctor", "studio"]))?;
    let doctor: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(doctor["result"]["space_freeze_state"], Value::Null);
    assert_eq!(doctor["result"]["space_freeze_error"]["kind"], "corrupt_state");
    assert!(
        doctor["result"]["space_freeze_error"]["hint"]
            .as_str()
            .is_some_and(|hint| hint.contains(&marker.to_string_lossy().to_string()))
    );
    run(quarters(&root).args(["unfreeze", "studio", "--confirm", "studio"]))?;
    run(quarters(&root).args(["exec", "studio", "--", "/usr/bin/true"]))?;
    Ok(())
}
