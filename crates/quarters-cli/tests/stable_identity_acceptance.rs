//! End-to-end stable-identity lifecycle acceptance.

use serde_json::Value;
use std::error::Error;
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

#[test]
fn rename_retains_identity_agent_adapters_and_snapshot_binding() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    run(quarters(temporary.path()).args(["create", "before-name"]))?;
    let proof = temporary.path().join("spaces/before-name/home/proof");
    std::fs::write(&proof, b"captured")?;
    run(quarters(temporary.path()).args([
        "snapshot",
        "create",
        "before-name",
        "before-rename",
        "--confirm-sensitive-state",
        "before-name",
    ]))?;
    run(quarters(temporary.path()).args(["agent", "start", "before-name"]))?;
    let before = run(quarters(temporary.path()).args(["--json", "status", "before-name"]))?;
    let before: Value = serde_json::from_slice(&before.stdout)?;
    let id = before["result"]["spaces"][0]["space_id"]
        .as_str()
        .ok_or("missing stable ID")?
        .to_owned();

    let preview = run(quarters(temporary.path()).args(["--json", "rename", "before-name", "after-name", "--preview"]))?;
    let preview: Value = serde_json::from_slice(&preview.stdout)?;
    assert_eq!(preview["result"]["changed"], false);
    assert_eq!(preview["result"]["space_id"], id);

    let renamed = run(quarters(temporary.path()).args([
        "--json",
        "rename",
        "before-name",
        "after-name",
        "--confirm",
        "before-name",
    ]))?;
    let renamed: Value = serde_json::from_slice(&renamed.stdout)?;
    assert_eq!(renamed["result"]["previous"], "before-name");
    assert_eq!(renamed["result"]["name"], "after-name");
    assert_eq!(renamed["result"]["space_id"], id);
    assert!(!temporary.path().join("spaces/before-name").exists());
    assert!(temporary.path().join("spaces/after-name").is_dir());

    let artifact = run(quarters(temporary.path()).args(["--json", "snapshot", "show", "before-rename"]))?;
    let artifact: Value = serde_json::from_slice(&artifact.stdout)?;
    assert_eq!(artifact["result"]["source_status"], "present");
    let adapters = run(quarters(temporary.path()).args(["--json", "adapter", "status", "after-name"]))?;
    let adapters: Value = serde_json::from_slice(&adapters.stdout)?;
    assert_eq!(adapters["result"]["launcher"]["state"], "managed");
    let agent = run(quarters(temporary.path()).args(["--json", "agent", "status", "after-name"]))?;
    let agent: Value = serde_json::from_slice(&agent.stdout)?;
    assert_eq!(agent["result"]["state"], "active");

    let renamed_proof = temporary.path().join("spaces/after-name/home/proof");
    std::fs::write(&renamed_proof, b"mutated")?;
    run(quarters(temporary.path()).args([
        "rollback",
        "after-name",
        "before-rename",
        "--recovery-name",
        "rename-recovery",
        "--confirm-space",
        "after-name",
        "--confirm-replace-state",
        "after-name",
    ]))?;
    assert_eq!(std::fs::read(renamed_proof)?, b"captured");
    run(quarters(temporary.path()).args(["agent", "stop", "after-name"]))?;
    Ok(())
}
