//! End-to-end credential isolation evidence.

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
    Err(format!("command failed: {}", String::from_utf8_lossy(&output.stderr)).into())
}

#[test]
fn private_ssh_agent_loads_a_real_key_and_remains_scoped_to_one_space() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    run(quarters(temporary.path()).args(["create", "agentdemo"]))?;

    let unset = run(quarters(temporary.path()).args(["--json", "agent", "status", "agentdemo"]))?;
    let unset: Value = serde_json::from_slice(&unset.stdout)?;
    assert_eq!(unset["result"]["state"], "unset");

    let active = run(quarters(temporary.path()).args(["--json", "agent", "start", "agentdemo"]))?;
    let active: Value = serde_json::from_slice(&active.stdout)?;
    assert_eq!(active["result"]["state"], "active");
    let socket = active["result"]["socket"].as_str().ok_or("missing agent socket")?;
    assert!(Path::new(socket).exists());

    let environment = run(quarters(temporary.path()).args(["--json", "env", "agentdemo"]))?;
    let environment: Value = serde_json::from_slice(&environment.stdout)?;
    assert_eq!(environment["result"]["environment"]["SSH_AUTH_SOCK"], socket);

    let empty = quarters(temporary.path())
        .args(["exec", "agentdemo", "--", "ssh-add", "-l"])
        .output()?;
    assert_eq!(empty.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&empty.stdout).contains("no identities"));
    for implicit in [vec!["ssh-add"], vec!["ssh-add", "-t", "1h"]] {
        let rejected = quarters(temporary.path())
            .args(["exec", "agentdemo", "--"])
            .args(implicit)
            .output()?;
        assert_eq!(rejected.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("host account home"));
    }

    let key = temporary.path().join("spaces/agentdemo/home/.ssh/acceptance-key");
    run(quarters(temporary.path()).args([
        "exec",
        "agentdemo",
        "--",
        "/usr/bin/ssh-keygen",
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-f",
        key.to_str().ok_or("key path is not UTF-8")?,
    ]))?;
    run(quarters(temporary.path()).args([
        "exec",
        "agentdemo",
        "--",
        "ssh-add",
        key.to_str().ok_or("key path is not UTF-8")?,
    ]))?;
    let loaded = run(quarters(temporary.path()).args(["exec", "agentdemo", "--", "ssh-add", "-l"]))?;
    assert!(String::from_utf8_lossy(&loaded.stdout).contains("ED25519"));

    let stopped = run(quarters(temporary.path()).args(["--json", "agent", "stop", "agentdemo"]))?;
    let stopped: Value = serde_json::from_slice(&stopped.stdout)?;
    assert_eq!(stopped["result"]["state"], "unset");
    assert!(!Path::new(socket).exists());
    Ok(())
}

#[test]
fn rollback_reports_completion_when_an_unmanaged_adapter_prevents_reinstallation() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    run(quarters(temporary.path()).args(["create", "rollback-links"]))?;
    run(quarters(temporary.path()).args(["adapter", "remove", "rollback-links"]))?;
    let ssh = temporary.path().join("spaces/rollback-links/home/.local/bin/ssh");
    std::fs::write(&ssh, b"unmanaged-snapshot-command")?;
    let state = temporary.path().join("spaces/rollback-links/home/state");
    std::fs::write(&state, b"before")?;
    run(quarters(temporary.path()).args([
        "snapshot",
        "create",
        "rollback-links",
        "with-collision",
        "--confirm-sensitive-state",
        "rollback-links",
    ]))?;
    std::fs::write(&state, b"after")?;

    let rollback = quarters(temporary.path())
        .args([
            "rollback",
            "rollback-links",
            "with-collision",
            "--recovery-name",
            "before-collision-rollback",
            "--confirm-space",
            "rollback-links",
            "--confirm-replace-state",
            "rollback-links",
        ])
        .output()?;

    assert_eq!(rollback.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&rollback.stderr).contains("rollback completed"));
    assert_eq!(std::fs::read(&state)?, b"before");
    assert_eq!(std::fs::read(&ssh)?, b"unmanaged-snapshot-command");
    Ok(())
}
