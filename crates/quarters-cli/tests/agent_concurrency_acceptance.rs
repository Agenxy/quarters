// SPDX-License-Identifier: GPL-3.0-or-later
//! Concurrent private-agent lifecycle acceptance.

use serde_json::Value;
use std::error::Error;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

#[path = "support/agent_guard.rs"]
mod agent_guard;
use agent_guard::AgentGuard;

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
fn concurrent_starts_converge_after_one_injected_launcher_exit() -> Result<(), Box<dyn Error>> {
    for _attempt in 0..20 {
        concurrent_round(true)?;
    }
    Ok(())
}

#[test]
fn concurrent_starts_converge_without_a_launcher_failure() -> Result<(), Box<dyn Error>> {
    for _attempt in 0..20 {
        concurrent_round(false)?;
    }
    Ok(())
}

fn concurrent_round(inject_exit: bool) -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    run(quarters(temporary.path()).args(["create", "concurrent-agent"]))?;
    let _agent = AgentGuard::new(temporary.path(), &["concurrent-agent"]);
    let children = (0..6)
        .map(|_| {
            let mut command = quarters(temporary.path());
            command
                .args(["--json", "agent", "start", "concurrent-agent"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if inject_exit {
                command.env("QUARTERS_TEST_AGENT_EXIT_ONCE", "1");
            }
            command.spawn()
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut reports = Vec::new();
    for child in children {
        let output = child.wait_with_output()?;
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        reports.push(serde_json::from_slice::<Value>(&output.stdout)?);
    }
    let pid = reports.first().ok_or("missing agent result")?["result"]["pid"].clone();
    assert!(reports.iter().all(|report| report["result"]["state"] == "active"));
    assert!(reports.iter().all(|report| report["result"]["pid"] == pid));
    run(quarters(temporary.path()).args(["agent", "stop", "concurrent-agent"]))?;
    run(quarters(temporary.path()).args(["rm", "concurrent-agent", "--confirm", "concurrent-agent"]))?;
    Ok(())
}

#[test]
fn the_single_retry_runs_even_when_the_first_exit_is_seen_after_the_deadline() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    run(quarters(temporary.path()).args(["create", "late-poll"]))?;
    let _agent = AgentGuard::new(temporary.path(), &["late-poll"]);
    // The launcher exits at once, but its owner first looks after the whole
    // ten-second startup budget has passed, as a heavily loaded host can.
    let output = run(quarters(temporary.path())
        .args(["--json", "agent", "start", "late-poll"])
        .env("QUARTERS_TEST_AGENT_EXIT_ONCE", "1")
        .env("QUARTERS_TEST_AGENT_STALL_FIRST_POLL_MS", "10500"))?;
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["result"]["state"], "active");
    run(quarters(temporary.path()).args(["agent", "stop", "late-poll"]))?;
    Ok(())
}

#[test]
fn an_agent_that_exits_on_every_attempt_says_so() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    run(quarters(temporary.path()).args(["create", "always-exits"]))?;
    let output = quarters(temporary.path())
        .args(["--json", "agent", "start", "always-exits"])
        .env("QUARTERS_TEST_AGENT_EXIT_ALWAYS", "1")
        .output()?;
    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stderr)?;
    let message = error["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("on all 2 launch attempts"), "{message}");
    Ok(())
}
