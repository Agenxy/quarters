// SPDX-License-Identifier: GPL-3.0-or-later
//! Acceptance for the explicit `quarters host` escape from a Quarter.

use std::error::Error;
use std::path::Path;
use std::process::{Command, Output};
#[path = "support/test_store.rs"]
mod test_store;
use test_store::TestTemp as TempDir;

fn quarters(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_quarters"));
    command.arg("--root").arg(root);
    command
}

fn run(command: &mut Command) -> Result<Output, Box<dyn Error>> {
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;

    // Spawned rather than `output()` so a failure names the process and the
    // signal, if any, that ended it.
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let pid = child.id();
    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(output);
    }
    Err(format!(
        "{command:?} (pid {pid}) failed with code {:?}, signal {:?}: {}",
        output.status.code(),
        output.status.signal(),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

fn create(root: &Path, name: &str) -> Result<(), Box<dyn Error>> {
    run(quarters(root).args(["create", name]))?;
    Ok(())
}

/// The value `quarters host` restores: a test running inside a Quarter
/// inherits the outermost host value, not the enclosing Quarter's.
fn outermost_host_value(name: &str) -> Result<String, std::env::VarError> {
    std::env::var(format!("QUARTERS_HOST_{name}")).or_else(|_| std::env::var(name))
}

#[test]
fn host_command_restores_host_home() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    let binary = env!("CARGO_BIN_EXE_quarters");
    let root = temporary.path().to_string_lossy().into_owned();
    let output = run(quarters(temporary.path()).args([
        "exec",
        "work",
        "--",
        binary,
        "--root",
        &root,
        "host",
        "--",
        "/usr/bin/printenv",
        "HOME",
    ]))?;
    assert_eq!(String::from_utf8(output.stdout)?.trim(), outermost_host_value("HOME")?);

    let output = run(quarters(temporary.path()).args([
        "exec",
        "work",
        "--",
        binary,
        "--root",
        &root,
        "host",
        "--",
        "/usr/bin/printenv",
        "PATH",
    ]))?;
    assert_eq!(String::from_utf8(output.stdout)?.trim(), outermost_host_value("PATH")?);
    Ok(())
}
