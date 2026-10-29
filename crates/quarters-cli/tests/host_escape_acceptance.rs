//! Acceptance for the explicit `quarters host` escape from a Quarter.

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
    if !output.status.success() {
        return Err(format!(
            "command failed with {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output)
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
