//! Portable working-directory and platform grant-option acceptance.

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

fn create(root: &Path, name: &str) -> Result<(), Box<dyn Error>> {
    run(quarters(root).args(["create", name]))?;
    Ok(())
}

#[test]
fn workdir_selects_the_initial_directory_without_changing_home() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "workdir")?;
    let selected = temporary.path().join("selected");
    std::fs::create_dir(&selected)?;
    let output = run(quarters(temporary.path())
        .arg("exec")
        .arg("workdir")
        .arg("--workdir")
        .arg(&selected)
        .args(["--", "/bin/sh", "-c", "printf '%s\\n%s\\n' \"$PWD\" \"$HOME\""]))?;
    let lines = String::from_utf8(output.stdout)?
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let canonical_selected = selected.canonicalize()?;
    assert_eq!(
        lines.first().map(String::as_str),
        Some(canonical_selected.to_string_lossy().as_ref())
    );
    assert_eq!(
        lines.get(1).map(String::as_str),
        Some(temporary.path().join("spaces/workdir/home").to_string_lossy().as_ref())
    );
    let entered = run(quarters(temporary.path())
        .arg("enter")
        .arg("workdir")
        .arg("--workdir")
        .arg(&selected)
        .args(["--shell", "/bin/pwd"]))?;
    assert_eq!(
        String::from_utf8(entered.stdout)?.trim(),
        canonical_selected.to_string_lossy()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn macos_refuses_user_grants_with_or_without_confinement() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "mac-grant")?;
    let grant = format!("{}:ro", temporary.path().display());
    for command_name in ["env", "enter", "exec"] {
        for confinement in [false, true] {
            let mut command = quarters(temporary.path());
            if command_name == "env" {
                command.arg("--json");
            }
            command.args([command_name, "mac-grant", "--grant-path", &grant]);
            if confinement {
                command.args(["--confinement", "filesystem"]);
            }
            if command_name == "exec" {
                command.args(["--", "/usr/bin/true"]);
            }
            let output = command.output()?;
            assert_eq!(output.status.code(), Some(6));
            if command_name == "env" {
                let error: Value = serde_json::from_slice(&output.stderr)?;
                assert_eq!(error["error"]["kind"], "unsupported");
                assert!(
                    error["error"]["message"]
                        .as_str()
                        .is_some_and(|message| message.contains("--grant-path"))
                );
            } else {
                assert!(String::from_utf8(output.stderr)?.contains("--grant-path"));
            }
        }
    }
    Ok(())
}
