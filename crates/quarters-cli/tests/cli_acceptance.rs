//! End-to-end process and state-profile acceptance tests.

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

#[test]
fn help_and_version_are_successful_control_flow() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let help = run(quarters(temporary.path()).arg("--help"))?;
    assert!(String::from_utf8(help.stdout)?.contains("Usage: quarters"));

    let version = run(quarters(temporary.path()).arg("--version"))?;
    assert!(String::from_utf8(version.stdout)?.starts_with("quarters 0.1.0-alpha.2"));
    Ok(())
}

#[test]
fn create_and_list_have_stable_json() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let output = run(quarters(temporary.path()).args(["--json", "create", "alpha"]))?;
    let created: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(created["schema_version"], 1);
    assert_eq!(created["ok"], true);
    assert_eq!(created["result"]["name"], "alpha");

    let output = run(quarters(temporary.path()).args(["--json", "list"]))?;
    let listed: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(listed["result"].as_array().map(Vec::len), Some(1));
    Ok(())
}

#[test]
fn exec_redirects_state_and_preserves_real_uid() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    let output = run(quarters(temporary.path())
        .env("NPM_CONFIG_USERCONFIG", "/tmp/host-npm-credentials")
        .env("SSH_AUTH_SOCK", "/tmp/host-ssh-agent")
        .env("UNLISTED_SECRET", "must-not-cross")
        .args(["exec", "work", "--", "/usr/bin/env"]))?;
    let environment = String::from_utf8(output.stdout)?;
    let expected_home = temporary.path().join("spaces/work/home");
    assert!(environment.contains(&format!("HOME={}", expected_home.display())));
    assert!(environment.contains("QUARTERS_SPACE=work"));
    assert!(environment.lines().any(|line| {
        line.starts_with("SSH_AUTH_SOCK=") && line.contains("/quarters-") && line.ends_with("/ssh-agent.sock")
    }));
    assert!(!environment.contains("host-npm-credentials"));
    assert!(!environment.contains("host-ssh-agent"));
    assert!(!environment.contains("QUARTERS_HOST_PROFILE_"));
    assert!(!environment.contains("UNLISTED_SECRET="));
    let git_config = std::fs::read_to_string(expected_home.join(".gitconfig"))?;
    assert!(git_config.contains("helper =\n"));

    let output = run(quarters(temporary.path()).args(["exec", "work", "--", "/usr/bin/id", "-u"]))?;
    assert_eq!(
        String::from_utf8(output.stdout)?.trim().parse::<u32>()?,
        nix::unistd::Uid::current().as_raw()
    );
    Ok(())
}

#[test]
fn explicit_inheritance_crosses_and_diagnostics_redact() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    let output = run(quarters(temporary.path()).env("UNLISTED_SECRET", "deliberate").args([
        "exec",
        "work",
        "--inherit",
        "UNLISTED_SECRET",
        "--",
        "/usr/bin/env",
    ]))?;
    assert!(String::from_utf8(output.stdout)?.contains("UNLISTED_SECRET=deliberate"));

    let output = run(quarters(temporary.path()).env("UNLISTED_SECRET", "deliberate").args([
        "env",
        "work",
        "--inherit",
        "UNLISTED_SECRET",
    ]))?;
    let diagnostic = String::from_utf8(output.stdout)?;
    assert!(diagnostic.contains("UNLISTED_SECRET=<explicitly inherited; redacted>"));
    assert!(!diagnostic.contains("UNLISTED_SECRET=deliberate"));
    Ok(())
}

#[test]
fn child_json_flag_does_not_change_quarters_error_format() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    let output = quarters(temporary.path())
        .args(["exec", "work", "--", "/definitely/not/a/quarters-command", "--json"])
        .output()?;
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr)?;
    assert!(error.starts_with("quarters: could not start profile command"));
    assert!(!error.trim_start().starts_with('{'));
    Ok(())
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
    assert_eq!(String::from_utf8(output.stdout)?.trim(), std::env::var("HOME")?);

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
    assert_eq!(String::from_utf8(output.stdout)?.trim(), std::env::var("PATH")?);
    Ok(())
}

#[test]
fn interactive_zsh_keeps_the_declared_history_path() -> Result<(), Box<dyn Error>> {
    if !Path::new("/bin/zsh").is_file() {
        return Ok(());
    }
    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    let output =
        run(quarters(temporary.path()).args(["exec", "work", "--", "/bin/zsh", "-ic", "print -r -- $HISTFILE"]))?;
    let expected = temporary.path().join("spaces/work/home/.local/state/shell/zsh_history");
    assert_eq!(String::from_utf8(output.stdout)?.trim(), expected.to_string_lossy());
    Ok(())
}

#[test]
fn removal_requires_exact_confirmation() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "short-lived")?;
    let failed = quarters(temporary.path())
        .args(["--json", "rm", "short-lived", "--confirm", "wrong"])
        .output()?;
    assert!(!failed.status.success());
    let error: Value = serde_json::from_slice(&failed.stderr)?;
    assert_eq!(error["error"]["kind"], "invalid_input");

    run(quarters(temporary.path()).args(["rm", "short-lived", "--confirm", "short-lived"]))?;
    assert!(!temporary.path().join("spaces/short-lived").exists());
    Ok(())
}

#[test]
fn doctor_does_not_advertise_unimplemented_confinement() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let doctor = run(quarters(temporary.path()).args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(report["result"]["platform"]["confinement"]["available"], false);
    assert_eq!(report["result"]["platform"]["confinement"]["status"], "not-implemented");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn linux_home_view_is_exercised_or_fails_closed() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    let home = temporary.path().join("spaces/work/home");
    std::fs::write(home.join(".quarters-home-view-marker"), b"home-view\n")?;

    let doctor = run(quarters(temporary.path()).args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    let available = report["result"]["platform"]["home_view"]["available"] == true;
    let output = quarters(temporary.path())
        .args([
            "exec",
            "work",
            "--home-view",
            "--",
            "/bin/sh",
            "-c",
            "test -f \"$HOME/.quarters-home-view-marker\"",
        ])
        .output()?;

    if available {
        assert!(
            output.status.success(),
            "home-view was reported available but failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        assert_eq!(output.status.code(), Some(6));
        assert!(String::from_utf8(output.stderr)?.contains("--home-view is unavailable"));
    }
    Ok(())
}
