//! Linux-only runtime and mount-home acceptance.

#![cfg(target_os = "linux")]

use serde_json::Value;
use std::error::Error;
use std::fs;
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

fn create(root: &Path, home: &Path, name: &str) -> Result<(), Box<dyn Error>> {
    run(quarters(root)
        .env("HOME", home)
        .env_remove("XDG_RUNTIME_DIR")
        .args(["create", name]))?;
    Ok(())
}

#[test]
fn home_view_mounts_space_state_and_disables_host_escape() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("store");
    let host_home = temporary.path().join("host-home");
    fs::create_dir(&host_home)?;
    create(&root, &host_home, "mounted")?;
    fs::write(
        root.join("spaces/mounted/home/.quarters-home-view-marker"),
        b"mounted\n",
    )?;

    let doctor = run(quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .args(["--json", "doctor"]))?;
    let doctor: Value = serde_json::from_slice(&doctor.stdout)?;
    let available = doctor["result"]["platform"]["home_view"]["available"] == true;
    let output = quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .args([
            "exec",
            "mounted",
            "--home-view",
            "--",
            "/bin/sh",
            "-c",
            "test -f \"$HOME/.quarters-home-view-marker\" || exit 1\ntest -f .quarters-home-view-marker || exit 1\ntest \"$(quarters current)\" = mounted || exit 1\nquarters host -- /usr/bin/true >/dev/null 2>&1\ntest $? -eq 6",
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
    run(quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .args(["rm", "mounted", "--confirm", "mounted"]))?;
    Ok(())
}

#[test]
fn runtime_falls_back_when_xdg_runtime_is_missing_or_below_home() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("store");
    let host_home = temporary.path().join("host-home");
    fs::create_dir(&host_home)?;
    create(&root, &host_home, "missing-xdg")?;
    let missing = environment(&root, &host_home, None, "missing-xdg")?;
    let expected_prefix = format!("/tmp/quarters-{}/", nix::unistd::Uid::current().as_raw());
    assert!(missing.starts_with(&expected_prefix));

    let nested = host_home.join("runtime");
    fs::create_dir(&nested)?;
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))?;
    create(&root, &host_home, "nested-xdg")?;
    let nested_result = environment(&root, &host_home, Some(&nested), "nested-xdg")?;
    assert!(nested_result.starts_with(&expected_prefix));

    for name in ["missing-xdg", "nested-xdg"] {
        run(quarters(&root)
            .env("HOME", &host_home)
            .env_remove("XDG_RUNTIME_DIR")
            .args(["rm", name, "--confirm", name]))?;
    }
    Ok(())
}

#[test]
fn private_agent_refuses_an_overlong_socket_path() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("store");
    let host_home = temporary.path().join("home");
    let runtime = temporary.path().join("r".repeat(90));
    fs::create_dir(&host_home)?;
    fs::create_dir(&runtime)?;
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
    create(&root, &host_home, "long-socket")?;

    let output = quarters(&root)
        .env("HOME", &host_home)
        .env("XDG_RUNTIME_DIR", &runtime)
        .args(["agent", "start", "long-socket"])
        .output()?;
    assert_eq!(output.status.code(), Some(6));
    assert!(String::from_utf8(output.stderr)?.contains("socket path exceeds the portable Unix limit"));

    run(quarters(&root)
        .env("HOME", &host_home)
        .env("XDG_RUNTIME_DIR", &runtime)
        .args(["rm", "long-socket", "--confirm", "long-socket"]))?;
    Ok(())
}

fn environment(root: &Path, home: &Path, runtime: Option<&Path>, name: &str) -> Result<String, Box<dyn Error>> {
    let mut command = quarters(root);
    command.env("HOME", home);
    if let Some(runtime) = runtime {
        command.env("XDG_RUNTIME_DIR", runtime);
    } else {
        command.env_remove("XDG_RUNTIME_DIR");
    }
    let output = run(command.args(["--json", "env", name]))?;
    let report: Value = serde_json::from_slice(&output.stdout)?;
    report["result"]["environment"]["XDG_RUNTIME_DIR"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "missing XDG_RUNTIME_DIR".into())
}
