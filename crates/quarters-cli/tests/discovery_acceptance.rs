//! End-to-end acceptance for privacy-bounded state discovery.

use serde_json::Value;
use std::error::Error;
use std::path::Path;
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn quarters(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_quarters"));
    command.arg("--root").arg(root);
    command
}

fn create(root: &Path, name: &str) -> Result<(), Box<dyn Error>> {
    let output = quarters(root).args(["create", name]).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned().into())
    }
}

fn discover_with_report(root: &Path, report: &Path, script: &str) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new("/bin/sh")
        .arg("-c")
        .arg(
            "exec 3>\"$REPORT_PATH\"; exec \"$QUARTERS_BIN\" --root \"$STORE_ROOT\" discover demo --report-fd 3 -- /bin/sh -c \"$CHILD_SCRIPT\"",
        )
        .env("REPORT_PATH", report)
        .env("QUARTERS_BIN", env!("CARGO_BIN_EXE_quarters"))
        .env("STORE_ROOT", root)
        .env("CHILD_SCRIPT", script)
        .output()?)
}

fn report_value(path: &Path) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn runtime_paths(root: &Path) -> Result<Vec<std::path::PathBuf>, Box<dyn Error>> {
    let manifest: Value = serde_json::from_slice(&std::fs::read(root.join("spaces/demo/.quarters.json"))?)?;
    let space_id = manifest["space_id"].as_str().ok_or("missing space ID")?;
    let namespace = format!("quarters-{}", nix::unistd::Uid::current().as_raw());
    let mut bases = vec![std::path::PathBuf::from("/tmp")];
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        bases.push(runtime.into());
    }
    bases.sort_unstable();
    bases.dedup();
    Ok(bases
        .into_iter()
        .map(|base| base.join(&namespace).join(space_id))
        .collect())
}

#[test]
fn preview_discloses_scope_bounds_and_patterns_without_execution() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "demo")?;
    let marker = temporary.path().join("spaces/demo/home/must-not-exist");
    let output = quarters(temporary.path())
        .args(["--json", "discover", "demo", "--scan", "home", "--preview"])
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let value: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(value["command"], "discover-preview");
    assert_eq!(value["result"]["selectors"], serde_json::json!(["home"]));
    assert_eq!(value["result"]["state"], "planned");
    assert_eq!(value["result"]["contents_inspected"], false);
    assert_eq!(value["result"]["host_writes_observed"], "not-measured");
    assert_eq!(value["result"]["limits"]["entries"], 262_144);
    assert_eq!(value["result"]["limits"]["pending_name_bytes"], 16_777_216);
    assert!(
        value["result"]["credential_patterns"]
            .as_array()
            .is_some_and(|patterns| {
                patterns.iter().any(|pattern| pattern == ".ssh/**")
                    && patterns.iter().any(|pattern| pattern == "**/*.pem")
            })
    );
    let refused = quarters(temporary.path())
        .args([
            "discover",
            "demo",
            "--preview",
            "--",
            "/bin/sh",
            "-c",
            "printf marker > \"$HOME/must-not-exist\"",
        ])
        .output()?;
    assert_eq!(refused.status.code(), Some(2));
    assert!(!marker.exists());
    assert!(runtime_paths(temporary.path())?.iter().all(|path| !path.exists()));
    Ok(())
}

#[test]
fn execution_preserves_child_streams_and_reports_only_classified_metadata() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "demo")?;
    let report = temporary.path().join("report.json");
    let hostile = "private-hostile-entry-name";
    let script = format!(
        "/bin/mkdir -p \"$HOME/.config/tool\" \"$HOME/.ssh\" \"$HOME/.cache/tool\" \"$XDG_RUNTIME_DIR/bin\"; printf config > \"$HOME/.config/tool/settings\"; printf secret > \"$HOME/.ssh/token\"; printf cache > \"$HOME/.cache/tool/item\"; printf hidden > \"$HOME/{hostile}\"; printf runtime > \"$XDG_RUNTIME_DIR/bin/child-created\"; printf 'child-out\\n'; printf 'child-err\\n' >&2"
    );
    let output = discover_with_report(temporary.path(), &report, &script)?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, b"child-out\n");
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("child-err"));
    assert!(stderr.contains("Discovery for demo: measured"));

    let bytes = std::fs::read(&report)?;
    let encoded = String::from_utf8(bytes.clone())?;
    assert!(!encoded.contains(hostile));
    assert!(!encoded.contains("settings"));
    assert!(!encoded.contains("secret"));
    let value: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(value["command"], "discover");
    assert_eq!(value["result"]["sound"], true);
    assert_eq!(value["result"]["child"]["exit_code"], 0);
    assert!(
        value["result"]["delta"]["created"]["configuration"]
            .as_u64()
            .is_some_and(|count| count >= 2)
    );
    assert!(
        value["result"]["delta"]["created"]["credential_shaped"]
            .as_u64()
            .is_some_and(|count| count >= 1)
    );
    assert!(
        value["result"]["delta"]["created"]["cache"]
            .as_u64()
            .is_some_and(|count| count >= 2)
    );
    assert!(
        value["result"]["delta"]["created"]["runtime"]
            .as_u64()
            .is_some_and(|count| count >= 1)
    );
    assert_eq!(value["result"]["host_writes_observed"], "not-measured");
    assert!(
        value["result"]["host_state_access"]["unknown"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
    Ok(())
}

#[test]
fn report_descriptor_preserves_position_append_and_pipe_delivery() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "demo")?;
    let report = temporary.path().join("position.json");
    std::fs::write(&report, b"prefix\n")?;
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(
            "exec 3>>\"$REPORT_PATH\"; exec \"$QUARTERS_BIN\" --root \"$STORE_ROOT\" discover demo --report-fd 3 -- /usr/bin/true",
        )
        .env("REPORT_PATH", &report)
        .env("QUARTERS_BIN", env!("CARGO_BIN_EXE_quarters"))
        .env("STORE_ROOT", temporary.path())
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let bytes = std::fs::read(&report)?;
    assert!(bytes.starts_with(b"prefix\n{"));

    let piped = Command::new("/bin/sh")
        .arg("-c")
        .arg("exec 3>&1; exec \"$QUARTERS_BIN\" --root \"$STORE_ROOT\" discover demo --report-fd 3 -- /usr/bin/true")
        .env("QUARTERS_BIN", env!("CARGO_BIN_EXE_quarters"))
        .env("STORE_ROOT", temporary.path())
        .output()?;
    assert!(piped.status.success(), "{}", String::from_utf8_lossy(&piped.stderr));
    let value: Value = serde_json::from_slice(&piped.stdout)?;
    assert_eq!(value["result"]["child"]["exit_code"], 0);
    Ok(())
}

#[test]
fn read_only_report_descriptor_fails_before_child_execution() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "demo")?;
    let input = temporary.path().join("read-only");
    std::fs::write(&input, b"input")?;
    let marker = temporary.path().join("spaces/demo/home/must-not-run");
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(
            "exec 3<\"$INPUT_PATH\"; exec \"$QUARTERS_BIN\" --root \"$STORE_ROOT\" discover demo --report-fd 3 -- /bin/sh -c 'printf marker > \"$HOME/must-not-run\"'",
        )
        .env("INPUT_PATH", &input)
        .env("QUARTERS_BIN", env!("CARGO_BIN_EXE_quarters"))
        .env("STORE_ROOT", temporary.path())
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(!marker.exists());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("not an inherited writable") || stderr.contains("not writable"));
    Ok(())
}

#[test]
fn report_descriptor_is_not_inherited_by_the_measured_child() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "demo")?;
    let report = temporary.path().join("report.json");
    let output = discover_with_report(
        temporary.path(),
        &report,
        "if [ -e /dev/fd/3 ]; then exit 91; fi; exit 0",
    )?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(report_value(&report)?["result"]["child"]["exit_code"], 0);
    Ok(())
}

#[test]
fn closed_stderr_and_child_signal_preserve_native_status() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "demo")?;
    let report = temporary.path().join("closed-stderr.json");
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(
            "exec 3>\"$REPORT_PATH\"; exec \"$QUARTERS_BIN\" --root \"$STORE_ROOT\" discover demo --report-fd 3 -- /bin/sh -c 'exit 17' 2>&-",
        )
        .env("REPORT_PATH", &report)
        .env("QUARTERS_BIN", env!("CARGO_BIN_EXE_quarters"))
        .env("STORE_ROOT", temporary.path())
        .output()?;
    assert_eq!(output.status.code(), Some(17));
    assert_eq!(report_value(&report)?["result"]["child"]["exit_code"], 17);

    let signaled_report = temporary.path().join("signaled.json");
    let signaled = discover_with_report(temporary.path(), &signaled_report, "kill -TERM $$")?;
    assert_eq!(signaled.status.code(), Some(143));
    let value = report_value(&signaled_report)?;
    assert!(value["result"]["child"]["exit_code"].is_null());
    assert_eq!(value["result"]["child"]["signal"], 15);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn report_write_failure_does_not_replace_child_exit() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "demo")?;
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(
            "exec 3>/dev/full; exec \"$QUARTERS_BIN\" --root \"$STORE_ROOT\" discover demo --report-fd 3 -- /bin/sh -c 'exit 29'",
        )
        .env("QUARTERS_BIN", env!("CARGO_BIN_EXE_quarters"))
        .env("STORE_ROOT", temporary.path())
        .output()?;
    assert_eq!(output.status.code(), Some(29));
    assert!(String::from_utf8(output.stderr)?.contains("report descriptor failed"));
    Ok(())
}

#[test]
fn post_scan_failure_preserves_child_exit_and_emits_an_incomplete_report() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "demo")?;
    let report = temporary.path().join("report.json");
    let output = discover_with_report(temporary.path(), &report, "/bin/chmod 000 \"$HOME\"; exit 23")?;
    assert_eq!(output.status.code(), Some(23));
    let value = report_value(&report)?;
    assert_eq!(value["result"]["state"], "post-scan-failed");
    assert_eq!(value["result"]["sound"], false);
    assert!(value["result"]["delta"].is_null());
    assert_eq!(value["result"]["child"]["exit_code"], 23);
    std::fs::set_permissions(
        temporary.path().join("spaces/demo/home"),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    Ok(())
}

#[test]
fn executing_json_is_refused_before_the_child_runs() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "demo")?;
    let marker = temporary.path().join("spaces/demo/home/marker");
    let output = quarters(temporary.path())
        .args([
            "--json",
            "discover",
            "demo",
            "--",
            "/bin/sh",
            "-c",
            "printf marker > \"$HOME/marker\"",
        ])
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(!marker.exists());
    let error: Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["kind"], "invalid_input");
    Ok(())
}

#[test]
fn exclusive_discovery_lease_rejects_a_cooperating_launch() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "demo")?;
    let marker = temporary.path().join("spaces/demo/home/ready");
    let mut discovery = quarters(temporary.path())
        .args([
            "discover",
            "demo",
            "--",
            "/bin/sh",
            "-c",
            "printf ready > \"$HOME/ready\"; exec /bin/sleep 2",
        ])
        .spawn()?;
    wait_for_path(&marker, &mut discovery)?;
    let competing = quarters(temporary.path())
        .args(["exec", "demo", "--", "/usr/bin/true"])
        .output()?;
    let discovery_status = discovery.wait()?;
    assert_eq!(competing.status.code(), Some(8));
    assert!(String::from_utf8(competing.stderr)?.contains("space activity"));
    assert!(discovery_status.success());
    Ok(())
}

#[test]
fn preview_does_not_contend_with_an_active_discovery() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "demo")?;
    let marker = temporary.path().join("spaces/demo/home/preview-ready");
    let mut discovery = quarters(temporary.path())
        .args([
            "discover",
            "demo",
            "--",
            "/bin/sh",
            "-c",
            "printf ready > \"$HOME/preview-ready\"; exec /bin/sleep 2",
        ])
        .spawn()?;
    wait_for_path(&marker, &mut discovery)?;
    let preview = quarters(temporary.path())
        .args(["--json", "discover", "demo", "--preview"])
        .output()?;
    let discovery_status = discovery.wait()?;
    assert!(preview.status.success(), "{}", String::from_utf8_lossy(&preview.stderr));
    assert_eq!(
        serde_json::from_slice::<Value>(&preview.stdout)?["result"]["state"],
        "planned"
    );
    assert!(discovery_status.success());
    Ok(())
}

fn wait_for_path(path: &Path, child: &mut Child) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            return Err(format!("discovery exited before readiness: {status}").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _status = child.kill();
    Err("timed out waiting for discovery child".into())
}
