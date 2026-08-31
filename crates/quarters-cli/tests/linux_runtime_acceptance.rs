//! Linux-only runtime and mount-home acceptance.

#![cfg(target_os = "linux")]

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use tempfile::TempDir;

fn quarters(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_quarters"));
    command.arg("--root").arg(root);
    command
}

fn landlock_required() -> bool {
    std::env::var_os("QUARTERS_REQUIRE_LANDLOCK").is_some_and(|value| !value.is_empty())
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

struct ToolCoverage {
    available: BTreeSet<&'static str>,
}

impl ToolCoverage {
    fn has(&self, name: &str) -> bool {
        self.available.contains(name)
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _kill = self.0.kill();
        let _wait = self.0.wait();
    }
}

const LANDLOCK_MATRIX: &str = r#"
test "$PWD" = "$HOME" || exit 10
printf 'allowed\n' > "$HOME/allowed" || exit 11
printf 'runtime\n' > "$TMPDIR/runtime" || exit 12
mv "$TMPDIR/runtime" "$HOME/moved" || exit 13
test -e "$1" || exit 14
cat "$1" >/dev/null 2>&1 && exit 15
cat "$HOME/known-host-link" >/dev/null 2>&1 && exit 16
cat "$2" >/dev/null 2>&1 && exit 17
cat "$3/sibling-secret" >/dev/null 2>&1 && exit 18
ls "$4" >/dev/null 2>&1 && exit 19
if ( : > "$1" ) 2>/dev/null; then exit 20; fi
if ( : > "/tmp/quarters-landlock-denied-$$" ) 2>/dev/null; then exit 21; fi
test "$(quarters current)" = confined || exit 22
quarters doctor >/dev/null 2>&1; test $? -eq 6 || exit 23
if [ "$5" = true ]; then ssh -V >/dev/null 2>&1 || exit 24; fi
if [ "$6" = true ]; then git init -q "$HOME/git-smoke" || exit 25; fi
if [ "$7" = true ]; then python3 -c 'from pathlib import Path; Path.home().joinpath("python-smoke").write_text("ok")' || exit 26; fi
if [ "$8" = true ]; then node -e 'require("fs").writeFileSync(process.env.HOME + "/node-smoke", "ok")' || exit 27; fi
"#;

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
    if std::env::var_os("QUARTERS_REQUIRE_HOME_VIEW_UNAVAILABLE").is_some() {
        assert!(
            !available,
            "the distribution-default user-namespace policy unexpectedly allowed home view"
        );
    }
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
fn landlock_confines_content_and_mutation_or_fails_closed() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("store");
    let host_home = temporary.path().join("host-home");
    fs::create_dir(&host_home)?;
    create(&root, &host_home, "confined")?;
    create(&root, &host_home, "sibling")?;
    let home = root.join("spaces/confined/home");
    let host_secret = temporary.path().join("host-secret");
    let manifest = root.join("spaces/confined/manifest.json");
    let sibling = root.join("spaces/sibling/home");
    fs::write(&host_secret, b"host-secret\n")?;
    fs::write(sibling.join("sibling-secret"), b"sibling\n")?;
    symlink(&host_secret, home.join("known-host-link"))?;

    let doctor = run(quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .args(["--json", "doctor"]))?;
    let doctor: Value = serde_json::from_slice(&doctor.stdout)?;
    let available = doctor["result"]["platform"]["confinement"]["available"] == true;
    if !available {
        if landlock_required() {
            return Err("hosted Linux requires Landlock ABI 3 confinement".into());
        }
        let refused = quarters(&root)
            .env("HOME", &host_home)
            .env_remove("XDG_RUNTIME_DIR")
            .args(["exec", "confined", "--confinement", "filesystem", "--", "/bin/true"])
            .output()?;
        assert_eq!(refused.status.code(), Some(6));
        return Ok(());
    }

    let policy = run(quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .args(["--json", "env", "confined", "--confinement", "filesystem"]))?;
    let policy: Value = serde_json::from_slice(&policy.stdout)?;
    let coverage = verify_policy(&policy, &home)?;
    let output = run_landlock_matrix(&root, &host_home, &host_secret, &manifest, &sibling, &coverage)?;
    assert!(
        output.status.success(),
        "Landlock acceptance failed with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&host_secret)?, b"host-secret\n");
    for name in ["allowed", "moved"] {
        assert!(home.join(name).is_file(), "missing confined output {name}");
    }
    assert_eq!(home.join("git-smoke").is_dir(), coverage.has("git"));
    assert_eq!(home.join("python-smoke").is_file(), coverage.has("python3"));
    assert_eq!(home.join("node-smoke").is_file(), coverage.has("node"));
    remove(&root, &host_home, "confined")?;
    remove(&root, &host_home, "sibling")?;
    Ok(())
}

#[test]
fn user_grants_are_data_only_explicit_and_workdir_bound() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("store");
    let host_home = temporary.path().join("host-home");
    let read_only = temporary.path().join("read-only");
    let read_write = temporary.path().join("read-write");
    let sibling = temporary.path().join("ungranted");
    for directory in [&host_home, &read_only, &read_write, &sibling] {
        fs::create_dir(directory)?;
    }
    fs::write(read_only.join("input"), b"readable\n")?;
    fs::write(sibling.join("secret"), b"denied\n")?;
    let executable = read_write.join("workspace-command");
    fs::write(&executable, b"#!/bin/sh\nprintf 'escaped\\n' > executed\n")?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
    create(&root, &host_home, "granted")?;
    if !confinement_available(&root, &host_home)? {
        if landlock_required() {
            return Err("hosted Linux requires user-grant confinement evidence".into());
        }
        return Ok(());
    }

    let read_only_arg = format!("{}:ro", read_only.display());
    let read_write_arg = format!("{}:rw", read_write.display());
    let plan = run(quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .arg("--json")
        .args(["env", "granted", "--confinement", "filesystem", "--grant-path"])
        .arg(&read_only_arg)
        .arg("--grant-path")
        .arg(&read_write_arg)
        .arg("--workdir")
        .arg(&read_write))?;
    let plan: Value = serde_json::from_slice(&plan.stdout)?;
    verify_user_grant_plan(&plan, &read_only, &read_write)?;

    let script = r#"
test "$PWD" = "$1" || exit 30
cat "$2/input" >/dev/null || exit 31
if printf 'no\n' > "$2/blocked" 2>/dev/null; then exit 32; fi
printf 'yes\n' > "$1/output" || exit 33
if cat "$3/secret" >/dev/null 2>&1; then exit 34; fi
"#;
    run(quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .arg("exec")
        .arg("granted")
        .args(["--confinement", "filesystem", "--grant-path"])
        .arg(&read_only_arg)
        .arg("--grant-path")
        .arg(&read_write_arg)
        .arg("--workdir")
        .arg(&read_write)
        .args(["--", "/bin/sh", "-c", script, "_"])
        .arg(&read_write)
        .arg(&read_only)
        .arg(&sibling))?;
    assert_eq!(fs::read(read_write.join("output"))?, b"yes\n");
    assert!(!read_only.join("blocked").exists());

    let refused = quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .arg("exec")
        .arg("granted")
        .args(["--confinement", "filesystem", "--grant-path"])
        .arg(&read_write_arg)
        .arg("--workdir")
        .arg(&read_write)
        .args(["--"])
        .arg(&executable)
        .output()?;
    assert_eq!(refused.status.code(), Some(6));
    assert!(!read_write.join("executed").exists());
    remove(&root, &host_home, "granted")?;
    Ok(())
}

fn verify_user_grant_plan(plan: &Value, read_only: &Path, read_write: &Path) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        plan["result"]["confinement"]["working_directory"],
        read_write.canonicalize()?.to_string_lossy().as_ref()
    );
    let grants = plan["result"]["confinement"]["grants"]
        .as_array()
        .ok_or("confinement grants are not an array")?;
    for (path, requested) in [(read_only, "ro"), (read_write, "rw")] {
        let canonical = path.canonicalize()?;
        let grant = grants
            .iter()
            .find(|grant| grant["path"] == canonical.to_string_lossy().as_ref())
            .ok_or("missing user grant")?;
        assert_eq!(grant["source"], "user-granted");
        assert_eq!(grant["requested_access"], requested);
        assert_eq!(grant["required"], true);
    }
    assert!(
        plan["result"]["confinement"]["limitations"]
            .as_array()
            .is_some_and(|items| items
                .iter()
                .any(|item| item.as_str().is_some_and(|text| text.contains("does not inspect"))))
    );
    Ok(())
}

#[test]
fn user_grants_reject_inert_and_reserved_authority() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("store");
    let host_home = temporary.path().join("host-home");
    fs::create_dir(&host_home)?;
    create(&root, &host_home, "reserved")?;
    let root_grant = format!("{}:ro", root.display());
    let inert = quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .args(["--json", "env", "reserved", "--grant-path", &root_grant])
        .output()?;
    assert_eq!(inert.status.code(), Some(2));

    if !confinement_available(&root, &host_home)? {
        if landlock_required() {
            return Err("hosted Linux requires reserved-grant evidence".into());
        }
        return Ok(());
    }
    let executable_grant = format!("{}:ro", env!("CARGO_BIN_EXE_quarters"));
    let executable_root_grant = "/usr:rw".to_owned();
    for grant in [root_grant, executable_grant, executable_root_grant] {
        let output = quarters(&root)
            .env("HOME", &host_home)
            .env_remove("XDG_RUNTIME_DIR")
            .args([
                "--json",
                "env",
                "reserved",
                "--confinement",
                "filesystem",
                "--grant-path",
                &grant,
            ])
            .output()?;
        assert_eq!(output.status.code(), Some(6));
        let error: Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(error["error"]["kind"], "unsupported");
        assert!(
            error["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("overlaps"))
        );
    }
    let duplicate = format!("{}:ro", host_home.display());
    let duplicate_output = quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .args([
            "--json",
            "env",
            "reserved",
            "--confinement",
            "filesystem",
            "--grant-path",
            &duplicate,
            "--grant-path",
            &duplicate,
        ])
        .output()?;
    assert_eq!(duplicate_output.status.code(), Some(2));
    remove(&root, &host_home, "reserved")?;
    Ok(())
}

fn verify_policy(policy: &Value, home: &Path) -> Result<ToolCoverage, Box<dyn Error>> {
    assert_eq!(policy["result"]["confinement"]["minimum_abi"], 3);
    assert_eq!(
        policy["result"]["confinement"]["working_directory"],
        home.to_string_lossy().as_ref()
    );
    let executable_path = policy["result"]["confinement"]["executable_path"]
        .as_array()
        .ok_or("confinement executable_path is not a readable array")?;
    assert!(!executable_path.is_empty());
    assert!(executable_path.iter().all(Value::is_string));
    assert!(policy["result"]["environment"].get("QUARTERS_HOST_PATH").is_none());
    let tiocsti = &policy["result"]["confinement"]["legacy_tiocsti"];
    assert!(matches!(
        tiocsti["state"].as_str(),
        Some("enabled" | "disabled" | "unavailable" | "unknown")
    ));
    if let Ok(value) = fs::read_to_string("/proc/sys/dev/tty/legacy_tiocsti") {
        match value.trim() {
            "1" => assert_eq!(tiocsti["state"], "enabled"),
            "0" => assert_eq!(tiocsti["state"], "disabled"),
            _ => assert_eq!(tiocsti["state"], "unknown"),
        }
    }
    let available = ["ssh", "git", "python3", "node"]
        .into_iter()
        .filter(|command| plan_has_command(policy, command))
        .collect();
    Ok(ToolCoverage { available })
}

fn run_landlock_matrix(
    root: &Path,
    host_home: &Path,
    host_secret: &Path,
    manifest: &Path,
    sibling: &Path,
    coverage: &ToolCoverage,
) -> Result<Output, Box<dyn Error>> {
    Ok(quarters(root)
        .env("HOME", host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .args([
            "exec",
            "confined",
            "--confinement",
            "filesystem",
            "--",
            "/bin/sh",
            "-c",
            LANDLOCK_MATRIX,
            "_",
        ])
        .arg(host_secret)
        .arg(manifest)
        .arg(sibling)
        .arg(root)
        .arg(coverage.has("ssh").to_string())
        .arg(coverage.has("git").to_string())
        .arg(coverage.has("python3").to_string())
        .arg(coverage.has("node").to_string())
        .output()?)
}

fn remove(root: &Path, home: &Path, name: &str) -> Result<(), Box<dyn Error>> {
    run(quarters(root)
        .env("HOME", home)
        .env_remove("XDG_RUNTIME_DIR")
        .args(["rm", name, "--confirm", name]))?;
    Ok(())
}

#[test]
fn combined_home_view_and_landlock_work_with_a_store_below_passwd_home() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let host_home = temporary.path().join("host-home");
    fs::create_dir(&host_home)?;
    let passwd_home = nix::unistd::User::from_uid(nix::unistd::Uid::current())?
        .ok_or("current user has no passwd record")?
        .dir
        .canonicalize()?;
    let covered = tempfile::Builder::new()
        .prefix(".quarters-home-view-test-")
        .tempdir_in(&passwd_home)?;
    let root = covered.path().join("store");
    run(quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .args(["create", "combined"]))?;
    let doctor = run(quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    let available = report["result"]["platform"]["confinement"]["available"] == true
        && report["result"]["platform"]["home_view"]["available"] == true;
    if !available {
        return Ok(());
    }
    let quarter_workdir = root.join("spaces/combined/home/project");
    fs::create_dir(&quarter_workdir)?;
    run(quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .arg("exec")
        .arg("combined")
        .arg("--home-view")
        .arg("--workdir")
        .arg(&quarter_workdir)
        .args(["--", "/bin/sh", "-c", "test \"$PWD\" = \"$HOME/project\""]))?;
    let hidden_grant = format!("{}:ro", passwd_home.display());
    let refused = quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .args([
            "--json",
            "env",
            "combined",
            "--home-view",
            "--confinement",
            "filesystem",
            "--grant-path",
            &hidden_grant,
        ])
        .output()?;
    assert_eq!(refused.status.code(), Some(6));
    let plan = run(quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .args([
            "--json",
            "env",
            "combined",
            "--home-view",
            "--confinement",
            "filesystem",
        ]))?;
    let plan: Value = serde_json::from_slice(&plan.stdout)?;
    assert_eq!(
        plan["result"]["confinement"]["working_directory"],
        passwd_home.to_string_lossy().as_ref()
    );
    run(quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .args([
            "exec",
            "combined",
            "--home-view",
            "--confinement",
            "filesystem",
            "--",
            "/bin/sh",
            "-c",
            "test \"$PWD\" = \"$HOME\" && test \"$(quarters current)\" = combined",
        ]))?;
    remove(&root, &host_home, "combined")?;
    Ok(())
}

#[test]
fn landlock_proc_evidence_has_an_unconfined_control_arm() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("store");
    let host_home = temporary.path().join("host-home");
    fs::create_dir(&host_home)?;
    create(&root, &host_home, "proc-evidence")?;
    if !confinement_available(&root, &host_home)? {
        if landlock_required() {
            return Err("hosted Linux requires the proc evidence confinement arm".into());
        }
        return Ok(());
    }

    fs::write(host_home.join("proc-secret"), b"outside\n")?;
    let mut witness = ChildGuard(
        Command::new("/bin/sh")
            .args(["-c", "printf '%s\\n' $$; while :; do sleep 1; done"])
            .current_dir(&host_home)
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let stdout = witness.0.stdout.take().ok_or("witness stdout missing")?;
    let mut reader = BufReader::new(stdout);
    let mut pid_line = String::new();
    reader.read_line(&mut pid_line)?;
    let pid = pid_line.trim().parse::<u32>()?;
    let control = proc_matrix(pid);
    assert!(fs::read(Path::new("/proc").join(pid.to_string()).join("cwd/proc-secret")).is_ok());
    let script = r#"
for entry in environ mem fd/0 cwd cmdline status; do
  if [ "$entry" = fd/0 ] || [ "$entry" = cwd ]; then
    readlink "/proc/$1/$entry" >/dev/null 2>&1
  else
    cat "/proc/$1/$entry" >/dev/null 2>&1
  fi
  if [ $? -eq 0 ]; then result=read; else result=denied; fi
  printf '%s=%s\n' "$entry" "$result"
done > "$HOME/proc-matrix"
if cat "/proc/$1/cwd/proc-secret" >/dev/null 2>&1; then
  printf 'cwd-content=read\n' >> "$HOME/proc-matrix"
else
  printf 'cwd-content=denied\n' >> "$HOME/proc-matrix"
fi
"#;
    let output = quarters(&root)
        .env("HOME", &host_home)
        .env_remove("XDG_RUNTIME_DIR")
        .args([
            "exec",
            "proc-evidence",
            "--confinement",
            "filesystem",
            "--",
            "/bin/sh",
            "-c",
            script,
            "_",
        ])
        .arg(pid.to_string())
        .output()?;
    assert!(
        output.status.success(),
        "proc probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let confined = fs::read_to_string(root.join("spaces/proc-evidence/home/proc-matrix"))?;
    assert!(confined.lines().any(|line| line == "cwd-content=denied"));
    for (entry, allowed) in control {
        let observed = format!("{entry}={}", if allowed { "read" } else { "denied" });
        if !allowed {
            assert!(
                confined.lines().any(|line| line == observed),
                "confined proc access exceeded control for {entry}"
            );
        }
        assert!(confined.lines().any(|line| line.starts_with(&format!("{entry}="))));
    }
    remove(&root, &host_home, "proc-evidence")?;
    Ok(())
}

fn plan_has_command(policy: &Value, command: &str) -> bool {
    policy["result"]["confinement"]["executable_path"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|directory| {
            fs::metadata(Path::new(directory).join(command))
                .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        })
}

fn confinement_available(root: &Path, home: &Path) -> Result<bool, Box<dyn Error>> {
    let output = run(quarters(root)
        .env("HOME", home)
        .env_remove("XDG_RUNTIME_DIR")
        .args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&output.stdout)?;
    Ok(report["result"]["platform"]["confinement"]["available"] == true)
}

fn proc_matrix(pid: u32) -> Vec<(&'static str, bool)> {
    ["environ", "mem", "fd/0", "cwd", "cmdline", "status"]
        .into_iter()
        .map(|entry| {
            let path = Path::new("/proc").join(pid.to_string()).join(entry);
            let allowed = if matches!(entry, "fd/0" | "cwd") {
                fs::read_link(path).is_ok()
            } else {
                fs::File::open(path).is_ok()
            };
            (entry, allowed)
        })
        .collect()
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
