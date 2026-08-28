//! End-to-end acceptance tests for walkthrough-driven product increments.

use serde_json::Value;
use std::error::Error;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

mod support;
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
fn private_agent_never_follows_an_unowned_socket_link() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new()?;
    create(temporary.path(), "stale-agent")?;
    let environment = run(quarters(temporary.path()).args(["--json", "env", "stale-agent"]))?;
    let environment: Value = serde_json::from_slice(&environment.stdout)?;
    let runtime = environment["result"]["environment"]["XDG_RUNTIME_DIR"]
        .as_str()
        .ok_or("missing runtime")?;
    let socket = Path::new(runtime).join("ssh-agent.sock");
    symlink("/tmp/host-agent.sock", &socket)?;

    let status = run(quarters(temporary.path()).args(["--json", "agent", "status", "stale-agent"]))?;
    let status: Value = serde_json::from_slice(&status.stdout)?;
    assert_eq!(status["result"]["state"], "stale");
    assert!(status["result"]["socket"].is_null());

    let launched = quarters(temporary.path())
        .args(["exec", "stale-agent", "--", "/usr/bin/true"])
        .output()?;
    assert_eq!(launched.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&launched.stderr).contains("state is stale"));
    assert!(std::fs::symlink_metadata(&socket)?.file_type().is_symlink());
    let doctor = run(quarters(temporary.path()).args(["--json", "doctor", "stale-agent"]))?;
    let doctor: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(doctor["result"]["space_environment_validated"], false);
    assert_eq!(doctor["result"]["space_ssh_agent"]["state"], "stale");
    Ok(())
}
#[test]
fn concurrent_private_agent_starts_converge_on_one_verified_process() -> Result<(), Box<dyn Error>> {
    for _attempt in 0..20 {
        let temporary = TempDir::new()?;
        create(temporary.path(), "concurrent-agent")?;
        let children = (0..6)
            .map(|_| {
                quarters(temporary.path())
                    .args(["--json", "agent", "start", "concurrent-agent"])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
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
    }
    Ok(())
}
#[test]
fn openssh_adapters_are_installed_by_default_and_preserve_version_output() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "adapter-demo")?;
    let status = run(quarters(temporary.path()).args(["--json", "adapter", "status", "adapter-demo"]))?;
    let status: Value = serde_json::from_slice(&status.stdout)?;
    assert_eq!(status["result"]["launcher"]["state"], "managed");
    let tools = status["result"]["tools"].as_array().ok_or("missing adapter tools")?;
    assert_eq!(tools.len(), 4);
    assert!(tools.iter().all(|entry| entry["state"] == "managed"));

    let adapted = quarters(temporary.path())
        .args(["exec", "adapter-demo", "--", "ssh", "-V"])
        .output()?;
    let direct = Command::new("/usr/bin/ssh").arg("-V").output()?;
    assert_eq!(adapted.status.code(), direct.status.code());
    assert_eq!(adapted.stdout, direct.stdout);
    assert_eq!(adapted.stderr, direct.stderr);

    let override_attempt = quarters(temporary.path())
        .args([
            "exec",
            "adapter-demo",
            "--",
            "ssh",
            "-F",
            "/dev/null",
            "example.invalid",
        ])
        .output()?;
    assert_eq!(override_attempt.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&override_attempt.stderr).contains("does not accept a competing -F"));

    let managed_ssh = temporary.path().join("spaces/adapter-demo/home/.local/bin/ssh");
    let forged = Command::new(managed_ssh)
        .arg("-V")
        .env("QUARTERS_ROOT", temporary.path())
        .env("QUARTERS_SPACE", "adapter-demo")
        .env("QUARTERS_SPACE_HOME", "/tmp/forged-quarter-home")
        .env("QUARTERS_HOST_PATH", "/usr/bin:/bin")
        .output()?;
    assert_eq!(forged.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&forged.stderr).contains("does not match the validated space home"));
    #[cfg(target_os = "macos")]
    {
        let forged_home_view = Command::new(temporary.path().join("spaces/adapter-demo/home/.local/bin/ssh"))
            .arg("-V")
            .env("QUARTERS_ROOT", temporary.path())
            .env("QUARTERS_SPACE", "adapter-demo")
            .env("QUARTERS_SPACE_HOME", "/tmp/forged-quarter-home")
            .env("QUARTERS_HOST_PATH", "/usr/bin:/bin")
            .env("QUARTERS_NO_HOST_ESCAPE", "home-view")
            .output()?;
        assert_eq!(forged_home_view.status.code(), Some(7));
    }
    Ok(())
}

#[test]
fn adapter_management_never_overwrites_or_removes_an_unmanaged_command() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new()?;
    create(temporary.path(), "adapter-collision")?;
    run(quarters(temporary.path()).args(["adapter", "remove", "adapter-collision"]))?;
    let ssh = temporary.path().join("spaces/adapter-collision/home/.local/bin/ssh");
    std::fs::write(&ssh, b"unmanaged")?;
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700))?;

    let install = quarters(temporary.path())
        .args(["--json", "adapter", "install", "adapter-collision"])
        .output()?;
    assert_eq!(install.status.code(), Some(4));
    assert_eq!(std::fs::read(&ssh)?, b"unmanaged");

    let remove = quarters(temporary.path())
        .args(["--json", "adapter", "remove", "adapter-collision"])
        .output()?;
    assert_eq!(remove.status.code(), Some(4));
    assert_eq!(std::fs::read(&ssh)?, b"unmanaged");
    Ok(())
}

#[test]
fn adapter_management_rejects_a_symlinked_command_directory_ancestor() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let temporary = TempDir::new()?;
    create(temporary.path(), "adapter-ancestor")?;
    let home = temporary.path().join("spaces/adapter-ancestor/home");
    std::fs::rename(home.join(".local"), home.join(".local-original"))?;
    let redirected = temporary.path().join("redirected-local");
    std::fs::create_dir_all(redirected.join("bin"))?;
    std::fs::set_permissions(&redirected, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(redirected.join("bin"), std::fs::Permissions::from_mode(0o700))?;
    symlink(&redirected, home.join(".local"))?;

    let status = quarters(temporary.path())
        .args(["adapter", "status", "adapter-ancestor"])
        .output()?;

    assert_eq!(status.status.code(), Some(7));
    let stderr = String::from_utf8_lossy(&status.stderr);
    assert!(stderr.contains("not a protected current-user directory"), "{stderr}");
    assert!(std::fs::read_dir(redirected.join("bin"))?.next().is_none());
    Ok(())
}

#[test]
fn lifecycle_copy_omits_and_recreates_only_managed_command_links() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "adapter-source")?;
    let preview =
        run(quarters(temporary.path()).args(["--json", "clone", "adapter-source", "adapter-copy", "--preview"]))?;
    let preview: Value = serde_json::from_slice(&preview.stdout)?;
    assert_eq!(preview["result"]["exclusions"]["managed_command_links"], 5);
    run(quarters(temporary.path()).args([
        "clone",
        "adapter-source",
        "adapter-copy",
        "--confirm-sensitive-state",
        "adapter-source",
    ]))?;
    let status = run(quarters(temporary.path()).args(["--json", "adapter", "status", "adapter-copy"]))?;
    let status: Value = serde_json::from_slice(&status.stdout)?;
    assert_eq!(status["result"]["launcher"]["state"], "managed");
    assert!(
        status["result"]["tools"]
            .as_array()
            .is_some_and(|entries| entries.iter().all(|entry| entry["state"] == "managed"))
    );
    Ok(())
}

#[test]
fn legacy_upgrade_assigns_identity_without_stranding_existing_snapshots() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "legacy")?;
    let manifest_path = temporary.path().join("spaces/legacy/.quarters.json");
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    manifest["schema_version"] = serde_json::json!(1);
    let object = manifest.as_object_mut().ok_or("manifest is not an object")?;
    object.remove("layout");
    object.remove("space_id");
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    let legacy_environment = run(quarters(temporary.path()).args(["--json", "env", "legacy"]))?;
    let legacy_environment: Value = serde_json::from_slice(&legacy_environment.stdout)?;
    let transitional_runtime = Path::new(
        legacy_environment["result"]["environment"]["XDG_RUNTIME_DIR"]
            .as_str()
            .ok_or("missing legacy runtime")?,
    )
    .to_path_buf();
    let runtime_parent = transitional_runtime.parent().ok_or("runtime has no parent")?;
    let space_root = temporary.path().join("spaces/legacy");
    let fingerprint = support::pre_alpha4_runtime_fingerprint(&space_root);
    let legacy_runtime = runtime_parent.join(format!("legacy-{fingerprint:016x}"));
    std::fs::rename(&transitional_runtime, &legacy_runtime)?;
    std::fs::write(legacy_runtime.join("tmp/runtime-proof"), b"runtime-state")?;
    let proof = temporary.path().join("spaces/legacy/home/proof");
    std::fs::write(&proof, b"before-upgrade")?;
    run(quarters(temporary.path()).args([
        "snapshot",
        "create",
        "legacy",
        "legacy-point",
        "--confirm-sensitive-state",
        "legacy",
    ]))?;

    let preview = run(quarters(temporary.path()).args(["--json", "upgrade", "legacy", "--preview"]))?;
    let preview: Value = serde_json::from_slice(&preview.stdout)?;
    assert_eq!(preview["result"]["previous_schema"], 1);
    assert_eq!(preview["result"]["schema"], 3);
    assert_eq!(preview["result"]["would_change"], true);
    assert!(preview["result"]["space_id"].is_null());

    let upgraded = run(quarters(temporary.path()).args(["--json", "upgrade", "legacy", "--confirm", "legacy"]))?;
    let upgraded: Value = serde_json::from_slice(&upgraded.stdout)?;
    assert_eq!(upgraded["result"]["changed"], true);
    assert_eq!(upgraded["result"]["space_id"].as_str().map(str::len), Some(32));
    let rename = quarters(temporary.path())
        .args(["rename", "legacy", "moved", "--confirm", "legacy"])
        .output()?;
    assert_eq!(rename.status.code(), Some(6));
    assert!(String::from_utf8_lossy(&rename.stderr).contains("captured before stable identity upgrade"));
    let stable_environment = run(quarters(temporary.path()).args(["--json", "env", "legacy"]))?;
    let stable_environment: Value = serde_json::from_slice(&stable_environment.stdout)?;
    let stable_runtime = Path::new(
        stable_environment["result"]["environment"]["XDG_RUNTIME_DIR"]
            .as_str()
            .ok_or("missing stable runtime")?,
    );
    assert_ne!(stable_runtime, legacy_runtime);
    assert!(!legacy_runtime.exists());
    assert!(!transitional_runtime.exists());
    assert_eq!(
        std::fs::read(stable_runtime.join("tmp/runtime-proof"))?,
        b"runtime-state"
    );

    std::fs::write(&proof, b"after-upgrade")?;
    run(quarters(temporary.path()).args([
        "rollback",
        "legacy",
        "legacy-point",
        "--recovery-name",
        "upgrade-recovery",
        "--confirm-space",
        "legacy",
        "--confirm-replace-state",
        "legacy",
    ]))?;
    assert_eq!(std::fs::read(&proof)?, b"before-upgrade");
    Ok(())
}

#[test]
fn clone_preview_and_execution_have_one_stable_disclosure_shape() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "source")?;
    std::fs::write(temporary.path().join("spaces/source/home/proof"), b"state")?;

    let preview = run(quarters(temporary.path()).args(["--json", "clone", "source", "copy", "--preview"]))?;
    let preview: Value = serde_json::from_slice(&preview.stdout)?;
    assert_eq!(preview["command"], "clone");
    assert_eq!(preview["result"]["mode"], "preview");
    assert_eq!(preview["result"]["policy"]["includes_sensitive_state"], true);
    assert_eq!(preview["result"]["detached_processes"], "unknown");
    assert!(preview["result"]["exclusions"]["symlinks_into_omitted_cache_roots"].is_u64());
    assert!(
        preview["result"]["exclusions"]
            .get("symlinks_dangling_after_exclusion")
            .is_none()
    );
    assert!(preview["result"]["destination_space_id"].is_null());
    assert!(!temporary.path().join("spaces/copy").exists());

    let cloned = run(quarters(temporary.path()).args([
        "--json",
        "clone",
        "source",
        "copy",
        "--confirm-sensitive-state",
        "source",
    ]))?;
    let cloned: Value = serde_json::from_slice(&cloned.stdout)?;
    assert_eq!(cloned["result"]["mode"], "execute");
    assert_eq!(cloned["result"]["counts"], preview["result"]["counts"]);
    assert_eq!(cloned["result"]["exclusions"], preview["result"]["exclusions"]);
    assert_eq!(
        std::fs::read(temporary.path().join("spaces/copy/home/proof"))?,
        b"state"
    );
    Ok(())
}

#[test]
fn clone_requires_exact_sensitive_state_confirmation() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "source")?;

    for arguments in [
        vec!["--json", "clone", "source", "copy"],
        vec![
            "--json",
            "clone",
            "source",
            "copy",
            "--confirm-sensitive-state",
            "other",
        ],
    ] {
        let output = quarters(temporary.path()).args(arguments).output()?;
        assert_eq!(output.status.code(), Some(2));
        let error: Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(error["error"]["kind"], "invalid_input");
        assert!(!temporary.path().join("spaces/copy").exists());
    }

    let conflict = quarters(temporary.path())
        .args([
            "--json",
            "clone",
            "source",
            "copy",
            "--preview",
            "--confirm-sensitive-state",
            "source",
        ])
        .output()?;
    assert_eq!(conflict.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&conflict.stderr)?;
    assert_eq!(error["error"]["kind"], "invalid_command");
    Ok(())
}

#[test]
fn template_lifecycle_is_verified_and_scriptable() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "source")?;
    std::fs::write(temporary.path().join("spaces/source/home/proof"), b"template-state")?;

    let preview = run(quarters(temporary.path()).args([
        "--json",
        "template",
        "create",
        "starter",
        "--from",
        "source",
        "--preview",
    ]))?;
    let preview: Value = serde_json::from_slice(&preview.stdout)?;
    assert_eq!(preview["command"], "template.create");
    assert_eq!(preview["result"]["mode"], "preview");
    assert!(!temporary.path().join(".templates").exists());

    run(quarters(temporary.path()).args([
        "template",
        "create",
        "starter",
        "--from",
        "source",
        "--confirm-sensitive-state",
        "source",
    ]))?;
    let used = run(quarters(temporary.path()).args([
        "--json",
        "template",
        "use",
        "starter",
        "copy",
        "--confirm-sensitive-state",
        "starter",
    ]))?;
    let used: Value = serde_json::from_slice(&used.stdout)?;
    assert_eq!(used["command"], "template.use");
    assert_eq!(used["result"]["destination"], "copy");
    assert_eq!(
        std::fs::read(temporary.path().join("spaces/copy/home/proof"))?,
        b"template-state"
    );

    run(quarters(temporary.path()).args(["template", "rename", "starter", "stationery"]))?;
    let shown = run(quarters(temporary.path()).args(["--json", "template", "show", "stationery"]))?;
    let shown: Value = serde_json::from_slice(&shown.stdout)?;
    assert_eq!(shown["result"]["manifest"]["name"], "stationery");
    run(quarters(temporary.path()).args(["template", "rm", "stationery", "--confirm", "stationery"]))?;
    Ok(())
}

#[test]
fn artifact_list_escapes_unhealthy_filesystem_metadata() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let temporary = TempDir::new()?;
    let root = temporary.path();
    let templates = root.join(".templates");
    std::fs::DirBuilder::new().mode(0o700).create(&templates)?;
    let hostile = templates.join("bad\u{1b}[2Jartifact");
    std::fs::DirBuilder::new().mode(0o700).create(&hostile)?;
    std::fs::set_permissions(&hostile, std::fs::Permissions::from_mode(0o700))?;

    let human = run(quarters(root).args(["template", "list"]))?;
    assert!(!human.stdout.contains(&0x1b));
    let text = String::from_utf8(human.stdout)?;
    assert!(text.contains("bad\\u{1b}[2Jartifact"));

    let json = run(quarters(root).args(["--json", "template", "list"]))?;
    assert!(!json.stdout.contains(&0x1b));
    let value: Value = serde_json::from_slice(&json.stdout)?;
    assert_eq!(value["result"][0]["id_encoding"], "escaped_bounded");
    Ok(())
}

#[test]
fn snapshot_creation_verification_and_filtering_are_truthful() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    std::fs::write(temporary.path().join("spaces/work/home/state"), b"before")?;
    run(quarters(temporary.path()).args([
        "snapshot",
        "create",
        "work",
        "before",
        "--confirm-sensitive-state",
        "work",
        "--exclude-cache",
    ]))?;

    let verified = run(quarters(temporary.path()).args(["--json", "snapshot", "verify", "before"]))?;
    let verified: Value = serde_json::from_slice(&verified.stdout)?;
    assert_eq!(verified["command"], "snapshot.verify");
    assert_eq!(verified["result"]["verified"], true);
    let listed = run(quarters(temporary.path()).args(["--json", "snapshot", "list", "work"]))?;
    let listed: Value = serde_json::from_slice(&listed.stdout)?;
    assert_eq!(listed["result"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed["result"][0]["source_status"], "present");
    Ok(())
}

#[test]
fn rollback_restores_snapshot_and_preserves_automatic_recovery() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    let state = temporary.path().join("spaces/work/home/state");
    std::fs::write(&state, b"before")?;
    run(quarters(temporary.path()).args([
        "snapshot",
        "create",
        "work",
        "before",
        "--confirm-sensitive-state",
        "work",
    ]))?;
    std::fs::write(&state, b"after")?;

    let preview = run(quarters(temporary.path()).args([
        "--json",
        "rollback",
        "work",
        "before",
        "--recovery-name",
        "pre-rollback",
        "--preview",
    ]))?;
    let preview: Value = serde_json::from_slice(&preview.stdout)?;
    assert_eq!(preview["result"]["mode"], "preview");
    assert_eq!(std::fs::read(&state)?, b"after");

    let rolled_back = run(quarters(temporary.path()).args([
        "--json",
        "rollback",
        "work",
        "before",
        "--recovery-name",
        "pre-rollback",
        "--confirm-space",
        "work",
        "--confirm-replace-state",
        "work",
    ]))?;
    let rolled_back: Value = serde_json::from_slice(&rolled_back.stdout)?;
    assert_eq!(rolled_back["result"]["mode"], "execute");
    assert_eq!(std::fs::read(&state)?, b"before");
    let recovery = run(quarters(temporary.path()).args(["--json", "snapshot", "show", "pre-rollback"]))?;
    let recovery: Value = serde_json::from_slice(&recovery.stdout)?;
    assert_eq!(recovery["result"]["manifest"]["origin"], "automatic-rollback-recovery");
    let adapters = run(quarters(temporary.path()).args(["--json", "adapter", "status", "work"]))?;
    let adapters: Value = serde_json::from_slice(&adapters.stdout)?;
    assert_eq!(adapters["result"]["launcher"]["state"], "managed");
    assert!(
        adapters["result"]["tools"]
            .as_array()
            .is_some_and(|tools| tools.iter().all(|tool| tool["state"] == "managed"))
    );
    Ok(())
}

#[test]
fn interrupted_and_malformed_rollbacks_share_one_target_row() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    let spaces = temporary.path().join("spaces");
    let manifest: Value = serde_json::from_slice(&std::fs::read(spaces.join("work/.quarters.json"))?)?;
    let id = "11111111111111111111111111111111";
    let staging_entry = format!(".rollback-staging-{id}");
    let staging = spaces.join(&staging_entry);
    std::fs::create_dir(&staging)?;
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700))?;
    let marker = serde_json::json!({
        "schema_version": 1,
        "transaction_id": id,
        "state": "prepared",
        "target": "work",
        "target_identity": {
            "schema_version": manifest["schema_version"],
            "name": "work",
            "created_unix_ms": manifest["created_unix_ms"],
            "space_id": manifest["space_id"],
        },
        "staging_entry": staging_entry,
        "retired_entry": format!(".rolled-back-{id}"),
        "snapshot_id": "22222222222222222222222222222222",
        "recovery_snapshot_id": "33333333333333333333333333333333",
    });
    let marker_path = spaces.join(format!(".rollback-{id}.json"));
    std::fs::write(&marker_path, serde_json::to_vec_pretty(&marker)?)?;
    std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o600))?;
    let issue_id = "44444444444444444444444444444444";
    let issue_marker = serde_json::json!({
        "schema_version": 1,
        "transaction_id": issue_id,
        "state": "prepared",
        "target": "work",
        "target_identity": {
            "schema_version": manifest["schema_version"],
            "name": "work",
            "created_unix_ms": manifest["created_unix_ms"],
            "space_id": manifest["space_id"],
        },
        "staging_entry": ".wrong-staging",
        "retired_entry": ".wrong-retired",
        "snapshot_id": "55555555555555555555555555555555",
        "recovery_snapshot_id": "66666666666666666666666666666666",
    });
    let issue_path = spaces.join(format!(".rollback-{issue_id}.json"));
    std::fs::write(&issue_path, serde_json::to_vec_pretty(&issue_marker)?)?;
    std::fs::set_permissions(&issue_path, std::fs::Permissions::from_mode(0o600))?;

    let listed = run(quarters(temporary.path()).args(["--json", "list"]))?;
    let listed: Value = serde_json::from_slice(&listed.stdout)?;
    assert_eq!(listed["result"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed["result"][0]["name"], "work");
    assert_eq!(listed["result"][0]["state"], "rollback_in_progress");

    let status = run(quarters(temporary.path()).args(["--json", "status"]))?;
    let status: Value = serde_json::from_slice(&status.stdout)?;
    assert_eq!(status["result"]["spaces"].as_array().map(Vec::len), Some(1));
    assert_eq!(status["result"]["spaces"][0]["state"], "rollback_in_progress");
    Ok(())
}

#[test]
fn human_list_shows_a_target_known_rollback_issue_without_spaces() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new()?;
    let spaces = temporary.path().join("spaces");
    std::fs::create_dir(&spaces)?;
    std::fs::set_permissions(&spaces, std::fs::Permissions::from_mode(0o700))?;
    let id = "11111111111111111111111111111111";
    let marker = serde_json::json!({
        "schema_version": 1,
        "transaction_id": id,
        "state": "prepared",
        "target": "ghost",
        "target_identity": {
            "schema_version": 1,
            "name": "ghost",
            "created_unix_ms": 1,
        },
        "staging_entry": ".wrong-staging",
        "retired_entry": ".wrong-retired",
        "snapshot_id": "22222222222222222222222222222222",
        "recovery_snapshot_id": "33333333333333333333333333333333",
    });
    let marker_path = spaces.join(format!(".rollback-{id}.json"));
    std::fs::write(&marker_path, serde_json::to_vec(&marker)?)?;
    std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o600))?;

    let listed = run(quarters(temporary.path()).arg("list"))?;
    let output = String::from_utf8(listed.stdout)?;
    assert!(output.contains("ghost"));
    assert!(output.contains("rollback"));
    assert!(!output.contains("No spaces yet"));
    Ok(())
}

#[test]
fn clone_human_output_names_the_exact_symlink_count_scope() -> Result<(), Box<dyn Error>> {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new()?;
    create(temporary.path(), "source")?;
    symlink(".cache/derived", temporary.path().join("spaces/source/home/cache-link"))?;
    let preview = run(quarters(temporary.path()).args(["clone", "source", "copy", "--preview"]))?;
    let output = String::from_utf8(preview.stdout)?;
    assert!(output.contains("1 links into omitted cache roots"));
    assert!(!output.contains("links may dangle after exclusions"));
    Ok(())
}

fn write_executable(path: &Path, body: &[u8]) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, body)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[test]
fn profile_default_and_expanded_workspace_have_stable_schema_contracts() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new()?;
    let profile = run(quarters(temporary.path()).args(["--json", "create", "profile"]))?;
    let profile: Value = serde_json::from_slice(&profile.stdout)?;
    assert_eq!(profile["result"]["layout"], "profile");
    assert_eq!(profile["result"]["space_id"].as_str().map(str::len), Some(32));
    let profile_manifest: Value =
        serde_json::from_slice(&std::fs::read(temporary.path().join("spaces/profile/.quarters.json"))?)?;
    assert_eq!(profile_manifest["schema_version"], 3);
    assert_eq!(profile_manifest["layout"], "profile");
    assert_eq!(profile_manifest["space_id"].as_str().map(str::len), Some(32));

    let workspace = run(quarters(temporary.path()).args(["--json", "create", "workspace", "--layout", "workspace"]))?;
    let workspace: Value = serde_json::from_slice(&workspace.stdout)?;
    assert_eq!(workspace["result"]["layout"], "workspace");
    assert_eq!(workspace["result"]["space_id"].as_str().map(str::len), Some(32));
    let workspace_home = temporary.path().join("spaces/workspace/home");
    for relative in ["Desktop", "Documents", "Downloads", "Pictures", "Templates"] {
        let metadata = std::fs::symlink_metadata(workspace_home.join(relative))?;
        assert!(metadata.is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }
    let list = run(quarters(temporary.path()).args(["--json", "list"]))?;
    let list: Value = serde_json::from_slice(&list.stdout)?;
    assert_eq!(list["result"][0]["layout"], "profile");
    assert_eq!(list["result"][1]["layout"], "workspace");
    let status = run(quarters(temporary.path()).args(["--json", "status", "workspace"]))?;
    let status: Value = serde_json::from_slice(&status.stdout)?;
    assert_eq!(status["result"]["shortcuts"].as_array().map(Vec::len), Some(2));
    Ok(())
}

#[test]
fn prompt_context_uses_only_the_validated_space_name() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("%F{red}$(id)`tick`\\root");
    create(&root, "safe-name")?;

    let output = run(quarters(&root).args(["--json", "env", "safe-name"]))?;
    let envelope: Value = serde_json::from_slice(&output.stdout)?;
    let environment = envelope["result"]["environment"]
        .as_object()
        .ok_or("missing environment")?;
    assert_eq!(environment["QUARTERS_PROMPT_NAME"], "safe-name");
    assert_eq!(environment["QUARTERS_PROMPT_PREFIX"], "[q:safe-name] ");
    for name in ["QUARTERS_PROMPT_NAME", "QUARTERS_PROMPT_PREFIX"] {
        let value = environment[name].as_str().ok_or("prompt value is not text")?;
        for rejected in ["%F{red}", "$(id)", "`tick`", "\\root"] {
            assert!(!value.contains(rejected));
        }
    }
    Ok(())
}

#[test]
fn host_escape_clears_prompt_context() -> Result<(), Box<dyn Error>> {
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
        "/usr/bin/env",
    ]))?;
    let environment = String::from_utf8(output.stdout)?;
    assert!(!environment.lines().any(|line| line.starts_with("QUARTERS_PROMPT_")));
    assert!(!environment.lines().any(|line| line.starts_with("QUARTERS_SPACE=")));
    Ok(())
}

#[test]
fn shell_init_is_constant_output_and_never_json_wrapped() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let output = run(quarters(temporary.path()).args(["shell-init", "zsh"]))?;
    let script = String::from_utf8(output.stdout)?;
    assert!(script.starts_with("# Quarters shell integration v1\n"));
    assert!(script.contains("QUARTERS_PROMPT_PREFIX"));
    assert!(!script.contains("QUARTERS_SPACE_ROOT"));

    let output = quarters(temporary.path())
        .args(["--json", "shell-init", "bash"])
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["kind"], "invalid_input");
    Ok(())
}

#[test]
fn opening_an_existing_space_never_rewrites_user_startup_files() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    let zshrc = temporary.path().join("spaces/work/home/.zshrc");
    std::fs::write(&zshrc, b"# user-owned after creation\n")?;
    run(quarters(temporary.path()).args(["doctor", "work"]))?;
    assert_eq!(std::fs::read(&zshrc)?, b"# user-owned after creation\n");
    Ok(())
}

#[test]
fn shortcut_install_status_and_remove_are_idempotent() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let home = temporary.path().join("home");
    let bin = home.join(".local/bin");
    std::fs::create_dir_all(&bin)?;
    write_executable(&bin.join("quarters"), b"#!/bin/sh\nexit 0\n")?;
    let path = bin.to_string_lossy().into_owned();
    let home = home.to_string_lossy().into_owned();
    let directory = bin.to_string_lossy().into_owned();

    for _attempt in 0..2 {
        let output = run(quarters(temporary.path())
            .env("HOME", &home)
            .env("PATH", &path)
            .args(["--json", "shortcut", "install", "qts", "--dir", &directory]))?;
        let report: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(report["result"]["state"], "managed");
        assert_eq!(report["result"]["link_target"], "quarters");
    }

    let output = run(quarters(temporary.path())
        .env("HOME", &home)
        .env("PATH", &path)
        .args(["--json", "shortcut", "status", "qts", "--dir", &directory]))?;
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["result"]["state"], "managed");
    assert_eq!(report["result"]["parent_shell_check"], "type -a qts");

    for _attempt in 0..2 {
        let output = run(quarters(temporary.path())
            .env("HOME", &home)
            .env("PATH", &path)
            .args(["--json", "shortcut", "remove", "qts", "--dir", &directory]))?;
        let report: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(report["result"]["state"], "absent");
    }
    Ok(())
}

#[test]
fn shortcut_never_overwrites_or_removes_an_unmanaged_entry() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let home = temporary.path().join("home");
    let bin = home.join(".local/bin");
    std::fs::create_dir_all(&bin)?;
    write_executable(&bin.join("quarters"), b"#!/bin/sh\nexit 0\n")?;
    write_executable(&bin.join("qts"), b"#!/bin/sh\nexit 7\n")?;
    let path = bin.to_string_lossy().into_owned();
    let home = home.to_string_lossy().into_owned();
    let directory = bin.to_string_lossy().into_owned();

    for action in ["install", "remove"] {
        let output = quarters(temporary.path())
            .env("HOME", &home)
            .env("PATH", &path)
            .args(["--json", "shortcut", action, "qts", "--dir", &directory])
            .output()?;
        assert_eq!(output.status.code(), Some(4));
        let error: Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(error["error"]["kind"], "already_exists");
    }
    assert_eq!(std::fs::read(bin.join("qts"))?, b"#!/bin/sh\nexit 7\n");
    Ok(())
}

#[test]
fn shortcut_mutation_refuses_quarters_context() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let home = temporary.path().join("home");
    let bin = home.join(".local/bin");
    std::fs::create_dir_all(&bin)?;
    write_executable(&bin.join("quarters"), b"#!/bin/sh\nexit 0\n")?;
    let path = bin.to_string_lossy().into_owned();
    let home = home.to_string_lossy().into_owned();
    let directory = bin.to_string_lossy().into_owned();

    let output = quarters(temporary.path())
        .env("HOME", &home)
        .env("PATH", &path)
        .env("QUARTERS_SPACE", "work")
        .args(["--json", "shortcut", "install", "qts", "--dir", &directory])
        .output()?;
    assert_eq!(output.status.code(), Some(6));
    let error: Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["kind"], "unsupported");
    assert!(!bin.join("qts").exists());
    Ok(())
}

#[test]
fn shortcut_reports_missing_path_and_rejects_an_unmanaged_symlink() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new()?;
    let home = temporary.path().join("home");
    let bin = home.join(".local/bin");
    std::fs::create_dir_all(&bin)?;
    let home_text = home.to_string_lossy().into_owned();
    let directory = bin.to_string_lossy().into_owned();

    let status = run(quarters(temporary.path())
        .env("HOME", &home_text)
        .env_remove("PATH")
        .args(["--json", "shortcut", "status", "qts", "--dir", &directory]))?;
    let status: Value = serde_json::from_slice(&status.stdout)?;
    assert_eq!(status["result"]["state"], "absent");
    assert_eq!(status["result"]["directory_on_path"], false);

    symlink("not-quarters", bin.join("qts"))?;
    let remove = quarters(temporary.path())
        .env("HOME", &home_text)
        .env("PATH", &bin)
        .args(["--json", "shortcut", "remove", "qts", "--dir", &directory])
        .output()?;
    assert_eq!(remove.status.code(), Some(4));
    assert_eq!(std::fs::read_link(bin.join("qts"))?, Path::new("not-quarters"));

    std::fs::remove_file(bin.join("qts"))?;
    symlink(temporary.path().join("missing/quarters"), bin.join("qts"))?;
    let stale = run(quarters(temporary.path())
        .env("HOME", &home_text)
        .env("PATH", &bin)
        .args(["--json", "shortcut", "status", "qts", "--dir", &directory]))?;
    let stale: Value = serde_json::from_slice(&stale.stdout)?;
    assert_eq!(stale["result"]["state"], "stale");
    run(quarters(temporary.path())
        .env("HOME", &home_text)
        .env("PATH", &bin)
        .args(["shortcut", "remove", "qts", "--dir", &directory]))?;
    assert!(!bin.join("qts").exists());

    write_executable(&temporary.path().join("quarters"), b"#!/bin/sh\nexit 0\n")?;
    let relative_path = std::env::join_paths([Path::new("."), bin.as_path()])?;
    let install = quarters(temporary.path())
        .current_dir(temporary.path())
        .env("HOME", &home_text)
        .env("PATH", relative_path)
        .args(["--json", "shortcut", "install", "qts", "--dir", &directory])
        .output()?;
    assert_eq!(install.status.code(), Some(3));
    let error: Value = serde_json::from_slice(&install.stderr)?;
    assert_eq!(error["error"]["kind"], "not_found");
    Ok(())
}

#[test]
fn shortcut_targets_the_path_launcher_not_the_running_native_binary() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let home = temporary.path().join("home");
    let launcher_bin = temporary.path().join("launcher-bin");
    let shortcut_bin = home.join(".local/bin");
    std::fs::create_dir_all(&launcher_bin)?;
    std::fs::create_dir_all(&shortcut_bin)?;
    write_executable(&launcher_bin.join("quarters"), b"#!/bin/sh\nexit 0\n")?;
    let path = std::env::join_paths([launcher_bin.as_path(), shortcut_bin.as_path()])?;
    let home = home.to_string_lossy().into_owned();
    let directory = shortcut_bin.to_string_lossy().into_owned();

    run(quarters(temporary.path())
        .env("HOME", &home)
        .env("PATH", path)
        .args(["shortcut", "install", "qts", "--dir", &directory]))?;
    assert_eq!(
        std::fs::read_link(shortcut_bin.join("qts"))?,
        launcher_bin.join("quarters")
    );

    let replacement_bin = temporary.path().join("replacement-bin");
    std::fs::create_dir_all(&replacement_bin)?;
    write_executable(&replacement_bin.join("quarters"), b"#!/bin/sh\nexit 0\n")?;
    let replacement_path = std::env::join_paths([replacement_bin.as_path(), shortcut_bin.as_path()])?;
    let relocated = run(quarters(temporary.path())
        .env("HOME", &home)
        .env("PATH", &replacement_path)
        .args(["--json", "shortcut", "status", "qts", "--dir", &directory]))?;
    let relocated: Value = serde_json::from_slice(&relocated.stdout)?;
    assert_eq!(relocated["result"]["state"], "relocated");
    let reinstall = quarters(temporary.path())
        .env("HOME", &home)
        .env("PATH", &replacement_path)
        .args(["shortcut", "install", "qts", "--dir", &directory])
        .output()?;
    assert_eq!(reinstall.status.code(), Some(4));
    run(quarters(temporary.path())
        .env("HOME", &home)
        .env("PATH", replacement_path)
        .args(["shortcut", "remove", "qts", "--dir", &directory]))?;
    assert!(!shortcut_bin.join("qts").exists());
    Ok(())
}

#[test]
fn doctor_json_pins_shortcut_and_runtime_truthfulness() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let home = temporary.path().join("home");
    let bin = home.join(".local/bin");
    std::fs::create_dir_all(&bin)?;
    write_executable(&bin.join("quarters"), b"#!/bin/sh\nexit 0\n")?;
    let output = run(quarters(temporary.path())
        .env("HOME", &home)
        .env("PATH", &bin)
        .args(["--json", "doctor"]))?;
    let envelope: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(envelope["schema_version"], 1);
    assert_eq!(envelope["command"], "doctor");
    assert_eq!(envelope["result"]["shortcuts"].as_array().map(Vec::len), Some(2));
    assert_eq!(envelope["result"]["platform"]["workspace_profile"]["available"], true);
    assert_eq!(
        envelope["result"]["platform"]["workspace_profile"]["status"],
        "experimental"
    );
    let first = &envelope["result"]["shortcuts"][0];
    for field in [
        "name",
        "context",
        "state",
        "directory",
        "entry",
        "link_target",
        "shortcut_matches",
        "quarters_matches",
        "directory_on_path",
        "parent_shell_check",
        "parent_shell_limitation",
        "issue",
    ] {
        assert!(first.get(field).is_some(), "missing doctor shortcut field {field}");
    }
    let ssh = envelope["result"]["tools"]
        .as_array()
        .and_then(|tools| tools.iter().find(|tool| tool["tool"] == "ssh"))
        .ok_or("missing ssh probe")?;
    assert!(
        ssh["limitation"]
            .as_str()
            .is_some_and(|limitation| limitation.contains("absolute host-tool paths bypass adapters"))
    );
    Ok(())
}
