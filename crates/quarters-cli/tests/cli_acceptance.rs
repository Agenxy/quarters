//! End-to-end process and state-profile acceptance tests.

use serde_json::Value;
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::{Command, Output, Stdio};
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
fn shortcut_invocation_creates_a_space_with_managed_commands() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let shortcut = temporary.path().join("qts");
    let root = temporary.path().join("store");
    symlink(env!("CARGO_BIN_EXE_quarters"), &shortcut)?;
    run(Command::new(&shortcut)
        .arg("--root")
        .arg(&root)
        .args(["create", "shortcut"]))?;
    for command in ["quarters", "ssh", "scp", "sftp", "ssh-add"] {
        assert!(
            std::fs::symlink_metadata(root.join("spaces/shortcut/home/.local/bin").join(command))?
                .file_type()
                .is_symlink()
        );
    }
    Ok(())
}

#[test]
fn renamed_mcp_executable_fails_before_serving() -> Result<(), Box<dyn Error>> {
    let executable = Path::new(env!("CARGO_BIN_EXE_quarters"));
    let parent = executable.parent().ok_or("test executable has no parent")?;
    let temporary = tempfile::tempdir_in(parent)?;
    let renamed = temporary.path().join("renamed-quarters");
    std::fs::hard_link(executable, &renamed)?;
    let output = Command::new(renamed)
        .arg("--root")
        .arg(temporary.path().join("store"))
        .arg("mcp")
        .output()?;
    assert_eq!(output.status.code(), Some(6));
    assert!(String::from_utf8(output.stderr)?.contains("not a protected stable Quarters launcher"));
    Ok(())
}

#[test]
fn mcp_stdio_serves_the_stateless_2026_path_end_to_end() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let mut child = quarters(temporary.path())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().ok_or("missing MCP stdin")?;
    let output = child.stdout.take().ok_or("missing MCP stdout")?;
    let mut output = BufReader::new(output);
    let metadata = serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "quarters-e2e", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });

    write_frame(
        &mut input,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {"_meta": metadata}
        }),
    )?;
    let discovered = read_frame(&mut output)?;
    assert_eq!(
        discovered["result"]["supportedVersions"],
        serde_json::json!(["2026-07-28"])
    );
    assert_eq!(
        discovered["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "quarters"
    );

    write_frame(
        &mut input,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {"_meta": metadata}
        }),
    )?;
    let tools = read_frame(&mut output)?;
    assert_eq!(tools["result"]["tools"].as_array().map(Vec::len), Some(3));
    assert_eq!(tools["result"]["cacheScope"], "public");
    assert_eq!(tools["result"]["ttlMs"], 3_600_000);

    write_frame(
        &mut input,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "quarters_create",
                "arguments": {"name": "agent", "layout": "workspace"},
                "_meta": metadata
            }
        }),
    )?;
    let created = read_frame(&mut output)?;
    assert_eq!(created["result"]["structuredContent"]["data"]["space"]["name"], "agent");
    assert_eq!(
        created["result"]["structuredContent"]["data"]["space"]["layout"],
        "workspace"
    );
    drop(input);
    let completed = child.wait_with_output()?;
    assert!(completed.status.success());
    assert!(completed.stderr.is_empty());
    for command in ["quarters", "ssh", "scp", "sftp", "ssh-add"] {
        assert!(
            std::fs::symlink_metadata(temporary.path().join("spaces/agent/home/.local/bin").join(command))?
                .file_type()
                .is_symlink()
        );
    }
    Ok(())
}

#[test]
fn mcp_stdio_serves_the_initialized_2025_path_end_to_end() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let mut child = quarters(temporary.path())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().ok_or("missing MCP stdin")?;
    let output = child.stdout.take().ok_or("missing MCP stdout")?;
    let mut output = BufReader::new(output);

    write_frame(
        &mut input,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "quarters-legacy-e2e", "version": "1"}
            }
        }),
    )?;
    let initialized = read_frame(&mut output)?;
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
    assert!(initialized["result"].get("_meta").is_none());
    write_frame(
        &mut input,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )?;
    write_frame(
        &mut input,
        &serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )?;
    let tools = read_frame(&mut output)?;
    assert_eq!(tools["result"]["tools"].as_array().map(Vec::len), Some(3));
    assert!(tools["result"].get("resultType").is_none());
    assert!(tools["result"].get("cacheScope").is_none());
    assert!(tools["result"].get("ttlMs").is_none());
    write_frame(
        &mut input,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "quarters_create",
                "arguments": {"name": "legacy-agent", "layout": "workspace"}
            }
        }),
    )?;
    let created = read_frame(&mut output)?;
    assert_eq!(
        created["result"]["structuredContent"]["data"]["space"]["name"],
        "legacy-agent"
    );
    assert_eq!(
        created["result"]["structuredContent"]["data"]["space"]["layout"],
        "workspace"
    );
    assert!(created["result"].get("resultType").is_none());
    drop(input);
    let completed = child.wait_with_output()?;
    assert!(completed.status.success());
    assert!(completed.stderr.is_empty());
    Ok(())
}

fn write_frame(writer: &mut impl Write, value: &Value) -> Result<(), Box<dyn Error>> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn read_frame(reader: &mut impl BufRead) -> Result<Value, Box<dyn Error>> {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line)?;
    if bytes == 0 {
        return Err("MCP server closed before returning a frame".into());
    }
    Ok(serde_json::from_str(&line)?)
}

#[test]
fn help_and_version_are_successful_control_flow() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let help = run(quarters(temporary.path()).arg("--help"))?;
    assert!(String::from_utf8(help.stdout)?.contains("Usage: quarters"));

    let clone_help = run(quarters(temporary.path()).args(["clone", "--help"]))?;
    let clone_help = String::from_utf8(clone_help.stdout)?;
    assert!(clone_help.contains("--preview"));
    assert!(clone_help.contains("--confirm-sensitive-state"));

    let version = run(quarters(temporary.path()).arg("--version"))?;
    assert!(String::from_utf8(version.stdout)?.starts_with("quarters 0.1.0-alpha.4"));
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
    assert_eq!(listed["result"][0]["health"], "healthy");
    Ok(())
}

#[test]
fn human_output_preserves_printable_unicode_paths() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("café-d'été");
    create(&root, "work")?;

    let output = run(quarters(&root).args(["list"]))?;
    let listed = String::from_utf8(output.stdout)?;
    assert!(listed.contains("café-d'été"));
    assert!(!listed.contains("\\u{e9}"));

    let output = run(quarters(&root).args(["env", "work"]))?;
    let environment = String::from_utf8(output.stdout)?;
    assert!(environment.contains("café-d'été"));
    assert!(!environment.contains("\\u{e9}"));
    Ok(())
}

#[test]
fn json_output_presentation_escapes_stored_paths() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new()?;
    let root = temporary.path().join("root\u{202e}hidden");
    let shell = temporary.path().join("shell\u{1b}[2J");
    std::fs::write(&shell, b"#!/bin/sh\nexit 0\n")?;
    std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o700))?;
    run(quarters(&root).args(["--json", "create", "work", "--shell", shell.to_string_lossy().as_ref()]))?;

    let output = run(quarters(&root).args(["--json", "list"]))?;
    let raw = String::from_utf8(output.stdout)?;
    assert!(!raw.contains('\u{1b}'));
    assert!(!raw.contains('\u{202e}'));
    let listed: Value = serde_json::from_str(&raw)?;
    assert!(
        listed["result"][0]["root"]
            .as_str()
            .is_some_and(|value| value.contains("\\u{202e}"))
    );
    assert!(
        listed["result"][0]["default_shell"]
            .as_str()
            .is_some_and(|value| value.contains("\\u{1b}"))
    );

    let output = run(quarters(&root)
        .env("TERM", "\u{1b}]0;hostile\u{7}")
        .env("LC_\u{202e}KEY", "value\u{1b}[2J")
        .args(["--json", "env", "work"]))?;
    let raw = String::from_utf8(output.stdout)?;
    assert!(!raw.contains('\u{1b}'));
    assert!(!raw.contains('\u{202e}'));
    let environment: Value = serde_json::from_str(&raw)?;
    let values = environment["result"]["environment"]
        .as_object()
        .ok_or("missing safe environment")?;
    assert!(values.keys().all(|key| !key.contains('\u{202e}')));
    assert!(values.values().all(|value| {
        value
            .as_str()
            .is_none_or(|value| !value.contains('\u{1b}') && !value.contains('\u{202e}'))
    }));
    Ok(())
}

#[test]
fn current_json_rejects_hostile_self_reported_state() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let output = run(quarters(temporary.path())
        .env("QUARTERS_SPACE", "work\u{202e}txt\u{1b}]0;hostile\u{7}")
        .args(["--json", "current"]))?;
    let raw = String::from_utf8(output.stdout)?;
    assert!(!raw.contains('\u{1b}'));
    assert!(!raw.contains('\u{7}'));
    assert!(!raw.contains('\u{202e}'));
    let current: Value = serde_json::from_str(&raw)?;
    assert_eq!(current["result"]["space"], "host");

    create(temporary.path(), "work")?;
    let output = run(quarters(temporary.path())
        .env("QUARTERS_SPACE", "work")
        .args(["--json", "current"]))?;
    let current: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(current["result"]["space"], "work");

    let hidden_root = temporary.path().join("home-view-hidden-root");
    let output = run(quarters(&hidden_root)
        .env("QUARTERS_SPACE", "work")
        .env("QUARTERS_NO_HOST_ESCAPE", "home-view")
        .args(["--json", "current"]))?;
    let current: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(current["result"]["space"], "work");
    Ok(())
}

#[test]
fn inspection_reports_an_unhealthy_sibling_and_removal_recovers() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new()?;
    create(temporary.path(), "healthy")?;
    create(temporary.path(), "broken")?;
    let manifest = temporary.path().join("spaces/broken/.quarters.json");
    std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o644))?;

    let output = run(quarters(temporary.path()).args(["--json", "list"]))?;
    let listed: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(listed["result"].as_array().map(Vec::len), Some(2));
    assert!(listed["result"].as_array().is_some_and(|entries| {
        entries
            .iter()
            .any(|entry| entry["name"] == "broken" && entry["health"] == "unhealthy")
    }));
    assert!(listed["result"].as_array().is_some_and(|entries| {
        entries
            .iter()
            .any(|entry| entry["name"] == "healthy" && entry["health"] == "healthy")
    }));

    let output = run(quarters(temporary.path()).args(["--json", "status"]))?;
    let status: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(status["result"]["spaces"][0]["name"], "broken");
    assert_eq!(status["result"]["spaces"][0]["lease_state"], "unknown");

    let output = run(quarters(temporary.path())
        .env("QUARTERS_SPACE", "broken")
        .args(["--json", "status", "broken"]))?;
    let current: Value = serde_json::from_slice(&output.stdout)?;
    assert!(current["result"]["current_space"].is_null());
    assert_eq!(current["result"]["spaces"][0]["current"], false);
    let output = run(quarters(temporary.path())
        .env("QUARTERS_SPACE", "broken")
        .args(["status", "broken"]))?;
    let human_current = String::from_utf8(output.stdout)?;
    let row = human_current
        .lines()
        .find(|line| line.starts_with("broken"))
        .ok_or("missing unhealthy current row")?;
    assert_eq!(
        row.split_whitespace().take(7).collect::<Vec<_>>(),
        ["broken", "unhealthy", "unknown", "unknown", "unknown", "unknown", "no"]
    );

    repair_then_remove_broken_space(temporary.path(), &manifest)?;
    assert!(!temporary.path().join("spaces/broken").exists());

    let rogue = "\u{1b}[31mrogue-\u{202e}name-that-is-far-too-long-for-a-space";
    let rogue_root = temporary.path().join("spaces").join(rogue);
    std::fs::create_dir(&rogue_root)?;
    std::fs::set_permissions(&rogue_root, std::fs::Permissions::from_mode(0o700))?;
    std::fs::create_dir(rogue_root.join("home"))?;
    std::fs::set_permissions(rogue_root.join("home"), std::fs::Permissions::from_mode(0o700))?;
    std::fs::write(rogue_root.join(".active"), b"")?;
    std::fs::set_permissions(rogue_root.join(".active"), std::fs::Permissions::from_mode(0o600))?;
    let rogue_manifest = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "name": rogue,
        "created_unix_ms": 0,
        "default_shell": "/bin/sh",
        "authority_model": "host-account-state-profile",
    }))?;
    std::fs::write(rogue_root.join(".quarters.json"), rogue_manifest)?;
    std::fs::set_permissions(
        rogue_root.join(".quarters.json"),
        std::fs::Permissions::from_mode(0o600),
    )?;

    let output = run(quarters(temporary.path()).args(["--json", "list"]))?;
    let raw_json = String::from_utf8(output.stdout)?;
    assert!(!raw_json.contains('\u{1b}'));
    assert!(!raw_json.contains('\u{202e}'));
    let safe_rogue = quarters_core::escape_untrusted_text_bounded(rogue, 64);
    let listed: Value = serde_json::from_str(&raw_json)?;
    assert!(listed["result"].as_array().is_some_and(|entries| {
        entries
            .iter()
            .any(|entry| entry["name"] == safe_rogue && entry["health"] == "unhealthy")
    }));
    let diagnostic = listed["result"]
        .as_array()
        .and_then(|entries| entries.iter().find(|entry| entry["name"] == safe_rogue))
        .and_then(|entry| entry["error"]["message"].as_str())
        .ok_or("missing rogue JSON diagnostic")?;
    assert!(!diagnostic.contains('\u{1b}'));
    assert!(diagnostic.contains("\\u{1b}"));
    let output = run(quarters(temporary.path()).args(["list"]))?;
    let human = String::from_utf8(output.stdout)?;
    assert!(!human.contains('\u{1b}'));
    assert!(human.contains("\\u{1b}[31mrogue"));
    let output = run(quarters(temporary.path()).args(["--json", "rm", rogue, "--confirm", rogue]))?;
    let removed = String::from_utf8(output.stdout)?;
    assert!(!removed.contains('\u{1b}'));
    assert!(!removed.contains('\u{202e}'));
    let removed: Value = serde_json::from_str(&removed)?;
    assert!(
        removed["result"]["removed"]
            .as_str()
            .is_some_and(|name| name.contains("\\u{1b}") && name.contains("\\u{202e}"))
    );
    assert!(!rogue_root.exists());
    Ok(())
}

fn repair_then_remove_broken_space(root: &Path, manifest: &Path) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let refused = quarters(root).args(["rm", "broken", "--confirm", "broken"]).output()?;
    assert_eq!(refused.status.code(), Some(7));
    assert!(String::from_utf8(refused.stderr)?.contains("cannot prove private SSH-agent state is absent"));
    std::fs::set_permissions(manifest, std::fs::Permissions::from_mode(0o600))?;
    run(quarters(root).args(["rm", "broken", "--confirm", "broken"]))?;
    Ok(())
}

#[test]
fn status_reports_supervised_activity_and_current_space() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    let output = run(quarters(temporary.path()).args(["--json", "status", "work"]))?;
    let inactive: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(inactive["result"]["observation_scope"], "quarters-cooperative-lease");
    assert_eq!(inactive["result"]["detached_processes"], "unknown");
    assert_eq!(inactive["result"]["spaces"][0]["lease_state"], "free");
    assert_eq!(inactive["result"]["spaces"][0]["current"], false);

    let mut probes = Vec::new();
    for _index in 0..60 {
        probes.push(
            quarters(temporary.path())
                .args(["--json", "status", "work"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        );
    }
    for probe in probes {
        let output = probe.wait_with_output()?;
        assert!(output.status.success(), "concurrent status probe failed");
        let status: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(status["result"]["spaces"][0]["lease_state"], "free");
    }

    let output = run(quarters(temporary.path())
        .env("QUARTERS_SPACE", "../untrusted")
        .args(["--json", "status", "work"]))?;
    let untrusted: Value = serde_json::from_slice(&output.stdout)?;
    assert!(untrusted["result"]["current_space"].is_null());

    let binary = env!("CARGO_BIN_EXE_quarters");
    let root = temporary.path().to_string_lossy().into_owned();
    let output = run(quarters(temporary.path()).args([
        "exec", "work", "--", binary, "--root", &root, "--json", "status", "work",
    ]))?;
    let active: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(active["result"]["spaces"][0]["lease_state"], "held");
    assert_eq!(active["result"]["spaces"][0]["current"], true);
    assert_eq!(active["result"]["current_space"], "work");

    create(temporary.path(), "play")?;
    let output = run(quarters(temporary.path()).args([
        "exec", "work", "--", binary, "--root", &root, "--json", "status", "play",
    ]))?;
    let filtered: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(filtered["result"]["current_space"], "work");
    assert_eq!(filtered["result"]["spaces"][0]["current"], false);

    let output = run(quarters(temporary.path()).args(["status", "work"]))?;
    let human = String::from_utf8(output.stdout)?;
    let row = human
        .lines()
        .find(|line| line.starts_with("work"))
        .ok_or("missing status row")?;
    assert_eq!(
        row.split_whitespace().take(7).collect::<Vec<_>>(),
        ["work", "healthy", "profile", "unfrozen", "free", "unset", "no"]
    );
    assert_eq!(row.find("profile"), Some(44));
    assert_eq!(row.find("unfrozen"), Some(55));
    assert_eq!(row.find("free"), Some(65));
    let aggregate = run(quarters(temporary.path()).args(["--json", "status"]))?;
    let aggregate: Value = serde_json::from_slice(&aggregate.stdout)?;
    assert!(
        aggregate["result"]["spaces"]
            .as_array()
            .is_some_and(|spaces| spaces.iter().all(|space| space["ssh_agent_state"] == "not-inspected"))
    );
    Ok(())
}

#[test]
fn missing_store_keeps_the_named_not_found_contract() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let missing_root = temporary.path().join("missing");
    let output = quarters(&missing_root).args(["--json", "status", "absent"]).output()?;
    assert_eq!(output.status.code(), Some(3));
    let error: Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["kind"], "not_found");
    assert_eq!(error["error"]["hint"], "run 'quarters list' to see available spaces");
    Ok(())
}

#[test]
fn stale_default_shell_does_not_block_inspection_exec_or_removal() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new()?;
    let shell = temporary.path().join("temporary-shell");
    std::fs::write(&shell, b"#!/bin/sh\nexec /bin/sh \"$@\"\n")?;
    std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o700))?;
    run(quarters(temporary.path()).args(["create", "stale", "--shell", shell.to_string_lossy().as_ref()]))?;
    std::fs::remove_file(&shell)?;

    let output = run(quarters(temporary.path()).args(["--json", "list"]))?;
    let listed: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(listed["result"][0]["health"], "healthy");
    run(quarters(temporary.path()).args(["exec", "stale", "--", "/bin/sh", "-c", "exit 0"]))?;
    run(quarters(temporary.path()).args(["rm", "stale", "--confirm", "stale"]))?;
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
    assert!(!environment.lines().any(|line| line.starts_with("SSH_AUTH_SOCK=")));
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
fn profile_owned_variables_cannot_be_explicitly_inherited() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    let output = quarters(temporary.path())
        .env("SSH_AUTH_SOCK", "/tmp/host-agent-secret")
        .args(["--json", "env", "work", "--inherit", "SSH_AUTH_SOCK"])
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["kind"], "invalid_input");
    assert!(
        error["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("owned by the space profile"))
    );
    assert!(!String::from_utf8(output.stderr)?.contains("host-agent-secret"));
    Ok(())
}

#[test]
fn removal_never_targets_hidden_store_entries() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    let hidden = temporary.path().join("spaces/.creating-recovery-state");
    std::fs::create_dir(&hidden)?;

    let output = quarters(temporary.path())
        .args([
            "--json",
            "rm",
            ".creating-recovery-state",
            "--confirm",
            ".creating-recovery-state",
        ])
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["kind"], "invalid_input");
    assert!(hidden.is_dir());
    Ok(())
}

#[test]
fn recovery_reports_and_reclaims_only_reserved_stale_state() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    let unfinished = temporary.path().join("spaces/.creating-crashed");
    let lockless = temporary.path().join("spaces/.creating-alpha2");
    let retired = temporary.path().join("trash/.retired-crashed");
    let unrelated = temporary.path().join("spaces/.operator-note");
    for path in [&unfinished, &lockless, &retired, &unrelated] {
        std::fs::create_dir(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    let creation_lock = unfinished.join(".creating.lock");
    std::fs::write(&creation_lock, b"")?;
    std::fs::set_permissions(&creation_lock, std::fs::Permissions::from_mode(0o600))?;

    let doctor = run(quarters(temporary.path()).args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(report["result"]["recovery"]["status"], "available");
    assert_eq!(report["result"]["recovery"]["active_creations"], 0);
    assert_eq!(report["result"]["recovery"]["unfinished_creations"], 2);
    assert_eq!(report["result"]["recovery"]["retired_entries"], 1);

    let refused = quarters(temporary.path())
        .args(["--json", "recover", "--confirm", "anything-else"])
        .output()?;
    assert_eq!(refused.status.code(), Some(2));
    assert!(unfinished.is_dir());
    assert!(retired.is_dir());

    let recovered = run(quarters(temporary.path()).args(["--json", "recover", "--confirm", "stale-state"]))?;
    let recovered: Value = serde_json::from_slice(&recovered.stdout)?;
    assert_eq!(recovered["result"]["active_creations"], 0);
    assert_eq!(recovered["result"]["unfinished_creations"], 2);
    assert_eq!(recovered["result"]["retired_entries"], 1);
    assert!(!unfinished.exists());
    assert!(!lockless.exists());
    assert!(!retired.exists());
    assert!(unrelated.is_dir());
    assert!(temporary.path().join("spaces/work").is_dir());

    let external = temporary.path().join("external");
    std::fs::create_dir(&external)?;
    std::os::unix::fs::symlink(&external, temporary.path().join("spaces/.creating-linked"))?;
    let doctor = run(quarters(temporary.path()).args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(report["result"]["recovery"]["status"], "unavailable");
    assert!(external.is_dir());
    Ok(())
}

#[test]
fn doctor_never_creates_observation_state_through_a_linked_root() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let target = temporary.path().join("target");
    std::fs::create_dir(&target)?;
    let linked = temporary.path().join("linked-root");
    std::os::unix::fs::symlink(&target, &linked)?;

    let doctor = run(quarters(&linked).args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(report["result"]["recovery"]["status"], "unavailable");
    assert!(!target.join(".observe").exists());
    Ok(())
}

#[test]
fn doctor_reports_root_format_without_repairing_it() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new()?;
    let absent = temporary.path().join("absent");
    let doctor = run(quarters(&absent).args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(report["result"]["store_layout"]["state"], "absent");
    assert_eq!(report["result"]["store_layout"]["writable"], true);
    assert!(!absent.exists());

    let dual = temporary.path().join("dual");
    create(&dual, "work")?;
    std::fs::create_dir(dual.join(".spaces"))?;
    std::fs::set_permissions(dual.join(".spaces"), std::fs::Permissions::from_mode(0o700))?;
    let doctor = run(quarters(&dual).args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(report["result"]["store_layout"]["state"], "ambiguous-dual-layout");
    assert_eq!(report["result"]["store_layout"]["writable"], false);
    assert_eq!(report["result"]["recovery"]["status"], "unavailable");
    assert!(dual.join("spaces/work").is_dir());
    assert!(dual.join(".spaces").is_dir());
    let named = run(quarters(&dual).args(["--json", "doctor", "work"]))?;
    let named: Value = serde_json::from_slice(&named.stdout)?;
    assert_eq!(named["result"]["store_layout"]["state"], "ambiguous-dual-layout");
    assert_eq!(named["result"]["space_requested"], "work");
    assert_eq!(named["result"]["space"], Value::Null);
    assert_eq!(named["result"]["space_inspection_error"]["kind"], "corrupt_state");

    let staging = temporary.path().join("staging");
    create(&staging, "work")?;
    for index in 0..20 {
        std::fs::write(
            staging.join(format!(".quarters-store-staging-invalid-{index}.tmp")),
            b"reserved",
        )?;
    }
    let doctor = run(quarters(&staging).args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(
        report["result"]["store_layout"]["state"],
        "marked-visible-with-staging-issue"
    );
    assert_eq!(report["result"]["store_layout"]["root_format"], "visible");
    assert_eq!(report["result"]["store_layout"]["writable"], true);
    assert_eq!(
        report["result"]["store_layout"]["staging_entries"]
            .as_array()
            .map(Vec::len),
        Some(16)
    );
    assert_eq!(report["result"]["store_layout"]["staging_entries_at_least"], 20);
    for index in 0..20 {
        assert!(
            staging
                .join(format!(".quarters-store-staging-invalid-{index}.tmp"))
                .is_file()
        );
    }
    let doctor = run(quarters(&staging).arg("doctor"))?;
    let human = String::from_utf8(doctor.stdout)?;
    assert!(human.contains("staging issue:"));
    assert!(human.contains("showing 16 of at least 20 entries"));
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

    let traversal = quarters(temporary.path())
        .args(["--json", "rm", "../short-lived", "--confirm", "../short-lived"])
        .output()?;
    assert_eq!(traversal.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&traversal.stderr)?;
    assert_eq!(error["error"]["kind"], "invalid_input");
    assert!(temporary.path().join("spaces/short-lived").exists());

    run(quarters(temporary.path()).args(["rm", "short-lived", "--confirm", "short-lived"]))?;
    assert!(!temporary.path().join("spaces/short-lived").exists());
    Ok(())
}

#[test]
fn removal_fails_closed_when_its_root_or_lock_is_invalid() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new()?;
    create(temporary.path(), "missing-lock")?;
    std::fs::remove_file(temporary.path().join("spaces/missing-lock/.active"))?;
    let missing_lock = quarters(temporary.path())
        .args(["--json", "rm", "missing-lock", "--confirm", "missing-lock"])
        .output()?;
    assert_eq!(missing_lock.status.code(), Some(7));
    let error: Value = serde_json::from_slice(&missing_lock.stderr)?;
    assert_eq!(error["error"]["kind"], "corrupt_state");
    assert!(temporary.path().join("spaces/missing-lock").exists());

    create(temporary.path(), "broad-root")?;
    let root = temporary.path().join("spaces/broad-root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o750))?;
    let broad_root = quarters(temporary.path())
        .args(["--json", "rm", "broad-root", "--confirm", "broad-root"])
        .output()?;
    assert_eq!(broad_root.status.code(), Some(7));
    let error: Value = serde_json::from_slice(&broad_root.stderr)?;
    assert_eq!(error["error"]["kind"], "corrupt_state");
    assert!(root.exists());
    Ok(())
}

#[test]
fn doctor_does_not_advertise_unimplemented_confinement() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let doctor = run(quarters(temporary.path()).args(["--json", "doctor"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(report["result"]["platform"]["confinement"]["available"], false);
    assert_eq!(report["result"]["platform"]["confinement"]["status"], "not-implemented");
    assert!(report["result"]["space_environment_validated"].is_null());
    assert!(
        report["result"]["tools"]
            .as_array()
            .is_some_and(|tools| tools.iter().all(|tool| tool.get("executable").is_none()))
    );
    Ok(())
}

#[test]
fn doctor_validates_a_named_space_environment() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    create(temporary.path(), "work")?;
    let doctor = run(quarters(temporary.path()).args(["--json", "doctor", "work"]))?;
    let report: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(report["result"]["space_environment_validated"], true);
    assert_eq!(report["result"]["space_lease_state"], "free");
    assert_eq!(report["result"]["detached_processes"], "unknown");

    let environment = run(quarters(temporary.path()).args(["--json", "env", "work"]))?;
    let environment: Value = serde_json::from_slice(&environment.stdout)?;
    let runtime = environment["result"]["environment"]["XDG_RUNTIME_DIR"]
        .as_str()
        .ok_or("missing runtime directory")?;
    std::fs::remove_dir_all(runtime)?;
    std::fs::write(runtime, b"not a directory")?;
    let failed = quarters(temporary.path()).args(["--json", "doctor", "work"]).output()?;
    assert!(!failed.status.success());
    std::fs::remove_file(runtime)?;
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
            "test -f \"$HOME/.quarters-home-view-marker\" && test -f .quarters-home-view-marker && test \"$(quarters current)\" = work",
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
