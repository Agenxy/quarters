//! End-to-end acceptance tests for walkthrough-driven product increments.

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
fn profile_default_and_expanded_workspace_have_distinct_schema_contracts() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new()?;
    let profile = run(quarters(temporary.path()).args(["--json", "create", "profile"]))?;
    let profile: Value = serde_json::from_slice(&profile.stdout)?;
    assert_eq!(profile["result"]["layout"], "profile");
    assert!(profile["result"]["space_id"].is_null());
    let profile_manifest: Value =
        serde_json::from_slice(&std::fs::read(temporary.path().join("spaces/profile/.quarters.json"))?)?;
    assert_eq!(profile_manifest["schema_version"], 1);
    assert!(profile_manifest.get("layout").is_none());
    assert!(profile_manifest.get("space_id").is_none());

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
            .is_some_and(|limitation| limitation.contains("SSH_AUTH_SOCK is unset"))
    );
    Ok(())
}
