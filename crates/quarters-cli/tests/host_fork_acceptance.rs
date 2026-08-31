//! End-to-end acceptance for previewed host-state forks.

use serde_json::Value;
use std::error::Error;
use std::os::unix::fs::{PermissionsExt, symlink};
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

#[test]
fn preview_confirmation_and_atomic_copy_are_coherent() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let host_home = protected_home(&temporary)?;
    let store = temporary.path().join("store");
    let sentinel = temporary.path().join("must-not-run");
    std::fs::write(
        host_home.join(".zshrc"),
        format!(
            "export HOST_FORK_SECRET_VALUE=not-in-preview\ntouch {}\n",
            sentinel.display()
        ),
    )?;
    std::fs::write(host_home.join(".customrc"), b"custom-state\n")?;

    let preview = preview(
        &store,
        &host_home,
        "forked",
        &["--from-host-path", ".customrc", "--replace-generated"],
    )?;
    let raw_preview = String::from_utf8(preview.stdout)?;
    assert!(!raw_preview.contains("HOST_FORK_SECRET_VALUE"));
    assert!(!raw_preview.contains("not-in-preview"));
    let preview: Value = serde_json::from_str(&raw_preview)?;
    let digest = preview["result"]["plan_digest"].as_str().ok_or("missing plan digest")?;
    assert_eq!(digest.len(), 64);
    assert_eq!(preview["result"]["mode"], "preview");
    assert_eq!(preview["result"]["file_count"], 2);
    assert_eq!(preview["result"]["content_uninspected"], true);
    assert_eq!(preview["result"]["may_include_sensitive_content"], true);
    assert!(!sentinel.exists());
    assert!(!store.join("spaces/forked").exists());

    let created = run(quarters(&store).env("HOME", &host_home).args([
        "--json",
        "create",
        "forked",
        "--shell",
        "/bin/sh",
        "--from-host",
        "shell",
        "--from-host-path",
        ".customrc",
        "--replace-generated",
        "--confirm-plan",
        digest,
    ]))?;
    let created: Value = serde_json::from_slice(&created.stdout)?;
    assert_eq!(created["result"]["mode"], "execute");
    assert_eq!(created["result"]["plan_digest"], digest);
    assert_eq!(
        std::fs::read(store.join("spaces/forked/home/.customrc"))?,
        b"custom-state\n"
    );
    let zshrc = std::fs::read_to_string(store.join("spaces/forked/home/.zshrc"))?;
    assert!(zshrc.contains("HOST_FORK_SECRET_VALUE"));
    assert!(zshrc.contains("Quarters-managed state and context for this fork"));
    assert!(zshrc.contains("XDG_STATE_HOME"));
    assert!(!sentinel.exists());
    assert!(store.join("spaces/forked/.quarters-provenance.json").is_file());
    Ok(())
}

#[test]
fn stale_plans_links_and_credential_paths_fail_closed() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let host_home = protected_home(&temporary)?;
    let store = temporary.path().join("store");
    std::fs::write(host_home.join(".customrc"), b"before\n")?;

    let stale_preview = preview(&store, &host_home, "stale", &["--from-host-path", ".customrc"])?;
    let stale_preview: Value = serde_json::from_slice(&stale_preview.stdout)?;
    let digest = stale_preview["result"]["plan_digest"]
        .as_str()
        .ok_or("missing digest")?;
    std::fs::write(host_home.join(".customrc"), b"after\n")?;
    let stale = quarters(&store)
        .env("HOME", &host_home)
        .args([
            "create",
            "stale",
            "--shell",
            "/bin/sh",
            "--from-host",
            "shell",
            "--from-host-path",
            ".customrc",
            "--confirm-plan",
            digest,
        ])
        .output()?;
    assert_eq!(stale.status.code(), Some(7));
    assert!(String::from_utf8(stale.stderr)?.contains("plan changed after preview"));
    assert!(!store.join("spaces/stale").exists());

    symlink(".customrc", host_home.join(".profile"))?;
    let linked = preview(&store, &host_home, "linked", &[])?;
    let linked: Value = serde_json::from_slice(&linked.stdout)?;
    assert_eq!(linked["result"]["ineligible"][0]["path"], ".profile");
    assert_eq!(
        linked["result"]["ineligible"][0]["reason"],
        "unsupported-file-type-or-link"
    );
    assert!(!store.join("spaces/linked").exists());

    let explicitly_linked = quarters(&store)
        .env("HOME", &host_home)
        .args([
            "create",
            "explicitly-linked",
            "--from-host",
            "shell",
            "--from-host-path",
            ".profile",
            "--preview",
        ])
        .output()?;
    assert!(!explicitly_linked.status.success());
    Ok(())
}

#[test]
fn explicit_sensitive_and_missing_paths_are_refused() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let host_home = protected_home(&temporary)?;
    let store = temporary.path().join("store");
    std::fs::create_dir(host_home.join(".ssh"))?;
    std::fs::write(host_home.join(".ssh/config"), b"Host *\n")?;

    for (name, path) in [
        ("credential", ".ssh/config"),
        ("credential-case", ".SSH/config"),
        ("history", ".zsh_history"),
    ] {
        let output = quarters(&store)
            .env("HOME", &host_home)
            .args([
                "create",
                name,
                "--from-host",
                "shell",
                "--from-host-path",
                path,
                "--preview",
            ])
            .output()?;
        assert_eq!(output.status.code(), Some(6));
    }

    let missing = quarters(&store)
        .env("HOME", &host_home)
        .args([
            "create",
            "missing-explicit",
            "--from-host",
            "shell",
            "--from-host-path",
            ".profile",
            "--preview",
        ])
        .output()?;
    assert!(!missing.status.success());
    Ok(())
}

#[test]
fn generated_startup_conflicts_require_a_new_approved_plan() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let host_home = protected_home(&temporary)?;
    let store = temporary.path().join("store");
    std::fs::write(host_home.join(".zshrc"), b"export EDITOR=vi\n")?;

    let unapproved = preview(&store, &host_home, "conflict", &[])?;
    let unapproved: Value = serde_json::from_slice(&unapproved.stdout)?;
    let digest = unapproved["result"]["plan_digest"]
        .as_str()
        .ok_or("missing unapproved digest")?;
    assert_eq!(unapproved["result"]["files"][0]["generated_conflict"], true);
    let refused = quarters(&store)
        .env("HOME", &host_home)
        .args([
            "create",
            "conflict",
            "--shell",
            "/bin/sh",
            "--from-host",
            "shell",
            "--confirm-plan",
            digest,
        ])
        .output()?;
    assert!(!refused.status.success());
    assert!(String::from_utf8(refused.stderr)?.contains("generated destination-file conflict"));
    assert!(!store.join("spaces/conflict").exists());

    let approved = preview(&store, &host_home, "conflict", &["--replace-generated"])?;
    let approved: Value = serde_json::from_slice(&approved.stdout)?;
    assert_ne!(approved["result"]["plan_digest"], digest);
    let human = run(quarters(&store).env("HOME", &host_home).args([
        "create",
        "human-conflict",
        "--from-host",
        "shell",
        "--replace-generated",
        "--preview",
    ]))?;
    let human = String::from_utf8(human.stdout)?;
    assert!(human.contains("File       .zshrc"));
    assert!(human.contains("append-managed-state-and-prompt-tail"));
    Ok(())
}

#[test]
fn nested_forks_and_unprotected_or_linked_anchors_fail_without_state() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let host_home = protected_home(&temporary)?;
    let store = temporary.path().join("store");

    let nested = quarters(&store)
        .env("HOME", &host_home)
        .env("QUARTERS_SPACE", "source")
        .args(["create", "nested", "--from-host", "shell", "--preview"])
        .output()?;
    assert!(!nested.status.success());
    assert!(String::from_utf8(nested.stderr)?.contains("unavailable inside a Quarter"));

    std::fs::set_permissions(&host_home, std::fs::Permissions::from_mode(0o720))?;
    let broad = quarters(&store)
        .env("HOME", &host_home)
        .args(["create", "broad", "--from-host", "shell", "--preview"])
        .output()?;
    assert!(!broad.status.success());
    std::fs::set_permissions(&host_home, std::fs::Permissions::from_mode(0o700))?;

    std::fs::create_dir(host_home.join("real-config"))?;
    std::fs::write(host_home.join("real-config/theme"), b"dark\n")?;
    symlink("real-config", host_home.join(".config"))?;
    let linked = quarters(&store)
        .env("HOME", &host_home)
        .args([
            "create",
            "linked-parent",
            "--from-host",
            "shell",
            "--from-host-path",
            ".config/theme",
            "--preview",
        ])
        .output()?;
    assert!(!linked.status.success());
    for name in ["nested", "broad", "linked-parent"] {
        assert!(!store.join("spaces").join(name).exists());
    }
    Ok(())
}

fn protected_home(temporary: &TempDir) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let home = temporary.path().join("host-home");
    std::fs::create_dir(&home)?;
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))?;
    Ok(home)
}

fn preview(store: &Path, home: &Path, name: &str, extra: &[&str]) -> Result<Output, Box<dyn Error>> {
    let mut command = quarters(store);
    command
        .env("HOME", home)
        .args(["--json", "create", name, "--shell", "/bin/sh", "--from-host", "shell"]);
    command.args(extra).arg("--preview");
    run(&mut command)
}
