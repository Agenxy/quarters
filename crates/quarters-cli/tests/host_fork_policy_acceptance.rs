//! Adversarial policy and resource-bound acceptance for host-state forks.

use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use serde_json::Value;
use std::error::Error;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const MIB: u64 = 1_048_576;

fn quarters(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_quarters"));
    command.arg("--root").arg(root);
    command
}

#[test]
fn unsafe_file_kinds_links_and_modes_are_refused() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let home = protected_home(&temporary)?;
    let store = temporary.path().join("store");

    std::fs::write(home.join("linked-source"), b"state\n")?;
    std::fs::hard_link(home.join("linked-source"), home.join("linked-alias"))?;
    assert_failed_preview(&store, &home, "hard-link", &["linked-alias"])?;

    std::fs::write(home.join("broad"), b"state\n")?;
    std::fs::set_permissions(home.join("broad"), std::fs::Permissions::from_mode(0o620))?;
    assert_failed_preview(&store, &home, "broad-file", &["broad"])?;

    mkfifo(&home.join("pipe"), Mode::from_bits_truncate(0o600))?;
    assert_failed_preview(&store, &home, "fifo", &["pipe"])?;

    for name in ["hard-link", "broad-file", "fifo"] {
        assert!(!store.join("spaces").join(name).exists());
    }
    Ok(())
}

#[test]
fn path_count_and_byte_limits_fail_before_publication() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let home = protected_home(&temporary)?;
    let store = temporary.path().join("store");

    assert_failed_preview(&store, &home, "parent", &["../outside"])?;
    assert_failed_preview(&store, &home, "absolute", &["/tmp/outside"])?;

    let mut too_many = quarters(&store);
    too_many
        .env("HOME", &home)
        .args(["create", "too-many", "--from-host", "shell"]);
    for index in 0..33 {
        let path = format!("file-{index}");
        std::fs::write(home.join(&path), b"x")?;
        too_many.arg("--from-host-path").arg(path);
    }
    assert!(!too_many.arg("--preview").output()?.status.success());

    let oversized = home.join("oversized");
    File::create(&oversized)?.set_len(MIB + 1)?;
    assert_failed_preview(&store, &home, "oversized", &["oversized"])?;

    let total_paths = (0..9).map(|index| format!("large-{index}")).collect::<Vec<_>>();
    for path in &total_paths {
        File::create(home.join(path))?.set_len(MIB)?;
    }
    let total_refs = total_paths.iter().map(String::as_str).collect::<Vec<_>>();
    assert_failed_preview(&store, &home, "too-large", &total_refs)?;

    for name in ["parent", "absolute", "too-many", "oversized", "too-large"] {
        assert!(!store.join("spaces").join(name).exists());
    }
    Ok(())
}

#[test]
fn a_home_inside_the_store_is_never_a_source_anchor() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let store = temporary.path().join("store");
    std::fs::create_dir(&store)?;
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700))?;
    let home = store.join("host-home");
    std::fs::create_dir(&home)?;
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))?;

    let output = quarters(&store)
        .env("HOME", &home)
        .args(["create", "inside", "--from-host", "shell", "--preview"])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("inside the Quarters store"));
    assert!(!store.join("spaces/inside").exists());
    Ok(())
}

#[test]
fn a_source_change_after_staging_leaves_no_destination_or_staging() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let home = protected_home(&temporary)?;
    let store = temporary.path().join("store");
    let padding = (0..7).map(|index| format!("aa-padding-{index}")).collect::<Vec<_>>();
    for path in &padding {
        File::create(home.join(path))?.set_len(MIB)?;
    }
    let source = home.join("zz-large");
    File::create(&source)?.set_len(MIB)?;
    let mut selected = padding.iter().map(String::as_str).collect::<Vec<_>>();
    selected.push("zz-large");
    let preview = preview(&store, &home, "raced", &selected)?;
    let preview: Value = serde_json::from_slice(&preview.stdout)?;
    let digest = preview["result"]["plan_digest"].as_str().ok_or("missing digest")?;

    let mut child = quarters(&store);
    child.env("HOME", &home).args([
        "create",
        "raced",
        "--shell",
        "/bin/sh",
        "--from-host",
        "shell",
        "--from-host-path",
        "zz-large",
        "--confirm-plan",
        digest,
    ]);
    for path in &padding {
        child.arg("--from-host-path").arg(path);
    }
    let mut child = child.spawn()?;
    wait_for_staging(&store)?;
    let file = OpenOptions::new().write(true).open(&source)?;
    file.set_len(12)?;
    file.sync_all()?;

    assert!(!child.wait()?.success());
    assert!(!store.join("spaces/raced").exists());
    assert_no_staging(&store)?;
    Ok(())
}

fn protected_home(temporary: &TempDir) -> Result<PathBuf, Box<dyn Error>> {
    let home = temporary.path().join("host-home");
    std::fs::create_dir(&home)?;
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))?;
    Ok(home)
}

fn assert_failed_preview(store: &Path, home: &Path, name: &str, paths: &[&str]) -> Result<(), Box<dyn Error>> {
    assert!(!preview_command(store, home, name, paths).output()?.status.success());
    Ok(())
}

fn preview(store: &Path, home: &Path, name: &str, paths: &[&str]) -> Result<Output, Box<dyn Error>> {
    let output = preview_command(store, home, name, paths).arg("--json").output()?;
    if output.status.success() {
        return Ok(output);
    }
    Err(String::from_utf8_lossy(&output.stderr).into_owned().into())
}

fn preview_command(store: &Path, home: &Path, name: &str, paths: &[&str]) -> Command {
    let mut command = quarters(store);
    command
        .env("HOME", home)
        .args(["create", name, "--shell", "/bin/sh", "--from-host", "shell"]);
    for path in paths {
        command.args([OsString::from("--from-host-path"), OsString::from(path)]);
    }
    command.arg("--preview");
    command
}

fn wait_for_staging(store: &Path) -> Result<(), Box<dyn Error>> {
    let spaces = store.join("spaces");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if std::fs::read_dir(&spaces)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().starts_with(".creating-raced-"))
        {
            return Ok(());
        }
        std::thread::yield_now();
    }
    Err("host-fork staging did not appear before timeout".into())
}

fn assert_no_staging(store: &Path) -> Result<(), Box<dyn Error>> {
    let entries = std::fs::read_dir(store.join("spaces"))?;
    assert!(
        entries
            .filter_map(Result::ok)
            .all(|entry| { !entry.file_name().to_string_lossy().starts_with(".creating-raced-") })
    );
    Ok(())
}
