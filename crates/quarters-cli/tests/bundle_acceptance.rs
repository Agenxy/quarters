//! End-to-end authenticated export and import acceptance.

use serde_json::Value;
use std::error::Error;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
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

fn fixture() -> Result<(TempDir, PathBuf, PathBuf, PathBuf), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
    let store = temporary.path().join("store");
    let key = temporary.path().join("bundle.key");
    let bundle = temporary.path().join("portable.qbundle");
    run(quarters(&store).args(["create", "source", "--shell", "/bin/sh"]))?;
    let home = store.join("spaces/source/home");
    fs::write(home.join("state.txt"), b"portable-state")?;
    fs::create_dir_all(home.join(".ssh-backup"))?;
    fs::write(home.join(".ssh-backup/note"), b"ordering")?;
    fs::create_dir_all(home.join(".ssh"))?;
    fs::write(home.join(".ssh/config"), b"Host example\n")?;
    fs::create_dir_all(home.join("dotfiles"))?;
    fs::write(home.join("dotfiles/config"), b"linked-state")?;
    symlink("../dotfiles", home.join(".config/dotfiles"))?;
    symlink("state.txt", home.join("state-link"))?;
    run(quarters(&store).args([
        "template",
        "create",
        "portable",
        "--from",
        "source",
        "--confirm-sensitive-state",
        "source",
    ]))?;
    run(Command::new(env!("CARGO_BIN_EXE_quarters"))
        .args(["export-key", "create"])
        .arg(&key))?;
    Ok((temporary, store, key, bundle))
}

fn export_bundle(store: &Path, key: &Path, bundle: &Path) -> Result<Value, Box<dyn Error>> {
    let output = run(quarters(store)
        .args(["--json", "export", "template", "portable", "--to"])
        .arg(bundle)
        .arg("--key")
        .arg(key)
        .args(["--confirm-sensitive-state", "portable"]))?;
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn import_preview(store: &Path, key: &Path, bundle: &Path, name: &str) -> Result<Value, Box<dyn Error>> {
    let output = run(quarters(store)
        .args(["--json", "import"])
        .arg(bundle)
        .arg(name)
        .arg("--key")
        .arg(key)
        .arg("--preview"))?;
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[test]
fn authenticated_round_trip_creates_external_template() -> Result<(), Box<dyn Error>> {
    let (_temporary, store, key, bundle) = fixture()?;
    let exported = export_bundle(&store, &key, &bundle)?;
    assert_eq!(exported["result"]["mode"], "execute");
    assert_eq!(exported["result"]["includes_sensitive_state"], true);
    let preview = import_preview(&store, &key, &bundle, "restored")?;
    let digest = preview["result"]["plan_digest"].as_str().ok_or("missing import plan")?;
    assert_eq!(digest.len(), 64);
    assert_eq!(preview["result"]["source_name"], "portable");
    assert!(preview["result"]["content_safety"].as_str().is_some());

    let imported = run(quarters(&store)
        .args(["--json", "import"])
        .arg(&bundle)
        .arg("restored")
        .arg("--key")
        .arg(&key)
        .arg("--confirm-plan")
        .arg(digest))?;
    let imported: Value = serde_json::from_slice(&imported.stdout)?;
    assert_eq!(imported["result"]["mode"], "execute");
    assert!(imported["result"]["artifact_id"].as_str().is_some());
    let shown = run(quarters(&store).args(["--json", "template", "show", "restored"]))?;
    let shown: Value = serde_json::from_slice(&shown.stdout)?;
    assert_eq!(shown["result"]["source_status"], "external");
    assert_eq!(shown["result"]["manifest"]["schema_version"], 2);
    assert!(shown["result"]["manifest"]["source_identity"].is_null());
    assert_eq!(
        shown["result"]["manifest"]["content_integrity"],
        exported["result"]["content_integrity"]
    );

    run(quarters(&store).args([
        "template",
        "use",
        "restored",
        "copy",
        "--confirm-sensitive-state",
        "restored",
    ]))?;
    assert_eq!(fs::read(store.join("spaces/copy/home/state.txt"))?, b"portable-state");
    assert_eq!(
        fs::read_link(store.join("spaces/copy/home/state-link"))?,
        Path::new("state.txt")
    );
    assert_eq!(
        fs::read_link(store.join("spaces/copy/home/.config/dotfiles"))?,
        Path::new("../dotfiles")
    );
    Ok(())
}

#[test]
fn wrong_key_tampering_and_stale_plan_publish_nothing() -> Result<(), Box<dyn Error>> {
    let (temporary, store, key, bundle) = fixture()?;
    export_bundle(&store, &key, &bundle)?;
    let wrong_key = temporary.path().join("wrong.key");
    run(Command::new(env!("CARGO_BIN_EXE_quarters"))
        .args(["export-key", "create"])
        .arg(&wrong_key))?;
    let wrong = quarters(&store)
        .args(["import"])
        .arg(&bundle)
        .arg("wrong")
        .arg("--key")
        .arg(&wrong_key)
        .arg("--preview")
        .output()?;
    assert_eq!(wrong.status.code(), Some(7));
    assert!(!store.join(".templates").join("wrong").exists());

    let preview = import_preview(&store, &key, &bundle, "stale")?;
    let digest = preview["result"]["plan_digest"].as_str().ok_or("missing digest")?;
    let mut bytes = fs::read(&bundle)?;
    let index = bytes.len().checked_sub(40).ok_or("bundle too short")?;
    bytes[index] ^= 0x01;
    fs::write(&bundle, &bytes)?;
    fs::set_permissions(&bundle, fs::Permissions::from_mode(0o600))?;
    let stale = quarters(&store)
        .args(["import"])
        .arg(&bundle)
        .arg("stale")
        .arg("--key")
        .arg(&key)
        .arg("--confirm-plan")
        .arg(digest)
        .output()?;
    assert_eq!(stale.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&stale.stderr).contains("authentication failed"));
    assert!(!store.join(".templates").join("stale").exists());
    Ok(())
}

#[test]
fn key_and_destination_policies_fail_closed_without_disclosure() -> Result<(), Box<dyn Error>> {
    let (temporary, store, key, bundle) = fixture()?;
    let repeated = Command::new(env!("CARGO_BIN_EXE_quarters"))
        .args(["export-key", "create"])
        .arg(&key)
        .output()?;
    assert_eq!(repeated.status.code(), Some(4));
    assert!(!String::from_utf8_lossy(&repeated.stderr).contains(key.to_string_lossy().as_ref()));

    let linked = temporary.path().join("linked.key");
    symlink(&key, &linked)?;
    let linked_output = quarters(&store)
        .args(["export", "template", "portable", "--to"])
        .arg(&bundle)
        .arg("--key")
        .arg(&linked)
        .arg("--preview")
        .output()?;
    assert!(!linked_output.status.success());
    assert!(!String::from_utf8_lossy(&linked_output.stderr).contains(linked.to_string_lossy().as_ref()));

    let inside_store = store.join("forbidden.qbundle");
    let refused = quarters(&store)
        .args(["export", "template", "portable", "--to"])
        .arg(&inside_store)
        .arg("--key")
        .arg(&key)
        .arg("--preview")
        .output()?;
    assert_eq!(refused.status.code(), Some(2));
    assert!(!inside_store.exists());
    Ok(())
}

#[test]
fn bundle_is_never_overwritten_and_preview_is_non_mutating() -> Result<(), Box<dyn Error>> {
    let (_temporary, store, key, bundle) = fixture()?;
    let preview = run(quarters(&store)
        .args(["--json", "export", "template", "portable", "--to"])
        .arg(&bundle)
        .arg("--key")
        .arg(&key)
        .arg("--preview"))?;
    let preview: Value = serde_json::from_slice(&preview.stdout)?;
    assert_eq!(preview["result"]["mode"], "preview");
    assert!(!bundle.exists());
    export_bundle(&store, &key, &bundle)?;
    let before = fs::read(&bundle)?;
    let repeated = quarters(&store)
        .args(["export", "template", "portable", "--to"])
        .arg(&bundle)
        .arg("--key")
        .arg(&key)
        .args(["--confirm-sensitive-state", "portable"])
        .output()?;
    assert_eq!(repeated.status.code(), Some(4));
    assert_eq!(fs::read(&bundle)?, before);
    Ok(())
}

#[test]
fn truncated_and_trailing_bundles_are_rejected() -> Result<(), Box<dyn Error>> {
    let (temporary, store, key, bundle) = fixture()?;
    export_bundle(&store, &key, &bundle)?;
    let original = fs::read(&bundle)?;
    let truncated = temporary.path().join("truncated.qbundle");
    fs::write(&truncated, &original[..original.len() - 1])?;
    fs::set_permissions(&truncated, fs::Permissions::from_mode(0o600))?;
    let truncated_result = quarters(&store)
        .args(["import"])
        .arg(&truncated)
        .arg("truncated")
        .arg("--key")
        .arg(&key)
        .arg("--preview")
        .output()?;
    assert!(!truncated_result.status.success());

    let trailing = temporary.path().join("trailing.qbundle");
    let mut trailing_bytes = original;
    trailing_bytes.extend_from_slice(b"trailing");
    fs::write(&trailing, trailing_bytes)?;
    fs::set_permissions(&trailing, fs::Permissions::from_mode(0o600))?;
    let trailing_result = quarters(&store)
        .args(["import"])
        .arg(&trailing)
        .arg("trailing")
        .arg("--key")
        .arg(&key)
        .arg("--preview")
        .output()?;
    assert!(!trailing_result.status.success());
    assert!(!store.join(".templates").join("truncated").exists());
    assert!(!store.join(".templates").join("trailing").exists());
    Ok(())
}

#[test]
fn export_key_contract_rejects_bad_mode_length_and_links() -> Result<(), Box<dyn Error>> {
    let (temporary, store, key, bundle) = fixture()?;
    fs::set_permissions(&key, fs::Permissions::from_mode(0o640))?;
    assert!(!export_preview(&store, &key, &bundle)?.status.success());

    let short = temporary.path().join("short.key");
    fs::write(&short, [0_u8; 31])?;
    fs::set_permissions(&short, fs::Permissions::from_mode(0o600))?;
    assert!(!export_preview(&store, &short, &bundle)?.status.success());

    let linked_source = temporary.path().join("linked-source.key");
    fs::write(&linked_source, [0_u8; 32])?;
    fs::set_permissions(&linked_source, fs::Permissions::from_mode(0o600))?;
    let hard_link = temporary.path().join("hard-link.key");
    fs::hard_link(&linked_source, &hard_link)?;
    assert!(!export_preview(&store, &linked_source, &bundle)?.status.success());
    Ok(())
}

#[test]
fn keys_inside_the_active_store_are_never_created_or_consumed() -> Result<(), Box<dyn Error>> {
    let (temporary, store, key, bundle) = fixture()?;
    let prospective_parent = temporary.path().join("prospective-store");
    fs::create_dir(&prospective_parent)?;
    fs::set_permissions(&prospective_parent, fs::Permissions::from_mode(0o700))?;
    let prospective_root = temporary.path().join("missing").join("..").join("prospective-store");
    let prospective_key = prospective_parent.join("prospective.key");
    let prospective = Command::new(env!("CARGO_BIN_EXE_quarters"))
        .args(["--root"])
        .arg(&prospective_root)
        .args(["export-key", "create"])
        .arg(&prospective_key)
        .output()?;
    assert_eq!(prospective.status.code(), Some(2));
    assert!(!prospective_key.exists());

    let inside = store.join("spaces/source/home/bundle.key");
    let creation = Command::new(env!("CARGO_BIN_EXE_quarters"))
        .args(["--root"])
        .arg(&store)
        .args(["export-key", "create"])
        .arg(&inside)
        .output()?;
    assert_eq!(creation.status.code(), Some(2));
    assert!(!inside.exists());

    export_bundle(&store, &key, &bundle)?;
    let moved = store.join("spaces/source/home/moved.key");
    fs::rename(&key, &moved)?;
    assert!(
        !export_preview(&store, &moved, &temporary.path().join("second.qbundle"))?
            .status
            .success()
    );
    let import = quarters(&store)
        .args(["import"])
        .arg(&bundle)
        .arg("forbidden-key")
        .arg("--key")
        .arg(&moved)
        .arg("--preview")
        .output()?;
    assert_eq!(import.status.code(), Some(2));
    let absent = quarters(&store).args(["template", "show", "forbidden-key"]).output()?;
    assert!(!absent.status.success());
    Ok(())
}

#[test]
fn deepest_legal_leaf_round_trips_through_a_bundle() -> Result<(), Box<dyn Error>> {
    let (_temporary, store, key, bundle) = fixture()?;
    run(quarters(&store).args(["create", "deep", "--shell", "/bin/sh"]))?;
    let mut directory = store.join("spaces/deep/home");
    for _index in 0..64 {
        directory.push("d");
    }
    fs::create_dir_all(&directory)?;
    fs::write(directory.join("leaf"), b"deep-state")?;
    symlink("leaf", directory.join("leaf-link"))?;
    run(quarters(&store).args([
        "template",
        "create",
        "deep-template",
        "--from",
        "deep",
        "--confirm-sensitive-state",
        "deep",
    ]))?;
    run(quarters(&store)
        .args(["export", "template", "deep-template", "--to"])
        .arg(&bundle)
        .arg("--key")
        .arg(&key)
        .args(["--confirm-sensitive-state", "deep-template"]))?;
    let preview = import_preview(&store, &key, &bundle, "deep-import")?;
    let digest = preview["result"]["plan_digest"].as_str().ok_or("missing digest")?;
    run(quarters(&store)
        .args(["import"])
        .arg(&bundle)
        .arg("deep-import")
        .arg("--key")
        .arg(&key)
        .arg("--confirm-plan")
        .arg(digest))?;
    run(quarters(&store).args([
        "template",
        "use",
        "deep-import",
        "deep-copy",
        "--confirm-sensitive-state",
        "deep-import",
    ]))?;
    let mut copied = store.join("spaces/deep-copy/home");
    for _index in 0..64 {
        copied.push("d");
    }
    assert_eq!(fs::read(copied.join("leaf"))?, b"deep-state");
    assert_eq!(fs::read_link(copied.join("leaf-link"))?, Path::new("leaf"));
    Ok(())
}

#[test]
fn snapshots_import_only_as_external_templates() -> Result<(), Box<dyn Error>> {
    let (_temporary, store, key, bundle) = fixture()?;
    run(quarters(&store).args([
        "snapshot",
        "create",
        "source",
        "checkpoint",
        "--confirm-sensitive-state",
        "source",
    ]))?;
    run(quarters(&store)
        .args(["export", "snapshot", "checkpoint", "--to"])
        .arg(&bundle)
        .arg("--key")
        .arg(&key)
        .args(["--confirm-sensitive-state", "checkpoint"]))?;
    let preview = import_preview(&store, &key, &bundle, "from-snapshot")?;
    assert_eq!(preview["result"]["source_kind"], "snapshot");
    let digest = preview["result"]["plan_digest"].as_str().ok_or("missing digest")?;
    run(quarters(&store)
        .args(["import"])
        .arg(&bundle)
        .arg("from-snapshot")
        .arg("--key")
        .arg(&key)
        .arg("--confirm-plan")
        .arg(digest))?;
    let shown = run(quarters(&store).args(["--json", "template", "show", "from-snapshot"]))?;
    let shown: Value = serde_json::from_slice(&shown.stdout)?;
    assert_eq!(shown["result"]["source_status"], "external");
    assert_eq!(
        shown["result"]["manifest"]["imported_bundle"]["source_artifact_kind"],
        "snapshot"
    );
    Ok(())
}

fn export_preview(store: &Path, key: &Path, bundle: &Path) -> Result<Output, Box<dyn Error>> {
    Ok(quarters(store)
        .args(["export", "template", "portable", "--to"])
        .arg(bundle)
        .arg("--key")
        .arg(key)
        .arg("--preview")
        .output()?)
}
