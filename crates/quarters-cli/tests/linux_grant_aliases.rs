//! Linux confinement rejects inode aliases and hidden mount ancestry.

#![cfg(target_os = "linux")]

use nix::mount::{MsFlags, mount};
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn quarters(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_quarters"));
    command.arg("--root").arg(root).env_remove("XDG_RUNTIME_DIR");
    command
}

fn setup(root: &Path) -> Result<bool, Box<dyn Error>> {
    let created = quarters(root).args(["create", "protected"]).output()?;
    assert!(created.status.success(), "{}", String::from_utf8_lossy(&created.stderr));
    let doctor = quarters(root).args(["--json", "doctor"]).output()?;
    assert!(doctor.status.success());
    let doctor: Value = serde_json::from_slice(&doctor.stdout)?;
    let available = doctor["result"]["platform"]["confinement"]["available"] == true;
    if !available && std::env::var_os("QUARTERS_REQUIRE_LANDLOCK").is_some_and(|value| !value.is_empty()) {
        return Err("required Landlock is unavailable for alias acceptance".into());
    }
    Ok(available)
}

fn reject(root: &Path, path: &Path, expected: &str) -> Result<(), Box<dyn Error>> {
    let grant = format!("{}:rw", path.display());
    let output = quarters(root)
        .args([
            "--json",
            "env",
            "protected",
            "--confinement",
            "filesystem",
            "--grant-path",
            &grant,
        ])
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(6),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let error: Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["kind"], "unsupported");
    assert!(
        error["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains(expected)),
        "{error}"
    );
    Ok(())
}

#[test]
fn hard_link_grants_cannot_alias_reserved_or_unrelated_files() -> Result<(), Box<dyn Error>> {
    let tree = tempfile::tempdir()?;
    let root = tree.path().join("store");
    if !setup(&root)? {
        return Ok(());
    }
    let manifest = root.join("spaces/protected/.quarters.json");
    let contents = fs::read(&manifest)?;
    let alias = tree.path().join("manifest-alias");
    fs::hard_link(&manifest, &alias)?;
    reject(&root, &alias, "single-link")?;
    let ordinary = tree.path().join("ordinary");
    let second = tree.path().join("ordinary-link");
    fs::write(&ordinary, b"ordinary")?;
    fs::hard_link(&ordinary, &second)?;
    reject(&root, &second, "single-link")?;
    assert_eq!(fs::read(&manifest)?, contents);
    Ok(())
}

#[test]
fn bind_mount_aliases_are_rejected_in_a_private_namespace() -> Result<(), Box<dyn Error>> {
    let tree = tempfile::tempdir()?;
    if !setup(&tree.path().join("store"))? {
        return Ok(());
    }
    let required = std::env::var_os("QUARTERS_REQUIRE_BIND_ALIASES").is_some_and(|value| !value.is_empty());
    // libtest is threaded, so namespace creation runs in the native unshare
    // utility before this test executable starts. Mounts cannot reach the host.
    let output = Command::new("/usr/bin/unshare")
        .args([
            "--user",
            "--map-current-user",
            "--mount",
            "--propagation",
            "private",
            "--",
        ])
        .arg(std::env::current_exe()?)
        .args([
            "--exact",
            "bind_mount_namespace_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("GRANT_ALIAS_FIXTURE", tree.path())
        .output();
    match output {
        Ok(output) if output.status.success() => {
            assert!(String::from_utf8_lossy(&output.stdout).contains("bind-aliases verified"));
        }
        Ok(output) if !required && namespace_unavailable(&output) => {
            eprintln!("bind aliases untested: host refuses private user/mount namespaces");
        }
        Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("bind aliases untested: /usr/bin/unshare is unavailable");
        }
        Ok(output) => {
            return Err(format!(
                "bind-alias acceptance failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )
            .into());
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn namespace_unavailable(output: &Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr.contains("unshare failed: Operation not permitted")
        || stderr.contains("unshare failed: Invalid argument")
        || stderr.contains("write failed /proc/self/uid_map: Operation not permitted")
}

#[test]
fn bind_mount_namespace_probe() -> Result<(), Box<dyn Error>> {
    let Some(fixture) = std::env::var_os("GRANT_ALIAS_FIXTURE") else {
        return Ok(());
    };
    let fixture = PathBuf::from(fixture);
    let root = fixture.join("store");
    let home = root.join("spaces/protected/home");
    let nested = home.join("private-child");
    fs::create_dir(&nested)?;
    fs::write(nested.join("secret"), b"protected")?;
    for (source, name, expected) in [
        (root.as_path(), "store-alias", "protected filesystem identity"),
        (Path::new("/usr"), "executable-alias", "built-in confinement root"),
        (nested.as_path(), "child-alias", "subtree mount"),
    ] {
        let target = fixture.join(name);
        fs::create_dir(&target)?;
        mount(Some(source), &target, None::<&str>, MsFlags::MS_BIND, None::<&str>)?;
        reject(&root, &target, expected)?;
    }
    let containing = fixture.join("workspace");
    fs::create_dir(&containing)?;
    let target = containing.join("nested-alias");
    fs::create_dir(&target)?;
    mount(Some(&nested), &target, None::<&str>, MsFlags::MS_BIND, None::<&str>)?;
    reject(&root, &containing, "subtree mount")?;
    println!("bind-aliases verified");
    Ok(())
}
