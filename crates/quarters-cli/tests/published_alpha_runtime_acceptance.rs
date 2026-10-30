// SPDX-License-Identifier: GPL-3.0-or-later
//! Runtime directories left by the published alpha.1 and alpha.2 releases.

use serde_json::Value;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

/// The 32-bit runtime fingerprint of the published alpha.1 and alpha.2 releases.
fn published_alpha_runtime_fingerprint(path: &Path) -> u32 {
    let mut hash = 2_166_136_261_u32;
    for byte in path.as_os_str().as_encoded_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

fn quarters(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_quarters"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("QUARTERS_") {
            command.env_remove(name);
        }
    }
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

/// Create a space whose runtime carries the name a published alpha gave it.
fn space_with_published_runtime(root: &Path, name: &str) -> Result<PathBuf, Box<dyn Error>> {
    run(quarters(root).args(["create", name]))?;
    let environment = run(quarters(root).args(["--json", "env", name]))?;
    let environment: Value = serde_json::from_slice(&environment.stdout)?;
    let stable = PathBuf::from(
        environment["result"]["environment"]["XDG_RUNTIME_DIR"]
            .as_str()
            .ok_or("missing runtime")?,
    );
    let fingerprint = published_alpha_runtime_fingerprint(&root.join("spaces").join(name));
    let published = stable
        .parent()
        .ok_or("runtime has no parent")?
        .join(format!("{name}-{fingerprint:08x}"));
    std::fs::rename(&stable, &published)?;
    std::fs::write(published.join("tmp/runtime-proof"), b"runtime-state")?;
    Ok(published)
}

#[test]
fn removal_deletes_a_runtime_named_by_a_published_alpha() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let published = space_with_published_runtime(temporary.path(), "sig")?;

    run(quarters(temporary.path()).args(["rm", "sig", "--confirm", "sig"]))?;

    assert!(!published.exists(), "{} survived removal", published.display());
    Ok(())
}

#[test]
fn launch_rekeys_a_runtime_named_by_a_published_alpha() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let published = space_with_published_runtime(temporary.path(), "upgraded")?;

    let proof = run(quarters(temporary.path()).args([
        "exec",
        "upgraded",
        "--",
        "/bin/sh",
        "-c",
        "cat \"$XDG_RUNTIME_DIR/tmp/runtime-proof\"",
    ]))?;

    assert_eq!(proof.stdout, b"runtime-state");
    assert!(!published.exists());
    run(quarters(temporary.path()).args(["rm", "upgraded", "--confirm", "upgraded"]))?;
    Ok(())
}
