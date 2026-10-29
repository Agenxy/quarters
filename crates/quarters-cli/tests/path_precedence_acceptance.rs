// SPDX-License-Identifier: GPL-3.0-or-later
//! Quarter-owned toolchain directories shadow host executables on PATH.

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
#[path = "support/test_store.rs"]
mod test_store;
use test_store::TestTemp as TempDir;

/// A host-context invocation, even when the test itself runs inside a Quarter.
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

fn install_probe(directory: &Path, name: &str, answer: &str) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(directory)?;
    let probe = directory.join(name);
    fs::write(&probe, format!("#!/bin/sh\necho {answer}\n"))?;
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn resolve(root: &Path, host_path: &str, name: &str) -> Result<String, Box<dyn Error>> {
    let output = run(quarters(root)
        .env("PATH", host_path)
        .args(["exec", "toolchain", "--", name]))?;
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

#[test]
fn quarter_toolchain_installs_shadow_host_copies_through_the_launcher() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("store");
    run(quarters(&root).args(["create", "toolchain"]))?;
    let home = root.join("spaces/toolchain/home");
    let host_bin = temporary.path().join("host-home/go/bin");
    let host_path = format!("{}:/usr/bin:/bin", host_bin.display());

    // `go install` inside a Quarter lands in its own go/bin and must win.
    install_probe(&host_bin, "probe-go", "host")?;
    install_probe(&home.join("go/bin"), "probe-go", "quarter")?;
    assert_eq!(resolve(&root, &host_path, "probe-go")?, "quarter");

    // A redirected CARGO_HOME and Bun's default root shadow the host too.
    install_probe(&host_bin, "probe-cargo", "host")?;
    install_probe(&home.join(".cargo/bin"), "probe-cargo", "quarter")?;
    assert_eq!(resolve(&root, &host_path, "probe-cargo")?, "quarter");
    install_probe(&host_bin, "probe-bun", "host")?;
    install_probe(&home.join(".bun/bin"), "probe-bun", "quarter")?;
    assert_eq!(resolve(&root, &host_path, "probe-bun")?, "quarter");

    // User installs come first among the Quarter's own directories.
    install_probe(&home.join("go/bin"), "probe-order", "go")?;
    install_probe(&home.join(".local/bin"), "probe-order", "local")?;
    assert_eq!(resolve(&root, &host_path, "probe-order")?, "local");

    // Host tools not installed in the Quarter stay reachable.
    install_probe(&host_bin, "probe-host-only", "host")?;
    assert_eq!(resolve(&root, &host_path, "probe-host-only")?, "host");
    Ok(())
}
