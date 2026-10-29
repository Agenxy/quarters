// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux launcher-path acceptance for privacy-bounded discovery.

#![cfg(target_os = "linux")]

use serde_json::Value;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn quarters(root: &Path, home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_quarters"));
    command
        .arg("--root")
        .arg(root)
        .env("HOME", home)
        .env_remove("XDG_RUNTIME_DIR");
    command
}

fn run(command: &mut Command) -> Result<Output, Box<dyn Error>> {
    let output = command.output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "command failed with {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into())
    }
}

fn capabilities(root: &Path, home: &Path) -> Result<Value, Box<dyn Error>> {
    let output = run(quarters(root, home).args(["--json", "doctor"]))?;
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn discover_with_launcher(
    root: &Path,
    home: &Path,
    name: &str,
    options: &[&str],
    report_path: &Path,
) -> Result<Value, Box<dyn Error>> {
    let report = OpenOptions::new().create_new(true).append(true).open(report_path)?;
    nix::fcntl::fcntl(&report, nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()))?;
    let descriptor = report.as_raw_fd();
    let script = format!(
        "printf smuggle >&{descriptor} 2>/dev/null || :; printf child > \"$HOME/child-state\"; printf child > \"$XDG_RUNTIME_DIR/bin/child-state\""
    );
    let mut command = quarters(root, home);
    command.arg("discover").arg(name).args(options);
    let output = command
        .args(["--report-fd", &descriptor.to_string(), "--", "/bin/sh", "-c", &script])
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    drop(report);
    let bytes = fs::read(report_path)?;
    assert!(!bytes.starts_with(b"smuggle"));
    Ok(serde_json::from_slice(&bytes)?)
}

#[test]
fn discovery_crosses_confinement_and_home_view_launchers_without_leaking_report_fd() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("store");
    let home = temporary.path().join("host-home");
    fs::create_dir(&home)?;
    for name in ["confined", "home-view"] {
        run(quarters(&root, &home).args(["create", name]))?;
    }
    let capabilities = capabilities(&root, &home)?;
    let cases = [
        (
            "confined",
            capabilities["result"]["platform"]["confinement"]["available"] == true,
            vec!["--confinement", "filesystem"],
        ),
        (
            "home-view",
            capabilities["result"]["platform"]["home_view"]["available"] == true,
            vec!["--home-view"],
        ),
    ];
    for (name, available, options) in cases {
        if available {
            let report = discover_with_launcher(
                &root,
                &home,
                name,
                &options,
                &temporary.path().join(format!("{name}.json")),
            )?;
            assert_eq!(report["result"]["complete"], true);
            assert_eq!(report["result"]["child"]["exit_code"], 0);
            assert!(
                report["result"]["delta"]["created"]["runtime"]
                    .as_u64()
                    .is_some_and(|count| count >= 1)
            );
            assert_eq!(report["result"]["delta"]["created"]["data"], 1);
        } else {
            let required = (name == "confined" && std::env::var_os("QUARTERS_REQUIRE_LANDLOCK").is_some())
                || (name == "home-view" && std::env::var_os("QUARTERS_REQUIRE_HOME_VIEW").is_some());
            if required {
                return Err(format!("hosted Linux requires discovery through the {name} launcher").into());
            }
        }
        run(quarters(&root, &home).args(["rm", name, "--confirm", name]))?;
    }
    Ok(())
}
