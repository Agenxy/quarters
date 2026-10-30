// SPDX-License-Identifier: GPL-3.0-or-later
//! Temporary test directories that remove their Quarters spaces on drop.

use serde_json::Value;
use std::fs;
use std::ops::Deref;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// A `TempDir` whose drop removes every space in each store beneath it with
/// `quarters rm`, then fails the test if a space or its private runtime
/// directory survived. Without it, each test space leaves a runtime
/// directory in the shared per-user runtime root.
pub(crate) struct TestTemp {
    directory: TempDir,
}

impl TestTemp {
    pub(crate) fn new() -> std::io::Result<Self> {
        TempDir::new().map(|directory| Self { directory })
    }
}

impl Deref for TestTemp {
    type Target = TempDir;

    fn deref(&self) -> &TempDir {
        &self.directory
    }
}

impl Drop for TestTemp {
    fn drop(&mut self) {
        let leaks = remove_spaces(self.directory.path());
        assert!(
            leaks.is_empty() || std::thread::panicking(),
            "test teardown leaked Quarters state:\n{}",
            leaks.join("\n")
        );
    }
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

/// Store roots are the directories holding a `spaces` directory.
fn store_roots(directory: &Path, depth: usize, roots: &mut Vec<PathBuf>) {
    if directory.join("spaces").is_dir() {
        roots.push(directory.to_path_buf());
        return;
    }
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let is_directory = entry.file_type().is_ok_and(|kind| kind.is_dir());
        if depth > 0 && is_directory {
            store_roots(&entry.path(), depth - 1, roots);
        }
    }
}

/// Every space's display name and stable id, read from its manifest so an
/// intentionally ambiguous store still reports what it holds.
fn manifested_spaces(root: &Path) -> Vec<(String, String)> {
    let Ok(entries) = fs::read_dir(root.join("spaces")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let manifest: Value = serde_json::from_slice(&fs::read(entry.path().join(".quarters.json")).ok()?).ok()?;
            Some((
                manifest["name"].as_str()?.to_owned(),
                manifest["space_id"].as_str()?.to_owned(),
            ))
        })
        .collect()
}

/// Run one teardown step, keeping its refusal as context for a leak.
fn attempt(root: &Path, arguments: &[&str]) -> Option<String> {
    match quarters(root).args(arguments).output() {
        Ok(output) if output.status.success() => None,
        Ok(output) => Some(format!(
            "quarters {}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        Err(error) => Some(format!("quarters {} failed to run: {error}", arguments.join(" "))),
    }
}

fn runtime_bases(owner: u32) -> Vec<PathBuf> {
    let mut bases = vec![PathBuf::from("/tmp")];
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        bases.push(PathBuf::from(runtime));
    }
    bases
        .into_iter()
        .map(|base| base.join(format!("quarters-{owner}")))
        .collect()
}

/// Remove each space through the product's own cleanup path, then report
/// only state that would outlive the temporary directory.
fn remove_spaces(directory: &Path) -> Vec<String> {
    let mut roots = Vec::new();
    store_roots(directory, 3, &mut roots);
    let owner = fs::metadata(directory).map_or(u32::MAX, |metadata| metadata.uid());
    let mut leaks = Vec::new();
    for root in roots {
        for (name, id) in manifested_spaces(&root) {
            let _stopped = attempt(&root, &["agent", "stop", &name]);
            // A failed agent record is cleared only by confirmed recovery.
            let _recovered = attempt(&root, &["agent", "recover", &name, "--confirm", &name]);
            let _thawed = attempt(&root, &["unfreeze", &name, "--confirm", &name]);
            let refusal = attempt(&root, &["rm", &name, "--confirm", &name]);
            for runtime in runtime_bases(owner).iter().map(|base| base.join(&id)) {
                if runtime.exists() {
                    let reason = refusal.as_deref().unwrap_or("quarters rm succeeded");
                    leaks.push(format!(
                        "{name}: runtime directory {} survived ({reason})",
                        runtime.display()
                    ));
                }
            }
        }
    }
    leaks
}
