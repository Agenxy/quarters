//! Stops private agents a test started, even when the test fails.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Runs `quarters agent stop` for each name when dropped, so a failing or
/// panicking test cannot leave an `ssh-agent` running after its store is gone.
/// Declare it after the test's temporary directory so it drops first.
pub(crate) struct AgentGuard {
    root: PathBuf,
    names: Vec<String>,
}

impl AgentGuard {
    /// Guard the agents of `names`; list every name the space may hold.
    pub(crate) fn new(root: &Path, names: &[&str]) -> Self {
        Self {
            root: root.to_path_buf(),
            names: names.iter().map(|name| (*name).to_owned()).collect(),
        }
    }
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        for name in &self.names {
            // Best effort: a stopped or renamed space simply reports an error.
            let _stopped = Command::new(env!("CARGO_BIN_EXE_quarters"))
                .arg("--root")
                .arg(&self.root)
                .args(["agent", "stop", name])
                .output();
        }
    }
}
