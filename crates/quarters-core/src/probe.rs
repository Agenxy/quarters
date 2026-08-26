//! Local compatibility inventory.

use serde::Serialize;
use std::collections::BTreeSet;
use std::env;
use std::path::{Path, PathBuf};

/// Compatibility class for user-owned state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum CompatibilityTier {
    /// The tool follows HOME or XDG paths without extra configuration.
    A,
    /// A documented environment or config-path override is applied.
    B,
    /// The tool needs an explicit invocation adapter.
    C,
    /// State remains tied to the host account or service.
    D,
}

/// One installed-tool compatibility assessment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ToolProbe {
    /// Display and executable name.
    pub tool: String,
    /// Whether an executable was found on this host.
    pub installed: bool,
    /// Compatibility class.
    pub tier: CompatibilityTier,
    /// Mechanism Quarters configures.
    pub mechanism: String,
    /// Known limitation that remains after configuration.
    pub limitation: Option<String>,
}

/// Inspect representative tools without executing them or reading credentials.
#[must_use]
pub fn tool_probes() -> Vec<ToolProbe> {
    vec![
        probe("zsh", CompatibilityTier::A, "HOME, ZDOTDIR and HISTFILE", None),
        probe("bash", CompatibilityTier::A, "HOME and per-space startup files", None),
        probe(
            "git",
            CompatibilityTier::B,
            "GIT_CONFIG_GLOBAL with host helpers cleared",
            None,
        ),
        probe(
            "ssh",
            CompatibilityTier::C,
            "verified managed ssh/scp/sftp links select the per-space configuration",
            Some(
                "doctor NAME reports actual link state; passwd home is unchanged; absolute host-tool paths bypass adapters",
            ),
        ),
        probe("gh", CompatibilityTier::B, "GH_CONFIG_DIR", None),
        probe(
            "tmux",
            CompatibilityTier::B,
            "TMUX_TMPDIR",
            Some("existing host tmux clients remain host-bound"),
        ),
        probe(
            "gpg",
            CompatibilityTier::B,
            "GNUPGHOME and short XDG runtime path",
            None,
        ),
        probe(
            "python3",
            CompatibilityTier::A,
            "HOME and XDG paths",
            Some("system and site packages remain shared"),
        ),
        probe(
            "uv",
            CompatibilityTier::B,
            "UV cache, Python and tool directories",
            None,
        ),
        probe(
            "cargo",
            CompatibilityTier::B,
            "CARGO_HOME",
            Some("system or rustup toolchains may remain shared"),
        ),
        probe("npm", CompatibilityTier::B, "npm user config and cache variables", None),
        probe(
            "codex",
            CompatibilityTier::B,
            "CODEX_HOME",
            Some("OS keychain and login session remain host-bound"),
        ),
        probe(
            "claude",
            CompatibilityTier::B,
            "CLAUDE_CONFIG_DIR",
            Some("OS keychain and login session remain host-bound"),
        ),
        probe("opencode", CompatibilityTier::B, "XDG and OPENCODE_CONFIG_DIR", None),
        probe(
            "sudo",
            CompatibilityTier::D,
            "host account authority",
            Some("sudo escapes the profile; Linux home view disables sudo"),
        ),
    ]
}

fn probe(tool: &str, tier: CompatibilityTier, mechanism: &str, limitation: Option<&str>) -> ToolProbe {
    let executable = find_executable(tool);
    ToolProbe {
        tool: tool.to_owned(),
        installed: executable.is_some(),
        tier,
        mechanism: mechanism.to_owned(),
        limitation: limitation.map(str::to_owned),
    }
}

fn find_executable(name: &str) -> Option<PathBuf> {
    executable_matches(name).into_iter().next()
}

/// Return every executable command match on `PATH` in shell resolution order.
#[must_use]
pub fn executable_matches(name: &str) -> Vec<PathBuf> {
    let Some(path) = env::var_os("PATH") else {
        return Vec::new();
    };
    let current = env::current_dir().ok();
    let mut seen = BTreeSet::new();
    env::split_paths(&path)
        .filter_map(|directory| absolute_directory(directory, current.as_deref()))
        .map(|directory| directory.join(name))
        .filter(|candidate| is_executable(candidate))
        .filter(|candidate| seen.insert(candidate.clone()))
        .collect()
}

fn absolute_directory(directory: PathBuf, current: Option<&Path>) -> Option<PathBuf> {
    if directory.is_absolute() {
        return Some(directory);
    }
    current.map(|current| current.join(directory))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}
