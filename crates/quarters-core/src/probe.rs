//! Local compatibility inventory.

use serde::Serialize;
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
    /// Resolved executable path when installed.
    pub executable: Option<PathBuf>,
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
            "explicit ssh -F <space>/home/.ssh/config",
            Some("passwd home is unchanged"),
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
        executable,
        tier,
        mechanism: mechanism.to_owned(),
        limitation: limitation.map(str::to_owned),
    }
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}
