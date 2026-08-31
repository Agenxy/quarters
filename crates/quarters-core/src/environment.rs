//! Deterministic child environment policy.

use crate::platform;
use crate::{ErrorKind, QuartersError, Result, Space};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

const REDIRECTED_VARIABLES: &[&str] = &[
    "CARGO_HOME",
    "CFFIXED_USER_HOME",
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "GH_CONFIG_DIR",
    "GIT_CONFIG_GLOBAL",
    "GNUPGHOME",
    "HISTFILE",
    "NPM_CONFIG_CACHE",
    "NPM_CONFIG_USERCONFIG",
    "OPENCODE_CONFIG_DIR",
    "SSH_AUTH_SOCK",
    "TMPDIR",
    "TMUX_TMPDIR",
    "UV_CACHE_DIR",
    "UV_PYTHON_INSTALL_DIR",
    "UV_TOOL_DIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_STATE_HOME",
    "ZDOTDIR",
];

/// A captured host environment used only to build a child allowlist.
#[derive(Clone, Debug)]
pub struct HostEnvironment {
    values: BTreeMap<OsString, OsString>,
}

impl HostEnvironment {
    /// Capture the current process environment.
    #[must_use]
    pub fn capture() -> Self {
        Self {
            values: env::vars_os().collect(),
        }
    }

    /// Read one captured value.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&OsString> {
        self.values.get(OsStr::new(name))
    }

    /// Return the original host runtime root across nested Quarters launches.
    #[cfg(target_os = "linux")]
    pub(crate) fn original_xdg_runtime(&self) -> Option<&OsString> {
        self.get("QUARTERS_HOST_XDG_RUNTIME_DIR").or_else(|| {
            if self.get("QUARTERS_SPACE").is_none() {
                self.get("XDG_RUNTIME_DIR")
            } else {
                None
            }
        })
    }

    fn safe_values(&self) -> BTreeMap<OsString, OsString> {
        self.values
            .iter()
            .filter(|(name, _value)| safe_to_inherit(name))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }
}

/// Complete environment for a launched process.
#[derive(Clone, Debug)]
pub struct EnvironmentPlan {
    values: BTreeMap<OsString, OsString>,
    explicit_inheritance: BTreeSet<String>,
}

impl EnvironmentPlan {
    /// Build a least-privilege environment for a space.
    ///
    /// # Errors
    ///
    /// Returns an error when a requested inherited variable is invalid or
    /// unset, or when a private runtime directory cannot be prepared.
    pub fn for_space(
        space: &Space,
        host: &HostEnvironment,
        effective_home: &Path,
        inherited_names: &[String],
    ) -> Result<Self> {
        let mut values = host.safe_values();
        let mut explicit_inheritance = BTreeSet::new();
        for name in inherited_names {
            validate_inherited_variable(name)?;
            let value = host.get(name).ok_or_else(|| {
                QuartersError::new(
                    ErrorKind::InvalidInput,
                    format!("cannot inherit '{name}' because it is unset on the host"),
                )
            })?;
            values.insert(OsString::from(name), value.clone());
            explicit_inheritance.insert(name.clone());
        }
        let runtime = platform::runtime_directory(space, host)?;
        insert_profile_values(&mut values, space, effective_home, &runtime, host)?;
        if effective_home != space.home() {
            values.insert("QUARTERS_NO_HOST_ESCAPE".into(), "home-view".into());
            prepend_path(&mut values, &runtime.join("bin"))?;
        }
        platform::extend_environment(&mut values, effective_home);
        Ok(Self {
            values,
            explicit_inheritance,
        })
    }

    /// Apply the full environment, clearing everything inherited by `Command`.
    pub fn apply(&self, command: &mut Command) {
        command.env_clear().envs(&self.values);
    }

    /// Narrow PATH and tool-owned state for an opt-in filesystem policy.
    ///
    /// # Errors
    ///
    /// Returns an error when explicit inheritance conflicts with confinement or
    /// when the reported PATH entries cannot be represented by the host OS.
    pub fn apply_filesystem_confinement(&mut self, plan: &platform::ConfinementPlan, home: &Path) -> Result<()> {
        for name in ["NPM_CONFIG_PREFIX", "RUSTUP_HOME", "UV_TOOL_BIN_DIR"] {
            if self.explicit_inheritance.contains(name) {
                return Err(QuartersError::new(
                    ErrorKind::InvalidInput,
                    format!("'{name}' cannot be inherited with filesystem confinement"),
                )
                .with_hint(format!(
                    "remove '--inherit {name}'; filesystem confinement redirects this tool state into the Quarter"
                )));
            }
        }
        let executable_path = env::join_paths(&plan.executable_path).map_err(|error| {
            QuartersError::new(ErrorKind::System, "could not construct the confined executable PATH").with_source(error)
        })?;
        self.values.insert("PATH".into(), executable_path);
        self.values.remove(OsStr::new("QUARTERS_HOST_PATH"));
        self.values.insert("QUARTERS_CONFINEMENT".into(), "filesystem".into());
        let context = if self.values.contains_key(OsStr::new("QUARTERS_NO_HOST_ESCAPE")) {
            "home-view+filesystem"
        } else {
            "filesystem"
        };
        self.values.insert("QUARTERS_NO_HOST_ESCAPE".into(), context.into());
        self.values
            .insert("RUSTUP_HOME".into(), home.join(".rustup").into_os_string());
        self.values.insert(
            "NPM_CONFIG_PREFIX".into(),
            home.join(".local/share/npm").into_os_string(),
        );
        self.values
            .insert("UV_TOOL_BIN_DIR".into(), home.join(".local/bin").into_os_string());
        Ok(())
    }

    /// Read one planned value without exposing the rest of the environment.
    #[must_use]
    pub fn value(&self, name: &str) -> Option<&OsStr> {
        self.values.get(OsStr::new(name)).map(OsString::as_os_str)
    }

    /// Values suitable for diagnostics. Explicitly inherited values are redacted.
    #[must_use]
    pub fn diagnostic_values(&self) -> BTreeMap<String, String> {
        self.values
            .iter()
            .map(|(name, value)| {
                let name = name.to_string_lossy().into_owned();
                let shown = if self.explicit_inheritance.contains(&name) {
                    "<explicitly inherited; redacted>".to_owned()
                } else {
                    value.to_string_lossy().into_owned()
                };
                (name, shown)
            })
            .collect()
    }
}

/// Restore host user-state paths for the explicit baseline escape command.
#[must_use]
pub fn host_command_environment() -> BTreeMap<OsString, Option<OsString>> {
    let mut changes = BTreeMap::new();
    for variable in REDIRECTED_VARIABLES {
        changes.insert(OsString::from(variable), None);
    }
    restore_host_value(&mut changes, "HOME", "QUARTERS_HOST_HOME");
    restore_host_value(&mut changes, "PATH", "QUARTERS_HOST_PATH");
    restore_host_value(&mut changes, "TMPDIR", "QUARTERS_HOST_TMPDIR");
    restore_host_value(&mut changes, "XDG_RUNTIME_DIR", "QUARTERS_HOST_XDG_RUNTIME_DIR");
    for variable in [
        "QUARTERS_HOST_HOME",
        "QUARTERS_HOST_PATH",
        "QUARTERS_HOST_TMPDIR",
        "QUARTERS_HOST_XDG_RUNTIME_DIR",
        "QUARTERS_CONFINEMENT",
        "QUARTERS_NO_HOST_ESCAPE",
        "QUARTERS_PROMPT_NAME",
        "QUARTERS_PROMPT_PREFIX",
        "QUARTERS_ROOT",
        "QUARTERS_SPACE",
        "QUARTERS_SPACE_HOME",
        "QUARTERS_SPACE_ROOT",
    ] {
        changes.insert(OsString::from(variable), None);
    }
    changes
}

fn insert_profile_values(
    values: &mut BTreeMap<OsString, OsString>,
    space: &Space,
    home: &Path,
    runtime: &Path,
    host: &HostEnvironment,
) -> Result<()> {
    let config = home.join(".config");
    let local = home.join(".local");
    let cache = home.join(".cache");
    values.insert("HOME".into(), home.as_os_str().to_owned());
    values.insert("XDG_CONFIG_HOME".into(), config.as_os_str().to_owned());
    values.insert("XDG_DATA_HOME".into(), local.join("share").into_os_string());
    values.insert("XDG_STATE_HOME".into(), local.join("state").into_os_string());
    values.insert("XDG_CACHE_HOME".into(), cache.as_os_str().to_owned());
    values.insert("XDG_RUNTIME_DIR".into(), runtime.as_os_str().to_owned());
    values.insert("TMPDIR".into(), runtime.join("tmp").into_os_string());
    values.insert("ZDOTDIR".into(), home.as_os_str().to_owned());
    values.insert(
        "HISTFILE".into(),
        local.join("state/shell/zsh_history").into_os_string(),
    );
    values.insert("GIT_CONFIG_GLOBAL".into(), home.join(".gitconfig").into_os_string());
    values.insert("GH_CONFIG_DIR".into(), config.join("gh").into_os_string());
    values.insert("GNUPGHOME".into(), home.join(".gnupg").into_os_string());
    if let Some(socket) = crate::agent::active_socket(space, host)? {
        values.insert("SSH_AUTH_SOCK".into(), socket.into_os_string());
    }
    values.insert("CARGO_HOME".into(), home.join(".cargo").into_os_string());
    values.insert(
        "NPM_CONFIG_USERCONFIG".into(),
        config.join("npm/npmrc").into_os_string(),
    );
    values.insert("NPM_CONFIG_CACHE".into(), cache.join("npm").into_os_string());
    values.insert("CODEX_HOME".into(), home.join(".codex").into_os_string());
    values.insert("CLAUDE_CONFIG_DIR".into(), home.join(".claude").into_os_string());
    values.insert("OPENCODE_CONFIG_DIR".into(), config.join("opencode").into_os_string());
    values.insert("UV_CACHE_DIR".into(), cache.join("uv").into_os_string());
    values.insert(
        "UV_PYTHON_INSTALL_DIR".into(),
        local.join("share/uv/python").into_os_string(),
    );
    values.insert("UV_TOOL_DIR".into(), local.join("share/uv/tools").into_os_string());
    values.insert("TMUX_TMPDIR".into(), runtime.join("tmux").into_os_string());
    values.insert("QUARTERS_SPACE".into(), OsString::from(space.manifest().name.as_str()));
    values.insert(
        "QUARTERS_PROMPT_NAME".into(),
        OsString::from(space.manifest().name.as_str()),
    );
    values.insert(
        "QUARTERS_PROMPT_PREFIX".into(),
        OsString::from(format!("[q:{}] ", space.manifest().name)),
    );
    values.insert("QUARTERS_SPACE_ROOT".into(), space.root().as_os_str().to_owned());
    values.insert("QUARTERS_SPACE_HOME".into(), home.as_os_str().to_owned());
    values.insert("QUARTERS_ROOT".into(), store_root(space).into_os_string());
    preserve_host_value(values, host, "HOME", "QUARTERS_HOST_HOME");
    preserve_host_value(values, host, "PATH", "QUARTERS_HOST_PATH");
    preserve_host_value(values, host, "TMPDIR", "QUARTERS_HOST_TMPDIR");
    preserve_host_value(values, host, "XDG_RUNTIME_DIR", "QUARTERS_HOST_XDG_RUNTIME_DIR");
    prepend_profile_path(values, home)
}

fn prepend_profile_path(values: &mut BTreeMap<OsString, OsString>, home: &Path) -> Result<()> {
    prepend_path(values, &home.join(".local/bin"))
}

fn prepend_path(values: &mut BTreeMap<OsString, OsString>, prefix: &Path) -> Result<()> {
    let mut paths = vec![prefix.to_path_buf()];
    if let Some(existing) = values.get(OsStr::new("PATH")) {
        paths.extend(env::split_paths(existing));
    }
    let joined = env::join_paths(paths).map_err(|error| {
        QuartersError::new(ErrorKind::InvalidInput, "host PATH cannot be represented safely")
            .with_hint("remove entries containing platform path separators, then retry")
            .with_source(error)
    })?;
    values.insert("PATH".into(), joined);
    Ok(())
}

fn safe_to_inherit(name: &OsString) -> bool {
    let name = name.to_string_lossy();
    matches!(
        name.as_ref(),
        "CLICOLOR"
            | "CLICOLOR_FORCE"
            | "COLORTERM"
            | "DEVELOPER_DIR"
            | "DISPLAY"
            | "EDITOR"
            | "GPG_TTY"
            | "LANG"
            | "LC_ALL"
            | "LC_CTYPE"
            | "LESS"
            | "LOGNAME"
            | "MANPAGER"
            | "NO_COLOR"
            | "PAGER"
            | "PATH"
            | "SHELL"
            | "SSH_TTY"
            | "TERM"
            | "TERM_PROGRAM"
            | "TERM_PROGRAM_VERSION"
            | "USER"
            | "VISUAL"
            | "WAYLAND_DISPLAY"
            | "__CFBundleIdentifier"
    ) || name.starts_with("LC_")
}

fn validate_variable_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if valid {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::InvalidInput,
        format!("'{name}' is not a valid environment variable name"),
    ))
}

fn validate_inherited_variable(name: &str) -> Result<()> {
    validate_variable_name(name)?;
    let profile_owned =
        name == "HOME" || name == "PATH" || name.starts_with("QUARTERS_") || REDIRECTED_VARIABLES.contains(&name);
    if !profile_owned {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::InvalidInput,
        format!("'{name}' is owned by the space profile and cannot be inherited"),
    )
    .with_hint(format!(
        "remove '--inherit {name}'; Quarters always computes this variable"
    )))
}

fn preserve_host_value(
    values: &mut BTreeMap<OsString, OsString>,
    host: &HostEnvironment,
    source: &str,
    destination: &str,
) {
    if let Some(value) = host.get(destination).or_else(|| host.get(source)) {
        values.insert(OsString::from(destination), value.clone());
    }
}

fn restore_host_value(changes: &mut BTreeMap<OsString, Option<OsString>>, destination: &str, source: &str) {
    changes.insert(OsString::from(destination), env::var_os(source));
}

fn store_root(space: &Space) -> PathBuf {
    space
        .root()
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::{safe_to_inherit, validate_inherited_variable, validate_variable_name};
    use std::ffi::OsString;

    #[test]
    fn allowlist_keeps_terminal_context_and_rejects_credentials() {
        for name in ["LANG", "LC_MESSAGES", "PATH", "TERM", "WAYLAND_DISPLAY"] {
            assert!(safe_to_inherit(&OsString::from(name)), "expected {name} to be safe");
        }
        for name in [
            "ANTHROPIC_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "SSH_AUTH_SOCK",
        ] {
            assert!(!safe_to_inherit(&OsString::from(name)), "expected {name} to be blocked");
        }
    }

    #[test]
    fn explicit_variable_names_follow_portable_environment_syntax() {
        for name in ["TOKEN", "_TOKEN", "TOKEN_2"] {
            assert!(validate_variable_name(name).is_ok(), "expected {name} to be valid");
        }
        for name in ["", "2TOKEN", "TOKEN-NAME", "TOKEN=VALUE", "TOKEN.NAME"] {
            assert!(validate_variable_name(name).is_err(), "expected {name} to be invalid");
        }
    }

    #[test]
    fn profile_owned_variables_cannot_be_explicitly_inherited() {
        for name in ["HOME", "PATH", "SSH_AUTH_SOCK", "XDG_CONFIG_HOME", "QUARTERS_ROOT"] {
            assert!(
                validate_inherited_variable(name).is_err(),
                "expected {name} to be profile-owned"
            );
        }
        assert!(validate_inherited_variable("EXPLICIT_SECRET").is_ok());
    }
}
