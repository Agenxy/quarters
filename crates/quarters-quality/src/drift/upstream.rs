// SPDX-License-Identifier: GPL-3.0-or-later
//! Latest upstream releases, fetched with the host's `curl`.

use super::pins::Upstream;
use std::process::Command;

fn fetch(url: &str) -> Result<String, String> {
    let mut command = Command::new("curl");
    command.args(["--fail", "--silent", "--show-error", "--location", "--max-time", "30"]);
    command.args([
        "--user-agent",
        "quarters-quality-drift (https://github.com/Agenxy/quarters)",
    ]);
    if url.starts_with("https://api.github.com/")
        && let Some(token) = std::env::var_os("GH_TOKEN").filter(|token| !token.is_empty())
    {
        let mut header = std::ffi::OsString::from("Authorization: Bearer ");
        header.push(token);
        command.arg("--header").arg(header);
    }
    let output = command
        .arg(url)
        .output()
        .map_err(|error| format!("curl {url}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "curl {url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| format!("{url}: {error}"))
}

fn json(url: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(&fetch(url)?).map_err(|error| format!("{url}: {error}"))
}

fn text_field(value: &serde_json::Value, pointer: &str, url: &str) -> Result<String, String> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{url}: no {pointer}"))
}

/// The version of the stable Rust release named in the channel manifest.
pub(crate) fn rust_from_channel(manifest: &str) -> Option<String> {
    let section = manifest.split("[pkg.rust]").nth(1)?;
    let line = section.lines().find(|line| line.starts_with("version = "))?;
    let quoted = line.strip_prefix("version = \"")?;
    quoted.split([' ', '"']).next().map(str::to_owned)
}

/// The newest long-term-support release in Node's distribution index.
pub(crate) fn node_lts_from_index(index: &serde_json::Value) -> Option<String> {
    index
        .as_array()?
        .iter()
        .find(|release| release["lts"].as_str().is_some())
        .and_then(|release| release["version"].as_str())
        .map(|version| version.trim_start_matches('v').to_owned())
}

/// The latest release of `upstream`, comparable with a pin's version.
pub(crate) fn latest(upstream: &Upstream, current: &str) -> Result<String, String> {
    match upstream {
        Upstream::Rust => {
            let url = "https://static.rust-lang.org/dist/channel-rust-stable.toml";
            rust_from_channel(&fetch(url)?).ok_or_else(|| format!("{url}: no [pkg.rust] version"))
        }
        Upstream::GitHubRelease { repository, tag_prefix } => {
            let url = format!("https://api.github.com/repos/{repository}/releases/latest");
            let tag = text_field(&json(&url)?, "/tag_name", &url)?;
            Ok(tag.strip_prefix(tag_prefix).unwrap_or(&tag).to_owned())
        }
        Upstream::NodeLts => {
            let url = "https://nodejs.org/dist/index.json";
            node_lts_from_index(&json(url)?).ok_or_else(|| format!("{url}: no LTS release"))
        }
        Upstream::PyPi(project) => {
            let url = format!("https://pypi.org/pypi/{project}/json");
            text_field(&json(&url)?, "/info/version", &url)
        }
        Upstream::Crate(name) => {
            let url = format!("https://crates.io/api/v1/crates/{name}");
            // A pre-release pin is compared with the newest release of any kind.
            let field = if current.contains('-') {
                "/crate/max_version"
            } else {
                "/crate/max_stable_version"
            };
            text_field(&json(&url)?, field, &url)
        }
        Upstream::Npm(name) => {
            let url = format!("https://registry.npmjs.org/{name}/latest");
            text_field(&json(&url)?, "/version", &url)
        }
    }
}
