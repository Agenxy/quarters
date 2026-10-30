// SPDX-License-Identifier: GPL-3.0-or-later
//! Every pinned tool and dependency, read offline from the repository.

use std::fs;
use std::path::Path;

/// Where an upstream release of a pin is published.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Upstream {
    /// The stable Rust release channel.
    Rust,
    /// A GitHub repository's latest release, with a tag prefix to strip.
    GitHubRelease {
        repository: String,
        tag_prefix: &'static str,
    },
    /// The newest Node.js long-term-support release.
    NodeLts,
    /// A project on the Python Package Index.
    PyPi(String),
    /// A crates.io crate.
    Crate(String),
    /// An npm package.
    Npm(String),
}

/// One pinned version and where it is declared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Pin {
    pub(crate) name: String,
    pub(crate) current: String,
    pub(crate) declared_in: String,
    pub(crate) upstream: Upstream,
}

fn read(root: &Path, relative: &str) -> Result<String, String> {
    fs::read_to_string(root.join(relative)).map_err(|error| format!("{relative}: {error}"))
}

fn workflows(root: &Path) -> Result<Vec<(String, String)>, String> {
    let directory = root.join(".github/workflows");
    let entries = fs::read_dir(&directory).map_err(|error| format!(".github/workflows: {error}"))?;
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if Path::new(&name).extension().is_some_and(|extension| extension == "yml") {
            let relative = format!(".github/workflows/{name}");
            files.push((relative.clone(), read(root, &relative)?));
        }
    }
    files.sort();
    Ok(files)
}

/// The text after `key` on a line, without quotes or a trailing comment.
pub(crate) fn value_after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix(key)?;
    let rest = rest.split(" #").next().unwrap_or(rest).trim();
    Some(rest.trim_matches('"').trim_matches('\''))
}

/// Every `uses: owner/repo@sha # vX` action with its commented version.
pub(crate) fn action_pins(file: &str, text: &str) -> Vec<Pin> {
    let mut pins = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim_start().trim_start_matches("- ").strip_prefix("uses: ") else {
            continue;
        };
        let Some((reference, comment)) = rest.split_once(" # ") else {
            continue;
        };
        let Some((repository, _sha)) = reference.split_once('@') else {
            continue;
        };
        pins.push(Pin {
            name: repository.to_owned(),
            current: comment.trim().to_owned(),
            declared_in: file.to_owned(),
            upstream: Upstream::GitHubRelease {
                repository: repository.to_owned(),
                tag_prefix: "",
            },
        });
    }
    pins
}

/// Exact `name = "=x"` or `name = { version = "=x", ... }` workspace pins.
pub(crate) fn crate_pins(manifest: &str) -> Vec<Pin> {
    let mut pins = Vec::new();
    let mut in_dependencies = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_dependencies = trimmed == "[workspace.dependencies]";
            continue;
        }
        let Some((name, specification)) = trimmed.split_once(" = ").filter(|_pair| in_dependencies) else {
            continue;
        };
        let version = specification
            .split("version = ")
            .nth(1)
            .unwrap_or(specification)
            .trim_start_matches('"')
            .split('"')
            .next()
            .unwrap_or_default();
        if let Some(exact) = version.strip_prefix('=') {
            pins.push(Pin {
                name: name.to_owned(),
                current: exact.to_owned(),
                declared_in: "Cargo.toml".to_owned(),
                upstream: Upstream::Crate(name.to_owned()),
            });
        }
    }
    pins
}

fn single(name: &str, current: Option<&str>, declared_in: &str, upstream: Upstream) -> Result<Pin, String> {
    let current = current.ok_or_else(|| format!("{declared_in}: no {name} pin found"))?;
    Ok(Pin {
        name: name.to_owned(),
        current: current.to_owned(),
        declared_in: declared_in.to_owned(),
        upstream,
    })
}

fn first_value<'a>(texts: &'a [(String, String)], key: &str) -> Option<(&'a str, &'a str)> {
    texts.iter().find_map(|(file, text)| {
        text.lines()
            .find_map(|line| value_after(line, key))
            .map(|value| (file.as_str(), value))
    })
}

/// The version a workflow pins after `marker`: inline (`npm@1.2.3`,
/// `--version 1.2.3`) or, for an action, its `version:` input.
pub(crate) fn marked_version(text: &str, marker: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let index = lines.iter().position(|line| line.contains(marker))?;
    let inline = lines[index].split(marker).nth(1).unwrap_or_default();
    if !marker.ends_with('@') || marker.contains(' ') {
        return inline.split_whitespace().next().map(str::to_owned);
    }
    lines
        .iter()
        .skip(index.saturating_add(1))
        .take(6)
        .find_map(|line| value_after(line, "version:"))
        .map(str::to_owned)
}

/// Collect every pin the drift check compares with upstream.
pub(crate) fn collect(root: &Path) -> Result<Vec<Pin>, String> {
    let flows = workflows(root)?;
    let toolchain = read(root, "rust-toolchain.toml")?;
    let package = read(root, "packaging/npm/quarters-cli/package.json")?;
    let manifest: serde_json::Value =
        serde_json::from_str(&package).map_err(|error| format!("packaging/npm/quarters-cli/package.json: {error}"))?;
    let pyproject = read(root, "pyproject.toml")?;
    let mut pins = vec![
        single(
            "rust",
            toolchain.lines().find_map(|line| value_after(line, "channel =")),
            "rust-toolchain.toml",
            Upstream::Rust,
        )?,
        single(
            "bun",
            manifest["packageManager"]
                .as_str()
                .and_then(|value| value.strip_prefix("bun@")),
            "packaging/npm/quarters-cli/package.json",
            Upstream::GitHubRelease {
                repository: "oven-sh/bun".to_owned(),
                tag_prefix: "bun-v",
            },
        )?,
        single(
            "maturin",
            pyproject
                .split("maturin==")
                .nth(1)
                .and_then(|rest| rest.split('"').next()),
            "pyproject.toml",
            Upstream::PyPi("maturin".to_owned()),
        )?,
    ];
    let (file, value) = first_value(&flows, "node-version:").ok_or("workflows: no `node-version:` pin")?;
    pins.push(single("node", Some(value), file, Upstream::NodeLts)?);
    for (name, marker, upstream) in [
        ("uv", "astral-sh/setup-uv@", Upstream::PyPi("uv".to_owned())),
        ("npm", "npm install --global npm@", Upstream::Npm("npm".to_owned())),
        (
            "cargo-audit",
            "cargo-audit --version ",
            Upstream::Crate("cargo-audit".to_owned()),
        ),
    ] {
        let found = flows
            .iter()
            .find_map(|(file, text)| marked_version(text, marker).map(|value| (file, value)));
        let (file, value) = found.ok_or_else(|| format!("workflows: no {name} pin `{marker}`"))?;
        pins.push(single(name, Some(&value), file, upstream)?);
    }
    for (file, text) in &flows {
        for pin in action_pins(file, text) {
            if !pins.iter().any(|existing| existing.name == pin.name) {
                pins.push(pin);
            }
        }
    }
    pins.extend(crate_pins(&read(root, "Cargo.toml")?));
    if let Some(development) = manifest["devDependencies"].as_object() {
        for (name, version) in development {
            pins.push(single(
                name,
                version.as_str(),
                "packaging/npm/quarters-cli/package.json",
                Upstream::Npm(name.clone()),
            )?);
        }
    }
    Ok(pins)
}

/// Versions written right after `word` in prose, such as `Rust 1.99.1`.
pub(crate) fn versions_after_word(text: &str, word: &str) -> Vec<String> {
    text.split(word)
        .skip(1)
        .filter_map(|rest| rest.split_whitespace().next())
        .map(|token| token.trim_end_matches(['.', ',', ')', ';', ':']))
        .filter(|token| token.starts_with(|character: char| character.is_ascii_digit()) && token.contains('.'))
        .map(str::to_owned)
        .collect()
}

/// Every value of `key` across the workflows, with its file.
fn workflow_values(flows: &[(String, String)], key: &str) -> Vec<(String, String)> {
    flows
        .iter()
        .flat_map(|(file, text)| {
            text.lines()
                .filter_map(move |line| value_after(line, key).map(|value| (file.clone(), value.to_owned())))
        })
        .collect()
}

/// Offline check that every mention of a pinned tool matches its pin, so
/// documentation and workflows never describe a toolchain the gate does not run.
pub(crate) fn consistency(root: &Path) -> Vec<String> {
    let pins = match collect_toolchain(root) {
        Ok(pins) => pins,
        Err(error) => return vec![format!("toolchain pins: {error}")],
    };
    let Ok(flows) = workflows(root) else {
        return vec!["toolchain pins: cannot read workflows".to_owned()];
    };
    let mut mentions: Vec<(String, String, String)> = Vec::new();
    for (tool, key) in [
        ("rust", "rust-toolchain:"),
        ("bun", "bun-version:"),
        ("node", "node-version:"),
        ("maturin", "maturin-version:"),
    ] {
        for (file, value) in workflow_values(&flows, key) {
            mentions.push((tool.to_owned(), file, value.trim_start_matches('v').to_owned()));
        }
    }
    for (tool, marker) in [
        ("cargo-audit", "cargo-audit --version "),
        ("npm", "npm install --global npm@"),
    ] {
        for (file, text) in &flows {
            for value in text
                .split(marker)
                .skip(1)
                .filter_map(|rest| rest.split_whitespace().next())
            {
                mentions.push((tool.to_owned(), file.clone(), value.to_owned()));
            }
        }
    }
    for document in ["AGENTS.md", "CONTRIBUTING.md", "README.md"] {
        let Ok(text) = read(root, document) else {
            continue;
        };
        for (tool, word) in [("rust", "Rust "), ("bun", "Bun "), ("node", "Node.js ")] {
            for value in versions_after_word(&text, word) {
                mentions.push((tool.to_owned(), document.to_owned(), value));
            }
        }
    }
    let mut violations = Vec::new();
    for (tool, file, value) in mentions {
        if let Some((_tool, pinned)) = pins.iter().find(|(name, _pinned)| *name == tool)
            && *pinned != value
        {
            violations.push(format!("{file}: {tool} {value} does not match the pinned {pinned}"));
        }
    }
    violations
}

/// The toolchain pins that prose and workflows must agree with.
fn collect_toolchain(root: &Path) -> Result<Vec<(String, String)>, String> {
    Ok(collect(root)?
        .into_iter()
        .filter(|pin| {
            matches!(
                pin.name.as_str(),
                "rust" | "bun" | "node" | "maturin" | "cargo-audit" | "npm"
            )
        })
        .map(|pin| (pin.name, pin.current))
        .collect())
}
