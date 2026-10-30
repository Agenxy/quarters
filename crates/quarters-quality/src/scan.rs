// SPDX-License-Identifier: GPL-3.0-or-later
//! Repository discovery and non-code policy checks.

use crate::limits::MAX_FILE_LINES;
use crate::metrics;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn check_repository() -> Result<(), Vec<String>> {
    let root = repository_root().map_err(|error| vec![error])?;
    let mut violations = Vec::new();
    check_required_files(&root, &mut violations);
    check_distribution_versions(&root, &mut violations);
    check_mcp_network_dependency_gate(&root, &mut violations);
    let files = rust_files(&root).map_err(|error| vec![error])?;
    for path in files {
        inspect_rust_file(&path, &mut violations);
    }
    check_repository_files(&root, &mut violations);
    if violations.is_empty() { Ok(()) } else { Err(violations) }
}

fn check_mcp_network_dependency_gate(root: &Path, violations: &mut Vec<String>) {
    let path = root.join("Cargo.lock");
    let source = match fs::read_to_string(&path) {
        Ok(source) => source,
        Err(error) => {
            violations.push(format!("{}: could not read: {error}", path.display()));
            return;
        }
    };
    for package in [
        "axum",
        "curl",
        "curl-sys",
        "h2",
        "hyper",
        "hyper-util",
        "isahc",
        "mio",
        "native-tls",
        "openssl",
        "openssl-sys",
        "reqwest",
        "rustls",
        "socket2",
        "sse-stream",
        "tokio-rustls",
        "tokio-tungstenite",
        "tonic",
        "tower-http",
        "tungstenite",
        "ureq",
    ] {
        if source.lines().any(|line| line == format!("name = \"{package}\"")) {
            violations.push(format!(
                "Cargo.lock: network transport dependency '{package}' violates the MCP stdio-only boundary"
            ));
        }
    }
}

fn repository_root() -> Result<PathBuf, String> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "could not resolve repository root".to_owned())
}

fn rust_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    collect_rust_files(root, &mut files).map_err(|error| format!("{}: {error}", root.display()))?;
    files.sort();
    Ok(files)
}

fn collect_rust_files(directory: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if !ignored_directory(&entry.file_name()) {
                collect_rust_files(&path, files)?;
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn inspect_rust_file(path: &Path, violations: &mut Vec<String>) {
    let source = match fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => {
            violations.push(format!("{}: could not read: {error}", path.display()));
            return;
        }
    };
    let line_count = source.lines().count();
    if line_count > MAX_FILE_LINES {
        violations.push(format!(
            "{}: has {line_count} lines; maximum is {MAX_FILE_LINES}",
            path.display()
        ));
    }
    match syn::parse_file(&source) {
        Ok(syntax) => violations.extend(metrics::inspect(path, &syntax)),
        Err(error) => violations.push(format!("{}: could not parse Rust: {error}", path.display())),
    }
}

fn check_required_files(root: &Path, violations: &mut Vec<String>) {
    for relative in ["LICENSE", "README.md", "SECURITY.md", "docs/security/THREAT-MODEL.md"] {
        if !root.join(relative).is_file() {
            violations.push(format!("missing required file: {relative}"));
        }
    }
}

fn check_distribution_versions(root: &Path, violations: &mut Vec<String>) {
    let Some(workspace_version) = workspace_version(root, violations) else {
        return;
    };
    for relative in [
        "packaging/npm/quarters-cli/package.json",
        "packaging/npm/platforms/darwin-arm64/package.json",
        "packaging/npm/platforms/darwin-x64/package.json",
        "packaging/npm/platforms/linux-arm64/package.json",
        "packaging/npm/platforms/linux-x64/package.json",
    ] {
        check_package_version(root, relative, &workspace_version, violations);
    }
    check_launcher_dependencies(root, &workspace_version, violations);
}

fn workspace_version(root: &Path, violations: &mut Vec<String>) -> Option<String> {
    let path = root.join("Cargo.toml");
    let source = match fs::read_to_string(&path) {
        Ok(source) => source,
        Err(error) => {
            violations.push(format!("{}: could not read: {error}", path.display()));
            return None;
        }
    };
    let version = source
        .split("[workspace.package]")
        .nth(1)
        .and_then(|section| section.lines().find_map(parse_version_line));
    if version.is_none() {
        violations.push(format!("{}: missing workspace package version", path.display()));
    }
    version
}

fn parse_version_line(line: &str) -> Option<String> {
    line.trim()
        .strip_prefix("version = \"")
        .and_then(|value| value.strip_suffix('"'))
        .map(str::to_owned)
}

fn check_package_version(root: &Path, relative: &str, expected: &str, violations: &mut Vec<String>) {
    let path = root.join(relative);
    let version = fs::read_to_string(&path)
        .map_err(|error| error.to_string())
        .and_then(|source| serde_json::from_str::<serde_json::Value>(&source).map_err(|error| error.to_string()))
        .ok()
        .and_then(|manifest| manifest["version"].as_str().map(str::to_owned));
    if version.as_deref() != Some(expected) {
        violations.push(format!(
            "{relative}: version {} does not match workspace {expected}",
            version.as_deref().unwrap_or("<missing or invalid>")
        ));
    }
}

fn check_launcher_dependencies(root: &Path, expected: &str, violations: &mut Vec<String>) {
    let relative = "packaging/npm/quarters-cli/package.json";
    let path = root.join(relative);
    let manifest = fs::read_to_string(&path)
        .map_err(|error| error.to_string())
        .and_then(|source| serde_json::from_str::<serde_json::Value>(&source).map_err(|error| error.to_string()));
    let Ok(manifest) = manifest else {
        return;
    };
    for package in [
        "quarters-cli-darwin-arm64",
        "quarters-cli-darwin-x64",
        "quarters-cli-linux-arm64",
        "quarters-cli-linux-x64",
    ] {
        let version = manifest["optionalDependencies"][package].as_str();
        if version != Some(expected) {
            violations.push(format!(
                "{relative}: optional dependency {package} is {} instead of {expected}",
                version.unwrap_or("<missing>")
            ));
        }
    }
}

fn ignored_directory(name: &std::ffi::OsStr) -> bool {
    matches!(
        name.to_str(),
        Some(".git" | ".venv" | "node_modules" | "target" | "work")
    )
}

const SHELL_ALLOWLIST: &str = "crates/quarters-quality/shell-allowlist.txt";

/// Walk the repository once for the file-level policies: no shell scripts,
/// whether named `.sh` or started with a shell shebang, unless the reviewed
/// allowlist names them, and no em dashes in any UTF-8 text.
fn check_repository_files(root: &Path, violations: &mut Vec<String>) {
    let allowed = match fs::read_to_string(root.join(SHELL_ALLOWLIST)) {
        Ok(text) => parse_shell_allowlist(&text, |path| root.join(path).is_file(), violations),
        Err(error) => {
            violations.push(format!("{SHELL_ALLOWLIST}: {error}"));
            Vec::new()
        }
    };
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if !ignored_directory(&entry.file_name()) {
                    directories.push(path);
                }
                continue;
            }
            let allowlisted = path
                .strip_prefix(root)
                .is_ok_and(|relative| allowed.iter().any(|entry| Path::new(entry) == relative));
            if !allowlisted && path.extension().is_some_and(|extension| extension == "sh") {
                violations.push(format!("shell script is not allowed: {}", path.display()));
            }
            if let Ok(text) = fs::read_to_string(&path) {
                if !allowlisted && starts_with_shell_shebang(&text) {
                    violations.push(format!(
                        "shell interpreter is not allowed: {}; use a uv script or a compiled program",
                        path.display()
                    ));
                }
                for line in em_dash_lines(&text) {
                    violations.push(format!(
                        "{}:{line}: em dash; use a comma, colon, semicolon or parentheses",
                        path.display()
                    ));
                }
            }
        }
    }
}

/// Paths from the shell allowlist. An entry without a reason after `#`, or
/// naming a file that does not exist, is a violation rather than a permit.
fn parse_shell_allowlist(text: &str, exists: impl Fn(&str) -> bool, violations: &mut Vec<String>) -> Vec<String> {
    let mut allowed = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = index.saturating_add(1);
        let (path, reason) = line
            .split_once('#')
            .map_or((line, ""), |(path, reason)| (path.trim(), reason.trim()));
        if reason.is_empty() {
            violations.push(format!("{SHELL_ALLOWLIST}:{number}: entry {path} gives no reason"));
        } else if !exists(path) {
            violations.push(format!("{SHELL_ALLOWLIST}:{number}: entry {path} names no file"));
        } else {
            allowed.push(path.to_owned());
        }
    }
    allowed
}

/// Whether the first line runs a POSIX-family shell, directly or via `env`.
fn starts_with_shell_shebang(text: &str) -> bool {
    let Some(interpreter) = text.lines().next().and_then(|line| line.strip_prefix("#!")) else {
        return false;
    };
    let mut words = interpreter.split_whitespace();
    let program = words.next().unwrap_or_default();
    let program = if program.ends_with("/env") {
        words.find(|word| !word.starts_with('-')).unwrap_or_default()
    } else {
        program
    };
    let name = program.rsplit('/').next().unwrap_or_default();
    matches!(name, "sh" | "bash" | "zsh" | "dash" | "ksh" | "fish")
}

/// One-based numbers of the lines that contain an em dash (U+2014).
fn em_dash_lines(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_index, line)| line.contains('\u{2014}'))
        .map(|(index, _line)| index.saturating_add(1))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{em_dash_lines, parse_shell_allowlist, starts_with_shell_shebang};

    #[test]
    fn shell_allowlist_entries_need_a_reason_and_an_existing_file() {
        let text =
            "# header\n\nboot/install.sh  # runs before any toolchain exists\nboot/bare.sh\nboot/gone.sh # stale\n";
        let mut violations = Vec::new();
        let allowed = parse_shell_allowlist(text, |path| path != "boot/gone.sh", &mut violations);
        assert_eq!(allowed, vec!["boot/install.sh".to_owned()]);
        assert_eq!(violations.len(), 2, "{violations:?}");
        assert!(
            violations[0].contains(":4: entry boot/bare.sh gives no reason"),
            "{violations:?}"
        );
        assert!(
            violations[1].contains(":5: entry boot/gone.sh names no file"),
            "{violations:?}"
        );
    }

    #[test]
    fn shell_shebangs_are_recognized_and_other_interpreters_are_not() {
        for script in [
            "#!/bin/sh\n",
            "#!/bin/bash -eu\n",
            "#!/usr/bin/env bash\n",
            "#!/usr/bin/env -S zsh -f\n",
        ] {
            assert!(starts_with_shell_shebang(script), "{script:?}");
        }
        for text in [
            "#!/usr/bin/env -S uv run --script\n",
            "#!/usr/bin/env python3\n",
            "fn main() {}\n",
            "x\n#!/bin/sh\n",
        ] {
            assert!(!starts_with_shell_shebang(text), "{text:?}");
        }
    }

    #[test]
    fn em_dashes_are_reported_by_line_and_other_dashes_are_not() {
        let text = "plain - hyphen\nrange 1\u{2013}2\nan aside \u{2014} here\n\u{2014}\n";
        assert_eq!(em_dash_lines(text), vec![3, 4]);
        assert_eq!(em_dash_lines("no dashes at all"), Vec::<usize>::new());
    }
}
