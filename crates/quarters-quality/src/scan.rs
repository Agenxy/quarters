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
    check_for_shell_scripts(&root, &mut violations);
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

fn check_for_shell_scripts(root: &Path, violations: &mut Vec<String>) {
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && !ignored_directory(&entry.file_name()) {
                directories.push(path);
            } else if path.extension().is_some_and(|extension| extension == "sh") {
                violations.push(format!("shell script is not allowed: {}", path.display()));
            }
        }
    }
}
