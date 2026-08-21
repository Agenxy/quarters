//! Repository discovery and non-code policy checks.

use crate::limits::MAX_FILE_LINES;
use crate::metrics;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn check_repository() -> Result<(), Vec<String>> {
    let root = repository_root().map_err(|error| vec![error])?;
    let mut violations = Vec::new();
    check_required_files(&root, &mut violations);
    let files = rust_files(&root).map_err(|error| vec![error])?;
    for path in files {
        inspect_rust_file(&path, &mut violations);
    }
    check_for_shell_scripts(&root, &mut violations);
    if violations.is_empty() { Ok(()) } else { Err(violations) }
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
            if entry.file_name() != "target" && entry.file_name() != ".git" {
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

fn check_for_shell_scripts(root: &Path, violations: &mut Vec<String>) {
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && entry.file_name() != ".git" && entry.file_name() != "target" {
                directories.push(path);
            } else if path.extension().is_some_and(|extension| extension == "sh") {
                violations.push(format!("shell script is not allowed: {}", path.display()));
            }
        }
    }
}
