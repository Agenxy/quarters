// SPDX-License-Identifier: GPL-3.0-or-later
//! Manual pages generated from the command-line definition. The committed
//! pages under `man/` must equal what the current definition renders, so a
//! manual page can never drift from `--help`. Run `make man` to regenerate.

use crate::cli::Cli;
use clap::CommandFactory;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

fn render(command: clap::Command) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut page = Vec::new();
    clap_mangen::Man::new(command).render(&mut page)?;
    Ok(page)
}

/// `quarters.1`, plus `quarters-NAME.1` for each visible subcommand.
fn pages() -> Result<BTreeMap<String, Vec<u8>>, Box<dyn Error>> {
    let command = Cli::command();
    let mut pages = BTreeMap::new();
    for subcommand in command.get_subcommands().filter(|subcommand| !subcommand.is_hide_set()) {
        // clap names are static strings unless its `string` feature is built
        // into the shipped binary; a test leaking a few short names is cheaper.
        let name: &'static str = Box::leak(format!("quarters-{}", subcommand.get_name()).into_boxed_str());
        pages.insert(format!("{name}.1"), render(subcommand.clone().name(name))?);
    }
    pages.insert("quarters.1".to_owned(), render(command)?);
    Ok(pages)
}

fn manual_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../man")
}

fn committed_pages() -> Result<BTreeMap<String, Vec<u8>>, Box<dyn Error>> {
    let mut committed = BTreeMap::new();
    for entry in fs::read_dir(manual_directory())? {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == "1") {
            let name = path
                .file_name()
                .ok_or("manual page has no name")?
                .to_string_lossy()
                .into_owned();
            committed.insert(name, fs::read(&path)?);
        }
    }
    Ok(committed)
}

#[test]
fn committed_manual_pages_match_the_command_line() -> Result<(), Box<dyn Error>> {
    let rendered = pages()?;
    if std::env::var_os("QUARTERS_WRITE_MAN").is_some() {
        let directory = manual_directory();
        fs::create_dir_all(&directory)?;
        for name in committed_pages().unwrap_or_default().keys() {
            if !rendered.contains_key(name) {
                fs::remove_file(directory.join(name))?;
            }
        }
        for (name, page) in &rendered {
            fs::write(directory.join(name), page)?;
        }
        return Ok(());
    }
    let package: serde_json::Value = serde_json::from_slice(&fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/npm/quarters-cli/package.json"),
    )?)?;
    let declared: Vec<&str> = package["man"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|page| page.as_str())
        .collect();
    let expected: Vec<String> = rendered.keys().map(|name| format!("./man/{name}")).collect();
    assert_eq!(
        declared, expected,
        "the npm launcher's `man` list must name exactly the generated pages"
    );
    let committed = committed_pages()?;
    let stale: Vec<&String> = rendered
        .iter()
        .filter(|(name, page)| committed.get(*name) != Some(*page))
        .map(|(name, _page)| name)
        .chain(committed.keys().filter(|name| !rendered.contains_key(*name)))
        .collect();
    assert!(
        stale.is_empty(),
        "manual pages differ from the command line; run `make man`: {stale:?}"
    );
    Ok(())
}
