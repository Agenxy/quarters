// SPDX-License-Identifier: GPL-3.0-or-later
use super::pins::{Pin, Upstream, action_pins, crate_pins, marked_version, versions_after_word};
use super::upstream::{node_lts_from_index, rust_from_channel};
use super::{compare_versions, verdict};
use std::cmp::Ordering;

#[test]
fn versions_compare_numerically_and_place_prereleases_first() {
    assert_eq!(compare_versions("1.99.1", "1.100.0"), Ordering::Less);
    assert_eq!(compare_versions("v7.0.1", "7.0.1"), Ordering::Equal);
    assert_eq!(compare_versions("0.1.0-alpha.4", "0.1.0"), Ordering::Less);
    assert_eq!(compare_versions("2.0", "1.9.9"), Ordering::Greater);
}

#[test]
fn workflow_pins_are_read_in_each_of_their_forms() {
    let workflow = "      - uses: actions/checkout@3d3c # v7.0.1\n        uses: astral-sh/setup-uv@6855 # \
        v10.3.3\n        with:\n          version: \"0.13.6\"\n        run: cargo install --locked cargo-audit \
        --version 0.22.2\n          npm install --global npm@12.2.1\n";
    let actions = action_pins("ci.yml", workflow);
    assert_eq!(actions.len(), 2);
    assert_eq!(
        (actions[0].name.as_str(), actions[0].current.as_str()),
        ("actions/checkout", "v7.0.1")
    );
    assert_eq!(
        marked_version(workflow, "astral-sh/setup-uv@").as_deref(),
        Some("0.13.6")
    );
    assert_eq!(
        marked_version(workflow, "cargo-audit --version ").as_deref(),
        Some("0.22.2")
    );
    assert_eq!(
        marked_version(workflow, "npm install --global npm@").as_deref(),
        Some("12.2.1")
    );
}

#[test]
fn only_exact_workspace_dependencies_are_pins() {
    let manifest = "[package]\nname = \"x\"\n[workspace.dependencies]\nblake3 = \"=1.8.7\"\nrmcp = { version = \
        \"=3.8.0\", default-features = false }\nloose = \"1\"\n[workspace.lints.rust]\n";
    let pins = crate_pins(manifest);
    let names: Vec<(&str, &str)> = pins
        .iter()
        .map(|pin| (pin.name.as_str(), pin.current.as_str()))
        .collect();
    assert_eq!(names, vec![("blake3", "1.8.7"), ("rmcp", "3.8.0")]);
}

#[test]
fn prose_versions_are_found_after_their_tool_name() {
    let text = "Use Rust 1.99.1, Bun 1.4.4 and Node.js 26.13.0. A current Rust toolchain.";
    assert_eq!(versions_after_word(text, "Rust "), vec!["1.99.1".to_owned()]);
    assert_eq!(versions_after_word(text, "Node.js "), vec!["26.13.0".to_owned()]);
}

#[test]
fn upstream_documents_yield_their_release() {
    let channel = "[pkg.cargo]\nversion = \"0.1 (x)\"\n[pkg.rust]\nversion = \"1.99.1 (abc 2026-10-01)\"\n";
    assert_eq!(rust_from_channel(channel).as_deref(), Some("1.99.1"));
    let index = serde_json::json!([
        {"version": "v27.0.0", "lts": false},
        {"version": "v26.13.0", "lts": "Name"}
    ]);
    assert_eq!(node_lts_from_index(&index).as_deref(), Some("26.13.0"));
}

#[test]
fn the_verdict_names_each_pin_behind_and_nothing_else() {
    let pin = |name: &str, current: &str| Pin {
        name: name.to_owned(),
        current: current.to_owned(),
        declared_in: "Cargo.toml".to_owned(),
        upstream: Upstream::Crate(name.to_owned()),
    };
    let (lines, behind) = verdict(&[
        (pin("nix", "0.31.3"), "0.32.0".to_owned()),
        (pin("syn", "3.0.9"), "3.0.9".to_owned()),
    ]);
    assert!(behind);
    assert_eq!(
        lines,
        vec!["behind: nix 0.31.3 in Cargo.toml, upstream 0.32.0".to_owned()]
    );
    let (lines, behind) = verdict(&[(pin("syn", "3.0.9"), "3.0.9".to_owned())]);
    assert!(!behind);
    assert_eq!(lines.len(), 1);
}
