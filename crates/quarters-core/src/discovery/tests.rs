// SPDX-License-Identifier: GPL-3.0-or-later
use super::{DiscoveryChild, DiscoveryLimits, DiscoverySelector, report, snapshot};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

fn private_roots() -> Result<(tempfile::TempDir, std::path::PathBuf, std::path::PathBuf), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let home = temporary.path().join("home");
    let runtime = temporary.path().join("runtime");
    fs::create_dir(&home)?;
    fs::create_dir(&runtime)?;
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
    Ok((temporary, home, runtime))
}

#[test]
fn snapshot_is_metadata_only_for_unreadable_files_and_links() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, home, runtime) = private_roots()?;
    let hostile_name = "do-not-leak-this-name";
    let hostile_target = "/host/secret/do-not-resolve-this-target";
    let unreadable = home.join(hostile_name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o000);
    options.open(&unreadable)?;
    symlink(hostile_target, home.join("opaque-link"))?;
    nix::unistd::mkfifo(&home.join("never-open-fifo"), nix::sys::stat::Mode::S_IRUSR)?;

    let before = snapshot(&home, &runtime, &[DiscoverySelector::Home], DiscoveryLimits::ALPHA)?;
    let result = report(
        "test",
        &before,
        Some(&before),
        DiscoveryChild {
            exit_code: Some(0),
            signal: None,
        },
        DiscoveryLimits::ALPHA,
    );
    let encoded = serde_json::to_string(&result)?;
    assert!(result.complete);
    assert!(!encoded.contains(hostile_name));
    assert!(!encoded.contains(hostile_target));
    assert!(!encoded.contains("opaque-link"));
    assert!(!encoded.contains("never-open-fifo"));
    Ok(())
}

#[test]
fn directory_symlinks_are_never_descended() -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, home, runtime) = private_roots()?;
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside)?;
    fs::write(outside.join("secret"), b"before")?;
    symlink(&outside, home.join("linked-directory"))?;
    let before = snapshot(&home, &runtime, &[DiscoverySelector::Home], DiscoveryLimits::ALPHA)?;
    fs::write(outside.join("secret"), b"after")?;
    let after = snapshot(&home, &runtime, &[DiscoverySelector::Home], DiscoveryLimits::ALPHA)?;
    let result = report(
        "test",
        &before,
        Some(&after),
        DiscoveryChild {
            exit_code: Some(0),
            signal: None,
        },
        DiscoveryLimits::ALPHA,
    );
    assert!(result.complete);
    assert_eq!(result.totals, Some(super::DiscoveryTotals::default()));
    Ok(())
}

#[test]
fn report_classifies_created_modified_replaced_and_deleted() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, home, runtime) = private_roots()?;
    fs::write(home.join(".zshrc"), b"before")?;
    fs::write(home.join("payload"), b"before")?;
    fs::write(home.join("obsolete"), b"before")?;
    let before = snapshot(&home, &runtime, &[DiscoverySelector::Home], DiscoveryLimits::ALPHA)?;

    OpenOptions::new()
        .append(true)
        .open(home.join(".zshrc"))?
        .write_all(b"-after")?;
    fs::write(home.join("replacement"), b"after")?;
    fs::rename(home.join("replacement"), home.join("payload"))?;
    fs::remove_file(home.join("obsolete"))?;
    fs::create_dir(home.join(".ssh"))?;
    fs::write(home.join(".ssh/token"), b"never-read")?;

    let after = snapshot(&home, &runtime, &[DiscoverySelector::Home], DiscoveryLimits::ALPHA)?;
    let result = report(
        "test",
        &before,
        Some(&after),
        DiscoveryChild {
            exit_code: Some(7),
            signal: None,
        },
        DiscoveryLimits::ALPHA,
    );
    let delta = result.delta.as_ref().ok_or("expected a complete delta")?;
    assert_eq!(delta.modified.configuration, 1);
    assert_eq!(delta.replaced.data, 1);
    assert_eq!(delta.deleted.data, 1);
    assert_eq!(delta.created.credential_shaped, 2);
    assert_eq!(result.child.exit_code, Some(7));
    Ok(())
}

#[test]
fn bounds_and_observation_gaps_never_emit_partial_deltas() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, home, runtime) = private_roots()?;
    fs::write(home.join("one"), b"1")?;
    fs::write(home.join("two"), b"2")?;
    let bounded = DiscoveryLimits {
        entries: 1,
        ..DiscoveryLimits::ALPHA
    };
    let before = snapshot(&home, &runtime, &[DiscoverySelector::Home], bounded)?;
    let result = report(
        "test",
        &before,
        Some(&before),
        DiscoveryChild {
            exit_code: Some(0),
            signal: None,
        },
        bounded,
    );
    assert_eq!(result.state, "bounds-exceeded");
    assert!(result.delta.is_none());
    assert!(result.totals.is_none());

    let inaccessible = home.join("inaccessible");
    fs::create_dir(&inaccessible)?;
    fs::set_permissions(&inaccessible, fs::Permissions::from_mode(0o000))?;
    let incomplete = snapshot(&home, &runtime, &[DiscoverySelector::Home], DiscoveryLimits::ALPHA)?;
    let incomplete_report = report(
        "test",
        &incomplete,
        Some(&incomplete),
        DiscoveryChild {
            exit_code: Some(0),
            signal: None,
        },
        DiscoveryLimits::ALPHA,
    );
    assert_eq!(incomplete_report.state, "observation-gap");
    assert!(incomplete_report.delta.is_none());
    assert_eq!(incomplete_report.observation.unreadable_directories, 2);
    assert_eq!(incomplete_report.observation.unreadable_classes.data, 2);
    fs::set_permissions(&inaccessible, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[test]
fn selected_roots_have_independent_entry_budgets() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, home, runtime) = private_roots()?;
    fs::write(home.join("one"), b"1")?;
    fs::write(home.join("two"), b"2")?;
    fs::write(runtime.join("only"), b"1")?;
    let limits = DiscoveryLimits {
        entries: 1,
        ..DiscoveryLimits::ALPHA
    };
    let captured = snapshot(
        &home,
        &runtime,
        &[DiscoverySelector::Home, DiscoverySelector::Runtime],
        limits,
    )?;
    let result = report(
        "test",
        &captured,
        Some(&captured),
        DiscoveryChild {
            exit_code: Some(0),
            signal: None,
        },
        limits,
    );
    let home_report = result
        .roots
        .iter()
        .find(|root| root.selector == DiscoverySelector::Home);
    let runtime_report = result
        .roots
        .iter()
        .find(|root| root.selector == DiscoverySelector::Runtime);
    assert!(home_report.is_some_and(|root| root.bounds_exceeded_pre && !root.complete_pre));
    assert!(runtime_report.is_some_and(|root| root.entries_pre == 1 && root.complete_pre));
    assert_eq!(result.state, "bounds-exceeded");
    assert!(result.delta.is_none());
    Ok(())
}

#[test]
fn every_scan_resource_bound_suppresses_the_delta() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, home, runtime) = private_roots()?;
    fs::create_dir(home.join("directory"))?;
    fs::write(home.join("directory/entry"), b"1")?;
    for limits in [
        DiscoveryLimits {
            depth: 0,
            ..DiscoveryLimits::ALPHA
        },
        DiscoveryLimits {
            relative_path_bytes: 1,
            ..DiscoveryLimits::ALPHA
        },
        DiscoveryLimits {
            pending_name_bytes: 1,
            ..DiscoveryLimits::ALPHA
        },
        DiscoveryLimits {
            phase_milliseconds: 0,
            ..DiscoveryLimits::ALPHA
        },
    ] {
        let captured = snapshot(&home, &runtime, &[DiscoverySelector::Home], limits)?;
        let result = report(
            "test",
            &captured,
            Some(&captured),
            DiscoveryChild {
                exit_code: Some(0),
                signal: None,
            },
            limits,
        );
        assert_eq!(result.state, "bounds-exceeded");
        assert!(result.delta.is_none());
    }
    Ok(())
}

#[test]
fn public_snapshot_rejects_an_unsafe_recursive_depth() -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, home, runtime) = private_roots()?;
    let mut deepest = home.clone();
    for _level in 0..DiscoveryLimits::MAXIMUM_DEPTH {
        deepest.push("d");
        fs::create_dir(&deepest)?;
    }
    let accepted = snapshot(
        &home,
        &runtime,
        &[DiscoverySelector::Home],
        DiscoveryLimits {
            depth: DiscoveryLimits::MAXIMUM_DEPTH,
            ..DiscoveryLimits::ALPHA
        },
    )?;
    let accepted_report = report(
        "test",
        &accepted,
        Some(&accepted),
        DiscoveryChild {
            exit_code: Some(0),
            signal: None,
        },
        DiscoveryLimits {
            depth: DiscoveryLimits::MAXIMUM_DEPTH,
            ..DiscoveryLimits::ALPHA
        },
    );
    assert!(accepted_report.complete);
    let limits = DiscoveryLimits {
        depth: DiscoveryLimits::MAXIMUM_DEPTH + 1,
        ..DiscoveryLimits::ALPHA
    };
    let error = match snapshot(&home, &runtime, &[DiscoverySelector::Home], limits) {
        Ok(_snapshot) => return Err("over-limit discovery depth was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
    Ok(())
}

#[test]
fn replacing_a_selected_root_suppresses_the_delta() -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, home, runtime) = private_roots()?;
    fs::write(home.join("before"), b"before")?;
    let before = snapshot(&home, &runtime, &[DiscoverySelector::Home], DiscoveryLimits::ALPHA)?;
    fs::rename(&home, temporary.path().join("retired-home"))?;
    fs::create_dir(&home)?;
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
    fs::write(home.join("after"), b"after")?;
    let after = snapshot(&home, &runtime, &[DiscoverySelector::Home], DiscoveryLimits::ALPHA)?;
    let result = report(
        "test",
        &before,
        Some(&after),
        DiscoveryChild {
            exit_code: Some(0),
            signal: None,
        },
        DiscoveryLimits::ALPHA,
    );
    assert_eq!(result.state, "root-identity-changed");
    assert!(!result.complete);
    assert!(result.delta.is_none());
    assert!(result.observation.root_identity_changed);
    Ok(())
}
