// SPDX-License-Identifier: GPL-3.0-or-later
//! Quarters' native repository quality gate.

mod drift;
mod limits;
mod metrics;
mod release;
mod scan;

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next();
    if command.as_deref() == Some("release-binary") {
        return check_release_binaries(&arguments.collect::<Vec<_>>());
    }
    if command.as_deref() == Some("drift") {
        return match std::env::current_dir() {
            Ok(root) => ExitCode::from(drift::run(&root)),
            Err(error) => {
                eprintln!("quarters-quality drift: {error}");
                ExitCode::from(2)
            }
        };
    }
    if command.as_deref() != Some("check") {
        eprintln!("usage: quarters-quality check | quarters-quality drift | quarters-quality release-binary PATH...");
        return ExitCode::from(2);
    }
    match scan::check_repository() {
        Ok(()) => {
            println!("quarters-quality: all structural and repository checks passed");
            ExitCode::SUCCESS
        }
        Err(violations) => {
            for violation in violations {
                eprintln!("{violation}");
            }
            ExitCode::from(1)
        }
    }
}

fn check_release_binaries(paths: &[String]) -> ExitCode {
    if paths.is_empty() {
        eprintln!("usage: quarters-quality release-binary PATH...");
        return ExitCode::from(2);
    }
    let failures: Vec<String> = paths
        .iter()
        .filter_map(|path| release::check_release_binary(std::path::Path::new(path)).err())
        .collect();
    if failures.is_empty() {
        println!("quarters-quality: release binaries carry no test hooks");
        return ExitCode::SUCCESS;
    }
    for failure in failures {
        eprintln!("{failure}");
    }
    ExitCode::from(1)
}
