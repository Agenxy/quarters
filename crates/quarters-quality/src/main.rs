//! Quarters' native repository quality gate.

mod limits;
mod metrics;
mod scan;

use std::process::ExitCode;

fn main() -> ExitCode {
    let command = std::env::args().nth(1);
    if command.as_deref() != Some("check") {
        eprintln!("usage: quarters-quality check");
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
