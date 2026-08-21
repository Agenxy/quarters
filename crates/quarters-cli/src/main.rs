//! Quarters command-line entry point.

mod app;
mod cli;
mod output;
mod process;

use clap::Parser;
use cli::Cli;
use quarters_core::QuartersError;
use std::process::ExitCode;

fn main() -> ExitCode {
    let json_requested = std::env::args_os()
        .take_while(|argument| argument != "--")
        .any(|argument| argument == "--json");
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if json_requested {
                output::print_parse_error(&error);
            } else if let Err(print_error) = error.print() {
                eprintln!("quarters: could not print command help: {print_error}");
            }
            return exit_code(error.exit_code());
        }
    };
    match app::run(cli) {
        Ok(code) => exit_code(code),
        Err(error) => {
            output::print_error(&error, json_requested);
            ExitCode::from(error_exit_code(&error))
        }
    }
}

fn exit_code(code: i32) -> ExitCode {
    let code = u8::try_from(code.clamp(0, 255)).unwrap_or(1);
    ExitCode::from(code)
}

fn error_exit_code(error: &QuartersError) -> u8 {
    use quarters_core::ErrorKind;
    match error.kind() {
        ErrorKind::InvalidInput => 2,
        ErrorKind::NotFound => 3,
        ErrorKind::AlreadyExists => 4,
        ErrorKind::SpaceActive => 5,
        ErrorKind::Unsupported => 6,
        ErrorKind::CorruptState => 7,
        ErrorKind::ResourceLimit => 8,
        ErrorKind::System => 1,
    }
}
