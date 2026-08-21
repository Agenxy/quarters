//! Command-line grammar.

use clap::{Args, Parser, Subcommand};
use std::ffi::OsString;
use std::path::PathBuf;

/// Give native processes a persistent alternate user-state profile.
#[derive(Debug, Parser)]
#[command(name = "quarters", version, about, long_about = None)]
pub(crate) struct Cli {
    /// Emit a stable JSON envelope for management and inspection commands.
    #[arg(long, global = true)]
    pub(crate) json: bool,

    /// Use this absolute storage root instead of ~/.quarters.
    #[arg(long, global = true, value_name = "PATH")]
    pub(crate) root: Option<PathBuf>,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Create a private, persistent space.
    Create(CreateArgs),
    /// List each space entry, its health and its stored home.
    List,
    /// Report current and cooperative lease state for spaces.
    Status(StatusArgs),
    /// Print the current space, or "host" outside Quarters.
    Current,
    /// Show the exact environment Quarters would apply.
    Env(ProfileArgs),
    /// Enter an interactive shell in a space.
    Enter(EnterArgs),
    /// Run one native command in a space.
    Exec(ExecArgs),
    /// Run a command with host user-state paths from a baseline space.
    Host(RawCommand),
    /// Inspect capabilities and optionally prepare and validate one environment.
    Doctor(DoctorArgs),
    /// Remove an inactive space after exact-name confirmation.
    Rm(RemoveArgs),
    /// Reclaim abandoned internal creation and deletion state.
    Recover(RecoverArgs),
    /// Serve the local agent interface over bounded MCP stdio.
    Mcp,
    /// Internal Linux launcher used to isolate namespace setup to a child.
    #[command(name = "__linux-launch", hide = true)]
    LinuxLaunch(LinuxLaunchArgs),
}

#[derive(Debug, Args)]
pub(crate) struct CreateArgs {
    /// Portable space name: letters, numbers, hyphens or underscores.
    pub(crate) name: String,

    /// Default absolute shell path. Uses the host SHELL or /bin/sh.
    #[arg(long, value_name = "PATH")]
    pub(crate) shell: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct StatusArgs {
    /// Inspect one space instead of listing every space.
    pub(crate) name: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ProfileArgs {
    /// Space to inspect or launch.
    pub(crate) name: String,

    /// Opt into Linux's experimental bind-mounted passwd-home view.
    #[arg(long)]
    pub(crate) home_view: bool,

    /// Explicitly inherit one otherwise-blocked host environment variable.
    #[arg(long = "inherit", value_name = "NAME")]
    pub(crate) inherit: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct EnterArgs {
    #[command(flatten)]
    pub(crate) profile: ProfileArgs,

    /// Override the space's default shell for this entry.
    #[arg(long, value_name = "PATH")]
    pub(crate) shell: Option<PathBuf>,

    /// Ask the shell for login behavior. This may run host system profiles.
    #[arg(long)]
    pub(crate) login: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ExecArgs {
    #[command(flatten)]
    pub(crate) profile: ProfileArgs,

    /// Command and arguments. Put `--` before options meant for the command.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) command: Vec<OsString>,
}

#[derive(Debug, Args)]
pub(crate) struct RawCommand {
    /// Command and arguments. Put `--` before options meant for the command.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) command: Vec<OsString>,
}

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {
    /// Also validate one space and its computed environment.
    pub(crate) name: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RemoveArgs {
    /// Space to remove.
    pub(crate) name: String,

    /// Must exactly repeat the space name.
    #[arg(long, value_name = "NAME")]
    pub(crate) confirm: String,
}

#[derive(Debug, Args)]
pub(crate) struct RecoverArgs {
    /// Must be exactly "stale-state" before reserved paths are removed.
    #[arg(long, value_name = "stale-state")]
    pub(crate) confirm: String,
}

#[derive(Debug, Args)]
pub(crate) struct LinuxLaunchArgs {
    #[arg(long)]
    pub(crate) space_home: PathBuf,
    #[arg(long)]
    pub(crate) host_home: PathBuf,
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) command: Vec<OsString>,
}
