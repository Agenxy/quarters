//! Command-line grammar.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::str::FromStr;

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
    /// Clone persistent state into a new independent space.
    Clone(CloneArgs),
    /// Assign stable identity to an inactive legacy space.
    Upgrade(UpgradeArgs),
    /// Change an inactive stable-identity space display name.
    Rename(RenameArgs),
    /// Block new Quarters-managed launches and mutations.
    Freeze(FreezeArgs),
    /// Remove a cooperative freeze marker after exact confirmation.
    Unfreeze(UnfreezeArgs),
    /// Create and manage reusable named creation sources.
    Template(TemplateArgs),
    /// Create and manage named recovery points.
    Snapshot(SnapshotArgs),
    /// Replace a Quarter from a snapshot after capturing recovery.
    Rollback(RollbackArgs),
    /// Export an authenticated plaintext template or snapshot bundle.
    Export(ExportArgs),
    /// Authenticate a bundle and import it as a fresh template.
    Import(ImportArgs),
    /// Create private authentication keys for portable bundles.
    ExportKey(ExportKeyArgs),
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
    /// Manage a verified private OpenSSH agent for one space.
    Agent(AgentArgs),
    /// Inspect or manage compiled OpenSSH invocation adapters.
    Adapter(AdapterArgs),
    /// Inspect capabilities and optionally prepare and validate one environment.
    Doctor(DoctorArgs),
    /// Remove an inactive space after exact-name confirmation.
    Rm(RemoveArgs),
    /// Reclaim abandoned internal creation and deletion state.
    Recover(RecoverArgs),
    /// Print composable shell prompt integration code.
    ShellInit(ShellInitArgs),
    /// Inspect or manage a short command that resolves to Quarters.
    Shortcut(ShortcutArgs),
    /// Serve the local agent interface over bounded MCP stdio.
    Mcp,
    /// Internal Linux launcher used to isolate namespace setup to a child.
    #[command(name = "__linux-launch", hide = true)]
    LinuxLaunch(LinuxLaunchArgs),
    /// Internal launcher which becomes the fixed OpenSSH agent executable.
    #[command(name = "__agent-launch", hide = true)]
    AgentLaunch(AgentLaunchArgs),
}

#[derive(Debug, Args)]
pub(crate) struct CreateArgs {
    /// Portable space name: letters, numbers, hyphens or underscores.
    pub(crate) name: String,

    /// Default absolute shell path. Uses the host SHELL or /bin/sh.
    #[arg(long, value_name = "PATH")]
    pub(crate) shell: Option<PathBuf>,

    /// User-directory layout to create.
    #[arg(long, value_enum, default_value_t = CreateLayout::Profile)]
    pub(crate) layout: CreateLayout,

    /// Preview or import a closed set of host-owned state.
    #[arg(long, value_enum)]
    pub(crate) from_host: Option<CreateHostPolicy>,

    /// Add one explicit regular file beneath host HOME (maximum 32).
    #[arg(long, value_name = "RELATIVE_PATH", requires = "from_host")]
    pub(crate) from_host_path: Vec<PathBuf>,

    /// Validate and print the exact metadata-bound host-fork plan.
    #[arg(long, requires = "from_host", conflicts_with = "confirm_plan")]
    pub(crate) preview: bool,

    /// Execute only the exact 64-hex digest returned by preview.
    #[arg(long, value_name = "DIGEST", requires = "from_host", conflicts_with = "preview")]
    pub(crate) confirm_plan: Option<String>,

    /// Replace generated files selected by the confirmed plan.
    #[arg(long, requires = "from_host")]
    pub(crate) replace_generated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum CreateHostPolicy {
    /// Selected startup and editing convention files; no credentials or history.
    Shell,
}

impl From<CreateHostPolicy> for quarters_core::HostForkPolicy {
    fn from(value: CreateHostPolicy) -> Self {
        match value {
            CreateHostPolicy::Shell => Self::Shell,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct CloneArgs {
    /// Existing source space.
    pub(crate) source: String,

    /// New destination space.
    pub(crate) destination: String,

    /// Validate and summarize without creating the destination.
    #[arg(long, conflicts_with = "confirm_sensitive_state")]
    pub(crate) preview: bool,

    /// Exactly repeat SOURCE to acknowledge copied state may contain credentials.
    #[arg(long, value_name = "SOURCE")]
    pub(crate) confirm_sensitive_state: Option<String>,

    /// Copy derived cache contents instead of recreating cache roots empty.
    #[arg(long)]
    pub(crate) include_cache: bool,
}

#[derive(Debug, Args)]
pub(crate) struct UpgradeArgs {
    /// Existing space to inspect or upgrade.
    pub(crate) name: String,
    /// Validate lease and schema without changing metadata.
    #[arg(long, conflicts_with = "confirm")]
    pub(crate) preview: bool,
    /// Exactly repeat NAME to execute the metadata upgrade.
    #[arg(long, value_name = "NAME")]
    pub(crate) confirm: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RenameArgs {
    /// Current space name.
    pub(crate) previous: String,
    /// New space name.
    pub(crate) name: String,
    /// Validate identities, activity and collisions without changing state.
    #[arg(long, conflicts_with = "confirm")]
    pub(crate) preview: bool,
    /// Exactly repeat PREVIOUS to execute the recoverable rename.
    #[arg(long, value_name = "PREVIOUS")]
    pub(crate) confirm: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct FreezeArgs {
    /// Space name. Defaults to the current Quarter when inside one.
    pub(crate) name: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct UnfreezeArgs {
    /// Space name. Defaults to the current Quarter when inside one.
    pub(crate) name: Option<String>,
    /// Must exactly repeat the resolved space name.
    #[arg(long, value_name = "NAME")]
    pub(crate) confirm: String,
}

#[derive(Debug, Args)]
pub(crate) struct TemplateArgs {
    #[command(subcommand)]
    pub(crate) command: TemplateCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum TemplateCommand {
    /// Capture a named creation source from an inactive Quarter.
    Create(ArtifactCreateArgs),
    /// List named templates and source status.
    List,
    /// Show one template and its integrity metadata.
    Show(ArtifactNameArgs),
    /// Create a fresh Quarter from a verified template.
    Use(TemplateUseArgs),
    /// Change a template's display name without moving content.
    Rename(ArtifactRenameArgs),
    /// Remove one whole template after exact-name confirmation.
    Rm(ArtifactRemoveArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SnapshotArgs {
    #[command(subcommand)]
    pub(crate) command: SnapshotCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SnapshotCommand {
    /// Capture a named recovery point from an inactive Quarter.
    Create(SnapshotCreateArgs),
    /// List snapshots, optionally for one exact current source identity.
    List(SnapshotListArgs),
    /// Show one snapshot and its integrity metadata.
    Show(ArtifactNameArgs),
    /// Recompute and compare one snapshot's canonical digest.
    Verify(ArtifactNameArgs),
    /// Change a snapshot's display name without moving content.
    Rename(ArtifactRenameArgs),
    /// Remove one whole snapshot after exact-name confirmation.
    Rm(ArtifactRemoveArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactCreateArgs {
    /// New artifact display name.
    pub(crate) name: String,
    /// Existing source Quarter.
    #[arg(
        long = "from",
        value_name = "SPACE",
        required_unless_present = "from_active",
        conflicts_with = "from_active"
    )]
    pub(crate) source: Option<String>,
    /// Capture immediately from the current cooperatively frozen Quarter.
    #[arg(long, conflicts_with = "source")]
    pub(crate) from_active: bool,
    /// Validate and summarize without creating an artifact.
    #[arg(long, conflicts_with = "confirm_sensitive_state")]
    pub(crate) preview: bool,
    /// Exactly repeat SPACE to acknowledge captured state may contain credentials.
    #[arg(long, value_name = "SPACE")]
    pub(crate) confirm_sensitive_state: Option<String>,
    /// Include derived cache contents.
    #[arg(long)]
    pub(crate) include_cache: bool,
}

#[derive(Debug, Args)]
pub(crate) struct SnapshotCreateArgs {
    /// Existing source Quarter.
    pub(crate) source: String,
    /// New snapshot display name.
    pub(crate) name: String,
    /// Validate and summarize without creating a snapshot.
    #[arg(long, conflicts_with = "confirm_sensitive_state")]
    pub(crate) preview: bool,
    /// Exactly repeat SPACE to acknowledge captured state may contain credentials.
    #[arg(long, value_name = "SPACE")]
    pub(crate) confirm_sensitive_state: Option<String>,
    /// Omit derived cache contents from this recovery point.
    #[arg(long)]
    pub(crate) exclude_cache: bool,
}

#[derive(Debug, Args)]
pub(crate) struct SnapshotListArgs {
    /// Filter to the exact current identity of this Quarter.
    pub(crate) source: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactNameArgs {
    /// Artifact display name.
    pub(crate) name: String,
}

#[derive(Debug, Args)]
pub(crate) struct TemplateUseArgs {
    /// Template display name.
    pub(crate) name: String,
    /// New destination Quarter.
    pub(crate) destination: String,
    /// Validate and summarize without creating the destination.
    #[arg(long, conflicts_with = "confirm_sensitive_state")]
    pub(crate) preview: bool,
    /// Exactly repeat TEMPLATE to acknowledge it may contain credentials.
    #[arg(long, value_name = "TEMPLATE")]
    pub(crate) confirm_sensitive_state: Option<String>,
    /// Override the captured default shell.
    #[arg(long, value_name = "PATH")]
    pub(crate) shell: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactRenameArgs {
    /// Existing display name.
    pub(crate) previous: String,
    /// New display name.
    pub(crate) name: String,
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactRemoveArgs {
    /// Artifact display name.
    pub(crate) name: String,
    /// Must exactly repeat NAME.
    #[arg(long, value_name = "NAME")]
    pub(crate) confirm: String,
}

#[derive(Debug, Args)]
pub(crate) struct RollbackArgs {
    /// Target Quarter whose identity will be retained.
    pub(crate) target: String,
    /// Snapshot display name to restore.
    pub(crate) snapshot: String,
    /// Name for the automatic pre-rollback recovery snapshot.
    #[arg(long, value_name = "NAME")]
    pub(crate) recovery_name: String,
    /// Validate all sources and bounds without creating or replacing state.
    #[arg(long, conflicts_with_all = ["confirm_space", "confirm_replace_state"])]
    pub(crate) preview: bool,
    /// Exactly repeat SPACE to confirm the target.
    #[arg(long, value_name = "SPACE")]
    pub(crate) confirm_space: Option<String>,
    /// Exactly repeat SPACE to acknowledge complete home replacement.
    #[arg(long, value_name = "SPACE")]
    pub(crate) confirm_replace_state: Option<String>,
    /// Omit derived caches from the automatic recovery snapshot.
    #[arg(long)]
    pub(crate) exclude_recovery_cache: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ExportKind {
    /// Reusable creation source.
    Template,
    /// Named recovery point; imports as a template.
    Snapshot,
}

impl From<ExportKind> for quarters_core::ArtifactKind {
    fn from(value: ExportKind) -> Self {
        match value {
            ExportKind::Template => Self::Template,
            ExportKind::Snapshot => Self::Snapshot,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct ExportArgs {
    /// Artifact category.
    #[arg(value_enum)]
    pub(crate) kind: ExportKind,
    /// Existing artifact display name.
    pub(crate) name: String,
    /// Absolute bundle destination outside the Quarters store.
    #[arg(long, value_name = "PATH")]
    pub(crate) to: PathBuf,
    /// Absolute private 32-byte key file in a protected directory outside the Quarters store.
    #[arg(long, value_name = "PATH")]
    pub(crate) key: PathBuf,
    /// Authenticate inputs and report the exact policy without writing.
    #[arg(long, conflicts_with = "confirm_sensitive_state")]
    pub(crate) preview: bool,
    /// Exactly repeat NAME to acknowledge plaintext sensitive-state export.
    #[arg(long, value_name = "NAME")]
    pub(crate) confirm_sensitive_state: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ImportArgs {
    /// Absolute path to one authenticated bundle.
    pub(crate) bundle: PathBuf,
    /// New local template display name.
    pub(crate) name: String,
    /// Absolute private 32-byte key file in a protected directory outside the Quarters store.
    #[arg(long, value_name = "PATH")]
    pub(crate) key: PathBuf,
    /// Authenticate and return the exact plan digest without mutation.
    #[arg(long, conflicts_with = "confirm_plan")]
    pub(crate) preview: bool,
    /// Execute only the exact digest returned by preview.
    #[arg(long, value_name = "DIGEST")]
    pub(crate) confirm_plan: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ExportKeyArgs {
    #[command(subcommand)]
    pub(crate) command: ExportKeyCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ExportKeyCommand {
    /// Create one no-clobber mode-0600 random key file.
    Create(ExportKeyCreateArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ExportKeyCreateArgs {
    /// Absolute destination in a protected current-user directory.
    pub(crate) path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum CreateLayout {
    /// Minimal shell and CLI state profile.
    Profile,
    /// Expanded home with common personal and platform directories.
    Workspace,
}

impl From<CreateLayout> for quarters_core::SpaceLayout {
    fn from(value: CreateLayout) -> Self {
        match value {
            CreateLayout::Profile => Self::Profile,
            CreateLayout::Workspace => Self::Workspace,
        }
    }
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

    /// Enforce the named native filesystem policy; starts in the Quarter home.
    #[arg(long, value_enum)]
    pub(crate) confinement: Option<ConfinementArg>,

    /// Explicitly inherit one otherwise-blocked host environment variable.
    #[arg(long = "inherit", value_name = "NAME")]
    pub(crate) inherit: Vec<String>,

    /// Admit one existing absolute host data path to Linux confinement.
    #[arg(long = "grant-path", value_name = "ABSOLUTE_PATH:ro|rw")]
    pub(crate) grant_paths: Vec<GrantPathArg>,

    /// Start the shell or command in this existing absolute directory.
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    pub(crate) workdir: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GrantPathArg {
    pub(crate) path: PathBuf,
    pub(crate) access: quarters_core::UserGrantAccess,
}

impl FromStr for GrantPathArg {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (path, access) = value
            .rsplit_once(':')
            .ok_or_else(|| "expected an absolute path followed by :ro or :rw".to_owned())?;
        let access = match access {
            "ro" => quarters_core::UserGrantAccess::ReadOnly,
            "rw" => quarters_core::UserGrantAccess::ReadWrite,
            _ => return Err("grant access must be exactly ro or rw".to_owned()),
        };
        if path.is_empty() || !Path::new(path).is_absolute() {
            return Err("grant path must be absolute".to_owned());
        }
        Ok(Self {
            path: PathBuf::from(path),
            access,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ConfinementArg {
    /// Linux Landlock ABI 3 path policy; unavailable on macOS.
    Filesystem,
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
pub(crate) struct AgentArgs {
    #[command(subcommand)]
    pub(crate) command: AgentCommand,
}

#[derive(Debug, Args)]
pub(crate) struct AdapterArgs {
    #[command(subcommand)]
    pub(crate) command: AdapterCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AdapterCommand {
    /// Inspect the closed managed launcher set without changing it.
    Status(AgentTargetArgs),
    /// Install only absent managed launcher links.
    Install(AgentTargetArgs),
    /// Remove only verified OpenSSH adapter links.
    Remove(AgentTargetArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum AgentCommand {
    /// Inspect process, socket identity and protocol liveness.
    Status(AgentTargetArgs),
    /// Start a private OpenSSH agent, or report the verified active agent.
    Start(AgentTargetArgs),
    /// Stop only an identity-verified private OpenSSH agent.
    Stop(AgentTargetArgs),
    /// Stop and start the private OpenSSH agent.
    Restart(AgentTargetArgs),
    /// Reconcile only dead or protocol-verified private-agent state.
    Recover(AgentRecoverArgs),
}

#[derive(Debug, Args)]
pub(crate) struct AgentTargetArgs {
    /// Space name. Defaults to the current Quarter when inside one.
    pub(crate) name: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct AgentRecoverArgs {
    /// Space whose private-agent state should be reconciled.
    pub(crate) name: String,
    /// Must exactly repeat the space name.
    #[arg(long, value_name = "NAME")]
    pub(crate) confirm: String,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ShellKind {
    /// Z shell integration.
    Zsh,
    /// Bash integration.
    Bash,
}

#[derive(Debug, Args)]
pub(crate) struct ShellInitArgs {
    /// Shell whose integration code should be printed.
    #[arg(value_enum)]
    pub(crate) shell: ShellKind,
}

#[derive(Debug, Args)]
pub(crate) struct ShortcutArgs {
    #[command(subcommand)]
    pub(crate) command: ShortcutCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ShortcutCommand {
    /// Inspect command resolution without changing it.
    Status(ShortcutTargetArgs),
    /// Install a non-overwriting managed shortcut.
    Install(ShortcutTargetArgs),
    /// Remove only a verified Quarters-managed shortcut.
    Remove(ShortcutTargetArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ShortcutTargetArgs {
    /// Short command name. `qts` is recommended; `q` is also available.
    #[arg(default_value = "qts")]
    pub(crate) name: String,

    /// Existing absolute PATH directory for the managed link.
    #[arg(long = "dir", value_name = "PATH")]
    pub(crate) directory: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct LinuxLaunchArgs {
    #[arg(long)]
    pub(crate) space_home: PathBuf,
    #[arg(long)]
    pub(crate) host_home: Option<PathBuf>,
    #[arg(long)]
    pub(crate) runtime_dir: PathBuf,
    #[arg(long)]
    pub(crate) confinement: bool,
    #[arg(long = "store-root")]
    pub(crate) store_root: PathBuf,
    #[arg(long = "request-executable")]
    pub(crate) request_executable: PathBuf,
    #[arg(long = "grant-path")]
    pub(crate) grant_paths: Vec<GrantPathArg>,
    #[arg(long)]
    pub(crate) workdir: Option<PathBuf>,
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) command: Vec<OsString>,
}

#[cfg(test)]
mod tests {
    use super::GrantPathArg;
    use quarters_core::UserGrantAccess;
    use std::path::PathBuf;
    use std::str::FromStr;

    #[test]
    fn grant_path_uses_the_final_colon_as_the_access_separator() -> Result<(), String> {
        let parsed = GrantPathArg::from_str("/tmp/project:variant:rw")?;
        assert_eq!(parsed.path, PathBuf::from("/tmp/project:variant"));
        assert_eq!(parsed.access, UserGrantAccess::ReadWrite);
        Ok(())
    }

    #[test]
    fn grant_path_rejects_relative_paths_and_unknown_access() {
        assert!(GrantPathArg::from_str("relative:ro").is_err());
        assert!(GrantPathArg::from_str("/tmp/project:execute").is_err());
    }
}

#[derive(Debug, Args)]
pub(crate) struct AgentLaunchArgs {
    #[arg(long)]
    pub(crate) space: String,
}
