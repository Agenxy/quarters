//! Command dispatch.

use crate::cli::{Cli, Command, CreateArgs, DoctorArgs, EnterArgs, ExecArgs, ProfileArgs, RemoveArgs};
use crate::{output, process};
use quarters_core::{ErrorKind, HostEnvironment, QuartersError, Result, Space, SpaceName, Store};
use std::path::PathBuf;

pub(crate) fn run(cli: Cli) -> Result<i32> {
    home_view_management_guard(&cli.command)?;
    let store = match cli.root {
        Some(root) => Store::new(root)?,
        None => Store::from_environment()?,
    };
    let host = HostEnvironment::capture();
    match cli.command {
        Command::Create(arguments) => create(&store, &host, arguments, cli.json),
        Command::List => list(&store, cli.json),
        Command::Current => current(cli.json),
        Command::Env(arguments) => environment(&store, &host, &arguments, cli.json),
        Command::Enter(arguments) => enter(&store, &host, arguments, cli.json),
        Command::Exec(arguments) => exec(&store, &host, &arguments, cli.json),
        Command::Host(arguments) => {
            passthrough_json_guard(cli.json).and_then(|()| process::run_host(&arguments.command))
        }
        Command::Doctor(arguments) => doctor(&store, &arguments, cli.json),
        Command::Rm(arguments) => remove(&store, &arguments, cli.json),
        Command::LinuxLaunch(arguments) => {
            passthrough_json_guard(cli.json)?;
            process::linux_launch(&arguments.space_home, &arguments.host_home, &arguments.command)
        }
    }
}

fn create(store: &Store, host: &HostEnvironment, arguments: CreateArgs, json: bool) -> Result<i32> {
    let name = SpaceName::parse(arguments.name)?;
    let shell = arguments.shell.unwrap_or_else(|| default_shell(host));
    let space = store.create(name, shell)?;
    output::print_created(&space, json)?;
    Ok(0)
}

fn list(store: &Store, json: bool) -> Result<i32> {
    output::print_list(&store.list()?, json)?;
    Ok(0)
}

fn current(json: bool) -> Result<i32> {
    let value = std::env::var("QUARTERS_SPACE").unwrap_or_else(|_| "host".to_owned());
    output::print_current(&value, json)?;
    Ok(0)
}

fn environment(store: &Store, host: &HostEnvironment, arguments: &ProfileArgs, json: bool) -> Result<i32> {
    let space = open_space(store, &arguments.name)?;
    let launch = profile_launch(store, &space, host, arguments);
    let values = launch.environment()?.diagnostic_values();
    output::print_environment(&space, &values, json)?;
    Ok(0)
}

fn enter(store: &Store, host: &HostEnvironment, arguments: EnterArgs, json: bool) -> Result<i32> {
    passthrough_json_guard(json)?;
    let space = open_space(store, &arguments.profile.name)?;
    let shell = arguments
        .shell
        .unwrap_or_else(|| space.manifest().default_shell.clone());
    let launch = profile_launch(store, &space, host, &arguments.profile);
    process::run_shell(&launch, &shell, arguments.login)
}

fn exec(store: &Store, host: &HostEnvironment, arguments: &ExecArgs, json: bool) -> Result<i32> {
    passthrough_json_guard(json)?;
    let space = open_space(store, &arguments.profile.name)?;
    let launch = profile_launch(store, &space, host, &arguments.profile);
    launch.run(&arguments.command)
}

fn doctor(store: &Store, arguments: &DoctorArgs, json: bool) -> Result<i32> {
    let space = arguments
        .name
        .as_deref()
        .map(|name| open_space(store, name))
        .transpose()?;
    output::print_doctor(
        &quarters_core::platform::capabilities(),
        &quarters_core::tool_probes(),
        space.as_ref(),
        json,
    )?;
    Ok(0)
}

fn remove(store: &Store, arguments: &RemoveArgs, json: bool) -> Result<i32> {
    if arguments.confirm != arguments.name {
        return Err(
            QuartersError::new(ErrorKind::InvalidInput, "--confirm must exactly repeat the space name").with_hint(
                format!("use --confirm {} only after checking the target", arguments.name),
            ),
        );
    }
    let space = open_space(store, &arguments.name)?;
    store.remove(&space)?;
    output::print_removed(&arguments.name, json)?;
    Ok(0)
}

fn open_space(store: &Store, raw_name: &str) -> Result<Space> {
    store.open(&SpaceName::parse(raw_name.to_owned())?)
}

fn profile_launch<'a>(
    store: &'a Store,
    space: &'a Space,
    host: &'a HostEnvironment,
    profile: &'a ProfileArgs,
) -> process::ProfileLaunch<'a> {
    process::ProfileLaunch {
        store,
        space,
        host,
        home_view: profile.home_view,
        inherited_names: &profile.inherit,
    }
}

fn default_shell(host: &HostEnvironment) -> PathBuf {
    host.get("SHELL")
        .map_or_else(|| PathBuf::from("/bin/sh"), PathBuf::from)
}

fn passthrough_json_guard(json: bool) -> Result<()> {
    if json {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "--json is unavailable for pass-through process commands because child stdout must remain unchanged",
        )
        .with_hint("omit --json, or use 'quarters env' and 'quarters doctor' for structured inspection"));
    }
    Ok(())
}

fn home_view_management_guard(command: &Command) -> Result<()> {
    if std::env::var_os("QUARTERS_NO_HOST_ESCAPE").as_deref() != Some(std::ffi::OsStr::new("home-view")) {
        return Ok(());
    }
    if matches!(
        command,
        Command::Current | Command::LinuxLaunch(_) | Command::Doctor(DoctorArgs { name: None })
    ) {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "space management is unavailable inside Linux home-view because the authoritative store is hidden",
    )
    .with_hint("exit the home-view process tree and run the management command from the host"))
}
