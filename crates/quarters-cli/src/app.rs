//! Command dispatch.

use crate::cli::{
    Cli, CloneArgs, Command, CreateArgs, DoctorArgs, EnterArgs, ExecArgs, ProfileArgs, RecoverArgs, RemoveArgs,
    StatusArgs,
};
use crate::{output, process};
use quarters_core::{
    EnvironmentPlan, ErrorKind, HostEnvironment, QuartersError, Result, Space, SpaceInspection, SpaceName, Store,
};
use std::path::PathBuf;

pub(crate) fn run(cli: Cli) -> Result<i32> {
    home_view_management_guard(&cli.command)?;
    if let Command::ShellInit(arguments) = &cli.command {
        passthrough_json_guard(cli.json)?;
        print!("{}", crate::shell_init::script(arguments.shell));
        return Ok(0);
    }
    if let Command::Shortcut(arguments) = &cli.command {
        let (action, report) = crate::shortcut::run(arguments)?;
        output::print_shortcut(action, &report, cli.json)?;
        return Ok(0);
    }
    let store = match cli.root {
        Some(root) => Store::new(root)?,
        None => Store::from_environment()?,
    };
    let host = HostEnvironment::capture();
    match cli.command {
        Command::Create(arguments) => create(&store, &host, arguments, cli.json),
        Command::Clone(arguments) => clone_space(&store, &arguments, cli.json),
        Command::List => list(&store, cli.json),
        Command::Status(arguments) => status(&store, &arguments, cli.json),
        Command::Current => current(&store, cli.json),
        Command::Env(arguments) => environment(&store, &host, &arguments, cli.json),
        Command::Enter(arguments) => enter(&store, &host, arguments, cli.json),
        Command::Exec(arguments) => exec(&store, &host, &arguments, cli.json),
        Command::Host(arguments) => {
            passthrough_json_guard(cli.json).and_then(|()| process::run_host(&arguments.command))
        }
        Command::Doctor(arguments) => doctor(&store, &host, &arguments, cli.json),
        Command::Rm(arguments) => remove(&store, &arguments, cli.json),
        Command::Recover(arguments) => recover(&store, &arguments, cli.json),
        Command::ShellInit(_) | Command::Shortcut(_) => Ok(0),
        Command::Mcp => {
            passthrough_json_guard(cli.json)?;
            quarters_mcp::serve_stdio(store, host)?;
            Ok(0)
        }
        Command::LinuxLaunch(arguments) => {
            passthrough_json_guard(cli.json)?;
            process::linux_launch(&arguments.space_home, &arguments.host_home, &arguments.command)
        }
    }
}

fn create(store: &Store, host: &HostEnvironment, arguments: CreateArgs, json: bool) -> Result<i32> {
    let name = SpaceName::parse(arguments.name)?;
    let shell = arguments.shell.unwrap_or_else(|| default_shell(host));
    let space = store.create_with_layout(name, shell, arguments.layout.into())?;
    output::print_created(&space, json)?;
    Ok(0)
}

fn clone_space(store: &Store, arguments: &CloneArgs, json: bool) -> Result<i32> {
    let source = SpaceName::parse(arguments.source.clone())?;
    let destination = SpaceName::parse(arguments.destination.clone())?;
    let report = if arguments.preview {
        store.clone_plan(&source, &destination, arguments.include_cache)?
    } else {
        if arguments.confirm_sensitive_state.as_deref() != Some(source.as_str()) {
            return Err(QuartersError::new(
                ErrorKind::InvalidInput,
                "--confirm-sensitive-state must exactly repeat the source space name",
            )
            .with_hint(format!(
                "run 'quarters clone {source} {destination} --preview', then execute with '--confirm-sensitive-state {source}'"
            )));
        }
        store.clone_space(&source, destination, arguments.include_cache)?
    };
    output::print_clone(&report, json)?;
    Ok(0)
}

fn list(store: &Store, json: bool) -> Result<i32> {
    output::print_list(&store.inspect()?, json)?;
    Ok(0)
}

fn status(store: &Store, arguments: &StatusArgs, json: bool) -> Result<i32> {
    let inspections = arguments.name.as_deref().map_or_else(
        || store.inspect(),
        |name| {
            let name = SpaceName::parse(name.to_owned())?;
            store.inspect_named(&name).map(|inspection| vec![inspection])
        },
    )?;
    let healthy_spaces = inspections
        .iter()
        .filter_map(|inspection| match inspection {
            SpaceInspection::Healthy(space) => Some(space),
            SpaceInspection::Unhealthy { .. } => None,
        })
        .collect::<Vec<_>>();
    let mut lease_states = store.lease_states(&healthy_spaces)?.into_iter();
    let statuses = inspections
        .into_iter()
        .map(|inspection| match inspection {
            SpaceInspection::Healthy(space) => lease_states
                .next()
                .ok_or_else(|| QuartersError::new(ErrorKind::System, "activity observation returned too few states"))
                .map(|lease_state| output::StatusEntry::Healthy { space, lease_state }),
            SpaceInspection::Unhealthy {
                name,
                name_was_lossy,
                error,
            } => Ok(output::StatusEntry::Unhealthy {
                name,
                name_was_lossy,
                error,
            }),
        })
        .collect::<Result<Vec<_>>>()?;
    let current = validated_current_space(store);
    output::print_status(&statuses, current.as_deref(), &crate::shortcut::default_reports(), json)?;
    Ok(0)
}

fn current(store: &Store, json: bool) -> Result<i32> {
    let value = validated_current_space(store).unwrap_or_else(|| "host".to_owned());
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

fn doctor(store: &Store, host: &HostEnvironment, arguments: &DoctorArgs, json: bool) -> Result<i32> {
    let space = arguments
        .name
        .as_deref()
        .map(|name| open_space(store, name))
        .transpose()?;
    let lease_state = space.as_ref().map(|space| store.lease_state(space)).transpose()?;
    if let Some(space) = &space {
        EnvironmentPlan::for_space(space, host, &space.home(), &[])?;
    }
    let recovery = store.recovery_summary();
    output::print_doctor(
        &quarters_core::platform::capabilities(),
        &quarters_core::tool_probes(),
        &crate::shortcut::default_reports(),
        space.as_ref(),
        lease_state,
        recovery.as_ref(),
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
    store.remove(&arguments.name)?;
    output::print_removed(&arguments.name, json)?;
    Ok(0)
}

fn recover(store: &Store, arguments: &RecoverArgs, json: bool) -> Result<i32> {
    if arguments.confirm != "stale-state" {
        return Err(
            QuartersError::new(ErrorKind::InvalidInput, "--confirm must be exactly 'stale-state'")
                .with_hint("run 'quarters doctor' first, then use --confirm stale-state"),
        );
    }
    output::print_recovered(&store.recover()?, json)?;
    Ok(0)
}

fn open_space(store: &Store, raw_name: &str) -> Result<Space> {
    store.open(&SpaceName::parse(raw_name.to_owned())?)
}

fn validated_current_space(store: &Store) -> Option<String> {
    let candidate = SpaceName::parse(std::env::var("QUARTERS_SPACE").ok()?).ok()?;
    match store.inspect_named(&candidate) {
        Ok(SpaceInspection::Healthy(_space)) => Some(candidate.as_str().to_owned()),
        Err(error)
            if error.kind() == ErrorKind::NotFound
                && std::env::var_os("QUARTERS_NO_HOST_ESCAPE").as_deref()
                    == Some(std::ffi::OsStr::new("home-view")) =>
        {
            Some(candidate.as_str().to_owned())
        }
        Ok(SpaceInspection::Unhealthy { .. }) | Err(_) => None,
    }
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
        Command::Current | Command::ShellInit(_) | Command::LinuxLaunch(_) | Command::Doctor(DoctorArgs { name: None })
    ) {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "space management is unavailable inside Linux home-view because the authoritative store is hidden",
    )
    .with_hint("exit the home-view process tree and run the management command from the host"))
}
