//! Command dispatch.

use crate::cli::{
    AdapterCommand, AgentCommand, AgentRecoverArgs, AgentTargetArgs, ArtifactCreateArgs, ArtifactRemoveArgs,
    ArtifactRenameArgs, Cli, CloneArgs, Command, CreateArgs, DoctorArgs, EnterArgs, ExecArgs, ProfileArgs, RecoverArgs,
    RemoveArgs, RenameArgs, RollbackArgs, SnapshotCommand, SnapshotCreateArgs, SnapshotListArgs, StatusArgs,
    TemplateCommand, TemplateUseArgs, UpgradeArgs,
};
use crate::{output, process};
use quarters_core::{
    ArtifactInspection, ArtifactKind, ArtifactName, ArtifactOrigin, EnvironmentPlan, ErrorKind, HostEnvironment,
    QuartersError, Result, Space, SpaceInspection, SpaceName, Store,
};
use std::collections::BTreeSet;
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
        Command::Upgrade(arguments) => upgrade(&store, &arguments, cli.json),
        Command::Rename(arguments) => rename(&store, &arguments, cli.json),
        Command::Template(arguments) => template(&store, arguments.command, cli.json),
        Command::Snapshot(arguments) => snapshot(&store, arguments.command, cli.json),
        Command::Rollback(arguments) => rollback(&store, &arguments, cli.json),
        Command::List => list(&store, cli.json),
        Command::Status(arguments) => status(&store, &host, &arguments, cli.json),
        Command::Current => current(&store, cli.json),
        Command::Env(arguments) => environment(&store, &host, &arguments, cli.json),
        Command::Enter(arguments) => enter(&store, &host, arguments, cli.json),
        Command::Exec(arguments) => exec(&store, &host, &arguments, cli.json),
        Command::Host(arguments) => {
            passthrough_json_guard(cli.json).and_then(|()| process::run_host(&arguments.command))
        }
        Command::Agent(arguments) => agent(&store, &host, arguments.command, cli.json),
        Command::Adapter(arguments) => adapter(&store, arguments.command, cli.json),
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
        Command::AgentLaunch(arguments) => {
            passthrough_json_guard(cli.json)?;
            let space = open_space(&store, &arguments.space)?;
            let token = std::env::var("QUARTERS_AGENT_TOKEN").map_err(|_error| {
                QuartersError::new(
                    ErrorKind::Unsupported,
                    "the private-agent launcher has no ownership handoff",
                )
            })?;
            quarters_core::run_ssh_agent_helper(&host, &space, &token)
        }
    }
}

fn upgrade(store: &Store, arguments: &UpgradeArgs, json: bool) -> Result<i32> {
    let name = SpaceName::parse(arguments.name.clone())?;
    let report = if arguments.preview {
        store.upgrade_plan(&name)?
    } else {
        if arguments.confirm.as_deref() != Some(name.as_str()) {
            return Err(QuartersError::new(
                ErrorKind::InvalidInput,
                "--confirm must exactly repeat the legacy space name",
            )
            .with_hint(format!(
                "run 'quarters upgrade {name} --preview', then repeat with '--confirm {name}'"
            )));
        }
        store.upgrade_space(&name)?
    };
    output::print_upgrade(&report, arguments.preview, json)?;
    Ok(0)
}

fn rename(store: &Store, arguments: &RenameArgs, json: bool) -> Result<i32> {
    let previous = SpaceName::parse(arguments.previous.clone())?;
    let name = SpaceName::parse(arguments.name.clone())?;
    let report = if arguments.preview {
        store.rename_plan(&previous, &name)?
    } else {
        if arguments.confirm.as_deref() != Some(previous.as_str()) {
            return Err(QuartersError::new(
                ErrorKind::InvalidInput,
                "--confirm must exactly repeat the current space name",
            )
            .with_hint(format!(
                "run 'quarters rename {previous} {name} --preview', then repeat with '--confirm {previous}'"
            )));
        }
        store.rename_space(&previous, &name)?
    };
    output::print_space_rename(&report, arguments.preview, json)?;
    Ok(0)
}

fn agent(store: &Store, host: &HostEnvironment, command: AgentCommand, json: bool) -> Result<i32> {
    let command = match command {
        AgentCommand::Recover(arguments) => return recover_agent(store, host, &arguments, json),
        command => command,
    };
    let (action, target) = match command {
        AgentCommand::Status(target) => ("status", target),
        AgentCommand::Start(target) => ("start", target),
        AgentCommand::Stop(target) => ("stop", target),
        AgentCommand::Restart(target) => ("restart", target),
        AgentCommand::Recover(_) => return Err(QuartersError::new(ErrorKind::System, "invalid agent dispatch")),
    };
    let name = agent_target(&target)?;
    let space = store.open(&name)?;
    let status = match action {
        "status" => store.ssh_agent_status(&space, host)?,
        "start" => store.start_ssh_agent(&space, host)?,
        "stop" => store.stop_ssh_agent(&space, host)?,
        "restart" => {
            if store.ssh_agent_status(&space, host)?.state == quarters_core::AgentState::Active {
                store.stop_ssh_agent(&space, host)?;
            }
            store.start_ssh_agent(&space, host)?
        }
        _ => return Err(QuartersError::new(ErrorKind::System, "unknown private-agent action")),
    };
    output::print_agent(action, &status, json)?;
    Ok(0)
}

fn recover_agent(store: &Store, host: &HostEnvironment, arguments: &AgentRecoverArgs, json: bool) -> Result<i32> {
    let name = SpaceName::parse(arguments.name.clone())?;
    if arguments.confirm != name.as_str() {
        return Err(
            QuartersError::new(ErrorKind::InvalidInput, "--confirm must exactly repeat the space name").with_hint(
                format!("inspect 'quarters agent status {name}', then repeat with '--confirm {name}'"),
            ),
        );
    }
    let space = store.open(&name)?;
    let status = store.recover_ssh_agent(&space, host)?;
    output::print_agent("recover", &status, json)?;
    Ok(0)
}

fn adapter(store: &Store, command: AdapterCommand, json: bool) -> Result<i32> {
    let (action, target) = match command {
        AdapterCommand::Status(target) => ("status", target),
        AdapterCommand::Install(target) => ("install", target),
        AdapterCommand::Remove(target) => ("remove", target),
    };
    let name = agent_target(&target)?;
    let space = store.open(&name)?;
    let report = match action {
        "status" => crate::adapter::inspect(&space)?,
        "install" => crate::adapter::install(store, &space)?,
        "remove" => crate::adapter::remove(store, &space)?,
        _ => return Err(QuartersError::new(ErrorKind::System, "unknown adapter action")),
    };
    output::print_adapter(action, &report, json)?;
    Ok(0)
}

fn agent_target(arguments: &AgentTargetArgs) -> Result<SpaceName> {
    if let Some(name) = &arguments.name {
        return SpaceName::parse(name.clone());
    }
    let current = std::env::var("QUARTERS_SPACE").map_err(|_| {
        QuartersError::new(ErrorKind::InvalidInput, "a space name is required outside a Quarter")
            .with_hint("run 'quarters agent status NAME'")
    })?;
    SpaceName::parse(current)
}

fn rollback(store: &Store, arguments: &RollbackArgs, json: bool) -> Result<i32> {
    let target = SpaceName::parse(arguments.target.clone())?;
    let snapshot = ArtifactName::parse(arguments.snapshot.clone())?;
    let recovery = ArtifactName::parse(arguments.recovery_name.clone())?;
    let include_cache = !arguments.exclude_recovery_cache;
    let report = if arguments.preview {
        store.rollback_plan(&target, &snapshot, &recovery, include_cache)?
    } else {
        if arguments.confirm_space.as_deref() != Some(target.as_str())
            || arguments.confirm_replace_state.as_deref() != Some(target.as_str())
        {
            return Err(QuartersError::new(
                ErrorKind::InvalidInput,
                "--confirm-space and --confirm-replace-state must each exactly repeat the target space name",
            ));
        }
        store.rollback_space(&target, &snapshot, &recovery, include_cache)?
    };
    if !arguments.preview {
        let space = store.open(&target)?;
        crate::adapter::install(store, &space).map_err(|error| {
            error.with_hint("rollback completed, but managed OpenSSH command links require inspection")
        })?;
    }
    output::print_rollback(&report, json)?;
    Ok(0)
}

fn template(store: &Store, command: TemplateCommand, json: bool) -> Result<i32> {
    match command {
        TemplateCommand::Create(arguments) => create_artifact(store, ArtifactKind::Template, &arguments, json),
        TemplateCommand::List => list_artifacts(store, ArtifactKind::Template, None, json),
        TemplateCommand::Show(arguments) => show_artifact(store, ArtifactKind::Template, &arguments.name, json),
        TemplateCommand::Use(arguments) => use_template(store, &arguments, json),
        TemplateCommand::Rename(arguments) => rename_artifact(store, ArtifactKind::Template, &arguments, json),
        TemplateCommand::Rm(arguments) => remove_artifact(store, ArtifactKind::Template, &arguments, json),
    }
}

fn snapshot(store: &Store, command: SnapshotCommand, json: bool) -> Result<i32> {
    match command {
        SnapshotCommand::Create(arguments) => create_snapshot(store, &arguments, json),
        SnapshotCommand::List(arguments) => list_snapshots(store, &arguments, json),
        SnapshotCommand::Show(arguments) => show_artifact(store, ArtifactKind::Snapshot, &arguments.name, json),
        SnapshotCommand::Verify(arguments) => {
            let name = ArtifactName::parse(arguments.name)?;
            let artifact = store.verify_artifact(ArtifactKind::Snapshot, &name)?;
            output::print_artifact_verified(&artifact, json)?;
            Ok(0)
        }
        SnapshotCommand::Rename(arguments) => rename_artifact(store, ArtifactKind::Snapshot, &arguments, json),
        SnapshotCommand::Rm(arguments) => remove_artifact(store, ArtifactKind::Snapshot, &arguments, json),
    }
}

fn create_artifact(store: &Store, kind: ArtifactKind, arguments: &ArtifactCreateArgs, json: bool) -> Result<i32> {
    let source = SpaceName::parse(arguments.source.clone())?;
    let name = ArtifactName::parse(arguments.name.clone())?;
    let report = if arguments.preview {
        store.artifact_plan(kind, &source, &name, arguments.include_cache)?
    } else {
        require_sensitive_confirmation(arguments.confirm_sensitive_state.as_deref(), &source)?;
        store.create_artifact(kind, &source, name, arguments.include_cache, ArtifactOrigin::User)?
    };
    output::print_artifact_report(&report, json)?;
    Ok(0)
}

fn create_snapshot(store: &Store, arguments: &SnapshotCreateArgs, json: bool) -> Result<i32> {
    let source = SpaceName::parse(arguments.source.clone())?;
    let name = ArtifactName::parse(arguments.name.clone())?;
    let include_cache = !arguments.exclude_cache;
    let report = if arguments.preview {
        store.artifact_plan(ArtifactKind::Snapshot, &source, &name, include_cache)?
    } else {
        require_sensitive_confirmation(arguments.confirm_sensitive_state.as_deref(), &source)?;
        store.create_artifact(
            ArtifactKind::Snapshot,
            &source,
            name,
            include_cache,
            ArtifactOrigin::User,
        )?
    };
    output::print_artifact_report(&report, json)?;
    Ok(0)
}

fn use_template(store: &Store, arguments: &TemplateUseArgs, json: bool) -> Result<i32> {
    let name = ArtifactName::parse(arguments.name.clone())?;
    let destination = SpaceName::parse(arguments.destination.clone())?;
    let report = if arguments.preview {
        store.template_use_plan(&name, &destination, arguments.shell.clone())?
    } else {
        if arguments.confirm_sensitive_state.as_deref() != Some(name.as_str()) {
            return Err(QuartersError::new(
                ErrorKind::InvalidInput,
                "--confirm-sensitive-state must exactly repeat the template name",
            ));
        }
        store.use_template(&name, &destination, arguments.shell.clone())?
    };
    if !arguments.preview {
        install_created_commands(store, &destination)?;
    }
    output::print_template_use(&report, json)?;
    Ok(0)
}

fn list_snapshots(store: &Store, arguments: &SnapshotListArgs, json: bool) -> Result<i32> {
    let source = arguments
        .source
        .as_deref()
        .map(|value| store.open(&SpaceName::parse(value.to_owned())?))
        .transpose()?;
    list_artifacts(store, ArtifactKind::Snapshot, source.as_ref(), json)
}

fn list_artifacts(store: &Store, kind: ArtifactKind, source: Option<&Space>, json: bool) -> Result<i32> {
    let inspections = store
        .inspect_artifacts(kind)?
        .into_iter()
        .filter(|inspection| match (source, inspection) {
            (Some(source), ArtifactInspection::Healthy { artifact, .. }) => {
                artifact.manifest().source_identity.matches(source)
            }
            (Some(_), ArtifactInspection::Unhealthy { .. }) => false,
            (None, _) => true,
        })
        .collect::<Vec<_>>();
    output::print_artifact_list(kind, &inspections, json)?;
    Ok(0)
}

fn show_artifact(store: &Store, kind: ArtifactKind, raw_name: &str, json: bool) -> Result<i32> {
    let name = ArtifactName::parse(raw_name.to_owned())?;
    let (artifact, source_status) = store.open_artifact_with_status(kind, &name)?;
    output::print_artifact(&artifact, source_status, json)?;
    Ok(0)
}

fn rename_artifact(store: &Store, kind: ArtifactKind, arguments: &ArtifactRenameArgs, json: bool) -> Result<i32> {
    let previous = ArtifactName::parse(arguments.previous.clone())?;
    let name = ArtifactName::parse(arguments.name.clone())?;
    let report = store.rename_artifact(kind, &previous, &name)?;
    output::print_artifact_mutation(&report, json)?;
    Ok(0)
}

fn remove_artifact(store: &Store, kind: ArtifactKind, arguments: &ArtifactRemoveArgs, json: bool) -> Result<i32> {
    let name = ArtifactName::parse(arguments.name.clone())?;
    if arguments.confirm != arguments.name {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "--confirm must exactly repeat the artifact name",
        ));
    }
    let report = store.remove_artifact(kind, &name)?;
    output::print_artifact_mutation(&report, json)?;
    Ok(0)
}

fn require_sensitive_confirmation(confirmation: Option<&str>, source: &SpaceName) -> Result<()> {
    if confirmation == Some(source.as_str()) {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::InvalidInput,
        "--confirm-sensitive-state must exactly repeat the source space name",
    ))
}

fn create(store: &Store, host: &HostEnvironment, arguments: CreateArgs, json: bool) -> Result<i32> {
    let name = SpaceName::parse(arguments.name)?;
    let shell = arguments.shell.unwrap_or_else(|| default_shell(host));
    let space = store.create_with_layout(name.clone(), shell, arguments.layout.into())?;
    install_created_commands(store, &name)?;
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
        store.clone_space(&source, destination.clone(), arguments.include_cache)?
    };
    if !arguments.preview {
        install_created_commands(store, &destination)?;
    }
    output::print_clone(&report, json)?;
    Ok(0)
}

fn install_created_commands(store: &Store, name: &SpaceName) -> Result<()> {
    let space = store.open(name)?;
    crate::adapter::install(store, &space).map(|_report| ()).map_err(|error| {
        error.with_hint(format!(
            "space '{name}' was published, but managed commands are incomplete; inspect 'quarters adapter status {name}', then retry installation"
        ))
    })
}

fn list(store: &Store, json: bool) -> Result<i32> {
    let rollbacks = store.rollback_inventory()?;
    output::print_list(&store.inspect()?, &rollbacks.observations, &rollbacks.issues, json)?;
    Ok(0)
}

fn status(store: &Store, host: &HostEnvironment, arguments: &StatusArgs, json: bool) -> Result<i32> {
    let unfiltered = arguments.name.is_none();
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
    let mut statuses = inspections
        .into_iter()
        .map(|inspection| match inspection {
            SpaceInspection::Healthy(space) => lease_states
                .next()
                .ok_or_else(|| QuartersError::new(ErrorKind::System, "activity observation returned too few states"))
                .map(|lease_state| {
                    let agent_state = if unfiltered {
                        "not-inspected".to_owned()
                    } else {
                        store.ssh_agent_status(&space, host).map_or_else(
                            |_error| "unavailable".to_owned(),
                            |status| status.state.as_str().to_owned(),
                        )
                    };
                    output::StatusEntry::Healthy {
                        space,
                        lease_state,
                        agent_state,
                    }
                }),
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
    if unfiltered {
        let rollback_inventory = store.rollback_inventory()?;
        let rollbacks = rollback_inventory.observations;
        let rollback_issues = rollback_inventory.issues;
        statuses.retain(|status| {
            !rollbacks
                .iter()
                .any(|rollback| rollback.target.as_str() == status.name())
                && !rollback_issues.iter().any(|issue| {
                    issue
                        .target
                        .as_ref()
                        .is_some_and(|target| target.as_str() == status.name())
                })
        });
        let mut represented_issue_targets = rollbacks
            .iter()
            .map(|rollback| rollback.target.clone())
            .collect::<BTreeSet<_>>();
        statuses.extend(
            rollbacks
                .into_iter()
                .map(|observation| output::StatusEntry::Rollback { observation }),
        );
        statuses.extend(rollback_issues.into_iter().filter_map(|issue| {
            let target = issue.target.as_ref()?;
            represented_issue_targets
                .insert(target.clone())
                .then_some(output::StatusEntry::RollbackIssue { issue })
        }));
        statuses.sort_by(|left, right| left.name().cmp(right.name()));
    }
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
    crate::adapter::warn_if_incomplete(&space);
    let shell = arguments
        .shell
        .unwrap_or_else(|| space.manifest().default_shell.clone());
    let launch = profile_launch(store, &space, host, &arguments.profile);
    process::run_shell(&launch, &shell, arguments.login)
}

fn exec(store: &Store, host: &HostEnvironment, arguments: &ExecArgs, json: bool) -> Result<i32> {
    passthrough_json_guard(json)?;
    let space = open_space(store, &arguments.profile.name)?;
    crate::adapter::warn_if_incomplete(&space);
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
    let agent_status = space
        .as_ref()
        .map(|space| store.ssh_agent_status(space, host))
        .transpose()?;
    let adapters = space.as_ref().map(crate::adapter::inspect).transpose()?;
    let tools = crate::adapter::tool_probes(adapters.as_ref());
    let environment_validated = space
        .as_ref()
        .map(|space| {
            let blocked = agent_status.as_ref().is_some_and(|status| {
                matches!(
                    status.state,
                    quarters_core::AgentState::Starting
                        | quarters_core::AgentState::Stopping
                        | quarters_core::AgentState::Stale
                )
            });
            if blocked {
                Ok(false)
            } else {
                EnvironmentPlan::for_space(space, host, &space.home(), &[]).map(|_plan| true)
            }
        })
        .transpose()?;
    let recovery = store.recovery_summary();
    output::print_doctor(
        &quarters_core::platform::capabilities(),
        &tools,
        &crate::shortcut::default_reports(),
        output::DoctorSpace {
            space: space.as_ref(),
            environment_validated,
            lease_state,
            agent_status: agent_status.as_ref(),
            adapters: adapters.as_ref(),
        },
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
    let surviving = SpaceName::parse(arguments.name.clone())
        .ok()
        .and_then(|name| store.open(&name).ok())
        .and_then(|space| {
            Some((
                surviving_artifacts(store, ArtifactKind::Template, &space).ok()?,
                surviving_artifacts(store, ArtifactKind::Snapshot, &space).ok()?,
            ))
        });
    store.remove(&arguments.name)?;
    output::print_removed(&arguments.name, surviving, json)?;
    Ok(0)
}

fn surviving_artifacts(store: &Store, kind: ArtifactKind, space: &Space) -> Result<usize> {
    Ok(store
        .inspect_artifacts(kind)?
        .into_iter()
        .filter(|inspection| {
            matches!(
                inspection,
                ArtifactInspection::Healthy { artifact, .. }
                    if artifact.manifest().source_identity.matches(space)
            )
        })
        .count())
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
    let name = SpaceName::parse(raw_name.to_owned())?;
    match store.inspect_named(&name)? {
        SpaceInspection::Healthy(space) => Ok(space),
        SpaceInspection::Unhealthy { error, .. } => Err(error),
    }
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
        Command::Current
            | Command::ShellInit(_)
            | Command::LinuxLaunch(_)
            | Command::AgentLaunch(_)
            | Command::Doctor(DoctorArgs { name: None })
    ) {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "space management is unavailable inside Linux home-view because the authoritative store is hidden",
    )
    .with_hint("exit the home-view process tree and run the management command from the host"))
}
