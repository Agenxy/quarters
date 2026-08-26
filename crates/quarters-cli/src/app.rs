//! Command dispatch.

use crate::cli::{
    ArtifactCreateArgs, ArtifactRemoveArgs, ArtifactRenameArgs, Cli, CloneArgs, Command, CreateArgs, DoctorArgs,
    EnterArgs, ExecArgs, ProfileArgs, RecoverArgs, RemoveArgs, RollbackArgs, SnapshotCommand, SnapshotCreateArgs,
    SnapshotListArgs, StatusArgs, TemplateCommand, TemplateUseArgs,
};
use crate::{output, process};
use quarters_core::{
    ArtifactInspection, ArtifactKind, ArtifactName, ArtifactOrigin, EnvironmentPlan, ErrorKind, HostEnvironment,
    QuartersError, Result, SourceStatus, Space, SpaceInspection, SpaceName, Store,
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
        Command::Template(arguments) => template(&store, arguments.command, cli.json),
        Command::Snapshot(arguments) => snapshot(&store, arguments.command, cli.json),
        Command::Rollback(arguments) => rollback(&store, &arguments, cli.json),
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
    let artifact = store.open_artifact(kind, &name)?;
    let source_status = match store.open(&artifact.manifest().source_identity.name) {
        Ok(space) if artifact.manifest().source_identity.matches(&space) => SourceStatus::Present,
        Ok(_) | Err(_) => SourceStatus::Orphaned,
    };
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
    let rollbacks = store.rollback_inventory()?;
    output::print_list(&store.inspect()?, &rollbacks.observations, &rollbacks.issues, json)?;
    Ok(0)
}

fn status(store: &Store, arguments: &StatusArgs, json: bool) -> Result<i32> {
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
