//! Native child-process launch and host escape behavior.

use quarters_core::platform;
use quarters_core::{
    ConfinementRequest, EnvironmentPlan, ErrorKind, HostEnvironment, QuartersError, Result, Space, Store,
    UserConfinementGrant,
};
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};

static RUNTIME_COPY_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) struct ProfileLaunch<'a> {
    pub(crate) store: &'a Store,
    pub(crate) space: &'a Space,
    pub(crate) host: &'a HostEnvironment,
    pub(crate) home_view: bool,
    pub(crate) confinement: bool,
    pub(crate) inherited_names: &'a [String],
    pub(crate) user_grants: &'a [crate::cli::GrantPathArg],
    pub(crate) working_directory: Option<&'a Path>,
}

impl ProfileLaunch<'_> {
    pub(crate) fn environment_and_confinement(
        &self,
    ) -> Result<(EnvironmentPlan, Option<quarters_core::ConfinementPlan>)> {
        self.validate_options()?;
        if self.confinement {
            let status = platform::capabilities().confinement;
            if !status.available {
                return Err(QuartersError::new(
                    ErrorKind::Unsupported,
                    format!(
                        "--confinement filesystem is {} on this host: {}",
                        status.status, status.detail
                    ),
                )
                .with_hint("omit --confinement filesystem for portable state redirection"));
            }
        }
        let effective_home = self.effective_home()?;
        let mut environment = EnvironmentPlan::for_space(self.space, self.host, &effective_home, self.inherited_names)?;
        let plan = self.confinement_plan(&environment)?;
        if let Some(plan) = plan.as_ref() {
            environment.apply_filesystem_confinement(plan, &effective_home)?;
        }
        Ok((environment, plan))
    }

    pub(crate) fn confinement_plan(
        &self,
        environment: &EnvironmentPlan,
    ) -> Result<Option<quarters_core::ConfinementPlan>> {
        if !self.confinement {
            return Ok(None);
        }
        let effective_home = self.effective_home()?;
        let runtime = required_environment_path(environment, "XDG_RUNTIME_DIR")?;
        let current_executable = current_executable()?;
        let user_grants = self.user_confinement_grants();
        platform::confinement_plan(&ConfinementRequest {
            space_home: &self.space.home(),
            effective_home: &effective_home,
            runtime: &runtime,
            store_root: self.store.root(),
            current_executable: &current_executable,
            request_executable: None,
            host_path: self.host.get("PATH"),
            user_grants: &user_grants,
            working_directory: self.working_directory,
            home_view: self.home_view,
        })
        .map(Some)
    }

    pub(crate) fn run(&self, raw_command: &[OsString]) -> Result<i32> {
        let (program, arguments) = split_command(raw_command)?;
        let _lease = self.store.lease(self.space)?;
        let (environment, confinement) = self.environment_and_confinement()?;
        let status = if self.home_view || self.confinement {
            self.run_linux_launcher(program, arguments, &environment, confinement.as_ref())?
        } else {
            run_direct(
                program,
                arguments,
                &environment,
                self.resolved_baseline_workdir()?.as_deref(),
            )?
        };
        Ok(status_code(status))
    }

    fn effective_home(&self) -> Result<PathBuf> {
        if !self.home_view {
            return Ok(self.space.home());
        }
        let capabilities = platform::capabilities();
        if !capabilities.home_view.available {
            return Err(QuartersError::new(
                ErrorKind::Unsupported,
                format!(
                    "--home-view is {} on this host: {}",
                    capabilities.home_view.status, capabilities.home_view.detail
                ),
            )
            .with_hint("omit --home-view for portable state redirection"));
        }
        Self::host_home()
    }

    fn run_linux_launcher(
        &self,
        program: &OsStr,
        arguments: &[OsString],
        environment: &EnvironmentPlan,
        confinement: Option<&quarters_core::ConfinementPlan>,
    ) -> Result<ExitStatus> {
        let current_executable = current_executable()?;
        install_runtime_binary(&current_executable, environment)?;
        let runtime = required_environment_path(environment, "XDG_RUNTIME_DIR")?;
        let mut command = Command::new(&current_executable);
        command
            .arg("__linux-launch")
            .arg("--space-home")
            .arg(self.space.home())
            .arg("--runtime-dir")
            .arg(runtime)
            .arg("--store-root")
            .arg(self.store.root())
            .arg("--request-executable")
            .arg(&current_executable);
        if self.home_view {
            command.arg("--host-home").arg(Self::host_home()?);
        }
        if self.confinement {
            command.arg("--confinement");
            if let Some(plan) = confinement
                && plan.omitted_host_path_entries > 0
            {
                eprintln!(
                    "quarters: filesystem confinement omitted {} resolvable host PATH entr{}; inspect 'quarters env {} --confinement filesystem'",
                    plan.omitted_host_path_entries,
                    if plan.omitted_host_path_entries == 1 {
                        "y"
                    } else {
                        "ies"
                    },
                    self.space.manifest().name
                );
            }
        }
        for grant in self.user_grants {
            let mut encoded = grant.path.as_os_str().to_owned();
            encoded.push(":");
            encoded.push(grant.access.as_str());
            command.arg("--grant-path").arg(encoded);
        }
        if let Some(workdir) = self.working_directory {
            command.arg("--workdir").arg(workdir);
        }
        command.arg("--").arg(program).args(arguments);
        environment.apply(&mut command);
        command
            .status()
            .map_err(|error| process_error("start Linux namespace launcher", program, error))
    }

    fn host_home() -> Result<PathBuf> {
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .map_err(|error| {
                QuartersError::new(ErrorKind::System, "could not resolve the current account home").with_source(error)
            })?
            .ok_or_else(|| QuartersError::new(ErrorKind::Unsupported, "the current account has no passwd record"))?;
        if user.dir.is_absolute() {
            return Ok(user.dir);
        }
        Err(QuartersError::new(
            ErrorKind::CorruptState,
            "the current account passwd home is not absolute",
        ))
    }

    fn validate_options(&self) -> Result<()> {
        if !self.user_grants.is_empty() && !cfg!(target_os = "linux") {
            return Err(QuartersError::new(
                ErrorKind::Unsupported,
                "--grant-path is available only with Linux filesystem confinement",
            )
            .with_hint("omit --grant-path on macOS; --workdir remains portable"));
        }
        if !self.user_grants.is_empty() && !self.confinement {
            return Err(QuartersError::new(
                ErrorKind::InvalidInput,
                "--grant-path requires --confinement filesystem on Linux",
            ));
        }
        self.resolved_baseline_workdir().map(|_path| ())
    }

    fn resolved_baseline_workdir(&self) -> Result<Option<PathBuf>> {
        self.working_directory
            .map(platform::resolve_existing_working_directory)
            .transpose()
    }

    fn user_confinement_grants(&self) -> Vec<UserConfinementGrant> {
        self.user_grants
            .iter()
            .map(|grant| UserConfinementGrant {
                path: grant.path.clone(),
                access: grant.access,
            })
            .collect()
    }
}

pub(crate) fn run_shell(launch: &ProfileLaunch<'_>, shell: &Path, login: bool) -> Result<i32> {
    let executable = fs::metadata(shell).is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0);
    if !shell.is_absolute() || !executable {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            format!(
                "shell must be an existing absolute executable file: {}",
                shell.display()
            ),
        ));
    }
    let mut command = vec![shell.as_os_str().to_owned()];
    if login {
        command.push(OsString::from("-l"));
    }
    launch.run(&command)
}

pub(crate) fn run_host(raw_command: &[OsString]) -> Result<i32> {
    let (program, arguments) = split_command(raw_command)?;
    if std::env::var_os("QUARTERS_SPACE").is_none() {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "'quarters host' must be run from inside a space",
        ));
    }
    if let Some(mode) = std::env::var_os("QUARTERS_NO_HOST_ESCAPE") {
        return Err(QuartersError::new(
            ErrorKind::Unsupported,
            format!("host escape is disabled in {} mode", mode.to_string_lossy()),
        )
        .with_hint("exit the space and run the command from the host shell"));
    }
    let mut command = Command::new(program);
    command.args(arguments);
    for (name, value) in quarters_core::host_command_environment() {
        match value {
            Some(value) => {
                command.env(name, value);
            }
            None => {
                command.env_remove(name);
            }
        }
    }
    let status = command
        .status()
        .map_err(|error| process_error("start host command", program, error))?;
    Ok(status_code(status))
}

pub(crate) struct LinuxLaunchRequest<'a> {
    pub(crate) space_home: &'a Path,
    pub(crate) host_home: Option<&'a Path>,
    pub(crate) runtime: &'a Path,
    pub(crate) store_root: &'a Path,
    pub(crate) request_executable: &'a Path,
    pub(crate) confinement: bool,
    pub(crate) user_grants: &'a [crate::cli::GrantPathArg],
    pub(crate) working_directory: Option<&'a Path>,
    pub(crate) raw_command: &'a [OsString],
}

pub(crate) fn linux_launch(request: &LinuxLaunchRequest<'_>) -> Result<i32> {
    let (program, arguments) = split_command(request.raw_command)?;
    let effective_home = request.host_home.unwrap_or(request.space_home);
    if !request.user_grants.is_empty() && !request.confinement {
        return Err(QuartersError::new(
            ErrorKind::InvalidInput,
            "internal user grants require filesystem confinement",
        ));
    }
    let user_grants = request
        .user_grants
        .iter()
        .map(|grant| UserConfinementGrant {
            path: grant.path.clone(),
            access: grant.access,
        })
        .collect::<Vec<_>>();
    let launcher_executable = current_executable()?;
    let confinement_plan = if request.confinement {
        Some(platform::confinement_plan(&ConfinementRequest {
            space_home: request.space_home,
            effective_home,
            runtime: request.runtime,
            store_root: request.store_root,
            current_executable: &launcher_executable,
            request_executable: Some(request.request_executable),
            host_path: None,
            user_grants: &user_grants,
            working_directory: request.working_directory,
            home_view: request.host_home.is_some(),
        })?)
    } else {
        None
    };
    let prepared_confinement = confinement_plan
        .as_ref()
        .map(platform::prepare_filesystem_confinement)
        .transpose()?;
    let baseline_workdir = if confinement_plan.is_none() {
        request
            .working_directory
            .map(|path| platform::resolve_home_view_working_directory(path, request.space_home, effective_home))
            .transpose()?
    } else {
        None
    };
    if let Some(host_home) = request.host_home {
        platform::enter_home_view(request.space_home, host_home, request.runtime)?;
    }
    if let Some(plan) = confinement_plan.as_ref() {
        std::env::set_current_dir(&plan.working_directory).map_err(|error| {
            QuartersError::io("enter the confined working directory", &plan.working_directory, error)
        })?;
    } else if let Some(workdir) = baseline_workdir {
        std::env::set_current_dir(&workdir)
            .map_err(|error| QuartersError::io("enter requested working directory", &workdir, error))?;
    }
    let confined_executable = if let Some(plan) = confinement_plan.as_ref() {
        let mapped = map_home_view_program(program, request.space_home, effective_home);
        let path = std::env::var_os("PATH")
            .ok_or_else(|| QuartersError::new(ErrorKind::CorruptState, "confined launcher has no executable PATH"))?;
        Some(platform::resolve_confined_executable(&mapped, &path, plan)?)
    } else {
        None
    };
    if let Some(prepared) = prepared_confinement {
        platform::enter_filesystem_confinement(prepared)?;
    }
    if let Some(executable) = confined_executable {
        let (program, descriptor) = executable.into_parts();
        return exec_confined_descriptor(&descriptor, &program, arguments);
    }
    let program = PathBuf::from(program);
    let error = std::os::unix::process::CommandExt::exec(Command::new(&program).args(arguments));
    Err(process_error(
        "replace the namespace launcher",
        program.as_os_str(),
        error,
    ))
}

#[cfg(target_os = "linux")]
fn exec_confined_descriptor(descriptor: &File, program: &Path, arguments: &[OsString]) -> Result<i32> {
    use nix::errno::Errno;
    use nix::fcntl::{AtFlags, FcntlArg, FdFlag, fcntl};
    use nix::unistd::execveat;

    let argument_storage = std::iter::once(program.as_os_str())
        .chain(arguments.iter().map(OsString::as_os_str))
        .map(execution_c_string)
        .collect::<Result<Vec<_>>>()?;
    let argument_refs = argument_storage.iter().map(CString::as_c_str).collect::<Vec<_>>();
    let environment_storage = std::env::vars_os()
        .map(|(name, value)| {
            let mut entry = name.into_vec();
            entry.push(b'=');
            entry.extend(value.into_vec());
            CString::new(entry).map_err(|error| {
                QuartersError::new(
                    ErrorKind::CorruptState,
                    "process environment contains an invalid NUL byte",
                )
                .with_source(error)
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let environment_refs = environment_storage.iter().map(CString::as_c_str).collect::<Vec<_>>();
    match execveat(
        descriptor,
        c"",
        &argument_refs,
        &environment_refs,
        AtFlags::AT_EMPTY_PATH,
    ) {
        Ok(never) => match never {},
        Err(Errno::ENOENT) => {
            fcntl(descriptor, FcntlArg::F_SETFD(FdFlag::empty())).map_err(|error| {
                QuartersError::new(ErrorKind::System, "could not prepare a script executable descriptor")
                    .with_source(error)
            })?;
            match execveat(
                descriptor,
                c"",
                &argument_refs,
                &environment_refs,
                AtFlags::AT_EMPTY_PATH,
            ) {
                Ok(never) => match never {},
                Err(error) => Err(executable_descriptor_error(program, error)),
            }
        }
        Err(error) => Err(executable_descriptor_error(program, error)),
    }
}

#[cfg(not(target_os = "linux"))]
fn exec_confined_descriptor(_descriptor: &File, program: &Path, _arguments: &[OsString]) -> Result<i32> {
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        format!(
            "descriptor-bound confinement execution is unavailable for {}",
            program.display()
        ),
    ))
}

#[cfg(target_os = "linux")]
fn execution_c_string(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|error| {
        QuartersError::new(ErrorKind::InvalidInput, "command arguments contain an invalid NUL byte").with_source(error)
    })
}

#[cfg(target_os = "linux")]
fn executable_descriptor_error(program: &Path, error: nix::errno::Errno) -> QuartersError {
    process_error(
        "replace the namespace launcher through its stable descriptor",
        program.as_os_str(),
        std::io::Error::from_raw_os_error(error as i32),
    )
}

fn map_home_view_program(program: &OsStr, space_home: &Path, effective_home: &Path) -> OsString {
    let path = Path::new(program);
    path.strip_prefix(space_home).map_or_else(
        |_error| program.to_owned(),
        |relative| effective_home.join(relative).into_os_string(),
    )
}

fn run_direct(
    program: &OsStr,
    arguments: &[OsString],
    environment: &EnvironmentPlan,
    working_directory: Option<&Path>,
) -> Result<ExitStatus> {
    let mut command = Command::new(program);
    command.args(arguments);
    if let Some(directory) = working_directory {
        command.current_dir(directory);
    }
    environment.apply(&mut command);
    command
        .status()
        .map_err(|error| process_error("start profile command", program, error))
}

fn current_executable() -> Result<PathBuf> {
    std::env::current_exe().map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not locate the Quarters executable").with_source(error)
    })
}

fn required_environment_path(environment: &EnvironmentPlan, name: &str) -> Result<PathBuf> {
    environment
        .value(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            QuartersError::new(
                ErrorKind::CorruptState,
                format!("profile environment has no absolute {name}"),
            )
        })
}

fn install_runtime_binary(source: &Path, environment: &EnvironmentPlan) -> Result<()> {
    let runtime = environment.value("XDG_RUNTIME_DIR").ok_or_else(|| {
        QuartersError::new(
            ErrorKind::CorruptState,
            "namespace-launch environment has no runtime directory",
        )
    })?;
    let command_directory = PathBuf::from(runtime).join("bin");
    install_runtime_command_set(source, &command_directory)
}

fn install_runtime_command_set(source: &Path, command_directory: &Path) -> Result<()> {
    validate_runtime_command_directory(command_directory)?;
    let destination = command_directory.join("quarters");
    let sequence = RUNTIME_COPY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = destination.with_extension(format!("tmp-{}-{sequence}", std::process::id()));
    if let Err(error) = copy_private_executable(source, &temporary) {
        let _cleanup = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary, &destination) {
        let _cleanup = fs::remove_file(&temporary);
        return Err(QuartersError::io("publish the namespace launcher", &destination, error));
    }
    for tool in ["ssh", "scp", "sftp", "ssh-add"] {
        install_runtime_adapter(&command_directory.join(tool))?;
    }
    File::open(command_directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| QuartersError::io("sync namespace command directory", command_directory, error))
}

fn validate_runtime_command_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect namespace command directory", path, error))?;
    let valid = metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == nix::unistd::Uid::current().as_raw()
        && metadata.permissions().mode() & 0o777 == 0o700;
    if valid {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "the namespace command directory is not a protected current-user directory",
    ))
}

fn install_runtime_adapter(path: &Path) -> Result<()> {
    match symlink("quarters", path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(QuartersError::io("install namespace OpenSSH adapter", path, error)),
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect namespace OpenSSH adapter", path, error))?;
    if metadata.file_type().is_symlink() && fs::read_link(path).is_ok_and(|target| target == Path::new("quarters")) {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::AlreadyExists,
        format!("namespace adapter entry is not managed: {}", path.display()),
    )
    .with_hint("inspect the exact private runtime entry; Quarters never replaces an unverified command"))
}

fn copy_private_executable(source: &Path, destination: &Path) -> Result<()> {
    let mut source_file =
        File::open(source).map_err(|error| QuartersError::io("open the namespace launcher", source, error))?;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o700)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let mut destination_file = options
        .open(destination)
        .map_err(|error| QuartersError::io("stage the namespace launcher", destination, error))?;
    std::io::copy(&mut source_file, &mut destination_file)
        .map_err(|error| QuartersError::io("copy the namespace launcher", destination, error))?;
    destination_file
        .flush()
        .map_err(|error| QuartersError::io("flush the namespace launcher", destination, error))?;
    destination_file
        .sync_all()
        .map_err(|error| QuartersError::io("sync the namespace launcher", destination, error))
}

fn split_command(raw_command: &[OsString]) -> Result<(&OsStr, &[OsString])> {
    raw_command
        .split_first()
        .map(|(program, arguments)| (program.as_os_str(), arguments))
        .ok_or_else(|| {
            QuartersError::new(ErrorKind::InvalidInput, "a command is required")
                .with_hint("put '--' before command options")
        })
}

fn status_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| status.signal().map_or(1, |signal| 128 + signal))
}

fn process_error(operation: &str, program: &OsStr, source: std::io::Error) -> QuartersError {
    QuartersError::new(
        ErrorKind::System,
        format!("could not {operation}: {}", program.to_string_lossy()),
    )
    .with_hint("check that the executable exists and is permitted by the host account")
    .with_source(source)
}

#[cfg(test)]
mod tests {
    use super::install_runtime_command_set;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn home_view_command_set_is_complete_and_collision_safe() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("bin");
        std::fs::create_dir(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        std::fs::create_dir(directory.join("quarters"))?;
        assert!(install_runtime_command_set(&std::env::current_exe()?, &directory).is_err());
        assert_eq!(std::fs::read_dir(&directory)?.count(), 1);
        std::fs::remove_dir(directory.join("quarters"))?;
        install_runtime_command_set(&std::env::current_exe()?, &directory)?;
        for tool in ["ssh", "scp", "sftp", "ssh-add"] {
            assert_eq!(
                std::fs::read_link(directory.join(tool))?,
                std::path::Path::new("quarters")
            );
        }
        std::fs::remove_file(directory.join("ssh"))?;
        std::fs::write(directory.join("ssh"), b"collision")?;
        assert!(install_runtime_command_set(&std::env::current_exe()?, &directory).is_err());
        assert_eq!(std::fs::read(directory.join("ssh"))?, b"collision");
        Ok(())
    }
}
