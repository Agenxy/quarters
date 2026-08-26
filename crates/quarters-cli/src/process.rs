//! Native child-process launch and host escape behavior.

use quarters_core::platform;
use quarters_core::{EnvironmentPlan, ErrorKind, HostEnvironment, QuartersError, Result, Space, Store};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
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
    pub(crate) inherited_names: &'a [String],
}

impl ProfileLaunch<'_> {
    pub(crate) fn environment(&self) -> Result<EnvironmentPlan> {
        let effective_home = self.effective_home()?;
        EnvironmentPlan::for_space(self.space, self.host, &effective_home, self.inherited_names)
    }

    pub(crate) fn run(&self, raw_command: &[OsString]) -> Result<i32> {
        let (program, arguments) = split_command(raw_command)?;
        let environment = self.environment()?;
        let _lease = self.store.lease(self.space)?;
        let status = if self.home_view {
            self.run_home_view(program, arguments, &environment)?
        } else {
            run_direct(program, arguments, &environment)?
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
        self.host_home()
    }

    fn run_home_view(
        &self,
        program: &OsStr,
        arguments: &[OsString],
        environment: &EnvironmentPlan,
    ) -> Result<ExitStatus> {
        let current_executable = std::env::current_exe().map_err(|error| {
            QuartersError::new(ErrorKind::System, "could not locate the Quarters executable").with_source(error)
        })?;
        install_runtime_binary(&current_executable, environment)?;
        let host_home = self.host_home()?;
        let mut command = Command::new(current_executable);
        command
            .arg("__linux-launch")
            .arg("--space-home")
            .arg(self.space.home())
            .arg("--host-home")
            .arg(host_home)
            .arg("--")
            .arg(program)
            .args(arguments);
        environment.apply(&mut command);
        command
            .status()
            .map_err(|error| process_error("start Linux home-view launcher", program, error))
    }

    fn host_home(&self) -> Result<PathBuf> {
        self.host
            .get("HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| QuartersError::new(ErrorKind::InvalidInput, "host HOME is unset or not absolute"))
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

pub(crate) fn linux_launch(space_home: &Path, host_home: &Path, raw_command: &[OsString]) -> Result<i32> {
    let (program, arguments) = split_command(raw_command)?;
    platform::enter_home_view(space_home, host_home)?;
    let error = std::os::unix::process::CommandExt::exec(Command::new(program).args(arguments));
    Err(process_error("replace the namespace launcher", program, error))
}

fn run_direct(program: &OsStr, arguments: &[OsString], environment: &EnvironmentPlan) -> Result<ExitStatus> {
    let mut command = Command::new(program);
    command.args(arguments);
    environment.apply(&mut command);
    command
        .status()
        .map_err(|error| process_error("start profile command", program, error))
}

fn install_runtime_binary(source: &Path, environment: &EnvironmentPlan) -> Result<()> {
    let runtime = environment.value("XDG_RUNTIME_DIR").ok_or_else(|| {
        QuartersError::new(
            ErrorKind::CorruptState,
            "home-view environment has no runtime directory",
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
        return Err(QuartersError::io("publish the home-view launcher", &destination, error));
    }
    for tool in ["ssh", "scp", "sftp", "ssh-add"] {
        install_runtime_adapter(&command_directory.join(tool))?;
    }
    File::open(command_directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| QuartersError::io("sync home-view command directory", command_directory, error))
}

fn validate_runtime_command_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect home-view command directory", path, error))?;
    let valid = metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == nix::unistd::Uid::current().as_raw()
        && metadata.permissions().mode() & 0o777 == 0o700;
    if valid {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "the home-view command directory is not a protected current-user directory",
    ))
}

fn install_runtime_adapter(path: &Path) -> Result<()> {
    match symlink("quarters", path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(QuartersError::io("install home-view OpenSSH adapter", path, error)),
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect home-view OpenSSH adapter", path, error))?;
    if metadata.file_type().is_symlink() && fs::read_link(path).is_ok_and(|target| target == Path::new("quarters")) {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::AlreadyExists,
        format!("home-view adapter entry is not managed: {}", path.display()),
    )
    .with_hint("inspect the exact private runtime entry; Quarters never replaces an unverified command"))
}

fn copy_private_executable(source: &Path, destination: &Path) -> Result<()> {
    let mut source_file =
        File::open(source).map_err(|error| QuartersError::io("open the home-view launcher", source, error))?;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o700)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let mut destination_file = options
        .open(destination)
        .map_err(|error| QuartersError::io("stage the home-view launcher", destination, error))?;
    std::io::copy(&mut source_file, &mut destination_file)
        .map_err(|error| QuartersError::io("copy the home-view launcher", destination, error))?;
    destination_file
        .flush()
        .map_err(|error| QuartersError::io("flush the home-view launcher", destination, error))?;
    destination_file
        .sync_all()
        .map_err(|error| QuartersError::io("sync the home-view launcher", destination, error))
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
