//! Collision-safe managed command links placed inside a space.

use crate::store::sync_directory;
use crate::store_lock::acquire_lifecycle_lease;
use crate::{ErrorKind, QuartersError, Result, Space, SpaceName, Store};
use serde::Serialize;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

const TOOLS: [&str; 4] = ["ssh", "scp", "sftp", "ssh-add"];

/// State of one managed command entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CommandLinkState {
    /// No filesystem entry exists.
    Absent,
    /// The link has the exact managed shape.
    Managed,
    /// The managed launcher shape no longer resolves to an executable.
    Stale,
    /// An unmanaged entry occupies the path.
    Collision,
}

impl CommandLinkState {
    /// Stable lowercase representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Managed => "managed",
            Self::Stale => "stale",
            Self::Collision => "collision",
        }
    }
}

/// One launcher or adapter path and its observed state.
#[derive(Clone, Debug, Serialize)]
pub struct CommandLinkEntry {
    /// Command name.
    pub tool: String,
    /// Exact observed state.
    pub state: CommandLinkState,
    /// Filesystem entry inspected.
    pub path: PathBuf,
}

/// Closed managed command set for one space.
#[derive(Clone, Debug, Serialize)]
pub struct CommandLinkReport {
    /// Space display name.
    pub space: String,
    /// Absolute Quarters launcher link.
    pub launcher: CommandLinkEntry,
    /// Relative OpenSSH adapter links.
    pub tools: Vec<CommandLinkEntry>,
    /// Honest authority boundary.
    pub boundary: &'static str,
}

/// Inspect managed command links without changing them.
///
/// # Errors
///
/// Returns an error when the private link directory cannot be inspected safely.
pub fn inspect_command_links(space: &Space) -> Result<CommandLinkReport> {
    let directory = space.home().join(".local/bin");
    validate_command_directory(space)?;
    let launcher = inspect_launcher(&directory)?;
    let tools = TOOLS
        .into_iter()
        .map(|tool| inspect_tool(&directory, tool, launcher.state))
        .collect::<Result<Vec<_>>>()?;
    Ok(CommandLinkReport {
        space: space.manifest().name.as_str().to_owned(),
        launcher,
        tools,
        boundary: "selects per-space OpenSSH configuration; it does not restrict host filesystem authority",
    })
}

/// Install absent entries using one validated Quarters executable.
///
/// # Errors
///
/// Returns an error without replacing any stale, colliding or unsafe entry.
fn install_command_links(space: &Space, executable: &Path) -> Result<CommandLinkReport> {
    let directory = space.home().join(".local/bin");
    validate_command_directory(space)?;
    validate_launcher(executable)?;
    let before = inspect_command_links(space)?;
    ensure_installable(&before)?;
    let mut created = Vec::new();
    if before.launcher.state == CommandLinkState::Absent {
        let path = directory.join("quarters");
        created.push(create_link(executable, &path)?);
    }
    for entry in &before.tools {
        if entry.state == CommandLinkState::Absent {
            match create_link(Path::new("quarters"), &entry.path) {
                Ok(link) => created.push(link),
                Err(error) => {
                    rollback_links(&created);
                    return Err(error);
                }
            }
        }
    }
    sync_directory(&directory)?;
    inspect_command_links(space)
}

/// Remove only exact managed adapter links, preserving the Quarters launcher.
///
/// # Errors
///
/// Returns an error without unlinking stale, colliding or unsafe entries.
fn remove_command_links(space: &Space) -> Result<CommandLinkReport> {
    let directory = space.home().join(".local/bin");
    validate_command_directory(space)?;
    let before = inspect_command_links(space)?;
    ensure_removable(&before)?;
    for entry in &before.tools {
        match entry.state {
            CommandLinkState::Managed | CommandLinkState::Stale => remove_managed_tool(&entry.path)?,
            CommandLinkState::Absent => {}
            CommandLinkState::Collision => unreachable!("preflight rejected unsafe entry"),
        }
    }
    sync_directory(&directory)?;
    inspect_command_links(space)
}

impl Store {
    /// Install absent command links while the named space is inactive.
    ///
    /// # Errors
    ///
    /// Returns an error without replacing a collision or racing lifecycle work.
    pub fn install_space_command_links(&self, name: &SpaceName, executable: &Path) -> Result<CommandLinkReport> {
        self.ensure_no_rename_target(name)?;
        self.ensure_no_rollback_target(name)?;
        let _management = self.management_guard()?;
        let space = self.open(name)?;
        let _lease = acquire_lifecycle_lease(&space, name.as_str())?;
        install_command_links(&space, executable)
    }

    /// Remove exact managed OpenSSH adapters while the space is inactive.
    ///
    /// # Errors
    ///
    /// Returns an error without removing a collision or racing lifecycle work.
    pub fn remove_space_command_links(&self, name: &SpaceName) -> Result<CommandLinkReport> {
        self.ensure_no_rename_target(name)?;
        self.ensure_no_rollback_target(name)?;
        let _management = self.management_guard()?;
        let space = self.open(name)?;
        let _lease = acquire_lifecycle_lease(&space, name.as_str())?;
        remove_command_links(&space)
    }
}

fn inspect_launcher(directory: &Path) -> Result<CommandLinkEntry> {
    let path = directory.join("quarters");
    let state = match fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.file_type().is_symlink() => CommandLinkState::Collision,
        Ok(_) => launcher_state(directory, &path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => CommandLinkState::Absent,
        Err(error) => return Err(QuartersError::io("inspect managed Quarters launcher", &path, error)),
    };
    Ok(CommandLinkEntry {
        tool: "quarters".to_owned(),
        state,
        path,
    })
}

fn launcher_state(directory: &Path, path: &Path) -> Result<CommandLinkState> {
    let target =
        fs::read_link(path).map_err(|error| QuartersError::io("read managed Quarters launcher", path, error))?;
    if !managed_launcher_shape(&target) {
        return Ok(CommandLinkState::Collision);
    }
    let resolved = if target.is_absolute() {
        target
    } else {
        directory.join(target)
    };
    Ok(
        if fs::symlink_metadata(&resolved).is_ok_and(|metadata| safe_launcher_metadata(&metadata)) {
            CommandLinkState::Managed
        } else {
            CommandLinkState::Stale
        },
    )
}

fn inspect_tool(directory: &Path, tool: &str, launcher: CommandLinkState) -> Result<CommandLinkEntry> {
    let path = directory.join(tool);
    let state = match fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.file_type().is_symlink() => CommandLinkState::Collision,
        Ok(_) => {
            let target =
                fs::read_link(&path).map_err(|error| QuartersError::io("read OpenSSH adapter link", &path, error))?;
            match (target == Path::new("quarters"), launcher) {
                (true, CommandLinkState::Managed) => CommandLinkState::Managed,
                (true, CommandLinkState::Absent | CommandLinkState::Stale) => CommandLinkState::Stale,
                _ => CommandLinkState::Collision,
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => CommandLinkState::Absent,
        Err(error) => return Err(QuartersError::io("inspect OpenSSH adapter entry", &path, error)),
    };
    Ok(CommandLinkEntry {
        tool: tool.to_owned(),
        state,
        path,
    })
}

fn ensure_installable(report: &CommandLinkReport) -> Result<()> {
    let blocked = std::iter::once(&report.launcher)
        .chain(report.tools.iter())
        .find(|entry| {
            entry.state == CommandLinkState::Collision
                || (entry.state == CommandLinkState::Stale
                    && (entry.tool == "quarters" || report.launcher.state != CommandLinkState::Absent))
        });
    if let Some(entry) = blocked {
        return Err(QuartersError::new(
            ErrorKind::AlreadyExists,
            format!(
                "adapter entry for '{}' is {}; it was not replaced",
                entry.tool,
                entry.state.as_str()
            ),
        )
        .with_hint("inspect the exact entry, then remove or relocate it intentionally before retrying"));
    }
    Ok(())
}

fn ensure_removable(report: &CommandLinkReport) -> Result<()> {
    if let Some(entry) = report
        .tools
        .iter()
        .find(|entry| entry.state == CommandLinkState::Collision)
    {
        return Err(QuartersError::new(
            ErrorKind::AlreadyExists,
            format!("refusing to remove unverified adapter entry for {}", entry.tool),
        ));
    }
    Ok(())
}

fn validate_command_directory(space: &Space) -> Result<()> {
    for path in [
        space.home(),
        space.home().join(".local"),
        space.home().join(".local/bin"),
    ] {
        validate_directory(&path)?;
    }
    Ok(())
}

fn validate_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect managed command directory", path, error))?;
    if metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == nix::unistd::Uid::current().as_raw()
        && metadata.permissions().mode() & 0o022 == 0
    {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::CorruptState,
        "the managed command directory is not a protected current-user directory",
    ))
}

fn validate_launcher(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| QuartersError::io("inspect Quarters launcher", path, error))?;
    if path.is_absolute() && path.file_name() == Some(OsStr::new("quarters")) && safe_launcher_metadata(&metadata) {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "the running executable cannot be installed as a stable Quarters launcher",
    ))
}

fn safe_launcher_metadata(metadata: &fs::Metadata) -> bool {
    let uid = metadata.uid();
    metadata.file_type().is_file()
        && (uid == 0 || uid == nix::unistd::Uid::current().as_raw())
        && metadata.permissions().mode() & 0o111 != 0
        && metadata.permissions().mode() & 0o022 == 0
}

fn managed_launcher_shape(target: &Path) -> bool {
    target == Path::new("quarters") || (target.is_absolute() && target.file_name() == Some(OsStr::new("quarters")))
}

struct CreatedLink {
    path: PathBuf,
    target: PathBuf,
    device: u64,
    inode: u64,
}

fn create_link(target: &Path, path: &Path) -> Result<CreatedLink> {
    symlink(target, path).map_err(|error| QuartersError::io("install managed OpenSSH adapter", path, error))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| QuartersError::io("inspect installed OpenSSH adapter", path, error))?;
    if !metadata.file_type().is_symlink() || !fs::read_link(path).is_ok_and(|actual| actual == target) {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            format!(
                "the newly installed adapter changed before verification: {}",
                path.display()
            ),
        ));
    }
    Ok(CreatedLink {
        path: path.to_path_buf(),
        target: target.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn rollback_links(links: &[CreatedLink]) {
    for link in links.iter().rev() {
        if matching_link(link) {
            let _cleanup = fs::remove_file(&link.path);
        }
    }
}

fn matching_link(link: &CreatedLink) -> bool {
    fs::symlink_metadata(&link.path).is_ok_and(|metadata| {
        metadata.file_type().is_symlink()
            && metadata.dev() == link.device
            && metadata.ino() == link.inode
            && fs::read_link(&link.path).is_ok_and(|actual| actual == link.target)
    })
}

fn remove_managed_tool(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| QuartersError::io("reinspect OpenSSH adapter", path, error))?;
    if !metadata.file_type().is_symlink() || !fs::read_link(path).is_ok_and(|actual| actual == Path::new("quarters")) {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            format!("the managed adapter changed before removal: {}", path.display()),
        ));
    }
    fs::remove_file(path).map_err(|error| QuartersError::io("remove OpenSSH adapter", path, error))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn an_absent_launcher_can_be_repaired_without_replacing_exact_tool_links() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let store = Store::new(temporary.path().join("root")).expect("valid store");
        let name = SpaceName::parse("adapter-repair").expect("space name");
        let space = store
            .create(name.clone(), PathBuf::from("/bin/sh"))
            .expect("create space");
        let executable = temporary.path().join("quarters");
        fs::write(&executable, b"quarters test executable").expect("write launcher");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("protect launcher");
        store
            .install_space_command_links(&name, &executable)
            .expect("install command links");
        fs::remove_file(space.home().join(".local/bin/quarters")).expect("remove launcher");

        let stale = inspect_command_links(&space).expect("inspect stale links");
        assert_eq!(stale.launcher.state, CommandLinkState::Absent);
        assert!(stale.tools.iter().all(|entry| entry.state == CommandLinkState::Stale));

        let repaired = store
            .install_space_command_links(&name, &executable)
            .expect("repair launcher");
        assert_eq!(repaired.launcher.state, CommandLinkState::Managed);
        assert!(
            repaired
                .tools
                .iter()
                .all(|entry| entry.state == CommandLinkState::Managed)
        );
    }
}
