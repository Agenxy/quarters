//! Installed-tool launch evidence without reading host credentials.

use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn quarters(root: &Path, sentinels: &Sentinels) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_quarters"));
    command
        .arg("--root")
        .arg(root)
        .env("GIT_CONFIG_GLOBAL", sentinels.file("git"))
        .env("NPM_CONFIG_USERCONFIG", sentinels.file("npm"))
        .env("GNUPGHOME", sentinels.directory("gpg"))
        .env("CARGO_HOME", sentinels.directory("cargo"))
        .env("UV_CACHE_DIR", sentinels.directory("uv"))
        .env("GH_CONFIG_DIR", sentinels.directory("gh"))
        .env("CODEX_HOME", sentinels.directory("codex"))
        .env("CLAUDE_CONFIG_DIR", sentinels.directory("claude"))
        .env("OPENCODE_CONFIG_DIR", sentinels.directory("opencode"));
    command
}

fn run(command: &mut Command) -> Result<Output, Box<dyn Error>> {
    let output = command.output()?;
    if output.status.success() {
        return Ok(output);
    }
    Err(format!(
        "command failed with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

#[test]
fn recursive_adapter_dispatch_fails_closed_before_spawning() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let adapter = temporary.path().join("ssh");
    symlink(env!("CARGO_BIN_EXE_quarters"), &adapter)?;
    let output = Command::new(adapter)
        .env("QUARTERS_ADAPTER_PARENT_PID", std::process::id().to_string())
        .output()?;
    assert_eq!(output.status.code(), Some(7));
    assert!(String::from_utf8(output.stderr)?.contains("resolved back to Quarters"));
    Ok(())
}

#[test]
fn host_path_with_the_space_command_directory_does_not_recurse() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let sentinels = Sentinels::new(temporary.path().join("host-sentinels"))?;
    let store = temporary.path().join("store");
    run(quarters(&store, &sentinels).args(["create", "self-skip"]))?;
    let command_directory = store.join("spaces/self-skip/home/.local/bin");
    let host_path = std::env::join_paths([command_directory, PathBuf::from("/usr/bin"), PathBuf::from("/bin")])?;
    let output =
        run(quarters(&store, &sentinels)
            .env("PATH", host_path)
            .args(["exec", "self-skip", "--", "ssh", "-V"]))?;
    assert!(String::from_utf8(output.stderr)?.contains("OpenSSH_"));
    Ok(())
}

struct Sentinels {
    root: PathBuf,
}

impl Sentinels {
    fn new(root: PathBuf) -> Result<Self, Box<dyn Error>> {
        fs::create_dir(&root)?;
        for name in ["gpg", "cargo", "uv", "gh", "codex", "claude", "opencode"] {
            fs::create_dir(root.join(name))?;
            fs::write(root.join(name).join("marker"), b"host-unchanged")?;
        }
        for name in ["git", "npm"] {
            fs::write(root.join(name), b"host-unchanged")?;
        }
        Ok(Self { root })
    }

    fn directory(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn assert_unchanged(&self) -> Result<(), Box<dyn Error>> {
        for name in ["gpg", "cargo", "uv", "gh", "codex", "claude", "opencode"] {
            let entries = fs::read_dir(self.directory(name))?.collect::<Result<Vec<_>, _>>()?;
            assert_eq!(entries.len(), 1, "host {name} directory changed");
            assert_eq!(fs::read(self.directory(name).join("marker"))?, b"host-unchanged");
        }
        for name in ["git", "npm"] {
            assert_eq!(fs::read(self.file(name))?, b"host-unchanged");
        }
        Ok(())
    }
}

#[test]
fn representative_installed_tools_launch_with_space_state_and_leave_host_sentinels() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let sentinels = Sentinels::new(temporary.path().join("host-sentinels"))?;
    let store = temporary.path().join("store with \"quotes\" and \\slashes");
    run(quarters(&store, &sentinels).args(["create", "compatibility"]))?;

    if executable("git").is_some() {
        run(quarters(&store, &sentinels).args([
            "exec",
            "compatibility",
            "--",
            "git",
            "config",
            "--global",
            "quarters.probe",
            "space-owned",
        ]))?;
        let config = store.join("spaces/compatibility/home/.gitconfig");
        assert!(fs::read_to_string(config)?.contains("space-owned"));
    }

    let ssh_config = store.join("spaces/compatibility/home/.ssh/config");
    fs::write(&ssh_config, b"Host *\n  User quarters-probe\n")?;
    let resolved =
        run(quarters(&store, &sentinels).args(["exec", "compatibility", "--", "ssh", "-G", "example.invalid"]))?;
    let resolved = String::from_utf8(resolved.stdout)?;
    let space_home = store.join("spaces/compatibility/home");
    assert!(resolved.contains("user quarters-probe"));
    assert!(resolved.contains("identityfile none"));
    assert_eq!(
        resolved
            .lines()
            .filter(|line| line.starts_with("identityfile "))
            .count(),
        1,
        "the managed configuration must suppress every passwd-home default identity"
    );
    assert!(resolved.contains("identitiesonly no"));
    assert!(resolved.contains(&format!("userknownhostsfile {}/.ssh/known_hosts", space_home.display())));
    if let Some(host_home) = std::env::var_os("HOME") {
        assert!(!resolved.contains(&format!(
            "userknownhostsfile {}/.ssh/known_hosts",
            PathBuf::from(host_home).display()
        )));
    }

    for (tool, arguments) in version_probes() {
        if executable(tool).is_some() {
            run(quarters(&store, &sentinels).args(["exec", "compatibility", "--", tool, arguments]))?;
        }
    }
    sentinels.assert_unchanged()
}

#[test]
fn nested_spaces_keep_the_original_host_escape_and_do_not_recurse_adapters() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let sentinels = Sentinels::new(temporary.path().join("host-sentinels"))?;
    run(quarters(temporary.path(), &sentinels).args(["create", "outer"]))?;
    run(quarters(temporary.path(), &sentinels).args(["create", "inner"]))?;
    let binary = env!("CARGO_BIN_EXE_quarters");
    let root = temporary.path().to_string_lossy();

    let nested_ssh = run(quarters(temporary.path(), &sentinels).args([
        "exec", "outer", "--", binary, "--root", &root, "exec", "inner", "--", "ssh", "-V",
    ]))?;
    let direct_ssh = Command::new("/usr/bin/ssh").arg("-V").output()?;
    assert_eq!(nested_ssh.status.code(), direct_ssh.status.code());
    assert_eq!(nested_ssh.stdout, direct_ssh.stdout);
    assert_eq!(nested_ssh.stderr, direct_ssh.stderr);

    let escaped = run(quarters(temporary.path(), &sentinels).args([
        "exec",
        "outer",
        "--",
        binary,
        "--root",
        &root,
        "exec",
        "inner",
        "--",
        binary,
        "--root",
        &root,
        "host",
        "--",
        "/usr/bin/env",
    ]))?;
    let environment = String::from_utf8(escaped.stdout)?;
    let outer_home = temporary.path().join("spaces/outer/home");
    assert!(!environment.contains(&format!("HOME={}", outer_home.display())));
    assert_eq!(
        environment.lines().find(|line| line.starts_with("HOME=")),
        std::env::var("HOME")
            .ok()
            .map(|value| format!("HOME={value}"))
            .as_deref()
    );
    Ok(())
}

#[test]
fn openssh_adapter_rejects_leading_config_overrides_but_allows_remote_dash_f() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let sentinels = Sentinels::new(temporary.path().join("host-sentinels"))?;
    run(quarters(temporary.path(), &sentinels).args(["create", "ssh-options"]))?;

    for arguments in [
        vec![
            "exec",
            "ssh-options",
            "--",
            "ssh",
            "-4F",
            "/tmp/host-config",
            "example.invalid",
        ],
        vec![
            "exec",
            "ssh-options",
            "--",
            "ssh",
            "-D",
            "1080",
            "-F",
            "/tmp/host-config",
        ],
        vec![
            "exec",
            "ssh-options",
            "--",
            "ssh",
            "-X",
            "-F",
            "/tmp/host-config",
            "example.invalid",
        ],
        vec![
            "exec",
            "ssh-options",
            "--",
            "sftp",
            "-s",
            "internal-sftp",
            "-F",
            "/tmp/host-config",
        ],
        vec![
            "exec",
            "ssh-options",
            "--",
            "ssh",
            "-vF/tmp/host-config",
            "example.invalid",
        ],
    ] {
        let output = quarters(temporary.path(), &sentinels).args(arguments).output()?;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("does not accept a competing -F"));
    }

    run(quarters(temporary.path(), &sentinels).args([
        "exec",
        "ssh-options",
        "--",
        "ssh",
        "-G",
        "example.invalid",
        "grep",
        "-F",
        "pattern",
    ]))?;
    Ok(())
}

#[test]
fn doctor_reports_stale_adapters_instead_of_claiming_a_managed_route() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new()?;
    let sentinels = Sentinels::new(temporary.path().join("host-sentinels"))?;
    run(quarters(temporary.path(), &sentinels).args(["create", "stale-adapter"]))?;
    let launcher = temporary.path().join("spaces/stale-adapter/home/.local/bin/quarters");
    fs::remove_file(&launcher)?;
    symlink("/definitely/not/installed/quarters", &launcher)?;

    let output = run(quarters(temporary.path(), &sentinels).args(["--json", "doctor", "stale-adapter"]))?;
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let result = &value["result"];
    assert_eq!(result["space_command_links"]["launcher"]["state"], "stale");
    let ssh = result["tools"]
        .as_array()
        .and_then(|tools| tools.iter().find(|tool| tool["tool"] == "ssh"))
        .ok_or("doctor omitted the SSH probe")?;
    assert!(
        ssh["mechanism"]
            .as_str()
            .is_some_and(|route| route.contains("incomplete"))
    );
    let execution = quarters(temporary.path(), &sentinels)
        .args(["exec", "stale-adapter", "--", "/usr/bin/true"])
        .output()?;
    assert!(execution.status.success());
    assert!(String::from_utf8_lossy(&execution.stderr).contains("managed command route is incomplete"));
    Ok(())
}

fn version_probes() -> [(&'static str, &'static str); 12] {
    [
        ("zsh", "--version"),
        ("bash", "--version"),
        ("gh", "--version"),
        ("tmux", "-V"),
        ("gpg", "--version"),
        ("python3", "--version"),
        ("uv", "--version"),
        ("cargo", "--version"),
        ("npm", "--version"),
        ("codex", "--version"),
        ("claude", "--version"),
        ("opencode", "--version"),
    ]
}

fn executable(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file() && candidate.file_name() == Some(OsStr::new(name)))
}
