//! Native errno probes run inside the confined acceptance process.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::path::Path;
use std::process::{Command, Output};

pub(super) fn install(home: &Path) -> Result<(), Box<dyn Error>> {
    let directory = home.join(".local/bin");
    fs::create_dir_all(&directory)?;
    fs::copy(std::env::current_exe()?, directory.join("grant-errno-probe"))?;
    Ok(())
}

pub(super) fn denied(
    root: &Path,
    name: &str,
    grants: &[String],
    operation: &str,
    path: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut command = super::quarters(root);
    command
        .env_remove("XDG_RUNTIME_DIR")
        .env("GRANT_PROBE_OPERATION", operation)
        .env("GRANT_PROBE_PATH", path)
        .args(["exec", name, "--confinement", "filesystem"])
        .args(["--inherit", "GRANT_PROBE_OPERATION", "--inherit", "GRANT_PROBE_PATH"]);
    for grant in grants {
        command.arg("--grant-path").arg(grant);
    }
    let output = command
        .args([
            "--",
            "grant-errno-probe",
            "--exact",
            "grant_probes::errno_denial_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()?;
    verify_output(&output, operation)
}

fn verify_output(output: &Output, operation: &str) -> Result<(), Box<dyn Error>> {
    if output.status.success() && String::from_utf8_lossy(&output.stdout).contains("denied errno=13") {
        return Ok(());
    }
    Err(format!(
        "{operation} must fail with EACCES, got {:?}: {} {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
    .into())
}

#[test]
fn errno_denial_probe() -> Result<(), Box<dyn Error>> {
    let Some(operation) = std::env::var_os("GRANT_PROBE_OPERATION") else {
        return Ok(());
    };
    let path = std::env::var_os("GRANT_PROBE_PATH").ok_or("probe path is missing")?;
    let path = Path::new(&path);
    let result = match operation.to_str().ok_or("probe operation is not ASCII")? {
        "read" => fs::read(path).map(|_| ()),
        "write" => OpenOptions::new().write(true).truncate(true).open(path).map(|_| ()),
        "create" => OpenOptions::new().write(true).create_new(true).open(path).map(|_| ()),
        "list" => fs::read_dir(path).map(|_| ()),
        "unlink" => fs::remove_file(path),
        "execute" => Command::new(path).output().map(|_| ()),
        _ => return Err("unknown errno probe operation".into()),
    };
    let error = result.err().ok_or("an ungranted operation succeeded")?;
    assert_eq!(error.raw_os_error(), Some(nix::libc::EACCES));
    println!("denied errno={}", nix::libc::EACCES);
    Ok(())
}
