//! Landlock ruleset construction and enforcement.

use super::{landlock_error, new_ruleset};
use crate::platform::{ConfinementGrant, ConfinementPlan};
use crate::{ErrorKind, QuartersError, Result};
use landlock::{ABI, Access, AccessFs, PathBeneath, PathFd, RulesetCreated, RulesetCreatedAttr, RulesetStatus};
use nix::sys::stat::fstat;
use std::os::fd::AsFd;

pub(super) fn create_ruleset() -> Result<RulesetCreated> {
    new_ruleset()
}

pub(super) fn prepare(plan: &ConfinementPlan) -> Result<RulesetCreated> {
    let mut ruleset = new_ruleset()?;
    for grant in &plan.grants {
        let access = grant_access(grant)?;
        let descriptor =
            PathFd::new(&grant.path).map_err(|error| landlock_error("open a filesystem policy anchor", error))?;
        let metadata = fstat(descriptor.as_fd()).map_err(|error| {
            QuartersError::new(
                ErrorKind::System,
                "could not inspect an opened filesystem policy anchor",
            )
            .with_source(error)
        })?;
        if metadata.st_dev != grant.anchor_device || metadata.st_ino != grant.anchor_inode {
            return Err(QuartersError::new(
                ErrorKind::Unsupported,
                "a filesystem policy anchor changed after validation",
            )
            .with_hint("retry after ensuring no process is replacing the requested path"));
        }
        ruleset = ruleset
            .add_rule(PathBeneath::new(descriptor, access))
            .map_err(|error| landlock_error("add a filesystem policy rule", error))?;
    }
    Ok(ruleset)
}

pub(super) fn enforce(ruleset: RulesetCreated) -> Result<()> {
    let status = ruleset
        .restrict_self()
        .map_err(|error| landlock_error("enforce the filesystem ruleset", error))?;
    if status.ruleset == RulesetStatus::FullyEnforced && status.no_new_privs {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::Unsupported,
        "the kernel did not fully enforce the Landlock ABI 3 policy",
    )
    .with_hint("omit --confinement filesystem only if portable state redirection is sufficient"))
}

fn grant_access(grant: &ConfinementGrant) -> Result<landlock::BitFlags<AccessFs>> {
    let access = match grant.access.as_str() {
        "read-file" => AccessFs::ReadFile.into(),
        "read" => AccessFs::from_read(ABI::V3) & !AccessFs::Execute,
        "read-execute" => AccessFs::from_read(ABI::V3),
        "read-write" => AccessFs::from_all(ABI::V3),
        "data-read" => AccessFs::from_read(ABI::V3) & !AccessFs::Execute,
        "data-read-write" => AccessFs::from_all(ABI::V3) & !AccessFs::Execute,
        "data-read-file" => AccessFs::ReadFile,
        "data-read-write-file" => AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate,
        "device" => AccessFs::ReadFile | AccessFs::WriteFile,
        _ => {
            return Err(QuartersError::new(
                ErrorKind::CorruptState,
                "filesystem policy contains an unknown access class",
            ));
        }
    };
    Ok(access)
}
