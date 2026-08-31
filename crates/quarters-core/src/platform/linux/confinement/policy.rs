//! Landlock ruleset construction and enforcement.

use super::{landlock_error, new_ruleset};
use crate::platform::{ConfinementGrant, ConfinementPlan};
use crate::{ErrorKind, QuartersError, Result};
use landlock::{ABI, Access, AccessFs, PathBeneath, PathFd, RulesetCreated, RulesetCreatedAttr, RulesetStatus};

pub(super) fn create_ruleset() -> Result<RulesetCreated> {
    new_ruleset()
}

pub(super) fn prepare(plan: &ConfinementPlan) -> Result<RulesetCreated> {
    let mut ruleset = new_ruleset()?;
    for grant in &plan.grants {
        let access = grant_access(grant)?;
        let descriptor =
            PathFd::new(&grant.path).map_err(|error| landlock_error("open a filesystem policy anchor", error))?;
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
