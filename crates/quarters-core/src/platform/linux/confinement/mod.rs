//! Fail-closed Linux Landlock filesystem policy.

mod paths;
mod policy;

use super::super::{CapabilityStatus, ConfinementPlan};
use crate::{ErrorKind, QuartersError, Result};
use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

pub(super) struct PreparedConfinement {
    ruleset: landlock::RulesetCreated,
}

pub(super) fn capability_status() -> CapabilityStatus {
    match policy::create_ruleset() {
        Ok(_ruleset) => CapabilityStatus {
            available: true,
            status: "experimental".to_owned(),
            detail: "Landlock ABI 3 policy creation succeeded; each launch still requires full enforcement".to_owned(),
        },
        Err(error) => CapabilityStatus {
            available: false,
            status: "unavailable".to_owned(),
            detail: format!("Landlock ABI 3 policy is unavailable: {}", error.message()),
        },
    }
}

pub(super) fn plan(
    space_home: &Path,
    effective_home: &Path,
    runtime: &Path,
    host_path: Option<&OsString>,
) -> Result<ConfinementPlan> {
    policy::create_ruleset()?;
    paths::build_plan(space_home, effective_home, runtime, host_path)
}

pub(super) fn prepare(plan: &ConfinementPlan) -> Result<PreparedConfinement> {
    policy::prepare(plan).map(|ruleset| PreparedConfinement { ruleset })
}

pub(super) fn restrict_current_thread(prepared: PreparedConfinement) -> Result<()> {
    policy::enforce(prepared.ruleset)
}

pub(super) fn resolve_executable(program: &OsStr, search_path: &OsStr, plan: &ConfinementPlan) -> Result<PathBuf> {
    paths::resolve_executable(program, search_path, plan)
}

fn landlock_error(operation: &str, error: impl std::error::Error + Send + Sync + 'static) -> QuartersError {
    let detail = error.to_string();
    QuartersError::new(
        ErrorKind::Unsupported,
        format!("could not {operation} with the complete Landlock ABI 3 policy: {detail}"),
    )
    .with_hint("omit --confinement filesystem only if portable state redirection is sufficient")
    .with_source(error)
}

fn new_ruleset() -> Result<landlock::RulesetCreated> {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V3))
        .map_err(|error| landlock_error("select filesystem rights", error))?
        .create()
        .map_err(|error| landlock_error("create a filesystem ruleset", error))
}
