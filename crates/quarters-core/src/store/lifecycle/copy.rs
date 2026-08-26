//! Descriptor-relative lifecycle copy implementation.

use super::cleanup::remove_tree_restoring_owner_access;
#[cfg(test)]
use super::policy::CloneLimits;
use super::policy::{CloneMode, CloneReport};
#[cfg(test)]
use super::walk::test_support::TestMutation;
use super::walk::{WalkControl, walk_home};
use crate::store::create::{acquire_creation_lock, write_manifest};
use crate::store_lock::{LifecycleLease, acquire_lifecycle_lease};
use crate::store_policy::{validate_shell, validate_stored_manifest};
use crate::text::escape_untrusted_text_bounded_bytes;
use crate::{ErrorKind, QuartersError, Result, Space, SpaceId, SpaceManifest, SpaceName, Store};
use serde::Serialize;
use std::fs::{self, File};
use std::path::PathBuf;

use crate::store::{
    create_private_dir, entry_exists, epoch_millis, space_not_found, sync_directory, sync_parent_directory,
    validate_space_anchors, write_private_file,
};

impl Store {
    /// Validate and summarize a clone without creating a destination.
    ///
    /// The source activity lease is held exclusively for the bounded walk.
    /// Detached processes remain unknowable.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid state, a held cooperative lease, unsafe
    /// filesystem entries or a resource-limit violation.
    pub fn clone_plan(&self, source: &SpaceName, destination: &SpaceName, include_cache: bool) -> Result<CloneReport> {
        let setup = CloneSetup::prepare(self, source, destination, CloneMode::Preview)?;
        let mut report = setup.report(include_cache);
        walk_home(&setup.source.home(), None, &mut report, &WalkControl::default())?;
        Ok(report)
    }

    #[cfg(test)]
    pub(super) fn clone_plan_with_limits(
        &self,
        source: &SpaceName,
        destination: &SpaceName,
        limits: CloneLimits,
    ) -> Result<CloneReport> {
        let setup = CloneSetup::prepare(self, source, destination, CloneMode::Preview)?;
        let mut report = setup.report(false);
        report.limits = limits;
        walk_home(&setup.source.home(), None, &mut report, &WalkControl::default())?;
        Ok(report)
    }

    /// Clone one inactive space into a new atomically published destination.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid state, a held cooperative lease, unsafe
    /// filesystem entries, a destination collision, or an I/O failure.
    pub fn clone_space(&self, source: &SpaceName, destination: SpaceName, include_cache: bool) -> Result<CloneReport> {
        self.clone_space_controlled(source, destination, include_cache, &CloneControl::default())
    }

    fn clone_space_controlled(
        &self,
        source: &SpaceName,
        destination: SpaceName,
        include_cache: bool,
        control: &CloneControl,
    ) -> Result<CloneReport> {
        let mut setup = CloneSetup::prepare(self, source, &destination, CloneMode::Execute)?;
        let result = self.execute_clone(&mut setup, destination, include_cache, control);
        if let Err(original) = &result
            && let Some(staging) = &setup.staging
            && let Err(cleanup) = remove_tree_restoring_owner_access(&staging.temporary)
        {
            return Err(compound_cleanup_error(original, cleanup));
        }
        result
    }

    #[cfg(test)]
    pub(super) fn clone_space_with_abort(
        &self,
        source: &SpaceName,
        destination: SpaceName,
        abort: LifecycleAbort,
    ) -> Result<CloneReport> {
        self.clone_space_controlled(
            source,
            destination,
            false,
            &CloneControl {
                abort: Some(abort),
                limits: None,
                mutation: None,
            },
        )
    }

    #[cfg(test)]
    pub(super) fn clone_space_with_limits(
        &self,
        source: &SpaceName,
        destination: SpaceName,
        limits: CloneLimits,
    ) -> Result<CloneReport> {
        self.clone_space_controlled(
            source,
            destination,
            false,
            &CloneControl {
                abort: None,
                limits: Some(limits),
                mutation: None,
            },
        )
    }

    #[cfg(test)]
    pub(super) fn clone_space_with_mutation(
        &self,
        source: &SpaceName,
        destination: SpaceName,
        mutation: TestMutation,
        limits: Option<CloneLimits>,
    ) -> Result<CloneReport> {
        self.clone_space_controlled(
            source,
            destination,
            false,
            &CloneControl {
                abort: None,
                limits,
                mutation: Some(mutation),
            },
        )
    }

    fn execute_clone(
        &self,
        setup: &mut CloneSetup,
        destination_name: SpaceName,
        include_cache: bool,
        control: &CloneControl,
    ) -> Result<CloneReport> {
        let staging = setup
            .staging
            .as_ref()
            .ok_or_else(|| QuartersError::new(ErrorKind::System, "clone execution has no private staging directory"))?;
        let mut report = setup.report(include_cache);
        #[cfg(test)]
        if let Some(limits) = control.limits {
            report.limits = limits;
        }
        #[cfg(test)]
        control.abort_before_copy()?;
        walk_home(
            &setup.source.home(),
            Some(&staging.temporary.join("home")),
            &mut report,
            &control.walk_control(),
        )?;
        let manifest = destination_manifest(&setup.source, destination_name)?;
        write_controls(&staging.temporary, setup.source.manifest(), &manifest, include_cache)?;
        #[cfg(test)]
        control.abort_before_identity_recheck()?;
        publish(self, setup, &manifest, control)?;
        let published = Self::open_path(staging.destination.clone()).map_err(|error| {
            error.with_hint(format!(
                "space '{}' was published completely but could not be reopened; inspect it before retrying",
                manifest.name
            ))
        })?;
        report.destination_space_id = published.id().map(|value| value.as_str().to_owned());
        Ok(report)
    }
}

pub(super) fn compound_cleanup_error(original: &QuartersError, cleanup: QuartersError) -> QuartersError {
    let original_message = escape_untrusted_text_bounded_bytes(original.message(), 256);
    let original_hint = original
        .hint()
        .map(|hint| escape_untrusted_text_bounded_bytes(hint, 256));
    let recovery = "run 'quarters doctor', then recover only validated stale state";
    let hint = original_hint.map_or_else(|| recovery.to_owned(), |hint| format!("{hint}; {recovery}"));
    QuartersError::new(
        original.kind(),
        format!("clone failed ({original_message}) and its private staging directory could not be reclaimed"),
    )
    .with_hint(hint)
    .with_source(cleanup)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LifecycleAbort {
    BeforeCopy,
    MidCopy,
    BeforeIdentityRecheck,
    BeforePublish,
    AfterPublish,
}

#[derive(Default)]
struct CloneControl {
    #[cfg(test)]
    abort: Option<LifecycleAbort>,
    #[cfg(test)]
    limits: Option<CloneLimits>,
    #[cfg(test)]
    mutation: Option<TestMutation>,
}

impl CloneControl {
    fn walk_control(&self) -> WalkControl {
        #[cfg(not(test))]
        let _ = self;
        WalkControl {
            artifact_source: false,
            recreate_cache_roots: true,
            #[cfg(test)]
            abort_mid_copy: self.abort == Some(LifecycleAbort::MidCopy),
            #[cfg(test)]
            mutation: self.mutation.clone(),
        }
    }

    #[cfg(test)]
    fn abort_before_copy(&self) -> Result<()> {
        self.abort_if_selected(LifecycleAbort::BeforeCopy)
    }

    #[cfg(test)]
    fn abort_before_identity_recheck(&self) -> Result<()> {
        self.abort_if_selected(LifecycleAbort::BeforeIdentityRecheck)
    }

    #[cfg(test)]
    fn abort_before_publish(&self) -> Result<()> {
        self.abort_if_selected(LifecycleAbort::BeforePublish)
    }

    #[cfg(test)]
    fn abort_after_publish(&self) -> Result<()> {
        self.abort_if_selected(LifecycleAbort::AfterPublish)
    }

    #[cfg(test)]
    fn abort_if_selected(&self, point: LifecycleAbort) -> Result<()> {
        if self.abort == Some(point) {
            return Err(QuartersError::new(
                ErrorKind::System,
                format!("injected lifecycle failure at {point:?}"),
            ));
        }
        Ok(())
    }
}

struct CloneSetup {
    source: Space,
    source_manifest: SpaceManifest,
    _activity_lock: LifecycleLease,
    mode: CloneMode,
    destination: SpaceName,
    staging: Option<Staging>,
}

struct Staging {
    temporary: PathBuf,
    destination: PathBuf,
    creation_lock_path: PathBuf,
    _creation_lock: File,
}

impl CloneSetup {
    fn prepare(store: &Store, source: &SpaceName, destination: &SpaceName, mode: CloneMode) -> Result<Self> {
        if source == destination {
            return Err(QuartersError::new(
                ErrorKind::InvalidInput,
                "clone source and destination must have different names",
            ));
        }
        if mode == CloneMode::Execute {
            store.ensure_layout()?;
        } else if store.existing_spaces_root()?.is_none() {
            return Err(space_not_found(source.as_str()));
        }
        let management = store.management_guard()?;
        let source_space = store.open(source)?;
        validate_shell(&source_space.manifest().default_shell)?;
        let activity_lock = acquire_lifecycle_lease(&source_space, source.as_str())?;
        let destination_path = store.space_path(destination);
        store.ensure_no_rollback_target(destination)?;
        reject_destination(&destination_path, destination.as_str())?;
        let staging = if mode == CloneMode::Execute {
            Some(prepare_staging(store, destination, destination_path)?)
        } else {
            None
        };
        drop(management);
        Ok(Self {
            source_manifest: source_space.manifest().clone(),
            source: source_space,
            _activity_lock: activity_lock,
            mode,
            destination: destination.clone(),
            staging,
        })
    }

    fn report(&self, include_cache: bool) -> CloneReport {
        CloneReport::new(
            self.source.manifest().name.as_str(),
            self.destination.as_str(),
            self.mode,
            self.source.layout(),
            include_cache,
        )
    }
}

fn prepare_staging(store: &Store, destination: &SpaceName, destination_path: PathBuf) -> Result<Staging> {
    let temporary = store.temporary_path(destination)?;
    if entry_exists(&temporary)? {
        return Err(
            QuartersError::new(ErrorKind::CorruptState, "reserved clone staging path already exists")
                .with_hint("run 'quarters doctor' and recover only validated stale state"),
        );
    }
    create_private_dir(&temporary)?;
    let creation_lock_path = temporary.join(crate::store_recovery::CREATION_LOCK_FILE);
    let creation_lock = acquire_creation_lock(&temporary, &creation_lock_path)?;
    if let Err(error) = create_private_dir(&temporary.join("home")) {
        drop(creation_lock);
        let _cleanup = remove_tree_restoring_owner_access(&temporary);
        return Err(error);
    }
    Ok(Staging {
        temporary,
        destination: destination_path,
        creation_lock_path,
        _creation_lock: creation_lock,
    })
}

fn destination_manifest(source: &Space, destination: SpaceName) -> Result<SpaceManifest> {
    let space_id = source.id().map(|_| SpaceId::generate()).transpose()?;
    Ok(SpaceManifest {
        schema_version: source.manifest().schema_version,
        layout: source.manifest().layout,
        space_id,
        name: destination,
        created_unix_ms: epoch_millis()?,
        default_shell: source.manifest().default_shell.clone(),
        authority_model: "host-account-state-profile".to_owned(),
    })
}

#[derive(Serialize)]
struct CloneProvenance<'a> {
    schema_version: u32,
    operation: &'static str,
    source: &'a str,
    created_unix_ms: u128,
    include_cache: bool,
    includes_sensitive_state: bool,
}

fn write_controls(
    root: &std::path::Path,
    source: &SpaceManifest,
    destination: &SpaceManifest,
    include_cache: bool,
) -> Result<()> {
    write_private_file(&root.join(".active"), b"")?;
    write_manifest(root, destination)?;
    let provenance = CloneProvenance {
        schema_version: 1,
        operation: "clone",
        source: source.name.as_str(),
        created_unix_ms: destination.created_unix_ms,
        include_cache,
        includes_sensitive_state: true,
    };
    let mut bytes = serde_json::to_vec_pretty(&provenance).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not serialize clone provenance").with_source(error)
    })?;
    bytes.push(b'\n');
    write_private_file(&root.join(".quarters-provenance.json"), &bytes)
}

fn publish(store: &Store, setup: &CloneSetup, manifest: &SpaceManifest, control: &CloneControl) -> Result<()> {
    #[cfg(not(test))]
    let _ = control;
    let staging = setup
        .staging
        .as_ref()
        .ok_or_else(|| QuartersError::new(ErrorKind::System, "clone publication has no private staging directory"))?;
    validate_space_anchors(&staging.temporary)?;
    validate_stored_manifest(manifest)?;
    let _management = store.management_guard()?;
    let reopened = store.open(&setup.source_manifest.name)?;
    if reopened.manifest() != &setup.source_manifest {
        return Err(
            QuartersError::new(ErrorKind::CorruptState, "source manifest changed during clone")
                .with_hint("inspect the source Quarter and retry"),
        );
    }
    store.ensure_no_rollback_target(&manifest.name)?;
    reject_destination(&staging.destination, manifest.name.as_str())?;
    #[cfg(test)]
    control.abort_before_publish()?;
    fs::remove_file(&staging.creation_lock_path)
        .map_err(|error| QuartersError::io("remove clone creation marker", &staging.creation_lock_path, error))?;
    sync_directory(&staging.temporary)?;
    fs::rename(&staging.temporary, &staging.destination)
        .map_err(|error| QuartersError::io("publish cloned space", &staging.destination, error))?;
    #[cfg(test)]
    control.abort_after_publish()?;
    sync_parent_directory(&staging.destination).map_err(|error| {
        error.with_hint(format!(
            "space '{}' was published completely, but directory durability could not be confirmed; inspect it before retrying",
            manifest.name
        ))
    })
}

fn reject_destination(path: &std::path::Path, name: &str) -> Result<()> {
    if !entry_exists(path)? {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::AlreadyExists,
        format!("space '{name}' already exists"),
    ))
}
