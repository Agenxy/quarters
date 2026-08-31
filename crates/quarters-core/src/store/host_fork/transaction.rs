//! Atomic host-fork staging, copy and publication.

use super::model::{HostForkMode, HostForkOptions, HostForkPolicy, HostForkReport};
use super::source::{PrepareRequest, PreparedHostFork, SourceFile, generated_conflict, prepare};
use crate::store::create::{acquire_creation_lock, populate_space};
use crate::store::lifecycle::StagingIdentity;
use crate::store_policy::{validate_private_file, validate_stored_manifest};
use crate::{ErrorKind, HostEnvironment, QuartersError, Result, SpaceLayout, SpaceName, Store};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::store::{
    create_private_dir, entry_exists, sync_directory, sync_parent_directory, validate_space_anchors, write_private_file,
};
use std::cell::Cell;

const ZSH_PROMPT_TAIL: &[u8] = b"\n# Quarters-managed state and context for this fork.\nHISTFILE=\"${XDG_STATE_HOME:-$HOME/.local/state}/shell/zsh_history\"\nsetopt APPEND_HISTORY INC_APPEND_HISTORY SHARE_HISTORY\nif command -v quarters >/dev/null 2>&1; then\n  eval \"$(quarters shell-init zsh 2>/dev/null)\"\nfi\n";
const BASH_PROMPT_TAIL: &[u8] = b"\n# Quarters-managed state and context for this fork.\nHISTFILE=\"${XDG_STATE_HOME:-$HOME/.local/state}/shell/bash_history\"\nexport HISTFILE\nif command -v quarters >/dev/null 2>&1; then\n  eval \"$(quarters shell-init bash 2>/dev/null)\"\nfi\n";

impl Store {
    /// Preview selected host state without creating store state.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe source anchor, path, destination or file.
    pub fn host_fork_plan(
        &self,
        host: &HostEnvironment,
        destination: &SpaceName,
        shell: &Path,
        layout: SpaceLayout,
        options: HostForkOptions<'_>,
    ) -> Result<HostForkReport> {
        preflight_destination(self, destination)?;
        prepare(
            self,
            &PrepareRequest {
                host,
                destination,
                shell,
                layout,
                policy: options.policy,
                explicit_paths: options.explicit_paths,
                replace_generated: options.replace_generated,
                mode: HostForkMode::Preview,
            },
        )
        .map(|prepared| prepared.report)
    }

    /// Create one space from a previously previewed, metadata-bound host plan.
    ///
    /// # Errors
    ///
    /// Returns an error when confirmation differs, a source generation changes,
    /// or atomic staging and publication cannot complete.
    pub fn create_from_host(
        &self,
        host: &HostEnvironment,
        destination: &SpaceName,
        shell: PathBuf,
        layout: SpaceLayout,
        options: HostForkOptions<'_>,
        confirmed_digest: &str,
    ) -> Result<HostForkReport> {
        validate_digest(confirmed_digest)?;
        self.ensure_layout()?;
        preflight_destination(self, destination)?;
        let mut prepared = prepare(
            self,
            &PrepareRequest {
                host,
                destination,
                shell: &shell,
                layout,
                policy: options.policy,
                explicit_paths: options.explicit_paths,
                replace_generated: options.replace_generated,
                mode: HostForkMode::Execute,
            },
        )?;
        if prepared.report.plan_digest != confirmed_digest {
            return Err(plan_mismatch_error(destination, &prepared.report.plan_digest));
        }
        reject_unapproved_conflicts(&prepared.report)?;
        let staging = prepare_staging(self, destination)?;
        let result = execute_staging(self, &mut prepared, &staging, destination, shell, layout);
        if let Err(original) = &result
            && !staging.published.get()
            && let Err(cleanup) = staging.identity.cleanup(&staging.temporary)
        {
            return Err(compound_host_fork_error(original, cleanup));
        }
        result
    }
}

struct Staging {
    temporary: PathBuf,
    destination: PathBuf,
    creation_lock_path: PathBuf,
    _creation_lock: File,
    identity: StagingIdentity,
    published: Cell<bool>,
}

fn execute_staging(
    store: &Store,
    prepared: &mut PreparedHostFork,
    staging: &Staging,
    destination: &SpaceName,
    shell: PathBuf,
    layout: SpaceLayout,
) -> Result<HostForkReport> {
    let manifest = populate_space(&staging.temporary, destination.clone(), shell, layout)?;
    copy_sources(
        &staging.temporary.join("home"),
        &mut prepared.sources,
        prepared.report.replace_generated,
    )?;
    write_provenance(&staging.temporary, &prepared.report, manifest.created_unix_ms)?;
    prepared.verify_sources()?;
    publish(store, staging, &manifest)?;
    let published = store.open(destination).map_err(|error| {
        error.with_hint(format!(
            "space '{destination}' was published completely but could not be reopened; inspect it before retrying"
        ))
    })?;
    prepared.report.set_mode(HostForkMode::Execute);
    prepared.report.destination_space_id = published.id().map(|id| id.as_str().to_owned());
    Ok(prepared.report.clone())
}

fn prepare_staging(store: &Store, destination: &SpaceName) -> Result<Staging> {
    let management = store.begin_mutation()?;
    let layout = management.layout();
    let temporary = layout.temporary_path(destination)?;
    if entry_exists(&temporary)? {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            "reserved host-fork staging path already exists",
        )
        .with_hint("run 'quarters doctor' and recover only validated stale state"));
    }
    create_private_dir(&temporary)?;
    let creation_lock_path = temporary.join(crate::store_recovery::CREATION_LOCK_FILE);
    let creation_lock = acquire_creation_lock(&temporary, &creation_lock_path)?;
    let identity = StagingIdentity::capture(&temporary, &creation_lock)?;
    Ok(Staging {
        temporary,
        destination: layout.space_path(destination),
        creation_lock_path,
        _creation_lock: creation_lock,
        identity,
        published: Cell::new(false),
    })
}

fn copy_sources(home: &Path, sources: &mut [SourceFile], replace_generated: bool) -> Result<()> {
    for source in sources {
        copy_source(home, source, replace_generated)?;
    }
    Ok(())
}

fn copy_source(home: &Path, source: &mut SourceFile, replace_generated: bool) -> Result<()> {
    let destination = home.join(&source.relative);
    if let Some(parent) = destination.parent() {
        create_private_dir(parent)?;
    }
    prepare_destination(&destination, &source.relative, replace_generated)?;
    source
        .file
        .rewind()
        .map_err(|error| QuartersError::io("rewind selected host file", &source.relative, error))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut output = options
        .open(&destination)
        .map_err(|error| QuartersError::io("create host-fork destination file", &destination, error))?;
    let copied = std::io::copy(
        &mut Read::by_ref(&mut source.file).take(source.metadata.length().saturating_add(1)),
        &mut output,
    )
    .map_err(|error| QuartersError::io("copy selected host file", &destination, error))?;
    if copied != source.metadata.length() {
        return Err(source_changed_error(&source.relative));
    }
    if let Some(tail) = prompt_tail(&source.relative) {
        output
            .write_all(tail)
            .map_err(|error| QuartersError::io("append managed prompt context", &destination, error))?;
    }
    output
        .sync_all()
        .map_err(|error| QuartersError::io("sync host-fork destination file", &destination, error))?;
    if !source.metadata.matches_file(&source.file)? {
        return Err(source_changed_error(&source.relative));
    }
    Ok(())
}

fn prepare_destination(destination: &Path, relative: &Path, replace_generated: bool) -> Result<()> {
    let metadata = match fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(QuartersError::io("inspect host-fork destination", destination, error)),
    };
    if !generated_conflict(relative) || !replace_generated {
        return Err(QuartersError::new(
            ErrorKind::AlreadyExists,
            format!(
                "generated destination conflicts with selected host path: {}",
                relative.display()
            ),
        )
        .with_hint("preview and confirm the same plan with --replace-generated"));
    }
    validate_private_file(destination, &metadata)?;
    fs::remove_file(destination)
        .map_err(|error| QuartersError::io("replace generated host-fork file", destination, error))
}

fn publish(store: &Store, staging: &Staging, manifest: &crate::SpaceManifest) -> Result<()> {
    validate_space_anchors(&staging.temporary)?;
    validate_stored_manifest(manifest)?;
    let _management = store.begin_mutation()?;
    store.ensure_no_rename_target(&manifest.name)?;
    store.ensure_no_rollback_target(&manifest.name)?;
    reject_destination_path(&staging.destination, manifest.name.as_str())?;
    staging
        .identity
        .verify(&staging.temporary, &staging.creation_lock_path)?;
    fs::remove_file(&staging.creation_lock_path)
        .map_err(|error| QuartersError::io("remove host-fork creation marker", &staging.creation_lock_path, error))?;
    sync_directory(&staging.temporary)?;
    fs::rename(&staging.temporary, &staging.destination)
        .map_err(|error| QuartersError::io("publish host-forked space", &staging.destination, error))?;
    staging.published.set(true);
    sync_parent_directory(&staging.destination).map_err(|error| {
        error.with_hint(format!(
            "space '{}' was published completely, but directory durability could not be confirmed; inspect it before retrying",
            manifest.name
        ))
    })?;
    Ok(())
}

#[derive(Serialize)]
struct HostForkProvenance<'a> {
    schema_version: u32,
    operation: &'static str,
    policy: HostForkPolicy,
    plan_digest: &'a str,
    created_unix_ms: u128,
    files: &'a [super::model::HostForkFile],
    ineligible: &'a [super::model::HostForkIneligible],
    excluded_categories: &'a [&'static str],
    content_uninspected: bool,
    may_include_sensitive_content: bool,
    source: &'static str,
}

fn write_provenance(root: &Path, report: &HostForkReport, created_unix_ms: u128) -> Result<()> {
    let provenance = HostForkProvenance {
        schema_version: 1,
        operation: "host-fork",
        policy: report.policy,
        plan_digest: &report.plan_digest,
        created_unix_ms,
        files: &report.files,
        ineligible: &report.ineligible,
        excluded_categories: &report.excluded_categories,
        content_uninspected: report.content_uninspected,
        may_include_sensitive_content: report.may_include_sensitive_content,
        source: "host-home",
    };
    let mut bytes = serde_json::to_vec_pretty(&provenance).map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not serialize host-fork provenance").with_source(error)
    })?;
    bytes.push(b'\n');
    write_private_file(&root.join(".quarters-provenance.json"), &bytes)
}

fn preflight_destination(store: &Store, destination: &SpaceName) -> Result<()> {
    store.ensure_no_rename_target(destination)?;
    store.ensure_no_rollback_target(destination)?;
    reject_destination_path(&store.layout()?.space_path(destination), destination.as_str())
}

fn reject_destination_path(path: &Path, name: &str) -> Result<()> {
    if !entry_exists(path)? {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::AlreadyExists,
        format!("space '{name}' already exists"),
    ))
}

fn reject_unapproved_conflicts(report: &HostForkReport) -> Result<()> {
    let conflicts = report.files.iter().filter(|file| file.generated_conflict).count();
    if conflicts == 0 || report.replace_generated {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::AlreadyExists,
        format!("host-fork plan has {conflicts} generated destination-file conflict(s)"),
    )
    .with_hint("repeat the preview with --replace-generated, review the changed digest, then confirm that exact plan"))
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::InvalidInput,
        "--confirm-plan must be exactly 64 lowercase hexadecimal characters",
    ))
}

fn plan_mismatch_error(destination: &SpaceName, current: &str) -> QuartersError {
    QuartersError::new(
        ErrorKind::CorruptState,
        "the host-fork plan changed after preview; nothing was created",
    )
    .with_hint(format!(
        "run 'quarters create {destination} --from-host shell --preview' again; the current digest is {current}"
    ))
}

fn source_changed_error(path: &Path) -> QuartersError {
    QuartersError::new(
        ErrorKind::CorruptState,
        format!(
            "selected host file changed while it was being copied: {}",
            path.display()
        ),
    )
    .with_hint("nothing was published; preview and confirm the new plan")
}

fn prompt_tail(path: &Path) -> Option<&'static [u8]> {
    match path.to_str() {
        Some(".zshrc") => Some(ZSH_PROMPT_TAIL),
        Some(".bashrc") => Some(BASH_PROMPT_TAIL),
        _ => None,
    }
}

fn compound_host_fork_error(original: &QuartersError, cleanup: QuartersError) -> QuartersError {
    QuartersError::new(
        original.kind(),
        format!(
            "host fork failed ({}) and its exact private staging generation could not be reclaimed",
            crate::escape_untrusted_text_bounded(original.message(), 256)
        ),
    )
    .with_hint("run 'quarters doctor', then recover only validated stale state")
    .with_source(cleanup)
}
