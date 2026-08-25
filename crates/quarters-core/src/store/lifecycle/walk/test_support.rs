//! Deterministic hostile-source mutations for lifecycle tests.

use crate::{QuartersError, Result};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Debug)]
pub(in crate::store::lifecycle) struct TestMutation {
    source_home: PathBuf,
    relative: PathBuf,
    action: TestMutationAction,
    applied: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::store::lifecycle) enum TestMutationAction {
    ReplaceRegular,
    ReplaceDirectory,
    ReplaceSymlink,
    DeleteRegular,
    GrowRegular { bytes: usize },
}

impl TestMutation {
    pub(in crate::store::lifecycle) fn new(source_home: &Path, relative: &Path, action: TestMutationAction) -> Self {
        Self {
            source_home: source_home.to_path_buf(),
            relative: relative.to_path_buf(),
            action,
            applied: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(in crate::store::lifecycle) fn was_applied(&self) -> bool {
        self.applied.load(Ordering::SeqCst)
    }

    pub(super) fn apply_before_open_if_selected(&self, observed: &[OsString]) -> Result<()> {
        if matches!(self.action, TestMutationAction::GrowRegular { .. }) {
            return Ok(());
        }
        self.apply_if_selected(observed)
    }

    pub(super) fn apply_after_open_if_selected(&self, observed: &[OsString]) -> Result<()> {
        if !matches!(self.action, TestMutationAction::GrowRegular { .. }) {
            return Ok(());
        }
        self.apply_if_selected(observed)
    }

    fn apply_if_selected(&self, observed: &[OsString]) -> Result<()> {
        let relative = observed.iter().collect::<PathBuf>();
        if relative != self.relative {
            return Ok(());
        }
        let target = self.source_home.join(&self.relative);
        let result = match self.action {
            TestMutationAction::ReplaceRegular => {
                fs::remove_file(&target).map_err(|error| mutation_error("remove file", &target, error))?;
                fs::write(&target, b"replacement").map_err(|error| mutation_error("replace file", &target, error))
            }
            TestMutationAction::ReplaceDirectory => {
                fs::remove_dir(&target).map_err(|error| mutation_error("remove directory", &target, error))?;
                fs::create_dir(&target).map_err(|error| mutation_error("replace directory", &target, error))?;
                fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
                    .map_err(|error| mutation_error("set replacement directory mode", &target, error))
            }
            TestMutationAction::ReplaceSymlink => {
                fs::remove_file(&target).map_err(|error| mutation_error("remove link", &target, error))?;
                symlink("replacement", &target).map_err(|error| mutation_error("replace link", &target, error))
            }
            TestMutationAction::DeleteRegular => {
                fs::remove_file(&target).map_err(|error| mutation_error("delete file", &target, error))
            }
            TestMutationAction::GrowRegular { bytes } => {
                let mut file = OpenOptions::new()
                    .append(true)
                    .open(&target)
                    .map_err(|error| mutation_error("open growing file", &target, error))?;
                file.write_all(&vec![b'x'; bytes])
                    .map_err(|error| mutation_error("grow file", &target, error))
            }
        };
        if result.is_ok() {
            self.applied.store(true, Ordering::SeqCst);
        }
        result
    }
}

fn mutation_error(operation: &str, path: &Path, source: std::io::Error) -> QuartersError {
    QuartersError::io(&format!("test mutation could not {operation}"), path, source)
}
