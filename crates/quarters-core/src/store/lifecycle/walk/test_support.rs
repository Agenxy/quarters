//! Deterministic hostile-source mutations for lifecycle tests.

use crate::{QuartersError, Result};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub(in crate::store::lifecycle) struct TestMutation {
    source_home: PathBuf,
    relative: PathBuf,
    action: TestMutationAction,
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
        }
    }

    pub(super) fn apply_if_selected(&self, observed: &[OsString]) -> Result<()> {
        let relative = observed.iter().collect::<PathBuf>();
        if relative != self.relative {
            return Ok(());
        }
        let target = self.source_home.join(&self.relative);
        match self.action {
            TestMutationAction::ReplaceRegular => {
                fs::remove_file(&target).map_err(|error| mutation_error("remove file", &target, error))?;
                fs::write(&target, b"replacement").map_err(|error| mutation_error("replace file", &target, error))
            }
            TestMutationAction::ReplaceDirectory => {
                fs::remove_dir(&target).map_err(|error| mutation_error("remove directory", &target, error))?;
                fs::create_dir(&target).map_err(|error| mutation_error("replace directory", &target, error))
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
        }
    }
}

fn mutation_error(operation: &str, path: &Path, source: std::io::Error) -> QuartersError {
    QuartersError::io(&format!("test mutation could not {operation}"), path, source)
}
