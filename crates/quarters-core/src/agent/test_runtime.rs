// SPDX-License-Identifier: GPL-3.0-or-later
//! Private runtime directories that unit tests remove on drop.

use crate::{HostEnvironment, Result, Space};
use std::path::PathBuf;

/// Owns a test space's private runtime directory and removes it on drop with
/// the same step `quarters rm` uses, so unit tests leave nothing in the shared
/// per-user runtime root.
pub(super) struct TestRuntime {
    space: Space,
    host: HostEnvironment,
}

impl TestRuntime {
    /// Create the runtime directory and return its guard and path.
    pub(super) fn create(space: &Space, host: &HostEnvironment) -> Result<(Self, PathBuf)> {
        let path = crate::platform::runtime_directory(space, host)?;
        let guard = Self {
            space: space.clone(),
            host: host.clone(),
        };
        Ok((guard, path))
    }
}

impl Drop for TestRuntime {
    fn drop(&mut self) {
        let removed = crate::platform::remove_runtime_directory(&self.space, &self.host);
        assert!(
            removed.is_ok() || std::thread::panicking(),
            "test runtime directory was not removed: {removed:?}"
        );
    }
}
