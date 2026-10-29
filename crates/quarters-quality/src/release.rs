// SPDX-License-Identifier: GPL-3.0-or-later
//! Release-artifact guard: no test-only steering hook may ship.

use std::fs;
use std::path::Path;

/// Prefix of every debug-only environment hook; none may appear in a release.
const TEST_HOOK_PREFIX: &[u8] = b"QUARTERS_TEST_";

/// Refuse a built binary that still contains a test-only environment hook.
///
/// The hooks sit behind `debug_assertions`, so finding one means a release
/// profile compiled them in and the binary could be steered from its
/// environment.
pub(crate) fn check_release_binary(path: &Path) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|error| format!("{}: cannot read release binary: {error}", path.display()))?;
    if bytes.is_empty() {
        return Err(format!("{}: release binary is empty", path.display()));
    }
    if bytes
        .windows(TEST_HOOK_PREFIX.len())
        .any(|window| window == TEST_HOOK_PREFIX)
    {
        return Err(format!(
            "{}: contains a QUARTERS_TEST_ hook; debug_assertions must stay off in release builds",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_release_binary;
    use std::error::Error;
    use std::fs;

    #[test]
    fn a_binary_carrying_a_test_hook_is_refused() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let clean = directory.path().join("clean");
        let steered = directory.path().join("steered");
        let empty = directory.path().join("empty");
        fs::write(&clean, b"\x7fELF ordinary release bytes QUARTERS_ROOT")?;
        fs::write(&steered, b"\x7fELF prefix QUARTERS_TEST_AGENT_EXIT_ONCE suffix")?;
        fs::write(&empty, b"")?;
        check_release_binary(&clean)?;
        assert!(check_release_binary(&steered).is_err());
        assert!(check_release_binary(&empty).is_err());
        assert!(check_release_binary(&directory.path().join("missing")).is_err());
        Ok(())
    }
}
