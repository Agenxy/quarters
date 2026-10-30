// SPDX-License-Identifier: GPL-3.0-or-later
//! Recovery of removals that the published alpha.1 and alpha.2 releases left
//! in trash.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use fs4::FileExt;

use crate::store::scan::ScanBudget;
use crate::store::{entry_exists, open_private_lock};
use crate::store_policy::validate_private_dir;
use crate::store_recovery::MAX_RECOVERY_ENTRIES;
use crate::{ErrorKind, HostEnvironment, QuartersError, Result, SpaceName};

/// A space a published alpha retired but failed to delete, and the path it
/// had while live, from which that alpha named its runtime directory.
pub(crate) struct PublishedAlphaRetirement {
    pub(crate) name: SpaceName,
    pub(crate) space_root: PathBuf,
}

/// alpha.1 and alpha.2 retired a space as `<name>-<pid>-<millis>` in trash and
/// deleted it in place, so a failed deletion left that entry behind.
fn published_alpha_retired_name(name: &OsStr) -> Option<SpaceName> {
    let mut parts = name.to_str()?.rsplitn(3, '-');
    let millis = parts.next()?;
    let pid = parts.next()?;
    let space = parts.next()?;
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    if !digits(millis) || !digits(pid) {
        return None;
    }
    SpaceName::parse(space.to_owned()).ok()
}

pub(crate) fn published_alpha_retired_entries(trash: &Path) -> Result<Vec<(PathBuf, SpaceName)>> {
    let entries = fs::read_dir(trash).map_err(|error| QuartersError::io("read recovery parent", trash, error))?;
    let mut matches = Vec::new();
    let mut scan = ScanBudget::new("the store recovery parent");
    for entry in entries {
        let entry = entry.map_err(|error| QuartersError::io("read recovery entry", trash, error))?;
        scan.observe()?;
        let Some(name) = published_alpha_retired_name(&entry.file_name()) else {
            continue;
        };
        if matches.len() >= MAX_RECOVERY_ENTRIES {
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                "the store contains more than 1024 reserved recovery entries",
            )
            .with_hint("inspect the protected store root before attempting recovery"));
        }
        matches.push((entry.path(), name));
    }
    Ok(matches)
}

/// Published-alpha entries whose cooperative lease nobody holds; an entry a
/// process still holds is left for a later recovery.
pub(crate) fn unleased_published_alpha_entries(trash: &Path) -> Result<Vec<(PathBuf, SpaceName)>> {
    let mut unleased = Vec::new();
    for (path, name) in published_alpha_retired_entries(trash)? {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| QuartersError::io("inspect recovery directory", &path, error))?;
        validate_private_dir(&path, &metadata)?;
        let lock_path = path.join(".active");
        if entry_exists(&lock_path)? {
            let lock = open_private_lock(&lock_path)?;
            match <File as FileExt>::try_lock(&lock) {
                Ok(()) => {}
                Err(fs4::TryLockError::WouldBlock) => continue,
                Err(fs4::TryLockError::Error(error)) => {
                    return Err(QuartersError::io("lock retired space for recovery", &lock_path, error));
                }
            }
        }
        unleased.push((path, name));
    }
    Ok(unleased)
}

/// Remove each recovered space's published-alpha runtime, unless a space of
/// that name exists again and may own it.
pub(crate) fn remove_published_alpha_runtimes(published: &[PublishedAlphaRetirement]) -> Result<()> {
    if published.is_empty() {
        return Ok(());
    }
    let host = HostEnvironment::capture();
    for retirement in published {
        if !entry_exists(&retirement.space_root)? {
            crate::platform::remove_published_alpha_runtime(retirement.name.as_str(), &retirement.space_root, &host)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    /// Lay out a store exactly as alpha.2 left it after a failed `rm`: no
    /// layout marker, and the space retired in place as `<name>-<pid>-<millis>`
    /// with its lease file, manifest and a partly deleted read-only home.
    fn alpha2_store_with_stranded_space(
        root: &Path,
        name: &str,
    ) -> std::result::Result<PathBuf, Box<dyn std::error::Error>> {
        for directory in [root.to_path_buf(), root.join("spaces"), root.join("trash")] {
            fs::create_dir_all(&directory)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        let retired = root.join("trash").join(format!("{name}-80423-1793317282985"));
        fs::create_dir(&retired)?;
        fs::set_permissions(&retired, fs::Permissions::from_mode(0o700))?;
        fs::write(retired.join(".active"), b"")?;
        fs::set_permissions(retired.join(".active"), fs::Permissions::from_mode(0o600))?;
        let manifest = serde_json::json!({
            "schema_version": 1,
            "name": name,
            "created_unix_ms": 1_793_290_860_761_u64,
            "default_shell": "/bin/zsh",
            "authority_model": "host-account-state-profile",
        })
        .to_string();
        fs::write(retired.join(".quarters.json"), manifest)?;
        fs::set_permissions(retired.join(".quarters.json"), fs::Permissions::from_mode(0o600))?;
        let module = retired.join("home/go/pkg/mod/example.com/m@v1.0.0");
        fs::create_dir_all(&module)?;
        fs::write(module.join("m.go"), b"package m\n")?;
        for directory in [
            module.clone(),
            retired.join("home/go/pkg/mod/example.com"),
            retired.join("home/go/pkg/mod"),
        ] {
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o555))?;
        }
        Ok(retired)
    }

    #[test]
    fn recovery_finishes_a_removal_a_published_alpha_left_in_trash()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let root = temporary.path().join("root");
        let retired = alpha2_store_with_stranded_space(&root, "stranded")?;
        let unrelated = root.join("trash").join("notes");
        fs::create_dir(&unrelated)?;
        fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o700))?;
        let host = HostEnvironment::capture();
        let runtime = crate::platform::published_alpha_runtime_path("stranded", &root.join("spaces/stranded"), &host);
        for directory in [runtime.clone(), runtime.join("tmp")] {
            fs::create_dir_all(&directory)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        let store = Store::new(root.clone())?;

        assert_eq!(store.recovery_summary()?.retired_entries, 1);
        let summary = store.recover()?;

        assert_eq!(summary.retired_entries, 1);
        assert!(!retired.exists());
        assert!(!runtime.exists(), "{} survived recovery", runtime.display());
        assert!(unrelated.is_dir(), "an entry outside the published naming was touched");
        assert_eq!(store.recovery_summary()?.retired_entries, 0);
        Ok(())
    }

    #[test]
    fn recovery_leaves_a_leased_published_alpha_entry_and_a_reused_name_runtime()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let root = temporary.path().join("root");
        let retired = alpha2_store_with_stranded_space(&root, "leased")?;
        let lease = File::open(retired.join(".active"))?;
        <File as FileExt>::try_lock(&lease)?;
        let store = Store::new(root.clone())?;

        store.recover()?;
        assert!(retired.join(".quarters.json").is_file(), "a held entry was removed");
        drop(lease);

        store.create(SpaceName::parse("leased")?, PathBuf::from("/bin/sh"))?;
        let host = HostEnvironment::capture();
        let runtime = crate::platform::published_alpha_runtime_path("leased", &root.join("spaces/leased"), &host);
        for directory in [runtime.clone(), runtime.join("tmp")] {
            fs::create_dir_all(&directory)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        store.recover()?;
        assert!(!retired.exists());
        assert!(
            runtime.is_dir(),
            "the runtime of a live space with the same name was removed"
        );
        fs::remove_dir_all(&runtime)?;
        store.remove("leased")?;
        Ok(())
    }
}
