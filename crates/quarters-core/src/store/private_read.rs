//! Bounded reads of private metadata files, tolerant of atomic replacement.

use super::{MAX_MANIFEST_BYTES, missing_private_file};
use crate::store_policy::validate_private_file;
use crate::{ErrorKind, QuartersError, Result};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// Bounded retries when a private file is caught mid atomic replacement.
pub(crate) const REPLACED_FILE_READ_ATTEMPTS: u32 = 8;

/// Exponential pause before retry `attempt`: 1, 2, 4 … 128 ms, at most 255 ms
/// in total, so a reader outlasts real writer churn yet stays bounded.
pub(crate) fn replacement_backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_millis(1_u64 << attempt.min(REPLACED_FILE_READ_ATTEMPTS - 1))
}

pub(crate) fn read_private_file(path: &Path) -> Result<Vec<u8>> {
    for attempt in 0..REPLACED_FILE_READ_ATTEMPTS {
        if let Some(bytes) = read_private_file_once(path)? {
            return Ok(bytes);
        }
        std::thread::sleep(replacement_backoff(attempt));
    }
    Err(QuartersError::new(
        ErrorKind::ResourceLimit,
        format!(
            "a private metadata file kept being replaced during a bounded read: {}",
            path.display()
        ),
    ))
}

/// Read once, or return `None` when an atomic replacement retired the inode
/// being inspected. APFS can report such a name or descriptor with no remaining
/// link; that is a replacement in progress, not corruption.
fn read_private_file_once(path: &Path) -> Result<Option<Vec<u8>>> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| missing_private_file(path, error))?;
    if path_metadata.nlink() == 0 {
        return Ok(None);
    }
    validate_private_file(path, &path_metadata)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|error| QuartersError::io("open private file", path, error))?;
    let file_metadata = file
        .metadata()
        .map_err(|error| QuartersError::io("inspect private file", path, error))?;
    // The bytes trusted below come from this descriptor, so it must be the
    // exact inode whose path inspection was accepted; anything else is a
    // replacement in progress and the whole sequence is retried.
    let same_inode = (path_metadata.dev(), path_metadata.ino()) == (file_metadata.dev(), file_metadata.ino());
    if file_metadata.nlink() == 0 || !same_inode {
        return Ok(None);
    }
    validate_private_file(path, &file_metadata)?;
    if file_metadata.len() > MAX_MANIFEST_BYTES {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            format!(
                "private metadata file is larger than {MAX_MANIFEST_BYTES} bytes: {}",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| QuartersError::io("read private file", path, error))?;
    let maximum_size = usize::try_from(MAX_MANIFEST_BYTES).map_err(|error| {
        QuartersError::new(ErrorKind::System, "manifest size limit does not fit this platform").with_source(error)
    })?;
    if bytes.len() > maximum_size {
        return Err(QuartersError::new(
            ErrorKind::CorruptState,
            format!(
                "private metadata file grew beyond {MAX_MANIFEST_BYTES} bytes: {}",
                path.display()
            ),
        ));
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::read_private_file;
    use crate::ErrorKind;
    use crate::store::write_private_file;
    use crate::store_policy::validate_private_file;
    use std::error::Error;
    use std::fs::{self, File};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn a_retired_file_is_reported_as_replaced_not_hard_linked() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("record.json");
        write_private_file(&path, b"{}")?;
        let opened = File::open(&path)?;
        fs::remove_file(&path)?;
        let retired = opened.metadata()?;
        let Err(error) = validate_private_file(&path, &retired) else {
            return Err("a retired file must not validate".into());
        };
        assert_eq!(error.kind(), ErrorKind::CorruptState);
        assert!(error.to_string().contains("no remaining link"), "{error}");
        Ok(())
    }

    #[test]
    fn readers_never_mistake_an_atomic_replacement_for_corruption() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("manifest.json");
        write_private_file(&path, b"{\"generation\":0}")?;
        let replacing = Arc::new(AtomicBool::new(true));
        let writer_flag = Arc::clone(&replacing);
        let writer_directory = directory.path().to_path_buf();
        let writer_path = path.clone();
        // Real manifest and registry writers replace on discrete operations,
        // so the writer is paced: hundreds of replacements, each racing many
        // reads, rather than an adversarial hot loop no Quarters writer runs.
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            for generation in 1..=300_u32 {
                let temporary = writer_directory.join(format!(".manifest-{generation}.tmp"));
                write_private_file(&temporary, format!("{{\"generation\":{generation}}}").as_bytes())
                    .map_err(std::io::Error::other)?;
                fs::rename(&temporary, &writer_path)?;
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            writer_flag.store(false, Ordering::Release);
            Ok(())
        });
        let mut reads = 0_u32;
        let mut failure = None;
        while replacing.load(Ordering::Acquire) {
            match read_private_file(&path) {
                Ok(_bytes) => reads += 1,
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        replacing.store(false, Ordering::Release);
        writer.join().map_err(|_panic| "writer panicked")??;
        if let Some(error) = failure {
            return Err(format!("a read failed during paced replacement ({:?}): {error}", error.kind()).into());
        }
        assert!(reads > 300, "the reader raced too few replacements: {reads}");
        Ok(())
    }
}
