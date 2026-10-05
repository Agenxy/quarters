//! Refuse subtree mounts that hide a grant's original inode ancestry.

use crate::{ErrorKind, QuartersError, Result};
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

const MAX_MOUNTINFO_BYTES: u64 = 1_048_576;
const MAX_MOUNTS: usize = 8_192;
const MAX_LINE_BYTES: usize = 16_384;

pub(super) struct SubtreeMounts(Vec<PathBuf>);

impl SubtreeMounts {
    pub(super) fn read() -> Result<Self> {
        let path = Path::new("/proc/self/mountinfo");
        let mut bytes = Vec::new();
        File::open(path)
            .and_then(|file| file.take(MAX_MOUNTINFO_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|error| QuartersError::io("read filesystem policy mount topology", path, error))?;
        if u64::try_from(bytes.len()).map_or(true, |size| size > MAX_MOUNTINFO_BYTES) {
            return Err(QuartersError::new(
                ErrorKind::ResourceLimit,
                "mount topology exceeds one MiB",
            ));
        }
        Self::parse(&bytes)
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.last() != Some(&b'\n') {
            return Err(invalid_mountinfo());
        }
        let mut points = Vec::new();
        for (count, line) in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n').enumerate() {
            if count >= MAX_MOUNTS {
                return Err(QuartersError::new(
                    ErrorKind::ResourceLimit,
                    "mount topology exceeds 8,192 entries",
                ));
            }
            if line.len() > MAX_LINE_BYTES {
                return Err(QuartersError::new(
                    ErrorKind::ResourceLimit,
                    "mount topology line exceeds 16 KiB",
                ));
            }
            if let Some(point) = parse_line(line)? {
                points.push(point);
            }
        }
        Ok(Self(points))
    }

    pub(super) fn reject_overlap(&self, path: &Path) -> Result<()> {
        if self
            .0
            .iter()
            .all(|point| !path.starts_with(point) && !point.starts_with(path))
        {
            return Ok(());
        }
        Err(QuartersError::new(
            ErrorKind::Unsupported,
            "user grant overlaps a subtree mount whose original ancestry cannot be verified",
        )
        .with_hint("select a data path outside bind-mounted subtrees and subvolume mounts"))
    }
}

fn parse_line(line: &[u8]) -> Result<Option<PathBuf>> {
    let fields: Vec<_> = line.split(|byte| *byte == b' ').collect();
    if fields.len() < 10 || fields.iter().any(|field| field.is_empty()) {
        return Err(invalid_mountinfo());
    }
    let separator = fields
        .iter()
        .position(|field| *field == b"-")
        .ok_or_else(invalid_mountinfo)?;
    if separator < 6
        || fields.len() != separator + 4
        || !fields[0].iter().all(u8::is_ascii_digit)
        || !fields[1].iter().all(u8::is_ascii_digit)
    {
        return Err(invalid_mountinfo());
    }
    let mut device = fields[2].split(|byte| *byte == b':');
    for _ in 0..2 {
        let part = device.next().ok_or_else(invalid_mountinfo)?;
        if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
            return Err(invalid_mountinfo());
        }
    }
    if device.next().is_some() {
        return Err(invalid_mountinfo());
    }
    let root = decode_path(fields[3])?;
    let point = decode_path(fields[4])?;
    Ok((root != Path::new("/")).then_some(point))
}

fn invalid_mountinfo() -> QuartersError {
    QuartersError::new(ErrorKind::Unsupported, "filesystem policy mount topology is malformed")
}

fn decode_path(bytes: &[u8]) -> Result<PathBuf> {
    let mut output = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            let escaped = bytes.get(cursor..cursor + 4).ok_or_else(invalid_mountinfo)?;
            output.push(match escaped {
                b"\\040" => b' ',
                b"\\011" => b'\t',
                b"\\012" => b'\n',
                b"\\134" => b'\\',
                _ => return Err(invalid_mountinfo()),
            });
            cursor += 4;
        } else {
            output.push(bytes[cursor]);
            cursor += 1;
        }
    }
    let path = PathBuf::from(std::ffi::OsString::from_vec(output));
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(invalid_mountinfo())
    }
}

#[cfg(test)]
mod tests {
    use super::SubtreeMounts;
    use std::error::Error;
    use std::path::Path;

    #[test]
    fn subtree_aliases_and_grants_containing_them_are_refused() -> Result<(), Box<dyn Error>> {
        let mounts = SubtreeMounts::parse(
            b"1 0 0:1 / / rw - overlay overlay rw\n2 1 0:1 /private/store/child /srv/alias rw - none none rw\n",
        )?;
        for path in ["/srv/alias", "/srv/alias/nested", "/srv"] {
            assert!(mounts.reject_overlap(Path::new(path)).is_err());
        }
        mounts.reject_overlap(Path::new("/workspace"))?;
        mounts.reject_overlap(Path::new("/srv/alias-other"))?;
        Ok(())
    }

    #[test]
    fn escaped_mount_points_preserve_path_components() -> Result<(), Box<dyn Error>> {
        let mounts = SubtreeMounts::parse(b"2 1 0:1 /hidden /srv/a\\040b rw - none none rw\n")?;
        assert!(mounts.reject_overlap(Path::new("/srv/a b/nested")).is_err());
        assert!(SubtreeMounts::parse(b"invalid\n").is_err());
        assert!(SubtreeMounts::parse(b"2 1 0:1 /hidden /bad\\999 rw\n").is_err());
        assert!(SubtreeMounts::parse(b"2 1 0:1 / /bad\\999 rw - none none rw\n").is_err());
        assert!(SubtreeMounts::parse(b"2 1 0:1 / /valid rw - none none rw").is_err());
        assert!(SubtreeMounts::parse(b"2 1 0:1 / /valid rw\n").is_err());
        Ok(())
    }
}
