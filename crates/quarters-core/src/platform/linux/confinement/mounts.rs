//! Refuse grants whose mounted filesystem regions alias protected state.
//!
//! Descriptor ancestry stops at a mount root, so a bind or subtree mount can
//! expose protected inodes beneath a path that looks unrelated. The kernel
//! names the mount that actually serves each grant and protected path
//! (`statx` `STATX_MNT_ID`); mountinfo then places it on its filesystem as
//! `(device, root-relative path)`. Every mount nested beneath a grant or a
//! protected path adds its own region. A grant is refused when any of its
//! regions overlaps any protected region on the same device.

use crate::{ErrorKind, QuartersError, Result};
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

const MAX_MOUNTINFO_BYTES: u64 = 1_048_576;
const MAX_MOUNTS: usize = 8_192;
const MAX_LINE_BYTES: usize = 16_384;

struct Mount {
    id: u64,
    device: (u32, u32),
    // `None` for pseudo filesystems whose root is not a path, such as nsfs.
    root: Option<PathBuf>,
    point: PathBuf,
}

/// One filesystem region: a device and a path relative to its filesystem root.
#[derive(Debug, Eq, PartialEq)]
struct Region {
    device: (u32, u32),
    path: PathBuf,
}

impl Region {
    fn overlaps(&self, other: &Self) -> bool {
        self.device == other.device && (self.path.starts_with(&other.path) || other.path.starts_with(&self.path))
    }
}

pub(super) struct MountTopology(Vec<Mount>);

impl MountTopology {
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
        let mut mounts = Vec::new();
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
            mounts.push(parse_line(line)?);
        }
        if mounts.is_empty() {
            return Err(invalid_mountinfo());
        }
        Ok(Self(mounts))
    }

    /// Refuse a grant whose visible filesystem regions overlap protected state.
    ///
    /// # Errors
    ///
    /// Returns `Unsupported` when the grant, or any mount beneath it, exposes
    /// a region overlapping a protected path or any mount beneath one, and
    /// when a path cannot be located through the kernel's mount identity.
    pub(super) fn reject_overlap(&self, grant: &Path, protected: &[PathBuf]) -> Result<()> {
        self.reject_overlap_with(grant, protected, &kernel_mount)
    }

    fn reject_overlap_with(&self, grant: &Path, protected: &[PathBuf], locate: &Locator<'_>) -> Result<()> {
        let mut reserved = Vec::new();
        for path in protected {
            reserved.push(self.region(path, locate)?);
            reserved.extend(self.beneath(path));
        }
        let mut exposed = vec![self.region(grant, locate)?];
        exposed.extend(self.beneath(grant));
        if exposed
            .iter()
            .all(|region| reserved.iter().all(|protected| !region.overlaps(protected)))
        {
            return Ok(());
        }
        Err(QuartersError::new(
            ErrorKind::Unsupported,
            "user grant exposes a mounted alias of protected filesystem state",
        )
        .with_hint("select a data path that no bind, subtree or nested mount connects to protected roots"))
    }

    /// Regions of every listed mount strictly beneath a path, hidden or not.
    fn beneath<'a>(&'a self, path: &'a Path) -> impl Iterator<Item = Region> + 'a {
        self.0
            .iter()
            .filter(move |mount| mount.point != path && mount.point.starts_with(path))
            .filter_map(|mount| {
                mount.root.clone().map(|root| Region {
                    device: mount.device,
                    path: root,
                })
            })
    }

    /// Place a path on its filesystem through the mount the kernel reports.
    fn region(&self, path: &Path, locate: &Locator<'_>) -> Result<Region> {
        let (id, existing) = locate(path)?;
        let mount = self
            .0
            .iter()
            .find(|mount| mount.id == id)
            .ok_or_else(|| unlocated(path))?;
        let root = mount.root.as_ref().ok_or_else(|| unlocated(path))?;
        let served = existing.strip_prefix(&mount.point).map_err(|_error| unlocated(path))?;
        let missing = path.strip_prefix(&existing).map_err(|_error| unlocated(path))?;
        Ok(Region {
            device: mount.device,
            path: root.join(served).join(missing),
        })
    }
}

/// Resolve a path to `(mount id, nearest existing ancestor-or-self)`.
type Locator<'a> = dyn Fn(&Path) -> Result<(u64, PathBuf)> + 'a;

fn kernel_mount(path: &Path) -> Result<(u64, PathBuf)> {
    use rustix::fs::{AtFlags, CWD, StatxFlags, statx};
    for candidate in path.ancestors() {
        match statx(CWD, candidate, AtFlags::SYMLINK_NOFOLLOW, StatxFlags::MNT_ID) {
            Ok(status) if status.stx_mask & StatxFlags::MNT_ID.bits() != 0 => {
                return Ok((status.stx_mnt_id, candidate.to_path_buf()));
            }
            Ok(_) => break,
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => {
                return Err(QuartersError::io(
                    "identify the mount serving a filesystem policy path",
                    candidate,
                    error.into(),
                ));
            }
        }
    }
    Err(unlocated(path))
}

fn parse_line(line: &[u8]) -> Result<Mount> {
    // The source field may legitimately be empty, so only the fields this
    // module reads are required to be non-empty.
    let fields: Vec<_> = line.split(|byte| *byte == b' ').collect();
    let separator = fields
        .iter()
        .position(|field| *field == b"-")
        .ok_or_else(invalid_mountinfo)?;
    if separator < 6 || fields.len() != separator + 4 || fields[..5].iter().any(|field| field.is_empty()) {
        return Err(invalid_mountinfo());
    }
    if !fields[1].iter().all(u8::is_ascii_digit) {
        return Err(invalid_mountinfo());
    }
    let id = parse_number(fields[0])?;
    let device = parse_device(fields[2])?;
    let root = decode_path(fields[3])?;
    let point = decode_path(fields[4])?;
    if !point.is_absolute() {
        return Err(invalid_mountinfo());
    }
    Ok(Mount {
        id,
        device,
        root: root.is_absolute().then_some(root),
        point,
    })
}

fn parse_number(field: &[u8]) -> Result<u64> {
    if field.is_empty() || !field.iter().all(u8::is_ascii_digit) {
        return Err(invalid_mountinfo());
    }
    std::str::from_utf8(field)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or_else(invalid_mountinfo)
}

fn parse_device(field: &[u8]) -> Result<(u32, u32)> {
    let text = std::str::from_utf8(field).map_err(|_error| invalid_mountinfo())?;
    let (major, minor) = text.split_once(':').ok_or_else(invalid_mountinfo)?;
    let parse = |part: &str| {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid_mountinfo());
        }
        part.parse::<u32>().map_err(|_error| invalid_mountinfo())
    };
    Ok((parse(major)?, parse(minor)?))
}

fn invalid_mountinfo() -> QuartersError {
    QuartersError::new(ErrorKind::Unsupported, "filesystem policy mount topology is malformed")
}

fn unlocated(path: &Path) -> QuartersError {
    QuartersError::new(
        ErrorKind::Unsupported,
        "a filesystem policy path cannot be located in the mount topology",
    )
    .with_hint(format!(
        "verify that {} is on a path-addressable filesystem",
        path.display()
    ))
}

/// Decode the kernel's three-digit octal escapes in a mountinfo path field.
fn decode_path(bytes: &[u8]) -> Result<PathBuf> {
    let mut output = Vec::with_capacity(bytes.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            let digits = bytes.get(cursor + 1..cursor + 4).ok_or_else(invalid_mountinfo)?;
            if !digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
                return Err(invalid_mountinfo());
            }
            let value = digits
                .iter()
                .fold(0_u16, |value, digit| value * 8 + u16::from(digit - b'0'));
            output.push(u8::try_from(value).map_err(|_error| invalid_mountinfo())?);
            cursor += 4;
        } else {
            output.push(bytes[cursor]);
            cursor += 1;
        }
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(output)))
}

#[cfg(test)]
mod tests {
    use super::MountTopology;
    use crate::Result;
    use std::error::Error;
    use std::path::{Path, PathBuf};

    const HOST: &[u8] = b"\
1 0 8:1 / / rw - ext4 /dev/sda1 rw
2 1 8:2 / /home rw - ext4 /dev/sda2 rw
3 1 0:4 net:[4026531840] /run/netns/a rw - nsfs nsfs rw
4 1 0:5 / /run/user/1000 rw - tmpfs  rw
";

    fn store() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/home/u/.local/share/quarters"),
            PathBuf::from("/home/u/.ssh"),
        ]
    }

    fn with(extra: &[u8]) -> std::result::Result<MountTopology, Box<dyn Error>> {
        Ok(MountTopology::parse(&[HOST, extra].concat())?)
    }

    /// Stand in for the kernel: the last-listed mount at the longest point.
    fn listed(topology: &MountTopology) -> impl Fn(&Path) -> Result<(u64, PathBuf)> + '_ {
        |path| {
            let mount = topology
                .0
                .iter()
                .filter(|mount| path.starts_with(&mount.point))
                .fold(None::<&super::Mount>, |best, mount| match best {
                    Some(best) if best.point.as_os_str().len() > mount.point.as_os_str().len() => Some(best),
                    _ => Some(mount),
                })
                .ok_or_else(|| super::unlocated(path))?;
            Ok((mount.id, path.to_path_buf()))
        }
    }

    fn check(topology: &MountTopology, grant: &str, protected: &[PathBuf]) -> Result<()> {
        topology.reject_overlap_with(Path::new(grant), protected, &listed(topology))
    }

    #[test]
    fn ordinary_grants_pass_beside_nsfs_and_empty_sources() -> std::result::Result<(), Box<dyn Error>> {
        let mounts = with(b"")?;
        for grant in ["/srv/data", "/home/u/projects", "/tmp", "/run/user/1000/work"] {
            check(&mounts, grant, &store())?;
        }
        Ok(())
    }

    #[test]
    fn subtree_and_whole_filesystem_aliases_are_refused() -> std::result::Result<(), Box<dyn Error>> {
        let cases: [(&[u8], &[&str]); 3] = [
            // A bind of only the protected child, granted directly or by a container.
            (
                b"9 1 8:2 /u/.local/share/quarters/spaces /srv/alias rw - ext4 /dev/sda2 rw\n",
                &["/srv/alias", "/srv/alias/x", "/srv"],
            ),
            // The whole home filesystem mounted a second time beneath a grant.
            (
                b"9 1 8:2 / /mnt/home rw - ext4 /dev/sda2 rw\n",
                &["/mnt", "/mnt/home/u"],
            ),
            // `mount --bind / /mnt/alias` exposes the root filesystem again.
            (b"9 1 8:1 / /mnt/alias rw - ext4 /dev/sda1 rw\n", &["/mnt"]),
        ];
        for (extra, grants) in cases {
            let mounts = with(extra)?;
            let protected = [store(), vec![PathBuf::from("/usr/bin")]].concat();
            for grant in grants {
                assert!(check(&mounts, grant, &protected).is_err(), "{grant}");
            }
            check(&mounts, "/srv/alias-other", &store())?;
        }
        Ok(())
    }

    #[test]
    fn mounts_beneath_protected_roots_are_protected() -> std::result::Result<(), Box<dyn Error>> {
        // The store keeps its spaces on a data disk bound beneath the store root.
        let mounts = with(b"9 2 8:3 /qspaces /home/u/.local/share/quarters/spaces rw - ext4 /dev/sdb1 rw\n10 1 8:3 / /data rw - ext4 /dev/sdb1 rw\n")?;
        assert!(check(&mounts, "/data/qspaces/other", &store()).is_err());
        assert!(check(&mounts, "/data", &store()).is_err());
        check(&mounts, "/data/unrelated", &store())?;
        Ok(())
    }

    #[test]
    fn the_serving_mount_decides_even_when_listed_earlier() -> std::result::Result<(), Box<dyn Error>> {
        // A tmpfs at /srv/protected is later covered by a bind of the spaces
        // directory over /srv; the kernel serves /srv/protected from the bind.
        let mounts = with(
            b"9 1 0:9 / /srv/protected rw - tmpfs  rw\n10 1 8:2 /u/.local/share/quarters/spaces /srv rw - ext4 /dev/sda2 rw\n",
        )?;
        let serving_bind = |path: &Path| Ok((10, path.to_path_buf()));
        assert!(
            mounts
                .reject_overlap_with(Path::new("/srv/protected"), &store(), &serving_bind)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn btrfs_subvolume_roots_are_not_false_aliases() -> std::result::Result<(), Box<dyn Error>> {
        let mounts = MountTopology::parse(
            b"1 0 0:30 /root / rw - btrfs /dev/vda3 rw\n2 1 0:30 /home /home rw - btrfs /dev/vda3 rw\n",
        )?;
        check(&mounts, "/srv/data", &store())?;
        check(&mounts, "/home/u/projects", &store())?;
        assert!(check(&mounts, "/home/u", &store()).is_err());
        Ok(())
    }

    #[test]
    fn escapes_and_malformed_topology_fail_closed() -> std::result::Result<(), Box<dyn Error>> {
        let mounts = with(b"9 1 8:2 /u/.ssh /srv/a\\040b rw - none none rw\n")?;
        assert!(check(&mounts, "/srv/a b/nested", &store()).is_err());
        for malformed in [
            &b"invalid\n"[..],
            b"2 1 0:1 / /bad\\999 rw - none none rw\n",
            b"2 1 0:1 / /valid rw - none none rw",
            b"2 1 0:1 / /valid rw\n",
            b"2 1 0:x / /valid rw - none none rw\n",
            b"x 1 0:1 / /valid rw - none none rw\n",
            b"2 1 0:1 / relative rw - none none rw\n",
            b"",
        ] {
            assert!(MountTopology::parse(malformed).is_err());
        }
        Ok(())
    }
}
