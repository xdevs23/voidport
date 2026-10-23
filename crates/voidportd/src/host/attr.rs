//! The `ino` is never the host ino: it is the server-global synthetic number
//! keyed by `(host_dev, host_ino)`, so identity is stable across sessions and
//! hardlink aliases share it. Raw host inos collide across devices.

use std::os::fd::BorrowedFd;

use rustix::fs::{AtFlags, FileType, Statx, StatxFlags, makedev, statx};
use rustix::io::Errno;
use voidport_proto::attr::{Attr, Timespec, file_type};
use zerocopy::byteorder::little_endian::{U32, U64};

use crate::records::Privileged;
use crate::rules::{
    EffectiveMode, HostIds, OwnerPresentation, Ownership, SYNTHESIZED_DIR_PERMISSIONS,
    presented_mode,
};

/// Captured once at startup and never read from the clock again, so the
/// structural skeleton of a namespace does not appear to change under a guest
/// that caches attributes. The start time is used instead of zero,
/// because zero presents as 1970.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynthesizedTimes(Timespec);

impl SynthesizedTimes {
    #[must_use]
    pub fn at_startup() -> Self {
        Self::at(std::time::SystemTime::now())
    }

    fn at(now: std::time::SystemTime) -> Self {
        // A host clock standing before the epoch falls back to the epoch.
        let since_epoch = now
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        Self(Timespec::new(
            i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX),
            since_epoch.subsec_nanos(),
        ))
    }

    #[must_use]
    pub fn timestamp(self) -> Timespec {
        self.0
    }
}

const SYNTHESIZED_BLKSIZE: u32 = 4096;

const SYNTHESIZED_NLINK: u32 = 2;

const S_IFDIR: u32 = 0o040_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileKind {
    Directory,
    Symlink,
    Regular,
    Other,
}

impl FileKind {
    #[must_use]
    pub fn of(host_mode: u32) -> Self {
        match FileType::from_raw_mode(host_mode) {
            FileType::Directory => Self::Directory,
            FileType::Symlink => Self::Symlink,
            FileType::RegularFile => Self::Regular,
            _ => Self::Other,
        }
    }

    #[must_use]
    pub fn is_directory(self) -> bool {
        self == Self::Directory
    }

    #[must_use]
    pub fn dirent_type(self, host_mode: u32) -> u32 {
        match self {
            Self::Directory => file_type::DIR,
            Self::Symlink => file_type::LNK,
            Self::Regular => file_type::REG,
            Self::Other => match FileType::from_raw_mode(host_mode) {
                FileType::CharacterDevice => file_type::CHR,
                FileType::BlockDevice => file_type::BLK,
                FileType::Fifo => file_type::FIFO,
                FileType::Socket => file_type::SOCK,
                _ => file_type::UNKNOWN,
            },
        }
    }
}

/// What a listing remembers about the host inode of an entry. The attributes are
/// not part of it: they are read when the entry reply is built, because a guest
/// caches the contents of an entry reply for the entry timeout and would serve
/// reads of a concurrently written file by an old size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostIdentity {
    pub device: u64,
    pub inode: u64,
    pub kind: FileKind,
}

/// `(device, inode)` alone is not an identity: on ext4 an unlink and recreate at
/// the same path can hand back the identical pair, so a check built on it would
/// serve the bytes of the impostor through the old node id. The birth time
/// separates them, and ext4, btrfs and tmpfs all record one. Where a filesystem
/// records none, the check falls back to `(device, inode, kind)` and the
/// guarantee is best-effort.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeIdentity {
    pub device: u64,
    pub inode: u64,
    pub kind: FileKind,
    pub birth: Option<(i64, u32)>,
}

impl NodeIdentity {
    /// A birth time on both sides must agree. One side without one is the
    /// best-effort case: the triple is all there is to compare.
    #[must_use]
    pub fn matches(&self, found: &Self) -> bool {
        self.device == found.device
            && self.inode == found.inode
            && self.kind == found.kind
            && match (self.birth, found.birth) {
                (Some(recorded), Some(now)) => recorded == now,
                _ => true,
            }
    }

    /// The comparison for a caller that has only a [`HostIdentity`]: the
    /// triple, without a birth time. It is enough for finding the nodes that name
    /// an entry that the server itself has just moved, and not enough to admit an
    /// entry, which is the job of [`Self::matches`].
    #[must_use]
    pub fn names(&self, entry: HostIdentity) -> bool {
        self.device == entry.device && self.inode == entry.inode && self.kind == entry.kind
    }

    #[must_use]
    pub fn host_identity(&self) -> HostIdentity {
        HostIdentity {
            device: self.device,
            inode: self.inode,
            kind: self.kind,
        }
    }

    /// For a comparison, never for the record: [`Self::matches`] treats a
    /// missing birth time as best-effort, so this never reaches a
    /// [`NodePin`](crate::data::NodePin).
    #[must_use]
    pub fn listed(entry: HostIdentity) -> Self {
        Self {
            device: entry.device,
            inode: entry.inode,
            kind: entry.kind,
            birth: None,
        }
    }
}

/// Read with `statx` for the birth time, in the one syscall a lookup makes
/// anyway, so the node identity is never captured from a second stat.
#[derive(Clone, Copy, Debug)]
pub struct HostAttr {
    pub stat: Statx,
}

const WANTED: StatxFlags = StatxFlags::BASIC_STATS.union(StatxFlags::BTIME);

#[allow(
    clippy::unnecessary_cast,
    reason = "the field widths of the statx fields differ by architecture, so the casts are only redundant on some of them"
)]
impl HostAttr {
    /// The empty-path form works on an `O_PATH` descriptor and never follows a
    /// symlink, so an `O_PATH` symlink reports on itself.
    ///
    /// # Errors
    ///
    /// Returns the host errno.
    pub fn of(fd: BorrowedFd<'_>) -> Result<Self, Errno> {
        let stat = statx(
            fd,
            "",
            AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
            WANTED,
        )?;
        Ok(Self { stat })
    }

    /// The one stat outside the containment discipline: the revalidation of the
    /// record sidecar names a locator that the server wrote itself, before any
    /// graft descriptor exists. The answer decides only whether a recorded row
    /// still describes the file.
    ///
    /// # Errors
    ///
    /// Returns the host errno — `ENOENT` where the locator names nothing.
    pub fn of_host_path(path: &std::path::Path) -> Result<Self, Errno> {
        let stat = statx(rustix::fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW, WANTED)?;
        Ok(Self { stat })
    }

    /// No path is assembled, so nothing outside `parent` can be named, and a
    /// symlink reports on itself.
    ///
    /// # Errors
    ///
    /// Returns the host errno — `ENOENT` for an entry that has gone since the
    /// directory was read.
    pub fn of_child(parent: BorrowedFd<'_>, name: &crate::rules::Name) -> Result<Self, Errno> {
        let stat = statx(parent, name.as_bytes(), AtFlags::SYMLINK_NOFOLLOW, WANTED)?;
        Ok(Self { stat })
    }

    #[must_use]
    pub fn host_identity(&self) -> HostIdentity {
        HostIdentity {
            device: makedev(self.stat.stx_dev_major, self.stat.stx_dev_minor),
            inode: self.stat.stx_ino as u64,
            kind: self.kind(),
        }
    }

    #[must_use]
    pub fn node_identity(&self) -> NodeIdentity {
        let entry = self.host_identity();
        NodeIdentity {
            device: entry.device,
            inode: entry.inode,
            kind: entry.kind,
            birth: self.birth(),
        }
    }

    /// An unfilled `stx_btime` is zeroes, not an error, so the mask of the
    /// fields `statx` filled is the only way to ask.
    #[must_use]
    pub fn birth(&self) -> Option<(i64, u32)> {
        let filled = StatxFlags::from_bits_truncate(self.stat.stx_mask);
        filled
            .contains(StatxFlags::BTIME)
            .then_some((self.stat.stx_btime.tv_sec, self.stat.stx_btime.tv_nsec))
    }

    #[must_use]
    pub fn host_mode(&self) -> u32 {
        self.stat.stx_mode as u32
    }

    #[must_use]
    pub fn kind(&self) -> FileKind {
        FileKind::of(self.host_mode())
    }

    #[must_use]
    pub fn owner(&self) -> HostIds {
        HostIds::new(self.stat.stx_uid as u32, self.stat.stx_gid as u32)
    }

    #[must_use]
    pub fn link_count(&self) -> u32 {
        self.stat.stx_nlink as u32
    }

    /// The attributes this entry presents to a guest, or `None` when ownership
    /// policy hides it.
    ///
    /// The caller allocates `ino`, because allocation is server-global state and
    /// this function is otherwise pure. `privileged` is the third transformation
    /// of the presented mode, resolved once by the caller for the whole
    /// operation, so the per-entry cost of a listing is a table lookup.
    #[must_use]
    pub fn present(
        &self,
        ino: u64,
        mode: EffectiveMode,
        ownership: &Ownership,
        privileged: Privileged,
    ) -> Option<Attr> {
        let OwnerPresentation::Visible(guest) = ownership.forward(self.owner()) else {
            return None;
        };
        Some(Attr {
            ino: U64::new(ino),
            size: U64::new(self.stat.stx_size as u64),
            blocks: U64::new(self.stat.stx_blocks as u64),
            atime: timespec(self.stat.stx_atime.tv_sec, self.stat.stx_atime.tv_nsec),
            mtime: timespec(self.stat.stx_mtime.tv_sec, self.stat.stx_mtime.tv_nsec),
            ctime: timespec(self.stat.stx_ctime.tv_sec, self.stat.stx_ctime.tv_nsec),
            mode: U32::new(privileged.apply(presented_mode(self.host_mode(), mode))),
            nlink: U32::new(self.link_count()),
            uid: U32::new(guest.uid),
            gid: U32::new(guest.gid),
            rdev: U32::new(makedev(self.stat.stx_rdev_major, self.stat.stx_rdev_minor) as u32),
            blksize: U32::new(self.stat.stx_blksize as u32),
        })
    }
}

/// A synthesized directory has no host inode and nothing can be created in it,
/// so it presents as traversable and readable, owned by the forward-mapped
/// server identity, with the start time of the server for every timestamp.
///
/// When the ownership policy hides the identity of the server, it presents the
/// squash ids instead, because hiding the skeleton of the namespace would make
/// every graft beneath it unreachable.
#[must_use]
pub fn synthesized_attr(ino: u64, ownership: &Ownership, times: SynthesizedTimes) -> Attr {
    let identity = ownership.identity().as_host_ids();
    let guest = match ownership.forward(identity) {
        OwnerPresentation::Visible(guest) => guest,
        OwnerPresentation::Hidden => {
            let squash = ownership.squash();
            crate::rules::GuestIds::new(squash.uid, squash.gid)
        }
    };
    Attr {
        ino: U64::new(ino),
        size: U64::ZERO,
        blocks: U64::ZERO,
        atime: times.timestamp(),
        mtime: times.timestamp(),
        ctime: times.timestamp(),
        mode: U32::new(S_IFDIR | presented_mode(SYNTHESIZED_DIR_PERMISSIONS, EffectiveMode::Ro)),
        nlink: U32::new(SYNTHESIZED_NLINK),
        uid: U32::new(guest.uid),
        gid: U32::new(guest.gid),
        rdev: U32::ZERO,
        blksize: U32::new(SYNTHESIZED_BLKSIZE),
    }
}

fn timespec(sec: i64, nsec: u32) -> Timespec {
    Timespec::new(sec, nsec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::PrivilegedBits;
    use crate::rules::{
        IdMap, IdMapping, OwnershipMode, ServerIdentity, SquashIds, UnmappedPolicy,
    };
    use std::os::fd::AsFd;
    use std::os::unix::fs::symlink;
    use voidport_test_host::Scratch;

    fn passthrough() -> Ownership {
        Ownership::new(
            OwnershipMode::Passthrough,
            ServerIdentity::new(1000, 100),
            SquashIds::default(),
        )
        .expect("valid ownership")
    }

    fn pin(path: &std::path::Path) -> std::os::fd::OwnedFd {
        rustix::fs::openat(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .expect("the entry pins")
    }

    #[test]
    fn a_file_presents_its_host_metadata() {
        let scratch = Scratch::new("attr");
        let pinned = pin(&scratch.file("file", b"1234567890"));
        let host = HostAttr::of(pinned.as_fd()).expect("stattable");

        assert_eq!(host.kind(), FileKind::Regular);
        assert!(!host.kind().is_directory());
        assert_eq!(host.kind().dirent_type(host.host_mode()), file_type::REG);
        let attr = host
            .present(
                77,
                EffectiveMode::Rw,
                &passthrough(),
                Privileged::Recorded(PrivilegedBits::NONE),
            )
            .expect("passthrough ownership shows every file");
        assert_eq!(attr.ino.get(), 77);
        assert_eq!(attr.size.get(), 10);
        assert_eq!(attr.nlink.get(), 1);
        assert_eq!(attr.mode.get(), host.host_mode());
        assert_eq!(attr.uid.get(), host.owner().uid);
    }

    #[test]
    fn read_only_presentation_clears_the_write_bits() {
        let scratch = Scratch::new("attr");
        let pinned = pin(&scratch.file("file", b"x"));
        let host = HostAttr::of(pinned.as_fd()).expect("stattable");
        let attr = host
            .present(
                1,
                EffectiveMode::Ro,
                &passthrough(),
                Privileged::Recorded(PrivilegedBits::NONE),
            )
            .expect("visible");
        assert_eq!(attr.mode.get() & 0o222, 0);
        assert_eq!(attr.mode.get(), host.host_mode() & !0o222);
    }

    #[test]
    fn a_symlink_stats_as_itself() {
        let scratch = Scratch::new("attr");
        symlink("/etc/hostname", scratch.join("link")).expect("writable");
        let pinned = pin(&scratch.join("link"));
        let host = HostAttr::of(pinned.as_fd()).expect("stattable");
        assert_eq!(host.kind(), FileKind::Symlink);
        assert_eq!(host.kind().dirent_type(host.host_mode()), file_type::LNK);
    }

    #[test]
    fn hidden_ownership_hides_the_attributes_too() {
        let scratch = Scratch::new("attr");
        let pinned = pin(&scratch.file("file", b"x"));
        let host = HostAttr::of(pinned.as_fd()).expect("stattable");

        let ownership = Ownership::new(
            OwnershipMode::Map {
                uid: IdMap::new([IdMapping::new(4_000_000_000, 0)]).expect("injective"),
                gid: IdMap::new([IdMapping::new(4_000_000_001, 0)]).expect("injective"),
                unmapped: UnmappedPolicy::Hide,
            },
            ServerIdentity::new(4_000_000_000, 4_000_000_001),
            SquashIds::default(),
        )
        .expect("valid ownership");
        assert!(
            host.present(1, EffectiveMode::Rw, &ownership, Privileged::Masked)
                .is_none()
        );
    }

    #[test]
    fn a_synthesized_directory_is_fixed_and_never_writable() {
        let times = SynthesizedTimes::at_startup();
        let attr = synthesized_attr(9, &passthrough(), times);
        assert_eq!(attr.ino.get(), 9);
        assert_eq!(attr.mode.get(), S_IFDIR | 0o555);
        assert_eq!(attr.nlink.get(), SYNTHESIZED_NLINK);
        assert_eq!(attr.uid.get(), 1000);
        assert_eq!(attr.gid.get(), 100);
        assert_eq!(attr.size.get(), 0);
        assert_eq!(attr.atime, times.timestamp());
        assert_eq!(attr.mtime, times.timestamp());
        assert_eq!(attr.ctime, times.timestamp());

        // A policy that cannot show the server identity shows the squash ids
        // instead of hiding the path to every graft beneath it.
        let hiding = Ownership::new(
            OwnershipMode::Map {
                uid: IdMap::default(),
                gid: IdMap::default(),
                unmapped: UnmappedPolicy::Hide,
            },
            ServerIdentity::new(1000, 100),
            SquashIds::new(7, 8),
        )
        .expect("valid ownership");
        let squashed = synthesized_attr(9, &hiding, times);
        assert_eq!((squashed.uid.get(), squashed.gid.get()), (7, 8));
    }

    #[test]
    fn the_synthesized_timestamp_is_a_captured_start_time() {
        use std::time::{Duration, SystemTime};

        let now = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 123);
        let times = SynthesizedTimes::at(now);
        let stamp = Timespec::new(1_700_000_000, 123);
        assert_eq!(times.timestamp(), stamp);
        assert_eq!(synthesized_attr(9, &passthrough(), times).mtime, stamp);
        assert_eq!(
            SynthesizedTimes::at(now + Duration::from_secs(1)).timestamp(),
            Timespec::new(1_700_000_001, 123)
        );
        assert_eq!(
            SynthesizedTimes::at(SystemTime::UNIX_EPOCH - Duration::from_secs(1)).timestamp(),
            Timespec::new(0, 0)
        );
    }
}
