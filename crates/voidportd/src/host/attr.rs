//! Host metadata, presented.
//!
//! Attributes are read fresh from the host on every request that needs them —
//! the server is a passthrough proxy and the host filesystem is the truth — and
//! then pass through exactly two policy transformations before they are sent
//! on the wire:
//!
//! * **ownership** is forward-mapped through the namespace's algebra, which may
//!   also decide the file must not be seen at all (`unmapped: hide`), and
//! * **privileged bits** are merged from the namespace's record store — the
//!   setuid and setgid bits the host backing must not carry — or masked away
//!   where the namespace switch is off (see [`crate::records`]).
//!
//! The `ino` is never the host's: it is the server-global synthetic number
//! keyed by `(host_dev, host_ino)`, so identity is stable across sessions and
//! hardlink aliases share it. Raw host inos collide across devices and are
//! never exposed.

use std::os::fd::BorrowedFd;

use rustix::fs::{AtFlags, FileType, Statx, StatxFlags, makedev, statx};
use rustix::io::Errno;
use voidport_proto::attr::{Attr, Timespec, file_type};
use zerocopy::byteorder::little_endian::{U32, U64};

use crate::records::Privileged;
use crate::rules::{HostIds, OwnerPresentation, Ownership, SYNTHESIZED_DIR_PERMISSIONS};

/// The timestamp every synthesized directory carries: the server's start time,
/// captured once.
///
/// Synthesized directories have no host backing and therefore no real times, so
/// the design injects one value for all of them. It is captured **once, at
/// startup**, and never read from the clock again: pinning them to "now" would
/// make a namespace's structural skeleton appear to change under a guest that
/// caches attributes. The value is the start time, not zero, because zero
/// presents as 1970, which reads as breakage to users and tools; a start time
/// keeps the same stability property while presenting a plausible clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynthesizedTimes(Timespec);

impl SynthesizedTimes {
    /// Captures the server's start time. Called once per server lifetime, from
    /// the daemon's startup path, and copied to every session from there.
    #[must_use]
    pub fn at_startup() -> Self {
        // A host clock standing before the epoch is the one case with no
        // plausible answer, and it falls back to the epoch itself.
        let since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        Self(Timespec::new(
            i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX),
            since_epoch.subsec_nanos(),
        ))
    }

    /// The captured timestamp.
    #[must_use]
    pub fn timestamp(self) -> Timespec {
        self.0
    }
}

/// The block size a synthesized directory reports.
const SYNTHESIZED_BLKSIZE: u32 = 4096;

/// The link count a synthesized directory reports: itself and `.`.
const SYNTHESIZED_NLINK: u32 = 2;

/// `S_IFDIR`, the file-type bits a synthesized directory carries.
const S_IFDIR: u32 = 0o040_000;

/// What kind of thing a host entry is.
///
/// The server cares about three distinctions and no more: directories drive
/// child resolution, symlinks are pinned but never followed, and everything
/// else is a leaf it passes bytes through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileKind {
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// A regular file.
    Regular,
    /// Anything else: device, fifo, socket.
    Other,
}

impl FileKind {
    /// Classifies a host `st_mode`.
    #[must_use]
    pub fn of(host_mode: u32) -> Self {
        match FileType::from_raw_mode(host_mode) {
            FileType::Directory => Self::Directory,
            FileType::Symlink => Self::Symlink,
            FileType::RegularFile => Self::Regular,
            _ => Self::Other,
        }
    }

    /// Whether the entry is a directory.
    #[must_use]
    pub fn is_directory(self) -> bool {
        self == Self::Directory
    }

    /// The wire directory-entry type, matching the Linux `DT_*` values.
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

/// What a listing needs to remember about an entry's host inode.
///
/// Not its attributes: those are read when the entry reply is built, because a
/// guest caches what an entry reply says about a file for the entry timeout and
/// would then serve reads of a concurrently written file by a size that was
/// already old when it was sent. This is only what it takes to *name* the
/// entry's node — which cannot go stale in a way that matters, because a node
/// key that no longer describes the host entry simply names the node the
/// session already listed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostIdentity {
    /// The host device.
    pub device: u64,
    /// The host inode number.
    pub inode: u64,
    /// What kind of entry it is.
    pub kind: FileKind,
}

/// What a node records at pin time so that re-pinning it can prove it found
/// the same file again.
///
/// `(device, inode)` alone is **not** an identity, and that was measured, not
/// assumed: on ext4 an unlink-and-recreate at the same path hands the
/// identical pair straight back — 20000 of 20000 probe cycles — so a check
/// built on it would serve the impostor's bytes through the old node id on the
/// most ordinary filesystem there is. The birth time is what separates them,
/// and ext4, btrfs and tmpfs all record one.
///
/// Where a filesystem records no birth time the check falls back to
/// `(device, inode, kind)` and the guarantee is best-effort for that
/// filesystem — stated, not hidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeIdentity {
    /// The host device.
    pub device: u64,
    /// The host inode number.
    pub inode: u64,
    /// What kind of entry it is.
    pub kind: FileKind,
    /// The birth time as `(seconds, nanoseconds)`, where `statx` reported one.
    pub birth: Option<(i64, u32)>,
}

impl NodeIdentity {
    /// Whether `found` is the very file this identity was taken from.
    ///
    /// A birth time on both sides must agree. One side without a birth time is
    /// the best-effort arm above: the filesystem does not record one, so the
    /// triple is all there is to compare.
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

    /// Whether this identity names the entry a listing or a rename stat'd.
    ///
    /// The comparison a caller holding only a [`HostIdentity`] can make: the
    /// triple, with no birth time on the other side to check against. That is
    /// enough for what it is used for — finding the nodes that name an entry
    /// the *server itself* has just moved, where nothing has been replaced —
    /// and it is deliberately not enough to admit an entry, which is
    /// [`Self::matches`]'s job.
    #[must_use]
    pub fn names(&self, entry: HostIdentity) -> bool {
        self.device == entry.device && self.inode == entry.inode && self.kind == entry.kind
    }

    /// The triple by which a move identifies the entry it moved.
    #[must_use]
    pub fn host_identity(&self) -> HostIdentity {
        HostIdentity {
            device: self.device,
            inode: self.inode,
            kind: self.kind,
        }
    }

    /// What a caller that stat'd without asking for a birth time can offer for
    /// a **comparison** — never for the record.
    ///
    /// A listing remembers a [`HostIdentity`] per entry; the identity a node
    /// records is captured from the `statx` that pinned it. Widening the first
    /// into the second is honest only in the direction [`Self::matches`] treats
    /// a missing birth time as best-effort, which is why nothing here ever
    /// reaches a [`NodePin`](crate::data::NodePin).
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

/// Host metadata plus the identity the server derives from it.
///
/// Read with `statx`, not `stat`, for one reason: the birth time. It is
/// the same single syscall a lookup always took, and the node identity above
/// is captured from it — never from a second stat.
#[derive(Clone, Copy, Debug)]
pub struct HostAttr {
    /// The raw host metadata.
    pub stat: Statx,
}

/// What every stat asks for: the ordinary fields, plus the birth time where the
/// filesystem has one.
const WANTED: StatxFlags = StatxFlags::BASIC_STATS.union(StatxFlags::BTIME);

#[allow(
    clippy::unnecessary_cast,
    reason = "the field widths of the statx fields differ by architecture, so the casts are only redundant on some of them"
)]
impl HostAttr {
    /// Reads the metadata of a pinned descriptor.
    ///
    /// The empty-path form works on an `O_PATH` descriptor and never follows a
    /// symlink, so a pinned symlink reports on itself.
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

    /// Reads the metadata of an absolute host path, following no symlink at
    /// the final component.
    ///
    /// The one stat that does **not** run under the containment discipline,
    /// and it is deliberately narrow: the record sidecar's revalidation names a
    /// locator the server itself wrote, before any graft descriptor exists —
    /// a fresh process has nothing pinned to descend from. Nothing is opened
    /// and nothing is served from it: the answer decides only whether a
    /// recorded row still describes the file it was written for.
    ///
    /// # Errors
    ///
    /// Returns the host errno — `ENOENT` where the locator names nothing.
    pub fn of_host_path(path: &std::path::Path) -> Result<Self, Errno> {
        let stat = statx(rustix::fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW, WANTED)?;
        Ok(Self { stat })
    }

    /// Reads the metadata of one named entry of a pinned directory.
    ///
    /// `name` is a single component — [`Name`](crate::rules::Name) cannot be
    /// empty, cannot contain a separator and cannot be `.` or `..` — resolved
    /// against `parent` with `AT_SYMLINK_NOFOLLOW`. No path is assembled, so
    /// nothing outside `parent` can be named, and a symlink reports on itself
    /// and is not followed: the same one-component-against-a-pinned-
    /// ancestor resolution shape the containment contract requires of the
    /// `openat2` pin, for a caller that wants the metadata and not a
    /// descriptor.
    ///
    /// # Errors
    ///
    /// Returns the host errno — `ENOENT` for an entry that has gone since the
    /// directory was read.
    pub fn of_child(parent: BorrowedFd<'_>, name: &crate::rules::Name) -> Result<Self, Errno> {
        let stat = statx(parent, name.as_bytes(), AtFlags::SYMLINK_NOFOLLOW, WANTED)?;
        Ok(Self { stat })
    }

    /// Everything a listing remembers about the entry: its identity and kind.
    ///
    /// This is also what a host entry's ino is keyed by, so the pair travels
    /// as one value and is never assembled twice from loose numbers.
    #[must_use]
    pub fn host_identity(&self) -> HostIdentity {
        HostIdentity {
            device: makedev(self.stat.stx_dev_major, self.stat.stx_dev_minor),
            inode: self.stat.stx_ino as u64,
            kind: self.kind(),
        }
    }

    /// Everything a node records about the entry it pinned, birth time
    /// included.
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

    /// The birth time, where this filesystem records one.
    ///
    /// `statx` answers with a mask saying which fields it actually filled, and
    /// an unfilled `stx_btime` is zeroes, not an error — so the mask is
    /// the only honest way to ask.
    #[must_use]
    pub fn birth(&self) -> Option<(i64, u32)> {
        let filled = StatxFlags::from_bits_truncate(self.stat.stx_mask);
        filled
            .contains(StatxFlags::BTIME)
            .then_some((self.stat.stx_btime.tv_sec, self.stat.stx_btime.tv_nsec))
    }

    /// The host `st_mode`, file-type bits included.
    #[must_use]
    pub fn host_mode(&self) -> u32 {
        self.stat.stx_mode as u32
    }

    /// What kind of entry this is.
    #[must_use]
    pub fn kind(&self) -> FileKind {
        FileKind::of(self.host_mode())
    }

    /// The host owner.
    #[must_use]
    pub fn owner(&self) -> HostIds {
        HostIds::new(self.stat.stx_uid as u32, self.stat.stx_gid as u32)
    }

    /// The attributes this entry presents to a guest, or `None` when ownership
    /// policy hides it.
    ///
    /// `ino` is the server-global synthetic inode number for
    /// [`Self::identity`]; the caller allocates it, because allocation is
    /// server-global state and this function is otherwise pure.
    ///
    /// `privileged` is the one transformation of the presented mode: the
    /// recorded setuid and setgid bits ORed in, or masked away where the
    /// namespace switch is off. Every other bit is the one the host entry has,
    /// whatever the share mode of the entry. It is a plain value the caller resolved once
    /// for the whole operation — no host syscall, no per-session cache — which
    /// is what keeps a listing's per-entry cost a table lookup.
    #[must_use]
    pub fn present(&self, ino: u64, ownership: &Ownership, privileged: Privileged) -> Option<Attr> {
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
            mode: U32::new(privileged.apply(self.host_mode())),
            nlink: U32::new(self.stat.stx_nlink as u32),
            uid: U32::new(guest.uid),
            gid: U32::new(guest.gid),
            rdev: U32::new(makedev(self.stat.stx_rdev_major, self.stat.stx_rdev_minor) as u32),
            blksize: U32::new(self.stat.stx_blksize as u32),
        })
    }
}

/// The fixed attributes of a synthesized directory.
///
/// A synthesized directory exists only because reachable grafts lie beneath it:
/// nothing can be created in it and it has no host inode, so it presents as
/// traversable and readable, owned by the forward-mapped server identity, with
/// the server's start time for every timestamp.
///
/// When the ownership policy hides the server's own identity — `unmapped: hide`
/// with no mapping for it — the directory presents the squash ids instead.
/// Hiding the skeleton of the namespace would make every graft beneath it
/// unreachable, which no configuration can have meant.
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
        mode: U32::new(S_IFDIR | SYNTHESIZED_DIR_PERMISSIONS),
        nlink: U32::new(SYNTHESIZED_NLINK),
        uid: U32::new(guest.uid),
        gid: U32::new(guest.gid),
        rdev: U32::ZERO,
        blksize: U32::new(SYNTHESIZED_BLKSIZE),
    }
}

/// Builds a wire timestamp.
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
    use crate::testing::Scratch;
    use std::os::fd::AsFd;
    use std::os::unix::fs::symlink;

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
        assert!(host.present(1, &ownership, Privileged::Masked).is_none());
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
        let before = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("a host clock at or after the epoch")
            .as_secs();
        let times = SynthesizedTimes::at_startup();

        // A plausible clock, never the 1970 a zero constant would present.
        let stamp = times.timestamp();
        assert_ne!(stamp, Timespec::new(0, 0));
        assert!(
            stamp.sec.get() >= i64::try_from(before).expect("a representable clock"),
            "the capture reads the clock: {} < {before}",
            stamp.sec.get()
        );

        // Captured, not re-read: the value a session was built with is what
        // every attribute derived from it carries, however much later.
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(times.timestamp(), stamp);
        assert_eq!(synthesized_attr(9, &passthrough(), times).mtime, stamp);
        assert_ne!(SynthesizedTimes::at_startup().timestamp(), stamp);
    }
}
