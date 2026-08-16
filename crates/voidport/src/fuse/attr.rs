//! Attribute translation, wire to kernel.
//!
//! One decision governs this module: **the kernel node id is the server node
//! id, and `st_ino` presents that same node id**. fuser takes the node id of an
//! entry reply from `attr.ino`, so the two cannot differ; the wire still
//! carries the server's global `ino`, which a client without that coupling
//! would present instead. The consequence is deliberate and accepted: `st_ino`
//! equality across hardlink aliases holds among aliases with the same effective
//! share mode, which is exactly the set that shares a node id.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{FileAttr, FileType, INodeNo, TimeOrNow};
use voidport_proto::attr::{Attr, Timespec, file_type};

use crate::client::{Entry, TimeChange};

/// The `S_IFMT` mask: the file-type bits of a mode word.
const FORMAT_MASK: u32 = 0o170_000;
/// The permission, setuid, setgid and sticky bits of a mode word.
const PERMISSION_MASK: u32 = 0o7777;

/// The attributes of an entry reply, presented to the kernel.
#[must_use]
pub fn entry_attr(entry: &Entry) -> FileAttr {
    node_attr(entry.node_id, &entry.attr)
}

/// The attributes of a node the client already knows the id of.
#[must_use]
pub fn node_attr(node_id: u64, attr: &Attr) -> FileAttr {
    FileAttr {
        ino: INodeNo(node_id),
        size: attr.size.get(),
        blocks: attr.blocks.get(),
        atime: system_time(attr.atime),
        mtime: system_time(attr.mtime),
        ctime: system_time(attr.ctime),
        // Linux has no creation time in `struct stat`; the field is macOS's.
        crtime: UNIX_EPOCH,
        kind: mode_kind(attr.mode.get()),
        perm: (attr.mode.get() & PERMISSION_MASK) as u16,
        nlink: attr.nlink.get(),
        uid: attr.uid.get(),
        gid: attr.gid.get(),
        rdev: attr.rdev.get(),
        blksize: attr.blksize.get(),
        flags: 0,
    }
}

/// The file type a mode word names.
#[must_use]
pub fn mode_kind(mode: u32) -> FileType {
    match mode & FORMAT_MASK {
        0o140_000 => FileType::Socket,
        0o120_000 => FileType::Symlink,
        0o060_000 => FileType::BlockDevice,
        0o040_000 => FileType::Directory,
        0o020_000 => FileType::CharDevice,
        0o010_000 => FileType::NamedPipe,
        // `S_IFREG`, and anything a future host type might present as: a
        // regular file is the only answer that cannot mislead a reader into
        // following or enumerating something.
        _ => FileType::RegularFile,
    }
}

/// The file type a readdirplus entry names.
///
/// The `DT_*` byte is what the entry stream carries; the attributes are the
/// fallback for a host filesystem that reports `DT_UNKNOWN`.
#[must_use]
pub fn dirent_kind(entry_type: u32, mode: u32) -> FileType {
    match entry_type {
        file_type::FIFO => FileType::NamedPipe,
        file_type::CHR => FileType::CharDevice,
        file_type::DIR => FileType::Directory,
        file_type::BLK => FileType::BlockDevice,
        file_type::REG => FileType::RegularFile,
        file_type::LNK => FileType::Symlink,
        file_type::SOCK => FileType::Socket,
        _ => mode_kind(mode),
    }
}

/// A wire timestamp as the kernel wants it.
///
/// Timestamps outside what `SystemTime` can express are clamped, not
/// dropped: an unrepresentable mtime is a strange file, not a failed `stat`.
#[must_use]
pub fn system_time(time: Timespec) -> SystemTime {
    let nanos = Duration::from_nanos(u64::from(time.nsec.get()));
    let seconds = time.sec.get();
    if seconds >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds.unsigned_abs()))
            .and_then(|time| time.checked_add(nanos))
            .unwrap_or(UNIX_EPOCH)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(seconds.unsigned_abs()))
            .and_then(|time| time.checked_add(nanos))
            .unwrap_or(UNIX_EPOCH)
    }
}

/// A kernel timestamp as the wire wants it.
#[must_use]
pub fn timespec(time: SystemTime) -> Timespec {
    match time.duration_since(UNIX_EPOCH) {
        Ok(since) => Timespec::new(
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
            since.subsec_nanos(),
        ),
        Err(before) => {
            let before = before.duration();
            Timespec::new(
                i64::try_from(before.as_secs()).map_or(i64::MIN, |seconds| {
                    -seconds - i64::from(before.subsec_nanos() > 0)
                }),
                if before.subsec_nanos() > 0 {
                    1_000_000_000 - before.subsec_nanos()
                } else {
                    0
                },
            )
        }
    }
}

/// A time the kernel asks a `setattr` to apply.
#[must_use]
pub fn time_change(time: TimeOrNow) -> TimeChange {
    match time {
        TimeOrNow::Now => TimeChange::Now,
        TimeOrNow::SpecificTime(time) => TimeChange::At(timespec(time)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::byteorder::little_endian::{U32, U64};

    fn attr(mode: u32) -> Attr {
        Attr {
            ino: U64::new(4242),
            size: U64::new(7),
            blocks: U64::new(1),
            atime: Timespec::new(10, 11),
            mtime: Timespec::new(20, 21),
            ctime: Timespec::new(30, 31),
            mode: U32::new(mode),
            nlink: U32::new(2),
            uid: U32::new(1000),
            gid: U32::new(1001),
            rdev: U32::ZERO,
            blksize: U32::new(4096),
        }
    }

    #[test]
    fn the_presented_inode_is_the_node_id_not_the_wire_ino() {
        let presented = node_attr(9, &attr(0o100_644));
        assert_eq!(presented.ino, INodeNo(9));
        assert_eq!(presented.kind, FileType::RegularFile);
        assert_eq!(presented.perm, 0o644);
        assert_eq!(presented.nlink, 2);
        assert_eq!(presented.uid, 1000);
        assert_eq!(presented.mtime, UNIX_EPOCH + Duration::new(20, 21));
    }

    #[test]
    fn every_file_type_survives_the_translation() {
        for (mode, kind) in [
            (0o100_000, FileType::RegularFile),
            (0o040_000, FileType::Directory),
            (0o120_000, FileType::Symlink),
            (0o010_000, FileType::NamedPipe),
            (0o020_000, FileType::CharDevice),
            (0o060_000, FileType::BlockDevice),
            (0o140_000, FileType::Socket),
        ] {
            assert_eq!(mode_kind(mode), kind);
            assert_eq!(dirent_kind(file_type::UNKNOWN, mode), kind);
        }
        // The dirent byte wins where the host supplies one.
        assert_eq!(dirent_kind(file_type::LNK, 0o100_000), FileType::Symlink);
    }

    #[test]
    fn timestamps_round_trip_through_the_kernel_representation() {
        for (sec, nsec) in [(0, 0), (1_700_000_000, 123_456_789), (-5, 500)] {
            let wire = Timespec::new(sec, nsec);
            let round = timespec(system_time(wire));
            assert_eq!((round.sec.get(), round.nsec.get()), (sec, nsec));
        }
    }
}
