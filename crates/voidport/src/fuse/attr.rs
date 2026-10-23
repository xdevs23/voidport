use voidport_fuse::{Attributes, FileType, Permissions, SetTime, Timestamp};
use voidport_proto::attr::{Attr, Timespec, file_type};
use voidport_session::metadata::PRIVILEGED;

use crate::client::{Entry, TimeChange};

/// Unlike `nosuid`, which still shows the bits, masking hides them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Privileged {
    #[default]
    Present,
    Masked,
}

impl Privileged {
    #[must_use]
    pub fn of(masked: bool) -> Self {
        if masked { Self::Masked } else { Self::Present }
    }

    #[must_use]
    pub fn apply(self, mode: u32) -> u32 {
        match self {
            Self::Present => mode,
            Self::Masked => mode & !PRIVILEGED,
        }
    }

    #[must_use]
    pub fn is_masked(self) -> bool {
        self == Self::Masked
    }
}

#[must_use]
pub fn entry_attr(entry: &Entry, privileged: Privileged) -> Attributes {
    node_attr(entry.node_id, &entry.attr, privileged)
}

/// `st_ino` is the node id, not the `ino` of the wire.
#[must_use]
pub fn node_attr(node_id: u64, attr: &Attr, privileged: Privileged) -> Attributes {
    Attributes {
        ino: node_id,
        size: attr.size.get(),
        blocks: attr.blocks.get(),
        atime: timestamp(attr.atime),
        mtime: timestamp(attr.mtime),
        ctime: timestamp(attr.ctime),
        kind: mode_kind(attr.mode.get()),
        permissions: Permissions::from_mode(privileged.apply(attr.mode.get())),
        nlink: attr.nlink.get(),
        uid: attr.uid.get(),
        gid: attr.gid.get(),
        rdev: attr.rdev.get(),
        blksize: attr.blksize.get(),
    }
}

/// An unknown type presents as a regular file, so that nothing is followed or
/// enumerated by mistake.
#[must_use]
pub fn mode_kind(mode: u32) -> FileType {
    match FileType::from_raw_mode(mode) {
        FileType::Unknown => FileType::RegularFile,
        kind => kind,
    }
}

/// The attributes are the fallback for a host filesystem that reports
/// `DT_UNKNOWN`.
#[must_use]
pub fn dirent_kind(entry_type: u32, mode: u32) -> FileType {
    match entry_type {
        file_type::FIFO => FileType::Fifo,
        file_type::CHR => FileType::CharacterDevice,
        file_type::DIR => FileType::Directory,
        file_type::BLK => FileType::BlockDevice,
        file_type::REG => FileType::RegularFile,
        file_type::LNK => FileType::Symlink,
        file_type::SOCK => FileType::Socket,
        _ => mode_kind(mode),
    }
}

#[must_use]
pub fn timestamp(time: Timespec) -> Timestamp {
    Timestamp {
        seconds: time.sec.get(),
        nanoseconds: time.nsec.get(),
    }
}

#[must_use]
pub fn timespec(time: Timestamp) -> Timespec {
    Timespec::new(time.seconds, time.nanoseconds)
}

#[must_use]
pub fn time_change(time: SetTime) -> TimeChange {
    match time {
        SetTime::Now => TimeChange::Now,
        SetTime::At(time) => TimeChange::At(timespec(time)),
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
    fn a_mount_that_opts_out_shows_no_privileged_bits() {
        assert_eq!(
            node_attr(9, &attr(0o106_755), Privileged::Present).permissions,
            Permissions::from_mode(0o6755)
        );
        assert_eq!(
            node_attr(9, &attr(0o106_755), Privileged::Masked).permissions,
            Permissions::from_mode(0o0755),
            "stronger than nosuid: the bits are not shown at all"
        );
        assert_eq!(
            node_attr(9, &attr(0o101_777), Privileged::Masked).permissions,
            Permissions::from_mode(0o1777)
        );
        assert!(Privileged::of(true).is_masked());
        assert!(!Privileged::of(false).is_masked());
        assert_eq!(Privileged::default(), Privileged::Present);
    }

    #[test]
    fn the_presented_inode_is_the_node_id_not_the_wire_ino() {
        let presented = node_attr(9, &attr(0o100_644), Privileged::Present);
        assert_eq!(presented.ino, 9);
        assert_eq!(presented.kind, FileType::RegularFile);
        assert_eq!(presented.permissions, Permissions::from_mode(0o644));
        assert_eq!(presented.nlink, 2);
        assert_eq!(presented.uid, 1000);
        assert_eq!(
            presented.mtime,
            Timestamp {
                seconds: 20,
                nanoseconds: 21
            }
        );
    }

    #[test]
    fn every_file_type_survives_the_translation() {
        for (mode, kind) in [
            (0o100_000, FileType::RegularFile),
            (0o040_000, FileType::Directory),
            (0o120_000, FileType::Symlink),
            (0o010_000, FileType::Fifo),
            (0o020_000, FileType::CharacterDevice),
            (0o060_000, FileType::BlockDevice),
            (0o140_000, FileType::Socket),
        ] {
            assert_eq!(mode_kind(mode), kind);
            assert_eq!(dirent_kind(file_type::UNKNOWN, mode), kind);
        }
        assert_eq!(dirent_kind(file_type::LNK, 0o100_000), FileType::Symlink);
        assert_eq!(mode_kind(0o170_000), FileType::RegularFile);
    }
}
