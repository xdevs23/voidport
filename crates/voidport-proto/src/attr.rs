//! File attributes and entry replies.

use zerocopy::byteorder::little_endian::{I64, U32, U64};

use crate::macros::wire_struct;

wire_struct! {
    /// A wire timestamp: seconds since the Unix epoch plus nanoseconds.
    pub struct Timespec {
        /// Whole seconds since the Unix epoch; may be negative.
        pub sec: I64,
        /// Nanoseconds within the second, `0..1_000_000_000`.
        pub nsec: U32,
    }
}

impl Timespec {
    /// Builds a timestamp.
    #[must_use]
    pub fn new(sec: i64, nsec: u32) -> Self {
        Self {
            sec: I64::new(sec),
            nsec: U32::new(nsec),
        }
    }
}

wire_struct! {
    /// Attributes of a file, as presented to the guest.
    ///
    /// `ino` is the server-global synthetic inode number keyed by
    /// `(host_dev, host_ino)` — stable across sessions, and equal for every
    /// hardlink alias of one host inode. It is deliberately *not* the node id used
    /// to name the file in wire operations, which is session-scoped and mode-keyed
    /// (see the "Inode identity and node ids" section of the design).
    ///
    /// The `mode` bits are presentation only: a read-only graft strips write bits
    /// here, while enforcement always happens on the server.
    pub struct Attr {
        /// Guest-visible inode number.
        pub ino: U64,
        /// Size in bytes.
        pub size: U64,
        /// Size in 512-byte blocks.
        pub blocks: U64,
        /// Last access time.
        pub atime: Timespec,
        /// Last modification time.
        pub mtime: Timespec,
        /// Last inode change time.
        pub ctime: Timespec,
        /// File type and permission bits, as in `struct stat`'s `st_mode`.
        pub mode: U32,
        /// Hard link count.
        pub nlink: U32,
        /// Owning uid, already mapped into guest id space.
        pub uid: U32,
        /// Owning gid, already mapped into guest id space.
        pub gid: U32,
        /// Device id for a block or character special file.
        pub rdev: U32,
        /// Preferred I/O block size.
        pub blksize: U32,
    }
}

wire_struct! {
    /// An entry reply: the node id a lookup produced, plus its attributes.
    ///
    /// A node id is session-scoped and keyed by
    /// `(host_dev, host_ino, effective_share_mode)`. `generation` distinguishes a
    /// reused node id from its previous life. Every entry reply — including each
    /// readdirplus entry — increments the node's lookup count, which `forget`
    /// decrements.
    pub struct EntryOut {
        /// Session-scoped node id naming the file in later operations.
        pub node_id: U64,
        /// Generation number of this node id.
        pub generation: U64,
        /// Attributes of the file.
        pub attr: Attr,
    }
}

/// Directory entry types, matching the Linux `DT_*` values.
pub mod file_type {
    /// Unknown type.
    pub const UNKNOWN: u32 = 0;
    /// Named pipe.
    pub const FIFO: u32 = 1;
    /// Character device.
    pub const CHR: u32 = 2;
    /// Directory.
    pub const DIR: u32 = 4;
    /// Block device.
    pub const BLK: u32 = 6;
    /// Regular file.
    pub const REG: u32 = 8;
    /// Symbolic link.
    pub const LNK: u32 = 10;
    /// Unix domain socket.
    pub const SOCK: u32 = 12;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn attribute_layout_is_pinned() {
        assert_eq!(size_of::<Timespec>(), 12);
        assert_eq!(offset_of!(Timespec, sec), 0);
        assert_eq!(offset_of!(Timespec, nsec), 8);

        assert_eq!(size_of::<Attr>(), 84);
        assert_eq!(align_of::<Attr>(), 1);
        assert_eq!(offset_of!(Attr, ino), 0);
        assert_eq!(offset_of!(Attr, size), 8);
        assert_eq!(offset_of!(Attr, blocks), 16);
        assert_eq!(offset_of!(Attr, atime), 24);
        assert_eq!(offset_of!(Attr, mtime), 36);
        assert_eq!(offset_of!(Attr, ctime), 48);
        assert_eq!(offset_of!(Attr, mode), 60);
        assert_eq!(offset_of!(Attr, nlink), 64);
        assert_eq!(offset_of!(Attr, uid), 68);
        assert_eq!(offset_of!(Attr, gid), 72);
        assert_eq!(offset_of!(Attr, rdev), 76);
        assert_eq!(offset_of!(Attr, blksize), 80);

        assert_eq!(size_of::<EntryOut>(), 100);
        assert_eq!(align_of::<EntryOut>(), 1);
        assert_eq!(offset_of!(EntryOut, node_id), 0);
        assert_eq!(offset_of!(EntryOut, generation), 8);
        assert_eq!(offset_of!(EntryOut, attr), 16);
    }
}
