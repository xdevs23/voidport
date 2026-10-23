use zerocopy::byteorder::little_endian::{I64, U32, U64};

use crate::macros::wire_struct;

wire_struct! {
    pub struct Timespec {
        /// Whole seconds since the Unix epoch; may be negative.
        pub sec: I64,
        pub nsec: U32,
    }
}

impl Timespec {
    pub fn validate(&self) -> Result<(), crate::error::FramingError> {
        let nsec = self.nsec.get();
        if nsec >= 1_000_000_000 {
            return Err(crate::error::FramingError::InvalidNanoseconds { nsec });
        }
        Ok(())
    }

    #[must_use]
    pub fn new(sec: i64, nsec: u32) -> Self {
        Self {
            sec: I64::new(sec),
            nsec: U32::new(nsec),
        }
    }
}

wire_struct! {
    /// `ino` is a synthetic number keyed by `(host_dev, host_ino)`, stable
    /// across sessions and equal for every hardlink of one host inode. It is
    /// not the node id that identifies the file in wire operations.
    ///
    /// The `mode` bits are for presentation: a read-only graft strips write
    /// bits here, and the server enforces access.
    pub struct Attr {
        pub ino: U64,
        pub size: U64,
        /// Size in 512-byte blocks.
        pub blocks: U64,
        pub atime: Timespec,
        pub mtime: Timespec,
        pub ctime: Timespec,
        pub mode: U32,
        pub nlink: U32,
        /// Owning uid, already mapped into guest id space.
        pub uid: U32,
        /// Owning gid, already mapped into guest id space.
        pub gid: U32,
        pub rdev: U32,
        pub blksize: U32,
    }
}

wire_struct! {
    /// A node id is session-scoped and keyed by
    /// `(host_dev, host_ino, effective_share_mode)`. `generation` tells a
    /// reused node id from its previous use. Every entry reply, each
    /// readdirplus entry included, increments the lookup count of the node,
    /// which `forget` decrements.
    pub struct EntryOut {
        pub node_id: U64,
        pub generation: U64,
        pub attr: Attr,
    }
}

/// Directory entry types, matching the Linux `DT_*` values.
pub mod file_type {
    pub const UNKNOWN: u32 = 0;
    pub const FIFO: u32 = 1;
    pub const CHR: u32 = 2;
    pub const DIR: u32 = 4;
    pub const BLK: u32 = 6;
    pub const REG: u32 = 8;
    pub const LNK: u32 = 10;
    pub const SOCK: u32 = 12;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn nanoseconds_must_be_a_fraction_of_one_second() {
        for sec in [i64::MIN, -1, 0, i64::MAX] {
            for nsec in [0, 999_999_999] {
                assert_eq!(Timespec::new(sec, nsec).validate(), Ok(()));
            }
            for nsec in [1_000_000_000, u32::MAX] {
                assert_eq!(
                    Timespec::new(sec, nsec).validate(),
                    Err(crate::error::FramingError::InvalidNanoseconds { nsec })
                );
            }
        }
    }

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
