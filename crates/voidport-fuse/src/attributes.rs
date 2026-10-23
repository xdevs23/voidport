use std::time::Duration;

use rustix::fs::FileType;
use zerocopy::byteorder::native_endian::{U32, U64};

use crate::abi;

/// Seconds before 1970 are negative, and the nanoseconds count forward from
/// the second.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

/// [`FileType::Unknown`] has no file type bits: the kernel rejects attributes
/// without a file type with `EIO` (`fuse_valid_type` in `fs/fuse/fuse_i.h`,
/// Linux 7.3), and a directory entry without one shows as `DT_UNKNOWN`.
fn type_bits(kind: FileType) -> u32 {
    match kind {
        FileType::Unknown => 0,
        known => known.as_raw_mode(),
    }
}

pub(crate) fn dirent_type(kind: FileType) -> u32 {
    type_bits(kind) >> 12
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions(u32);

impl Permissions {
    /// Drops the file type bits of `mode` and any bit above them.
    #[must_use]
    pub fn from_mode(mode: u32) -> Self {
        Self(mode & 0o7777)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attributes {
    pub ino: u64,
    pub size: u64,
    /// The size in 512-byte blocks.
    pub blocks: u64,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub kind: FileType,
    pub permissions: Permissions,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
}

impl Attributes {
    pub(crate) fn encode(&self) -> abi::Attr {
        abi::Attr {
            ino: U64::new(self.ino),
            size: U64::new(self.size),
            blocks: U64::new(self.blocks),
            atime: U64::new(self.atime.seconds.cast_unsigned()),
            mtime: U64::new(self.mtime.seconds.cast_unsigned()),
            ctime: U64::new(self.ctime.seconds.cast_unsigned()),
            atimensec: U32::new(self.atime.nanoseconds),
            mtimensec: U32::new(self.mtime.nanoseconds),
            ctimensec: U32::new(self.ctime.nanoseconds),
            mode: U32::new(type_bits(self.kind) | self.permissions.0),
            nlink: U32::new(self.nlink),
            uid: U32::new(self.uid),
            gid: U32::new(self.gid),
            rdev: U32::new(self.rdev),
            blksize: U32::new(self.blksize),
            flags: U32::ZERO,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub node: u64,
    /// Tells this node from an earlier one with the same node id.
    pub generation: u64,
    pub attributes: Attributes,
    /// How long the kernel may resolve the name without asking again.
    pub entry_valid: Duration,
    /// How long the kernel may use the attributes without asking again.
    pub attr_valid: Duration,
}

impl Entry {
    pub(crate) fn encode(&self) -> abi::EntryOut {
        abi::EntryOut {
            nodeid: U64::new(self.node),
            generation: U64::new(self.generation),
            entry_valid: U64::new(self.entry_valid.as_secs()),
            attr_valid: U64::new(self.attr_valid.as_secs()),
            entry_valid_nsec: U32::new(self.entry_valid.subsec_nanos()),
            attr_valid_nsec: U32::new(self.attr_valid.subsec_nanos()),
            attr: self.attributes.encode(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn attributes() -> Attributes {
        Attributes {
            ino: 9,
            size: 7,
            blocks: 1,
            atime: Timestamp {
                seconds: 10,
                nanoseconds: 11,
            },
            mtime: Timestamp {
                seconds: -20,
                nanoseconds: 21,
            },
            ctime: Timestamp {
                seconds: 30,
                nanoseconds: 31,
            },
            kind: FileType::RegularFile,
            permissions: Permissions::from_mode(0o4755),
            nlink: 2,
            uid: 1000,
            gid: 1001,
            rdev: 0,
            blksize: 4096,
        }
    }

    #[test]
    fn an_unknown_kind_sends_no_file_type() {
        assert_eq!(type_bits(FileType::Directory), 0o040_000);
        assert_eq!(dirent_type(FileType::Directory), 4);
        assert_eq!(type_bits(FileType::Unknown), 0);
        assert_eq!(dirent_type(FileType::Unknown), 0);
    }

    /// A time before 1970 stores its negative seconds as two's complement,
    /// which the kernel reads.
    #[test]
    fn attributes_encode_as_the_kernel_reads_them() {
        let encoded = attributes().encode();
        assert_eq!(encoded.mode.get(), 0o104_755);
        assert_eq!(encoded.ino.get(), 9);
        assert_eq!(encoded.mtime.get().cast_signed(), -20);
        assert_eq!(encoded.mtimensec.get(), 21);
        assert_eq!(encoded.flags.get(), 0);
    }

    #[test]
    fn an_entry_carries_both_validities_apart() {
        let entry = Entry {
            node: 5,
            generation: 3,
            attributes: attributes(),
            entry_valid: Duration::new(2, 500),
            attr_valid: Duration::from_millis(1500),
        }
        .encode();
        assert_eq!(entry.nodeid.get(), 5);
        assert_eq!(
            entry.attr.ino.get(),
            9,
            "the node id and st_ino are separate"
        );
        assert_eq!(
            (entry.entry_valid.get(), entry.entry_valid_nsec.get()),
            (2, 500)
        );
        assert_eq!(
            (entry.attr_valid.get(), entry.attr_valid_nsec.get()),
            (1, 500_000_000)
        );
    }
}
