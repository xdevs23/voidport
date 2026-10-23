use zerocopy::byteorder::little_endian::{U32, U64};

use crate::attr::EntryOut;
use crate::macros::{wire_body, wire_struct};
use crate::message::{Request, split_region};
use crate::opcode::Opcode;
use crate::stream::{StreamEntry, StreamIter, StreamWriter};

wire_struct! {
    pub struct MkdirRequest {
        pub mode: U32,
        pub umask: U32,
        pub name_len: U32,
        pub reserved: U32,
    }
}

wire_body!(request MkdirRequest => Opcode::Mkdir, regions = [name_len: Name]);

impl<'a> Request<'a, MkdirRequest> {
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    pub struct MkdirResponse {
        pub entry: EntryOut,
    }
}

wire_body!(response MkdirResponse => Opcode::Mkdir);

wire_struct! {
    /// A server creates FIFOs and socket files and returns `EPERM` for
    /// everything else. `rdev` is needed because `mknod(2)` expects a device
    /// number, and a server that does not allow device nodes never reads it.
    pub struct MknodRequest {
        pub mode: U32,
        pub umask: U32,
        pub rdev: U32,
        pub name_len: U32,
    }
}

wire_body!(request MknodRequest => Opcode::Mknod, regions = [name_len: Name]);

impl<'a> Request<'a, MknodRequest> {
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    pub struct MknodResponse {
        pub entry: EntryOut,
    }
}

wire_body!(response MknodResponse => Opcode::Mknod);

wire_struct! {
    pub struct UnlinkRequest {
        pub name_len: U32,
    }
}

wire_body!(request UnlinkRequest => Opcode::Unlink, regions = [name_len: Name]);

impl<'a> Request<'a, UnlinkRequest> {
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    pub struct UnlinkResponse;
}

wire_body!(response UnlinkResponse => Opcode::Unlink);

wire_struct! {
    pub struct RmdirRequest {
        pub name_len: U32,
    }
}

wire_body!(request RmdirRequest => Opcode::Rmdir, regions = [name_len: Name]);

impl<'a> Request<'a, RmdirRequest> {
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    pub struct RmdirResponse;
}

wire_body!(response RmdirResponse => Opcode::Rmdir);

pub mod rename_flags {
    pub const NOREPLACE: u32 = 1 << 0;
    pub const EXCHANGE: u32 = 1 << 1;
    pub const WHITEOUT: u32 = 1 << 2;
}

wire_struct! {
    pub struct RenameRequest {
        pub new_parent_node_id: U64,
        pub flags: U32,
        pub old_name_len: U32,
        pub new_name_len: U32,
        pub reserved: U32,
    }
}

wire_body!(
    request RenameRequest => Opcode::Rename,
    regions = [old_name_len: Name, new_name_len: Name]
);

impl<'a> Request<'a, RenameRequest> {
    #[must_use]
    pub fn old_name(&self) -> &'a [u8] {
        split_region(self.payload(), self.body().old_name_len.get()).0
    }

    #[must_use]
    pub fn new_name(&self) -> &'a [u8] {
        let rest = split_region(self.payload(), self.body().old_name_len.get()).1;
        split_region(rest, self.body().new_name_len.get()).0
    }
}

wire_struct! {
    pub struct RenameResponse;
}

wire_body!(response RenameResponse => Opcode::Rename);

wire_struct! {
    /// The link and its target have one `ino`, but each share mode that can
    /// reach them has a node id of its own, so the node id in the reply can
    /// differ from `target_node_id`.
    pub struct LinkRequest {
        pub target_node_id: U64,
        pub name_len: U32,
        pub reserved: U32,
    }
}

wire_body!(request LinkRequest => Opcode::Link, regions = [name_len: Name]);

impl<'a> Request<'a, LinkRequest> {
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    pub struct LinkResponse {
        pub entry: EntryOut,
    }
}

wire_body!(response LinkResponse => Opcode::Link);

wire_struct! {
    pub struct SymlinkRequest {
        pub name_len: U32,
        pub target_len: U32,
    }
}

wire_body!(
    request SymlinkRequest => Opcode::Symlink,
    regions = [name_len: Name, target_len: Path]
);

impl<'a> Request<'a, SymlinkRequest> {
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        split_region(self.payload(), self.body().name_len.get()).0
    }

    /// The target is stored verbatim.
    #[must_use]
    pub fn target(&self) -> &'a [u8] {
        let rest = split_region(self.payload(), self.body().name_len.get()).1;
        split_region(rest, self.body().target_len.get()).0
    }
}

wire_struct! {
    pub struct SymlinkResponse {
        pub entry: EntryOut,
    }
}

wire_body!(response SymlinkResponse => Opcode::Symlink);

wire_struct! {
    pub struct ReaddirplusRequest {
        pub handle: U64,
        /// 0 starts at the beginning, otherwise the
        /// [`DirEntryHeader::next_cookie`] of the last entry consumed.
        pub cookie: U64,
        /// The server stops before an entry that would take the entries it
        /// sent past this, and it allocates nothing by it.
        pub size: U32,
        pub reserved: U32,
    }
}

wire_body!(request ReaddirplusRequest => Opcode::Readdirplus);

wire_struct! {
    /// The exhausted bit of the closing piece shows that the directory has no
    /// more entries. A reader never infers the end from a short batch. A
    /// listing that fails partway ends with the errno in the closing piece.
    /// Every entry has passed rule resolution and ownership mapping, so a
    /// hidden entry is absent.
    pub struct ReaddirplusResponse;
}

wire_body!(response ReaddirplusResponse => Opcode::Readdirplus, pieces = DirEntries);

/// Each entry is at least a [`DirEntryHeader`] long, so a reply has at most
/// `size` divided by that many length words. A server keeps a copy of the
/// reply in a buffer of this size in case the connection is lost, and a client
/// receives the reply into a buffer of the same size.
#[must_use]
pub const fn listing_reply_bound(size: u32) -> usize {
    let size = size as usize;
    crate::frame::FrameWriter::response_len::<ReaddirplusResponse>(0)
        + crate::piece::stream_len(size / core::mem::size_of::<DirEntryHeader>(), size)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u32)]
pub enum EntryType {
    #[default]
    Unknown = 0,
    Fifo = 1,
    Character = 2,
    Directory = 4,
    Block = 6,
    Regular = 8,
    Symlink = 10,
    Socket = 12,
}

impl EntryType {
    /// The same mapping as `IFTODT` of the C library.
    pub fn of_mode(mode: u32) -> Option<Self> {
        match mode & 0o170_000 {
            0o010_000 => Some(Self::Fifo),
            0o020_000 => Some(Self::Character),
            0o040_000 => Some(Self::Directory),
            0o060_000 => Some(Self::Block),
            0o100_000 => Some(Self::Regular),
            0o120_000 => Some(Self::Symlink),
            0o140_000 => Some(Self::Socket),
            _ => None,
        }
    }
}

impl TryFrom<u32> for EntryType {
    type Error = crate::error::FramingError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Fifo),
            2 => Ok(Self::Character),
            4 => Ok(Self::Directory),
            6 => Ok(Self::Block),
            8 => Ok(Self::Regular),
            10 => Ok(Self::Symlink),
            12 => Ok(Self::Socket),
            _ => Err(crate::error::FramingError::InvalidEntryType),
        }
    }
}

wire_struct! {
    /// Each entry has a node id whose lookup count the client balances
    /// with `forget`.
    pub struct DirEntryHeader {
        pub entry: EntryOut,
        pub next_cookie: U64,
        /// Unvalidated wire storage, read through [`DirEntryHeader::entry_type`].
        entry_type: U32,
        pub name_len: U32,
    }
}

impl DirEntryHeader {
    pub fn entry_type(&self) -> Result<EntryType, crate::error::FramingError> {
        EntryType::try_from(self.entry_type.get())
    }

    #[must_use]
    pub fn new(entry: EntryOut, next_cookie: u64, entry_type: EntryType, name_len: u32) -> Self {
        Self {
            entry,
            next_cookie: U64::new(next_cookie),
            entry_type: U32::new(entry_type as u32),
            name_len: U32::new(name_len),
        }
    }
}

impl StreamEntry for DirEntryHeader {
    fn tail_len(&self) -> u32 {
        self.name_len.get()
    }
}

pub type DirEntryIter<'a> = StreamIter<'a, DirEntryHeader>;

pub type DirEntryWriter<'a> = StreamWriter<'a, DirEntryHeader>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_types_are_checked_without_changing_wire_layout() {
        for raw in 0..=255 {
            let mut header = DirEntryHeader::new(EntryOut::default(), 1, EntryType::Unknown, 0);
            header.entry_type = U32::new(raw);
            let expected = matches!(raw, 0 | 1 | 2 | 4 | 6 | 8 | 10 | 12);
            assert_eq!(header.entry_type().is_ok(), expected, "type {raw}");
            if let Ok(kind) = header.entry_type() {
                assert_eq!(kind as u32, raw);
            }
        }
        assert!(EntryType::try_from(u32::MAX).is_err());
    }

    #[test]
    fn every_mode_class_with_permissions_names_its_type() {
        for class in 0..16u32 {
            let expected = match class << 12 {
                0o010_000 => Some(EntryType::Fifo),
                0o020_000 => Some(EntryType::Character),
                0o040_000 => Some(EntryType::Directory),
                0o060_000 => Some(EntryType::Block),
                0o100_000 => Some(EntryType::Regular),
                0o120_000 => Some(EntryType::Symlink),
                0o140_000 => Some(EntryType::Socket),
                _ => None,
            };
            for permissions in [0, 0o444, 0o755, 0o7777] {
                assert_eq!(
                    EntryType::of_mode((class << 12) | permissions),
                    expected,
                    "class {class:o}"
                );
            }
        }
        assert_eq!(
            core::mem::size_of::<DirEntryHeader>(),
            core::mem::size_of::<EntryOut>() + 16
        );
    }
}
