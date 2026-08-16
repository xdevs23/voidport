//! Directory operations and the readdirplus entry stream.

use zerocopy::byteorder::little_endian::{U32, U64};

use crate::attr::EntryOut;
use crate::macros::{wire_body, wire_struct};
use crate::message::{Request, Response, split_region};
use crate::opcode::Opcode;
use crate::stream::{StreamEntry, StreamIter, StreamWriter};

wire_struct! {
    /// Create a directory in the parent named by the request head.
    pub struct MkdirRequest {
        /// Permission bits requested.
        pub mode: U32,
        /// The caller's umask, applied by the server.
        pub umask: U32,
        /// Length of the name in the payload.
        pub name_len: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(request MkdirRequest => Opcode::Mkdir, regions = [name_len]);

impl<'a> Request<'a, MkdirRequest> {
    /// The name of the directory to create.
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    /// The created directory.
    pub struct MkdirResponse {
        /// Entry of the new directory.
        pub entry: EntryOut,
    }
}

wire_body!(response MkdirResponse => Opcode::Mkdir);

wire_struct! {
    /// Create a special file in the parent named by the request head.
    ///
    /// The kind rides in the file-type bits of [`mode`](Self::mode): a server
    /// creates FIFOs and socket files and answers `EPERM` for everything else,
    /// device nodes included. `rdev` is carried because `mknod` has always
    /// carried it and a privileged device opt-in would need it, not because a
    /// v1 server ever reads a nonzero one.
    pub struct MknodRequest {
        /// File type and permission bits, as `mknod(2)` takes them.
        pub mode: U32,
        /// The caller's umask, applied by the server.
        pub umask: U32,
        /// The device number, meaningful only for a device node.
        pub rdev: U32,
        /// Length of the name in the payload.
        pub name_len: U32,
    }
}

wire_body!(request MknodRequest => Opcode::Mknod, regions = [name_len]);

impl<'a> Request<'a, MknodRequest> {
    /// The name of the entry to create.
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    /// The created special file.
    pub struct MknodResponse {
        /// Entry of the new FIFO or socket.
        pub entry: EntryOut,
    }
}

wire_body!(response MknodResponse => Opcode::Mknod);

wire_struct! {
    /// Remove a non-directory entry from the parent named by the request head.
    pub struct UnlinkRequest {
        /// Length of the name in the payload.
        pub name_len: U32,
    }
}

wire_body!(request UnlinkRequest => Opcode::Unlink, regions = [name_len]);

impl<'a> Request<'a, UnlinkRequest> {
    /// The name to remove.
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    /// Acknowledgement of an unlink.
    pub struct UnlinkResponse;
}

wire_body!(response UnlinkResponse => Opcode::Unlink);

wire_struct! {
    /// Remove a directory from the parent named by the request head.
    pub struct RmdirRequest {
        /// Length of the name in the payload.
        pub name_len: U32,
    }
}

wire_body!(request RmdirRequest => Opcode::Rmdir, regions = [name_len]);

impl<'a> Request<'a, RmdirRequest> {
    /// The name to remove.
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    /// Acknowledgement of an rmdir.
    pub struct RmdirResponse;
}

wire_body!(response RmdirResponse => Opcode::Rmdir);

/// Bit values for [`RenameRequest::flags`], matching the Linux `RENAME_*`
/// flags.
pub mod rename_flags {
    /// Fail with `EEXIST` if the new name already exists.
    pub const NOREPLACE: u32 = 1 << 0;
    /// Atomically exchange the two entries.
    pub const EXCHANGE: u32 = 1 << 1;
    /// Leave a whiteout at the old name.
    pub const WHITEOUT: u32 = 1 << 2;
}

wire_struct! {
    /// Rename an entry. The request head names the source parent directory.
    ///
    /// The payload carries the old name followed by the new name.
    pub struct RenameRequest {
        /// Node id of the destination parent directory; may equal the source.
        pub new_parent_node_id: U64,
        /// See [`rename_flags`].
        pub flags: U32,
        /// Length of the old name in the payload.
        pub old_name_len: U32,
        /// Length of the new name in the payload.
        pub new_name_len: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(request RenameRequest => Opcode::Rename, regions = [old_name_len, new_name_len]);

impl<'a> Request<'a, RenameRequest> {
    /// The name in the source directory.
    #[must_use]
    pub fn old_name(&self) -> &'a [u8] {
        split_region(self.payload(), self.body().old_name_len.get()).0
    }

    /// The name in the destination directory.
    #[must_use]
    pub fn new_name(&self) -> &'a [u8] {
        let rest = split_region(self.payload(), self.body().old_name_len.get()).1;
        split_region(rest, self.body().new_name_len.get()).0
    }
}

wire_struct! {
    /// Acknowledgement of a rename.
    pub struct RenameResponse;
}

wire_body!(response RenameResponse => Opcode::Rename);

wire_struct! {
    /// Create a hard link. The request head names the parent directory of the new
    /// link; the payload carries the new name.
    ///
    /// The link and its target share one `ino`, but each reachable share mode has
    /// its own node id, so the reply's node id may differ from the source's.
    pub struct LinkRequest {
        /// Node id of the existing file to link to.
        pub target_node_id: U64,
        /// Length of the new name in the payload.
        pub name_len: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(request LinkRequest => Opcode::Link, regions = [name_len]);

impl<'a> Request<'a, LinkRequest> {
    /// The name of the new link.
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    /// The created link.
    pub struct LinkResponse {
        /// Entry of the new link.
        pub entry: EntryOut,
    }
}

wire_body!(response LinkResponse => Opcode::Link);

wire_struct! {
    /// Create a symlink in the parent named by the request head.
    ///
    /// The payload carries the link name followed by the target.
    pub struct SymlinkRequest {
        /// Length of the link name in the payload.
        pub name_len: U32,
        /// Length of the link target in the payload.
        pub target_len: U32,
    }
}

wire_body!(request SymlinkRequest => Opcode::Symlink, regions = [name_len, target_len]);

impl<'a> Request<'a, SymlinkRequest> {
    /// The name of the symlink to create.
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        split_region(self.payload(), self.body().name_len.get()).0
    }

    /// The target the symlink points at, stored verbatim.
    #[must_use]
    pub fn target(&self) -> &'a [u8] {
        let rest = split_region(self.payload(), self.body().name_len.get()).1;
        split_region(rest, self.body().target_len.get()).0
    }
}

wire_struct! {
    /// The created symlink.
    pub struct SymlinkResponse {
        /// Entry of the new symlink.
        pub entry: EntryOut,
    }
}

wire_body!(response SymlinkResponse => Opcode::Symlink);

wire_struct! {
    /// Enumerate the directory named by the request head, attributes included.
    pub struct ReaddirplusRequest {
        /// Handle from a previous open of this directory.
        pub handle: U64,
        /// Where to resume: 0 starts at the beginning, otherwise the
        /// [`DirEntryHeader::next_cookie`] of the last entry consumed.
        pub cookie: U64,
        /// Maximum number of entry-stream bytes the client will accept.
        pub size: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(request ReaddirplusRequest => Opcode::Readdirplus);

wire_struct! {
    /// A batch of directory entries.
    ///
    /// The payload is a [`DirEntryHeader`] stream; an empty stream means the
    /// directory is exhausted. Every entry that appears here has passed rule
    /// resolution and ownership mapping, so hidden entries are simply absent.
    pub struct ReaddirplusResponse {
        /// Length of the entry stream in the payload.
        pub entries_len: U32,
    }
}

wire_body!(response ReaddirplusResponse => Opcode::Readdirplus, regions = [entries_len]);

impl<'a> Response<'a, ReaddirplusResponse> {
    /// Walks the entry stream.
    #[must_use]
    pub fn entries(&self) -> DirEntryIter<'a> {
        DirEntryIter::new(self.payload())
    }
}

wire_struct! {
    /// The fixed header of one readdirplus entry; the name follows it.
    ///
    /// Each entry is an entry reply in its own right: it carries a node id whose
    /// lookup count the client must balance with `forget`.
    pub struct DirEntryHeader {
        /// Node id, generation and attributes of the entry.
        pub entry: EntryOut,
        /// Cookie that resumes enumeration after this entry.
        pub next_cookie: U64,
        /// Entry type; see [`file_type`](crate::attr::file_type).
        pub entry_type: U32,
        /// Length of the name that follows this header.
        pub name_len: U32,
    }
}

impl DirEntryHeader {
    /// Builds an entry header for a name of `name_len` bytes.
    #[must_use]
    pub fn new(entry: EntryOut, next_cookie: u64, entry_type: u32, name_len: u32) -> Self {
        Self {
            entry,
            next_cookie: U64::new(next_cookie),
            entry_type: U32::new(entry_type),
            name_len: U32::new(name_len),
        }
    }
}

impl StreamEntry for DirEntryHeader {
    fn tail_len(&self) -> u32 {
        self.name_len.get()
    }
}

/// Iterator over a readdirplus entry stream.
pub type DirEntryIter<'a> = StreamIter<'a, DirEntryHeader>;

/// Builder for a readdirplus entry stream.
pub type DirEntryWriter<'a> = StreamWriter<'a, DirEntryHeader>;
