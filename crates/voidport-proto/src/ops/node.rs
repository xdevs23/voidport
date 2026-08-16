//! Node operations: lookup, forget, attributes, symlink targets, statfs.

use zerocopy::byteorder::little_endian::{U32, U64};

use crate::attr::{Attr, EntryOut, Timespec};
use crate::macros::{wire_body, wire_struct};
use crate::message::{Request, Response};
use crate::opcode::Opcode;

wire_struct! {
    /// Resolve a name in the directory named by the request head's `node_id`.
    ///
    /// The payload is the name. A successful reply increments the node's lookup
    /// count; the client balances it with [`ForgetRequest`].
    pub struct LookupRequest {
        /// Length of the name in the payload.
        pub name_len: U32,
    }
}

wire_body!(request LookupRequest => Opcode::Lookup, regions = [name_len]);

impl<'a> Request<'a, LookupRequest> {
    /// The name to resolve in the parent directory.
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    /// The resolved entry.
    pub struct LookupResponse {
        /// The node id, generation and attributes of the resolved file.
        pub entry: EntryOut,
    }
}

wire_body!(response LookupResponse => Opcode::Lookup);

wire_struct! {
    /// Drop `nlookup` lookup counts from the node named in the request head.
    ///
    /// The one request with no response: the server drops the node entry when the
    /// count reaches zero, and a client that disappears mid-flight is handled by
    /// tearing down the whole session node table.
    pub struct ForgetRequest {
        /// Number of outstanding lookups to release.
        pub nlookup: U64,
    }
}

wire_body!(request ForgetRequest => Opcode::Forget);

/// Bit values for [`GetattrRequest::flags`].
pub mod getattr_flags {
    /// [`super::GetattrRequest::handle`] names an open file and should be used
    /// instead of resolving the node.
    pub const HANDLE: u32 = 1 << 0;
}

wire_struct! {
    /// Fetch attributes of the node named in the request head.
    pub struct GetattrRequest {
        /// Open handle to stat, valid only with [`getattr_flags::HANDLE`].
        pub handle: U64,
        /// See [`getattr_flags`].
        pub flags: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(request GetattrRequest => Opcode::Getattr);

wire_struct! {
    /// The node's attributes.
    pub struct GetattrResponse {
        /// Current attributes.
        pub attr: Attr,
    }
}

wire_body!(response GetattrResponse => Opcode::Getattr);

/// Bit values for [`SetattrRequest::valid`], naming which fields apply.
///
/// Fields whose bit is clear are ignored entirely; their wire value carries no
/// meaning.
pub mod setattr_valid {
    /// Apply [`super::SetattrRequest::mode`].
    pub const MODE: u32 = 1 << 0;
    /// Apply [`super::SetattrRequest::uid`].
    pub const UID: u32 = 1 << 1;
    /// Apply [`super::SetattrRequest::gid`].
    pub const GID: u32 = 1 << 2;
    /// Apply [`super::SetattrRequest::size`] (truncate).
    pub const SIZE: u32 = 1 << 3;
    /// Apply [`super::SetattrRequest::atime`].
    pub const ATIME: u32 = 1 << 4;
    /// Apply [`super::SetattrRequest::mtime`].
    pub const MTIME: u32 = 1 << 5;
    /// Apply [`super::SetattrRequest::ctime`].
    pub const CTIME: u32 = 1 << 6;
    /// Set the access time to the server's current time; overrides
    /// [`ATIME`].
    pub const ATIME_NOW: u32 = 1 << 7;
    /// Set the modification time to the server's current time; overrides
    /// [`MTIME`].
    pub const MTIME_NOW: u32 = 1 << 8;
    /// [`super::SetattrRequest::handle`] names the open file to operate on.
    pub const HANDLE: u32 = 1 << 9;
}

wire_struct! {
    /// Change attributes of the node named in the request head.
    pub struct SetattrRequest {
        /// Validity bitmask; see [`setattr_valid`].
        pub valid: U32,
        /// Reserved; zero.
        pub reserved: U32,
        /// Open handle, valid only with [`setattr_valid::HANDLE`].
        pub handle: U64,
        /// New size, valid only with [`setattr_valid::SIZE`].
        pub size: U64,
        /// New permission bits, valid only with [`setattr_valid::MODE`].
        pub mode: U32,
        /// New owner in guest id space, valid only with [`setattr_valid::UID`].
        pub uid: U32,
        /// New group in guest id space, valid only with [`setattr_valid::GID`].
        pub gid: U32,
        /// Reserved; zero.
        pub reserved2: U32,
        /// New access time, valid only with [`setattr_valid::ATIME`].
        pub atime: Timespec,
        /// New modification time, valid only with [`setattr_valid::MTIME`].
        pub mtime: Timespec,
        /// New change time, valid only with [`setattr_valid::CTIME`].
        pub ctime: Timespec,
    }
}

wire_body!(request SetattrRequest => Opcode::Setattr);

wire_struct! {
    /// Attributes after the change.
    pub struct SetattrResponse {
        /// Attributes as they now stand.
        pub attr: Attr,
    }
}

wire_body!(response SetattrResponse => Opcode::Setattr);

wire_struct! {
    /// Read the target of the symlink named in the request head.
    pub struct ReadlinkRequest;
}

wire_body!(request ReadlinkRequest => Opcode::Readlink);

wire_struct! {
    /// The symlink target.
    ///
    /// The target is a byte string with no NUL terminator, and is returned raw:
    /// the server never follows it, and resolution below a graft is confined by
    /// `RESOLVE_BENEATH` regardless of what it points at.
    pub struct ReadlinkResponse {
        /// Length of the target in the payload.
        pub target_len: U32,
    }
}

wire_body!(response ReadlinkResponse => Opcode::Readlink, regions = [target_len]);

impl<'a> Response<'a, ReadlinkResponse> {
    /// The link target.
    #[must_use]
    pub fn target(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    /// Filesystem statistics for the session's namespace.
    pub struct StatfsRequest;
}

wire_body!(request StatfsRequest => Opcode::Statfs);

wire_struct! {
    /// Filesystem statistics, in the shape of `struct statvfs`.
    pub struct StatfsResponse {
        /// Total data blocks.
        pub blocks: U64,
        /// Free data blocks.
        pub bfree: U64,
        /// Free blocks available to unprivileged users.
        pub bavail: U64,
        /// Total inodes.
        pub files: U64,
        /// Free inodes.
        pub ffree: U64,
        /// Optimal transfer block size.
        pub bsize: U32,
        /// Maximum filename length.
        pub namelen: U32,
        /// Fragment size.
        pub frsize: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(response StatfsResponse => Opcode::Statfs);
