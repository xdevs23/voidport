use zerocopy::byteorder::little_endian::{U32, U64};

use crate::attr::{Attr, EntryOut, Timespec};
use crate::macros::{wire_body, wire_struct};
use crate::message::{Request, Response};
use crate::opcode::Opcode;

wire_struct! {
    pub struct LookupRequest {
        pub name_len: U32,
    }
}

wire_body!(request LookupRequest => Opcode::Lookup, regions = [name_len: Name]);

impl<'a> Request<'a, LookupRequest> {
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    pub struct LookupResponse {
        pub entry: EntryOut,
    }
}

wire_body!(response LookupResponse => Opcode::Lookup);

wire_struct! {
    pub struct ForgetRequest {
        pub nlookup: U64,
    }
}

wire_body!(request ForgetRequest => Opcode::Forget);

pub mod getattr_flags {
    pub const HANDLE: u32 = 1 << 0;
}

wire_struct! {
    pub struct GetattrRequest {
        /// Open handle to stat, valid only with [`getattr_flags::HANDLE`].
        pub handle: U64,
        pub flags: U32,
        pub reserved: U32,
    }
}

wire_body!(request GetattrRequest => Opcode::Getattr);

wire_struct! {
    pub struct GetattrResponse {
        pub attr: Attr,
    }
}

wire_body!(response GetattrResponse => Opcode::Getattr);

/// Fields whose bit is clear are ignored entirely, and their wire value has no
/// meaning.
pub mod setattr_valid {
    pub const MODE: u32 = 1 << 0;
    pub const UID: u32 = 1 << 1;
    pub const GID: u32 = 1 << 2;
    pub const SIZE: u32 = 1 << 3;
    pub const ATIME: u32 = 1 << 4;
    pub const MTIME: u32 = 1 << 5;
    pub const CTIME: u32 = 1 << 6;
    /// Set the access time to the server's current time; overrides
    /// [`ATIME`].
    pub const ATIME_NOW: u32 = 1 << 7;
    /// Set the modification time to the server's current time; overrides
    /// [`MTIME`].
    pub const MTIME_NOW: u32 = 1 << 8;
    pub const HANDLE: u32 = 1 << 9;
}

wire_struct! {
    pub struct SetattrRequest {
        pub valid: U32,
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
    pub struct SetattrResponse {
        pub attr: Attr,
    }
}

wire_body!(response SetattrResponse => Opcode::Setattr);

wire_struct! {
    pub struct ReadlinkRequest;
}

wire_body!(request ReadlinkRequest => Opcode::Readlink);

wire_struct! {
    /// The target is a byte string with no NUL terminator, and is returned raw.
    pub struct ReadlinkResponse {
        pub target_len: U32,
    }
}

wire_body!(response ReadlinkResponse => Opcode::Readlink, regions = [target_len: Path]);

impl<'a> Response<'a, ReadlinkResponse> {
    #[must_use]
    pub fn target(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    pub struct StatfsRequest;
}

wire_body!(request StatfsRequest => Opcode::Statfs);

wire_struct! {
    /// Filesystem statistics, in the shape of `struct statvfs`.
    pub struct StatfsResponse {
        pub blocks: U64,
        pub bfree: U64,
        pub bavail: U64,
        pub files: U64,
        pub ffree: U64,
        pub bsize: U32,
        pub namelen: U32,
        pub frsize: U32,
        pub reserved: U32,
    }
}

wire_body!(response StatfsResponse => Opcode::Statfs);
