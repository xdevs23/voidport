//! A dropped connection tears down the handle table of its session, so a
//! handle never outlives its session.

use zerocopy::byteorder::little_endian::{U32, U64};

use crate::attr::EntryOut;
use crate::macros::{wire_body, wire_struct};
use crate::message::Request;
use crate::opcode::Opcode;

wire_struct! {
    /// Permission is checked once, here: a graft downgraded to read-only after
    /// this point does not disturb the handle.
    pub struct OpenRequest {
        pub flags: U32,
        pub reserved: U32,
    }
}

wire_body!(request OpenRequest => Opcode::Open);

/// A reply with neither bit leaves the pages to the lifetime of the handle:
/// the guest drops the pages it cached of the file before the open, and caches
/// the pages it reads until the handle closes.
pub mod open_flags {
    /// The guest may cache the pages after the handle closes and read later
    /// opens from them. The server has a lease that shows no other writer
    /// exists, and it recalls the pages before one goes ahead.
    pub const KEEP_CACHE: u32 = 1 << 0;
    /// The guest must not cache the pages: nothing shows that no other writer
    /// exists, so every read has to reach the server.
    pub const UNCACHED: u32 = 1 << 1;
}

wire_struct! {
    pub struct OpenResponse {
        pub handle: U64,
        pub flags: U32,
        pub reserved: U32,
    }
}

wire_body!(response OpenResponse => Opcode::Open);

wire_struct! {
    pub struct CreateRequest {
        pub flags: U32,
        pub mode: U32,
        pub umask: U32,
        pub name_len: U32,
    }
}

wire_body!(request CreateRequest => Opcode::Create, regions = [name_len: Name]);

impl<'a> Request<'a, CreateRequest> {
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    pub struct CreateResponse {
        pub entry: EntryOut,
        pub handle: U64,
        /// Reply flags. None are defined.
        pub flags: U32,
        pub reserved: U32,
    }
}

wire_body!(response CreateResponse => Opcode::Create);

pub mod release_flags {
    pub const FLUSH: u32 = 1 << 0;
    pub const UNLOCK: u32 = 1 << 1;
}

wire_struct! {
    /// The last release of a handle closes the underlying host file.
    pub struct ReleaseRequest {
        pub handle: U64,
        pub lock_owner: U64,
        pub flags: U32,
        pub release_flags: U32,
    }
}

wire_body!(request ReleaseRequest => Opcode::Release);

wire_struct! {
    pub struct ReleaseResponse;
}

wire_body!(response ReleaseResponse => Opcode::Release);

wire_struct! {
    pub struct ReadRequest {
        pub handle: U64,
        pub offset: U64,
        pub size: U32,
        pub flags: U32,
    }
}

wire_body!(request ReadRequest => Opcode::Read);

wire_struct! {
    /// The server reads a piece, sends it with its length in front, and
    /// closes with a closing piece whose exhausted bit shows that the file
    /// ended before the request was filled. After a reply that closes without
    /// that bit and short of the request, the reader reads again from where it
    /// stopped.
    pub struct ReadResponse;
}

wire_body!(response ReadResponse => Opcode::Read, pieces = Data);

/// A bit is zero on send unless its meaning applies, and a receiver ignores
/// the bits it does not define. The `reserved` field is enforced.
pub mod write_flags {
    /// The guest kernel asks for this file's privileged mode bits to be
    /// stripped, because the writer does not hold the file-mode privilege.
    ///
    /// It is set on every request of a write split by the guest kernel, since
    /// stripping is idempotent.
    pub const PRIVILEGED_STRIP: u32 = 1 << 0;
}

wire_struct! {
    /// Exactly `data_len` bytes of data follow the message on the connection,
    /// outside the framed message.
    pub struct WriteRequest {
        pub handle: U64,
        pub offset: U64,
        pub data_len: U32,
        pub flags: U32,
        pub write_flags: U32,
        pub reserved: U32,
    }
}

wire_body!(request WriteRequest => Opcode::Write, data = data_len);

wire_struct! {
    pub struct WriteResponse {
        pub written: U32,
    }
}

wire_body!(response WriteResponse => Opcode::Write);

wire_struct! {
    /// Sent once per guest descriptor closed, so more than once per handle.
    pub struct FlushRequest {
        pub handle: U64,
        pub lock_owner: U64,
    }
}

wire_body!(request FlushRequest => Opcode::Flush);

wire_struct! {
    pub struct FlushResponse;
}

wire_body!(response FlushResponse => Opcode::Flush);

pub mod fsync_flags {
    pub const DATASYNC: u32 = 1 << 0;
}

wire_struct! {
    pub struct FsyncRequest {
        pub handle: U64,
        pub flags: U32,
        pub reserved: U32,
    }
}

wire_body!(request FsyncRequest => Opcode::Fsync);

wire_struct! {
    pub struct FsyncResponse;
}

wire_body!(response FsyncResponse => Opcode::Fsync);

/// Lock types, matching the Linux `F_RDLCK`/`F_WRLCK`/`F_UNLCK` values.
pub mod lock_type {
    pub const READ: u32 = 0;
    pub const WRITE: u32 = 1;
    pub const UNLOCK: u32 = 2;
}

wire_struct! {
    pub struct FileLock {
        pub start: U64,
        /// Last byte of the locked range; `u64::MAX` locks to end of file.
        pub end: U64,
        pub owner: U64,
        /// Guest pid holding the lock; informational.
        pub pid: U32,
        pub lock_type: U32,
    }
}

wire_struct! {
    pub struct GetlkRequest {
        pub handle: U64,
        pub lock: FileLock,
    }
}

wire_body!(request GetlkRequest => Opcode::Getlk);

wire_struct! {
    /// The conflicting lock, or one of type [`lock_type::UNLOCK`] when the range
    /// is free.
    pub struct GetlkResponse {
        pub lock: FileLock,
    }
}

wire_body!(response GetlkResponse => Opcode::Getlk);

pub mod setlk_flags {
    /// Block until the lock can be taken; the `F_SETLKW` of this protocol.
    pub const WAIT: u32 = 1 << 0;
}

wire_struct! {
    pub struct SetlkRequest {
        pub handle: U64,
        pub lock: FileLock,
        pub flags: U32,
        pub reserved: U32,
    }
}

wire_body!(request SetlkRequest => Opcode::Setlk);

wire_struct! {
    pub struct SetlkResponse;
}

wire_body!(response SetlkResponse => Opcode::Setlk);
