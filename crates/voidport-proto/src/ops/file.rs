//! File operations: open, create, read, write, release, sync, locking.
//!
//! Open files are named by `u64` handles that live in a per-session handle
//! table. A dropped connection tears the table down, so a handle never
//! outlives its session.

use zerocopy::byteorder::little_endian::{U32, U64};

use crate::attr::EntryOut;
use crate::macros::{wire_body, wire_struct};
use crate::message::{Request, Response};
use crate::opcode::Opcode;

wire_struct! {
    /// Open the file named by the request head.
    ///
    /// Permission is checked once, here: a graft downgraded to read-only after
    /// this point does not disturb the handle, exactly as a local `chmod` leaves
    /// open descriptors alone.
    pub struct OpenRequest {
        /// Linux `open(2)` flags.
        pub flags: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(request OpenRequest => Opcode::Open);

wire_struct! {
    /// The opened handle.
    pub struct OpenResponse {
        /// Handle naming the open file for the rest of the session.
        pub handle: U64,
        /// Reply flags. v1 defines none: zero on send, unknown bits ignored on
        /// receive.
        pub flags: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(response OpenResponse => Opcode::Open);

wire_struct! {
    /// Create and open a file in the parent named by the request head, in one
    /// round trip. The payload carries the name.
    pub struct CreateRequest {
        /// Linux `open(2)` flags.
        pub flags: U32,
        /// Permission bits requested.
        pub mode: U32,
        /// The caller's umask, applied by the server.
        pub umask: U32,
        /// Length of the name in the payload.
        pub name_len: U32,
    }
}

wire_body!(request CreateRequest => Opcode::Create, regions = [name_len]);

impl<'a> Request<'a, CreateRequest> {
    /// The name of the file to create.
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    /// The created file and its handle.
    pub struct CreateResponse {
        /// Entry of the new file; its lookup count is held like any other entry
        /// reply's.
        pub entry: EntryOut,
        /// Handle naming the open file.
        pub handle: U64,
        /// Reply flags. v1 defines none.
        pub flags: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(response CreateResponse => Opcode::Create);

/// Bit values for [`ReleaseRequest::release_flags`].
pub mod release_flags {
    /// Flush the file before releasing the handle.
    pub const FLUSH: u32 = 1 << 0;
    /// Release the lock owned by [`super::ReleaseRequest::lock_owner`].
    pub const UNLOCK: u32 = 1 << 1;
}

wire_struct! {
    /// Release a handle. The last release of a handle closes the underlying host
    /// file.
    pub struct ReleaseRequest {
        /// Handle to release.
        pub handle: U64,
        /// Lock owner to release with [`release_flags::UNLOCK`].
        pub lock_owner: U64,
        /// Linux `open(2)` flags the handle was opened with.
        pub flags: U32,
        /// See [`release_flags`].
        pub release_flags: U32,
    }
}

wire_body!(request ReleaseRequest => Opcode::Release);

wire_struct! {
    /// Acknowledgement of a release.
    pub struct ReleaseResponse;
}

wire_body!(response ReleaseResponse => Opcode::Release);

wire_struct! {
    /// Read from an open file.
    pub struct ReadRequest {
        /// Handle to read from.
        pub handle: U64,
        /// Byte offset to read at.
        pub offset: U64,
        /// Maximum number of bytes to return.
        pub size: U32,
        /// Linux `open(2)` flags the handle was opened with.
        pub flags: U32,
    }
}

wire_body!(request ReadRequest => Opcode::Read);

wire_struct! {
    /// File data.
    ///
    /// The data rides in the trailing payload and is never re-serialized: the
    /// server reads host bytes straight into the frame buffer. A short read means
    /// end of file.
    pub struct ReadResponse {
        /// Length of the data in the payload.
        pub data_len: U32,
    }
}

wire_body!(response ReadResponse => Opcode::Read, regions = [data_len]);

impl<'a> Response<'a, ReadResponse> {
    /// The bytes read.
    #[must_use]
    pub fn data(&self) -> &'a [u8] {
        self.payload()
    }
}

/// Bit values for [`WriteRequest::write_flags`].
///
/// The field has carried must-be-zero-on-send / ignore-unknown-on-receive from
/// day one, which is what makes adding a flag additive: the zero value is
/// exactly the old behaviour, an elder peer ignores the bit, and every existing
/// frame stays byte-identical. The strictly enforced `reserved` field beside it
/// is unaffected and is still a framing error when nonzero.
pub mod write_flags {
    /// The guest kernel asks for this file's privileged mode bits to be
    /// stripped, because the writer does not hold the file-mode privilege.
    ///
    /// Carried on **every chunk** of a write the guest kernel split, since
    /// stripping is idempotent. An elder server ignores it and strips nothing:
    /// fail-open for stripping under version skew, until both sides update.
    pub const PRIVILEGED_STRIP: u32 = 1 << 0;
}

wire_struct! {
    /// Write to an open file. The payload carries the data.
    pub struct WriteRequest {
        /// Handle to write to.
        pub handle: U64,
        /// Byte offset to write at.
        pub offset: U64,
        /// Length of the data in the payload.
        pub data_len: U32,
        /// Linux `open(2)` flags the handle was opened with.
        pub flags: U32,
        /// See [`write_flags`]: zero on send for a flag the sender does not
        /// mean, unknown bits ignored on receive.
        pub write_flags: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(request WriteRequest => Opcode::Write, regions = [data_len]);

impl<'a> Request<'a, WriteRequest> {
    /// The bytes to write.
    #[must_use]
    pub fn data(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    /// How much was written.
    pub struct WriteResponse {
        /// Number of bytes written.
        pub written: U32,
    }
}

wire_body!(response WriteResponse => Opcode::Write);

wire_struct! {
    /// Flush on close of one guest file descriptor. May be sent more than once per
    /// handle, once per descriptor closed.
    pub struct FlushRequest {
        /// Handle being flushed.
        pub handle: U64,
        /// Owner of the locks to drop, following POSIX close semantics.
        pub lock_owner: U64,
    }
}

wire_body!(request FlushRequest => Opcode::Flush);

wire_struct! {
    /// Acknowledgement of a flush.
    pub struct FlushResponse;
}

wire_body!(response FlushResponse => Opcode::Flush);

/// Bit values for [`FsyncRequest::flags`].
pub mod fsync_flags {
    /// Sync data only, leaving metadata alone (`fdatasync`).
    pub const DATASYNC: u32 = 1 << 0;
}

wire_struct! {
    /// Flush an open file to stable storage.
    pub struct FsyncRequest {
        /// Handle to sync.
        pub handle: U64,
        /// See [`fsync_flags`].
        pub flags: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(request FsyncRequest => Opcode::Fsync);

wire_struct! {
    /// Acknowledgement of an fsync.
    pub struct FsyncResponse;
}

wire_body!(response FsyncResponse => Opcode::Fsync);

/// Lock types, matching the Linux `F_RDLCK`/`F_WRLCK`/`F_UNLCK` values.
pub mod lock_type {
    /// Shared read lock.
    pub const READ: u32 = 0;
    /// Exclusive write lock.
    pub const WRITE: u32 = 1;
    /// Lock release.
    pub const UNLOCK: u32 = 2;
}

wire_struct! {
    /// One POSIX record lock.
    pub struct FileLock {
        /// First byte of the locked range.
        pub start: U64,
        /// Last byte of the locked range; `u64::MAX` locks to end of file.
        pub end: U64,
        /// Opaque lock owner, as supplied by the guest kernel.
        pub owner: U64,
        /// Guest pid holding the lock; informational.
        pub pid: U32,
        /// See [`lock_type`].
        pub lock_type: U32,
    }
}

wire_struct! {
    /// Test whether a lock could be placed.
    pub struct GetlkRequest {
        /// Handle the lock applies to.
        pub handle: U64,
        /// The lock being tested.
        pub lock: FileLock,
    }
}

wire_body!(request GetlkRequest => Opcode::Getlk);

wire_struct! {
    /// The conflicting lock, or one of type [`lock_type::UNLOCK`] when the range
    /// is free.
    pub struct GetlkResponse {
        /// The conflicting lock.
        pub lock: FileLock,
    }
}

wire_body!(response GetlkResponse => Opcode::Getlk);

/// Bit values for [`SetlkRequest::flags`].
pub mod setlk_flags {
    /// Block until the lock can be taken; the `F_SETLKW` of this protocol.
    pub const WAIT: u32 = 1 << 0;
}

wire_struct! {
    /// Acquire or release a lock.
    pub struct SetlkRequest {
        /// Handle the lock applies to.
        pub handle: U64,
        /// The lock to place, or one of type [`lock_type::UNLOCK`] to release.
        pub lock: FileLock,
        /// See [`setlk_flags`].
        pub flags: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(request SetlkRequest => Opcode::Setlk);

wire_struct! {
    /// Acknowledgement that the lock was placed or released.
    pub struct SetlkResponse;
}

wire_body!(response SetlkResponse => Opcode::Setlk);
