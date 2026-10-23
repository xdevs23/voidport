// SPDX-License-Identifier: GPL-2.0

use kernel::prelude::*;
use voidport_proto::ops::file::{
    fsync_flags, lock_type, setlk_flags, write_flags, FileLock, FlushRequest, FlushResponse,
    FsyncRequest, FsyncResponse, GetlkRequest, GetlkResponse, SetlkRequest, SetlkResponse,
    WriteRequest, WriteResponse,
};
use voidport_session::owed;
use zerocopy::byteorder::little_endian::{U32, U64};

use super::{acknowledged_operations, Operation, Paged, Request};
use crate::cleanup::Cleanup;
use crate::connection::{Data, Landing};
use crate::session::{ExtractError, Session};
use crate::wire::Caller;

#[derive(Clone, Copy)]
pub(crate) struct Through {
    pub(crate) caller: Caller,
    pub(crate) node_id: u64,
    pub(crate) handle: u64,
}

/// Whether a write keeps the setuid and setgid bits of its file, or has the
/// server clear them.
#[derive(Clone, Copy)]
pub(crate) enum Privileged {
    Keep,
    Strip,
}

/// What an fsync puts on stable storage: everything of the file, or its data
/// and what reading the data needs.
#[derive(Clone, Copy)]
pub(crate) enum SyncScope {
    Full,
    DataOnly,
}

/// Whether a Setlk waits while a lock of another owner is in the way.
#[derive(Clone, Copy)]
pub(crate) enum LockWait {
    /// It fails at once.
    Try,
    /// Its reply comes once no such lock is in the way.
    Block,
}

acknowledged_operations!(
    FlushRequest => FlushResponse,
    FsyncRequest => FsyncResponse,
);

impl Paged for WriteRequest {
    fn cut(mut self, len: usize) -> Self {
        let len = u32::try_from(len).unwrap_or(u32::MAX);
        self.data_len = U32::new(self.data_len.get().min(len));
        self
    }
}

impl Operation for WriteRequest {
    type Response = WriteResponse;
    type Output = u32;

    fn extract(
        &self,
        response: &WriteResponse,
        _: &[u8],
        _: &Landing,
    ) -> core::result::Result<u32, ExtractError> {
        Ok(response.written.get())
    }
}

impl Operation for GetlkRequest {
    type Response = GetlkResponse;
    /// The lock of another owner in the way, or the lock asked about marked
    /// unlocked.
    type Output = FileLock;

    fn extract(
        &self,
        response: &GetlkResponse,
        _: &[u8],
        _: &Landing,
    ) -> core::result::Result<FileLock, ExtractError> {
        Ok(response.lock)
    }
}

impl Operation for SetlkRequest {
    type Response = SetlkResponse;
    type Output = ();

    /// Reserves the record of the lock the reply places, as
    /// `owed::setlk_leaves_lock` returns: an unlock of the same owner, range
    /// and handle gives it back when the caller left before the reply.
    fn cleanup(&self, caller: Caller, node_id: u64) -> Result<Option<KBox<Cleanup>>> {
        if !owed::setlk_leaves_lock(self.lock.lock_type.get()) {
            return Ok(None);
        }
        let unlock = SetlkRequest {
            lock: FileLock {
                lock_type: U32::new(lock_type::UNLOCK),
                ..self.lock
            },
            flags: U32::ZERO,
            ..*self
        };
        Cleanup::lock(caller, node_id, unlock).map(Some)
    }

    fn extract(
        &self,
        _: &SetlkResponse,
        _: &[u8],
        _: &Landing,
    ) -> core::result::Result<(), ExtractError> {
        Ok(())
    }
}

impl Session {
    pub(crate) fn write(
        &self,
        through: Through,
        offset: u64,
        data: &dyn Data,
        privileged: Privileged,
    ) -> Result<u32> {
        let body = WriteRequest {
            handle: U64::new(through.handle),
            offset: U64::new(offset),
            data_len: U32::new(u32::try_from(data.len()).map_err(|_| EINVAL)?),
            flags: U32::ZERO,
            write_flags: U32::new(match privileged {
                Privileged::Keep => 0,
                Privileged::Strip => write_flags::PRIVILEGED_STRIP,
            }),
            reserved: U32::ZERO,
        };
        self.call(Request::new(through.caller, through.node_id, body).data(data))
    }

    /// Sends the server a notice that a descriptor of a handle closed, which
    /// releases the record locks of `lock_owner`.
    pub(crate) fn flush(&self, through: Through, lock_owner: u64) -> Result {
        let body = FlushRequest {
            handle: U64::new(through.handle),
            lock_owner: U64::new(lock_owner),
        };
        self.call(Request::new(through.caller, through.node_id, body))
    }

    pub(crate) fn fsync(&self, through: Through, scope: SyncScope) -> Result {
        let body = FsyncRequest {
            handle: U64::new(through.handle),
            flags: U32::new(match scope {
                SyncScope::Full => 0,
                SyncScope::DataOnly => fsync_flags::DATASYNC,
            }),
            reserved: U32::ZERO,
        };
        self.call(Request::new(through.caller, through.node_id, body))
    }

    pub(crate) fn getlk(&self, through: Through, lock: FileLock) -> Result<FileLock> {
        let body = GetlkRequest {
            handle: U64::new(through.handle),
            lock,
        };
        self.call(Request::new(through.caller, through.node_id, body))
    }

    pub(crate) fn setlk(&self, through: Through, lock: FileLock, wait: LockWait) -> Result {
        let body = SetlkRequest {
            handle: U64::new(through.handle),
            lock,
            flags: U32::new(match wait {
                LockWait::Try => 0,
                LockWait::Block => setlk_flags::WAIT,
            }),
            reserved: U32::ZERO,
        };
        self.call(Request::new(through.caller, through.node_id, body))
    }
}
