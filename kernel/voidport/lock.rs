// SPDX-License-Identifier: GPL-2.0

use kernel::bindings;
use kernel::prelude::*;
use voidport_proto::ops::file::{lock_type, FileLock};
use voidport_session::owed;
use zerocopy::byteorder::little_endian::{U32, U64};

use crate::handle::handle_of;
use crate::helpers::{
    voidport_lock_conflict, voidport_lock_is_getlk, voidport_lock_read, NoFsScope,
};
use crate::node::{inode_mount, reserve_flush, session_and_id};
use crate::ops::{LockWait, Through};
use crate::vfs::{status, RecordLock};
use crate::wire::Caller;

const TYPES: [(u32, u32); 3] = [
    (bindings::F_RDLCK, lock_type::READ),
    (bindings::F_WRLCK, lock_type::WRITE),
    (bindings::F_UNLCK, lock_type::UNLOCK),
];

/// The last byte the kernel gives a lock that runs to the end of the file:
/// `OFFSET_MAX`, the largest `loff_t`. The wire spells it `u64::MAX`.
const END_OF_FILE: bindings::loff_t = bindings::loff_t::MAX;

/// A holder that is not a process of this kernel, as the kernel reports a
/// lock held on another machine.
const REMOTE_HOLDER: bindings::pid_t = -1;

pub(crate) unsafe extern "C" fn lock(
    file: *mut bindings::file,
    cmd: c_int,
    fl: *mut bindings::file_lock,
) -> c_int {
    let _scope = NoFsScope::enter();
    // SAFETY: the VFS passes a live file this filesystem opened and the lock
    // of the call.
    status(unsafe { record_lock(file, cmd, fl) })
}

/// # Safety
///
/// `file` is a live file this filesystem opened, and `fl` is the lock of the
/// call.
unsafe fn record_lock(
    file: *mut bindings::file,
    cmd: c_int,
    fl: *mut bindings::file_lock,
) -> Result {
    // No lock of this mount waits for a grant that arrives after the reply,
    // so none is to be cancelled.
    if u32::try_from(cmd) == Ok(bindings::F_CANCELLK) {
        return Ok(());
    }
    // SAFETY: the promises of the caller hold. The inode of a live file is
    // live.
    let (inode, handle, asked) = unsafe {
        (
            (*file).f_inode,
            handle_of(file).ok_or(EIO)?,
            voidport_lock_read(fl),
        )
    };
    // SAFETY: as above.
    let (session, node_id) = unsafe { session_and_id(inode) };
    // SAFETY: as above.
    let owner = unsafe { inode_mount(inode) }.lock_owner(asked.owner);
    let request = wire_lock(&asked, owner)?;
    let through = Through {
        caller: Caller::current(),
        node_id,
        handle,
    };
    // SAFETY: a test of the command number.
    if unsafe { voidport_lock_is_getlk(cmd) } {
        let conflict = conflict(&asked, session.getlk(through, request)?)?;
        // SAFETY: `fl` is the lock of the call.
        unsafe { voidport_lock_conflict(fl, conflict) };
        return Ok(());
    }
    // The wire has no grant that arrives after the reply, which lockd asks for.
    if asked.deferred_grant {
        return Err(crate::errno::enolck());
    }
    // The lock of an open file description ends with the Release of its
    // handle, and a lock of a process with the Flush of a close.
    if owed::setlk_leaves_lock(request.lock_type.get()) && asked.owner != file.cast() {
        // SAFETY: the inode of a live file is live and initialised.
        unsafe { reserve_flush(inode, through.caller, request.owner.get()) }?;
    }
    let wait = if asked.sleep {
        LockWait::Block
    } else {
        LockWait::Try
    };
    session.setlk(through, request, wait)
}

fn wire_lock(asked: &RecordLock, owner: u64) -> Result<FileLock> {
    let kind = TYPES
        .iter()
        .find(|(kernel, _)| *kernel == u32::from(asked.type_))
        .map(|&(_, wire)| wire)
        .ok_or(EINVAL)?;
    let end = match asked.end {
        END_OF_FILE => u64::MAX,
        end => u64::try_from(end).map_err(|_| EINVAL)?,
    };
    Ok(FileLock {
        start: U64::new(u64::try_from(asked.start).map_err(|_| EINVAL)?),
        end: U64::new(end),
        owner: U64::new(owner),
        pid: U32::new(u32::try_from(asked.pid).map_err(|_| EINVAL)?),
        lock_type: U32::new(kind),
    })
}

/// A reply with a lock type the wire does not define, or a range the kernel
/// cannot represent, fails with `EIO`.
fn conflict(asked: &RecordLock, found: FileLock) -> Result<RecordLock> {
    let kind = TYPES
        .iter()
        .find(|(_, wire)| *wire == found.lock_type.get())
        .and_then(|&(kernel, _)| u8::try_from(kernel).ok())
        .ok_or(EIO)?;
    let (start, end) = if u32::from(kind) == bindings::F_UNLCK {
        // The kernel reads only the type of a range that is free.
        (asked.start, asked.end)
    } else {
        let start = bindings::loff_t::try_from(found.start.get()).map_err(|_| EIO)?;
        let end = match found.end.get() {
            u64::MAX => END_OF_FILE,
            end => bindings::loff_t::try_from(end).map_err(|_| EIO)?,
        };
        if end < start {
            return Err(EIO);
        }
        (start, end)
    };
    Ok(RecordLock {
        start,
        end,
        pid: REMOTE_HOLDER,
        type_: kind,
        ..*asked
    })
}
