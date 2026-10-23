// SPDX-License-Identifier: GPL-2.0

use kernel::bindings;
use kernel::prelude::*;

use crate::handle::{attach, detach, handle_of, shared_handle, Handle};
use crate::helpers::{voidport_dir_emit, FatalSignalsOnly, Hold, Locked, NoFsScope};
use crate::node::{
    inode_mount, placed_locks, refresh_if_stale, resize, session_and_id, take_flush, write_back_all,
};
use crate::ops::{SyncScope, Through};
use crate::vfs::{length, status};
use crate::vtable::Table;
use crate::wire::Caller;

pub(crate) static FILE_FILE_OPS: Table<bindings::file_operations> =
    Table::new(bindings::file_operations {
        open: Some(open_file),
        release: Some(release),
        read_iter: Some(read_iter),
        splice_read: Some(splice_read),
        write_iter: Some(crate::write::write_iter),
        splice_write: Some(bindings::iter_file_splice_write),
        flush: Some(flush),
        fsync: Some(fsync),
        lock: Some(crate::lock::lock),
        mmap_prepare: Some(crate::writeback::mmap_prepare),
        llseek: Some(bindings::generic_file_llseek),
        ..pin_init::zeroed()
    });

pub(crate) static DIR_FILE_OPS: Table<bindings::file_operations> =
    Table::new(bindings::file_operations {
        open: Some(open),
        release: Some(release),
        iterate_shared: Some(iterate),
        fsync: Some(fsync),
        llseek: Some(bindings::generic_file_llseek),
        ..pin_init::zeroed()
    });

/// The server truncates the file at an open with `O_TRUNC`. That open
/// acquires the inode lock and the invalidate lock of the file exclusively,
/// from the writeback of its dirty folios until the page cache is cut, as a
/// size change does, so no store that a writeback sends after the truncation
/// brings back bytes of the file from before it.
unsafe extern "C" fn open_file(inode: *mut bindings::inode, file: *mut bindings::file) -> c_int {
    // SAFETY: the VFS passes the file being opened, before it checks
    // `O_DIRECT` against the mode of the file.
    unsafe { crate::vfs::allow_direct(file) };
    // SAFETY: as above.
    if unsafe { (*file).f_flags } & bindings::O_TRUNC == 0 {
        // SAFETY: the VFS passes a live inode of this filesystem and its file.
        return unsafe { open(inode, file) };
    }
    let _scope = NoFsScope::enter();
    // SAFETY: as above.
    status(unsafe { open_truncating(inode, file) })
}

/// # Safety
///
/// `inode` is a live, initialised regular file inode of this filesystem, and
/// `file` the file being opened with `O_TRUNC`.
unsafe fn open_truncating(inode: *mut bindings::inode, file: *mut bindings::file) -> Result {
    // SAFETY: the promises of the caller hold. The refresh acquires the
    // invalidate lock, so it comes first.
    unsafe { refresh_if_stale(inode, Caller::current()) }?;
    // SAFETY: as above.
    let _lock = unsafe { Locked::take(&raw mut (*inode).i_rwsem, Hold::Exclusive) }?;
    // SAFETY: as above.
    let _invalidate = unsafe { Locked::invalidate(inode, Hold::Exclusive) }?;
    // SAFETY: as above. No store dirties a folio while the invalidate lock is
    // held.
    unsafe { write_back_all(inode) }?;
    // SAFETY: as above.
    unsafe { open_handle(inode, file) }?;
    // SAFETY: as above, with both locks held exclusively. The truncation is
    // a write of the mount: the server set the modification time with it.
    unsafe { resize(inode, 0) };
    Ok(())
}

unsafe extern "C" fn read_iter(iocb: *mut bindings::kiocb, to: *mut bindings::iov_iter) -> isize {
    // SAFETY: the VFS passes a live request on a voidport file and its
    // destination.
    unsafe {
        if crate::direct::bypasses_cache((*iocb).ki_filp, crate::vfs::direct(iocb)) {
            length(crate::direct::read(iocb, to))
        } else {
            bindings::generic_file_read_iter(iocb, to)
        }
    }
}

/// A splice past the page cache reads through [`read_iter`] into pages that
/// it then adds to the pipe.
unsafe extern "C" fn splice_read(
    file: *mut bindings::file,
    position: *mut bindings::loff_t,
    pipe: *mut bindings::pipe_inode_info,
    len: usize,
    flags: c_uint,
) -> isize {
    // SAFETY: the VFS passes a live voidport file, the position in it and the
    // pipe that the splice fills.
    unsafe {
        let o_direct = (*file).f_flags & bindings::O_DIRECT != 0;
        if crate::direct::bypasses_cache(file, o_direct) {
            bindings::copy_splice_read(file, position, pipe, len, flags)
        } else {
            bindings::filemap_splice_read(file, position, pipe, len, flags)
        }
    }
}

/// Attributes past their lifetime are refreshed first, so a file the host
/// changed since the guest last looked drops its cached pages before the
/// reads that follow this open are read from them.
unsafe extern "C" fn open(inode: *mut bindings::inode, file: *mut bindings::file) -> c_int {
    let _scope = NoFsScope::enter();
    // SAFETY: the VFS passes a live, initialised inode of this filesystem and
    // the file being opened.
    status(unsafe {
        refresh_if_stale(inode, Caller::current()).and_then(|()| open_handle(inode, file))
    })
}

/// # Safety
///
/// `inode` is a live, initialised inode of this filesystem, and `file` the
/// file being opened.
unsafe fn open_handle(inode: *mut bindings::inode, file: *mut bindings::file) -> Result {
    // SAFETY: the promises of the caller hold.
    let ((session, node_id), flags) = unsafe { (session_and_id(inode), (*file).f_flags) };
    let id = session.open_handle(Caller::current(), node_id, flags)?;
    // SAFETY: as above.
    unsafe {
        attach(
            inode,
            file,
            Handle::of_file(inode_mount(inode), file, id, flags),
        )
    }
}

/// Closing the handle is not forgetting the node: the inode has its lookup
/// count, which eviction gives back separately.
///
/// The stores through a shared mapping of the file since its last flush go to
/// the server first, through the handles of the file that write in place, of
/// which this one is still one.
unsafe extern "C" fn release(inode: *mut bindings::inode, file: *mut bindings::file) -> c_int {
    // SAFETY: the VFS passes the file being released, of the live inode.
    unsafe { detach(inode, file) };
    0
}

/// An owner that never placed a record lock on the file through this mount
/// sends nothing.
///
/// The stores through a shared mapping of the file go to the server first,
/// and the first error of their writeback returns here.
unsafe extern "C" fn flush(file: *mut bindings::file, owner: bindings::fl_owner_t) -> c_int {
    let _scope = NoFsScope::enter();
    // SAFETY: the VFS passes a live file this filesystem opened.
    let (inode, handle) = unsafe { ((*file).f_inode, shared_handle(file)) };
    let Some(handle) = handle else {
        return EIO.to_errno();
    };
    // SAFETY: the inode of a live file is live.
    let written = unsafe { write_back_all(inode) };
    // SAFETY: the inode of a live file is live and initialised.
    let (session, node_id) = unsafe { session_and_id(inode) };
    // SAFETY: as above.
    let lock_owner = unsafe { inode_mount(inode) }.lock_owner(owner);
    // The server releases the record locks also after a failed writeback.
    // SAFETY: as above.
    let flushed = if unsafe { placed_locks(inode, lock_owner) } {
        let through = Through {
            caller: Caller::current(),
            node_id,
            handle: handle.id(),
        };
        // Only a fatal signal ends the Flush. When one does, or the process
        // dies, the cleanup worker sends the Flush the owner reserved.
        let sent = {
            let _signals = FatalSignalsOnly::enter();
            session.flush(through, lock_owner)
        };
        match sent {
            Err(error) if error == ERESTARTSYS => {
                // SAFETY: as above.
                if let Some(reserved) = unsafe { take_flush(inode, lock_owner) } {
                    session.flush_after_close(reserved, &handle);
                }
                Ok(())
            }
            sent => sent,
        }
    } else {
        Ok(())
    };
    status(written.and(flushed))
}

/// The stores through a shared mapping of the range go to the server first,
/// and the first error of a writeback since the file last saw one returns
/// instead.
unsafe extern "C" fn fsync(
    file: *mut bindings::file,
    start: bindings::loff_t,
    end: bindings::loff_t,
    datasync: c_int,
) -> c_int {
    let _scope = NoFsScope::enter();
    // SAFETY: the VFS passes a live file this filesystem opened.
    let written = unsafe { bindings::file_write_and_wait_range(file, start, end) };
    if written != 0 {
        return written;
    }
    // SAFETY: as above.
    let (inode, handle) = unsafe { ((*file).f_inode, handle_of(file)) };
    let Some(handle) = handle else {
        return EIO.to_errno();
    };
    // SAFETY: the inode of a live file is live and initialised.
    let (session, node_id) = unsafe { session_and_id(inode) };
    let through = Through {
        caller: Caller::current(),
        node_id,
        handle,
    };
    let scope = if datasync != 0 {
        SyncScope::DataOnly
    } else {
        SyncScope::Full
    };
    status(session.fsync(through, scope))
}

unsafe extern "C" fn iterate(file: *mut bindings::file, ctx: *mut bindings::dir_context) -> c_int {
    // SAFETY: the VFS passes a live directory file and context.
    status(unsafe { enumerate(file, ctx) })
}

/// # Safety
///
/// `file` is a live directory file this filesystem opened; `ctx` is live.
unsafe fn enumerate(file: *mut bindings::file, ctx: *mut bindings::dir_context) -> Result {
    // SAFETY: `file` and `ctx` are live; the dots are emitted first, which
    // moves `ctx->pos` past them.
    if !unsafe { crate::helpers::voidport_dir_emit_dots(file, ctx) } {
        return Ok(());
    }
    // SAFETY: `file` is live; its inode belongs to a live superblock and its
    // private data holds the directory's handle.
    let ((session, node_id), handle) =
        unsafe { (session_and_id((*file).f_inode), handle_of(file).ok_or(EIO)?) };
    let caller = Caller::current();
    // The dots occupy positions 0 and 1; the wire cookies are offset by two so
    // they never collide with them, and a resume reads the offset back off.
    // SAFETY: `ctx` is live.
    let start = unsafe { (*ctx).pos };
    let mut cookie = u64::try_from(start.saturating_sub(2)).map_err(|_| EINVAL)?;
    loop {
        if kernel::current!().signal_pending() {
            return Err(ERESTARTSYS);
        }
        // The session retains the complete reply for deferred discharge;
        // these copied display entries own no server references.
        let (batch, exhausted) = session.readdirplus(caller, node_id, handle, cookie)?;
        // An empty batch ends the listing only with the exhausted bit, below.
        // Without it the reply made no progress, which EIO reports as it does
        // for a cookie that does not advance.
        if batch.is_empty() && !exhausted {
            return Err(EIO);
        }
        for item in &batch {
            if kernel::current!().signal_pending() {
                return Err(ERESTARTSYS);
            }
            // A peer cookie must advance and fit the VFS position including
            // dot offsets. EIO reports non-progress; EOVERFLOW reports range.
            if item.next_cookie <= cookie {
                return Err(EIO);
            }
            let position = item.next_cookie.checked_add(2).ok_or(EOVERFLOW)?;
            let position = bindings::loff_t::try_from(position).map_err(|_| EOVERFLOW)?;
            let len = c_int::try_from(item.name.len()).map_err(|_| EOVERFLOW)?;
            // SAFETY: `ctx` is live; the name slice is valid for the call.
            let emitted = unsafe {
                voidport_dir_emit(
                    ctx,
                    item.name.as_ptr().cast(),
                    len,
                    item.ino,
                    item.entry_type as c_uint,
                )
            };
            if !emitted {
                return Ok(());
            }
            // SAFETY: `ctx` is live; advance the resume position past this
            // entry.
            unsafe { (*ctx).pos = position };
            cookie = item.next_cookie;
        }
        // The closing piece says the directory has nothing past this page, so
        // the enumeration ends here and not on a short batch.
        if exhausted {
            return Ok(());
        }
    }
}
