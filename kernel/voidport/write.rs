// SPDX-License-Identifier: GPL-2.0

//! The locks are acquired in this order: the inode lock, the invalidate lock
//! of the mapping, the send lock of the connection, a folio lock. A write
//! acquires no folio lock while it waits for the send lock. A task that holds
//! a folio lock of a file must hold the invalidate lock of that file before it
//! waits for the send lock, as a page cache fill holds it shared.

use core::ops::Range;

use kernel::bindings;
use kernel::error::to_result;
use kernel::page::{PAGE_SHIFT, PAGE_SIZE};
use kernel::prelude::*;
use voidport_session::cache::{self, CacheChange, Placement};
use voidport_session::write::{self, Next};

use crate::buffer::Buffer;
use crate::connection::Data;
use crate::diag::warn_limited;
use crate::folio::Folio;
use crate::handle::{file_handle, Handle};
use crate::helpers::{
    voidport_fatal_signal_pending, voidport_i_size_read, voidport_i_size_write,
    voidport_mapping_set_error, voidport_write_sync, Hold, Locked, NoFsScope,
};
use crate::node::{record_session_write, session_and_id};
use crate::ops::{Privileged, Through};
use crate::part::{ended, Part, Step};
use crate::session::Session;
use crate::vfs::length;
use crate::wire::Caller;

pub(crate) unsafe extern "C" fn write_iter(
    iocb: *mut bindings::kiocb,
    from: *mut bindings::iov_iter,
) -> isize {
    // SAFETY: the VFS passes a live request on a voidport file and its source.
    match unsafe { write(iocb, from) } {
        // SAFETY: as above. A write that asks for stable storage waits for it.
        Ok(written) if written > 0 => unsafe { voidport_write_sync(iocb, written) },
        written => length(written),
    }
}

/// Sends a write of `length` bytes with `send`, which sends the bytes from
/// the offset it is called with on and returns the reply, until
/// `write::next` ends the write, and returns how many bytes the server wrote.
pub(crate) fn send_until_written(
    length: u64,
    mut send: impl FnMut(u64) -> Result<u32>,
) -> Result<u64> {
    let mut next = write::start(length);
    loop {
        match next {
            Next::Send { from } => next = write::next(length, from, send(from)),
            Next::Return(written) => return Ok(written),
            Next::Fail(error) => return Err(error),
            Next::Overrun => return Err(EIO),
        }
    }
}

/// A write with `O_DIRECT` through a handle that does not append takes the
/// lock shared, and takes it again exclusively when the checks show that it
/// extends past the end of the file, since only that lock lets it change the
/// size.
///
/// # Safety
///
/// `iocb` is a live request on a voidport file, and `from` is its source.
unsafe fn write(iocb: *mut bindings::kiocb, from: *mut bindings::iov_iter) -> Result<isize> {
    let _scope = NoFsScope::enter();
    // SAFETY: the request is on a live file, whose inode lives as long.
    let (file, o_direct) = unsafe { ((*iocb).ki_filp, crate::vfs::direct(iocb)) };
    // SAFETY: as above.
    let (inode, handle, bypasses_cache) = unsafe {
        (
            (*file).f_inode,
            file_handle(file).ok_or(EIO)?,
            crate::direct::bypasses_cache(file, o_direct),
        )
    };
    let mut hold = if o_direct && !handle.appends() {
        Hold::Shared
    } else {
        Hold::Exclusive
    };
    loop {
        // SAFETY: as above.
        let _lock = unsafe { Locked::take(&raw mut (*inode).i_rwsem, hold)? };
        // SAFETY: the request and its source are live. The checks move a
        // write with `IOCB_APPEND` to the presented size and cut the source
        // at the limits of the file.
        let count = unsafe { bindings::generic_write_checks(iocb, from) };
        let length = usize::try_from(count).map_err(|_| Error::from_errno(count as c_int))?;
        if length == 0 {
            return Ok(0);
        }
        // SAFETY: the request and the inode are live.
        let (position, size) = unsafe { ((*iocb).ki_pos, voidport_i_size_read(inode)) };
        // The checks limit the end to the largest size of a file.
        if matches!(hold, Hold::Shared) && position + length as bindings::loff_t > size {
            hold = Hold::Exclusive;
            continue;
        }
        // SAFETY: the promises of the caller hold, and this task holds the
        // inode lock of the file, exclusively unless the write has `O_DIRECT`
        // and lies inside the file.
        return unsafe { write_locked(iocb, from, inode, handle, length, bypasses_cache) };
    }
}

/// # Safety
///
/// As [`write`], `handle` is the handle of the file, the checks of the write
/// have passed `length` bytes, `bypasses_cache` shows whether the write goes
/// past the page cache, and the caller has the lock of `inode`, the inode of
/// the file: shared only for a write with `O_DIRECT` inside the file.
unsafe fn write_locked(
    iocb: *mut bindings::kiocb,
    from: *mut bindings::iov_iter,
    inode: *mut bindings::inode,
    handle: &Handle,
    length: usize,
    bypasses_cache: bool,
) -> Result<isize> {
    // SAFETY: the request is live.
    let offset = u64::try_from(unsafe { (*iocb).ki_pos }).map_err(|_| EINVAL)?;
    // The server appends every write through an appending handle at its own
    // end of the file, whatever the position of the write, and the cache past
    // the presented end is dropped for it, also for a write that bypasses the
    // page cache.
    let placement = if handle.appends() {
        Placement::End
    } else if bypasses_cache {
        Placement::Direct { offset }
    } else {
        Placement::At { offset }
    };
    let direct = placement.is_direct();
    // SAFETY: `inode` is the live inode of a voidport file.
    let (session, node_id) = unsafe { session_and_id(inode) };
    let write = Write {
        session,
        through: Through {
            caller: Caller::current(),
            node_id,
            handle: handle.id(),
        },
        offset,
        placement,
        direct,
        // A writer without the file-mode privilege has the server clear the
        // setuid and setgid bits. The presented mode cannot show whether the
        // file has them: a mount may mask them.
        // SAFETY: a check of the credentials of the current task.
        privileged: if unsafe { bindings::capable(bindings::CAP_FSETID as c_int) } {
            Privileged::Keep
        } else {
            Privileged::Strip
        },
        // SAFETY: the source is live, and this task holds no lock that a
        // fault on its pages could need.
        source: unsafe { Buffer::take(from, length)? },
    };
    let outcome = (|| {
        if direct {
            // SAFETY: the request is live. Stores through a mapping of the
            // range are sent to the server before the write.
            to_result(unsafe { bindings::kiocb_write_and_wait(iocb, write.source.len()) })?;
        }
        let hold = if direct {
            Hold::Shared
        } else {
            Hold::Exclusive
        };
        // SAFETY: the inode is live.
        let _invalidate = unsafe { Locked::invalidate(inode, hold)? };
        // SAFETY: this task holds the invalidate lock, shared only for a
        // direct write.
        unsafe { write.perform(inode) }
    })();
    // A write sends at most the bytes of its source.
    let written = outcome.as_ref().map_or(0, |&written| written as usize);
    // SAFETY: the request and its source are live. The source still contains
    // the bytes the write did not send.
    unsafe {
        bindings::iov_iter_revert(from, write.source.len() - written);
        (*iocb).ki_pos += written as bindings::loff_t;
    }
    isize::try_from(outcome?).map_err(|_| EOVERFLOW)
}

struct Write<'a> {
    session: &'a Session,
    through: Through,
    /// The position of the write, which the server ignores for an append.
    offset: u64,
    placement: Placement,
    direct: bool,
    privileged: Privileged,
    source: Buffer,
}

impl Write<'_> {
    /// Sends the bytes until `write::next` ends the write, applies what the
    /// write changed to the cache of `inode`, and returns the bytes written.
    ///
    /// # Safety
    ///
    /// `inode` is the live inode of the write, and the caller holds its
    /// invalidate lock, shared only for a direct write.
    unsafe fn perform(&self, inode: *mut bindings::inode) -> Result<u64> {
        // SAFETY: the promises of the caller hold.
        let (mapping, size) = unsafe { ((*inode).i_mapping, voidport_i_size_read(inode)) };
        let size = u64::try_from(size).map_err(|_| EOVERFLOW)?;
        // A direct write sent the stores of its range before it acquired the
        // invalidate lock shared, under which stores go on.
        if !self.direct {
            // SAFETY: as above, and the invalidate lock is held exclusively.
            unsafe { self.write_back_stores(mapping, size) }?;
        }
        let outcome = send_until_written(self.source.len() as u64, |from| {
            let rest = Rest {
                source: &self.source,
                from: from as usize,
            };
            self.session
                .write(self.through, self.offset + from, &rest, self.privileged)
        });
        let written = *outcome.as_ref().unwrap_or(&0);
        if let Placement::At { offset } = self.placement {
            // SAFETY: as above, and the invalidate lock is held exclusively.
            unsafe { self.fill_cache(mapping, offset, written) };
        }
        let change = cache::after_write(self.placement, written, size);
        // SAFETY: the promises of the caller hold.
        unsafe {
            apply(inode, change, size, self.direct);
            record_session_write(inode);
        }
        outcome
    }

    /// Sends the stores through shared mappings into the pages of the write
    /// before it, so the write changes those bytes last and the pages it
    /// drops contain no store. No store marks a folio dirty while the caller
    /// holds the invalidate lock.
    ///
    /// # Safety
    ///
    /// `mapping` is the live mapping of the file of the write, presented as
    /// `size` bytes long, and the caller holds its invalidate lock
    /// exclusively.
    unsafe fn write_back_stores(&self, mapping: *mut bindings::address_space, size: u64) -> Result {
        // The pages an append drops start at the end of the file. The checks
        // of a write limit its end to the largest size of a file.
        let (start, end) = match self.placement {
            Placement::End => (size, bindings::loff_t::MAX),
            _ => (
                self.offset,
                (self.offset + self.source.len() as u64 - 1) as bindings::loff_t,
            ),
        };
        let start = bindings::loff_t::try_from(start).map_err(|_| EFBIG)?;
        // A writeback that fails leaves its error on the mapping, for fsync
        // and close.
        // SAFETY: the promises of the caller hold.
        unsafe {
            bindings::filemap_fdatawrite_range(mapping, start, end);
            bindings::filemap_fdatawait_range_keep_errors(mapping, start, end);
        }
        // A fatal signal ends a writeback with its folios still dirty, and
        // the write with it.
        // SAFETY: a read of the signals of the current task.
        if unsafe { voidport_fatal_signal_pending() } {
            return Err(ERESTARTSYS);
        }
        Ok(())
    }

    /// Copies the `written` bytes the server wrote from `offset` on into the
    /// page cache folios of their range that are uptodate or that the bytes
    /// cover whole. A folio is created only for a page the bytes cover whole:
    /// a new folio of a part of a page is read whole before it shows
    /// anything.
    ///
    /// # Safety
    ///
    /// `mapping` is the live mapping of the file of the write, and the caller
    /// holds its invalidate lock exclusively.
    unsafe fn fill_cache(&self, mapping: *mut bindings::address_space, offset: u64, written: u64) {
        let page = PAGE_SIZE as u64;
        let mut at = 0;
        while at < written {
            let position = offset + at;
            let left = written - at;
            let whole_page = position.is_multiple_of(page) && left >= page;
            // A page without a folio caches nothing that the write changed.
            // SAFETY: the promises of the caller hold.
            let Ok(folio) = (unsafe { Folio::locked(mapping, position, whole_page) }) else {
                at += (page - position % page).min(left);
                continue;
            };
            let extent = folio.extent();
            let step = (extent.end - position).min(left);
            let whole = position == extent.start && position + step == extent.end;
            if whole || folio.uptodate() {
                let mut copied = at as usize;
                let into = (position - extent.start) as usize;
                let filled = folio.each_page(into, step as usize, |bytes, len| {
                    // SAFETY: the folio is locked, and `each_page` maps the
                    // part for the call.
                    unsafe { self.source.copy(copied, bytes, len) };
                    copied += len;
                    Ok::<(), core::convert::Infallible>(())
                });
                match filled {
                    Ok(()) => {}
                    Err(never) => match never {},
                }
                folio.flush_dcache();
                if whole {
                    folio.mark_uptodate();
                }
            }
            at += step;
        }
    }
}

/// Drops the cached range that a write leaves wrong, and presents the size
/// it leaves when that differs from `size`, the size presented before.
///
/// # Safety
///
/// `inode` is a live voidport inode, and the caller holds its invalidate lock,
/// shared only for a `direct` write. The caller holds the inode lock
/// exclusively for a write that changes the size.
unsafe fn apply(inode: *mut bindings::inode, change: CacheChange, size: u64, direct: bool) {
    // SAFETY: the promises of the caller hold.
    let mapping = unsafe { (*inode).i_mapping };
    if let Some((start, end)) = whole_pages(change.drop) {
        if direct {
            // A direct write holds the invalidate lock shared, so pages of
            // the range may be filled and stored to while it is sent. The
            // invalidation sends a page that a store dirtied meanwhile
            // through `launder_folio`, after the write, before it drops the
            // page. When a fatal signal ends that writeback, the page remains
            // dirty for a later one, which is no failure of the write. Any
            // other failure leaves a page that may show the bytes from before
            // the write, such as a page that a program holds with
            // `pin_user_pages`: the error goes to the mapping, as the generic
            // direct I/O path records it, and the next reply with attributes
            // drops the cache of the file.
            //
            // SAFETY: the promises of the caller hold, and the indices are
            // those of the first and the last page, the last one past every
            // page for a range to the end of the file.
            let failed = unsafe {
                bindings::invalidate_inode_pages2_range(
                    mapping,
                    (start >> PAGE_SHIFT) as c_ulong,
                    (end >> PAGE_SHIFT) as c_ulong,
                )
            };
            if failed != 0 && failed != ERESTARTSYS.to_errno() {
                // SAFETY: as above.
                unsafe { voidport_mapping_set_error(mapping, EIO.to_errno()) };
                warn_limited!(Cache, "a direct write left cached pages it could not drop");
            }
        } else {
            // SAFETY: the promises of the caller hold.
            unsafe { bindings::truncate_pagecache_range(inode, start, end) };
        }
    }
    // The checks of a write limit its end to the largest size of a file.
    if change.size != size {
        if let Ok(size) = bindings::loff_t::try_from(change.size) {
            // SAFETY: as above.
            unsafe { voidport_i_size_write(inode, size) };
        }
    }
}

/// The first and the last byte of the whole pages that cover `range`, the end
/// being -1 for a range to the end of the file, or `None` when it is empty.
///
/// The folios of a voidport mapping are single pages, and the cache drops a
/// part of a page by filling it with zeros where the file has bytes.
fn whole_pages(range: Range<u64>) -> Option<(bindings::loff_t, bindings::loff_t)> {
    if range.is_empty() {
        return None;
    }
    let page = PAGE_SIZE as u64;
    let start = bindings::loff_t::try_from(range.start - range.start % page).ok()?;
    let end = range
        .end
        .checked_next_multiple_of(page)
        .and_then(|end| bindings::loff_t::try_from(end - 1).ok())
        .unwrap_or(-1);
    Some((start, end))
}

struct Rest<'a> {
    source: &'a Buffer,
    from: usize,
}

impl Data for Rest<'_> {
    fn len(&self) -> usize {
        self.source.len() - self.from
    }

    fn parts(&self, visit: &mut dyn FnMut(Part) -> Step) -> Result {
        ended(self.source.parts(self.from, self.len(), visit))
    }
}
