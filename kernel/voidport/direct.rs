// SPDX-License-Identifier: GPL-2.0

use kernel::bindings;
use kernel::error::to_result;
use kernel::prelude::*;
use kernel::sync::Arc;

use crate::buffer::Buffer;
use crate::connection::{ReadPages, ReadRange};
use crate::handle::handle_of;
use crate::helpers::{voidport_iov_iter_extract_will_pin, NoFsScope};
use crate::node::{inode_mount, session_and_id};
use crate::wire::Caller;

/// Whether a request on `file` goes past the page cache: the request asks for
/// it with `o_direct`, or the mount that contains the file has `direct_io`.
///
/// # Safety
///
/// `file` is a live voidport file.
pub(crate) unsafe fn bypasses_cache(file: *const bindings::file, o_direct: bool) -> bool {
    // SAFETY: the inode of a live voidport file belongs to a live voidport
    // superblock.
    o_direct || unsafe { inode_mount((*file).f_inode) }.direct_io()
}

/// Reads into `to` from the position of `iocb`, and returns the bytes read.
/// An error after some bytes returns those bytes.
///
/// A reply streams into the buffer of the read also after a fatal signal ended
/// the caller, which only pages held in memory allow. A destination whose pages the
/// extraction does not pin, such as the kernel iterator of a splice, is read
/// into a buffer of the module first.
///
/// # Safety
///
/// `iocb` is a live request on a voidport file, and `to` is its destination.
pub(crate) unsafe fn read(
    iocb: *mut bindings::kiocb,
    to: *mut bindings::iov_iter,
) -> Result<isize> {
    let _scope = NoFsScope::enter();
    // SAFETY: the destination is live.
    let length = unsafe { count_of(to) };
    if length == 0 {
        return Ok(0);
    }
    // SAFETY: the request is on a live voidport file, whose inode belongs to a
    // live voidport superblock.
    let (file, (session, node_id)) = unsafe {
        let file = (*iocb).ki_filp;
        (file, session_and_id((*file).f_inode))
    };
    // SAFETY: as above.
    let (handle, caller) = unsafe { (handle_of(file).ok_or(EIO)?, Caller::of_file(file)) };
    // SAFETY: as above.
    let offset = u64::try_from(unsafe { (*iocb).ki_pos }).map_err(|_| EINVAL)?;
    // SAFETY: the request is live.
    to_result(unsafe { bindings::kiocb_write_and_wait(iocb, length) })?;
    // SAFETY: the destination is live.
    let bounced = unsafe { !voidport_iov_iter_extract_will_pin(to) };
    let buffer = if bounced {
        Buffer::bounce(length)?
    } else {
        // SAFETY: the destination is live, and this task holds no lock.
        unsafe { Buffer::take(to, length)? }
    };
    let buffer = Arc::new(buffer, GFP_KERNEL)?;
    let mut done = 0;
    let failure = loop {
        if done == buffer.len() {
            break None;
        }
        let range = ReadRange::new(ReadPages::Buffer(buffer.clone()), done);
        let read = match session.read_into(caller, node_id, handle, offset + done as u64, range) {
            Ok(read) => read,
            Err(error) => break Some(error),
        };
        done += read.filled;
        if read.exhausted {
            break None;
        }
        // A reply that ends short without the end of the file made no
        // progress.
        if read.filled == 0 {
            break Some(EIO);
        }
    };
    let done = if bounced {
        // SAFETY: the destination is live, and the replies that filled the
        // bytes have ended.
        unsafe { buffer.copy_to_iter(done, to) }
    } else {
        // SAFETY: the destination is live, and still has room for the bytes
        // the read did not fill.
        unsafe { bindings::iov_iter_revert(to, buffer.len() - done) };
        done
    };
    // SAFETY: the request is live.
    unsafe { (*iocb).ki_pos += done as bindings::loff_t };
    match failure {
        Some(error) if done == 0 => Err(error),
        _ => isize::try_from(done).map_err(|_| EOVERFLOW),
    }
}

/// # Safety
///
/// `iter` is live for this access.
unsafe fn count_of(iter: *const bindings::iov_iter) -> usize {
    // SAFETY: the caller keeps the iterator live, and every kind of iterator
    // has its count in this member.
    unsafe { (*iter).__bindgen_anon_1.__bindgen_anon_1.as_ref().count }
}
