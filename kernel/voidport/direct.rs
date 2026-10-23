// SPDX-License-Identifier: GPL-2.0

use kernel::bindings;
use kernel::error::to_result;
use kernel::prelude::*;
use kernel::sync::Arc;

use crate::buffer::Buffer;
use crate::connection::{ReadPages, ReadRange};
use crate::handle::handle_of;
use crate::helpers::NoFsScope;
use crate::node::session_and_id;
use crate::wire::Caller;

/// Reads into `to` from the position of `iocb`, and returns the bytes read.
/// An error after some bytes returns those bytes.
///
/// # Safety
///
/// `iocb` is a live request on a voidport file, and `to` is its destination,
/// whose pages the extraction holds.
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
    // SAFETY: the destination is live, and this task holds no lock.
    let buffer = Arc::new(unsafe { Buffer::take(to, length)? }, GFP_KERNEL)?;
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
    // SAFETY: the request and its destination are live. The destination still
    // has room for the bytes the read did not fill.
    unsafe {
        bindings::iov_iter_revert(to, buffer.len() - done);
        (*iocb).ki_pos += done as bindings::loff_t;
    }
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
