// SPDX-License-Identifier: GPL-2.0

use core::convert::Infallible;
use core::ops::ControlFlow;

use kernel::bindings;
use kernel::prelude::*;

use voidport_proto::piece::Closing;

use crate::connection::{ReadPages, ReadRange};
use crate::folio::{each_page, folio_parts};
use crate::helpers::{
    voidport_flush_dcache_folio, voidport_folio_pos, voidport_folio_size, voidport_readahead_folio,
    NoFsScope,
};
use crate::node::session_of;
use crate::part::Part;
use crate::session::handed;
use crate::vtable::Table;
use crate::wire::{Caller, Source};

pub(crate) static DATA_AOPS: Table<bindings::address_space_operations> =
    Table::new(bindings::address_space_operations {
        read_folio: Some(read_folio),
        readahead: Some(readahead),
        dirty_folio: Some(bindings::filemap_dirty_folio),
        writepages: Some(crate::writeback::writepages),
        launder_folio: Some(crate::writeback::launder_folio),
        migrate_folio: Some(bindings::filemap_migrate_folio),
        ..pin_init::zeroed()
    });

enum Unfilled {
    /// The read failed; the folio is still locked and its read is the
    /// caller's to end.
    Failed(Error),
    /// The caller left while the reply was streaming into the folio; the
    /// reader ends the read.
    Handed,
}

impl From<Error> for Unfilled {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

unsafe extern "C" fn read_folio(file: *mut bindings::file, folio: *mut bindings::folio) -> c_int {
    // SAFETY: the read path passes a live folio locked for us, and a file that
    // authorizes the read.
    match unsafe { fill(file, folio) } {
        // A handed folio is ended by the reader, as an asynchronous read is.
        Ok(()) | Err(Unfilled::Handed) => 0,
        Err(Unfilled::Failed(error)) => {
            // SAFETY: `folio` is the locked folio the caller handed us; ending
            // its read unlocks it and reports the failure.
            unsafe { bindings::folio_end_read(folio, false) };
            error.to_errno()
        }
    }
}

unsafe extern "C" fn readahead(rac: *mut bindings::readahead_control) {
    // SAFETY: the readahead path passes a live control block; its file
    // authorizes the reads, and each folio it yields is locked for us.
    let file = unsafe { (*rac).file };
    let mut failed = false;
    loop {
        // SAFETY: `rac` is live; `readahead_folio` yields the next locked
        // folio or null.
        let folio = unsafe { voidport_readahead_folio(rac) };
        if folio.is_null() {
            break;
        }
        if !failed {
            // SAFETY: `folio` is the locked folio just yielded; `file` authorizes.
            match unsafe { fill(file, folio) } {
                Ok(()) => continue,
                // The reader ends a handed folio; the rest of the batch is not
                // read by a caller that has left.
                Err(Unfilled::Handed) => {
                    failed = true;
                    continue;
                }
                Err(Unfilled::Failed(_)) => failed = true,
            }
        }
        // No fill error promises that another wire attempt can succeed.
        // Drain this batch without restarting the peer's stall window for
        // each folio. A later synchronous read can retry independently.
        // SAFETY: a failed fill leaves its folio locked, and remaining
        // folios have not been filled. End each failed read exactly once.
        unsafe { bindings::folio_end_read(folio, false) };
    }
}

/// # Safety
///
/// `folio` must be a locked folio of a voidport inode's mapping; `file`, if
/// non-null, must be a live file open on that inode.
unsafe fn fill(
    file: *mut bindings::file,
    folio: *mut bindings::folio,
) -> core::result::Result<(), Unfilled> {
    if file.is_null() {
        return Err(EIO.into());
    }
    // SAFETY: `file` is live; its inode is the folio's, and its private data
    // holds the wire handle the read needs.
    let (inode, handle, caller) = unsafe {
        let inode = (*file).f_inode;
        let handle = crate::handle::handle_of(file).ok_or(EIO)?;
        (inode, handle, Caller::of_file(file))
    };
    // SAFETY: the inode belongs to a live voidport superblock.
    let session = unsafe { session_of((*inode).i_sb) };
    // SAFETY: the inode is live for this call.
    let node_id = unsafe { crate::node::id_of(inode) };
    // SAFETY: `folio` is live and locked, so its geometry is stable.
    let pos = unsafe { voidport_folio_pos(folio) };
    // SAFETY: as above.
    let size = unsafe { voidport_folio_size(folio) };
    let pos = u64::try_from(pos).map_err(|_| EOVERFLOW)?;
    let _scope = NoFsScope::enter();
    // SAFETY: the folio is locked by this caller until its read ends, and
    // `size` is its byte length.
    let pages = ReadPages::Folio(unsafe { FolioPages::new(folio, size) });
    let mut done = 0usize;
    while done < size {
        let offset = pos
            .checked_add(u64::try_from(done).map_err(|_| EOVERFLOW)?)
            .ok_or(EOVERFLOW)?;
        let range = ReadRange::new(pages.clone(), done);
        let read = match session.read_into(caller, node_id, handle, offset, range) {
            Ok(read) => read,
            Err(error) if error == handed() => return Err(Unfilled::Handed),
            Err(error) => return Err(error.into()),
        };
        if read.filled == 0 && !read.exhausted {
            return Err(EIO.into());
        }
        done += read.filled;
        if read.exhausted {
            // SAFETY: only bytes beyond the end the reply reported are zeroed.
            unsafe { zero_folio(folio, done, size - done) };
            break;
        }
    }
    // SAFETY: the folio's data pages were just written on architectures whose
    // instruction and data caches are not unified.
    unsafe { voidport_flush_dcache_folio(folio) };
    // SAFETY: `folio` is the locked folio; the read succeeded, so mark it
    // uptodate and unlock it.
    unsafe { bindings::folio_end_read(folio, true) };
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Read {
    pub(crate) filled: usize,
    pub(crate) exhausted: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct FolioPages {
    folio: *mut bindings::folio,
    size: usize,
}

// SAFETY: the folio is locked for the whole time a range of it is in flight,
// by the caller or, once handed, by the reader that ends its read; only the
// one that holds the range writes it.
unsafe impl Send for FolioPages {}
// SAFETY: as above; the folio is never written through a shared reference.
unsafe impl Sync for FolioPages {}

impl FolioPages {
    /// # Safety
    ///
    /// `folio` must be locked for as long as a range of it is in flight, and
    /// `size` must be its byte length.
    pub(crate) unsafe fn new(folio: *mut bindings::folio, size: usize) -> Self {
        Self { folio, size }
    }

    pub(crate) fn len(&self) -> usize {
        self.size
    }

    /// The bytes lie within the folio.
    pub(crate) fn receive(&mut self, source: &impl Source, at: usize, len: usize) -> Result {
        // SAFETY: the folio is locked and handed to this reader, and the
        // caller checked that the bytes lie within it. `each_page` maps each
        // part for the call.
        unsafe {
            each_page(self.folio, at, len, |map, step| {
                source.receive_exact(core::slice::from_raw_parts_mut(map, step))
            })
        }
    }

    /// The bytes lie within the folio.
    pub(crate) fn parts<B>(
        &self,
        at: usize,
        len: usize,
        visit: &mut dyn FnMut(Part) -> ControlFlow<B>,
    ) -> ControlFlow<B> {
        // SAFETY: the folio is locked while a range of it is in flight, and
        // a part does not outlive the visit.
        unsafe { folio_parts(self.folio, at, len, visit) }
    }

    /// `closing` is `None` when the connection ended the read. The folio is
    /// uptodate when every byte of it arrived, or when the file ended inside it
    /// and the rest is zero-filled.
    pub(crate) fn complete(self, at: usize, closing: Option<Closing>) {
        let whole = match closing {
            Some(closing) if closing.status == 0 && closing.exhausted => {
                // SAFETY: the folio is locked, handed to this reader, and the
                // range past the end of the file lies within it.
                unsafe { zero_folio(self.folio, at, self.size - at) };
                true
            }
            Some(closing) => closing.status == 0 && at == self.size,
            None => false,
        };
        if whole {
            // SAFETY: the folio's pages were written on architectures whose
            // instruction and data caches are not unified.
            unsafe { voidport_flush_dcache_folio(self.folio) };
        }
        // SAFETY: the folio is locked and this reader is the one that ends
        // its read, exactly once.
        unsafe { bindings::folio_end_read(self.folio, whole) };
    }
}

/// # Safety
///
/// `folio` must be locked and `offset..offset + size` within its byte length.
unsafe fn zero_folio(folio: *mut bindings::folio, offset: usize, size: usize) {
    // SAFETY: the promises of the caller hold, and `each_page` maps each part
    // for the call.
    let Ok(()) = unsafe {
        each_page(folio, offset, size, |map, step| {
            core::ptr::write_bytes(map, 0, step);
            Ok::<(), Infallible>(())
        })
    };
}
