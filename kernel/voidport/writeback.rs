// SPDX-License-Identifier: GPL-2.0

//! A store marks its folio dirty under the invalidate lock of the file held
//! shared, so no folio turns dirty while a write or an invalidation holds it
//! exclusively. Writeback acquires no invalidate lock: a write sends the dirty
//! folios of its range under it. Writeback does not lock a folio while it
//! waits for the connection, and a folio under writeback remains in the page
//! cache, where the send looks it up.

use core::ops::{ControlFlow, Range};

use kernel::bindings;
use kernel::prelude::*;

use crate::connection::Data;
use crate::folio::{extent, Folio};
use crate::handle::{file_handle, Handle};
use crate::helpers::{
    voidport_i_size_read, voidport_mapping_set_error, FatalSignalsOnly, Hold, Locked,
};
use crate::node::{record_session_write, session_and_id, writers};
use crate::part::{Part, Step};
use crate::vfs::status;
use crate::vtable::Table;
use crate::write::send_until_written;

static FILE_VM_OPS: Table<bindings::vm_operations_struct> =
    Table::new(bindings::vm_operations_struct {
        fault: Some(bindings::filemap_fault),
        map_pages: Some(bindings::filemap_map_pages),
        page_mkwrite: Some(page_mkwrite),
        ..pin_init::zeroed()
    });

/// The server stores the access time, so the mapping changes no time of the
/// file.
pub(crate) unsafe extern "C" fn mmap_prepare(desc: *mut bindings::vm_area_desc) -> c_int {
    // SAFETY: the mapping code passes the live description of a new mapping.
    unsafe { (*desc).vm_ops = FILE_VM_OPS.get() };
    0
}

unsafe extern "C" fn page_mkwrite(vmf: *mut bindings::vm_fault) -> bindings::vm_fault_t {
    // SAFETY: the fault code passes a live fault in a mapping of a voidport
    // file, which the mapping has open.
    let file = unsafe { (*(*vmf).__bindgen_anon_1.vma).vm_file };
    // SAFETY: as above.
    if !unsafe { file_handle(file) }.is_some_and(Handle::writes_in_place) {
        return bindings::vm_fault_reason_VM_FAULT_SIGBUS;
    }
    // A fatal signal ends the wait for the lock, and the task with it.
    // SAFETY: as above. The inode of an open file lives as long.
    let Ok(_invalidate) = (unsafe { Locked::invalidate((*file).f_inode, Hold::Shared) }) else {
        return bindings::vm_fault_reason_VM_FAULT_SIGBUS;
    };
    // SAFETY: as above.
    unsafe { bindings::filemap_page_mkwrite(vmf) }
}

pub(crate) unsafe extern "C" fn writepages(
    mapping: *mut bindings::address_space,
    wbc: *mut bindings::writeback_control,
) -> c_int {
    // SAFETY: writeback passes a live mapping of a voidport inode.
    let size = unsafe { voidport_i_size_read((*mapping).host) } as u64;
    let mut run: Option<Range<u64>> = None;
    let mut error = 0;
    let mut folio = core::ptr::null_mut();
    loop {
        // SAFETY: the mapping and the control are live, and `folio` is null
        // or the folio the iteration returned last.
        folio = unsafe { bindings::writeback_iter(mapping, wbc, folio, &mut error) };
        if folio.is_null() {
            break;
        }
        error = 0;
        // SAFETY: the iteration returns the folio locked and no longer dirty.
        let extent = unsafe { extent(folio) };
        if extent.start >= size {
            // The truncation that moved the end of the file drops it.
            // SAFETY: as above.
            unsafe { bindings::folio_unlock(folio) };
            continue;
        }
        // SAFETY: as above. Writeback leaves the folio in the page cache.
        unsafe {
            bindings::__folio_start_writeback(folio, false);
            bindings::folio_unlock(folio);
        }
        let end = extent.end.min(size);
        match run.take() {
            // The count of bytes of a Write has 32 bits.
            Some(previous)
                if previous.end == extent.start && u32::try_from(end - previous.start).is_ok() =>
            {
                run = Some(previous.start..end);
            }
            previous => {
                if let Some(previous) = previous {
                    // SAFETY: the folios of the run are under writeback.
                    error = unsafe { send_run(mapping, wbc, previous) };
                }
                run = Some(extent.start..end);
            }
        }
    }
    // SAFETY: as above.
    let last = run.map_or(0, |run| unsafe { send_run(mapping, wbc, run) });
    if error == 0 {
        last
    } else {
        error
    }
}

/// Sends the bytes `run` of the folios under writeback, and ends their
/// writeback. A folio whose send a fatal signal ended is dirty again.
///
/// # Safety
///
/// `mapping` is a live mapping of a voidport inode, `wbc` is the control of
/// the writeback, and every folio of `run` is under writeback.
unsafe fn send_run(
    mapping: *mut bindings::address_space,
    wbc: *mut bindings::writeback_control,
    run: Range<u64>,
) -> c_int {
    // SAFETY: the promises of the caller hold.
    let sent = unsafe { write_back((*mapping).host, run.clone()) };
    let mut at = run.start;
    while at < run.end {
        // SAFETY: as above. Every folio of the run remains in the page cache
        // under writeback, so each is found.
        let Ok(folio) = (unsafe { Folio::cached(mapping, at) }) else {
            break;
        };
        // SAFETY: the folio is under writeback, which blocks truncation and
        // ends here, once.
        unsafe {
            if sent == Err(ERESTARTSYS) {
                bindings::folio_redirty_for_writepage(wbc, folio.as_ptr());
            }
            bindings::folio_end_writeback(folio.as_ptr());
        }
        at = folio.extent().end;
    }
    status(sent)
}

/// Sends a dirty folio before an invalidation drops it from the page cache.
/// A folio whose send a fatal signal ended remains, dirty, and fails the
/// invalidation.
///
/// The caller of an invalidation holds the invalidate lock of the file, so no
/// store marks another folio dirty meanwhile.
pub(crate) unsafe extern "C" fn launder_folio(folio: *mut bindings::folio) -> c_int {
    // SAFETY: the invalidation passes a locked folio of a voidport mapping.
    // The lock leaves it in the page cache while it is sent.
    unsafe {
        if !bindings::folio_clear_dirty_for_io(folio) {
            return 0;
        }
        let inode = (*bindings::folio_mapping(folio)).host;
        let size = voidport_i_size_read(inode) as u64;
        let extent = extent(folio);
        if extent.start >= size {
            return 0;
        }
        match write_back(inode, extent.start..extent.end.min(size)) {
            Err(error) if error == ERESTARTSYS => {
                bindings::folio_mark_dirty(folio);
                error.to_errno()
            }
            _ => 0,
        }
    }
}

/// Sends the bytes `range` of the file of `inode` from its folios, through a
/// handle of the file that writes in place, until `write::next` ends the
/// write. An error other than a fatal signal goes to the mapping.
///
/// # Safety
///
/// `inode` is a live voidport inode, and every folio of `range` remains in its
/// page cache: it is under writeback, or locked by this task.
unsafe fn write_back(inode: *mut bindings::inode, range: Range<u64>) -> Result {
    let _signals = FatalSignalsOnly::enter();
    // SAFETY: the promises of the caller hold.
    let (mapping, writer) = unsafe { ((*inode).i_mapping, writers(inode).first()) };
    let sent = match writer {
        // SAFETY: as above.
        Some(writer) => unsafe { send_through(&writer, inode, range) },
        // A store outlived every handle that writes in place, as one into
        // pages that a program holds with `pin_user_pages` does.
        None => Err(EIO),
    };
    match sent {
        // SAFETY: the mapping of a live inode is live.
        Err(error) if error != ERESTARTSYS => unsafe {
            voidport_mapping_set_error(mapping, error.to_errno())
        },
        _ => {}
    }
    sent
}

/// # Safety
///
/// As [`write_back`].
unsafe fn send_through(writer: &Handle, inode: *mut bindings::inode, range: Range<u64>) -> Result {
    // SAFETY: the promises of the caller hold.
    let (mapping, (_, node_id)) = unsafe { ((*inode).i_mapping, session_and_id(inode)) };
    let length = range.end - range.start;
    // The errno of the last reply that failed, for a write that stops short.
    let mut failure = EIO;
    let sent = send_until_written(length, |from| {
        let rest = Folios {
            mapping,
            range: range.start + from..range.end,
        };
        writer
            .write(node_id, rest.range.start, &rest)
            .inspect_err(|&error| failure = error)
    });
    // SAFETY: as above.
    unsafe { record_session_write(inode) };
    match sent {
        Ok(written) if written == length => Ok(()),
        Ok(_) => Err(failure),
        Err(error) => Err(error),
    }
}

struct Folios {
    mapping: *mut bindings::address_space,
    range: Range<u64>,
}

impl Data for Folios {
    fn len(&self) -> usize {
        // A run fits the 32-bit count of a Write.
        (self.range.end - self.range.start) as usize
    }

    fn parts(&self, visit: &mut dyn FnMut(Part) -> Step) -> Result {
        let mut at = self.range.start;
        while at < self.range.end {
            // SAFETY: every folio of the range remains in the page cache under
            // writeback.
            let folio = unsafe { Folio::cached(self.mapping, at) }?;
            let extent = folio.extent();
            let end = extent.end.min(self.range.end);
            let offset = (at - extent.start) as usize;
            if let ControlFlow::Break(result) = folio.parts(offset, (end - at) as usize, visit) {
                return result;
            }
            at = end;
        }
        Ok(())
    }
}
