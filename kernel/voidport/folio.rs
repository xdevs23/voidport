// SPDX-License-Identifier: GPL-2.0

use core::ops::{ControlFlow, Range};

use kernel::bindings;
use kernel::error::from_err_ptr;
use kernel::page::{PAGE_SHIFT, PAGE_SIZE};
use kernel::prelude::*;

use crate::helpers::{
    voidport_flush_dcache_folio, voidport_folio_mark_uptodate, voidport_folio_pos,
    voidport_folio_put, voidport_folio_size, voidport_folio_test_uptodate, voidport_get_folio,
    voidport_kmap_local_folio, voidport_write_folio,
};
use crate::part::Part;
use crate::parts::within_pages;

/// A folio of a page cache, referenced until the value is dropped, and locked
/// by this task when `locked`.
pub(crate) struct Folio {
    folio: *mut bindings::folio,
    locked: bool,
}

impl Folio {
    /// # Safety
    ///
    /// `mapping` is live, and the folio is under writeback or locked by this
    /// task.
    pub(crate) unsafe fn cached(
        mapping: *mut bindings::address_space,
        position: u64,
    ) -> Result<Self> {
        // SAFETY: the promises of the caller hold. The lookup only takes a
        // reference.
        from_err_ptr(unsafe { voidport_get_folio(mapping, index_of(position)?) }).map(|folio| {
            Self {
                folio,
                locked: false,
            }
        })
    }

    /// The folio is created when it is absent and `create` is set.
    ///
    /// # Safety
    ///
    /// `mapping` is live, and the caller holds its invalidate lock.
    pub(crate) unsafe fn locked(
        mapping: *mut bindings::address_space,
        position: u64,
        create: bool,
    ) -> Result<Self> {
        // SAFETY: the promises of the caller hold.
        from_err_ptr(unsafe { voidport_write_folio(mapping, index_of(position)?, create) }).map(
            |folio| Self {
                folio,
                locked: true,
            },
        )
    }

    pub(crate) fn as_ptr(&self) -> *mut bindings::folio {
        self.folio
    }

    pub(crate) fn extent(&self) -> Range<u64> {
        // SAFETY: the folio is locked or under writeback while this value
        // exists.
        unsafe { extent(self.folio) }
    }

    /// Whether every byte of the folio shows the file. The folio is locked.
    pub(crate) fn uptodate(&self) -> bool {
        // SAFETY: the folio is referenced.
        unsafe { voidport_folio_test_uptodate(self.folio) }
    }

    /// Marks every byte of the folio as showing the file, after this task
    /// wrote all of them into the locked folio.
    pub(crate) fn mark_uptodate(&self) {
        // SAFETY: the folio is locked by this task, which wrote it whole.
        unsafe { voidport_folio_mark_uptodate(self.folio) };
    }

    pub(crate) fn each_page<E>(
        &self,
        offset: usize,
        len: usize,
        visit: impl FnMut(*mut u8, usize) -> core::result::Result<(), E>,
    ) -> core::result::Result<(), E> {
        // SAFETY: the folio remains in the page cache while this value
        // exists, and the parts lie within it.
        unsafe { each_page(self.folio, offset, len, visit) }
    }

    /// Makes the bytes this task wrote into the folio visible to the
    /// instruction cache, on architectures whose caches are not unified.
    pub(crate) fn flush_dcache(&self) {
        // SAFETY: the folio is referenced.
        unsafe { voidport_flush_dcache_folio(self.folio) };
    }

    pub(crate) fn parts<B>(
        &self,
        offset: usize,
        len: usize,
        visit: &mut dyn FnMut(Part) -> ControlFlow<B>,
    ) -> ControlFlow<B> {
        // SAFETY: the folio remains in the page cache while this value
        // exists, and a part does not outlive the visit.
        unsafe { folio_parts(self.folio, offset, len, visit) }
    }
}

/// Calls `visit` with each part of the bytes `offset..offset + len` of
/// `folio` that lies in one page, in order, until it stops.
///
/// # Safety
///
/// `folio` is not freed while a part that `visit` is given exists, and the
/// bytes lie within it.
pub(crate) unsafe fn folio_parts<B>(
    folio: *mut bindings::folio,
    offset: usize,
    len: usize,
    visit: &mut dyn FnMut(Part) -> ControlFlow<B>,
) -> ControlFlow<B> {
    within_pages(offset, len, PAGE_SIZE).try_for_each(|(position, len)| {
        // SAFETY: the caller promises that the folio is not freed while a
        // part exists and that the bytes lie within it, and the part lies
        // within one page of the folio.
        visit(unsafe { Part::folio(folio, position, len) })
    })
}

/// Calls `visit` with the address and the length of each part of the bytes
/// `offset..offset + len` of `folio` that lies in one page, mapped for the
/// call, and stops at the first error.
///
/// # Safety
///
/// `folio` remains in the page cache during the call, and the bytes lie
/// within it.
pub(crate) unsafe fn each_page<E>(
    folio: *mut bindings::folio,
    offset: usize,
    len: usize,
    mut visit: impl FnMut(*mut u8, usize) -> core::result::Result<(), E>,
) -> core::result::Result<(), E> {
    for (position, step) in within_pages(offset, len, PAGE_SIZE) {
        // SAFETY: the promises of the caller hold, and the part stops at the
        // mapped page boundary. A local mapping belongs to this task and
        // remains valid while it sleeps.
        let visited = unsafe {
            let map = voidport_kmap_local_folio(folio, position).cast::<u8>();
            let visited = visit(map, step);
            bindings::kunmap_local(map.cast::<c_void>());
            visited
        };
        visited?;
    }
    Ok(())
}

impl Drop for Folio {
    fn drop(&mut self) {
        // SAFETY: this value has a reference of the folio, and its lock when
        // `locked`.
        unsafe {
            if self.locked {
                bindings::folio_unlock(self.folio);
            }
            voidport_folio_put(self.folio);
        }
    }
}

/// # Safety
///
/// `folio` is a folio of a page cache that is locked or under writeback, so
/// its geometry is stable.
pub(crate) unsafe fn extent(folio: *mut bindings::folio) -> Range<u64> {
    // SAFETY: the promises of the caller hold, and a position in the page
    // cache is not negative.
    unsafe {
        let start = voidport_folio_pos(folio) as u64;
        start..start + voidport_folio_size(folio) as u64
    }
}

fn index_of(position: u64) -> Result<c_ulong> {
    c_ulong::try_from(position >> PAGE_SHIFT).map_err(|_| EFBIG)
}
