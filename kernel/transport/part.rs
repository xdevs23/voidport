// SPDX-License-Identifier: GPL-2.0
//! One part of the bytes that travel straight from or into the pages they lie
//! in: bytes inside one page of a folio or of the buffer a read or a write
//! was called with.
//!
//! A stream sends a part through a local mapping of the page that contains
//! it, and a descriptor chain lists that page.

use core::ops::ControlFlow;

use kernel::bindings;
use kernel::page::PAGE_SIZE;
use kernel::prelude::*;
use voidport_bindings::voidport_folio_page;

/// Where the bytes of a part lie.
#[derive(Clone, Copy)]
enum Place {
    /// From `offset` on in `page`, whose references the kernel counts.
    Page {
        page: *mut bindings::page,
        offset: usize,
    },
    /// From `offset` on in `page` of kernel memory, which may have no count
    /// of references, as a page of the slab allocator has none.
    Kernel {
        page: *mut bindings::page,
        offset: usize,
    },
    /// From the byte `offset` of `folio` on.
    Folio {
        folio: *mut bindings::folio,
        offset: usize,
    },
}

/// Bytes inside one page.
///
/// # Invariants
///
/// The page that contains the bytes is not freed while the part exists, and
/// the `len` bytes lie inside it.
#[derive(Clone, Copy)]
pub struct Part {
    place: Place,
    len: usize,
}

/// What a visit of parts does after one part: it goes on to the next one, or
/// it stops with a result.
pub type Step = ControlFlow<Result>;

/// The step after `result`: the visit goes on after a success, and stops with
/// an error.
pub fn step(result: Result) -> Step {
    match result {
        Ok(()) => ControlFlow::Continue(()),
        Err(error) => ControlFlow::Break(Err(error)),
    }
}

/// The result a visit of parts ended with: the one it stopped with, or a
/// success when it visited every part.
pub fn ended(step: Step) -> Result {
    match step {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(result) => result,
    }
}

/// The bytes in the first `count` parts that `parts` visits.
pub fn fitting(
    count: usize,
    parts: impl FnOnce(&mut dyn FnMut(Part) -> Step) -> Result,
) -> Result<usize> {
    let (mut taken, mut bytes) = (0, 0);
    parts(&mut |part| {
        if taken == count {
            return ControlFlow::Break(Ok(()));
        }
        taken += 1;
        bytes += part.len();
        ControlFlow::Continue(())
    })?;
    Ok(bytes)
}

/// Calls `each` with the first parts that `parts` visits, until they contain
/// `len` bytes, and stops at the first error.
pub fn for_first_bytes(
    len: usize,
    parts: impl FnOnce(&mut dyn FnMut(Part) -> Step) -> Result,
    mut each: impl FnMut(&Part) -> Result,
) -> Result {
    let mut left = len;
    parts(&mut |part| {
        if left == 0 {
            return ControlFlow::Break(Ok(()));
        }
        left = left.saturating_sub(part.len());
        step(each(&part))
    })
}

impl Part {
    /// The `len` bytes from `offset` on in `page`, whose references the
    /// kernel counts.
    ///
    /// # Safety
    ///
    /// `page` is not freed while the part exists, and `offset + len` is at
    /// most the size of a page.
    pub unsafe fn page(page: *mut bindings::page, offset: usize, len: usize) -> Self {
        Self {
            place: Place::Page { page, offset },
            len,
        }
    }

    /// The `len` bytes from `offset` on in `page` of kernel memory, which may
    /// have no count of references.
    ///
    /// # Safety
    ///
    /// As for [`Part::page`].
    pub unsafe fn kernel(page: *mut bindings::page, offset: usize, len: usize) -> Self {
        Self {
            place: Place::Kernel { page, offset },
            len,
        }
    }

    /// The `len` bytes from the byte `offset` of `folio` on.
    ///
    /// # Safety
    ///
    /// `folio` is not freed while the part exists, and the bytes lie inside
    /// one page of it.
    pub unsafe fn folio(folio: *mut bindings::folio, offset: usize, len: usize) -> Self {
        Self {
            place: Place::Folio { folio, offset },
            len,
        }
    }

    /// How many bytes the part contains.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the part contains no byte.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the kernel counts the references to the page that contains the
    /// part, so that a reference prevents freeing the page.
    pub fn counted(&self) -> bool {
        !matches!(self.place, Place::Kernel { .. })
    }

    /// The page the bytes lie in, and where in it they start.
    pub fn page_of(&self) -> (*mut bindings::page, usize) {
        match self.place {
            Place::Page { page, offset } | Place::Kernel { page, offset } => (page, offset),
            Place::Folio { folio, offset } => {
                let index = (offset / PAGE_SIZE) as c_ulong;
                // SAFETY: the folio is not freed while the part exists, and
                // the bytes lie inside the page of the folio with this index.
                (
                    unsafe { voidport_folio_page(folio, index) },
                    offset % PAGE_SIZE,
                )
            }
        }
    }

    /// Calls `visit` with the address of the bytes, mapped for the call, at
    /// which `len` bytes are valid.
    pub fn map<R>(&self, visit: impl FnOnce(*mut u8) -> R) -> R {
        let (page, offset) = self.page_of();
        // SAFETY: the page is not freed while the part exists. A local
        // mapping belongs to this task, remains valid while it sleeps, and
        // ends before the call returns. The bytes lie inside the page.
        unsafe {
            let map = bindings::kmap_local_page(page).cast::<u8>();
            let visited = visit(map.add(offset));
            bindings::kunmap_local(map.cast::<c_void>());
            visited
        }
    }
}
