// SPDX-License-Identifier: GPL-2.0

use core::convert::Infallible;
use core::ops::ControlFlow;

use kernel::bindings;
use kernel::page::PAGE_SIZE;
use kernel::prelude::*;

use crate::helpers::voidport_iov_iter_extract_will_pin;
use crate::part::{ended, step, Part};
use crate::parts::within_pages;
use crate::wire::Source;

/// The extraction holds the pages of a program until the buffer is dropped, so
/// any task can map them, such as the reader of the connection that receives
/// the reply to a direct read.
pub(crate) struct Buffer {
    runs: KVec<Run>,
    len: usize,
}

// SAFETY: the pages of every run remain valid until the buffer is dropped, and
// any task may map them.
unsafe impl Send for Buffer {}
// SAFETY: as above. The bytes are written only by the one reader that a reply
// streams through.
unsafe impl Sync for Buffer {}

/// Pages of the buffer that follow each other: `len` bytes from `offset` in
/// the first page, which are the bytes from `start` on in the buffer.
struct Run {
    /// The array of `count` pages the extraction allocated.
    pages: *mut *mut bindings::page,
    count: usize,
    offset: usize,
    len: usize,
    start: usize,
    pinned: bool,
    /// Whether the pages receive the bytes of a read, which marks them dirty
    /// as they are released.
    dirty: bool,
}

impl Drop for Run {
    fn drop(&mut self) {
        // SAFETY: `pages` is the array the extraction allocated, or null, and
        // contains `count` pages, held by the extraction when `pinned`.
        unsafe {
            if self.pinned {
                bindings::unpin_user_pages_dirty_lock(
                    self.pages,
                    self.count as c_ulong,
                    self.dirty,
                );
            }
            bindings::kvfree(self.pages.cast::<c_void>());
        }
    }
}

impl Buffer {
    /// A fault after the first byte ends the buffer there, so the buffer is
    /// shorter than `length`.
    ///
    /// # Safety
    ///
    /// `iter` is the live iterator of a read or a write, and the caller holds
    /// no lock that a fault on its pages could need.
    pub(crate) unsafe fn take(iter: *mut bindings::iov_iter, length: usize) -> Result<Self> {
        // SAFETY: the iterator is live.
        let (pinned, dirty) = unsafe {
            (
                voidport_iov_iter_extract_will_pin(iter),
                !(*iter).data_source,
            )
        };
        let mut buffer = Self {
            runs: KVec::new(),
            len: 0,
        };
        while buffer.len < length {
            let mut pages = core::ptr::null_mut();
            let mut offset = 0;
            // SAFETY: the iterator is live, and the extraction allocates the
            // page array, which the run frees.
            let taken = unsafe {
                bindings::iov_iter_extract_pages(
                    iter,
                    &mut pages,
                    length - buffer.len,
                    c_uint::MAX,
                    0,
                    &mut offset,
                )
            };
            // The extraction may allocate the array even when it extracts
            // nothing.
            let mut run = Run {
                pages,
                count: 0,
                offset,
                len: 0,
                start: buffer.len,
                pinned,
                dirty,
            };
            match usize::try_from(taken) {
                Ok(0) => break,
                Ok(len) => {
                    run.len = len;
                    run.count = (offset + len).div_ceil(PAGE_SIZE);
                    buffer.runs.push(run, GFP_KERNEL)?;
                    buffer.len += len;
                }
                Err(_) if buffer.len > 0 => break,
                Err(_) => return Err(Error::from_errno(taken as c_int)),
            }
        }
        Ok(buffer)
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Calls `visit` with each part of the bytes `at..at + len` that lies
    /// in one page, in order, until it stops.
    pub(crate) fn parts<B>(
        &self,
        at: usize,
        len: usize,
        visit: &mut dyn FnMut(Part) -> ControlFlow<B>,
    ) -> ControlFlow<B> {
        let first = self.runs.partition_point(|run| run.start + run.len <= at);
        let mut skip = self.runs.get(first).map_or(0, |run| at - run.start);
        let mut left = len;
        for run in &self.runs[first..] {
            if left == 0 {
                break;
            }
            let from = run.offset + core::mem::take(&mut skip);
            let taken = (run.offset + run.len - from).min(left);
            for (position, len) in within_pages(from, taken, PAGE_SIZE) {
                // SAFETY: `position` lies in the run, whose array has a page
                // for every page it spans.
                let page = unsafe { *run.pages.add(position / PAGE_SIZE) };
                let offset = position % PAGE_SIZE;
                // SAFETY: the pages of the run remain valid until the buffer
                // is dropped, and the part stops at the end of its page. The
                // kernel counts the references of the extracted pages of a
                // program, and may not count those of a kernel iterator.
                let part = unsafe {
                    if run.pinned {
                        Part::page(page, offset, len)
                    } else {
                        Part::kernel(page, offset, len)
                    }
                };
                visit(part)?;
            }
            left -= taken;
        }
        ControlFlow::Continue(())
    }

    pub(crate) fn receive(&self, source: &impl Source, at: usize, len: usize) -> Result {
        ended(self.parts(at, len, &mut |part| {
            step(part.map(|bytes| {
                // SAFETY: `map` maps the part for the call, and only the
                // reader that the reply streams through writes it.
                let bytes = unsafe { core::slice::from_raw_parts_mut(bytes, part.len()) };
                source.receive_exact(bytes)
            }))
        }))
    }

    /// `destination` may lie in a page of the buffer itself.
    ///
    /// # Safety
    ///
    /// `destination` is valid for writes of `len` bytes.
    pub(crate) unsafe fn copy(&self, at: usize, destination: *mut u8, len: usize) {
        let mut done = 0;
        let copied = self.parts(at, len, &mut |part| {
            part.map(|bytes| {
                // SAFETY: `map` maps the part, and the caller promises the
                // room.
                unsafe { core::ptr::copy(bytes, destination.add(done), part.len()) }
            });
            done += part.len();
            ControlFlow::<Infallible>::Continue(())
        });
        match copied {
            ControlFlow::Continue(()) => {}
            ControlFlow::Break(never) => match never {},
        }
    }
}
