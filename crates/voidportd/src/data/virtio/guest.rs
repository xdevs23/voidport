//! The two host calls that move file data between a descriptor and guest
//! memory are `unsafe`, because no safe interface does that without a copy.
//! The safe forms tried were `preadv` and `pwritev2` of `rustix`, which take
//! Rust slices, and a Rust slice over memory that another party may change at
//! any moment breaks the guarantees a slice gives; and the file transfers of
//! `vm-memory`, which call `read` and `write` at the offset of the file
//! description, which concurrent requests of one file cannot share. Both calls
//! are confined behind [`Chain::read_file`] and [`Chain::write_file`].

use std::ops::Range;
use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use rustix::io::{Errno, ReadWriteFlags};
use virtio_queue::DescriptorChain;
use vm_memory::{
    Address as _, Bytes as _, GuestAddress, GuestMemoryBackend as _, GuestMemoryMmap,
    GuestMemoryResult, VolatileSlice,
};

use super::ring::Started;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Area {
    start: GuestAddress,
    len: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Areas(Vec<Area>);

impl Areas {
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.0.iter().map(|area| area.len).sum()
    }

    #[must_use]
    pub(crate) fn slice(&self, start: usize, len: usize) -> Self {
        let mut skip = start;
        let mut left = len;
        let mut slice = Vec::new();
        for area in &self.0 {
            if left == 0 {
                break;
            }
            if skip >= area.len {
                skip -= area.len;
                continue;
            }
            let covered = (area.len - skip).min(left);
            slice.push(Area {
                start: area.start.unchecked_add(skip as u64),
                len: covered,
            });
            left -= covered;
            skip = 0;
        }
        Self(slice)
    }

    #[must_use]
    pub(crate) fn starting_at(&self, start: usize) -> Self {
        self.slice(start, usize::MAX)
    }

    fn push(&mut self, start: GuestAddress, len: usize) {
        if len > 0 {
            self.0.push(Area { start, len });
        }
    }
}

/// A chain refers to the memory it was pulled from, so a mapping the frontend
/// replaces remains mapped until the last chain in it has finished.
#[derive(Debug, Default)]
pub(super) struct Mapped(Mutex<Arc<GuestMemoryMmap>>);

impl Mapped {
    pub(super) fn get(&self) -> Arc<GuestMemoryMmap> {
        Arc::clone(&self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    pub(super) fn replace(&self, memory: GuestMemoryMmap) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(memory);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Unreached {
    #[error("the queue of the chain has stopped")]
    Stopped,
    #[error("the chain lists memory outside the guest memory")]
    Outside,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failed {
    Host(Errno),
    Guest(Unreached),
}

struct Vector<G> {
    pointers: Vec<G>,
    iovecs: Vec<libc::iovec>,
}

impl<G> Vector<G> {
    fn len(&self) -> usize {
        self.iovecs.iter().map(|iovec| iovec.iov_len).sum()
    }

    fn count(&self) -> libc::c_int {
        libc::c_int::try_from(self.iovecs.len()).expect("a vector has at most UIO_MAXIOV stretches")
    }
}

/// Dropping it puts it back on its queue with the number of bytes written into
/// it once [`Self::keep`] has marked them as final, and with none otherwise.
#[derive(Debug)]
pub(crate) struct Chain {
    started: Arc<Started>,
    memory: Arc<GuestMemoryMmap>,
    head: u16,
    readable: Areas,
    writable: Areas,
    written: AtomicUsize,
    kept: AtomicBool,
}

impl Chain {
    pub(super) fn new(
        started: Arc<Started>,
        memory: Arc<GuestMemoryMmap>,
        chain: DescriptorChain<Arc<GuestMemoryMmap>>,
    ) -> Self {
        let head = chain.head_index();
        let mut readable = Areas::default();
        let mut writable = Areas::default();
        for descriptor in chain {
            let part = if descriptor.is_write_only() {
                &mut writable
            } else {
                &mut readable
            };
            part.push(descriptor.addr(), descriptor.len() as usize);
        }
        Self {
            started,
            memory,
            head,
            readable,
            writable,
            written: AtomicUsize::new(0),
            kept: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub(crate) fn readable(&self) -> &Areas {
        &self.readable
    }

    #[must_use]
    pub(crate) fn writable(&self) -> &Areas {
        &self.writable
    }

    #[must_use]
    pub(crate) fn accessible(&self) -> bool {
        self.readable
            .0
            .iter()
            .chain(&self.writable.0)
            .all(|area| self.memory.check_range(area.start, area.len))
    }

    #[must_use]
    pub(crate) fn fits_one_call(&self, areas: &Areas) -> bool {
        let slices: usize = areas
            .0
            .iter()
            .map(|area| self.memory.get_slices(area.start, area.len).count())
            .sum();
        slices <= vector_max()
    }

    pub(crate) fn keep(&self) {
        self.kept.store(true, Ordering::Release);
    }

    pub(crate) fn copy_out(&self, areas: &Areas, into: &mut [u8]) -> Result<(), Unreached> {
        self.each_stretch(areas, into.len(), |area, range| {
            self.memory.read_slice(&mut into[range], area.start)
        })
    }

    pub(crate) fn copy_in(&self, areas: &Areas, bytes: &[u8]) -> Result<(), Unreached> {
        self.each_stretch(areas, bytes.len(), |area, range| {
            let len = range.len();
            self.memory.write_slice(&bytes[range], area.start)?;
            self.written.fetch_add(len, Ordering::AcqRel);
            Ok(())
        })
    }

    fn each_stretch(
        &self,
        areas: &Areas,
        len: usize,
        mut visit: impl FnMut(Area, Range<usize>) -> GuestMemoryResult<()>,
    ) -> Result<(), Unreached> {
        let _open = self.started.access().ok_or(Unreached::Stopped)?;
        let mut at = 0;
        for area in areas.slice(0, len).0 {
            visit(area, at..at + area.len).map_err(|_| Unreached::Outside)?;
            at += area.len;
        }
        if at == len {
            Ok(())
        } else {
            Err(Unreached::Outside)
        }
    }

    /// One call covers as many stretches as the kernel accepts in one vector,
    /// `UIO_MAXIOV`, so a vector over more stretches has fewer bytes than
    /// `areas`.
    fn vector<G>(
        &self,
        areas: &Areas,
        map: impl Fn(&VolatileSlice<'_, ()>) -> (G, libc::iovec),
    ) -> Result<Vector<G>, Unreached> {
        let mut vector = Vector {
            pointers: Vec::new(),
            iovecs: Vec::new(),
        };
        for area in &areas.0 {
            for slice in self.memory.get_slices(area.start, area.len) {
                if vector.iovecs.len() == vector_max() {
                    return Ok(vector);
                }
                let (pointer, iovec) = map(&slice.map_err(|_| Unreached::Outside)?);
                vector.pointers.push(pointer);
                vector.iovecs.push(iovec);
            }
        }
        Ok(vector)
    }

    /// Returns how many bytes it read and how many the call asked for, which is
    /// fewer than `areas` has when it has more stretches than one call covers.
    pub(crate) fn read_file(
        &self,
        fd: BorrowedFd<'_>,
        offset: u64,
        areas: &Areas,
    ) -> Result<(usize, usize), Failed> {
        let _open = self
            .started
            .access()
            .ok_or(Failed::Guest(Unreached::Stopped))?;
        let vector = self
            .vector(areas, |slice| {
                let pointer = slice.ptr_guard_mut();
                let iovec = libc::iovec {
                    iov_base: pointer.as_ptr().cast(),
                    iov_len: pointer.len(),
                };
                (pointer, iovec)
            })
            .map_err(Failed::Guest)?;
        let offset = libc::off_t::try_from(offset).map_err(|_| Failed::Host(Errno::INVAL))?;
        // SAFETY: the call is unavoidable, since no safe binding reads into
        // memory another party shares; the safe alternatives are listed in the
        // module documentation. `fd` is an open descriptor for the length of
        // the call, as `BorrowedFd` guarantees. Each element of
        // `vector.iovecs` gives one slice of guest memory, valid for writes of
        // its length: the slices come from the mapping in `self.memory`,
        // which this chain refers to until it is dropped, and the `PtrGuard`
        // values in `vector`, which outlive the call, leave each slice mapped.
        // The count is the length of `vector.iovecs`. The kernel writes only
        // within those slices, and the bytes it writes are guest memory, which
        // no Rust reference of this process covers.
        let read = unsafe {
            libc::preadv(
                fd.as_raw_fd(),
                vector.iovecs.as_ptr(),
                vector.count(),
                offset,
            )
        };
        let asked = vector.len();
        drop(vector);
        let read = usize::try_from(read).map_err(|_| Failed::Host(last_errno()))?;
        self.written.fetch_add(read, Ordering::AcqRel);
        Ok((read, asked))
    }

    /// Returns how many bytes it wrote and how many the call offered, which is
    /// fewer than `areas` has as for [`Self::read_file`].
    pub(crate) fn write_file(
        &self,
        fd: BorrowedFd<'_>,
        offset: u64,
        areas: &Areas,
        flags: ReadWriteFlags,
    ) -> Result<(usize, usize), Failed> {
        let _open = self
            .started
            .access()
            .ok_or(Failed::Guest(Unreached::Stopped))?;
        let vector = self
            .vector(areas, |slice| {
                let pointer = slice.ptr_guard();
                let iovec = libc::iovec {
                    iov_base: pointer.as_ptr().cast_mut().cast(),
                    iov_len: pointer.len(),
                };
                (pointer, iovec)
            })
            .map_err(Failed::Guest)?;
        let offset = libc::off_t::try_from(offset).map_err(|_| Failed::Host(Errno::INVAL))?;
        let flags = libc::c_int::try_from(flags.bits()).map_err(|_| Failed::Host(Errno::INVAL))?;
        // SAFETY: the call is unavoidable, since no safe binding writes from
        // memory another party shares; the safe alternatives are listed in the
        // module documentation. `fd` is an open descriptor for the length of
        // the call, as `BorrowedFd` guarantees. Each element of
        // `vector.iovecs` gives one slice of guest memory, valid for reads of
        // its length: the slices come from the mapping in `self.memory`,
        // which this chain refers to until it is dropped, and the `PtrGuard`
        // values in `vector`, which outlive the call, leave each slice mapped.
        // The count is the length of `vector.iovecs`. The kernel only reads the
        // slices, so the pointer made mutable for the type of `iovec` is never
        // written through. `flags` contains only the bits of a
        // `ReadWriteFlags`, which the kernel takes for this call.
        let written = unsafe {
            libc::pwritev2(
                fd.as_raw_fd(),
                vector.iovecs.as_ptr(),
                vector.count(),
                offset,
                flags,
            )
        };
        let offered = vector.len();
        drop(vector);
        let written = usize::try_from(written).map_err(|_| Failed::Host(last_errno()))?;
        Ok((written, offered))
    }
}

impl Drop for Chain {
    fn drop(&mut self) {
        let written = if self.kept.load(Ordering::Acquire) {
            u32::try_from(self.written.load(Ordering::Acquire)).unwrap_or(u32::MAX)
        } else {
            0
        };
        self.started.finish(&self.memory, self.head, written);
    }
}

fn last_errno() -> Errno {
    Errno::from_raw_os_error(
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    )
}

fn vector_max() -> usize {
    usize::try_from(libc::UIO_MAXIOV).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn areas(stretches: &[(u64, usize)]) -> Areas {
        let mut areas = Areas::default();
        for &(start, len) in stretches {
            areas.push(GuestAddress(start), len);
        }
        areas
    }

    #[test]
    fn a_slice_of_a_part_cuts_its_stretches_where_it_starts_and_ends() {
        let part = areas(&[(0x1000, 16), (0x8000, 0), (0x4000, 8), (0x9000, 32)]);
        assert_eq!(part.len(), 56);
        assert_eq!(part.slice(4, 16), areas(&[(0x1004, 12), (0x4000, 4)]));
        assert_eq!(part.slice(16, 8), areas(&[(0x4000, 8)]));
        assert_eq!(part.starting_at(20), areas(&[(0x4004, 4), (0x9000, 32)]));
        assert_eq!(part.slice(50, 100), areas(&[(0x901a, 6)]));
        assert_eq!(part.slice(56, 1), Areas::default());
        assert_eq!(part.slice(0, 0), Areas::default());
    }
}
