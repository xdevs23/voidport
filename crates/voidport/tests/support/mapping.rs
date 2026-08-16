//! A shared file mapping, for the proofs that `mmap` works through a mount.
//!
//! # Why this module has `unsafe`
//!
//! `mmap` is the one thing `--direct-io` may never break, so the suite has to
//! make a real shared mapping of a real file on a real mount and store through
//! it — a mapping the *test* makes, not one the loader makes on its behalf,
//! because a write through the mapping is what a SQLite WAL does and what a
//! demand-paged execution never does. `rustix`'s `mmap`, `msync` and `munmap`
//! are unsafe functions (they hand out a raw pointer to memory whose lifetime
//! the compiler cannot see), and no safe binding for them exists in this
//! workspace's dependencies. The three calls are confined here, each with its
//! safety argument, behind a type that owns the mapping and unmaps it on drop.
#![allow(
    unsafe_code,
    reason = "mmap has no safe binding, and the mmap proofs are the point of the direct-io suite"
)]

use std::ffi::c_void;
use std::fs;
use std::io;
use std::path::Path;
use std::ptr;

use rustix::mm::{MapFlags, MsyncFlags, ProtFlags, mmap, msync, munmap};

/// A readable, writable `MAP_SHARED` mapping of the first `length` bytes of a
/// file, unmapped when it is dropped.
#[derive(Debug)]
pub struct SharedMapping {
    /// The mapping, valid for `length` bytes until [`Drop`] releases it.
    address: *mut c_void,
    length: usize,
}

impl SharedMapping {
    /// Opens a file read-write and maps its first `length` bytes `MAP_SHARED`.
    ///
    /// The file is closed immediately: a mapping holds its own reference to the
    /// file, so nothing here needs to keep the descriptor alive.
    ///
    /// # Errors
    ///
    /// Whatever `open(2)` or `mmap(2)` returned — and `ENODEV` is the one that
    /// matters: that is what a kernel answers for a shared mapping of a
    /// `FOPEN_DIRECT_IO` file it was not asked to allow mappings of.
    pub fn open(path: &Path, length: usize) -> io::Result<Self> {
        let file = fs::OpenOptions::new().read(true).write(true).open(path)?;
        // SAFETY: a fresh mapping at an address the kernel chooses, of a file
        // this call opened for reading and writing, with a length the caller
        // asserts the file covers. The pointer it returns is owned by the value
        // returned here and released by `Drop` alone.
        let address = unsafe {
            mmap(
                ptr::null_mut(),
                length,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED,
                &file,
                0,
            )
        }?;
        Ok(Self { address, length })
    }

    /// The mapped bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the mapping is live for as long as `self` is, covers
        // `self.length` readable bytes, and the borrow ties the slice to it.
        unsafe { std::slice::from_raw_parts(self.address.cast::<u8>(), self.length) }
    }

    /// The mapped bytes, to store through.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above, and the exclusive borrow of `self` is what makes
        // the exclusive slice sound: nothing else can be holding one.
        unsafe { std::slice::from_raw_parts_mut(self.address.cast::<u8>(), self.length) }
    }

    /// Writes the mapping's dirty pages back to the file and waits for it.
    ///
    /// # Errors
    ///
    /// Whatever `msync(2)` returned.
    pub fn flush(&self) -> io::Result<()> {
        // SAFETY: the mapping is live and is exactly `self.length` bytes long.
        unsafe { msync(self.address, self.length, MsyncFlags::SYNC) }.map_err(io::Error::from)
    }
}

impl Drop for SharedMapping {
    fn drop(&mut self) {
        // SAFETY: the address and length are the ones `mmap` returned, the
        // mapping has not been released before now, and nothing can reach it
        // afterwards.
        let _ = unsafe { munmap(self.address, self.length) };
    }
}
