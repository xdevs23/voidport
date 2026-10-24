use std::ffi::c_void;
use std::fs;
use std::io;
use std::path::Path;
use std::ptr;

use rustix::mm::{MapFlags, MsyncFlags, ProtFlags, mmap, msync, munmap};

#[derive(Debug)]
pub struct SharedMapping {
    address: *mut c_void,
    length: usize,
    writable: bool,
}

impl SharedMapping {
    /// The file is closed on return, because the mapping has a reference to it.
    /// `ENODEV` is what the kernel returns for a shared mapping of a
    /// `FOPEN_DIRECT_IO` file that was not allowed.
    pub fn open(path: &Path, length: usize) -> io::Result<Self> {
        Self::map(path, length, true)
    }

    pub fn open_read_only(path: &Path, length: usize) -> io::Result<Self> {
        Self::map(path, length, false)
    }

    fn map(path: &Path, length: usize, writable: bool) -> io::Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(writable)
            .open(path)?;
        let protection = if writable {
            ProtFlags::READ | ProtFlags::WRITE
        } else {
            ProtFlags::READ
        };
        // SAFETY: Unavoidable: a store through a shared mapping is what the
        // proofs exercise, and `read(2)` and `write(2)`, the safe forms, pass
        // the page cache without a mapping. A fresh mapping at an address the
        // kernel chooses, of a file this call opened with the access the
        // protection asks for, with a length the caller asserts the file
        // covers. The pointer it returns is owned by the value returned here
        // and released by `Drop` alone.
        let address = unsafe {
            mmap(
                ptr::null_mut(),
                length,
                protection,
                MapFlags::SHARED,
                &file,
                0,
            )
        }?;
        Ok(Self {
            address,
            length,
            writable,
        })
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: Unavoidable: a raw pointer from `mmap` becomes a slice only
        // through `from_raw_parts`, and copying the bytes out through a safe
        // read of the file would not read the mapping. The mapping is live for
        // as long as `self` is, covers `self.length` readable bytes, and the
        // borrow ties the slice to it.
        unsafe { std::slice::from_raw_parts(self.address.cast::<u8>(), self.length) }
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        assert!(
            self.writable,
            "a mapping readable only is not stored through"
        );
        // SAFETY: Unavoidable, as for `bytes`, and a store through the slice
        // is the store through the mapping that the proofs make. The mapping
        // is live and covers `self.length` writable bytes, and the exclusive
        // borrow of `self` is what makes the exclusive slice sound: nothing
        // else can be holding one.
        unsafe { std::slice::from_raw_parts_mut(self.address.cast::<u8>(), self.length) }
    }

    pub fn flush(&self) -> io::Result<()> {
        // SAFETY: Unavoidable: `fsync(2)`, the safe form, does not write back
        // the pages a mapping dirtied before `msync` marks them. The mapping
        // is live and is exactly `self.length` bytes long.
        unsafe { msync(self.address, self.length, MsyncFlags::SYNC) }.map_err(io::Error::from)
    }
}

impl Drop for SharedMapping {
    fn drop(&mut self) {
        // SAFETY: Unavoidable: a mapping made by `mmap` ends only by
        // `munmap`, and dropping the file it maps leaves it in place. The
        // address and length are the ones `mmap` returned, the mapping has not
        // been released before now, and nothing can access it afterwards.
        if let Err(error) = unsafe { munmap(self.address, self.length) } {
            eprintln!("the shared mapping is not released: {error}");
        }
    }
}
