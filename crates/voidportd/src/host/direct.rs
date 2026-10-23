//! A description opened `O_DIRECT` needs the address, the offset and the length
//! of a transfer aligned as the backing file asks. The wire allocates the one
//! buffer of a transfer aligned to [`Transfer::memory_alignment`], so the
//! backing read and write use it without a copy.
//!
//! The request is not repaired. The offset and the length of the guest are
//! handed to the kernel as they arrived, and a request that the backing
//! filesystem calls misaligned is refused by that filesystem with the errno a
//! local program would get. The wire cuts its pieces at multiples of the offset
//! alignment, so an aligned request is aligned piece by piece.
//!
//! Every handle makes one `statx` when it is opened, which records the preferred
//! block and both alignments. A failing `statx` fails the open, because
//! without the answer of the host no piece size exists.
//!
//! One description supports handles of both kinds: every handle of a session on
//! a regular file reads and writes through one description
//! ([`crate::data::cache`]), and its `O_DIRECT` status flag is set to match the
//! handle for each transfer ([`Description`]). Transfers of one kind run
//! together, and a transfer of the other kind waits until they are done, sets
//! the flag and runs alone.

use std::io::IoSlice;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Arc, RwLock};

use rustix::fs::{AtFlags, OFlags, Statx, StatxFlags, statx};
use rustix::io::{Errno, ReadWriteFlags};

use crate::host::open::reopen;

/// 512 bytes is the smallest logical block size of a Linux block device and the
/// alignment that direct I/O demanded before `STATX_DIOALIGN`: over-aligning is
/// always accepted, and under-aligning is `EINVAL`.
const LOGICAL_BLOCK_SIZE: usize = 512;

/// The alignments of the memory, and of the file offset and length, of a
/// transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Direct {
    memory: usize,
    offset: usize,
}

/// Decided once at open and carried by the handle, so a posture change is live
/// at the next open and invisible to handles already open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transfer {
    block: usize,
    direct: Option<Direct>,
}

impl Transfer {
    /// # Errors
    ///
    /// The host errno when `statx` fails.
    pub fn of(fd: BorrowedFd<'_>, flags: OFlags) -> Result<Self, Errno> {
        let stat = statx(
            fd,
            "",
            AtFlags::EMPTY_PATH,
            StatxFlags::BASIC_STATS | StatxFlags::DIOALIGN,
        )?;
        Ok(Self::from_stat(&stat, flags))
    }

    /// A kernel or filesystem that does not fill the direct-I/O fields leaves the
    /// alignment open, so both alignments are [`LOGICAL_BLOCK_SIZE`].
    #[must_use]
    pub fn from_stat(stat: &Statx, flags: OFlags) -> Self {
        // Never zero: a zero would make one-byte pieces.
        let block = (stat.stx_blksize as usize).max(1);
        let direct = flags.contains(OFlags::DIRECT).then(|| {
            let filled = StatxFlags::from_bits_truncate(stat.stx_mask);
            let stated = |value: u32| {
                if filled.contains(StatxFlags::DIOALIGN) && value > 0 {
                    value as usize
                } else {
                    LOGICAL_BLOCK_SIZE
                }
            };
            Direct {
                memory: stated(stat.stx_dio_mem_align),
                offset: stated(stat.stx_dio_offset_align),
            }
        });
        Self { block, direct }
    }

    #[must_use]
    pub fn is_direct(&self) -> bool {
        self.direct.is_some()
    }

    #[must_use]
    pub fn piece_len(&self) -> usize {
        match self.direct {
            Some(direct) => self.block.next_multiple_of(direct.offset),
            None => self.block,
        }
    }

    #[must_use]
    pub fn memory_alignment(&self) -> usize {
        self.direct.map_or(1, |direct| direct.memory)
    }

    #[must_use]
    pub fn offset_alignment(&self) -> Option<usize> {
        self.direct.map(|direct| direct.offset)
    }
}

#[derive(Debug)]
pub struct Description {
    fd: OwnedFd,
    access: OFlags,
    /// Whether the `O_DIRECT` status flag is set on the description now. A
    /// transfer locks the read side while the flag matches its handle, and the
    /// write side while it sets the flag to match its handle.
    direct: RwLock<bool>,
}

impl Description {
    #[must_use]
    pub fn of(fd: OwnedFd, flags: OFlags) -> Arc<Self> {
        Arc::new(Self {
            fd,
            access: flags & (OFlags::RDONLY | OFlags::WRONLY | OFlags::RDWR),
            direct: RwLock::new(flags.contains(OFlags::DIRECT)),
        })
    }

    /// # Errors
    ///
    /// The host errno of the open.
    pub fn open(pinned: BorrowedFd<'_>, flags: OFlags) -> Result<Arc<Self>, Errno> {
        Ok(Self::of(reopen(pinned, flags)?, flags))
    }

    #[must_use]
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    #[must_use]
    pub fn access(&self) -> OFlags {
        self.access
    }

    #[must_use]
    pub fn writable(&self) -> bool {
        self.access.intersects(OFlags::WRONLY | OFlags::RDWR)
    }

    /// A host that rejects the flag rejects the open, as it rejects an open with
    /// it.
    ///
    /// # Errors
    ///
    /// The host errno of setting the flag.
    pub fn accept(&self, direct: bool) -> Result<(), Errno> {
        self.transferring(direct, |_| Ok(()))
    }

    fn transferring<R>(
        &self,
        direct: bool,
        transfer: impl FnOnce(BorrowedFd<'_>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        {
            let current = self
                .direct
                .read()
                .unwrap_or_else(|poison| poison.into_inner());
            if *current == direct {
                return transfer(self.fd());
            }
        }
        let mut current = self
            .direct
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        if *current != direct {
            let flags = rustix::fs::fcntl_getfl(&self.fd)?;
            rustix::fs::fcntl_setfl(
                &self.fd,
                flags.difference(OFlags::DIRECT) | direct_flag(direct),
            )?;
            *current = direct;
        }
        transfer(self.fd())
    }
}

fn direct_flag(direct: bool) -> OFlags {
    if direct {
        OFlags::DIRECT
    } else {
        OFlags::empty()
    }
}

#[derive(Clone, Debug)]
pub struct Io {
    description: Arc<Description>,
    transfer: Transfer,
}

impl Io {
    /// # Errors
    ///
    /// The host errno of the open or of the `statx`.
    pub fn reopen(pinned: BorrowedFd<'_>, flags: OFlags) -> Result<Self, Errno> {
        Self::of(reopen(pinned, flags)?, flags)
    }

    /// # Errors
    ///
    /// The host errno when `statx` fails.
    pub fn of(fd: OwnedFd, flags: OFlags) -> Result<Self, Errno> {
        let transfer = Transfer::of(fd.as_fd(), flags)?;
        Ok(Self {
            description: Description::of(fd, flags),
            transfer,
        })
    }

    /// `description` for a handle with a `transfer` measured on another
    /// description of the same file.
    #[must_use]
    pub(crate) fn measured(description: Arc<Description>, transfer: Transfer) -> Self {
        Self {
            description,
            transfer,
        }
    }

    #[must_use]
    pub fn description(&self) -> &Arc<Description> {
        &self.description
    }

    #[must_use]
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.description.fd()
    }

    #[must_use]
    pub fn transfer(&self) -> Transfer {
        self.transfer
    }

    /// # Errors
    ///
    /// Returns the host errno, `EINVAL` included: that is what a backing
    /// filesystem returns for a request whose offset or length it calls
    /// misaligned, and it reaches the guest unchanged.
    pub fn read(&self, into: &mut [u8], offset: u64) -> Result<usize, Errno> {
        self.call(|fd| rustix::io::pread(fd, into, offset))
    }

    /// # Errors
    ///
    /// As [`Self::read`].
    pub fn write(
        &self,
        from: &[IoSlice<'_>],
        offset: u64,
        flags: ReadWriteFlags,
    ) -> Result<usize, Errno> {
        self.call(|fd| rustix::io::pwritev2(fd, from, offset, flags))
    }

    /// The call of a transfer that [`Self::read`] and [`Self::write`] do not make,
    /// such as one into memory that another party shares.
    /// # Errors
    ///
    /// The host errno of setting the flag, and the errno of `transfer`.
    pub fn call<R>(
        &self,
        transfer: impl FnOnce(BorrowedFd<'_>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        self.description
            .transferring(self.transfer.is_direct(), transfer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use voidport_memory::Memory;

    use voidport_test_host::Scratch;

    const PAGE: usize = 4096;

    fn pinned(path: &std::path::Path) -> OwnedFd {
        rustix::fs::open(path, OFlags::PATH, rustix::fs::Mode::empty())
            .expect("the file opens by path")
    }

    #[test]
    fn a_cached_description_takes_its_preferred_block_and_no_alignment() {
        let scratch = Scratch::new("direct");
        let path = scratch.file("cached.bin", b"0123456789");
        let io = Io::reopen(pinned(&path).as_fd(), OFlags::RDWR).expect("opens");
        let transfer = io.transfer();
        assert!(!transfer.is_direct());
        let stat = rustix::fs::fstat(io.fd()).expect("stat");
        assert_eq!(transfer.piece_len(), stat.st_blksize as usize);
        assert_eq!(transfer.memory_alignment(), 1);
        assert_eq!(transfer.offset_alignment(), None);

        assert_eq!(
            io.write(&[IoSlice::new(b"AB")], 4, ReadWriteFlags::empty())
                .expect("writable"),
            2
        );
        let mut read = [0u8; 3];
        assert_eq!(io.read(&mut read, 3).expect("readable"), 3);
        assert_eq!(&read, b"3AB");
    }

    /// Whether the kernel refuses is the policy of the backing filesystem: ext4
    /// returns `EINVAL` for a misaligned direct request, btrfs falls back to
    /// buffered I/O. The refusal arm runs where the probe shows that the
    /// filesystem rejects.
    #[tokio::test]
    async fn an_aligned_buffer_serves_what_an_unaligned_one_cannot() {
        let scratch = Scratch::new("direct");
        let path = scratch.file("data.bin", &[0u8; PAGE]);
        let io = Io::reopen(pinned(&path).as_fd(), OFlags::RDWR | OFlags::DIRECT)
            .expect("the scratch filesystem serves direct I/O");
        let transfer = io.transfer();
        assert!(transfer.is_direct());
        assert!(transfer.memory_alignment() >= 1);
        assert_eq!(
            transfer.piece_len() % transfer.offset_alignment().expect("uncached"),
            0
        );

        let memory = Memory::host();
        let mut written = memory.buffer(PAGE, transfer.memory_alignment()).await;
        for (at, byte) in written.iter_mut().enumerate() {
            *byte = at as u8;
        }
        assert_eq!(
            io.write(&[IoSlice::new(&written)], 0, ReadWriteFlags::empty())
                .expect("aligned"),
            PAGE
        );
        let mut read = memory.buffer(PAGE, transfer.memory_alignment()).await;
        assert_eq!(io.read(&mut read, 0).expect("aligned"), PAGE);
        assert_eq!(&read[..], &written[..], "the aligned buffer round-tripped");

        let mut unaligned = vec![0u8; PAGE + 1];
        if rustix::io::pread(io.fd(), &mut unaligned[1..], 0).is_err() {
            assert!(io.read(&mut read, 1).is_err());
        }
    }

    #[tokio::test]
    async fn handles_of_both_kinds_transfer_through_one_description() {
        let scratch = Scratch::new("direct");
        let path = scratch.file("shared.bin", &[0u8; 2 * PAGE]);
        let buffered = Io::reopen(pinned(&path).as_fd(), OFlags::RDWR).expect("opens");
        let flags = OFlags::RDWR | OFlags::DIRECT;
        let transfer = Transfer::of(buffered.fd(), flags).expect("statx succeeds");
        buffered
            .description()
            .accept(transfer.is_direct())
            .expect("the scratch filesystem serves direct I/O");
        let direct = Io::measured(Arc::clone(buffered.description()), transfer);
        assert!(Arc::ptr_eq(buffered.description(), direct.description()));

        let memory = Memory::host();
        let mut page = memory
            .buffer(PAGE, direct.transfer().memory_alignment())
            .await;
        page.fill(b'D');
        assert_eq!(
            direct
                .write(&[IoSlice::new(&page)], 0, ReadWriteFlags::empty())
                .expect("aligned"),
            PAGE
        );
        assert_eq!(
            buffered
                .write(
                    &[IoSlice::new(b"bb")],
                    PAGE as u64 + 1,
                    ReadWriteFlags::empty()
                )
                .expect("a buffered transfer accepts any offset"),
            2
        );
        let mut read = [0u8; 4];
        assert_eq!(buffered.read(&mut read, PAGE as u64 - 1).expect("reads"), 4);
        assert_eq!(&read, b"D\0bb");
        assert!(
            !rustix::fs::fcntl_getfl(buffered.fd())
                .expect("the flags read")
                .contains(OFlags::DIRECT),
            "the last transfer left the flag of its handle"
        );
    }
}
