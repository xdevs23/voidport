//! Uncached backing I/O, and the aligned buffers it demands.
//!
//! A description opened `O_DIRECT` does not accept any buffer: the kernel
//! transfers straight between the storage and the caller's memory, so the
//! address must sit on the boundary the backing file asks for. The server's own
//! buffers cannot: a read lands in the middle of a frame buffer, right behind
//! the fixed response head, and a write is a borrowed slice of the request
//! frame that arrived off the wire. Both are byte-aligned by construction, and
//! direct I/O refuses them regardless of how carefully the *guest* aligned its
//! own request.
//!
//! So a direct handle carries a bounce: one buffer aligned to what the backing
//! file demands, copied through on the way past. That is the whole of the cost,
//! and it buys the posture its production contract — an aligned guest request
//! reaches the storage and comes back with real data.
//!
//! **What is not bounced is the request itself.** The offset and the length are
//! the guest's, and they are handed to the kernel exactly as they arrived: a
//! request the backing filesystem calls misaligned is refused by that
//! filesystem, with the errno it gives a local program. The bounce fixes the
//! one thing the guest cannot see and never fixes the two things it chose.

use std::os::fd::BorrowedFd;

use rustix::fs::{AtFlags, OFlags, StatxFlags, statx};
use rustix::io::Errno;

/// The buffer alignment assumed where `statx` does not answer.
///
/// 512 bytes is the smallest logical block size a Linux block device reports
/// and the alignment direct I/O demanded everywhere before `STATX_DIOALIGN`
/// existed, so it is the safe answer for a filesystem or a kernel that does not
/// state its own: over-aligning a buffer is always accepted, under-aligning it
/// is `EINVAL`.
const LOGICAL_BLOCK_SIZE: usize = 512;

/// How one open backing description reaches its file.
///
/// This is the consequence of the namespace's direct-I/O posture, decided once
/// when the description is created and carried by the handle for as long as it
/// lives — which is what makes a posture change live at the next open and
/// invisible to handles already open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackingIo {
    /// Through the host page cache. The buffer the wire already owns is the
    /// buffer the kernel is given, so a read costs one copy from the kernel and
    /// a write costs none at all.
    Cached,
    /// Past the host page cache, through a buffer aligned to `alignment` bytes.
    Direct {
        /// The memory alignment the backing file demands of a direct transfer.
        alignment: usize,
    },
}

impl BackingIo {
    /// Decides how a freshly opened description will be read and written.
    ///
    /// `flags` are the flags the description was opened with, which is the only
    /// thing that decides this: `O_DIRECT` is on it exactly when the
    /// namespace's posture put it there.
    #[must_use]
    pub fn of(fd: BorrowedFd<'_>, flags: OFlags) -> Self {
        if flags.contains(OFlags::DIRECT) {
            Self::Direct {
                alignment: memory_alignment(fd),
            }
        } else {
            Self::Cached
        }
    }

    /// Reads `into` from `offset`, through the bounce where the description is
    /// uncached.
    ///
    /// # Errors
    ///
    /// Returns the host errno, `EINVAL` included: that is what a backing
    /// filesystem answers a request whose offset or length it calls misaligned,
    /// and it reaches the guest unchanged.
    pub fn read(&self, fd: BorrowedFd<'_>, into: &mut [u8], offset: u64) -> Result<usize, Errno> {
        let Self::Direct { alignment } = *self else {
            return rustix::io::pread(fd, into, offset);
        };
        let mut bounce = slack(into.len(), alignment);
        let window = window(&mut bounce, alignment, into.len());
        let read = rustix::io::pread(fd, &mut *window, offset)?;
        into[..read].copy_from_slice(&window[..read]);
        Ok(read)
    }

    /// Writes `from` at `offset`, through the bounce where the description is
    /// uncached.
    ///
    /// # Errors
    ///
    /// As [`Self::read`].
    pub fn write(&self, fd: BorrowedFd<'_>, from: &[u8], offset: u64) -> Result<usize, Errno> {
        let Self::Direct { alignment } = *self else {
            return rustix::io::pwrite(fd, from, offset);
        };
        let mut bounce = slack(from.len(), alignment);
        let window = window(&mut bounce, alignment, from.len());
        window.copy_from_slice(from);
        rustix::io::pwrite(fd, window, offset)
    }
}

/// A buffer large enough to hold `len` bytes at whatever offset alignment
/// forces it to start at.
///
/// An allocation of bytes is byte-aligned, so the alignment is bought with
/// slack instead of with an allocator that could promise it: at most
/// `alignment - 1` bytes are skipped at the front.
fn slack(len: usize, alignment: usize) -> Vec<u8> {
    vec![0u8; len + alignment - 1]
}

/// The aligned window of `buffer` that holds `len` bytes.
///
/// The start is rounded up to the next multiple of `alignment`, which is the
/// arithmetic and not a power-of-two trick: a kernel that ever reported an
/// alignment that is not a power of two would still be answered correctly
/// instead of ending the process.
fn window(buffer: &mut [u8], alignment: usize, len: usize) -> &mut [u8] {
    let start = buffer.as_ptr() as usize;
    let offset = start.next_multiple_of(alignment) - start;
    &mut buffer[offset..offset + len]
}

/// The memory alignment a backing file demands of direct transfers.
///
/// `STATX_DIOALIGN` is the kernel's own answer and the only one that is right
/// per file — it varies by filesystem and by device — so it is asked first.
/// A kernel or filesystem that does not fill the field says nothing about the
/// demand, not that there is none, so the answer is
/// [`LOGICAL_BLOCK_SIZE`], never a smaller guess.
fn memory_alignment(fd: BorrowedFd<'_>) -> usize {
    let Ok(stat) = statx(fd, "", AtFlags::EMPTY_PATH, StatxFlags::DIOALIGN) else {
        return LOGICAL_BLOCK_SIZE;
    };
    let filled = StatxFlags::from_bits_truncate(stat.stx_mask);
    if filled.contains(StatxFlags::DIOALIGN) && stat.stx_dio_mem_align > 0 {
        stat.stx_dio_mem_align as usize
    } else {
        LOGICAL_BLOCK_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    use rustix::fs::Mode;

    use crate::testing::Scratch;

    /// One page of recognizable bytes, which is an aligned length at every
    /// alignment a filesystem asks for.
    const PAGE: usize = 4096;

    /// Whether the scratch filesystem serves direct I/O at all.
    ///
    /// tmpfs does not, and a suite running on one cannot prove anything about
    /// an uncached description — so the proofs below say so out loud instead of
    /// passing quietly.
    fn uncached(path: &std::path::Path) -> Option<std::os::fd::OwnedFd> {
        rustix::fs::open(path, OFlags::RDWR | OFlags::DIRECT, Mode::empty()).ok()
    }

    #[test]
    fn an_unaligned_buffer_yields_an_aligned_window() {
        // Every start offset within one alignment, so the rounding is exercised
        // at the boundary and either side of it.
        for skew in 0..8usize {
            let mut buffer = slack(PAGE + skew, 512);
            let window = window(&mut buffer[skew..], 512, PAGE);
            assert_eq!(window.len(), PAGE);
            assert_eq!(window.as_ptr() as usize % 512, 0, "skew {skew}");
        }
    }

    /// The bounce, against a real uncached description.
    ///
    /// The point is not that the bytes arrive — a cached description proves
    /// that — but that they arrive *at all*: the same transfer through the
    /// server's own unaligned buffer is what direct I/O refuses, and the
    /// refusal is asserted right beside the success so the bounce cannot
    /// silently stop being needed.
    ///
    /// Whether the kernel refuses is the backing filesystem's own policy,
    /// not a law: ext4 answers a misaligned direct request `EINVAL`, btrfs
    /// quietly falls back to buffered I/O and serves it. The bounce exists
    /// for the refusing kind, so the refusal arms run exactly there — on a
    /// repairing filesystem they would assert another filesystem's
    /// behavior, and the proof says which kind it ran against instead of
    /// presuming one.
    #[test]
    fn an_aligned_bounce_serves_what_an_unaligned_buffer_cannot() {
        let scratch = Scratch::new("direct");
        let path = scratch.file("data.bin", &[0u8; PAGE]);
        let Some(fd) = uncached(&path) else {
            eprintln!(
                "skipping the bounce proof: {} serves no direct I/O",
                path.display()
            );
            return;
        };

        let backing = BackingIo::of(fd.as_fd(), OFlags::RDWR | OFlags::DIRECT);
        let BackingIo::Direct { alignment } = backing else {
            panic!("an O_DIRECT description is uncached");
        };
        assert!(alignment >= LOGICAL_BLOCK_SIZE);

        let written: Vec<u8> = (0..PAGE).map(|index| index as u8).collect();
        assert_eq!(
            backing.write(fd.as_fd(), &written, 0).expect("aligned"),
            PAGE
        );
        let mut read = vec![0u8; PAGE];
        assert_eq!(
            backing.read(fd.as_fd(), &mut read, 0).expect("aligned"),
            PAGE
        );
        assert_eq!(read, written, "the bounce did not round-trip the data");

        // The buffer the wire would have handed the kernel: one byte into an
        // allocation, which is what a frame buffer's payload region looks
        // like. This is the probe that tells the two filesystem kinds apart.
        let mut unaligned = vec![0u8; PAGE + 1];
        if rustix::io::pread(fd.as_fd(), &mut unaligned[1..], 0).is_err() {
            // The refusing kind, where the bounce is load-bearing. What the
            // guest chose is never repaired: an offset this filesystem calls
            // misaligned is refused through the bounce exactly as locally.
            assert!(backing.read(fd.as_fd(), &mut read, 1).is_err());
        } else {
            eprintln!(
                "the scratch filesystem repairs misaligned direct I/O \
                 itself; the refusal arms prove nothing here"
            );
        }
    }

    /// A cached description hands the kernel the caller's own buffer, which is
    /// the zero-copy read path the wire format exists for.
    #[test]
    fn a_cached_description_bounces_nothing() {
        let scratch = Scratch::new("direct");
        let path = scratch.file("cached.bin", b"0123456789");
        let fd = rustix::fs::open(&path, OFlags::RDWR, Mode::empty()).expect("opens");
        let backing = BackingIo::of(fd.as_fd(), OFlags::RDWR);
        assert_eq!(backing, BackingIo::Cached);

        assert_eq!(backing.write(fd.as_fd(), b"AB", 4).expect("writable"), 2);
        // Any offset, any length: nothing here carries an alignment demand.
        let mut read = [0u8; 3];
        assert_eq!(backing.read(fd.as_fd(), &mut read, 3).expect("readable"), 3);
        assert_eq!(&read, b"3AB");
    }
}
