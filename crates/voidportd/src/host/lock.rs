//! Byte-range open-file-description locks.
//!
//! The design rules file locking onto **OFD locks** (`F_OFD_SETLK`,
//! `F_OFD_GETLK`) after kernel probes, for a reason that no other locking
//! primitive satisfies: classic POSIX record locks are owned by the *process*,
//! so two guest lock owners multiplexed through one server process could never
//! conflict with each other — the second request would simply replace the
//! first. OFD locks belong to the open file description, so the server can give
//! each wire lock owner its own description of each file (see the data plane's
//! lock sets) and have their locks conflict exactly as they would between two
//! independent processes on the host.
//!
//! `F_OFD_GETLK` reports `l_pid` as -1, which is why the wire's `pid` field is
//! informational for locks: an open file description has no owning process to
//! name.
//!
//! # Why there is no blocking command here
//!
//! The kernel offers `F_OFD_SETLKW`, which sleeps in the syscall until the
//! range is free, and this module deliberately does not expose it. A sleeping
//! syscall costs a *thread*, and the server's threads are the blocking pool
//! every session's host I/O shares; the design's waits-are-async rule
//! ("a blocking-pool thread is never parked indefinitely") makes a few hundred
//! stacked waiters a pool-starvation hole, not a heavy but survivable
//! load. A guest's blocking lock is therefore served by
//! [`crate::data::ops::LockWait`] — the non-blocking command retried with
//! capped async backoff — and the only lock call that ever reaches the kernel
//! from anywhere is the non-blocking one below.
//!
//! # Why this module is the one place with `unsafe`
//!
//! `rustix` — the project's syscall crate — exposes only whole-file
//! process-associated `fcntl` locks (`fcntl_lock`) and classic `F_GETLK`
//! (`fcntl_getlk`); it has no `F_OFD_*` command and no byte-range set. The
//! required semantics are therefore unreachable through it, and the `fcntl` calls
//! below are made directly. They are confined to this module, each with its
//! safety argument. The shipped code has one other such place, for the same
//! reason — [`crate::reclaim`], where glibc's arena bound and heap trim have no
//! safe binding either — and one in test scaffolding: the client suite's `mmap`
//! helper.
#![allow(
    unsafe_code,
    reason = "F_OFD_* locking is required by the design and has no safe binding in rustix 1.1"
)]

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

use rustix::io::Errno;

/// What a lock request asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockKind {
    /// A shared read lock.
    Read,
    /// An exclusive write lock.
    Write,
    /// Release whatever is held over the range.
    Unlock,
}

impl LockKind {
    /// The `F_*LCK` value.
    fn as_raw(self) -> libc::c_short {
        (match self {
            Self::Read => libc::F_RDLCK,
            Self::Write => libc::F_WRLCK,
            Self::Unlock => libc::F_UNLCK,
        }) as libc::c_short
    }

    /// The kind a raw `l_type` names, if it is one the server knows.
    fn from_raw(raw: libc::c_short) -> Option<Self> {
        match i32::from(raw) {
            libc::F_RDLCK => Some(Self::Read),
            libc::F_WRLCK => Some(Self::Write),
            libc::F_UNLCK => Some(Self::Unlock),
            _ => None,
        }
    }
}

/// One byte-range lock request.
///
/// The wire describes a range by its first and last byte, with `u64::MAX` as
/// "to the end of the file, however it grows"; `l_len == 0` is the kernel's
/// spelling of the same thing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockRange {
    /// First byte of the range.
    pub start: u64,
    /// Last byte of the range; `u64::MAX` means end of file.
    pub end: u64,
}

impl LockRange {
    /// Builds a range.
    #[must_use]
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// The whole file.
    #[must_use]
    pub fn whole_file() -> Self {
        Self::new(0, u64::MAX)
    }

    /// The range the kernel holds when it accepts this one, in its own
    /// coordinates: offsets are clamped the way [`set`] passes them, and a range
    /// to the end of the file ends at the last offset the kernel has.
    ///
    /// # Errors
    ///
    /// Returns `EINVAL` for a range that ends before it starts.
    pub fn as_held(self) -> Result<Self, Errno> {
        let (start, length) = self.as_raw()?;
        let (start, last) = (start.unsigned_abs(), libc::off_t::MAX.unsigned_abs());
        let end = if length <= 0 {
            last
        } else {
            start.saturating_add(length.unsigned_abs() - 1).min(last)
        };
        Ok(Self::new(start, end))
    }

    /// The request that places a range [`Self::as_held`] returned: one that
    /// ends at the kernel's last offset runs to the end of the file.
    #[must_use]
    pub fn from_held(self) -> Self {
        if self.end >= libc::off_t::MAX.unsigned_abs() {
            Self::new(self.start, u64::MAX)
        } else {
            self
        }
    }

    /// The kernel's `(l_start, l_len)` pair.
    ///
    /// # Errors
    ///
    /// Returns `EINVAL` for a range that ends before it starts.
    fn as_raw(self) -> Result<(libc::off_t, libc::off_t), Errno> {
        if self.end == u64::MAX {
            return Ok((clamp_offset(self.start), 0));
        }
        if self.end < self.start {
            return Err(Errno::INVAL);
        }
        let length = self.end - self.start + 1;
        Ok((clamp_offset(self.start), clamp_offset(length)))
    }

    /// The range a kernel `(l_start, l_len)` pair describes.
    fn from_raw(start: libc::off_t, length: libc::off_t) -> Self {
        let start = start.max(0) as u64;
        if length <= 0 {
            return Self::new(start, u64::MAX);
        }
        Self::new(start, start.saturating_add(length as u64).saturating_sub(1))
    }
}

/// Clamps a wire offset into the kernel's signed offset space.
///
/// The wire carries `u64` offsets and the kernel takes `off_t`; a value past
/// the signed maximum cannot name a byte of any file, so it saturates instead
/// of wrapping into a negative offset.
fn clamp_offset(value: u64) -> libc::off_t {
    libc::off_t::try_from(value).unwrap_or(libc::off_t::MAX)
}

/// A lock that blocks the requested one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Conflict {
    /// The conflicting lock's kind.
    pub kind: LockKind,
    /// The range it holds.
    pub range: LockRange,
    /// The pid the kernel reports. OFD locks report -1: a description has no
    /// owning process.
    pub pid: i32,
}

/// Places or releases a lock on an open file description, without waiting.
///
/// This never sleeps in the kernel: a conflict is reported at once, and a guest
/// that asked to wait is served by retrying this call (see the module header).
///
/// # Errors
///
/// Returns the host errno: `EAGAIN` for a conflict, `EBADF` when the
/// description's access mode does not permit the lock kind, and `EINVAL` for a
/// malformed range.
pub fn set(fd: BorrowedFd<'_>, kind: LockKind, range: LockRange) -> Result<(), Errno> {
    let mut lock = flock(kind, range)?;
    fcntl(fd, libc::F_OFD_SETLK, &mut lock).map(|_| ())
}

/// Whether an errno from [`set`] means "another description holds the range".
///
/// POSIX allows either `EAGAIN` or `EACCES` for a refused non-blocking lock and
/// says an application should test for both; Linux returns `EAGAIN`. This is
/// the one condition a blocking request retries on — every other errno is the
/// answer.
#[must_use]
pub fn is_conflict(error: Errno) -> bool {
    error == Errno::AGAIN || error == Errno::ACCESS
}

/// Tests whether a lock could be placed.
///
/// Returns the lock that would block it, or `None` when the range is free.
///
/// # Errors
///
/// Returns the host errno.
pub fn test(
    fd: BorrowedFd<'_>,
    kind: LockKind,
    range: LockRange,
) -> Result<Option<Conflict>, Errno> {
    let mut lock = flock(kind, range)?;
    fcntl(fd, libc::F_OFD_GETLK, &mut lock)?;
    match LockKind::from_raw(lock.l_type) {
        // The kernel answers a free range by setting the type to F_UNLCK.
        Some(LockKind::Unlock) | None => Ok(None),
        Some(kind) => Ok(Some(Conflict {
            kind,
            range: LockRange::from_raw(lock.l_start, lock.l_len),
            pid: lock.l_pid,
        })),
    }
}

/// Builds the kernel lock description for a request.
fn flock(kind: LockKind, range: LockRange) -> Result<libc::flock, Errno> {
    let (start, length) = range.as_raw()?;
    Ok(libc::flock {
        l_type: kind.as_raw(),
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: start,
        l_len: length,
        l_pid: 0,
    })
}

/// Issues one `fcntl` lock command.
///
/// Both commands used here take a pointer to a `struct flock` that the kernel
/// reads and, for `F_OFD_GETLK`, writes back into.
fn fcntl(fd: BorrowedFd<'_>, command: libc::c_int, lock: &mut libc::flock) -> Result<(), Errno> {
    // SAFETY: `command` is one of `F_OFD_SETLK` and `F_OFD_GETLK`, whose
    // contract is exactly "the variadic argument is a `*mut libc::flock`".
    // `lock` is a live, exclusively borrowed `flock` that
    // outlives the call, and `fd` is a valid descriptor for the duration of the
    // borrow. The kernel does not retain the pointer past the call and writes
    // only within the struct.
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), command, std::ptr::from_mut(lock)) };
    if result < 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// The errno of the failed call.
fn last_errno() -> Errno {
    Errno::from_raw_os_error(
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Scratch;
    use std::fs;
    use std::os::fd::AsFd;

    /// Two independent descriptions of one file, as two lock owners hold.
    fn descriptions(scratch: &Scratch) -> (fs::File, fs::File) {
        let path = scratch.file("file", &[0u8; 1024]);
        let open = || {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .expect("openable")
        };
        (open(), open())
    }

    #[test]
    fn ranges_translate_to_the_kernels_spelling_and_back() {
        assert_eq!(LockRange::new(0, 9).as_raw(), Ok((0, 10)));
        assert_eq!(LockRange::whole_file().as_raw(), Ok((0, 0)));
        assert_eq!(LockRange::new(4, u64::MAX).as_raw(), Ok((4, 0)));
        assert_eq!(LockRange::new(9, 0).as_raw(), Err(Errno::INVAL));
        assert_eq!(LockRange::from_raw(0, 10), LockRange::new(0, 9));
        assert_eq!(LockRange::from_raw(4, 0), LockRange::new(4, u64::MAX));
    }

    #[test]
    fn two_descriptions_of_one_process_genuinely_conflict() {
        let scratch = Scratch::new("lock");
        let (first, second) = descriptions(&scratch);

        set(first.as_fd(), LockKind::Write, LockRange::new(0, 9)).expect("the range is free");
        // This is the property classic POSIX record locks cannot provide: the
        // same process, a second description, a real conflict.
        assert_eq!(
            set(second.as_fd(), LockKind::Write, LockRange::new(5, 20)).expect_err("overlapping"),
            Errno::AGAIN
        );
        // A disjoint range is unaffected.
        set(second.as_fd(), LockKind::Write, LockRange::new(10, 20))
            .expect("disjoint ranges do not conflict");

        let conflict = test(second.as_fd(), LockKind::Write, LockRange::new(0, 4))
            .expect("testable")
            .expect("the first description holds it");
        assert_eq!(conflict.kind, LockKind::Write);
        assert_eq!(conflict.range, LockRange::new(0, 9));
        assert_eq!(conflict.pid, -1, "an OFD lock has no owning process");

        // Releasing one description leaves the other's locks alone.
        set(first.as_fd(), LockKind::Unlock, LockRange::whole_file()).expect("releasable");
        assert_eq!(
            test(second.as_fd(), LockKind::Write, LockRange::new(0, 4)).expect("testable"),
            None
        );
        assert!(
            test(first.as_fd(), LockKind::Write, LockRange::new(10, 20))
                .expect("testable")
                .is_some(),
            "the second description still holds its own range"
        );
    }

    #[test]
    fn closing_a_description_drops_its_locks() {
        let scratch = Scratch::new("lock");
        let (first, second) = descriptions(&scratch);
        set(first.as_fd(), LockKind::Write, LockRange::whole_file()).expect("free");
        assert!(
            test(second.as_fd(), LockKind::Read, LockRange::whole_file())
                .expect("testable")
                .is_some()
        );
        drop(first);
        assert_eq!(
            test(second.as_fd(), LockKind::Read, LockRange::whole_file()).expect("testable"),
            None
        );
    }

    #[test]
    fn read_locks_share_and_write_locks_do_not() {
        let scratch = Scratch::new("lock");
        let (first, second) = descriptions(&scratch);
        set(first.as_fd(), LockKind::Read, LockRange::new(0, 9)).expect("free");
        set(second.as_fd(), LockKind::Read, LockRange::new(0, 9)).expect("read locks share");
        assert_eq!(
            set(second.as_fd(), LockKind::Write, LockRange::new(0, 9))
                .expect_err("a reader blocks a writer"),
            Errno::AGAIN
        );
    }
}
