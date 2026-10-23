//! Classic POSIX record locks belong to the process, so two guest lock holders
//! multiplexed through one server process would replace the locks of each
//! other. OFD locks (`F_OFD_SETLK`, `F_OFD_GETLK`) belong to the open file
//! description. The server places the locks of the lock holders of a session on
//! one description of the file, so they conflict as they would with the locks
//! of an independent process on the host. `F_OFD_GETLK` reports `l_pid` as -1,
//! because a description belongs to no process.
//!
//! `F_OFD_SETLKW` is deliberately not exposed: a sleeping syscall costs a thread
//! of the blocking pool that the host I/O of every session shares, so a few
//! hundred stacked waiters would starve the pool. A blocking lock of a guest is
//! served by [`crate::data::ops::LockWait`], which retries the non-blocking
//! command with capped async backoff.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

use rustix::io::Errno;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockKind {
    Read,
    Write,
    Unlock,
}

impl LockKind {
    fn as_raw(self) -> libc::c_short {
        (match self {
            Self::Read => libc::F_RDLCK,
            Self::Write => libc::F_WRLCK,
            Self::Unlock => libc::F_UNLCK,
        }) as libc::c_short
    }

    fn from_raw(raw: libc::c_short) -> Option<Self> {
        match i32::from(raw) {
            libc::F_RDLCK => Some(Self::Read),
            libc::F_WRLCK => Some(Self::Write),
            libc::F_UNLCK => Some(Self::Unlock),
            _ => None,
        }
    }
}

/// `u64::MAX` as the end means to the end of the file, however it grows.
/// `l_len == 0` means the same to the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockRange {
    pub start: u64,
    pub end: u64,
}

impl LockRange {
    #[must_use]
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub fn whole_file() -> Self {
        Self::new(0, u64::MAX)
    }

    /// The range the kernel holds when it accepts this one, in its own
    /// coordinates.
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

    #[must_use]
    pub fn from_held(self) -> Self {
        if self.end >= libc::off_t::MAX.unsigned_abs() {
            Self::new(self.start, u64::MAX)
        } else {
            self
        }
    }

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

    fn from_raw(start: libc::off_t, length: libc::off_t) -> Self {
        let start = start.max(0) as u64;
        if length <= 0 {
            return Self::new(start, u64::MAX);
        }
        Self::new(start, start.saturating_add(length as u64).saturating_sub(1))
    }
}

/// A value past the signed maximum cannot name a byte of any file, so it
/// saturates instead of wrapping into a negative offset.
fn clamp_offset(value: u64) -> libc::off_t {
    libc::off_t::try_from(value).unwrap_or(libc::off_t::MAX)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Conflict {
    pub kind: LockKind,
    pub range: LockRange,
    /// The pid the kernel reports; OFD locks report -1.
    pub pid: i32,
}

/// Never sleeps in the kernel: a conflict is reported at once.
///
/// # Errors
///
/// Returns the host errno: `EAGAIN` for a conflict, `EBADF` when the access
/// mode of the description does not permit the lock kind, and `EINVAL` for a
/// malformed range.
pub fn set(fd: BorrowedFd<'_>, kind: LockKind, range: LockRange) -> Result<(), Errno> {
    let mut lock = flock(kind, range)?;
    fcntl(fd, libc::F_OFD_SETLK, &mut lock).map(|_| ())
}

/// POSIX allows `EAGAIN` or `EACCES` for a refused non-blocking lock, and Linux
/// returns `EAGAIN`.
#[must_use]
pub fn is_conflict(error: Errno) -> bool {
    error == Errno::AGAIN || error == Errno::ACCESS
}

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
        // The kernel reports a free range by setting the type to F_UNLCK.
        Some(LockKind::Unlock) | None => Ok(None),
        Some(kind) => Ok(Some(Conflict {
            kind,
            range: LockRange::from_raw(lock.l_start, lock.l_len),
            pid: lock.l_pid,
        })),
    }
}

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

fn fcntl(fd: BorrowedFd<'_>, command: libc::c_int, lock: &mut libc::flock) -> Result<(), Errno> {
    // SAFETY: Unavoidable: `rustix::fs::fcntl_lock` and
    // `rustix::process::fcntl_getlk`, the safe forms, lock and query only
    // process-associated locks, and rustix has no `F_OFD_*` command. `command`
    // is one of `F_OFD_SETLK` and `F_OFD_GETLK`, whose contract is exactly
    // "the variadic argument is a `*mut libc::flock`". `lock` is a live,
    // exclusively borrowed `flock` that outlives the call, and `fd` is a valid
    // descriptor for the duration of the borrow. The kernel does not retain the
    // pointer past the call and writes only within the struct.
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), command, std::ptr::from_mut(lock)) };
    if result < 0 {
        return Err(last_errno());
    }
    Ok(())
}

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
    use std::fs;
    use std::os::fd::AsFd;
    use voidport_test_host::Scratch;

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
        assert_eq!(
            set(second.as_fd(), LockKind::Write, LockRange::new(5, 20)).expect_err("overlapping"),
            Errno::AGAIN
        );
        set(second.as_fd(), LockKind::Write, LockRange::new(10, 20))
            .expect("disjoint ranges do not conflict");

        let conflict = test(second.as_fd(), LockKind::Write, LockRange::new(0, 4))
            .expect("testable")
            .expect("the first description holds it");
        assert_eq!(conflict.kind, LockKind::Write);
        assert_eq!(conflict.range, LockRange::new(0, 9));
        assert_eq!(conflict.pid, -1, "an OFD lock has no owning process");

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
