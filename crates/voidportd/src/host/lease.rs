//! A read lease (`F_RDLCK`) proves that nobody else writes a file: the kernel
//! grants it only while nobody has the file open for writing, and an open for
//! writing or a truncate breaks it. A write lease (`F_WRLCK`) proves that nobody
//! else has the file open at all: the kernel grants it only on the one open
//! description of the file. A break makes the opener wait until the holder gives
//! the lease up or the lease break time has passed, and signals the holder.
//! [`take`] sets that signal with `F_SETSIG`, so it reports the descriptor the
//! lease was placed on, and sends it to the thread named by the caller. A
//! signal the kernel cannot queue arrives as a plain `SIGIO` that reports no
//! descriptor, so every lease then has to be asked whether it is breaking.
//!
//! Only the account that owns a file, or a holder of `CAP_LEASE`, may lease it.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::time::Duration;

use rustix::event::EventfdFlags;
use rustix::fs::OFlags;
use rustix::io::Errno;
use rustix::net::SendFlags;
use rustix::process::Pid;
use signal_hook_registry::SigId;

/// A real-time signal, because those queue, one per break, with the descriptor
/// of each.
fn break_signal() -> libc::c_int {
    libc::SIGRTMIN()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Read,
    Write,
}

impl Kind {
    /// A write lease for a description opened for writing, since the kernel
    /// rejects a read lease while the file is open for writing.
    #[must_use]
    pub fn of(flags: OFlags) -> Self {
        if flags.intersects(OFlags::WRONLY | OFlags::RDWR) {
            Self::Write
        } else {
            Self::Read
        }
    }

    #[must_use]
    pub fn excludes(self, other: Self) -> bool {
        self == Self::Write || other == Self::Write
    }

    fn lock_type(self) -> libc::c_int {
        match self {
            Self::Read => libc::F_RDLCK,
            Self::Write => libc::F_WRLCK,
        }
    }
}

/// A read lease needs a descriptor open for reading. The break signal goes to
/// the thread `signalled`.
///
/// # Errors
///
/// The host errno: `EAGAIN` while the file is open for writing, or for a
/// write lease while it is open anywhere else, `EACCES` for a file of
/// another account without `CAP_LEASE`, `ESRCH` when `signalled` is no
/// thread, and whatever a filesystem that has no leases returns.
pub fn take(file: BorrowedFd<'_>, kind: Kind, signalled: Pid) -> Result<(), Errno> {
    let signal = linux_raw_sys::general::F_SETSIG as libc::c_int;
    fcntl(file, signal, break_signal())?;
    fcntl(file, libc::F_SETLEASE, kind.lock_type())?;
    // Each lease added by `F_SETLEASE` sends its break signal to the calling
    // thread (`lease_setup`, `fs/locks.c`). The kernel drops that signal once
    // the thread has ended, and delays it while the thread sleeps
    // uninterruptibly, so the opener would wait out the lease break time. A
    // break before the next call goes to the calling thread, which is running.
    signal_thread(file, signalled).inspect_err(|_| give_up(file))
}

fn signal_thread(file: BorrowedFd<'_>, thread: Pid) -> Result<(), Errno> {
    let signalled = linux_raw_sys::general::f_owner_ex {
        type_: linux_raw_sys::general::F_OWNER_TID as libc::c_int,
        pid: thread.as_raw_nonzero().get(),
    };
    let command = linux_raw_sys::general::F_SETOWN_EX as libc::c_int;
    // SAFETY: Unavoidable: rustix and libc have no `F_SETOWN_EX`. The kernel
    // copies the `f_owner_ex` behind the pointer during the call and keeps no
    // pointer. `signalled` lives until the call returns, and `file` is a valid
    // descriptor for the duration of the borrow.
    checked(unsafe { libc::fcntl(file.as_raw_fd(), command, &raw const signalled) })
}

/// While a break runs, the kernel returns the type the lease is being broken
/// to (`target_leasetype`, `fs/locks.c`): `F_UNLCK` for a read lease, and
/// `F_RDLCK` or `F_UNLCK` for a write lease, as the opener reads or writes.
#[must_use]
pub fn is_broken(file: BorrowedFd<'_>, kind: Kind) -> bool {
    // SAFETY: Unavoidable: the `fcntl_*` functions of rustix, the safe forms,
    // have no lease command. `F_GETLEASE` takes no argument besides the
    // descriptor, and `file` is a valid descriptor for the duration of the
    // borrow.
    let held = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLEASE) };
    held != kind.lock_type()
}

/// A lease that the kernel already removed is no error.
pub fn give_up(file: BorrowedFd<'_>) {
    if let Err(errno) = fcntl(file, libc::F_SETLEASE, libc::F_UNLCK) {
        tracing::debug!(%errno, "a lease was already gone when it was given up");
    }
}

/// # Errors
///
/// The error of reading `/proc/sys/fs/lease-break-time`, or of a value that is
/// not a whole number of seconds.
pub fn break_time() -> io::Result<Duration> {
    let seconds = std::fs::read_to_string("/proc/sys/fs/lease-break-time")?;
    seconds
        .trim()
        .parse()
        .map(Duration::from_secs)
        .map_err(io::Error::other)
}

#[derive(Debug)]
pub struct Breaks {
    descriptors: UnixDatagram,
    /// An eventfd that counts the breaks whose descriptor did not arrive: one
    /// the full socket did not take, and every plain `SIGIO`.
    unknown: OwnedFd,
    actions: [SigId; 2],
}

impl Breaks {
    /// Installs the actions of the break signal and of `SIGIO`. Each call adds
    /// actions that only the returned [`Breaks`] reads.
    ///
    /// # Errors
    ///
    /// The error of making the socket pair or the eventfd, or of installing an
    /// action.
    pub fn install() -> io::Result<Self> {
        let (sender, descriptors) = UnixDatagram::pair()?;
        sender.set_nonblocking(true)?;
        let unknown = rustix::event::eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)?;
        let counter = Arc::new(unknown.try_clone()?);
        let lost = Arc::clone(&counter);
        let broken = move |info: &libc::siginfo_t| {
            let file = descriptor_of(info);
            // A raw `send(2)`, which sets no errno and locks nothing, so it
            // may run in a signal action on any thread of the process.
            if rustix::net::send(&sender, &file.to_ne_bytes(), SendFlags::DONTWAIT).is_err() {
                count(&counter);
            }
        };
        // SAFETY: Unavoidable: the safe form, the signal iterator of
        // `signal-hook` with the `WithRawSiginfo` exfiltrator, queues at most
        // five `siginfo`s and silently drops the rest, so a break would lose
        // its descriptor without being counted. The action is
        // async-signal-safe: it reads the `siginfo` it is handed and makes one
        // `send(2)` on a socket moved into it, and at most one `write(2)` on an
        // eventfd moved into it. It allocates nothing and locks nothing.
        let broken = unsafe { signal_hook_registry::register_sigaction(break_signal(), broken) }?;
        // SAFETY: Unavoidable: `signal_hook::flag::register`, the safe form,
        // sets a flag that nothing can wait on, and the server waits until the
        // eventfd becomes readable. As above, with the one `write(2)` alone.
        let plain = unsafe {
            signal_hook_registry::register_sigaction(libc::SIGIO, move |_: &libc::siginfo_t| {
                count(&lost);
            })
        };
        let plain = plain.inspect_err(|_| {
            signal_hook_registry::unregister(broken);
        })?;
        Ok(Self {
            descriptors,
            unknown,
            actions: [broken, plain],
        })
    }

    /// The socket the descriptors of broken leases arrive on, each as the four
    /// bytes of a native-endian `i32`.
    #[must_use]
    pub fn descriptors(&self) -> &UnixDatagram {
        &self.descriptors
    }

    /// Becomes readable when a break arrived without its descriptor. Reading it
    /// resets it.
    #[must_use]
    pub fn unknown(&self) -> BorrowedFd<'_> {
        self.unknown.as_fd()
    }
}

impl Drop for Breaks {
    fn drop(&mut self) {
        for action in self.actions {
            signal_hook_registry::unregister(action);
        }
    }
}

/// A raw `write(2)` sets no errno and locks nothing, and a counter that is full
/// already counts.
fn count(unknown: &OwnedFd) {
    let _ = rustix::io::write(unknown, &1u64.to_ne_bytes());
}

/// The descriptor reported by a lease break signal: `si_fd` of a
/// `SIGPOLL`-class `siginfo`, which `F_SETSIG` makes the break signal carry.
fn descriptor_of(info: &libc::siginfo_t) -> RawFd {
    let info = std::ptr::from_ref(info).cast::<linux_raw_sys::general::siginfo_t>();
    // SAFETY: Unavoidable: `siginfo_t` of libc has no accessor for `si_fd`, and
    // a union member is read only in `unsafe` code. `siginfo_t` of the C
    // library and `siginfo` of the kernel are the same 128 bytes with the
    // same alignment, so the cast reads the memory the kernel wrote. Every bit
    // pattern is a valid `c_int`, so reading the union member is defined
    // whichever member the kernel filled; for this signal it filled `_sigpoll`.
    unsafe {
        (*info)
            .__bindgen_anon_1
            .__bindgen_anon_1
            ._sifields
            ._sigpoll
            ._fd
    }
}

fn fcntl(file: BorrowedFd<'_>, command: libc::c_int, argument: libc::c_int) -> Result<(), Errno> {
    // SAFETY: Unavoidable: the `fcntl_*` functions of rustix, the safe forms,
    // have neither `F_SETSIG` nor a lease command. `F_SETSIG` and `F_SETLEASE`
    // take an `int` as their variadic argument, and `file` is a valid
    // descriptor for the duration of the borrow. The kernel stores no pointer.
    checked(unsafe { libc::fcntl(file.as_fd().as_raw_fd(), command, argument) })
}

fn checked(returned: libc::c_int) -> Result<(), Errno> {
    if returned < 0 {
        return Err(Errno::from_raw_os_error(
            io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::os::fd::{AsFd, AsRawFd, RawFd};
    use std::os::unix::fs::OpenOptionsExt;

    use rustix::event::{PollFd, PollFlags};
    use rustix::net::RecvFlags;
    use rustix::process::{Signal, getpid, kill_process};
    use voidport_test_host::Scratch;

    use super::{Breaks, Kind, give_up, take};

    #[test]
    fn a_break_signals_the_thread_named_at_take_after_the_taking_thread_ended() {
        let breaks = Breaks::install().expect("the actions install");
        let scratch = Scratch::new("lease-signalled-thread");
        let path = scratch.file("leased", b"data");
        let leased = File::open(&path).expect("readable");
        let signalled = rustix::thread::gettid();
        std::thread::scope(|scope| {
            scope
                .spawn(|| take(leased.as_fd(), Kind::Read, signalled))
                .join()
        })
        .expect("the thread that takes the lease ends")
        .expect("the scratch filesystem grants a lease");

        // The open starts the break and fails at once. The kernel sends the
        // break signal inside the open, and this thread runs its action on the
        // way back.
        let opened = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path);
        assert_eq!(
            opened.err().and_then(|error| error.raw_os_error()),
            Some(libc::EWOULDBLOCK),
            "the open breaks the lease"
        );
        let reported: Vec<RawFd> = std::iter::from_fn(|| {
            let mut datagram = [0u8; size_of::<RawFd>()];
            rustix::net::recv(breaks.descriptors(), &mut datagram, RecvFlags::DONTWAIT)
                .ok()
                .map(|_| RawFd::from_ne_bytes(datagram))
        })
        .collect();
        give_up(leased.as_fd());
        assert!(
            reported.contains(&leased.as_raw_fd()),
            "the break reports the leased descriptor"
        );
    }

    #[test]
    fn a_plain_sigio_counts_as_a_break_whose_descriptor_did_not_arrive() {
        let breaks = Breaks::install().expect("the actions install");
        kill_process(getpid(), Signal::IO).expect("the signal is sent");

        // The action runs on whichever thread the kernel picks, and the
        // eventfd is readable once it has run.
        let mut unknown = [PollFd::new(&breaks.unknown, PollFlags::IN)];
        rustix::event::poll(&mut unknown, None).expect("the eventfd is polled");
        let mut counted = [0u8; 8];
        rustix::io::read(breaks.unknown(), &mut counted).expect("the count reads");
        assert_ne!(u64::from_ne_bytes(counted), 0, "the break is counted");
    }
}
