//! Every dispatch thread of the mount locks a priority-inheriting futex of its
//! own, in memory that the guardian maps too, before it reads its first request,
//! and the guardian waits to lock every one of them. A dispatch thread ends only
//! once the client can no longer reply to the mount. The kernel hands the futex
//! of a thread that ends to its waiter while it releases the futexes of the
//! thread, in `exit_mm` (`exit_pi_state_list`, `kernel/futex/core.c`). That
//! comes after every read the thread made has returned, and before the exit of
//! the thread drops its share of the files of the process (`exit_files`,
//! `kernel/exit.c`), so before the last thread to exit closes them. Once the
//! guardian has every futex, no thread reads a request any more and the exit has
//! closed no file yet. The guardian can then reply to every request the client
//! had read, and to the requests that closing a file of the mount sends, such as
//! the flush of a file the client has open on its own mount, which the exit
//! waits for. A pidfd becomes readable only once the exit is past closing the
//! files.
//!
//! The guardian follows only a lifeline whose every futex is locked, since it
//! would lock a futex that no thread has locked yet at once. A dispatch thread
//! may end before the guardian follows the lifeline. The kernel hands a futex
//! over only to a waiter, so the futex of that thread still contains its thread
//! ID, and the guardian counts the thread as ended. This needs the guardian in
//! the PID namespace of the client. The kernel may give the thread ID of a
//! holder that has exited to a new thread, and a guardian that waits on the
//! futex only after that would wait for the new thread. So every dispatch thread
//! also hands the guardian a pidfd of itself, which becomes readable once it has
//! exited, and a dispatch thread counts as ended once either shows it.

use std::ffi::c_void;
use std::io;
use std::num::NonZeroUsize;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::thread::JoinHandle;

use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::{MemfdFlags, fstat, ftruncate, memfd_create};
use rustix::io::Errno;
use rustix::io::retry_on_intr;
use rustix::mm::{MapFlags, ProtFlags, mmap, munmap};
use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
use rustix::process::{PidfdFlags, pidfd_open};
use rustix::thread::{futex, gettid};

#[derive(Debug, thiserror::Error)]
pub enum LifelineError {
    #[error("the memory of the lifeline failed")]
    Memory(#[source] Errno),
    #[error("the memory of the lifeline could not be shared")]
    Share(#[source] io::Error),
    #[error("the memory of the lifeline could not be mapped")]
    Map(#[source] Errno),
    #[error("the lifeline has no futex for dispatch thread {0}")]
    NoFutex(usize),
    #[error("a futex of the lifeline failed")]
    Futex(#[source] Errno),
    #[error("a pidfd of a dispatch thread could not be opened")]
    Pidfd(#[source] Errno),
    #[error("the memory of the lifeline is {0} bytes, which is no whole number of futexes")]
    Size(i64),
    #[error("the lifeline has {futexes} futexes for {threads} dispatch threads")]
    Count { futexes: usize, threads: usize },
    #[error("a dispatch thread of the mount does not hold its futex of the lifeline")]
    Unheld,
    #[error("a socket of the watch of the dispatch threads could not be made")]
    Socket(#[source] Errno),
    #[error("a thread of the watch of the dispatch threads could not be started")]
    Thread(#[source] io::Error),
    #[error("the dispatch threads could not be polled")]
    Poll(#[source] Errno),
    #[error("the wait for a dispatch thread of the mount panicked")]
    WaitPanicked,
}

#[derive(Debug)]
pub(super) struct Lifeline {
    memory: OwnedFd,
    threads: NonZeroUsize,
}

impl Lifeline {
    pub(super) fn new(threads: NonZeroUsize) -> Result<Self, LifelineError> {
        let memory = memfd_create("voidport-lifeline", MemfdFlags::CLOEXEC)
            .map_err(LifelineError::Memory)?;
        ftruncate(&memory, (threads.get() * size_of::<AtomicU32>()) as u64)
            .map_err(LifelineError::Memory)?;
        Ok(Self { memory, threads })
    }

    pub(super) fn memory(&self) -> Result<OwnedFd, LifelineError> {
        self.memory.try_clone().map_err(LifelineError::Share)
    }

    /// The mapping is needed only to take the futex: the kernel hands it over at
    /// the end of the thread without reading it.
    pub(super) fn hold(&self, index: usize) -> Result<OwnedFd, LifelineError> {
        let mapping = Mapping::new(&self.memory, self.threads.get())?;
        let futex = mapping
            .futexes()
            .get(index)
            .ok_or(LifelineError::NoFutex(index))?;
        futex::lock_pi(futex, futex::Flags::empty(), None).map_err(LifelineError::Futex)?;
        pidfd_open(gettid(), PidfdFlags::from_bits_retain(libc::PIDFD_THREAD))
            .map_err(LifelineError::Pidfd)
    }
}

#[derive(Debug)]
pub(super) struct Waiting {
    pub(super) gone: OwnedFd,
    pub(super) watcher: JoinHandle<Result<(), LifelineError>>,
}

/// A futex cannot be polled: a thread waits on each futex, and its end of a
/// socket pair closes when it returns. A watcher polls those sockets and the
/// pidfds, and its end of `gone` closes once every dispatch thread has ended. A
/// wait on the futex of a thread that had exited before it began may wait for a
/// new thread with that ID: it ends with that thread or with this process, and
/// the watcher does not wait for it.
pub(super) fn follow(memory: OwnedFd, threads: Vec<OwnedFd>) -> Result<Waiting, LifelineError> {
    let bytes = fstat(&memory).map_err(LifelineError::Memory)?.st_size;
    let size = usize::try_from(bytes).map_err(|_| LifelineError::Size(bytes))?;
    let futexes = size / size_of::<AtomicU32>();
    if futexes == 0 || size % size_of::<AtomicU32>() != 0 {
        return Err(LifelineError::Size(bytes));
    }
    if futexes != threads.len() {
        return Err(LifelineError::Count {
            futexes,
            threads: threads.len(),
        });
    }
    let mapping = Mapping::new(&memory, futexes)?;
    for futex in mapping.futexes() {
        match futex::trylock_pi(futex, futex::Flags::empty()) {
            // Locked by its dispatch thread, which runs or has ended.
            Err(Errno::WOULDBLOCK | HOLDER_ENDED) => {}
            Ok(_) => return Err(LifelineError::Unheld),
            Err(errno) => return Err(LifelineError::Futex(errno)),
        }
    }
    drop(mapping);
    let memory = Arc::new(memory);
    let dispatch_threads = threads
        .into_iter()
        .enumerate()
        .map(|(index, pidfd)| {
            let (handed_over, waiter) = pair()?;
            let memory = Arc::clone(&memory);
            let wait = std::thread::Builder::new()
                .name("voidport-lifeline".to_owned())
                .spawn(move || {
                    let _waiter = waiter;
                    wait(&memory, futexes, index)
                })
                .map_err(LifelineError::Thread)?;
            Ok(DispatchThread {
                handed_over,
                pidfd,
                wait,
            })
        })
        .collect::<Result<Vec<_>, LifelineError>>()?;
    let (gone, watching) = pair()?;
    let watcher = std::thread::Builder::new()
        .name("voidport-lifeline".to_owned())
        .spawn(move || {
            let _watching = watching;
            watch(dispatch_threads)
        })
        .map_err(LifelineError::Thread)?;
    Ok(Waiting { gone, watcher })
}

struct DispatchThread {
    handed_over: OwnedFd,
    pidfd: OwnedFd,
    wait: JoinHandle<Result<(), LifelineError>>,
}

impl DispatchThread {
    fn polled(&self) -> [PollFd<'_>; 2] {
        [
            PollFd::new(&self.handed_over, PollFlags::IN),
            PollFd::new(&self.pidfd, PollFlags::IN),
        ]
    }

    fn join(self) -> Result<(), LifelineError> {
        self.wait.join().map_err(|_| LifelineError::WaitPanicked)?
    }
}

/// A wait whose thread was seen to exit through its pidfd first is not joined:
/// it waits on a thread that took over the ID of the exited one, or returns at
/// once where no thread did. A wait on a priority-inheriting futex restarts
/// after a signal and ends only with the thread it waits on, so nothing here
/// can end it, and a join could wait for a thread of another program. It ends
/// at the latest with the guardian.
fn watch(mut threads: Vec<DispatchThread>) -> Result<(), LifelineError> {
    let mut failed = Ok(());
    while !threads.is_empty() {
        let seen: Vec<(bool, bool)> = {
            let mut ready: Vec<PollFd<'_>> =
                threads.iter().flat_map(DispatchThread::polled).collect();
            retry_on_intr(|| poll(&mut ready, None)).map_err(LifelineError::Poll)?;
            let readable = |fd: &PollFd<'_>| !fd.revents().is_empty();
            ready
                .chunks(2)
                .map(|fds| (readable(&fds[0]), readable(&fds[1])))
                .collect()
        };
        let mut running = Vec::with_capacity(threads.len());
        for (thread, (handed_over, exited)) in threads.into_iter().zip(seen) {
            if handed_over {
                failed = failed.and(thread.join());
            } else if !exited {
                running.push(thread);
            }
        }
        threads = running;
    }
    failed
}

fn pair() -> Result<(OwnedFd, OwnedFd), LifelineError> {
    socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(LifelineError::Socket)
}

/// A lock of a futex fails with this error when its holder had ended before the
/// lock: no thread with the ID in the futex exists any more, or that thread has
/// released its futexes (`handle_exit_race`, `kernel/futex/pi.c`).
const HOLDER_ENDED: Errno = Errno::SRCH;

fn wait(memory: &OwnedFd, futexes: usize, index: usize) -> Result<(), LifelineError> {
    let mapping = Mapping::new(memory, futexes)?;
    match futex::lock_pi(&mapping.futexes()[index], futex::Flags::empty(), None) {
        // The kernel handed the futex over, or the thread had ended before
        // this one waited.
        Ok(()) | Err(HOLDER_ENDED) => Ok(()),
        Err(errno) => Err(LifelineError::Futex(errno)),
    }
}

struct Mapping {
    start: *mut c_void,
    futexes: usize,
}

impl Mapping {
    fn new(memory: &OwnedFd, futexes: usize) -> Result<Self, LifelineError> {
        // SAFETY: Unavoidable: std maps no memory, and rustix maps it only
        // through this `unsafe` call. A new mapping at an address the kernel
        // picks overlaps no memory this process uses.
        let start = unsafe {
            mmap(
                std::ptr::null_mut(),
                futexes * size_of::<AtomicU32>(),
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED,
                memory,
                0,
            )
            .map_err(LifelineError::Map)?
        };
        Ok(Self { start, futexes })
    }

    fn futexes(&self) -> &[AtomicU32] {
        // SAFETY: Unavoidable: a mapping is raw memory, and std makes a slice
        // of raw memory only through `from_raw_parts`. The mapping holds
        // `futexes` futexes from its start, which the page aligns, until `self`
        // is dropped, and every process that maps the memory accesses them only
        // atomically.
        unsafe { std::slice::from_raw_parts(self.start.cast::<AtomicU32>(), self.futexes) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: Unavoidable: rustix unmaps memory only through this `unsafe`
        // call, and closing the descriptor leaves the mapping in place. The
        // mapping was made by `new` with this length, and no reference into it
        // outlives `self`.
        let unmapped = unsafe { munmap(self.start, self.futexes * size_of::<AtomicU32>()) };
        debug_assert!(unmapped.is_ok(), "a mapping that was made unmaps");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::io::retry_on_intr;

    use super::*;

    fn lifeline_of_two() -> Arc<Lifeline> {
        Arc::new(Lifeline::new(NonZeroUsize::new(2).expect("2 is not zero")).expect("a lifeline"))
    }

    fn dispatch_thread(
        lifeline: &Arc<Lifeline>,
        index: usize,
    ) -> (mpsc::Sender<()>, JoinHandle<()>, OwnedFd) {
        let lifeline = Arc::clone(lifeline);
        let (held, holding) = mpsc::channel();
        let (end, ending) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            held.send(lifeline.hold(index)).expect("the test waits");
            let _sent_or_dropped_either_ends_the_hold = ending.recv();
        });
        let pidfd = holding
            .recv()
            .expect("the thread reports")
            .expect("the thread holds its futex");
        (end, thread, pidfd)
    }

    fn readable(gone: &OwnedFd) -> bool {
        let mut ready = [PollFd::new(gone, PollFlags::IN)];
        retry_on_intr(|| poll(&mut ready, Some(&Timespec::default()))).expect("a poll") > 0
    }

    #[test]
    fn the_guardian_waits_until_every_dispatch_thread_has_ended() {
        let lifeline = lifeline_of_two();
        let (end_first, first, first_pidfd) = dispatch_thread(&lifeline, 0);
        let (end_last, last, last_pidfd) = dispatch_thread(&lifeline, 1);
        let Waiting { gone, watcher } = follow(
            lifeline.memory().expect("the memory"),
            vec![first_pidfd, last_pidfd],
        )
        .expect("the lifeline is followed");

        drop(end_first);
        first.join().expect("the first thread ends");
        assert!(
            !readable(&gone),
            "a dispatch thread still runs, so the guardian waits"
        );
        drop(end_last);
        last.join().expect("the last thread ends");
        retry_on_intr(|| poll(&mut [PollFd::new(&gone, PollFlags::IN)], None))
            .expect("every dispatch thread has ended");
        watcher
            .join()
            .expect("the watch ends")
            .expect("every futex was handed over");
    }

    #[test]
    fn a_dispatch_thread_that_ended_before_the_guardian_followed_it_counts_as_ended() {
        let lifeline = lifeline_of_two();
        let (end_first, first, first_pidfd) = dispatch_thread(&lifeline, 0);
        drop(end_first);
        first.join().expect("the first thread ends");
        let (end_last, last, last_pidfd) = dispatch_thread(&lifeline, 1);
        let Waiting { gone, watcher } = follow(
            lifeline.memory().expect("the memory"),
            vec![first_pidfd, last_pidfd],
        )
        .expect("the lifeline is followed");

        assert!(
            !readable(&gone),
            "the last dispatch thread still runs, so the guardian waits"
        );
        drop(end_last);
        last.join().expect("the last thread ends");
        retry_on_intr(|| poll(&mut [PollFd::new(&gone, PollFlags::IN)], None))
            .expect("every dispatch thread has ended");
        watcher
            .join()
            .expect("the watch ends")
            .expect("no wait on a futex failed");
    }

    #[test]
    fn a_lifeline_that_a_dispatch_thread_does_not_hold_yet_is_not_followed() {
        let lifeline = lifeline_of_two();
        let (_end, _thread, pidfd) = dispatch_thread(&lifeline, 0);

        assert!(follow(lifeline.memory().expect("the memory"), vec![pidfd]).is_err());
    }
}
