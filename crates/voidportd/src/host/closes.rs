//! A file whose lease was broken by another writer can be leased again once that
//! writer is done. The watch reports a close after a write (`IN_CLOSE_WRITE`),
//! a write (`IN_MODIFY`) and an attribute change (`IN_ATTRIB`), which is what a
//! truncate by path reports besides its write. A write lease is broken by
//! readers too, so only its watch asks for a close without a write
//! (`IN_CLOSE_NOWRITE`). A watch is added through the `/proc/self/fd` link of a
//! descriptor, so it points at the very inode that descriptor is open on.

use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::inotify::{self, CreateFlags, ReadFlags, WatchFlags};
use rustix::io::Errno;
use tokio::io::unix::AsyncFd;

use crate::host::lease::Kind;

#[derive(Debug)]
pub struct Closes {
    inotify: OwnedFd,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WatchId(i32);

#[derive(Debug, Default)]
pub struct Closed {
    pub changed: Vec<WatchId>,
    pub lost: Vec<WatchId>,
    /// Events were lost, so any watched file may have changed.
    pub overflowed: bool,
}

impl Closes {
    /// # Errors
    ///
    /// The error of `inotify_init1(2)`.
    pub fn new() -> io::Result<Self> {
        let inotify = inotify::init(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK)?;
        Ok(Self { inotify })
    }

    /// Every descriptor of one inode gets the one watch, which reports the
    /// changes every lease waiting through it asks for.
    ///
    /// # Errors
    ///
    /// The error of `inotify_add_watch(2)`.
    pub fn watch(&self, file: BorrowedFd<'_>, kind: Kind) -> io::Result<WatchId> {
        let link = format!("/proc/self/fd/{}", file.as_raw_fd());
        let mut changes = WatchFlags::CLOSE_WRITE
            | WatchFlags::MODIFY
            | WatchFlags::ATTRIB
            | WatchFlags::MASK_ADD;
        if kind == Kind::Write {
            changes |= WatchFlags::CLOSE_NOWRITE;
        }
        Ok(WatchId(inotify::add_watch(&self.inotify, link, changes)?))
    }

    /// Stops watching `watch`. A watch the kernel removed already, because its
    /// file was deleted, is no error.
    pub fn unwatch(&self, watch: WatchId) {
        if let Err(errno) = inotify::remove_watch(&self.inotify, watch.0) {
            tracing::debug!(%errno, "a watch was gone when it was removed");
        }
    }

    /// Runs on a runtime with I/O enabled.
    ///
    /// # Errors
    ///
    /// The error of reading the instance, which ends the reading.
    pub async fn read(&self, mut closed: impl FnMut(Closed)) -> io::Result<()> {
        let events = AsyncFd::new(self.inotify.try_clone()?)?;
        let mut buffer = [MaybeUninit::<u8>::uninit(); 4096];
        loop {
            let mut ready = events.readable().await?;
            let mut seen = Closed::default();
            let mut reader = inotify::Reader::new(events.get_ref().as_fd(), &mut buffer);
            loop {
                match reader.next() {
                    Ok(event) if event.events().contains(ReadFlags::QUEUE_OVERFLOW) => {
                        seen.overflowed = true;
                    }
                    Ok(event) if event.events().contains(ReadFlags::IGNORED) => {
                        seen.lost.push(WatchId(event.wd()));
                    }
                    Ok(event) => seen.changed.push(WatchId(event.wd())),
                    Err(Errno::AGAIN) => {
                        ready.clear_ready();
                        break;
                    }
                    Err(Errno::INTR) => {}
                    Err(errno) => return Err(errno.into()),
                }
            }
            closed(seen);
        }
    }
}
