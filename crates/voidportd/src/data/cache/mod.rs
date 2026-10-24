//! A guest may cache the pages of a file across opens only while the server
//! has a lease on the host file ([`crate::host::lease`]): a read lease shows
//! that nobody else writes the file, and a write lease that nobody else has it
//! open.
//!
//! Every handle of the session on a file reads and writes it through one
//! description, cached or not ([`FileCache::open`]), so no handle of the
//! session blocks the lease. It is opened for reading while the session only
//! reads, and again for reading and writing once it writes, and the locks of
//! the session move to it ([`FileLocks::move_to`]).
//!
//! A lease is given up only once the guest has dropped the pages it caches
//! under it: the server recalls them ([`crate::data::recall`]), and gives the
//! lease up when the guest replies, or once the window granted to the guest has
//! surely passed. A session that ended can no longer be recalled, so its leases
//! remain until that window has passed ([`Leases::linger`]).
//!
//! After a break, every request of the session that reads or writes the file
//! waits in the server until the lease is gained again, those of its uncached
//! handles included, since a private mapping of an uncached handle reads into
//! the page cache the cached handles share (`fuse_file_mmap`), and its read
//! cannot be told from another. An open meanwhile caches no pages, so that its
//! handle never extends the wait: the opener the handles wait for may itself
//! wait for a request of that handle. A file whose changes cannot be watched
//! delays nothing: the waiting requests fail with `EIO` instead.

mod grant;
mod lease;
mod recall;
#[cfg(test)]
mod tests;

use std::ops::{Deref, DerefMut};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rustix::fs::OFlags;
use rustix::io::Errno;
use tokio::sync::Notify;

use grant::Until;
pub use grant::{Grant, Postponed, Unserved};
pub use lease::Pages;
use lease::{Kept, Lease, Then};

use crate::data::descriptor_budget::LeaseHolder;
use crate::data::leases::{LeaseFile, Leases};
use crate::data::locks::FileLocks;
use crate::data::recall::Recalls;
use crate::host::attr::NodeIdentity;
use crate::host::lease::Kind;
use crate::host::{Description, Transfer};

#[derive(Debug)]
pub struct FileCache {
    node_id: u64,
    identity: NodeIdentity,
    recalls: Arc<Recalls>,
    leases: Arc<Leases>,
    state: Mutex<State>,
    /// What the session has of the file, as the other caches of the file see it
    /// without locking this one: [`HOLDS_READ`], [`HOLDS_WRITE`] and [`WAITS`].
    presence: AtomicU8,
    changed: Notify,
}

#[derive(Debug, Default)]
struct State {
    lease: Lease,
    handles: usize,
    cached: usize,
    epoch: u64,
    /// How many opens wait to read or write the file in a way the description of
    /// the session does not.
    widening: usize,
    pin: Option<Arc<OwnedFd>>,
}

const HOLDS_READ: u8 = 1;
const HOLDS_WRITE: u8 = 2;
const WAITS: u8 = 4;

fn presence(lease: &Lease) -> u8 {
    let holds = match lease.holds() {
        None => 0,
        Some(Kind::Read) => HOLDS_READ,
        Some(Kind::Write) => HOLDS_WRITE,
    };
    let waits = if matches!(lease, Lease::Waiting { .. }) {
        WAITS
    } else {
        0
    };
    holds | waits
}

/// The state of a cache, locked. Its presence is published when the lock is
/// released.
struct Locked<'a> {
    cache: &'a FileCache,
    state: MutexGuard<'a, State>,
}

impl Deref for Locked<'_> {
    type Target = State;

    fn deref(&self) -> &State {
        &self.state
    }
}

impl DerefMut for Locked<'_> {
    fn deref_mut(&mut self) -> &mut State {
        &mut self.state
    }
}

impl Drop for Locked<'_> {
    fn drop(&mut self) {
        self.cache
            .presence
            .store(presence(&self.state.lease), Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Access {
    read: bool,
    write: bool,
}

impl Access {
    fn wanted(flags: OFlags) -> Self {
        Self {
            read: !flags.contains(OFlags::WRONLY),
            write: flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::TRUNC),
        }
    }

    fn of(mode: OFlags) -> Self {
        Self {
            read: !mode.contains(OFlags::WRONLY),
            write: mode.intersects(OFlags::WRONLY | OFlags::RDWR),
        }
    }

    fn covers(self, other: Self) -> bool {
        (self.read || !other.read) && (self.write || !other.write)
    }

    fn and(self, other: Self) -> Self {
        Self {
            read: self.read || other.read,
            write: self.write || other.write,
        }
    }

    fn kind(self) -> Kind {
        if self.write { Kind::Write } else { Kind::Read }
    }
}

fn open_for(pinned: BorrowedFd<'_>, access: Access) -> Result<Arc<Description>, Errno> {
    if !access.write {
        return Description::open(pinned, OFlags::RDONLY);
    }
    match Description::open(pinned, OFlags::RDWR) {
        Err(Errno::ACCESS) if !access.read => Description::open(pinned, OFlags::WRONLY),
        opened => opened,
    }
}

impl FileCache {
    #[must_use]
    pub fn new(
        node_id: u64,
        identity: NodeIdentity,
        recalls: &Arc<Recalls>,
        leases: &Arc<Leases>,
    ) -> Arc<Self> {
        let cache = Arc::new(Self {
            node_id,
            identity,
            recalls: Arc::clone(recalls),
            leases: Arc::clone(leases),
            state: Mutex::default(),
            presence: AtomicU8::new(0),
            changed: Notify::new(),
        });
        leases.join(identity, &cache);
        cache
    }

    /// Every other cache of the file whose lease excludes the open makes way
    /// first. A session with a lease recalls its pages before it opens the file
    /// again, so that its own description does not break its lease.
    pub fn open(
        self: &Arc<Self>,
        pinned: &Arc<OwnedFd>,
        flags: OFlags,
        locks: &FileLocks,
        created: Option<OwnedFd>,
    ) -> Result<Grant, Unserved> {
        let transfer = Transfer::of(pinned.as_fd(), flags)?;
        let wanted = Access::wanted(flags);
        let reopened = self.locked().reopens();
        self.make_way(reopened.map_or(wanted, |access| access.and(wanted)).kind())?;
        let mut asked = None;
        let opened = {
            let mut state = self.locked();
            let opened = self
                .opened(&mut state, pinned, flags, locks, created)
                .and_then(|()| {
                    if self.recalls.reachable() {
                        asked = self.lease(&mut state);
                    }
                    self.truncate(&state, flags)
                });
            if opened.is_err() {
                state.close_if_unused();
            }
            opened.map(|()| self.grant(&mut state, transfer))
        };
        // Outside the lock: giving a lease back locks its cache.
        if let Some(holder) = asked {
            holder.give_back();
        }
        opened
    }

    fn opened(
        self: &Arc<Self>,
        state: &mut State,
        pinned: &Arc<OwnedFd>,
        flags: OFlags,
        locks: &FileLocks,
        created: Option<OwnedFd>,
    ) -> Result<(), Unserved> {
        let wanted = Access::wanted(flags);
        let widens = state
            .lease
            .access()
            .is_some_and(|access| !Access::of(access).covers(wanted));
        match state.lease {
            Lease::Held { .. } if widens => {
                self.recall(state, Then::Release);
                return Err(self.widening(state));
            }
            Lease::Recalling { .. } if widens => return Err(self.widening(state)),
            _ => {}
        }
        state.pin = Some(Arc::clone(pinned));
        if let Some(description) = self.describe(state, pinned.as_fd(), wanted, created)? {
            locks.move_to(&description)?;
            if flags.contains(OFlags::DIRECT) {
                description.accept(true)?;
            }
        }
        Ok(())
    }

    fn truncate(self: &Arc<Self>, state: &State, flags: OFlags) -> Result<(), Unserved> {
        if !flags.contains(OFlags::TRUNC) {
            return Ok(());
        }
        let description = state.lease.description().ok_or_else(|| {
            self.postponed(Until::Usable {
                through: Pages::Uncached,
            })
        })?;
        Ok(rustix::fs::ftruncate(description.fd(), 0)?)
    }

    fn describe(
        self: &Arc<Self>,
        state: &mut State,
        pinned: BorrowedFd<'_>,
        wanted: Access,
        created: Option<OwnedFd>,
    ) -> Result<Option<Arc<Description>>, Errno> {
        state.resume()?;
        match &mut state.lease {
            Lease::Closed => {
                let description = match created {
                    Some(fd) => Description::of(fd, OFlags::RDWR),
                    None => open_for(pinned, wanted)?,
                };
                state.lease = Lease::Open(Arc::clone(&description));
                Ok(Some(description))
            }
            Lease::Open(description) => {
                let held = Access::of(description.access());
                if !held.covers(wanted) {
                    *description = open_for(pinned, held.and(wanted))?;
                }
                Ok(Some(Arc::clone(description)))
            }
            Lease::Waiting {
                access,
                kept,
                watch,
                ..
            } => {
                let held = Access::of(*access);
                if held.covers(wanted) {
                    return Ok(kept.description());
                }
                let description = open_for(pinned, held.and(wanted))?;
                let kind = Kind::of(description.access());
                if watch.is_some() && kind != Kind::of(*access) {
                    *watch = self.leases.watch(description.fd(), self, kind);
                }
                *access = description.access();
                *kept = Kept::Open(Arc::clone(&description));
                Ok(Some(description))
            }
            // A lease is placed on a description that supports the open: the
            // caller recalled one that does not.
            lease => Ok(lease.description().cloned()),
        }
    }

    /// Returns the lease that a full budget asks back for the slot. The caller
    /// gives it back outside the lock ([`LeaseHolder::give_back`]).
    fn lease(self: &Arc<Self>, state: &mut State) -> Option<Arc<dyn LeaseHolder>> {
        if !matches!(state.lease, Lease::Open(_)) {
            self.retake(state);
            return None;
        }
        let Lease::Open(description) = std::mem::take(&mut state.lease) else {
            return None;
        };
        match self.leases.slot(self) {
            Ok(slot) => {
                let file = LeaseFile::new(&self.leases, description, slot, self);
                state.lease = if self.leases.take(file.fd(), file.kind()).is_ok() {
                    state.epoch += 1;
                    Lease::Held {
                        file,
                        covered: false,
                    }
                } else {
                    Lease::Open(file.into_parts().0)
                };
                None
            }
            Err(holder) => {
                state.lease = Lease::Open(description);
                holder
            }
        }
    }

    fn make_way(&self, kind: Kind) -> Result<(), Unserved> {
        for other in self.leases.others(self.identity, self) {
            other.give_way(kind)?;
        }
        Ok(())
    }

    fn give_way(self: &Arc<Self>, kind: Kind) -> Result<(), Unserved> {
        let mut state = self.locked();
        let watch = match &mut state.lease {
            Lease::Held { file, .. } if file.kind().excludes(kind) => {
                self.leases.watch(file.fd(), self, file.kind())
            }
            Lease::Recalling { file, .. } if file.kind().excludes(kind) => {
                return Err(self.postponed(Until::Settled));
            }
            Lease::Waiting { kept, .. } => {
                if kept
                    .description()
                    .is_some_and(|description| Kind::of(description.access()).excludes(kind))
                {
                    kept.close();
                }
                return Ok(());
            }
            _ => return Ok(()),
        };
        self.recall(&mut state, Then::Break(watch));
        Err(self.postponed(Until::Settled))
    }

    fn requested(self: &Arc<Self>, taken: bool, epoch: u64) {
        let mut state = self.locked();
        if taken
            && state.epoch == epoch
            && let Lease::Held { covered, .. } = &mut state.lease
        {
            *covered = true;
        }
        self.retake(&mut state);
    }

    fn holds(&self) -> Option<Kind> {
        match self.presence.load(Ordering::SeqCst) & (HOLDS_READ | HOLDS_WRITE) {
            HOLDS_READ => Some(Kind::Read),
            HOLDS_WRITE => Some(Kind::Write),
            _ => None,
        }
    }

    fn waits(&self) -> bool {
        self.presence.load(Ordering::SeqCst) & WAITS != 0
    }

    fn others_wait(&self) -> bool {
        self.leases.arbitrate(self.identity, self, |others| {
            others.iter().any(|other| other.waits())
        })
    }

    fn locked(&self) -> Locked<'_> {
        Locked {
            cache: self,
            state: self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
        }
    }
}

impl LeaseHolder for FileCache {
    fn give_back(self: Arc<Self>) {
        let mut state = self.locked();
        if state.cached == 0 {
            self.recall(&mut state, Then::Release);
        }
    }
}

impl Drop for FileCache {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Lease::Recalling { recall, .. } = std::mem::take(&mut state.lease) {
            recall.close(&self.recalls);
        }
        self.leases.leave(self.identity);
    }
}

impl State {
    fn reopens(&self) -> Option<Access> {
        match &self.lease {
            Lease::Waiting { access, kept, .. }
                if self.cached == 0 && kept.description().is_none() =>
            {
                Some(Access::of(*access))
            }
            _ => None,
        }
    }

    fn resume(&mut self) -> Result<(), Errno> {
        let Lease::Waiting { access, kept, .. } = &self.lease else {
            return Ok(());
        };
        if self.cached > 0 {
            return Ok(());
        }
        let description = match kept.description() {
            Some(description) => description,
            None => {
                let pin = self.pin.as_ref().ok_or(Errno::BADF)?;
                Description::open(pin.as_fd(), *access)?
            }
        };
        self.lease = Lease::Open(description);
        Ok(())
    }

    fn close_if_unused(&mut self) {
        if self.handles > 0 {
            return;
        }
        self.pin = None;
        if matches!(self.lease, Lease::Open(_) | Lease::Waiting { .. }) {
            self.lease = Lease::Closed;
        }
    }
}
