//! The record locks a session holds, one set per host file.
//!
//! POSIX gives a record lock to its owner for the whole file, whichever
//! descriptor placed it: a process that locks a file through one descriptor and
//! then through another holds one set of locks, the second request merges with
//! the first instead of conflicting with it, and closing either descriptor
//! releases them all. The wire names that owner, so the server keeps its locks
//! per file and owner, never per handle.
//!
//! They are carried by OFD locks (see [`crate::host::lock`]), which belong to
//! an open file description, and probing showed that two owners sharing one
//! description have their locks *coalesce* instead of conflicting. So each
//! owner gets a description of its own, opened on its first lock and closed
//! once it holds nothing and no blocking request of the owner waits on it;
//! closing a description releases exactly its own locks and nothing else's.
//! Every handle
//! the session holds on the file shares the one set, and the set lives as long
//! as one of those handles does.
//!
//! **A description is never opened for writing unless a handle that placed a
//! lock through it was.** A lock lives on a description, and the kernel refuses
//! a write lock through one that cannot be written, so an owner whose
//! description was opened to read and who then locks for writing through a
//! writable handle gets a wider description. Its locks move over with it: each
//! owner's record keeps the ranges it holds, as the kernel holds them for the
//! description, and they are placed on the new description before the old one
//! closes. They are read locks, since a description that cannot be written
//! carries no other kind, so nothing can stand in their way: the old
//! description still holds them while they are copied, and read locks on two
//! descriptions do not conflict. A description opened for writing is opened
//! for reading too wherever the host allows it, so it never has to move.

use std::collections::HashMap;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard};

use rustix::fs::OFlags;
use rustix::io::Errno;

use crate::host::attr::NodeIdentity;
use crate::host::lock::{Conflict, LockKind, LockRange, is_conflict, set, test};
use crate::host::open::reopen;

/// Which kinds of lock a descriptor may carry: the access it was opened with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockAccess {
    read: bool,
    write: bool,
}

impl LockAccess {
    /// The access a descriptor opened with `flags` has, from its access mode
    /// alone: read-only, write-only, read-write, or — for the mode with both
    /// bits set, which Linux opens for neither — no access at all.
    #[must_use]
    pub fn of(flags: OFlags) -> Self {
        let (write_only, read_write) =
            (flags.contains(OFlags::WRONLY), flags.contains(OFlags::RDWR));
        match (write_only, read_write) {
            (false, false) => Self {
                read: true,
                write: false,
            },
            (true, false) => Self {
                read: false,
                write: true,
            },
            (false, true) => Self {
                read: true,
                write: true,
            },
            (true, true) => Self {
                read: false,
                write: false,
            },
        }
    }

    /// Whether a lock of `kind` may be placed through a descriptor with this
    /// access: a read lock needs it open for reading, a write lock for writing,
    /// and releasing needs neither.
    #[must_use]
    pub fn permits(self, kind: LockKind) -> bool {
        match kind {
            LockKind::Read => self.read,
            LockKind::Write => self.write,
            LockKind::Unlock => true,
        }
    }

    /// The access that covers both.
    fn union(self, other: Self) -> Self {
        Self {
            read: self.read || other.read,
            write: self.write || other.write,
        }
    }

    /// The flags that open a description with this access.
    fn flags(self) -> OFlags {
        match (self.read, self.write) {
            (true, true) => OFlags::RDWR,
            (false, true) => OFlags::WRONLY,
            _ => OFlags::RDONLY,
        }
    }
}

/// The byte ranges an owner holds, by kind, as the kernel keeps them for the
/// owner's description: sorted, disjoint, never of kind unlock.
#[derive(Debug, Default)]
struct Held {
    ranges: Vec<(LockKind, LockRange)>,
}

impl Held {
    /// Records a placement the host accepted: the range, as the kernel holds it
    /// (see [`LockRange::as_held`]), takes `kind`, replacing whatever the owner
    /// held over it, and an unlock leaves it free.
    fn apply(&mut self, kind: LockKind, range: LockRange) {
        let mut ranges = Vec::with_capacity(self.ranges.len() + 2);
        for &(held, span) in &self.ranges {
            if span.end < range.start || span.start > range.end {
                ranges.push((held, span));
                continue;
            }
            // The overlapped span keeps what lies outside the new range. Each
            // bound is in range: the span starts before the range only when the
            // range does not start at 0, and ends after it only when the range
            // does not end at the last byte.
            if span.start < range.start {
                ranges.push((held, LockRange::new(span.start, range.start - 1)));
            }
            if span.end > range.end {
                ranges.push((held, LockRange::new(range.end + 1, span.end)));
            }
        }
        if kind != LockKind::Unlock {
            ranges.push((kind, range));
        }
        ranges.sort_by_key(|&(_, span)| span.start);
        // Adjacent ranges of one kind are one lock, as the kernel merges them,
        // so the record grows with the locks held and not with the requests.
        let mut merged: Vec<(LockKind, LockRange)> = Vec::with_capacity(ranges.len());
        for (held, span) in ranges {
            match merged.last_mut() {
                Some((last, joined))
                    if *last == held && joined.end.checked_add(1) == Some(span.start) =>
                {
                    joined.end = span.end;
                }
                _ => merged.push((held, span)),
            }
        }
        self.ranges = merged;
    }

    fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Whether the owner holds a write lock anywhere on the file.
    fn writes(&self) -> bool {
        self.ranges.iter().any(|&(kind, _)| kind == LockKind::Write)
    }
}

/// An owner's open description and the access it was opened with.
#[derive(Debug)]
struct Description {
    fd: OwnedFd,
    access: LockAccess,
}

impl Description {
    /// Releases every lock the description carries, then closes it.
    ///
    /// The release is explicit because closing a descriptor releases its locks
    /// only when it is the last reference to the open file description: a copy
    /// held elsewhere, such as by a child process between its fork and its
    /// exec, would keep them until that copy closes.
    fn close(self) {
        unlock(&self);
    }
}

/// Releases every lock a description carries, whatever else still refers to
/// it.
fn unlock(description: &Description) {
    // An unlock cannot conflict; should it fail, closing the descriptor still
    // releases the locks with its last reference.
    let _ = set(
        description.fd.as_fd(),
        LockKind::Unlock,
        LockRange::whole_file(),
    );
}

/// One owner's locks on one file.
#[derive(Debug, Default)]
pub struct OwnerLocks {
    state: Mutex<OwnerState>,
}

#[derive(Debug, Default)]
struct OwnerState {
    /// The description the owner's locks are placed through, or `None` before
    /// its first lock.
    description: Option<Description>,
    held: Held,
    /// How many blocking requests wait on this record. It stays open while one
    /// does, even holding nothing.
    waiters: usize,
    /// Whether the owner's locks on the file were released: the description
    /// is closed and this record is no longer the owner's.
    released: bool,
}

impl OwnerState {
    /// Whether nothing needs the record any more: it holds no range and no
    /// request waits on it.
    fn idle(&self) -> bool {
        self.held.is_empty() && self.waiters == 0
    }
}

impl OwnerLocks {
    fn state(&self) -> MutexGuard<'_, OwnerState> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Tries a placement a blocking request is waiting on once more.
    ///
    /// Returns whether it was placed. A record released in the meantime, which
    /// happens to a record with waiters only when the session's last handle on
    /// the file closes, answers `EBADF`, as the kernel answers a waiting lock
    /// whose descriptor was closed.
    ///
    /// # Errors
    ///
    /// `EBADF` for a released record, and any host errno of the placement
    /// other than a conflict.
    ///
    /// A placed lock ends the request's wait on the record. One that fails
    /// ends it through [`FileLocks::abandon`], which closes the record if that
    /// leaves it idle.
    pub fn retry(&self, kind: LockKind, range: LockRange) -> Result<bool, Errno> {
        let mut state = self.state();
        if state.released {
            return Err(Errno::BADF);
        }
        let description = state.description.as_ref().ok_or(Errno::BADF)?;
        let outcome = set(description.fd.as_fd(), kind, range);
        match outcome {
            Ok(()) => {
                state.held.apply(kind, range.as_held()?);
                state.waiters = state.waiters.saturating_sub(1);
                Ok(true)
            }
            Err(error) if is_conflict(error) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// What a placement did.
#[derive(Debug)]
pub enum Placed {
    /// The lock was placed or released.
    Done,
    /// The range is held by another owner and the request waits: the record
    /// to retry through with [`OwnerLocks::retry`].
    Waiting(Arc<OwnerLocks>),
}

/// The locks one session holds on one host file, by wire lock owner.
#[derive(Debug)]
pub struct FileLocks {
    /// The file's pinned `O_PATH` descriptor, which descriptions are reopened
    /// from.
    pinned: Arc<OwnedFd>,
    owners: Mutex<HashMap<u64, Arc<OwnerLocks>>>,
}

impl FileLocks {
    /// An empty set for the file `pinned` names.
    #[must_use]
    pub fn new(pinned: Arc<OwnedFd>) -> Self {
        Self {
            pinned,
            owners: Mutex::new(HashMap::new()),
        }
    }

    /// Tests whether `owner` could place a lock, through its own description
    /// so that its own locks do not answer as conflicts.
    ///
    /// A query never opens a description: a guest that may name `u64::MAX`
    /// owners must not be able to make the server open one per name. An owner
    /// with no description holds no locks, so `lock_free` — any description of
    /// the file that carries none — answers its query identically.
    ///
    /// # Errors
    ///
    /// Returns the host errno of the test.
    pub fn test(
        &self,
        owner: u64,
        kind: LockKind,
        range: LockRange,
        lock_free: BorrowedFd<'_>,
    ) -> Result<Option<Conflict>, Errno> {
        loop {
            let owners = self.owners();
            let Some(record) = owners.get(&owner).map(Arc::clone) else {
                // The map stays locked across the test, so no record of this
                // owner can place a lock that the lock-free description would
                // then report as a conflict.
                return test(lock_free, kind, range);
            };
            drop(owners);
            let state = record.state();
            if state.released {
                // Released since it was looked up; ask its successor, if any.
                continue;
            }
            return match &state.description {
                Some(description) => test(description.fd.as_fd(), kind, range),
                None => test(lock_free, kind, range),
            };
        }
    }

    /// Places or releases `owner`'s lock, through a handle with `access`.
    ///
    /// The owner's description is opened on its first lock, to the handle's
    /// access, and widened as [the module header](self) says when the lock
    /// needs access it lacks. A record that holds nothing afterwards is closed,
    /// so a released or refused request costs no descriptor. A conflict on a
    /// request that asked to wait keeps the record for the wait.
    ///
    /// # Errors
    ///
    /// The host errno of the placement — a conflict included, for a request
    /// that does not wait — or of the reopen.
    pub fn place(
        &self,
        owner: u64,
        kind: LockKind,
        range: LockRange,
        access: LockAccess,
        wait: bool,
    ) -> Result<Placed, Errno> {
        loop {
            let record = if kind == LockKind::Unlock {
                // Releasing what an owner never held opens nothing.
                match self.owners().get(&owner) {
                    Some(record) => Arc::clone(record),
                    None => return Ok(Placed::Done),
                }
            } else {
                Arc::clone(self.owners().entry(owner).or_default())
            };
            let mut state = record.state();
            if state.released {
                // Released since it was looked up; the map holds its successor
                // or nothing.
                continue;
            }
            if kind == LockKind::Unlock && state.description.is_none() {
                return Ok(Placed::Done);
            }
            if let Err(error) = self.cover(&mut state, kind, access) {
                if state.idle() {
                    self.close(owner, &record, &mut state);
                }
                return Err(error);
            }
            let description = state.description.as_ref().ok_or(Errno::BADF)?;
            let outcome = set(description.fd.as_fd(), kind, range).and_then(|()| range.as_held());
            match outcome {
                Ok(held) => state.held.apply(kind, held),
                Err(error) if is_conflict(error) && wait => {
                    state.waiters += 1;
                    drop(state);
                    return Ok(Placed::Waiting(record));
                }
                Err(_) => {}
            }
            if state.idle() {
                self.close(owner, &record, &mut state);
            }
            return outcome.map(|_| Placed::Done);
        }
    }

    /// Ends a wait that was cancelled or failed without placing its lock,
    /// closing the record if nothing needs it any more.
    pub fn abandon(&self, owner: u64, record: &Arc<OwnerLocks>) {
        let mut state = record.state();
        if state.released {
            return;
        }
        state.waiters = state.waiters.saturating_sub(1);
        if state.idle() {
            self.close(owner, record, &mut state);
        }
    }

    /// Releases every lock `owner` holds on the file, whichever handle placed
    /// it, as closing any of the owner's descriptors does.
    ///
    /// A blocking request the owner has pending through another descriptor
    /// keeps waiting, as it does locally, so a record with waiters stays open,
    /// holding nothing; one without is closed. The locks go first either way,
    /// so a request of the same owner that follows can never meet them: it
    /// waits for the record and finds it empty, or released with its successor
    /// to start.
    pub fn release_owner(&self, owner: u64) {
        let record = self.owners().get(&owner).map(Arc::clone);
        let Some(record) = record else {
            return;
        };
        let mut state = record.state();
        if state.released {
            return;
        }
        if let Some(description) = &state.description {
            unlock(description);
        }
        state.held = Held::default();
        if state.waiters == 0 {
            self.close(owner, &record, &mut state);
        }
    }

    /// How many owners hold a record on the file.
    #[must_use]
    pub fn lock_owners(&self) -> usize {
        self.owners().len()
    }

    /// Makes sure the owner's description can carry a lock of `kind`, opening
    /// it or widening it to the access of the handle the request came through.
    fn cover(
        &self,
        state: &mut OwnerState,
        kind: LockKind,
        access: LockAccess,
    ) -> Result<(), Errno> {
        let needed = match &state.description {
            None => access,
            Some(description) if description.access.permits(kind) => return Ok(()),
            // Write locks cannot move: two descriptions cannot both hold one,
            // and releasing it first would let another owner take the range.
            // Only a description the host would not open for reading holds
            // them without being readable.
            Some(_) if state.held.writes() => return Err(Errno::BADF),
            Some(description) => description.access.union(access),
        };
        let (fd, opened) = self.open(needed)?;
        // The owner's read locks move to the wider description while the old
        // one still holds them, so no other owner can take a range in between.
        for &(held, span) in &state.held.ranges {
            set(fd.as_fd(), held, span.from_held())?;
        }
        let wider = Description { fd, access: opened };
        if let Some(old) = state.description.replace(wider) {
            old.close();
        }
        Ok(())
    }

    /// Opens a description of the file with `access`, and for reading as well
    /// where it is opened for writing and the host allows it, so that a
    /// description carrying write locks never has to widen.
    fn open(&self, access: LockAccess) -> Result<(OwnedFd, LockAccess), Errno> {
        let pinned = self.pinned.as_fd();
        if access.write && !access.read {
            let both = access.union(LockAccess {
                read: true,
                write: false,
            });
            if let Ok(fd) = reopen(pinned, both.flags()) {
                return Ok((fd, both));
            }
        }
        Ok((reopen(pinned, access.flags())?, access))
    }

    /// Closes a record, then takes it out of the map if it is still the owner's.
    ///
    /// In that order: a request of the same owner that finds the map empty
    /// must never meet the old description's locks, so the description is
    /// closed first, while the record is still the one the owner's requests
    /// find and wait for.
    fn close(&self, owner: u64, record: &Arc<OwnerLocks>, state: &mut OwnerState) {
        Self::release(state);
        let mut owners = self.owners();
        if owners
            .get(&owner)
            .is_some_and(|filed| Arc::ptr_eq(filed, record))
        {
            owners.remove(&owner);
        }
    }

    /// Marks a record released and closes its description, which releases
    /// every lock it carried.
    fn release(state: &mut OwnerState) {
        state.released = true;
        if let Some(description) = state.description.take() {
            description.close();
        }
        state.held = Held::default();
    }

    /// Takes the owner map, ignoring poisoning: a panicking caller can leave
    /// behind a record, which is a closed descriptor at worst.
    fn owners(&self) -> MutexGuard<'_, HashMap<u64, Arc<OwnerLocks>>> {
        self.owners
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

impl FileLocks {
    /// Releases every owner's locks on the file, including those of a record a
    /// waiting request still holds, which then answers `EBADF`.
    fn release_all(&self) {
        let records: Vec<_> = self.owners().drain().map(|(_, record)| record).collect();
        for record in records {
            Self::release(&mut record.state());
        }
    }
}

impl Drop for FileLocks {
    fn drop(&mut self) {
        self.release_all();
    }
}

/// One session's lock sets, one per host file it holds a handle on.
///
/// Each handle joins its file's set and leaves it when it closes. When the last
/// handle leaves, every lock in the set is released while the registry is
/// still locked, so a handle opened on the file afterwards starts a set of its
/// own only once nothing of the old one holds a lock: a process that locks the
/// file again never meets its own released locks.
#[derive(Debug, Default)]
pub struct LockSets {
    files: Mutex<HashMap<NodeIdentity, Joined>>,
}

/// A file's lock set and how many handles have joined it.
#[derive(Debug)]
struct Joined {
    locks: Arc<FileLocks>,
    handles: usize,
}

impl LockSets {
    /// Joins a handle to the lock set of the file `identity` names, made from
    /// `pinned` if the session holds none for it yet.
    ///
    /// Keyed by the host file and not by the node, so two names of one file —
    /// hard links reached as two nodes — share one set, as they share one set
    /// of locks on a local filesystem.
    pub fn join(self: &Arc<Self>, identity: NodeIdentity, pinned: &Arc<OwnedFd>) -> Membership {
        let mut files = self.files();
        let joined = files.entry(identity).or_insert_with(|| Joined {
            locks: Arc::new(FileLocks::new(Arc::clone(pinned))),
            handles: 0,
        });
        joined.handles += 1;
        Membership {
            sets: Arc::clone(self),
            identity,
            locks: Arc::clone(&joined.locks),
        }
    }

    /// A handle of the file `identity` names has closed; the last one to close
    /// releases the set.
    fn leave(&self, identity: NodeIdentity) {
        let mut files = self.files();
        let Some(joined) = files.get_mut(&identity) else {
            return;
        };
        joined.handles = joined.handles.saturating_sub(1);
        if joined.handles == 0
            && let Some(joined) = files.remove(&identity)
        {
            joined.locks.release_all();
        }
    }

    fn files(&self) -> MutexGuard<'_, HashMap<NodeIdentity, Joined>> {
        self.files
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// A handle's place in its file's lock set, which it leaves when dropped.
#[derive(Debug)]
pub struct Membership {
    sets: Arc<LockSets>,
    identity: NodeIdentity,
    locks: Arc<FileLocks>,
}

impl Membership {
    /// The lock set the handle belongs to.
    #[must_use]
    pub fn locks(&self) -> &Arc<FileLocks> {
        &self.locks
    }
}

impl Drop for Membership {
    fn drop(&mut self) {
        self.sets.leave(self.identity);
    }
}

#[cfg(test)]
mod tests;
