//! POSIX gives a record lock to its process for the whole file, whichever
//! descriptor placed it, so the server stores its locks per file and lock
//! holder, never per handle. The wire identifies that process by a lock holder
//! id.
//!
//! The server checks the lock holders of one session against each other and
//! places the union of their locks as OFD locks (see [`crate::host::lock`]) on
//! the one description the session reads and writes the file through
//! ([`crate::data::cache`]). The kernel cannot separate the lock holders of one
//! description: their locks coalesce instead of conflicting. The set references
//! the description while a lock holder has a lock through it or a blocking
//! request waits; the description itself belongs to the file of the session,
//! which closes it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use rustix::fs::OFlags;
use rustix::io::Errno;

use crate::host::Description;
use crate::host::attr::NodeIdentity;
use crate::host::lock::{Conflict, LockKind, LockRange, is_conflict, set, test};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockAccess {
    read: bool,
    write: bool,
}

impl LockAccess {
    /// The mode with both access bits set, which Linux opens for neither, has
    /// no access at all.
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

    #[must_use]
    pub fn permits(self, kind: LockKind) -> bool {
        match kind {
            LockKind::Read => self.read,
            LockKind::Write => self.write,
            LockKind::Unlock => true,
        }
    }
}

/// In the coordinates of the kernel (see [`LockRange::as_held`]): sorted,
/// disjoint, never of kind unlock.
#[derive(Debug, Default)]
struct Held {
    ranges: Vec<(LockKind, LockRange)>,
}

impl Held {
    fn apply(&mut self, kind: LockKind, range: LockRange) {
        let mut ranges = Vec::with_capacity(self.ranges.len() + 2);
        for &(held, span) in &self.ranges {
            if span.end < range.start || span.start > range.end {
                ranges.push((held, span));
                continue;
            }
            // The overlapped span retains what lies outside the new range. Each
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
        // Adjacent ranges of one kind are one lock, as the kernel merges them.
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

    fn writes(&self) -> bool {
        self.ranges.iter().any(|&(kind, _)| kind == LockKind::Write)
    }

    fn conflict(&self, kind: LockKind, range: LockRange) -> Option<(LockKind, LockRange)> {
        self.ranges.iter().copied().find(|&(held, span)| {
            span.start <= range.end
                && range.start <= span.end
                && (kind == LockKind::Write || held == LockKind::Write)
        })
    }
}

/// The release is explicit because the description outlives the reference of
/// the set: a copy elsewhere, such as in a child process between its fork and
/// its exec, preserves the locks until that copy closes.
fn unlock_all(description: &Description) {
    // An unlock cannot conflict; should it fail, closing the description still
    // releases the locks with its last reference.
    let _ = set(description.fd(), LockKind::Unlock, LockRange::whole_file());
}

#[derive(Debug, Default)]
struct Holder {
    held: Held,
    waiters: usize,
}

impl Holder {
    fn idle(&self) -> bool {
        self.held.is_empty() && self.waiters == 0
    }
}

#[derive(Debug)]
pub enum Placed {
    Done,
    Waiting,
}

#[derive(Debug, Default)]
pub struct FileLocks {
    state: Mutex<SetState>,
}

#[derive(Debug, Default)]
struct SetState {
    description: Option<Arc<Description>>,
    holders: HashMap<u64, Holder>,
    released: bool,
}

impl FileLocks {
    pub fn test(
        &self,
        holder: u64,
        kind: LockKind,
        range: LockRange,
        description: &Description,
    ) -> Result<Option<Conflict>, Errno> {
        let state = self.state();
        if let Some((held, span)) = state.conflict(holder, kind, range.as_held()?) {
            return Ok(Some(Conflict {
                kind: held,
                range: span.from_held(),
                pid: -1,
            }));
        }
        let probe = state.description.as_deref().unwrap_or(description);
        test(probe.fd(), kind, range)
    }

    pub fn place(
        &self,
        holder: u64,
        kind: LockKind,
        range: LockRange,
        wait: bool,
        description: &Arc<Description>,
    ) -> Result<Placed, Errno> {
        if kind == LockKind::Unlock {
            return self.unlock(holder, range).map(|()| Placed::Done);
        }
        let mut state = self.state();
        state.carry(kind, description)?;
        match state.lock(holder, kind, range) {
            Err(error) if is_conflict(error) && wait => {
                state.holders.entry(holder).or_default().waiters += 1;
                Ok(Placed::Waiting)
            }
            placed => {
                state.forget_if_idle(holder);
                placed.map(|()| Placed::Done)
            }
        }
    }

    pub fn unlock(&self, holder: u64, range: LockRange) -> Result<(), Errno> {
        let mut state = self.state();
        state.unlock(holder, range.as_held()?);
        state.forget_if_idle(holder);
        Ok(())
    }

    pub fn retry(&self, holder: u64, kind: LockKind, range: LockRange) -> Result<bool, Errno> {
        let mut state = self.state();
        if state.released {
            return Err(Errno::BADF);
        }
        match state.lock(holder, kind, range) {
            Ok(()) => {
                let waiting = state.holders.entry(holder).or_default();
                waiting.waiters = waiting.waiters.saturating_sub(1);
                Ok(true)
            }
            Err(error) if is_conflict(error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub fn abandon(&self, holder: u64) {
        let mut state = self.state();
        if state.released {
            return;
        }
        if let Some(waiting) = state.holders.get_mut(&holder) {
            waiting.waiters = waiting.waiters.saturating_sub(1);
        }
        state.forget_if_idle(holder);
    }

    pub fn release_holder(&self, holder: u64) {
        let mut state = self.state();
        state.unlock(holder, LockRange::whole_file());
        state.forget_if_idle(holder);
    }

    /// The locks are placed on `description` while the one they are on still has
    /// them, so no other process can lock a range in between. Only read locks
    /// move that way: a write lock conflicts with its own copy on another
    /// description. A set with a write lock remains where it is, on a
    /// description that can be written already.
    pub fn move_to(&self, description: &Arc<Description>) -> Result<(), Errno> {
        self.state().move_to(description)
    }

    /// Ignores poisoning: a panicking caller leaves behind at worst a lock that
    /// outlasts its need.
    fn state(&self) -> MutexGuard<'_, SetState> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn release_all(&self) {
        let mut state = self.state();
        state.released = true;
        state.holders.clear();
        if let Some(description) = state.description.take() {
            unlock_all(&description);
        }
    }
}

impl Drop for FileLocks {
    fn drop(&mut self) {
        self.release_all();
    }
}

impl SetState {
    fn conflict(
        &self,
        holder: u64,
        kind: LockKind,
        range: LockRange,
    ) -> Option<(LockKind, LockRange)> {
        if kind == LockKind::Unlock {
            return None;
        }
        self.holders
            .iter()
            .filter(|&(&other, _)| other != holder)
            .filter_map(|(_, other)| other.held.conflict(kind, range))
            .min_by_key(|&(_, span)| span.start)
    }

    fn carry(&mut self, kind: LockKind, description: &Arc<Description>) -> Result<(), Errno> {
        match &self.description {
            None => {
                self.description = Some(Arc::clone(description));
                Ok(())
            }
            Some(current) if kind == LockKind::Write && !current.writable() => {
                self.move_to(description)
            }
            Some(_) => Ok(()),
        }
    }

    fn move_to(&mut self, description: &Arc<Description>) -> Result<(), Errno> {
        match &self.description {
            Some(current) if !Arc::ptr_eq(current, description) && !self.writes() => {}
            _ => return Ok(()),
        }
        if let Err(error) = self.place_union(description) {
            unlock_all(description);
            return Err(error);
        }
        if let Some(old) = self.description.replace(Arc::clone(description)) {
            unlock_all(&old);
        }
        Ok(())
    }

    fn lock(&mut self, holder: u64, kind: LockKind, range: LockRange) -> Result<(), Errno> {
        let held = range.as_held()?;
        if self.conflict(holder, kind, held).is_some() {
            return Err(Errno::AGAIN);
        }
        let description = self.description.as_ref().ok_or(Errno::BADF)?;
        set(description.fd(), kind, range)?;
        self.holders
            .entry(holder)
            .or_default()
            .held
            .apply(kind, held);
        Ok(())
    }

    fn unlock(&mut self, holder: u64, range: LockRange) {
        let Some(released) = self.holders.get(&holder) else {
            return;
        };
        if let Some(description) = &self.description {
            let mut others: Vec<LockRange> = self
                .holders
                .iter()
                .filter(|&(&other, _)| other != holder)
                .flat_map(|(_, other)| other.held.ranges.iter().map(|&(_, span)| span))
                .collect();
            others.sort_by_key(|span| span.start);
            for &(_, span) in &released.held.ranges {
                if span.end < range.start || span.start > range.end {
                    continue;
                }
                let piece = LockRange::new(span.start.max(range.start), span.end.min(range.end));
                for free in uncovered(piece, &others) {
                    let _ = set(description.fd(), LockKind::Unlock, free.from_held());
                }
            }
        }
        if let Some(released) = self.holders.get_mut(&holder) {
            released.held.apply(LockKind::Unlock, range);
        }
    }

    fn forget_if_idle(&mut self, holder: u64) {
        if self.holders.get(&holder).is_some_and(Holder::idle) {
            self.holders.remove(&holder);
        }
        if self.holders.is_empty()
            && let Some(description) = self.description.take()
        {
            unlock_all(&description);
        }
    }

    fn writes(&self) -> bool {
        self.holders.values().any(|holder| holder.held.writes())
    }

    fn place_union(&self, description: &Description) -> Result<(), Errno> {
        for holder in self.holders.values() {
            for &(held, span) in &holder.held.ranges {
                set(description.fd(), held, span.from_held())?;
            }
        }
        Ok(())
    }
}

fn uncovered(range: LockRange, taken: &[LockRange]) -> Vec<LockRange> {
    let mut free = Vec::new();
    let mut next = Some(range.start);
    for span in taken {
        let Some(start) = next else {
            break;
        };
        if span.end < start || span.start > range.end {
            continue;
        }
        if span.start > start {
            free.push(LockRange::new(start, span.start - 1));
        }
        next = span.end.checked_add(1);
    }
    if let Some(start) = next
        && start <= range.end
    {
        free.push(LockRange::new(start, range.end));
    }
    free
}

/// When the last handle leaves, every lock in the set is released while the
/// registry is still locked, so a process that locks the file again never meets
/// its own released locks.
#[derive(Debug, Default)]
pub struct LockSets {
    files: Mutex<HashMap<NodeIdentity, Joined>>,
}

#[derive(Debug)]
struct Joined {
    locks: Arc<FileLocks>,
    handles: usize,
}

impl LockSets {
    /// Keyed by the host file and not by the node, so two names of one file
    /// share one set, as they do on a local filesystem.
    pub fn join(self: &Arc<Self>, identity: NodeIdentity) -> Membership {
        let mut files = self.files();
        let joined = files.entry(identity).or_insert_with(|| Joined {
            locks: Arc::default(),
            handles: 0,
        });
        joined.handles += 1;
        Membership {
            sets: Arc::clone(self),
            identity,
            locks: Arc::clone(&joined.locks),
        }
    }

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

#[derive(Debug)]
pub struct Membership {
    sets: Arc<LockSets>,
    identity: NodeIdentity,
    locks: Arc<FileLocks>,
}

impl Membership {
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
