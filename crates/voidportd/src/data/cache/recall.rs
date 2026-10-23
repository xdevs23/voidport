use std::os::fd::AsFd;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use rustix::fs::OFlags;
use tokio::time::Instant;

use super::lease::{Kept, Lease, OpenRecall, Then};
use super::{FileCache, HOLDS_READ, HOLDS_WRITE, State, WAITS};
use crate::data::leases::LeaseFile;
use crate::host::Description;
use crate::host::lease::{self as host_lease, Kind};

const FIRST_PAUSE: Duration = Duration::from_millis(1);

/// The pauses double from [`FIRST_PAUSE`] up to this. It matches
/// `LOCK_RETRY_CAP` in `data::ops::file`: both are a guest program waiting for
/// a host program to let go.
const LONGEST_LAG: Duration = Duration::from_millis(8);

impl FileCache {
    pub(super) fn recall(self: &Arc<Self>, state: &mut State, then: Then) {
        match std::mem::take(&mut state.lease) {
            Lease::Held { file, .. } => self.recall_on(state, file, then),
            lease => state.lease = lease,
        }
    }

    fn recall_on(self: &Arc<Self>, state: &mut State, file: LeaseFile, then: Then) {
        let passed = Instant::from_std(self.recalls.window_passed());
        let id = self.recalls.send(self.node_id);
        let cache = Arc::downgrade(self);
        let deadline = self.leases.spawn(async move {
            tokio::time::sleep_until(passed).await;
            if let Some(cache) = cache.upgrade() {
                cache.expired(id);
            }
        });
        state.lease = Lease::Recalling {
            file,
            recall: OpenRecall {
                id,
                _deadline: deadline,
            },
            then,
        };
    }

    pub fn recalled(self: &Arc<Self>, recall: u64) {
        let mut state = self.locked();
        self.settle(&mut state, recall, true);
    }

    fn expired(self: &Arc<Self>, recall: u64) {
        let mut state = self.locked();
        if self.settle(&mut state, recall, false) {
            tracing::warn!(
                node_id = self.node_id,
                "the guest did not reply to a recall within the window granted to it, so the lease went on without it"
            );
        }
    }

    /// Nothing bounds the pages the guest caches without a window, so a held
    /// lease is recalled and given up, and the waiting requests fail, since a
    /// page they use could be stale the moment after.
    pub fn release(self: &Arc<Self>) {
        let mut state = self.locked();
        match &mut state.lease {
            Lease::Held { .. } => self.recall(&mut state, Then::Break(None)),
            Lease::Recalling { then, .. } if !matches!(then, Then::Release) => {
                *then = Then::Break(None);
            }
            Lease::Waiting { watch, .. } => *watch = None,
            _ => {}
        }
        drop(state);
        self.changed.notify_waiters();
    }

    pub fn relinquish(&self) {
        let mut state = self.locked();
        let counts = (state.handles, state.cached);
        let given_up = |file| Lease::after(file, Then::Break(None), true, counts, |_, _| None);
        state.lease = match std::mem::take(&mut state.lease) {
            Lease::Held { file, .. } => given_up(file),
            Lease::Recalling { file, recall, .. } => {
                recall.close(&self.recalls);
                given_up(file)
            }
            mut lease => {
                if let Lease::Waiting { watch, .. } = &mut lease {
                    *watch = None;
                }
                lease
            }
        };
        drop(state);
        self.changed.notify_waiters();
    }

    #[must_use]
    pub fn leased(&self) -> bool {
        matches!(
            self.locked().lease,
            Lease::Held { .. } | Lease::Recalling { .. }
        )
    }

    fn settle(self: &Arc<Self>, state: &mut State, recall: u64, replied: bool) -> bool {
        match std::mem::take(&mut state.lease) {
            Lease::Recalling {
                file,
                recall: open,
                then,
            } if open.id == recall => {
                open.close(&self.recalls);
                state.lease = Lease::after(
                    file,
                    then,
                    replied,
                    (state.handles, state.cached),
                    |fd, kind| self.leases.watch(fd, self, kind),
                );
            }
            lease => {
                state.lease = lease;
                return false;
            }
        }
        self.changed.notify_waiters();
        true
    }

    pub(crate) fn broken(self: &Arc<Self>) {
        let mut state = self.locked();
        let file = match &state.lease {
            Lease::Held { file, .. } => file,
            Lease::Recalling { file, then, .. } if !matches!(then, Then::Break(_)) => file,
            _ => return,
        };
        if !host_lease::is_broken(file.fd(), file.kind()) {
            return;
        }
        let watch = self.leases.watch(file.fd(), self, file.kind());
        if let Lease::Recalling { then, .. } = &mut state.lease {
            *then = Then::Break(watch);
        } else {
            self.recall(&mut state, Then::Break(watch));
        }
    }

    /// The kernel reports a change, a close included, before the opener that
    /// made it stops counting as one (`__fput` and `vfs_truncate`), and the
    /// rest of a close can take any time, so no number of tries after a change
    /// is sure to see its end. The lease is tried after pauses that double from
    /// [`FIRST_PAUSE`] up to [`LONGEST_LAG`], until it is gained or no request
    /// waits any more, and every change starts the pauses again.
    pub(crate) fn opener_changed(self: &Arc<Self>) {
        let mut state = self.locked();
        let Lease::Waiting { retrying, .. } = &mut state.lease else {
            return;
        };
        let cache = Arc::downgrade(self);
        // The tries under way end with the task that replaces them.
        *retrying = Some(self.leases.spawn(retry(move || {
            cache.upgrade().is_some_and(|cache| cache.try_again())
        })));
    }

    fn try_again(self: &Arc<Self>) -> bool {
        let mut state = self.locked();
        self.retake(&mut state);
        state.cached > 0 && matches!(state.lease, Lease::Waiting { watch: Some(_), .. })
    }

    pub(crate) fn unwatched(&self) {
        let mut state = self.locked();
        if let Lease::Waiting { watch, .. }
        | Lease::Recalling {
            then: Then::Break(watch),
            ..
        } = &mut state.lease
        {
            *watch = None;
        }
        drop(state);
        self.changed.notify_waiters();
    }

    /// The lease is tried only while no other cache of the file has a
    /// description that it excludes: a description that the session has open is
    /// closed meanwhile, so that it blocks no lease of that cache either. A
    /// description that the lease fails on remains open, and none is opened
    /// while one is open: the opener is another process, and closing the
    /// description of the session would be a change that tries again.
    pub(super) fn retake(self: &Arc<Self>, state: &mut State) {
        let Lease::Waiting { access, kept, .. } = &mut state.lease else {
            return;
        };
        if state.widening > 0 || !self.recalls.granted() {
            return;
        }
        let kind = Kind::of(*access);
        if !self.claim(kind) {
            kept.close();
            return;
        }
        let Some(description) = kept.description().or_else(|| {
            let pin = state.pin.as_ref()?;
            Description::open(pin.as_fd(), *access | OFlags::NONBLOCK).ok()
        }) else {
            return;
        };
        let Lease::Waiting {
            access,
            slot,
            watch,
            retrying,
            ..
        } = std::mem::take(&mut state.lease)
        else {
            return;
        };
        let file = LeaseFile::new(&self.leases, description, slot, self);
        if host_lease::take(file.fd(), kind).is_err() {
            let (description, slot) = file.into_parts();
            state.lease = Lease::Waiting {
                access,
                kept: Kept::Open(description),
                slot,
                watch,
                retrying,
            };
            return;
        }
        state.epoch += 1;
        self.recall_on(state, file, Then::Settle);
        self.changed.notify_waiters();
    }

    fn claim(&self, kind: Kind) -> bool {
        self.leases.arbitrate(self.identity, self, |others| {
            let free = others
                .iter()
                .all(|other| !other.holds().is_some_and(|held| held.excludes(kind)));
            if free {
                let holds = match kind {
                    Kind::Read => HOLDS_READ,
                    Kind::Write => HOLDS_WRITE,
                };
                self.presence.store(holds | WAITS, Ordering::SeqCst);
            }
            free
        })
    }
}

async fn retry(mut try_again: impl FnMut() -> bool) {
    let mut pause = FIRST_PAUSE;
    loop {
        tokio::time::sleep(pause).await;
        if !try_again() {
            return;
        }
        pause = (pause * 2).min(LONGEST_LAG);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_tries_go_on_until_nothing_waits_any_more() {
        let waiting = 30;
        let mut tries = 0;
        retry(|| {
            tries += 1;
            tries <= waiting
        })
        .await;
        assert_eq!(
            tries,
            waiting + 1,
            "the tries end with the first that gains the lease"
        );
    }
}
