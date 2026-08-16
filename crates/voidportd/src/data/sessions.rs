//! The live-session registry.
//!
//! Two jobs, both server-global:
//!
//! * it is what `session list` reads, so an operator can see which guests are
//!   mounted, on what, and how much they hold;
//! * it enforces the session cap where the operator configured one. A
//!   connection takes a **reservation** before
//!   its handshake does any work, and only turns it into a registration once
//!   the mount resolves. Reserving first is what keeps the cap honest under
//!   concurrent connects: the count includes the connections that are still
//!   handshaking, so the cap cannot be overshot by a burst.
//!
//! A session leaves the registry when its connection ends, whichever way it
//! ends: the guard that holds it is owned by the connection task.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use voidport_control::SessionSummary;

use super::session::Session;

/// Every session the server is serving.
#[derive(Debug)]
pub struct Sessions {
    state: Mutex<State>,
    /// The configured cap, or `None` where the operator configured none and any
    /// number of guests may mount at once.
    limit: Option<usize>,
}

/// The registry's contents, behind one lock.
#[derive(Debug, Default)]
struct State {
    /// The next session id. Monotonic, never reused.
    next_id: u64,
    /// The registered sessions, in id order.
    live: BTreeMap<u64, Arc<Session>>,
    /// Reservations taken but not yet registered or released.
    reserved: usize,
}

impl State {
    /// How many session slots are spoken for.
    fn occupancy(&self) -> usize {
        self.live.len() + self.reserved
    }
}

impl Sessions {
    /// A registry admitting `limit` sessions at once, or any number when it is
    /// `None`.
    #[must_use]
    pub fn new(limit: Option<usize>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            limit,
        })
    }

    /// Takes a session slot, or `None` when the server is at a configured cap.
    ///
    /// The caller answers a refused connection with an error response and
    /// closes it — the design's "accepted and closed after an error response".
    /// An unconfigured registry refuses nobody.
    pub fn reserve(self: &Arc<Self>) -> Option<Reservation> {
        let mut state = self.locked();
        if self.limit.is_some_and(|limit| state.occupancy() >= limit) {
            return None;
        }
        state.reserved += 1;
        state.next_id += 1;
        let id = state.next_id;
        Some(Reservation {
            sessions: Arc::clone(self),
            id,
            attached: false,
        })
    }

    /// Every live session, in id order.
    ///
    /// A snapshot, deliberately: the caller works through the sessions holding
    /// nothing of this registry's, and a session that ends while it does is
    /// kept alive by the snapshot's own reference instead of disappearing
    /// mid-walk. This is what a mount-side rename reaches the *other* mounts'
    /// node tables through.
    #[must_use]
    pub fn live(&self) -> Vec<Arc<Session>> {
        self.locked().live.values().map(Arc::clone).collect()
    }

    /// Every live session, summarized in id order.
    #[must_use]
    pub fn list(&self) -> Vec<SessionSummary> {
        self.locked()
            .live
            .values()
            .map(|session| session.summary())
            .collect()
    }

    /// How many sessions are live.
    #[must_use]
    pub fn len(&self) -> usize {
        self.locked().live.len()
    }

    /// Whether nothing is mounted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The cap this registry enforces, if it enforces one.
    #[must_use]
    pub fn limit(&self) -> Option<usize> {
        self.limit
    }

    /// Takes the lock, ignoring poisoning: the registry is a map and a counter,
    /// and a panicking caller leaves both consistent.
    fn locked(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// A session slot held while a connection is still handshaking.
///
/// Dropping it without attaching a session releases the slot, so a handshake
/// that fails does not cost the server a session for the rest of its life.
#[derive(Debug)]
pub struct Reservation {
    sessions: Arc<Sessions>,
    id: u64,
    attached: bool,
}

impl Reservation {
    /// The session id this slot will carry.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Registers the session that resolved, turning the reservation into the
    /// guard that keeps it listed.
    #[must_use]
    pub fn attach(mut self, session: Arc<Session>) -> Registered {
        let mut state = self.sessions.locked();
        state.reserved -= 1;
        state.live.insert(self.id, session);
        drop(state);
        self.attached = true;
        Registered {
            sessions: Arc::clone(&self.sessions),
            id: self.id,
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.attached {
            self.sessions.locked().reserved -= 1;
        }
    }
}

/// A registered session, unregistered when this guard is dropped.
#[derive(Debug)]
pub struct Registered {
    sessions: Arc<Sessions>,
    id: u64,
}

impl Registered {
    /// The session id.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        self.sessions.locked().live.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_count_against_the_cap_and_release_when_dropped() {
        let sessions = Sessions::new(Some(2));
        assert!(sessions.is_empty());
        assert_eq!(sessions.limit(), Some(2));

        let first = sessions.reserve().expect("room");
        let second = sessions.reserve().expect("room");
        assert!(
            sessions.reserve().is_none(),
            "a handshaking connection still occupies a slot"
        );
        assert_eq!(first.id(), 1);
        assert_eq!(second.id(), 2);
        // Ids are not reused, and a failed handshake gives its slot back.
        drop(second);
        let third = sessions.reserve().expect("the slot came back");
        assert_eq!(third.id(), 3);
        assert_eq!(sessions.len(), 0, "nothing is registered yet");
        drop((first, third));
        assert!(sessions.reserve().is_some());
    }

    /// The default posture: no cap, so no connection is ever the excess one.
    #[test]
    fn an_unconfigured_registry_admits_every_connection() {
        let sessions = Sessions::new(None);
        assert_eq!(sessions.limit(), None);
        let held: Vec<_> = (0..256)
            .map(|_| sessions.reserve().expect("room"))
            .collect();
        assert!(sessions.reserve().is_some(), "and there is always room");
        drop(held);
    }
}
