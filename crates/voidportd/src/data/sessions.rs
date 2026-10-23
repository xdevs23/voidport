use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use rustix::io::Errno;
use voidport_control::SessionSummary;

use super::session::Session;

#[derive(Debug)]
pub struct Sessions {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    next_id: u64,
    live: BTreeMap<u64, Arc<Session>>,
}

impl Sessions {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
        })
    }

    pub fn next_id(&self) -> Result<u64, Errno> {
        let mut state = self.locked();
        state.next_id = id_after(state.next_id)?;
        Ok(state.next_id)
    }

    #[must_use]
    pub fn register(self: &Arc<Self>, session: Arc<Session>) -> Registered {
        let id = session.id();
        self.locked().live.insert(id, session);
        Registered {
            sessions: Arc::clone(self),
            id,
        }
    }

    #[must_use]
    pub fn get(&self, id: u64) -> Option<Arc<Session>> {
        self.locked().live.get(&id).map(Arc::clone)
    }

    /// A snapshot: a session that ends while the caller walks is kept alive by
    /// the reference in the snapshot instead of disappearing mid-walk.
    #[must_use]
    pub fn live(&self) -> Vec<Arc<Session>> {
        self.locked().live.values().map(Arc::clone).collect()
    }

    #[must_use]
    pub fn list(&self) -> Vec<SessionSummary> {
        self.locked()
            .live
            .values()
            .map(|session| session.summary())
            .collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.locked().live.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Ignores poisoning: a panicking caller leaves the map and the counter
    /// consistent.
    fn locked(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

#[derive(Debug)]
pub struct Registered {
    sessions: Arc<Sessions>,
    id: u64,
}

impl Registered {
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        let removed = self.sessions.locked().live.remove(&self.id);
        // Dropped with the lock released: the last reference tears the whole
        // session down, and every handshake and session list waits on the lock.
        drop(removed);
    }
}

pub(super) fn id_after(last: u64) -> Result<u64, Errno> {
    last.checked_add(1).ok_or(Errno::OVERFLOW)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_start_at_one() {
        let sessions = Sessions::new();
        assert_eq!(sessions.next_id(), Ok(1));
        assert_eq!(sessions.next_id(), Ok(2));
    }

    #[test]
    fn the_session_counter_at_its_last_value_fails_with_eoverflow_and_stays_there() {
        let sessions = Sessions::new();
        sessions.locked().next_id = u64::MAX;
        assert_eq!(sessions.next_id(), Err(Errno::OVERFLOW));
        assert_eq!(sessions.locked().next_id, u64::MAX);
    }
}
