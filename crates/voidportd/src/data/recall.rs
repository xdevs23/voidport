use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use tokio::sync::Notify;
use voidport_session::Window;

use crate::data::subscribe::NotificationQueue;

#[derive(Debug, Default)]
pub struct Recalls {
    state: Mutex<State>,
    idle: Notify,
}

#[derive(Debug, Default)]
struct State {
    last: u64,
    route: Option<Arc<NotificationQueue>>,
    open: BTreeMap<u64, u64>,
    grant: Grant,
}

#[derive(Clone, Copy, Debug)]
struct Renewed {
    at: Instant,
    window: Window,
}

#[derive(Clone, Copy, Debug, Default)]
enum Grant {
    #[default]
    Never,
    Window(Renewed),
    /// The last renewal granted no window. The window granted before still
    /// bounds the pages the guest cached under it.
    Withheld(Renewed),
    /// The guest relinquished every page it caches and fills none, so no
    /// window bounds anything, and no renewal grants one.
    Relinquished,
}

impl Recalls {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    pub fn send(&self, node_id: u64) -> u64 {
        let mut state = self.locked();
        state.last += 1;
        let recall = state.last;
        state.open.insert(recall, node_id);
        if let Some(queue) = &state.route {
            queue.recall(node_id, recall);
        }
        recall
    }

    pub fn close(&self, recall: u64) {
        let mut state = self.locked();
        state.open.remove(&recall);
        if state.open.is_empty() {
            self.idle.notify_waiters();
        }
    }

    pub fn route(&self, queue: Option<&Arc<NotificationQueue>>) {
        let mut state = self.locked();
        state.route = queue.cloned();
        if let Some(queue) = queue {
            for (&recall, &node_id) in &state.open {
                queue.recall(node_id, recall);
            }
        }
    }

    pub async fn renew(&self, window: Window) -> Option<Window> {
        loop {
            let idle = self.idle.notified();
            tokio::pin!(idle);
            idle.as_mut().enable();
            {
                let mut state = self.locked();
                if matches!(state.grant, Grant::Relinquished) {
                    return None;
                }
                if state.open.is_empty() {
                    let at = Instant::now();
                    state.grant = Grant::Window(Renewed { at, window });
                    return Some(window);
                }
            }
            idle.await;
        }
    }

    pub fn relinquish(&self) {
        self.locked().grant = Grant::Relinquished;
    }

    /// A renewal granted no window. The window granted before still bounds
    /// the pages the guest cached under it.
    pub fn withhold(&self) {
        let mut state = self.locked();
        if let Grant::Window(renewed) = state.grant {
            state.grant = Grant::Withheld(renewed);
        }
    }

    #[must_use]
    pub fn granted(&self) -> bool {
        matches!(self.locked().grant, Grant::Window(_))
    }

    #[must_use]
    pub fn reachable(&self) -> bool {
        let state = self.locked();
        state.route.is_some()
            && matches!(state.grant, Grant::Window(renewed)
                if renewed.at.elapsed() < renewed.window.length())
    }

    #[must_use]
    pub fn window_passed(&self) -> Instant {
        match self.locked().grant {
            Grant::Window(renewed) | Grant::Withheld(renewed) => {
                renewed.window.surely_passed_from(renewed.at)
            }
            Grant::Never | Grant::Relinquished => Instant::now(),
        }
    }

    fn locked(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}
