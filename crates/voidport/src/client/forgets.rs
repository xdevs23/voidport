use std::sync::Weak;

use tokio::sync::mpsc;

use super::connection::Forget;
use super::{Caller, Client};

/// A forget is bound to the session that was serving when it was queued, since
/// only that session counted the lookups it gives back.
#[derive(Clone, Copy, Debug)]
pub(super) struct QueuedForget {
    generation: u64,
    forget: Forget,
}

impl Client {
    /// Never waits. A mount with no session installed drops the forget, since
    /// it names a node that died with the session.
    pub fn queue_forget(&self, caller: Caller, node_id: u64, nlookup: u64) {
        let Some(pool) = self.current() else { return };
        let queued = QueuedForget {
            generation: pool.generation(),
            forget: Forget {
                caller,
                node_id,
                nlookup,
            },
        };
        if self.forgets.send(queued).is_err() {
            tracing::error!(
                node_id,
                nlookup,
                "a forget was dropped, because the task that sends forgets has ended"
            );
        }
    }
}

/// Each pass sends every forget queued since the last one, so the rate grows
/// with the backlog, and the forgets of one session go out in order over one
/// connection at a time.
pub(super) async fn send_queued(
    client: Weak<Client>,
    mut queued: mpsc::UnboundedReceiver<QueuedForget>,
) {
    let mut backlog = Vec::new();
    while queued.recv_many(&mut backlog, usize::MAX).await > 0 {
        let Some(client) = client.upgrade() else {
            return;
        };
        for session in backlog.chunk_by(|one, next| one.generation == next.generation) {
            let forgets: Vec<Forget> = session.iter().map(|queued| queued.forget).collect();
            client.forget_within(session[0].generation, &forgets).await;
        }
        backlog.clear();
    }
}
