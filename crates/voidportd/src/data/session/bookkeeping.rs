//! What the mount is: the facts a session answers about itself.
//!
//! Everything here reads the session's own bookkeeping — its id, its peer, the
//! namespace it serves by name, its share subscription and its teardown. None
//! of it resolves a path or touches the host; the one thing it decides is which
//! snapshot the rest of the session works against, which is why
//! [`Session::namespace`] lives here and not beside the resolution that calls
//! it.

use std::sync::Arc;

use voidport_control::{NamespaceName, SessionSummary};

use super::{Peer, Session};
use crate::data::caps::Limits;
use crate::data::subscribe::NotificationQueue;
use crate::namespace::Namespace;

impl Session {
    /// The session id, as the control plane reports it.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Where the client connected from.
    #[must_use]
    pub fn peer(&self) -> &Peer {
        &self.peer
    }

    /// The namespace this session serves, as the server publishes it **now**.
    ///
    /// Every path-resolving operation starts here instead of reusing what the
    /// handshake found, which is what makes a control-plane mutation visible to
    /// the next lookup: a rule added, removed or downgraded to read-only takes
    /// effect on a fresh lookup without the guest remounting (design: "Session
    /// lifecycle").
    ///
    /// Once the namespace is deleted the registry has nothing to answer with,
    /// and the session falls back to the snapshot it mounted — the tombstone —
    /// so an established mount keeps serving until it disconnects.
    ///
    /// One operation takes this once and works from the result, so it cannot
    /// resolve a rule against one snapshot and a graft against the next.
    #[must_use]
    pub fn namespace(&self) -> Arc<Namespace> {
        self.namespaces
            .namespace(&self.name)
            .unwrap_or_else(|| Arc::clone(&self.tombstone))
    }

    /// The namespace's name.
    #[must_use]
    pub fn namespace_name(&self) -> &NamespaceName {
        &self.name
    }

    /// The session's resource caps.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Whether the namespace this session mounted has been deleted.
    ///
    /// A tombstoned session keeps serving what it mounted — that is the required
    /// lifecycle — but it may not *subscribe*, because a frozen tombstone can
    /// never change again and a stream over it could only ever say nothing.
    #[must_use]
    pub fn is_tombstoned(&self) -> bool {
        self.namespaces.namespace(&self.name).is_none()
    }

    /// The queue this session's share notifications leave through.
    #[must_use]
    pub fn notifications(&self) -> &Arc<NotificationQueue> {
        &self.notifications
    }

    /// Registers this session's share subscription and queues its snapshot.
    ///
    /// Called by the connection **after** the confirm reply is on the reply
    /// queue, which is what makes the contract's "the confirm always precedes
    /// the first snapshot part" true by construction, not by luck.
    pub fn subscribe(&self) {
        self.namespaces
            .subscribe(self.id, &self.name, &self.subpath, &self.notifications);
    }

    /// Ends this session's share subscription. A session that has none is
    /// untouched.
    pub fn unsubscribe(&self) {
        self.namespaces.unsubscribe(self.id);
    }

    /// Sends this session the fresh snapshot a lapse owes it.
    pub fn refresh_subscription(&self) {
        self.namespaces.refresh_subscription(self.id);
    }

    /// Releases everything the mount held: every handle, every node, every
    /// descriptor behind them.
    ///
    /// The connection calls this the moment it ends. Dropping the session
    /// itself would do the same job, but only once the *last* holder of it lets
    /// go — and a request already on the blocking pool cannot be cancelled (a
    /// waiting lock may block for as long as the lock is held), so it keeps its
    /// reference for an unbounded time. Tearing the tables down here is what
    /// makes the design's "connection drop or any framing error tears down the
    /// session: all handles and nodes close" true when the connection ends
    /// and not whenever the last request unblocks.
    pub fn teardown(&self) {
        self.handles().clear();
        self.nodes().clear();
    }

    /// This session, summarized for the operator.
    ///
    /// The two counts are taken one lock at a time, and deliberately not inside
    /// the struct literal: a guard produced in one field expression is still
    /// alive while the next field is evaluated, so writing them there would hold
    /// the node table across the handle table. **No code path holds both of this
    /// session's tables at once** — that is what keeps the control plane free of
    /// any lock order against the request path, which would otherwise be a
    /// deadlock waiting for the two to interleave.
    #[must_use]
    pub fn summary(&self) -> SessionSummary {
        let nodes = self.nodes().len();
        let handles = self.handles().len();
        SessionSummary {
            id: self.id,
            namespace: self.name.clone(),
            subpath: self.subpath.to_string(),
            transport: self.peer.transport.to_string(),
            peer: self.peer.address.clone(),
            nodes,
            handles,
            // Read from the subscriber registry, not from a flag of this
            // session's own, so it is one fact with one owner: a stream the
            // server ended — a deleted namespace — reports as unsubscribed
            // without anything having to remember to clear a bit.
            subscribed: self.namespaces.is_subscribed(self.id),
        }
    }
}
