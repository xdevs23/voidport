use std::sync::Arc;

use voidport_control::{NamespaceName, SessionSummary};

use super::{Peer, Session};
use crate::namespace::Namespace;

impl Session {
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    #[must_use]
    pub fn peer(&self) -> &Peer {
        &self.peer
    }

    /// One operation takes this once and works from the result, so it cannot
    /// resolve a rule against one snapshot and a graft against the next. Once
    /// the namespace is deleted, the session falls back to the snapshot it
    /// mounted.
    #[must_use]
    pub fn namespace(&self) -> Arc<Namespace> {
        self.namespaces
            .namespace(&self.name)
            .unwrap_or_else(|| Arc::clone(&self.tombstone))
    }

    #[must_use]
    pub fn namespace_name(&self) -> &NamespaceName {
        &self.name
    }

    /// A tombstoned session may not subscribe: a frozen tombstone can never
    /// change, so a stream over it could only say nothing.
    #[must_use]
    pub fn is_tombstoned(&self) -> bool {
        self.namespaces.namespace(&self.name).is_none()
    }

    pub fn refresh_subscription(&self) {
        self.namespaces.refresh_subscription(self.id);
    }

    /// A request already on the blocking pool cannot be cancelled and has its
    /// reference for an unbounded time, so the tables are torn down here, when
    /// the last connection ends, and not whenever the last request unblocks.
    /// The leases remain until the window granted to the guest has surely
    /// passed.
    pub fn teardown(&self) {
        let caches = self.nodes().caches();
        self.handles().clear();
        self.nodes().clear();
        self.leases.linger(caches, self.recalls().window_passed());
    }

    pub fn release_leases(&self) {
        self.recalls().withhold();
        let caches = self.nodes().caches();
        for cache in caches {
            cache.release();
        }
    }

    pub fn relinquish(&self) {
        self.recalls().relinquish();
        for cache in self.nodes().caches() {
            cache.relinquish();
        }
    }

    /// The two counts are taken one lock at a time, not inside the struct
    /// literal, where a lock would stay held across the next field. No code
    /// path holds both tables at once, which frees the control plane of any
    /// lock order against the request path.
    #[must_use]
    pub fn summary(&self) -> SessionSummary {
        let nodes = self.nodes().len();
        let handles = self.handles().len();
        let connections = self.open_connections();
        SessionSummary {
            id: self.id,
            namespace: self.name.clone(),
            subpath: self.subpath.to_string(),
            transport: self.peer.transport.to_string(),
            peer: self.peer.address.clone(),
            connections,
            nodes,
            handles,
            // Read from the subscriber registry, so a stream the server ended
            // reports as unsubscribed without anything clearing a flag.
            subscribed: self.namespaces.is_subscribed(self.id),
        }
    }
}
