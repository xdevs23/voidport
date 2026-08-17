//! The data plane's shared state.
//!
//! Sessions share exactly five things, and nothing else: the **published
//! namespace registry** they resolve against, the **ino allocator**
//! (server-global by contract, so identity is stable across sessions), the
//! **id generations** (server-global, so no two sessions can name a node or a
//! handle with the same number), the **descriptor budget** (server-global
//! because the process's descriptor table is), and the **session registry**
//! (server-global, so the operator can see them and the cap can be enforced).
//! There is no global lock on the request path.
//!
//! Namespaces are looked up through the control-plane service's published
//! snapshot, and not only at handshake time: a session keeps the handle and
//! consults it on every path-resolving operation, so a namespace created a
//! moment ago is mountable, a rule added a moment ago is visible to the next
//! lookup, and a deleted namespace stops accepting new mounts while the
//! sessions that hold it fall back to the snapshot they mounted.

use std::sync::{Arc, Weak};

use voidport_control::NamespaceName;

use super::caps::Limits;
use super::ids::Generations;
use super::ino::InoAllocator;
use super::pin::DescriptorBudget;
use super::sessions::Sessions;
use crate::control::service::{Published, Service};
use crate::host::SynthesizedTimes;
use crate::namespace::Namespace;

/// The server-global sources of identity a session names things from, and the
/// descriptor cache it pins through.
///
/// The first two travel together because they answer the same question at two
/// levels: what the *guest* calls a file (an ino, stable across sessions so
/// hardlink aliases agree), and what the *wire* calls it (a node or handle id,
/// disjoint across sessions and across restarts so a stale one names nothing).
/// Handing a session one value instead of several keeps them impossible to
/// separate by accident — and the descriptor budget rides along for the same
/// reason: it is process-wide, because the descriptor table it bounds is.
///
/// The synthesized-directory timestamps ride here for the reason the ino table
/// is server-global: a directory the server invented has neither a host inode
/// nor host times, and both of the values it presents instead have to outlive
/// every namespace snapshot — a value owned by a snapshot would change under a
/// guest on every rule mutation.
#[derive(Clone, Debug)]
pub struct Identity {
    /// Guest-visible inode numbers.
    pub ino: Arc<InoAllocator>,
    /// Node and handle id generations.
    pub generations: Arc<Generations>,
    /// The bound on cache-resident node descriptors, across every session.
    pub budget: Arc<DescriptorBudget>,
    /// The timestamps synthesized directories present: the server's start time.
    pub synthesized_times: SynthesizedTimes,
}

/// The server-global registries a session consults while it serves.
///
/// Two of them, and both are *observed*, not owned: the published
/// namespaces every path-resolving operation resolves against, and the other
/// live mounts — which a session reaches for exactly one purpose, to re-point
/// their nodes at a host entry this session has just moved. The second is weak
/// because the registry owns the sessions in it.
#[derive(Clone, Debug)]
pub struct Registries {
    /// The published namespace snapshot, by name.
    pub namespaces: Arc<Published>,
    /// Every live mount, this one included.
    pub peers: Weak<Sessions>,
}

/// What every data-plane connection shares.
#[derive(Debug)]
pub struct DataPlane {
    namespaces: Arc<Published>,
    sessions: Arc<Sessions>,
    identity: Identity,
    limits: Limits,
}

impl DataPlane {
    /// Builds the shared state around a running control-plane service.
    ///
    /// This is where the server's start time is captured: the data plane is
    /// built once, while the daemon starts, and every synthesized directory
    /// this server ever presents carries the value taken here.
    #[must_use]
    pub fn new(service: Arc<Service>) -> Arc<Self> {
        Arc::new(Self {
            namespaces: service.published(),
            sessions: service.sessions(),
            identity: Identity {
                ino: Arc::new(InoAllocator::new()),
                generations: Generations::shared(),
                budget: service.descriptor_budget(),
                synthesized_times: SynthesizedTimes::at_startup(),
            },
            limits: service.limits(),
        })
    }

    /// The published registry sessions resolve their namespace through.
    #[must_use]
    pub fn namespaces(&self) -> Arc<Published> {
        Arc::clone(&self.namespaces)
    }

    /// The registries a session is built with.
    #[must_use]
    pub fn registries(&self) -> Registries {
        Registries {
            namespaces: Arc::clone(&self.namespaces),
            peers: Arc::downgrade(&self.sessions),
        }
    }

    /// The namespace of that name, as the server currently publishes it.
    #[must_use]
    pub fn namespace(&self, name: &NamespaceName) -> Option<Arc<Namespace>> {
        self.namespaces.namespace(name)
    }

    /// What a handshake mounts: the namespace of that name and its record
    /// store, from one snapshot read.
    #[must_use]
    pub fn mount_of(
        &self,
        name: &NamespaceName,
    ) -> Option<(Arc<Namespace>, Option<Arc<crate::records::RecordStore>>)> {
        self.namespaces.mount_of(name)
    }

    /// The live-session registry.
    #[must_use]
    pub fn sessions(&self) -> Arc<Sessions> {
        Arc::clone(&self.sessions)
    }

    /// The server-global sources a session names nodes, handles and inodes
    /// from.
    ///
    /// Shared so that two sessions — and two lifetimes of this server — can
    /// never name a node or a handle with the same number; see
    /// [`crate::data::ids`].
    #[must_use]
    pub fn identity(&self) -> Identity {
        self.identity.clone()
    }

    /// The resource caps every session is built with.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }
}
