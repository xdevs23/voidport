use std::io;
use std::sync::{Arc, Weak};

use voidport_control::NamespaceName;
use voidport_memory::Memory;

use super::descriptor_budget::DescriptorBudget;
use super::ids::Generations;
use super::ino::InoAllocator;
use super::leases::{LeaseThread, Leases};
use super::pool::Pool;
use super::sessions::Sessions;
use super::token::Signer;
use crate::control::service::{Published, Service};
use crate::host::SynthesizedTimes;
use crate::namespace::Namespace;

/// Everything here is server-global: ids must be disjoint across sessions and
/// restarts, and a value kept in a namespace snapshot would change under a
/// guest on every rule mutation.
#[derive(Clone, Debug)]
pub struct Identity {
    pub ino: Arc<InoAllocator>,
    pub generations: Arc<Generations>,
    pub budget: Arc<DescriptorBudget>,
    pub synthesized_times: SynthesizedTimes,
}

/// The peers are weak because the registry has the strong references to the
/// sessions.
#[derive(Clone, Debug)]
pub struct Registries {
    pub namespaces: Arc<Published>,
    pub peers: Weak<Sessions>,
    pub leases: Arc<Leases>,
}

#[derive(Debug, thiserror::Error)]
pub enum PlaneError {
    #[error("cannot start the first thread of the request pool")]
    Pool(#[source] io::Error),
    #[error("cannot catch the breaks of host leases")]
    Leases(#[source] io::Error),
}

#[derive(Debug)]
pub struct DataPlane {
    namespaces: Arc<Published>,
    sessions: Arc<Sessions>,
    identity: Identity,
    pool: Pool,
    memory: Arc<Memory>,
    signer: Signer,
    leases: LeaseThread,
}

impl DataPlane {
    /// The start time of the server is taken here: every synthesized directory
    /// presents it.
    pub fn new(service: Arc<Service>, signer: Signer) -> Result<Arc<Self>, PlaneError> {
        let budget = service.descriptor_budget();
        Ok(Arc::new(Self {
            namespaces: service.published(),
            sessions: service.sessions(),
            leases: LeaseThread::start(Arc::clone(&budget)).map_err(PlaneError::Leases)?,
            identity: Identity {
                ino: Arc::new(InoAllocator::new()),
                generations: Generations::shared(),
                budget,
                synthesized_times: SynthesizedTimes::at_startup(),
            },
            pool: Pool::new().map_err(PlaneError::Pool)?,
            memory: Memory::host(),
            signer,
        }))
    }

    #[must_use]
    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    #[must_use]
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    #[must_use]
    pub fn memory(&self) -> &Arc<Memory> {
        &self.memory
    }

    /// A handshake declaring a longer name can match nothing, so it is refused
    /// before a byte of the name is read.
    #[must_use]
    pub fn longest_namespace(&self) -> usize {
        self.namespaces.longest_name()
    }

    #[must_use]
    pub fn namespaces(&self) -> Arc<Published> {
        Arc::clone(&self.namespaces)
    }

    #[must_use]
    pub fn registries(&self) -> Registries {
        Registries {
            namespaces: Arc::clone(&self.namespaces),
            peers: Arc::downgrade(&self.sessions),
            leases: Arc::clone(self.leases.leases()),
        }
    }

    #[must_use]
    pub fn namespace(&self, name: &NamespaceName) -> Option<Arc<Namespace>> {
        self.namespaces.namespace(name)
    }

    #[must_use]
    pub fn mount_of(
        &self,
        name: &NamespaceName,
    ) -> Option<(Arc<Namespace>, Option<Arc<crate::records::RecordStore>>)> {
        self.namespaces.mount_of(name)
    }

    #[must_use]
    pub fn sessions(&self) -> Arc<Sessions> {
        Arc::clone(&self.sessions)
    }

    #[must_use]
    pub fn identity(&self) -> Identity {
        self.identity.clone()
    }
}
