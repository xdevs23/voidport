//! The session refers to its namespace by name: every path-resolving operation
//! asks the published registry, so a control-plane change is visible to the
//! next lookup. The snapshot the handshake resolved is kept only as the
//! tombstone: once the namespace is deleted, the session still serves the
//! policy and the grafts it mounted.

mod attr;
mod bookkeeping;
mod connections;
mod dir;
mod resolve;
mod tables;

use std::os::fd::AsFd;
use std::sync::{Arc, Mutex, Weak};

use rustix::io::Errno;
use voidport_control::NamespaceName;
use voidport_proto::attr::Attr;

use crate::control::service::Published;
use crate::data::descriptor_budget::{DescriptorBudget, Pinned};
use crate::data::handle::HandleTable;
use crate::data::ino::InoAllocator;
use crate::data::leases::Leases;
use crate::data::listener::Transport;
use crate::data::locks::LockSets;
use crate::data::node::{Node, NodeBacking, NodeKey, NodeTable, ROOT_NODE_ID};
use crate::data::recall::Recalls;
use crate::data::server::{Identity, Registries};
use crate::data::sessions::Sessions;
use crate::host::attr::HostAttr;
use crate::host::open::pin_relative_no_symlinks;
use crate::host::{FileKind, SynthesizedTimes};
use crate::namespace::Namespace;
use crate::records::RecordStore;
use crate::rules::NamespacePath;

pub use attr::PrivilegedView;
pub use connections::{Kept, Left, Link, Outcome};
pub use resolve::{ParentDir, Site};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub transport: Transport,
    pub address: String,
}

impl Peer {
    #[must_use]
    pub fn new(transport: Transport, address: impl Into<String>) -> Self {
        Self {
            transport,
            address: address.into(),
        }
    }
}

#[derive(Debug)]
pub struct MountTarget {
    pub namespace: Arc<Namespace>,
    pub records: Arc<RecordStore>,
    pub subpath: NamespacePath,
}

/// Produced together: the stat that decides whether ownership policy hides an
/// entry is the same stat the reply presents.
#[derive(Clone, Debug)]
pub struct Resolved {
    pub node: Node,
    pub attr: Attr,
    pub kind: FileKind,
}

#[derive(Debug)]
pub struct Session {
    id: u64,
    token: String,
    peer: Peer,
    subpath: NamespacePath,
    name: NamespaceName,
    namespaces: Arc<Published>,
    /// A rename through this mount moves a host entry that other mounts may hold
    /// nodes for. Weak because the registry has the strong references.
    peers: Weak<Sessions>,
    tombstone: Arc<Namespace>,
    /// Captured and not looked up per operation: the namespace snapshot is
    /// republished on every control mutation, while the store is one instance
    /// per name. A namespace deleted underneath this mount takes the registry
    /// entry, not the store a session still serving records through.
    records: Arc<RecordStore>,
    ino: Arc<InoAllocator>,
    /// Copied, not re-read, so the skeleton of a namespace never appears to
    /// change under a guest that caches attributes.
    synthesized_times: SynthesizedTimes,
    budget: Arc<DescriptorBudget>,
    nodes: Mutex<NodeTable>,
    handles: Mutex<HandleTable>,
    connections: Mutex<connections::Connections>,
    locks: Arc<LockSets>,
    leases: Arc<Leases>,
    recalls: Arc<Recalls>,
}

impl Session {
    /// The subpath walk is followed by a host walk that follows no symlink at
    /// all: a symlink in a mount subpath is a mount error, not a redirection.
    ///
    /// No node or handle id this session hands out was ever used by another
    /// session or by another lifetime of this server (see
    /// [`crate::data::ids`]). The mount root is the one exemption: it is node
    /// id 1 in every session, so the walk of a reconnecting client from the
    /// root heals instead of aliasing.
    pub fn mount(
        id: u64,
        token: String,
        peer: Peer,
        registries: Registries,
        target: MountTarget,
        identity: Identity,
    ) -> Result<Self, Errno> {
        let MountTarget {
            namespace,
            records,
            subpath,
        } = target;
        let Registries {
            namespaces,
            peers,
            leases,
        } = registries;
        let Identity {
            ino,
            generations,
            budget,
            synthesized_times,
        } = identity;
        let context = namespace.rules().walk(&subpath).ok_or(Errno::NOENT)?;
        let mut nodes = NodeTable::new(generations.space());
        match context.state() {
            crate::rules::DirState::Synthesized => {
                let root_ino = ino.synthesized(namespace.name(), context.path());
                nodes.install_root(
                    NodeKey::Directory(context.path().clone()),
                    root_ino,
                    context.path().clone(),
                    NodeBacking::Synthesized,
                );
            }
            crate::rules::DirState::HostBacked { backing, mode } => {
                let graft = namespace.grafts().graft_of(backing).ok_or(Errno::NOENT)?;
                let fd = pin_relative_no_symlinks(graft, backing.relative())?;
                let host = HostAttr::of(fd.as_fd())?;
                if !host.kind().is_directory() {
                    return Err(Errno::NOTDIR);
                }
                let root_ino = ino.host(host.host_identity());
                // The mount root must be presentable: a root the ownership
                // policy hides is a namespace the guest cannot see into.
                let privileged = if namespace.privileged_bits() {
                    crate::records::Privileged::Recorded(
                        records.records().bits(&host.node_identity()),
                    )
                } else {
                    crate::records::Privileged::Masked
                };
                host.present(root_ino, *mode, namespace.ownership(), privileged)
                    .ok_or(Errno::NOENT)?;
                // The mount root has no ancestor inside the namespace, so it
                // reopens by descending from its graft.
                let pin = budget.pin(Pinned {
                    fd,
                    path: context.path().clone(),
                    backing: backing.clone(),
                    identity: host.node_identity(),
                    recipe: backing.clone(),
                });
                nodes.install_root(
                    NodeKey::Directory(context.path().clone()),
                    root_ino,
                    context.path().clone(),
                    NodeBacking::Host {
                        pin,
                        mode: *mode,
                        kind: host.kind(),
                        cache: None,
                    },
                );
            }
        }
        Ok(Self {
            id,
            token,
            peer,
            subpath,
            name: namespace.name().clone(),
            namespaces,
            peers,
            tombstone: namespace,
            records,
            ino,
            synthesized_times,
            budget,
            nodes: Mutex::new(nodes),
            handles: Mutex::new(HandleTable::new(generations.space())),
            connections: Mutex::default(),
            locks: Arc::new(LockSets::default()),
            leases,
            recalls: Recalls::new(),
        })
    }
}

pub const ROOT: u64 = ROOT_NODE_ID;
