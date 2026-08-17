//! One mount: the session.
//!
//! A session is one data-plane connection: one client's mount of one namespace
//! subpath. It owns everything that mount can name — the node table, the handle
//! table — and it holds its namespace by **name**: every path-resolving
//! operation asks the published registry for the namespace of that name, so a
//! rule added, removed or downgraded through the control plane is visible to
//! the very next lookup (design: "Session lifecycle", the fresh-lookup decision).
//!
//! The snapshot the handshake resolved is kept only as the **tombstone**: once
//! the namespace is deleted the registry has nothing to answer with, and the
//! session keeps serving the policy and the pinned grafts it mounted until it
//! disconnects. Nodes and handles are untouched either way — a node's share
//! mode binds at the lookup that admitted it, and an open handle keeps working
//! (design: "Namespace lifecycle", "Policy binds at lookup").
//!
//! Resolution is the engine's, one component at a time, from the parent node's
//! namespace path; the host work — pinning, stat, ownership presentation — is
//! layered on top of each decision. A guest therefore cannot reach anything the
//! rule table does not admit, and cannot leave a graft even if the host tree
//! below it is full of symlinks.
//!
//! This file holds the type itself, what a mount is built from, and the values
//! every part of it speaks in. The rest is one concern per file, each an `impl
//! Session` block of its own:
//!
//! * `bookkeeping` — what the mount is, and the connection-lifetime facts the
//!   control plane reads off it;
//! * `tables` — the node and handle tables, and what an id names;
//! * `resolve` — the path-resolution and admission algorithm;
//! * `attr` — presented attributes and the ownership a created entry lands
//!   with;
//! * `dir` — a directory's materialized listing, and the re-pointing a move
//!   through the mount owes every node.

mod attr;
mod bookkeeping;
mod dir;
mod resolve;
mod tables;

use std::os::fd::AsFd;
use std::sync::{Arc, Mutex, Weak};

use rustix::io::Errno;
use voidport_control::NamespaceName;
use voidport_proto::attr::Attr;

use crate::control::service::Published;
use crate::data::caps::Limits;
use crate::data::handle::HandleTable;
use crate::data::ino::InoAllocator;
use crate::data::listener::Transport;
use crate::data::node::{Node, NodeBacking, NodeKey, NodeTable, ROOT_NODE_ID};
use crate::data::pin::{DescriptorBudget, Pinned};
use crate::data::server::{Identity, Registries};
use crate::data::sessions::Sessions;
use crate::data::subscribe::NotificationQueue;
use crate::host::attr::HostAttr;
use crate::host::open::pin_relative_no_symlinks;
use crate::host::{FileKind, SynthesizedTimes};
use crate::namespace::Namespace;
use crate::records::RecordStore;
use crate::rules::NamespacePath;

pub use attr::PrivilegedView;
pub use resolve::{ParentDir, Site};

/// Where a session came from, for the operator's session list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The transport it arrived on.
    pub transport: Transport,
    /// The peer address, as the transport describes it.
    pub address: String,
}

impl Peer {
    /// Describes a peer.
    #[must_use]
    pub fn new(transport: Transport, address: impl Into<String>) -> Self {
        Self {
            transport,
            address: address.into(),
        }
    }
}

/// A node together with the attributes to reply with.
///
/// Every entry reply carries both, and they are produced together: the stat
/// that decides whether ownership policy hides an entry is the same stat the
/// reply presents.
#[derive(Clone, Debug)]
pub struct Resolved {
    /// The node, already counted as one lookup.
    pub node: Node,
    /// Its presented attributes.
    pub attr: Attr,
    /// What kind of host entry it is; synthesized directories report
    /// [`FileKind::Directory`].
    pub kind: FileKind,
}

/// One client's mount.
#[derive(Debug)]
pub struct Session {
    id: u64,
    peer: Peer,
    subpath: NamespacePath,
    /// The namespace this mount serves, by name: the key every path-resolving
    /// operation looks the current snapshot up under.
    name: NamespaceName,
    /// The published registry, consulted per path-resolving operation.
    namespaces: Arc<Published>,
    /// Every mount the server is serving, this one included.
    ///
    /// Read for one purpose: a rename through *this* mount moves a host entry
    /// that the *other* mounts may hold nodes for, and the design's "the server
    /// never stales what it renamed itself" is unqualified — it means every
    /// session's nodes, not merely the renaming session's. Weak because the
    /// registry owns the sessions; a session only observes it.
    peers: Weak<Sessions>,
    /// The snapshot the handshake resolved, kept only for after the namespace
    /// is deleted.
    tombstone: Arc<Namespace>,
    /// The namespace's record store, captured at handshake beside the
    /// namespace resolution.
    ///
    /// Captured and not looked up per operation, because the two have different
    /// lifetimes on purpose: the namespace snapshot is republished on every
    /// control mutation, while the store is one instance per name. A namespace
    /// deleted underneath this mount takes the *registry entry*, not the store
    /// a session still serving is recording through — it retires instead, and
    /// stops taking writes.
    records: Arc<RecordStore>,
    ino: Arc<InoAllocator>,
    /// The timestamps this session's synthesized directories present, captured
    /// once when the server started. Copied, not re-read, so the
    /// skeleton of a namespace never appears to change under a guest that
    /// caches attributes.
    synthesized_times: SynthesizedTimes,
    /// The server-global descriptor cache every node of this session pins
    /// through.
    budget: Arc<DescriptorBudget>,
    limits: Limits,
    nodes: Mutex<NodeTable>,
    handles: Mutex<HandleTable>,
    /// The share subscription's outgoing queue, drained by this connection's
    /// writer beside its replies.
    ///
    /// Every session owns one, subscribed or not: it costs an empty deque, and
    /// making it conditional would mean the connection's writer had to learn
    /// about a queue appearing under it mid-flight. Nothing is ever pushed into
    /// it until the session registers with the subscriber registry, and a
    /// session that never subscribes never receives a notification.
    notifications: Arc<NotificationQueue>,
}

impl Session {
    /// Resolves a mount and builds the session that serves it.
    ///
    /// The subpath walk is an ordinary component walk through the rule table,
    /// followed by a host walk that **follows no symlink at all**: a symlink in
    /// a mount subpath is a mount error, not a redirection.
    ///
    /// `namespace` is the snapshot the handshake resolved out of `registries`.
    /// The mount root is pinned from it, and it then becomes the session's
    /// tombstone; everything after the handshake resolves against whatever the
    /// registry publishes under the same name.
    ///
    /// `identity` carries the server-global sources this session names things
    /// from: inos, and the generations both id tables take their id spaces
    /// from. No node or handle id this session hands out was ever used by
    /// another session or by another lifetime of this server (see
    /// [`crate::data::ids`]). The mount root is the one exemption: it is node
    /// id 1 in every session, which is what makes a reconnecting client's walk
    /// from the root heal instead of aliasing.
    ///
    /// # Errors
    ///
    /// * `ENOENT` — the subpath does not resolve, or ownership policy hides the
    ///   directory it names;
    /// * `ENOTDIR` — it names something that is not a directory;
    /// * `ELOOP` — a component of it is a symlink;
    /// * any other host errno from pinning the mount root.
    #[allow(
        clippy::too_many_arguments,
        reason = "a mount is built from the server-global sources and the policy it resolved; every one of them is named here on purpose"
    )]
    pub fn mount(
        id: u64,
        peer: Peer,
        registries: Registries,
        namespace: Arc<Namespace>,
        records: Arc<RecordStore>,
        subpath: NamespacePath,
        identity: Identity,
        limits: Limits,
    ) -> Result<Self, Errno> {
        let Registries { namespaces, peers } = registries;
        let Identity {
            ino,
            generations,
            budget,
            synthesized_times,
        } = identity;
        let context = namespace.rules().walk(&subpath).ok_or(Errno::NOENT)?;
        let mut nodes = NodeTable::new(limits.max_nodes, generations.space());
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
                // The mount root presents its recorded bits like any other
                // host-backed node: it is a file of the namespace, not a
                // fixture of the mount.
                let privileged = if namespace.privileged_bits() {
                    crate::records::Privileged::Recorded(
                        records.records().bits(&host.node_identity()),
                    )
                } else {
                    crate::records::Privileged::Masked
                };
                host.present(root_ino, *mode, namespace.ownership(), privileged)
                    .ok_or(Errno::NOENT)?;
                // The mount root is a cache slot like any other: it has no
                // ancestor inside the namespace, so it re-pins by descending
                // from its graft, which is what a fresh mount would do.
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
                    },
                );
            }
        }
        Ok(Self {
            id,
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
            limits,
            nodes: Mutex::new(nodes),
            handles: Mutex::new(HandleTable::new(limits.max_handles, generations.space())),
            notifications: NotificationQueue::new(),
        })
    }
}

/// The node id every session's mount root has.
pub const ROOT: u64 = ROOT_NODE_ID;
