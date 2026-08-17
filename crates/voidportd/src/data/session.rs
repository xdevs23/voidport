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

use std::cell::Cell;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use rustix::fs::{Dir, OFlags};
use rustix::io::Errno;
use voidport_control::{NamespaceName, SessionSummary};
use voidport_proto::attr::Attr;

use crate::control::service::Published;
use crate::data::caps::Limits;
use crate::data::handle::{DirListing, HandleTable, ListingEntry};
use crate::data::ino::InoAllocator;
use crate::data::listener::Transport;
use crate::data::node::{Interned, Move, Node, NodeBacking, NodeKey, NodeTable, ROOT_NODE_ID};
use crate::data::pin::{DescriptorBudget, NodePin, Pinned};
use crate::data::server::{Identity, Registries};
use crate::data::sessions::Sessions;
use crate::data::subscribe::NotificationQueue;
use crate::host::attr::HostAttr;
use crate::host::open::{pin_child, pin_relative, pin_relative_no_symlinks, reopen};
use crate::host::{FileKind, HostIdentity, SynthesizedTimes, synthesized_attr};
use crate::namespace::Namespace;
use crate::rules::{
    DirContext, EffectiveMode, GuestIds, HostBacking, Name, NamespacePath, Resolution,
};

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
    pub fn mount(
        id: u64,
        peer: Peer,
        registries: Registries,
        namespace: Arc<Namespace>,
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
                host.present(root_ino, *mode, namespace.ownership())
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
            ino,
            synthesized_times,
            budget,
            limits,
            nodes: Mutex::new(nodes),
            handles: Mutex::new(HandleTable::new(limits.max_handles, generations.space())),
            notifications: NotificationQueue::new(),
        })
    }

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

    /// The node table.
    pub fn nodes(&self) -> MutexGuard<'_, NodeTable> {
        self.nodes
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// The handle table.
    pub fn handles(&self) -> MutexGuard<'_, HandleTable> {
        self.handles
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// The node an id names.
    ///
    /// # Errors
    ///
    /// Returns `ESTALE` for an id this session never handed out or has already
    /// forgotten — the node is gone, which is exactly what stale means.
    pub fn node(&self, id: u64) -> Result<Node, Errno> {
        self.nodes().get(id).ok_or(Errno::STALE)
    }

    /// The node an id names, required to be a directory.
    ///
    /// # Errors
    ///
    /// As [`Self::node`], plus `ENOTDIR`.
    pub fn directory(&self, id: u64) -> Result<Node, Errno> {
        let node = self.node(id)?;
        if node.is_directory() {
            Ok(node)
        } else {
            Err(Errno::NOTDIR)
        }
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

    /// Resolves `name` under a directory node, counting the lookup.
    ///
    /// This is the whole of lookup: the engine decides, the host is asked, and
    /// ownership policy gets the last word — an entry whose owner the policy
    /// hides does not exist, exactly as a hidden rule's would not.
    ///
    /// # Errors
    ///
    /// `ENOENT` when the entry does not resolve or is hidden, `ENFILE` when the
    /// node table is full, `ENOTDIR` for a lookup under a file, and any host
    /// errno from pinning or stat.
    pub fn lookup(&self, parent: &Node, name: &Name) -> Result<Resolved, Errno> {
        let namespace = self.namespace();
        let parent = self.parent_dir(&namespace, parent)?;
        let resolution = namespace.rules().resolve(&parent.context, name);
        self.admit(&namespace, &parent, name, &resolution)
    }

    /// The **live** policy context of a directory node, and the descriptor its
    /// children are pinned from.
    ///
    /// The context is re-derived from the snapshot the caller is serving this
    /// operation against — the directory's namespace path is walked again —
    /// and not taken from the state the node was created with. That is what
    /// makes a *directory-level* policy change reach a mounted guest: a graft
    /// downgraded to read-only, removed, or re-pointed at another host path is
    /// observed by the very next child lookup, because the parent's effective
    /// mode and backing are read fresh each time. Freezing them in the node
    /// would make the operator's canonical "cut them off" action invisible to
    /// exactly the sessions it is aimed at (design: the 2026-08-13 adversarial
    /// review, "Directory nodes freeze policy context").
    ///
    /// Node identity is untouched by this: the node keeps its id, its ino and
    /// its own share mode — the mode a node was admitted under still governs
    /// what may be done *through it*. Only the policy its children are resolved
    /// under is live.
    ///
    /// # Errors
    ///
    /// `ENOTDIR` for a node that is not a directory, and `ENOENT` when the
    /// directory's namespace path no longer resolves at all — the namespace no
    /// longer has that directory, so it has no children either.
    pub fn parent_dir(&self, namespace: &Namespace, node: &Node) -> Result<ParentDir, Errno> {
        if !node.is_directory() {
            return Err(Errno::NOTDIR);
        }
        let context = namespace.rules().walk(&node.path).ok_or(Errno::NOENT)?;
        // The *slot* is taken, not the descriptor: a re-target makes the pin
        // irrelevant, and re-pinning a directory only to discard it would turn
        // a re-pointed graft into a spurious `ESTALE`. The descriptor is
        // materialized where it is actually used.
        Ok(ParentDir {
            context,
            pinned: node.pin().map(Arc::clone),
        })
    }

    /// Turns one resolution into a node and its attributes.
    ///
    /// Shared by lookup and the entry replies of the creating operations, so
    /// all of them apply the same ownership filter and the same node-keying
    /// rules. The snapshot is the caller's, so one operation cannot resolve a
    /// rule against one snapshot and a graft against the next.
    ///
    /// # Errors
    ///
    /// As [`Self::lookup`].
    pub fn admit(
        &self,
        namespace: &Namespace,
        parent: &ParentDir,
        name: &Name,
        resolution: &Resolution,
    ) -> Result<Resolved, Errno> {
        let path = parent.context.path().child(name);
        match resolution {
            Resolution::Nonexistent => Err(Errno::NOENT),
            Resolution::SynthesizedDir => self.admit_synthesized(namespace, path),
            Resolution::HostBacked { backing, mode } => {
                let (fd, recipe) = self.pin(namespace, parent, name, backing)?;
                self.admit_pinned_in(namespace, path, fd, recipe, backing.clone(), *mode)
            }
        }
    }

    /// Admits one entry of a materialized listing.
    ///
    /// This is [`Self::admit`] for the one caller that already knows *which
    /// inode* the entry is: `readdirplus` walking a listing whose every entry
    /// was stat'd once, at `opendir`, to decide it was visible at all. A node
    /// is keyed by that identity, so an entry the session has already seen —
    /// every entry of the second listing of a directory — is named, and its
    /// lookup counted, **without opening it again**: the `openat2` pin, the
    /// most expensive primitive in a listing, is paid once per entry per
    /// session, not once per entry per listing.
    ///
    /// Its **attributes are read here**, not carried from `opendir`. An entry
    /// reply is what a guest caches a file's size by, and handing it a size
    /// that was already old when the reply was built makes a following read of
    /// a file another writer is extending return that stale length — measured,
    /// not theorised.
    ///
    /// **No host syscall runs under the node table.** A listing batch is
    /// hundreds of entries and every other operation of this session — a
    /// lookup, a getattr, a write's entry reply — needs that table, so the
    /// guard is taken for the table work of one entry (a hash lookup, an
    /// insertion) and dropped before the pin or the stat that surrounds it. The
    /// batching win the listing path is measured on is the *pin* an entry the
    /// session has already seen no longer pays, not a longer hold (design: the
    /// 2026-08-14 optimisation-boundary disposition, "Host syscalls leave the
    /// node-table guard").
    ///
    /// # Errors
    ///
    /// As [`Self::lookup`].
    pub fn admit_listed(
        &self,
        namespace: &Namespace,
        parent: &ParentDir,
        entry: &ListingEntry,
    ) -> Result<Resolved, Errno> {
        let (Resolution::HostBacked { backing, mode }, Some(identity)) =
            (&entry.resolution, entry.identity)
        else {
            // A synthesized directory has no host entry to have stat'd.
            return match entry.resolution {
                Resolution::SynthesizedDir => {
                    let path = parent.context.path().child(&entry.name);
                    self.admit_synthesized(namespace, path)
                }
                _ => Err(Errno::NOENT),
            };
        };

        let key = NodeKey::listed(parent.context.path(), &entry.name, identity, *mode);
        // Bound to a `let` so the guard is dropped here instead of living to
        // the end of the block below, which stats the host and may need the
        // table again to give the lookup back.
        //
        // The listing's own stat is what says whether the node under that key
        // is still this entry: a directory replaced on the host since the
        // session pinned it keys the same namespace path, and the node holding
        // it is retired, not listed as the entry that replaced it.
        let seen = self
            .nodes()
            .revisit(&key, Some(crate::host::NodeIdentity::listed(identity)));
        if let Some(node) = seen {
            // The node's own pinned descriptor answers the stat, so the reply
            // describes the inode the session listed even if the host has since
            // put something else under that name — which is the same rule a
            // repeated lookup follows. The lookup `revisit` just counted is
            // what keeps that node alive while the stat runs unlocked.
            let attr = self.counted_attr(namespace, &node)?;
            return Ok(Resolved {
                kind: node.kind(),
                node,
                attr,
            });
        }
        let (fd, recipe) = self.pin(namespace, parent, &entry.name, backing)?;
        let path = parent.context.path().child(&entry.name);
        self.admit_pinned_in(namespace, path, fd, recipe, backing.clone(), *mode)
    }

    /// Interns a synthesized directory and answers with its fixed attributes.
    ///
    /// Nothing here touches the host, so the table work is all there is.
    fn admit_synthesized(
        &self,
        namespace: &Namespace,
        path: NamespacePath,
    ) -> Result<Resolved, Errno> {
        let ino = self.ino.synthesized(&self.name, &path);
        // No identity to offer, and none to compare against: a synthesized
        // directory is the rule table's own structure, not a host entry.
        let (node, _) = self
            .nodes()
            .intern(NodeKey::Directory(path.clone()), None, |id| Node {
                id,
                ino,
                path,
                backing: NodeBacking::Synthesized,
            })?;
        Ok(Resolved {
            attr: synthesized_attr(node.ino, namespace.ownership(), self.synthesized_times),
            node,
            kind: FileKind::Directory,
        })
    }

    /// Interns an already pinned host entry.
    ///
    /// The creating operations (create, mkdir, symlink, link) take this path:
    /// they have just made the entry and pinned it, and only need it to become
    /// a node with an entry reply.
    ///
    /// # Errors
    ///
    /// As [`Self::lookup`].
    pub fn admit_pinned(
        &self,
        path: NamespacePath,
        fd: OwnedFd,
        recipe: HostBacking,
        backing: HostBacking,
        mode: EffectiveMode,
    ) -> Result<Resolved, Errno> {
        self.admit_pinned_in(&self.namespace(), path, fd, recipe, backing, mode)
    }

    /// [`Self::admit_pinned`], against a snapshot the caller already took.
    ///
    /// The stat of what was pinned runs *before* the node table is touched, and
    /// the stat of an entry the session already holds runs after the guard is
    /// dropped: naming a node is table work, and reading a file's attributes is
    /// host work, and the two never overlap.
    ///
    /// The cache slot is filed **before** the table is touched too, for the
    /// same reason: admitting a slot may evict another, and closing the evicted
    /// descriptor is a host syscall. A slot whose node turns out to exist
    /// already is given straight back when the unused pin is dropped.
    fn admit_pinned_in(
        &self,
        namespace: &Namespace,
        path: NamespacePath,
        fd: OwnedFd,
        recipe: HostBacking,
        backing: HostBacking,
        mode: EffectiveMode,
    ) -> Result<Resolved, Errno> {
        let host = HostAttr::of(fd.as_fd())?;
        let identity = host.host_identity();
        let ino = self.ino.host(identity);
        // The ownership filter runs on what was just pinned: an entry whose
        // owner the policy hides does not exist, whatever the session may
        // already hold under that name.
        let fresh = host
            .present(ino, mode, namespace.ownership())
            .ok_or(Errno::NOENT)?;
        let kind = identity.kind;
        let key = NodeKey::of(&path, identity, mode);
        let found = host.node_identity();
        let pin = self.budget.pin(Pinned {
            fd,
            path: path.clone(),
            backing,
            identity: found,
            recipe: recipe.clone(),
        });
        let (node, interned) = self.nodes().intern(key, Some(found), |id| Node {
            id,
            ino,
            path,
            backing: NodeBacking::Host {
                pin: Arc::clone(&pin),
                mode,
                kind,
            },
        })?;
        // An existing node is one the table has just **proved** names this very
        // entry: a key whose node named something else was retired, and this
        // resolution minted a fresh node in its place. So the two arms are the
        // node just pinned, and the node the session already had for the file
        // in hand — never the impostor at a name the session pinned earlier.
        let (attr, kind) = match interned {
            Interned::Created => (fresh, kind),
            Interned::Existing => {
                // The session already had this entry under another name — a
                // hard link's other name, above all. What was just pinned *is*
                // that inode, so the recipe it was reached by is a fresher way
                // back to it than the one the node holds: adopting it is what
                // keeps a link plus an unlink of the original name from
                // stale-ing a node the server itself moved.
                if let Some(held) = node.pin() {
                    held.rebind(recipe);
                }
                (self.counted_attr(namespace, &node)?, node.kind())
            }
        };
        Ok(Resolved { node, attr, kind })
    }

    /// The attributes of a node whose lookup has **already been counted**.
    ///
    /// Naming a node is what counts the lookup, so anything fallible after it
    /// has a debt to settle: a caller that fails here sends no entry reply
    /// describing the node, so the client is never told about that lookup and
    /// can never `forget` it. `readdirplus` is where this bites — it *skips* an
    /// entry whose ownership policy has come to hide it since the listing was
    /// materialized, and a skipped entry would otherwise pin its node for the
    /// life of the session. The count is given back on every failing path, so
    /// "one lookup counted per entry reply sent" holds however the stat ends.
    ///
    /// The stat is taken with no lock held; the table is touched only to settle
    /// that debt.
    fn counted_attr(&self, namespace: &Namespace, node: &Node) -> Result<Attr, Errno> {
        self.attr_in(namespace, node).inspect_err(|_| {
            self.nodes().forget(node.id, 1);
        })
    }

    /// Locates `name` under `parent` for an entry-modifying operation.
    ///
    /// This is where directory-modifying enforcement lives, in one place, so
    /// create, mkdir, symlink, link, unlink, rmdir and rename cannot drift
    /// apart:
    ///
    /// * the **parent node** must be writable, so a read-only graft — or a
    ///   synthesized directory, which has nothing to write to — fails `EROFS`;
    /// * the **name** must resolve to an admitted host-backed entry, because a
    ///   name the namespace hides cannot be created (the guest would not see
    ///   what it made) or removed (it does not exist); that is `EACCES`;
    /// * the entry's **own** effective mode must be writable, so a read-only
    ///   literal rule inside a read-write graft still protects its entry.
    ///
    /// The site it returns is always a directory descriptor plus a *single*
    /// component. The entry-modifying syscalls take no resolution flags, so
    /// handing them one component of a descriptor obtained under containment is
    /// what keeps them contained.
    ///
    /// # Errors
    ///
    /// `EROFS`, `EACCES` or `EPERM` per the rules above, plus any host errno
    /// from pinning the target's directory.
    pub fn site(&self, parent: &Node, name: &Name) -> Result<Site, Errno> {
        let namespace = self.namespace();
        parent.require_writable()?;
        let parent = self.parent_dir(&namespace, parent)?;
        let resolution = namespace.rules().resolve(&parent.context, name);
        let Resolution::HostBacked { backing, mode } = resolution else {
            return Err(Errno::ACCESS);
        };
        if !mode.is_writable() {
            return Err(Errno::ROFS);
        }
        if let Some((directory, fd)) = parent.child_site(name, &backing, &namespace)? {
            return Ok(Site {
                directory: crate::host::open::dup(fd.as_fd())?,
                recipe: child_recipe(&directory, &backing, name),
                name: name.clone(),
                backing,
                mode,
            });
        }
        // A re-targeted rule names another graft. Its own root has no parent
        // inside the namespace, so it is not created or removed through the
        // directory that merely shows it.
        let Some((last, leading)) = backing.relative().split_last() else {
            return Err(Errno::PERM);
        };
        let graft = namespace.grafts().graft_of(&backing).ok_or(Errno::NOENT)?;
        Ok(Site {
            directory: pin_relative(graft, leading)?,
            recipe: backing.clone(),
            name: last.clone(),
            backing,
            mode,
        })
    }

    /// The host owner a guest-created entry must land with.
    ///
    /// Applying it can fail — a host id other than the server's own needs
    /// `CAP_CHOWN` — and that failure is deliberately not fatal: the entry then
    /// stays owned by the server identity, and presentation forward-maps
    /// whatever the host actually recorded, so the guest's view stays
    /// consistent either way.
    pub fn apply_create_ownership(&self, fd: BorrowedFd<'_>, caller: GuestIds) {
        self.chown_created(
            rustix::fs::CWD,
            crate::host::open::proc_path(fd).as_str(),
            rustix::fs::AtFlags::empty(),
            caller,
        );
    }

    /// [`Self::apply_create_ownership`], for a symlink, which is owned through
    /// the directory it was created in and its own name.
    ///
    /// A symlink is the one created kind a descriptor cannot speak for. An
    /// `O_PATH` pin of it answers `EPERM` to a chown naming the empty path, and
    /// the `/proc/self/fd` form makes the *magic link* the final component — so
    /// `AT_SYMLINK_NOFOLLOW` there owns procfs' own object, reports success,
    /// and leaves the link the guest made owned by the server. Naming the entry
    /// in its parent is what reaches the link itself.
    ///
    /// It stays as contained as the creation was: the descriptor is the very
    /// one the `symlinkat` was issued against, the name is that same single
    /// component, and `AT_SYMLINK_NOFOLLOW` keeps the chown off whatever the
    /// link names. What the name can no longer promise is the *inode* — a host
    /// writer that replaces the name in between is owned instead of the link —
    /// and it is bounded to the directory a create was already admitted into.
    pub fn apply_create_symlink_ownership(&self, site: &Site, caller: GuestIds) {
        self.chown_created(
            site.directory.as_fd(),
            site.name.as_bytes(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            caller,
        );
    }

    /// Applies the create ownership contract to one named host entry.
    fn chown_created<P: rustix::path::Arg>(
        &self,
        directory: BorrowedFd<'_>,
        path: P,
        flags: rustix::fs::AtFlags,
        caller: GuestIds,
    ) {
        let host = self.namespace().ownership().reverse_for_create(caller);
        let result = rustix::fs::chownat(
            directory,
            path,
            Some(rustix::process::Uid::from_raw(host.uid)),
            Some(rustix::process::Gid::from_raw(host.gid)),
            flags,
        );
        if let Err(error) = result {
            tracing::debug!(
                %error,
                uid = host.uid,
                gid = host.gid,
                "a created entry keeps the server's own ownership"
            );
        }
    }

    /// Reads a node's attributes fresh from the host.
    ///
    /// # Errors
    ///
    /// `ENOENT` when ownership policy hides the entry, or the host errno.
    pub fn attr(&self, node: &Node) -> Result<Attr, Errno> {
        self.attr_in(&self.namespace(), node)
    }

    /// [`Self::attr`], against a snapshot the caller already took.
    fn attr_in(&self, namespace: &Namespace, node: &Node) -> Result<Attr, Errno> {
        let ownership = namespace.ownership();
        let NodeBacking::Host { mode, .. } = &node.backing else {
            return Ok(synthesized_attr(
                node.ino,
                ownership,
                self.synthesized_times,
            ));
        };
        let fd = node.descriptor(namespace)?.ok_or(Errno::STALE)?;
        HostAttr::of(fd.as_fd())?
            .present(node.ino, *mode, ownership)
            .ok_or(Errno::NOENT)
    }

    /// Where an admitted entry is reached from on the host.
    ///
    /// One decision, made once for everything that touches an entry named by a
    /// listing or a lookup: is this really a host child of the directory the
    /// guest named, or does a *re-targeted* literal rule put it in another
    /// graft entirely? The two answers demand different containment shapes —
    /// one component off the parent's own pin, or a contained walk from the
    /// graft's descriptor — and deriving that per operation is how the two
    /// would drift apart. Each caller applies its own final syscall to the
    /// site: [`Self::pin`] opens it, [`Self::stat_entry`] stats it.
    fn entry_site<'a>(
        &self,
        namespace: &'a Namespace,
        parent: &ParentDir,
        name: &Name,
        backing: &'a HostBacking,
    ) -> Result<EntrySite<'a>, Errno> {
        match parent.child_site(name, backing, namespace)? {
            Some((directory, fd)) => Ok(EntrySite::Child { directory, fd }),
            None => Ok(EntrySite::Grafted {
                graft: namespace.grafts().graft_of(backing).ok_or(Errno::NOENT)?,
                relative: backing.relative(),
            }),
        }
    }

    /// Pins the host entry a resolution admitted, and records how to pin it
    /// again.
    ///
    /// A child of a host-backed directory is pinned from the parent's own
    /// descriptor — one component, under containment — and records that
    /// directory's **own** recorded path plus the component, which is the whole
    /// path from the graft root and therefore the walk a fresh resolution would
    /// make. The parent's recorded path, not the namespace's, is what
    /// makes this right after a rename *through the mount*: the namespace still
    /// describes the entry where the guest first found it, while the parent's
    /// record has followed the move.
    ///
    /// A child admitted through a *re-targeted* literal rule belongs to another
    /// graft, so it is pinned, and re-pinned, from that graft's descriptor
    /// instead.
    fn pin(
        &self,
        namespace: &Namespace,
        parent: &ParentDir,
        name: &Name,
        backing: &HostBacking,
    ) -> Result<(OwnedFd, HostBacking), Errno> {
        match self.entry_site(namespace, parent, name, backing)? {
            EntrySite::Child { directory, fd } => Ok((
                pin_child(fd.as_fd(), name)?,
                child_recipe(&directory, backing, name),
            )),
            EntrySite::Grafted { graft, relative } => {
                Ok((pin_relative(graft, relative)?, backing.clone()))
            }
        }
    }

    /// Materializes the merged, policy-filtered listing of a directory node.
    ///
    /// A synthesized directory lists exactly its structural children. A
    /// host-backed one lists the union of its host children and its
    /// literal-rule children — so a re-targeted graft appears in `ls` as well
    /// as in `stat` — with every entry decided by the engine and every hidden
    /// one, whether hidden by a rule or by ownership policy, removed.
    ///
    /// Host names are consumed one at a time and only admitted entries are
    /// retained, so the memory a listing costs is the size of the listing — not
    /// the size of the host directory it was read from. A configured cap bounds
    /// that size as well, for an operator who wants a ceiling on a directory
    /// they did not choose; unconfigured, the listing is as large as the
    /// directory is, which is what the host filesystem itself would hand a
    /// local reader.
    ///
    /// # Errors
    ///
    /// `EOVERFLOW` for a listing larger than a configured cap, `ENOTDIR` for a
    /// node that is not a directory, or the host errno of reading the
    /// directory.
    pub fn materialize(&self, node: &Node) -> Result<DirListing, Errno> {
        let namespace = self.namespace();
        let parent = self.parent_dir(&namespace, node)?;
        let limit = self.limits.max_listing_entries;
        let keep = |name: &Name, resolution: &Resolution| {
            self.listed(&namespace, &parent, name, resolution)
        };

        let failure = Cell::new(None);
        let pinned;
        let repinned;
        let entries = match parent.context.backing() {
            // A synthesized directory has no host children at all: its listing
            // is what the rule table puts beneath it.
            None => namespace
                .rules()
                .enumerate(&parent.context, std::iter::empty(), limit, keep),
            Some(backing) => {
                let fd = match parent.pinned_at(backing, &namespace)? {
                    Some((_, fd)) => {
                        pinned = fd;
                        pinned.as_fd()
                    }
                    // The node's pin no longer names this directory — the graft
                    // was re-pointed — so the listing comes from where the
                    // namespace says the directory is now.
                    None => {
                        let graft = namespace.grafts().graft_of(backing).ok_or(Errno::NOENT)?;
                        repinned = pin_relative(graft, backing.relative())?;
                        repinned.as_fd()
                    }
                };
                namespace
                    .rules()
                    .enumerate(&parent.context, host_names(fd, &failure)?, limit, keep)
            }
        };
        // A directory the server could not finish reading has not been listed,
        // and saying otherwise would report a short listing as the whole truth.
        if let Some(error) = failure.get() {
            return Err(error);
        }
        let entries = entries
            .ok_or(Errno::OVERFLOW)?
            .into_iter()
            .map(|entry| ListingEntry {
                name: entry.name,
                resolution: entry.resolution,
                identity: entry.kept,
            })
            .collect();
        DirListing::new(entries, limit)
    }

    /// Whether an admitted entry survives ownership policy, and the host
    /// metadata that decided it.
    ///
    /// `unmapped: hide` is decided per file, so it needs the host owner; an
    /// entry that has vanished since the directory was read is dropped too,
    /// because a listing that names entries a lookup cannot find is worse than
    /// a listing that is one entry short.
    ///
    /// `None` drops the entry. `Some(None)` keeps a synthesized directory,
    /// which has no host entry and no owner to judge; `Some(Some(identity))`
    /// keeps a host entry together with the identity the stat that judged it
    /// reported, which is what names its node when the entry is emitted.
    fn listed(
        &self,
        namespace: &Namespace,
        parent: &ParentDir,
        name: &Name,
        resolution: &Resolution,
    ) -> Option<Option<HostIdentity>> {
        let Resolution::HostBacked { backing, mode } = resolution else {
            return Some(None);
        };
        let host = self.stat_entry(namespace, parent, name, backing).ok()?;
        host.present(0, *mode, namespace.ownership())?;
        Some(Some(host.host_identity()))
    }

    /// Reads the metadata of an admitted entry, without pinning it.
    ///
    /// A child of a host-backed directory is stat'd **by name against the
    /// parent's own pinned descriptor**: one component, `AT_SYMLINK_NOFOLLOW`,
    /// no assembled path — the same resolution shape [`pin_child`] runs under
    /// `RESOLVE_BENEATH`, since neither can name anything outside the pinned
    /// directory and neither follows a symlink. What it saves is the descriptor
    /// itself, which a visibility decision opens only to close again (design:
    /// the 2026-08-13 hot-path profiling disposition, "statx for the visibility
    /// check only where the name is a single component resolved NOFOLLOW
    /// against the pinned parent").
    ///
    /// A child admitted through a *re-targeted* literal rule is not a child of
    /// this directory on the host at all — it belongs to another graft — so it
    /// keeps the contained walk from that graft's descriptor, which costs the
    /// descriptor this path exists to save.
    fn stat_entry(
        &self,
        namespace: &Namespace,
        parent: &ParentDir,
        name: &Name,
        backing: &HostBacking,
    ) -> Result<HostAttr, Errno> {
        match self.entry_site(namespace, parent, name, backing)? {
            EntrySite::Child { fd, .. } => HostAttr::of_child(fd.as_fd(), name),
            EntrySite::Grafted { graft, relative } => {
                HostAttr::of(pin_relative(graft, relative)?.as_fd())
            }
        }
    }

    /// Re-points the recorded host paths of every node — in **every** mount —
    /// that the moves affect.
    ///
    /// A rename or a link through the mount is the server moving a file it may
    /// still be asked about by node id, and a node whose recorded path still
    /// names the old place would answer `ESTALE` for a move the server
    /// performed itself. The `ESTALE` surface is host-side *external* mutation,
    /// and this is what keeps it that way.
    ///
    /// The move is not this session's private business, and the design says so
    /// without qualification: another mount of the same namespace — or another
    /// namespace grafting the same host directory — holds nodes for the very
    /// entry that moved, and one host directory grafted at two namespace paths
    /// is two nodes in one table. All of them are re-pointed here, and all of
    /// them to the same thing: a whole host path from a graft root is a way
    /// back every namespace holding that target can walk, so no mount's nodes
    /// depend on another mount's cache slots, and every table takes the very
    /// same pass.
    ///
    /// **One table at a time.** The peers are taken as a snapshot and each
    /// table is locked and released in turn — no session ever holds two node
    /// tables, and no lock is held across the registry's.
    pub fn rebind(&self, moves: &[Move]) {
        self.nodes().rebind_moved(moves);
        let Some(peers) = self.peers.upgrade() else {
            return;
        };
        for peer in peers.live() {
            if std::ptr::eq(peer.as_ref(), self) {
                continue;
            }
            peer.nodes().rebind_moved(moves);
        }
    }
}

/// Where an entry lives relative to what the session already holds pinned.
///
/// [`Session::entry_site`] is the only thing that decides between the two, and
/// both arms are containment shapes the host layer enforces: a single component
/// off a pinned directory, or a `RESOLVE_BENEATH` walk from a graft root.
#[derive(Debug)]
enum EntrySite<'a> {
    /// The entry is a host child of the directory it was named in, reachable as
    /// one component of that directory's own pinned descriptor.
    Child {
        /// The directory's own recorded host path, which the child's whole
        /// path — its way back — is one component below.
        directory: HostBacking,
        /// Its descriptor, re-pinned already if the budget had evicted it.
        fd: Arc<OwnedFd>,
    },
    /// The entry belongs to another graft — a re-targeted literal rule — and is
    /// reached by its path relative to that graft's root.
    Grafted {
        /// The graft's pinned root.
        graft: BorrowedFd<'a>,
        /// The entry's path below it.
        relative: &'a [Name],
    },
}

/// Where an entry lives on the host: a directory descriptor and the single
/// component naming the entry inside it.
///
/// Every entry-modifying syscall takes exactly this shape, which is what keeps
/// them to one component of a contained descriptor.
#[derive(Debug)]
pub struct Site {
    /// The directory the entry lives in.
    pub directory: OwnedFd,
    /// The entry's name inside it — not necessarily the name the guest used,
    /// since a re-targeted rule renames as it re-points.
    pub name: Name,
    /// Where the namespace says the entry lives, for the node it will become.
    pub backing: HostBacking,
    /// The entry's whole host path as it will be **on the host** once the
    /// operation has run: how a node landing here re-pins itself, and where a
    /// node moved here is re-pointed at.
    ///
    /// It differs from `backing` exactly where the parent directory has been
    /// renamed through the mount since the guest resolved it — the namespace
    /// still describes it under its old name, and the parent's recorded path
    /// does not.
    pub recipe: HostBacking,
    /// The effective share mode of the entry.
    pub mode: EffectiveMode,
}

/// The whole host path of a child of a pinned directory, from its graft root
/// down.
///
/// One component below the directory's **recorded** path, because that is where
/// the host really has it — the namespace still describes a directory the
/// server renamed under its old name, and a child pinned through it must record
/// where it went, not where the guest first found it.
///
/// Wherever the two agree — everything a rename has not touched, which is
/// almost everything — the resolution's own backing already spells that path,
/// and it is shared, not rebuilt. A `Name` is an owned byte string, so
/// rebuilding costs one allocation per component of the path, and a walk
/// resolves deep paths hundreds of thousands of times.
fn child_recipe(directory: &HostBacking, backing: &HostBacking, name: &Name) -> HostBacking {
    match backing.strip_prefix(directory) {
        Some([below]) if below == name => backing.clone(),
        _ => directory.child(name),
    }
}

/// A directory's own recorded host path together with the descriptor its node
/// currently holds: what a child resolution needs, and what a child's whole
/// path is built from.
type PinnedDir = (HostBacking, Arc<OwnedFd>);

/// A directory a lookup or a listing runs under: its policy context, and the
/// cache slot its node pinned.
///
/// The context is always the **current** one, re-derived per operation by
/// [`Session::parent_dir`]; the slot is the node's, holding the host location
/// it was pinned at. The two can disagree — a graft re-pointed at another host
/// path is the whole reason this pair is kept apart — and every use of the pin
/// goes through [`Self::pinned_at`], which hands it out only when it still
/// names the directory the current policy describes. A stale pin is simply not
/// used, and is never even re-pinned: the caller pins the current backing from
/// its graft instead.
///
/// Carrying a pin at all is what keeps a child lookup to a single contained
/// `openat2` from the parent, instead of re-walking the whole relative path
/// from the graft on every component.
#[derive(Debug)]
pub struct ParentDir {
    /// The policy context children resolve against, as the namespace defines it
    /// now.
    pub context: DirContext,
    /// The node's cache slot; `None` for a synthesized directory, which has no
    /// host entry to hold one.
    pinned: Option<Arc<NodePin>>,
}

impl ParentDir {
    /// The node's pin and its descriptor, if the pin names exactly the host
    /// directory `backing` does.
    ///
    /// The comparison is the whole staleness check: the pin records an inode
    /// the session captured, `backing` is where the namespace says this
    /// directory lives *now*, and a re-target makes them different directories.
    /// It runs **before** the descriptor is asked for, so a re-pointed graft
    /// never pays a re-pin — nor turns one into a spurious `ESTALE`.
    ///
    /// # Errors
    ///
    /// The re-pin's, when the pin matches but the budget has evicted it.
    fn pinned_at(
        &self,
        backing: &HostBacking,
        namespace: &Namespace,
    ) -> Result<Option<PinnedDir>, Errno> {
        let Some(pin) = &self.pinned else {
            return Ok(None);
        };
        if pin.backing() != backing {
            return Ok(None);
        }
        let fd = pin.descriptor(namespace)?;
        Ok(Some((pin.recipe(), fd)))
    }

    /// The pin to resolve `name` from, when the entry really is this
    /// directory's own host child, not a re-targeted graft.
    fn child_site(
        &self,
        name: &Name,
        backing: &HostBacking,
        namespace: &Namespace,
    ) -> Result<Option<PinnedDir>, Errno> {
        let Some(parent_backing) = self.context.backing() else {
            return Ok(None);
        };
        if backing != &parent_backing.child(name) {
            return Ok(None);
        }
        self.pinned_at(parent_backing, namespace)
    }
}

/// Streams the host child names of a pinned directory.
///
/// The pinned descriptor is `O_PATH`, which `getdents` cannot use, so the
/// directory is reopened through the `/proc/self/fd` idiom — the same exemption
/// the open path documents. `.` and `..` are dropped: they are not entries the
/// namespace has an opinion about, and the client kernel synthesizes them.
///
/// Names arrive **one at a time**, never as a vector of the whole directory:
/// that is what lets the listing cap bound the memory a guest can make the
/// server spend, instead of merely reporting on it afterwards.
///
/// A directory that stops being readable part-way ends the stream and records
/// its errno in `failure`, because an enumeration cannot fail through an
/// iterator — and a listing that quietly stopped early would be a directory
/// that appears to have lost files.
fn host_names(
    fd: BorrowedFd<'_>,
    failure: &Cell<Option<Errno>>,
) -> Result<impl Iterator<Item = Name>, Errno> {
    let mut directory = Dir::new(reopen(fd, OFlags::RDONLY | OFlags::DIRECTORY)?)?;
    Ok(std::iter::from_fn(move || {
        loop {
            match directory.next()? {
                Ok(entry) => {
                    let raw = entry.file_name().to_bytes();
                    if raw != b"."
                        && raw != b".."
                        && let Ok(name) = Name::new(raw)
                    {
                        return Some(name);
                    }
                }
                Err(error) => {
                    failure.set(Some(error));
                    return None;
                }
            }
        }
    }))
}

/// The node id every session's mount root has.
pub const ROOT: u64 = ROOT_NODE_ID;
