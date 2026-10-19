//! The per-session node table.
//!
//! A **node** is what a session calls a file it has resolved: the wire names
//! files by session-scoped `u64` node ids, and every id in this table stands
//! for one pinned host entry (or one synthesized directory) plus the policy
//! that admitted it.
//!
//! Three rules from the design shape the table:
//!
//! * **Node ids are generation-disjoint and never given to another file.**
//!   Every session's mount root is node id 1, which is what lets one server
//!   serve many roots; every other id comes from [`IdSpace`], which takes no
//!   id twice — not within a session, not across the sessions of one server,
//!   and not across server restarts. That is what makes a stale id a plain
//!   `ESTALE` after a reconnect instead of a silently different file. The
//!   one way an id comes back is to the same file: the table remembers the
//!   id of a forgotten node whose identity carries a birth time, or which
//!   has no identity because it is a synthesized directory. A lookup that
//!   proves the same identity gets that id and inode number back while the
//!   record remains in the session. Because an id never names a second file,
//!   the wire's `generation` field is reserved and carries 0.
//! * **Non-directories are keyed by `(host_dev, host_ino, effective mode)`.**
//!   One host inode reachable through rules with different share modes is one
//!   node id per mode, each with its own enforcement, while all of them share
//!   one `ino`.
//! * **Directories are keyed by namespace path.** Child resolution runs from
//!   the parent's namespace path, so one host directory grafted at two
//!   namespace paths is two nodes — their children may differ by policy.
//!   Directories cannot be hardlinked, so this costs no identity.
//!
//! A node holds the mode it was admitted under, and that mode governs what may
//! be done *through it* for as long as it lives. It deliberately holds no
//! directory policy *context*: the policy a directory's children resolve under
//! is re-derived from the current namespace per operation
//! ([`Session::parent_dir`](crate::data::session::Session::parent_dir)), so a
//! graft downgraded, removed or re-targeted reaches a mounted session at its
//! next child lookup.
//!
//! Lifecycle follows FUSE: every entry reply increments a lookup count, FORGET
//! decrements it, and the node — with its pinned descriptor — is dropped at
//! zero. Session teardown drops the whole table. Every entry in and out is
//! counted through [`crate::reclaim`], which is what turns a drained table back
//! into host memory, not allocator arena the process keeps for life.

use std::collections::{BTreeMap, HashMap};
use std::os::fd::OwnedFd;
use std::sync::Arc;

use rustix::io::Errno;

use crate::data::ids::IdSpace;
use crate::data::pin::NodePin;
use crate::host::attr::NodeIdentity;
use crate::host::{FileKind, HostIdentity};
use crate::namespace::Namespace;
use crate::reclaim;
use crate::rules::{EffectiveMode, HostBacking, NamespacePath};

/// The node id of every session's mount root.
pub const ROOT_NODE_ID: u64 = 1;

/// The generation every entry reply carries.
///
/// A node id is never given to another file within a session, so there is
/// nothing for a generation to distinguish. The field stays on the wire for a
/// future client that does give an id to a second file.
pub const GENERATION: u64 = 0;

/// What backs a node.
#[derive(Clone, Debug)]
pub enum NodeBacking {
    /// A synthesized directory: no host entry, fixed attributes, children
    /// resolved structurally from the rule table.
    Synthesized,
    /// A host entry, pinned `O_PATH` under containment.
    Host {
        /// The node's **cache slot**: the pinned descriptor while the budget
        /// keeps it, and the identity-verified recipe for pinning it again
        /// once the budget has evicted it. Shared so an operation can take it
        /// out of the table and do I/O without holding the table lock, and so
        /// every clone of the node agrees about the one slot.
        pin: Arc<NodePin>,
        /// The share mode of the rule that admitted it. Enforcement uses
        /// this: the policy of the path that admitted the entry, fixed at
        /// lookup.
        mode: EffectiveMode,
        /// What kind of host entry it is, as of the lookup that pinned it.
        kind: FileKind,
    },
}

/// One resolved file, named by a session-scoped node id.
#[derive(Clone, Debug)]
pub struct Node {
    /// The session-scoped id.
    pub id: u64,
    /// The server-global inode number the guest sees.
    pub ino: u64,
    /// The namespace path this node was reached by.
    pub path: NamespacePath,
    /// What backs it.
    pub backing: NodeBacking,
}

impl Node {
    /// The node's cache slot, or `None` for a synthesized directory, which has
    /// no host entry and therefore no descriptor at all.
    #[must_use]
    pub fn pin(&self) -> Option<&Arc<NodePin>> {
        match &self.backing {
            NodeBacking::Synthesized => None,
            NodeBacking::Host { pin, .. } => Some(pin),
        }
    }

    /// The pinned descriptor, re-pinning the host entry if the budget has
    /// evicted it; `None` for a synthesized directory.
    ///
    /// Every operation that touches the host goes through here, and the
    /// descriptor comes back **owned**: it outlives the table lock, and it
    /// outlives an eviction that happens while the operation is running — the
    /// budget bounds what the *cache* holds, never what a caller is using.
    ///
    /// # Errors
    ///
    /// `ESTALE` where the entry can no longer be re-pinned as the same file,
    /// and any other host errno of the re-pin. See
    /// [`NodePin::descriptor`](crate::data::pin::NodePin::descriptor).
    pub fn descriptor(&self, namespace: &Namespace) -> Result<Option<Arc<OwnedFd>>, Errno> {
        match self.pin() {
            None => Ok(None),
            Some(pin) => pin.descriptor(namespace).map(Some),
        }
    }

    /// What the node's pin found at pin time, or `None` for a synthesized
    /// directory, which has no host entry to have an identity.
    #[must_use]
    pub fn identity(&self) -> Option<NodeIdentity> {
        self.pin().map(|pin| pin.identity())
    }

    /// The entry's whole host path **as the host has it now**, or `None` for a
    /// synthesized directory.
    ///
    /// The node's recipe, not the location the namespace described at pin time:
    /// the two part company wherever the server has since moved the entry, or
    /// moved a parent it was reached through, and only the recipe names
    /// something the host can be asked about. It is therefore also the space
    /// [`Move`] is spelled in, so a locator built from it is one
    /// [`RecordStore::relocate`](crate::records::RecordStore::relocate) can
    /// re-point.
    ///
    /// A snapshot, because the recipe lives behind the pin's own lock.
    #[must_use]
    pub fn host_recipe(&self) -> Option<HostBacking> {
        self.pin().map(|pin| pin.recipe())
    }

    /// The effective share mode, or `None` for a synthesized directory (which
    /// nothing can be written through).
    #[must_use]
    pub fn mode(&self) -> Option<EffectiveMode> {
        match &self.backing {
            NodeBacking::Synthesized => None,
            NodeBacking::Host { mode, .. } => Some(*mode),
        }
    }

    /// What kind of entry the node names. A synthesized directory is a
    /// directory like any other, as far as a guest is concerned.
    #[must_use]
    pub fn kind(&self) -> FileKind {
        match &self.backing {
            NodeBacking::Synthesized => FileKind::Directory,
            NodeBacking::Host { kind, .. } => *kind,
        }
    }

    /// Whether the node is a directory — synthesized directories included.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.kind().is_directory()
    }

    /// Enforces that a write-class operation may go through this node.
    ///
    /// # Errors
    ///
    /// Returns `EROFS` for a read-only node and for a synthesized directory,
    /// which has no host backing to write to. This is the server-side
    /// enforcement the design makes unconditional: the presented permission
    /// bits are UX, this is the rule.
    pub fn require_writable(&self) -> Result<(), Errno> {
        match self.mode() {
            Some(mode) if mode.is_writable() => Ok(()),
            _ => Err(Errno::ROFS),
        }
    }
}

/// What makes two lookups the same node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NodeKey {
    /// A directory, keyed by the namespace path it was reached by.
    Directory(NamespacePath),
    /// Anything else, keyed by host identity and the mode that admitted it.
    Inode {
        /// The host device.
        device: u64,
        /// The host inode number.
        inode: u64,
        /// The effective share mode.
        mode: EffectiveMode,
    },
}

impl NodeKey {
    /// The key a resolved entry gets.
    #[must_use]
    pub fn of(path: &NamespacePath, identity: HostIdentity, mode: EffectiveMode) -> Self {
        if identity.kind.is_directory() {
            Self::Directory(path.clone())
        } else {
            Self::Inode {
                device: identity.device,
                inode: identity.inode,
                mode,
            }
        }
    }

    /// The key of an entry named by `name` inside the directory at `parent`.
    ///
    /// [`Self::of`] takes the entry's own path; a listing has the parent's and
    /// a name, and building the child path for every entry allocates a whole
    /// component vector per entry for a key that, for everything but a
    /// directory, does not contain a path at all. This builds one only when the
    /// key needs it.
    #[must_use]
    pub fn listed(
        parent: &NamespacePath,
        name: &crate::rules::Name,
        identity: HostIdentity,
        mode: EffectiveMode,
    ) -> Self {
        if identity.kind.is_directory() {
            Self::Directory(parent.child(name))
        } else {
            Self::Inode {
                device: identity.device,
                inode: identity.inode,
                mode,
            }
        }
    }
}

/// What a lookup found in the node table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interned {
    /// The entry had no node yet; this lookup made one.
    Created,
    /// A node for it was already there, and this lookup counted against it.
    Existing,
}

/// One host entry the server has just given a new name, for the nodes that
/// name it.
///
/// A rename moves an entry from one host path to another; a link gives an inode
/// a second name and moves nothing. Both owe the node table the same thing —
/// the nodes naming that inode must re-pin by a name that is still there — and
/// a rename owes one thing more, which is why the old path is recorded: a
/// directory's descendants recorded their paths through it.
#[derive(Clone, Debug)]
pub struct Move {
    /// The entry as the host had it **before** the move: what identifies the
    /// nodes naming it, whatever path each of them recorded. Taken before the
    /// syscall, because afterwards the old name is gone.
    entry: HostIdentity,
    /// Where it was, so that the recorded paths of a directory's descendants
    /// can have that prefix swapped for the new one. `None` for a link, which
    /// adds a name instead of moving one and can carry no subtree: the host
    /// refuses to hard-link a directory.
    from: Option<HostBacking>,
    /// Where it is now — the whole host path, from its graft root down.
    to: HostBacking,
}

impl Move {
    /// An entry renamed from one host path to another.
    #[must_use]
    pub fn renamed(entry: HostIdentity, from: HostBacking, to: HostBacking) -> Self {
        Self {
            entry,
            from: Some(from),
            to,
        }
    }

    /// An inode given a second name.
    #[must_use]
    pub fn linked(entry: HostIdentity, to: HostBacking) -> Self {
        Self {
            entry,
            from: None,
            to,
        }
    }

    /// The entry that moved, as the host had it before the move.
    ///
    /// Read by the namespace's record store, which owes the very same
    /// re-pointing the node table does: a record's locator must follow the
    /// entry the server itself moved, or a restart would revalidate it against
    /// a name that is gone.
    #[must_use]
    pub fn entry(&self) -> HostIdentity {
        self.entry
    }

    /// Where it was, or `None` for a link, which moves nothing.
    #[must_use]
    pub fn from(&self) -> Option<&HostBacking> {
        self.from.as_ref()
    }

    /// Where it is now.
    #[must_use]
    pub fn to(&self) -> &HostBacking {
        &self.to
    }

    /// Whether this move can have taken other nodes' entries with it, which is
    /// what decides between two hash lookups and a scan of the table.
    fn carries_a_subtree(&self) -> bool {
        self.entry.kind.is_directory() && self.from.is_some()
    }

    /// The path a pin should record after this move, or `None` where the move
    /// does not concern it.
    ///
    /// Two ways to be concerned, and the identity comes first: a node *is* the
    /// entry that moved, whatever name it recorded reaching it — a hard link's
    /// other name, an alias under a differently spelled graft — or it recorded
    /// a path underneath the one that moved, and moved with it.
    fn rebound(&self, pin: &NodePin) -> Option<HostBacking> {
        if pin.identity().names(self.entry) {
            return Some(self.to.clone());
        }
        let recipe = pin.recipe();
        let below = recipe.strip_prefix(self.from.as_ref()?)?;
        Some(self.to.extend(below))
    }
}

/// One session's nodes.
#[derive(Debug)]
pub struct NodeTable {
    nodes: HashMap<u64, Entry>,
    index: HashMap<NodeKey, u64>,
    /// The generation-disjoint id space this session names nodes from.
    ids: IdSpace,
    /// The configured cap, or `None` where the operator configured none and the
    /// table grows until the process runs out of descriptors.
    limit: Option<usize>,
    /// The ids of forgotten nodes whose identity has a birth time or is
    /// absent, by the key each node had. Records hold no descriptor and count
    /// neither toward the cap nor in the reclaim ledger.
    remembered: HashMap<NodeKey, Remembered>,
    /// The order the records were remembered in, oldest first, kept only
    /// under a configured cap. Each remembered record has exactly one entry,
    /// removed with the record on recall, rejection or eviction.
    order: BTreeMap<u64, NodeKey>,
    /// The age the next record gets.
    next_age: u64,
}

/// The id of a forgotten node, kept so the same file gets it back.
#[derive(Debug)]
struct Remembered {
    id: u64,
    /// When it was remembered, as a count of records made before it.
    age: u64,
    identity: Option<NodeIdentity>,
}

/// A node plus the lookup count that keeps it alive.
#[derive(Debug)]
struct Entry {
    node: Node,
    key: NodeKey,
    lookups: u64,
}

impl NodeTable {
    /// An empty table naming nodes from `ids`. `limit` bounds its nodes and,
    /// by the same number, the ids it remembers of forgotten nodes; `None`
    /// bounds neither.
    #[must_use]
    pub fn new(limit: Option<usize>, ids: IdSpace) -> Self {
        Self {
            nodes: HashMap::new(),
            index: HashMap::new(),
            ids,
            limit,
            remembered: HashMap::new(),
            order: BTreeMap::new(),
            next_age: 0,
        }
    }

    /// Installs the mount root, which is always node id 1.
    ///
    /// The root is the single id the allocator never produces: every session
    /// names its own root 1, which is the one number a stale kernel-held id may
    /// legitimately still mean after a reconnect.
    ///
    /// # Panics
    ///
    /// Panics if a root was already installed; a session has exactly one.
    pub fn install_root(
        &mut self,
        key: NodeKey,
        ino: u64,
        path: NamespacePath,
        backing: NodeBacking,
    ) -> u64 {
        assert!(self.nodes.is_empty(), "a session has exactly one root");
        let id = ROOT_NODE_ID;
        self.insert(
            id,
            key,
            Node {
                id,
                ino,
                path,
                backing,
            },
        );
        id
    }

    /// Returns the node for a resolved entry, allocating one if this is the
    /// first lookup of it, and counts the lookup either way.
    ///
    /// A forgotten file gets the id it had: where the table remembers `key`
    /// and the identity it remembers agrees with `found`, the node is built
    /// with the remembered id. That still reports [`Interned::Created`],
    /// because the node is new and the caller's fresh pin is the one it holds.
    /// Where they disagree the record is dropped and a fresh id taken, so an id
    /// never names two files.
    ///
    /// `build` is only called when the entry is new, so a repeated lookup costs
    /// no descriptor. The flag says which happened, because the caller's reply
    /// must describe the node it got back, not what it just resolved —
    /// they differ when a directory's name has been replaced on the host since
    /// the session pinned it.
    ///
    /// `found` is the identity of the entry the caller has just resolved, or
    /// `None` where it has none to offer — a synthesized directory. It is what
    /// decides whether the node already under this key is still the same file;
    /// see [`Self::revisit`].
    ///
    /// # Errors
    ///
    /// Returns `ENFILE` when a configured table is full — the lookup that would
    /// exceed the cap fails, and nothing is inserted; a remembered id stays
    /// remembered for the next attempt. An unconfigured table never returns it.
    pub fn intern(
        &mut self,
        key: NodeKey,
        found: Option<NodeIdentity>,
        build: impl FnOnce(u64) -> Node,
    ) -> Result<(Node, Interned), Errno> {
        if let Some(node) = self.revisit(&key, found) {
            return Ok((node, Interned::Existing));
        }
        // A record of another file is dead whatever the cap answers.
        if self
            .remembered
            .get(&key)
            .is_some_and(|record| !both_prove_the_same(record.identity, found))
        {
            self.remove_remembered(&key);
        }
        if self.limit.is_some_and(|limit| self.nodes.len() >= limit) {
            return Err(Errno::NFILE);
        }
        let id = match self.remove_remembered(&key) {
            Some(record) => record.id,
            None => self.ids.take(),
        };
        let node = build(id);
        self.insert(id, key, node.clone());
        Ok((node, Interned::Created))
    }

    /// Counts a lookup against the node an entry already has, if it has one and
    /// it is still the same file.
    ///
    /// This is [`Self::intern`] without the build: a caller that can name the
    /// key of an entry without opening it — a listing knows every key from the
    /// stat it already took — needs no descriptor for an entry the session has
    /// seen before, and every entry of the second listing of a directory is
    /// one of those. `None` means the entry is new and must be pinned like any
    /// first lookup.
    ///
    /// **Retire and remint.** A key is not a file: a directory is keyed by its
    /// namespace path, which an external replacement leaves pointing at the old
    /// directory, and on a filesystem that reuses inode numbers a recreated
    /// file lands on the very key its predecessor holds. Where `found` says the
    /// entry there is *not* the one the node names, the node is **retired** —
    /// taken out of the table, so its id answers `ESTALE` from then on (which
    /// is what a node whose file is gone owes the guest) and its key is free —
    /// and the caller mints a fresh node for the entry it actually resolved.
    /// Without this the dead node holds the key and the path can never heal.
    ///
    /// The lookups the guest still holds against a retired id die with it: a
    /// `forget` naming an id the table no longer has is already a no-op, so the
    /// accounting stays balanced however many the client had outstanding.
    pub fn revisit(&mut self, key: &NodeKey, found: Option<NodeIdentity>) -> Option<Node> {
        let id = *self.index.get(key)?;
        let entry = self.nodes.get_mut(&id).expect("the index names a node");
        if !still_the_same(entry.node.identity(), found) {
            self.retire(id);
            return None;
        }
        entry.lookups += 1;
        Some(entry.node.clone())
    }

    /// Takes a node out of the table, whatever its lookup count.
    ///
    /// The id is not reused, so nothing the client still holds against it can
    /// ever name another file.
    fn retire(&mut self, id: u64) {
        if let Some(entry) = self.nodes.remove(&id) {
            self.index.remove(&entry.key);
            reclaim::released(1);
            self.shrink_if_drained();
        }
    }

    /// The node an id names.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<Node> {
        self.nodes.get(&id).map(|entry| entry.node.clone())
    }

    /// Drops `count` lookups from a node, forgetting it at zero.
    ///
    /// Forgetting closes the pinned descriptor and takes the node out. The
    /// table remembers its id under its key if its identity has a birth time
    /// or is absent, so a lookup proving the same file gets it back. The id
    /// is never given to another file. The mount root is installed by its
    /// own path and is not remembered.
    pub fn forget(&mut self, id: u64, count: u64) {
        let Some(entry) = self.nodes.get_mut(&id) else {
            return;
        };
        entry.lookups = entry.lookups.saturating_sub(count);
        if entry.lookups == 0 {
            let entry = self.nodes.remove(&id).expect("just looked it up");
            self.index.remove(&entry.key);
            reclaim::released(1);
            self.shrink_if_drained();
            if id != ROOT_NODE_ID {
                self.remember(entry);
            }
        }
    }

    /// Records the id of a node that has just left the table, if its identity
    /// has a birth time or is absent.
    ///
    /// Under a configured cap the records are kept to that same number, the
    /// oldest going first. A guest exceeds it only by forgetting more distinct
    /// files than the cap lets it hold at once, so a cap sized for a working
    /// set never pushes out a record of that working set.
    fn remember(&mut self, entry: Entry) {
        let identity = entry.node.identity();
        if identity.is_some_and(|identity| identity.birth.is_none()) {
            return;
        }
        let age = self.next_age;
        self.next_age += 1;
        let id = entry.node.id;
        if self.limit.is_some() {
            self.order.insert(age, entry.key.clone());
        }
        self.remembered
            .insert(entry.key, Remembered { id, age, identity });
        if let Some(limit) = self.limit {
            while self.remembered.len() > limit {
                let (_, key) = self.order.pop_first().expect("an entry per record");
                self.remembered.remove(&key);
            }
        }
    }

    /// A record and its ordering entry must be removed together.
    fn remove_remembered(&mut self, key: &NodeKey) -> Option<Remembered> {
        let record = self.remembered.remove(key)?;
        self.order.remove(&record.age);
        Some(record)
    }

    /// Gives back the table's own storage once most of it is empty.
    ///
    /// Removing an entry frees the entry; it does not free the *table*, and a
    /// hash table sized for an AOSP-scale walk is tens of megabytes of spine
    /// that a drained session would otherwise hold until it disconnects
    /// (measured 2026-08-15: 13.8 MiB behind 60 000 entries, and it is one
    /// allocation large enough that giving it back needs no allocator trim at
    /// all). Shrinking at a quarter full keeps it amortized — a shrink costs
    /// one rehash of what is left, and the table must then double twice before
    /// another can happen — and the floor keeps ordinary sessions, whose tables
    /// never grew, out of it entirely.
    fn shrink_if_drained(&mut self) {
        const FLOOR: usize = 1024;
        if self.nodes.capacity() > FLOOR && self.nodes.len() * 4 <= self.nodes.capacity() {
            self.nodes.shrink_to_fit();
            self.index.shrink_to_fit();
        }
    }

    /// Drops every node, closing every pinned descriptor.
    ///
    /// Session teardown. Ids are not reused afterwards: the counter only moves
    /// forward.
    pub fn clear(&mut self) {
        reclaim::released(self.nodes.len());
        self.nodes.clear();
        self.index.clear();
        self.remembered.clear();
        self.order.clear();
    }

    /// How many nodes the session holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the table is empty. A live session's never is: it holds its
    /// root.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// How many forgotten ids the table remembers, which no lookup or forget
    /// shows.
    #[cfg(test)]
    fn remembered(&self) -> usize {
        self.remembered.len()
    }

    /// The lookup count of a node, for tests and diagnostics.
    #[must_use]
    pub fn lookups(&self, id: u64) -> Option<u64> {
        self.nodes.get(&id).map(|entry| entry.lookups)
    }

    /// Re-points the recorded host paths of **every** node the moves affect:
    /// the entries themselves, and the descendants of any directory among them.
    ///
    /// This is how the server keeps from stale-ing what it moved itself: an
    /// entry renamed or linked *through the mount* is still the same file, so
    /// the nodes that name it — and, for a directory, the nodes beneath it —
    /// must be able to find it at its new place. A node records its whole host
    /// path, so a directory move is a **subtree rewrite**: the old path is a
    /// prefix of every descendant's, and swapping that prefix for the new one
    /// re-points them all.
    ///
    /// *Every* node, because one host entry can be several: a file reachable
    /// under two share modes is a node per mode, and one host directory grafted
    /// at two namespace paths is a node per path. The two are found differently
    /// on purpose. A move that carries no subtree — a file rename, a link — is
    /// **keyed** by host identity, so its nodes are two hash lookups. A
    /// directory move scans, because a namespace path is not a key any host
    /// identity can name and a subtree is not a key at all: the cost the design
    /// sanctions, paid by directory renames only and never by the file renames
    /// a build system runs on.
    ///
    /// **All the moves in one pass**, and at most one of them per node: a
    /// `RENAME_EXCHANGE` swaps two subtrees, and rewriting one prefix and then
    /// the other in turn would carry the first subtree's nodes straight back
    /// over with the second.
    ///
    /// Nothing here touches the host, so it is safe under the table lock.
    pub fn rebind_moved(&mut self, moves: &[Move]) {
        if !moves.iter().any(Move::carries_a_subtree) {
            for moved in moves {
                for mode in [EffectiveMode::Ro, EffectiveMode::Rw] {
                    self.rebind_key(
                        &NodeKey::Inode {
                            device: moved.entry.device,
                            inode: moved.entry.inode,
                            mode,
                        },
                        moved.to.clone(),
                    );
                }
            }
            return;
        }
        for entry in self.nodes.values() {
            let Some(pin) = entry.node.pin() else {
                continue;
            };
            if let Some(recipe) = moves.iter().find_map(|moved| moved.rebound(pin)) {
                pin.rebind(recipe);
            }
        }
    }

    /// Re-points the recorded path of the node one key names, if it names one.
    fn rebind_key(&mut self, key: &NodeKey, recipe: HostBacking) {
        let Some(id) = self.index.get(key) else {
            return;
        };
        let Some(entry) = self.nodes.get(id) else {
            return;
        };
        if let Some(pin) = entry.node.pin() {
            pin.rebind(recipe);
        }
    }

    /// Inserts a node with one lookup outstanding.
    fn insert(&mut self, id: u64, key: NodeKey, node: Node) {
        self.index.insert(key.clone(), id);
        self.nodes.insert(
            id,
            Entry {
                node,
                key,
                lookups: 1,
            },
        );
        reclaim::admitted(1);
    }
}

/// A dropped table is a drained table: a session that disconnects frees every
/// entry it held, which is the largest single release the server ever makes and
/// exactly the one an operator watches for.
impl Drop for NodeTable {
    fn drop(&mut self) {
        reclaim::released(self.nodes.len());
    }
}

/// Whether the node a key already names is still the entry a fresh resolution
/// found there.
///
/// `held` is what the node recorded when it pinned its entry; `found` is what
/// the caller has just resolved. Either side may have nothing to say — a
/// synthesized directory has no host entry at all, and a caller that resolved
/// an entry without stat'ing it has no identity to offer — and silence is never
/// evidence of a replacement, so only two recorded identities can disagree.
fn still_the_same(held: Option<NodeIdentity>, found: Option<NodeIdentity>) -> bool {
    match (held, found) {
        (Some(held), Some(found)) => held.matches(&found),
        _ => true,
    }
}

/// Whether both identities prove that a forgotten file is the one found.
///
/// Stricter than [`still_the_same`]: one side with an identity and one
/// without is no match, and neither is a pair in which a birth time is
/// missing. Without one the check rests on device, inode and kind, which a
/// recycled inode number satisfies, and a record waits far longer for its
/// file than a live node does. Two absent identities name a synthesized
/// directory under the same namespace path.
fn both_prove_the_same(held: Option<NodeIdentity>, found: Option<NodeIdentity>) -> bool {
    match (held, found) {
        (None, None) => true,
        (Some(held), Some(found)) => {
            held.birth.is_some() && found.birth.is_some() && held.matches(&found)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::pin::{DescriptorBudget, Pinned};
    use crate::host::attr::HostAttr;
    use crate::rules::{HostTarget, Name};
    use std::os::fd::AsFd as _;

    fn path(raw: &str) -> NamespacePath {
        NamespacePath::parse(raw).expect("valid namespace path")
    }

    fn backing(name: &str) -> HostBacking {
        HostBacking::graft_root(HostTarget::new("/srv")).child(&Name::new(name).expect("valid"))
    }

    /// A node table holding one synthesized root, as a session starts.
    fn table() -> NodeTable {
        let mut table = NodeTable::new(Some(4), crate::data::ids::Generations::shared().space());
        table.install_root(
            NodeKey::Directory(path("/")),
            1,
            path("/"),
            NodeBacking::Synthesized,
        );
        table
    }

    /// A host-backed node over a real descriptor, filed in its own ledger:
    /// these tests are about the table, so the budget is large enough never to
    /// evict anything.
    fn file(id: u64, name: &str, ino: u64, mode: EffectiveMode) -> Node {
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            ".",
            rustix::fs::OFlags::PATH,
            rustix::fs::Mode::empty(),
        )
        .expect("the working directory pins");
        let identity = HostAttr::of(fd.as_fd()).expect("stattable").node_identity();
        let pin = DescriptorBudget::new(4096).pin(Pinned {
            fd,
            path: path(&format!("/{name}")),
            backing: backing(name),
            identity,
            recipe: backing(name),
        });
        Node {
            id,
            ino,
            path: path(&format!("/{name}")),
            backing: NodeBacking::Host {
                pin,
                mode,
                kind: FileKind::Regular,
            },
        }
    }

    /// A node over one real entry, so that its recorded identity is that
    /// entry's own — which is what distinguishing two files takes.
    fn node_of(id: u64, entry: &std::path::Path, mode: EffectiveMode) -> Node {
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            entry,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .expect("the entry pins");
        let identity = HostAttr::of(fd.as_fd()).expect("stattable").node_identity();
        let pin = DescriptorBudget::new(4096).pin(Pinned {
            fd,
            path: path("/entry"),
            backing: backing("entry"),
            identity,
            recipe: backing("entry"),
        });
        Node {
            id,
            ino: 7,
            path: path("/entry"),
            backing: NodeBacking::Host {
                pin,
                mode,
                kind: identity.kind,
            },
        }
    }

    /// What a fresh resolution of one real entry would offer `intern`.
    fn identity_of(entry: &std::path::Path) -> Option<NodeIdentity> {
        node_of(0, entry, EffectiveMode::Rw).identity()
    }

    /// A synthesized directory, which holds no identity.
    fn synthesized(id: u64, name: &str) -> Node {
        Node {
            id,
            ino: 3,
            path: path(&format!("/{name}")),
            backing: NodeBacking::Synthesized,
        }
    }

    /// A node over one real entry that recorded `identity` for it.
    fn node_as(id: u64, entry: &std::path::Path, identity: NodeIdentity) -> Node {
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            entry,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .expect("the entry pins");
        let pin = DescriptorBudget::new(4096).pin(Pinned {
            fd,
            path: path("/entry"),
            backing: backing("entry"),
            identity,
            recipe: backing("entry"),
        });
        Node {
            id,
            ino: 7,
            path: path("/entry"),
            backing: NodeBacking::Host {
                pin,
                mode: EffectiveMode::Rw,
                kind: identity.kind,
            },
        }
    }

    /// The identity of one real entry with a birth time, the entry's own
    /// where the scratch filesystem reports one. The table compares birth
    /// times and never reads them from the host, so a made-up one keeps these
    /// tests the same on every filesystem.
    fn born(entry: &std::path::Path) -> NodeIdentity {
        let mut identity = identity_of(entry).expect("a host entry has an identity");
        identity.birth = identity.birth.or(Some((1, 0)));
        identity
    }

    /// The key a file of that identity gets.
    fn key_of(identity: NodeIdentity) -> NodeKey {
        NodeKey::Inode {
            device: identity.device,
            inode: identity.inode,
            mode: EffectiveMode::Rw,
        }
    }

    /// A table with the root installed and the given cap.
    fn table_of(limit: Option<usize>) -> NodeTable {
        let mut table = NodeTable::new(limit, crate::data::ids::Generations::shared().space());
        table.install_root(
            NodeKey::Directory(path("/")),
            1,
            path("/"),
            NodeBacking::Synthesized,
        );
        table
    }

    #[test]
    fn the_root_is_node_id_one_and_synthesized_nodes_have_no_descriptor() {
        let table = table();
        let root = table.get(ROOT_NODE_ID).expect("the root is installed");
        assert_eq!(root.id, ROOT_NODE_ID);
        assert!(root.is_directory());
        assert!(root.pin().is_none());
        assert_eq!(root.mode(), None);
        assert_eq!(root.require_writable(), Err(Errno::ROFS));
        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());
    }

    #[test]
    fn a_repeated_lookup_returns_the_same_id_and_counts_again() {
        let mut table = table();
        let key = NodeKey::Directory(path("/a"));
        let (first, interned) = table
            .intern(key.clone(), None, |id| synthesized(id, "a"))
            .expect("room");
        assert_eq!(interned, Interned::Created);
        let (second, interned) = table
            .intern(key.clone(), None, |_| {
                unreachable!("the node already exists")
            })
            .expect("room");
        assert_eq!(interned, Interned::Existing);
        assert_eq!(first.id, second.id);
        assert_eq!(table.lookups(first.id), Some(2));
        assert_eq!(table.len(), 2);

        // One forget leaves it; the second drops it.
        table.forget(first.id, 1);
        assert!(table.get(first.id).is_some());
        table.forget(first.id, 1);
        assert!(table.get(first.id).is_none());
        assert_eq!(table.len(), 1);

        // Neither side offers an identity, so the file gets its id back.
        let (third, _) = table
            .intern(key, None, |id| synthesized(id, "a"))
            .expect("room");
        assert_eq!(third.id, first.id);
    }

    #[test]
    fn one_inode_under_two_modes_is_two_nodes_sharing_an_ino() {
        let mut table = table();
        let (rw, _) = table
            .intern(
                NodeKey::Inode {
                    device: 1,
                    inode: 2,
                    mode: EffectiveMode::Rw,
                },
                None,
                |id| file(id, "a", 10, EffectiveMode::Rw),
            )
            .expect("room");
        let (ro, _) = table
            .intern(
                NodeKey::Inode {
                    device: 1,
                    inode: 2,
                    mode: EffectiveMode::Ro,
                },
                None,
                |id| file(id, "b", 10, EffectiveMode::Ro),
            )
            .expect("room");
        assert_ne!(rw.id, ro.id);
        assert_eq!(rw.ino, ro.ino);
        assert_eq!(rw.require_writable(), Ok(()));
        assert_eq!(ro.require_writable(), Err(Errno::ROFS));
    }

    #[test]
    fn a_full_table_refuses_the_lookup_that_would_exceed_it() {
        let mut table = table();
        let mut admitted = Vec::new();
        for index in 0..3u64 {
            let (node, _) = table
                .intern(
                    NodeKey::Inode {
                        device: 1,
                        inode: index,
                        mode: EffectiveMode::Rw,
                    },
                    None,
                    |id| file(id, "a", index, EffectiveMode::Rw),
                )
                .expect("room");
            admitted.push(node.id);
        }
        assert_eq!(table.len(), 4);
        let full = table
            .intern(
                NodeKey::Inode {
                    device: 1,
                    inode: 99,
                    mode: EffectiveMode::Rw,
                },
                None,
                |id| file(id, "a", 99, EffectiveMode::Rw),
            )
            .expect_err("the table is full");
        assert_eq!(full, Errno::NFILE);
        assert_eq!(table.len(), 4, "a refused lookup inserts nothing");

        // Forgetting one makes room again.
        table.forget(admitted[0], 1);
        assert!(
            table
                .intern(
                    NodeKey::Inode {
                        device: 1,
                        inode: 99,
                        mode: EffectiveMode::Rw
                    },
                    None,
                    |id| file(id, "a", 99, EffectiveMode::Rw)
                )
                .is_ok()
        );
    }

    /// The default posture: a table nobody configured a cap for refuses
    /// nothing, however many entries a guest looks up.
    #[test]
    fn an_unconfigured_table_never_refuses_a_lookup() {
        let mut table = NodeTable::new(None, crate::data::ids::Generations::shared().space());
        table.install_root(
            NodeKey::Directory(path("/")),
            1,
            path("/"),
            NodeBacking::Synthesized,
        );
        for index in 0..1000u64 {
            table
                .intern(
                    NodeKey::Inode {
                        device: 1,
                        inode: index,
                        mode: EffectiveMode::Rw,
                    },
                    None,
                    |id| file(id, "a", index, EffectiveMode::Rw),
                )
                .expect("an unbounded table admits every entry");
        }
        assert_eq!(table.len(), 1001);
    }

    #[test]
    fn teardown_drops_every_node_without_reusing_an_id() {
        let mut table = table();
        let (node, _) = table
            .intern(
                NodeKey::Inode {
                    device: 1,
                    inode: 2,
                    mode: EffectiveMode::Rw,
                },
                None,
                |id| file(id, "a", 10, EffectiveMode::Rw),
            )
            .expect("room");
        table.clear();
        assert!(table.is_empty());
        assert!(table.get(node.id).is_none());
        let (fresh, interned) = table
            .intern(
                NodeKey::Inode {
                    device: 1,
                    inode: 2,
                    mode: EffectiveMode::Rw,
                },
                None,
                |id| file(id, "a", 10, EffectiveMode::Rw),
            )
            .expect("room");
        assert_eq!(interned, Interned::Created, "the index went with them");
        assert!(fresh.id > node.id, "ids are not reused");
    }

    /// A key is not a file. Where a fresh resolution finds a *different* entry
    /// under the key a node holds — a directory replaced at its namespace path,
    /// or a recreated file on a filesystem that hands the same inode number
    /// back — the node is retired and a fresh one is minted, so the path heals
    /// while the old id stays honest.
    #[test]
    fn a_replaced_entry_retires_the_node_holding_its_key() {
        let scratch = crate::testing::Scratch::new("node-retire");
        let first = scratch.file("first", b"1");
        let second = scratch.file("second", b"2");
        let mut table = table();
        let key = NodeKey::Directory(path("/entry"));

        let (old, interned) = table
            .intern(key.clone(), identity_of(&first), |id| {
                node_of(id, &first, EffectiveMode::Rw)
            })
            .expect("room");
        assert_eq!(interned, Interned::Created);

        // The same entry is the same node, and counts another lookup.
        let (again, interned) = table
            .intern(key.clone(), identity_of(&first), |_| {
                unreachable!("the node already exists")
            })
            .expect("room");
        assert_eq!((again.id, interned), (old.id, Interned::Existing));
        assert_eq!(table.lookups(old.id), Some(2));

        // A different entry under the same key retires the node holding it,
        // however many lookups the client still had outstanding.
        let (fresh, interned) = table
            .intern(key, identity_of(&second), |id| {
                node_of(id, &second, EffectiveMode::Rw)
            })
            .expect("room");
        assert_eq!(interned, Interned::Created);
        assert_ne!(fresh.id, old.id, "ids are never reused");
        assert!(
            table.get(old.id).is_none(),
            "a retired id names nothing, which is what `ESTALE` means"
        );

        // And the forgets the client still owes for it are harmless.
        table.forget(old.id, 2);
        assert!(table.get(fresh.id).is_some(), "the fresh node is untouched");
    }

    #[test]
    fn a_forgotten_file_gets_its_id_back_and_is_reported_as_created() {
        let scratch = crate::testing::Scratch::new("node-recall");
        let entry = scratch.file("entry", b"1");
        let identity = born(&entry);
        let mut table = table();

        let (first, _) = table
            .intern(key_of(identity), Some(identity), |id| {
                node_as(id, &entry, identity)
            })
            .expect("room");
        table.forget(first.id, 1);
        assert!(table.get(first.id).is_none(), "a remembered id is stale");
        assert_eq!(table.len(), 1, "a remembered entry is no node");
        assert_eq!(table.remembered(), 1);

        // A forget naming the remembered id changes nothing.
        table.forget(first.id, 1);
        assert_eq!(table.remembered(), 1);

        let (again, interned) = table
            .intern(key_of(identity), Some(identity), |id| {
                node_as(id, &entry, identity)
            })
            .expect("room");
        assert_eq!(again.id, first.id);
        assert_eq!(
            interned,
            Interned::Created,
            "the caller keeps its fresh pin"
        );
        assert_eq!(table.remembered(), 0);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn a_directory_keyed_by_path_gets_its_id_back() {
        let scratch = crate::testing::Scratch::new("node-recall-dir");
        let entry = scratch.file("entry", b"1");
        let identity = born(&entry);
        let key = NodeKey::Directory(path("/entry"));
        let mut table = table();

        let (first, _) = table
            .intern(key.clone(), Some(identity), |id| {
                node_as(id, &entry, identity)
            })
            .expect("room");
        table.forget(first.id, 1);
        let (again, _) = table
            .intern(key, Some(identity), |id| node_as(id, &entry, identity))
            .expect("room");
        assert_eq!(again.id, first.id);
    }

    #[test]
    fn a_synthesized_directory_admitted_again_gets_its_id_back() {
        let mut table = table();
        let key = NodeKey::Directory(path("/a"));
        let (first, _) = table
            .intern(key.clone(), None, |id| synthesized(id, "a"))
            .expect("room");
        table.forget(first.id, 1);
        let (again, _) = table
            .intern(key, None, |id| synthesized(id, "a"))
            .expect("room");
        assert_eq!(again.id, first.id);
    }

    #[test]
    fn the_mount_root_is_never_remembered() {
        let mut table = table();
        table.forget(ROOT_NODE_ID, 1);
        assert!(table.get(ROOT_NODE_ID).is_none());
        assert_eq!(table.remembered(), 0);
    }

    #[test]
    fn a_file_replaced_while_forgotten_gets_a_fresh_id() {
        let scratch = crate::testing::Scratch::new("node-recall-replaced");
        let first = scratch.file("first", b"1");
        let second = scratch.file("second", b"2");
        let held = born(&first);
        // The replacement under the very same key: same device and inode
        // number, as a recycled inode number has it, and another birth time.
        let mut found = held;
        found.birth = held.birth.map(|(seconds, nanos)| (seconds + 1, nanos));
        let mut table = table();

        let (old, _) = table
            .intern(key_of(held), Some(held), |id| node_as(id, &first, held))
            .expect("room");
        table.forget(old.id, 1);
        let (fresh, _) = table
            .intern(key_of(held), Some(found), |id| node_as(id, &second, found))
            .expect("room");
        assert_ne!(fresh.id, old.id);
        assert_eq!(table.remembered(), 0, "the dead entry was dropped");

        // The old id is not given out again, not even to the file it named.
        table.forget(fresh.id, 1);
        let (third, _) = table
            .intern(key_of(held), Some(held), |id| node_as(id, &first, held))
            .expect("room");
        assert_ne!(third.id, old.id);
        assert_ne!(third.id, fresh.id);
    }

    #[test]
    fn an_identity_on_one_side_only_gets_a_fresh_id() {
        let scratch = crate::testing::Scratch::new("node-recall-one-sided");
        let entry = std::path::PathBuf::from(scratch.directory("entry"));
        let identity = born(&entry);
        let key = NodeKey::Directory(path("/entry"));
        let mut table = table();

        let (first, _) = table
            .intern(key.clone(), Some(identity), |id| {
                node_as(id, &entry, identity)
            })
            .expect("room");
        table.forget(first.id, 1);
        let (second, _) = table
            .intern(key.clone(), None, |id| synthesized(id, "entry"))
            .expect("room");
        assert_ne!(second.id, first.id);

        // And the other way around: remembered without, looked up with.
        table.forget(second.id, 1);
        let (third, _) = table
            .intern(key, Some(identity), |id| node_as(id, &entry, identity))
            .expect("room");
        assert_ne!(third.id, second.id);
        assert_ne!(third.id, first.id);
    }

    #[test]
    fn an_identity_without_a_birth_time_gets_a_fresh_id() {
        let scratch = crate::testing::Scratch::new("node-recall-no-birth");
        let entry = scratch.file("entry", b"1");
        let born = born(&entry);
        let mut unborn = born;
        unborn.birth = None;
        let mut table = table();

        let (first, _) = table
            .intern(key_of(unborn), Some(unborn), |id| {
                node_as(id, &entry, unborn)
            })
            .expect("room");
        table.forget(first.id, 1);
        assert_eq!(table.remembered(), 0);
        let (second, _) = table
            .intern(key_of(unborn), Some(unborn), |id| {
                node_as(id, &entry, unborn)
            })
            .expect("room");
        assert_ne!(second.id, first.id);

        table.forget(second.id, 1);
        assert_eq!(table.remembered(), 0);
        let (third, _) = table
            .intern(key_of(born), Some(born), |id| node_as(id, &entry, born))
            .expect("room");
        assert_ne!(third.id, second.id);
        assert_ne!(third.id, first.id);

        // A birth time on the remembered side alone cannot prove a match.
        table.forget(third.id, 1);
        assert_eq!(table.remembered(), 1);
        let (fourth, _) = table
            .intern(key_of(unborn), Some(unborn), |id| {
                node_as(id, &entry, unborn)
            })
            .expect("room");
        assert_ne!(fourth.id, third.id);
        assert_eq!(table.remembered(), 0);
    }

    #[test]
    fn a_retired_id_is_never_reused() {
        let scratch = crate::testing::Scratch::new("node-recall-retired");
        let first = scratch.file("first", b"1");
        let second = scratch.file("second", b"2");
        let (held, other) = (born(&first), born(&second));
        let key = NodeKey::Directory(path("/entry"));
        let mut table = table();

        let (old, _) = table
            .intern(key.clone(), Some(held), |id| node_as(id, &first, held))
            .expect("room");
        let (fresh, _) = table
            .intern(key.clone(), Some(other), |id| node_as(id, &second, other))
            .expect("room");
        assert_ne!(fresh.id, old.id);
        assert_eq!(table.remembered(), 0, "a retired node is not remembered");

        // The first file back under the key retires the second node and gets
        // an id of its own, never the retired one.
        let (third, _) = table
            .intern(key, Some(held), |id| node_as(id, &first, held))
            .expect("room");
        assert_ne!(third.id, old.id);
        assert_ne!(third.id, fresh.id);
    }

    #[test]
    fn a_recall_at_a_full_table_is_refused_and_succeeds_once_room_exists() {
        let mut table = table();
        let key = NodeKey::Directory(path("/a"));
        let (first, _) = table
            .intern(key.clone(), None, |id| synthesized(id, "a"))
            .expect("room");
        table.forget(first.id, 1);

        let mut filling = Vec::new();
        for name in ["b", "c", "d"] {
            let (node, _) = table
                .intern(NodeKey::Directory(path(&format!("/{name}"))), None, |id| {
                    synthesized(id, name)
                })
                .expect("room");
            filling.push(node.id);
        }
        assert_eq!(table.len(), 4);
        let full = table
            .intern(key.clone(), None, |_| {
                unreachable!("a refused recall builds nothing")
            })
            .expect_err("the table is full");
        assert_eq!(full, Errno::NFILE);
        assert_eq!(
            table.remembered(),
            1,
            "the entry waits for the next attempt"
        );

        table.forget(filling[0], 1);
        let (again, _) = table
            .intern(key, None, |id| synthesized(id, "a"))
            .expect("room");
        assert_eq!(again.id, first.id);
    }

    #[test]
    fn every_forgotten_node_is_remembered_until_the_table_is_cleared() {
        let mut table = table_of(None);
        let mut ids = Vec::new();
        for index in 0..100u64 {
            let (node, _) = table
                .intern(NodeKey::Directory(path(&format!("/{index}"))), None, |id| {
                    synthesized(id, "a")
                })
                .expect("room");
            ids.push(node.id);
        }
        for id in ids {
            table.forget(id, 1);
            assert_exact_order(&table);
        }
        assert_eq!(table.remembered(), 100);
        assert_eq!(table.len(), 1, "remembered entries are not nodes");
        table.clear();
        assert_eq!(table.remembered(), 0);
        assert_exact_order(&table);
    }

    fn assert_exact_order(table: &NodeTable) {
        for key in table.remembered.keys() {
            assert!(!table.index.contains_key(key));
        }
        if table.limit.is_none() {
            assert!(table.order.is_empty());
            return;
        }
        assert_eq!(table.order.len(), table.remembered.len());
        for (age, key) in &table.order {
            assert_eq!(table.remembered.get(key).expect("current record").age, *age);
        }
        for (key, record) in &table.remembered {
            assert_eq!(table.order.get(&record.age), Some(key));
        }
    }

    #[test]
    fn the_order_contains_exactly_the_current_records() {
        let mut table = table_of(Some(3));
        let key = |name: &str| NodeKey::Directory(path(&format!("/{name}")));
        for name in ["a", "b", "entry"] {
            let (node, _) = table
                .intern(key(name), None, |id| synthesized(id, name))
                .expect("room");
            assert_exact_order(&table);
            table.forget(node.id, 1);
            assert_exact_order(&table);
        }

        let recalled_id = table.remembered[&key("b")].id;
        let (recalled, _) = table
            .intern(key("b"), None, |id| synthesized(id, "b"))
            .expect("room");
        assert_eq!(recalled.id, recalled_id);
        assert_exact_order(&table);
        table.forget(recalled.id, 1);
        assert_exact_order(&table);

        let (new, _) = table
            .intern(key("d"), None, |id| synthesized(id, "d"))
            .expect("room");
        table.forget(new.id, 1);
        assert!(!table.remembered.contains_key(&key("a")));
        assert!(table.remembered.contains_key(&key("b")));
        assert_exact_order(&table);

        let scratch = crate::testing::Scratch::new("node-order-rejection");
        let entry = std::path::PathBuf::from(scratch.directory("entry"));
        let identity = born(&entry);
        let rejected_id = table.remembered[&key("entry")].id;
        let (replacement, _) = table
            .intern(key("entry"), Some(identity), |id| {
                node_as(id, &entry, identity)
            })
            .expect("room");
        assert_ne!(replacement.id, rejected_id);
        assert_exact_order(&table);

        table.clear();
        assert!(table.remembered.is_empty());
        assert_exact_order(&table);
    }

    #[test]
    fn a_cap_keeps_the_newest_remembered_entries_and_evicts_the_oldest() {
        let mut table = table_of(Some(3));
        let key = |index: u64| NodeKey::Directory(path(&format!("/{index}")));
        let mut ids = Vec::new();
        for index in 0..5u64 {
            let (node, _) = table
                .intern(key(index), None, |id| synthesized(id, "a"))
                .expect("room");
            ids.push(node.id);
            table.forget(node.id, 1);
        }
        assert_eq!(table.remembered(), 3);

        // The newest is still known, the oldest gets a fresh id.
        let (newest, _) = table
            .intern(key(4), None, |id| synthesized(id, "a"))
            .expect("room");
        assert_eq!(newest.id, ids[4]);
        let (oldest, _) = table
            .intern(key(0), None, |id| synthesized(id, "a"))
            .expect("room");
        assert!(!ids.contains(&oldest.id));
    }

    #[test]
    fn one_file_forgotten_many_times_evicts_nothing() {
        let mut table = table_of(Some(3));
        let other = NodeKey::Directory(path("/other"));
        let (kept, _) = table
            .intern(other.clone(), None, |id| synthesized(id, "other"))
            .expect("room");
        table.forget(kept.id, 1);
        let key = NodeKey::Directory(path("/a"));
        for _ in 0..50 {
            let (node, _) = table
                .intern(key.clone(), None, |id| synthesized(id, "a"))
                .expect("room");
            table.forget(node.id, 1);
        }
        assert_eq!(table.remembered(), 2);
        let (again, _) = table
            .intern(other, None, |id| synthesized(id, "other"))
            .expect("room");
        assert_eq!(again.id, kept.id);
    }

    /// The size the documents quote for one remembered entry. A record keyed
    /// by a directory owns the bytes of its namespace path on top of it.
    #[test]
    fn a_remembered_entry_stays_lean() {
        let record = std::mem::size_of::<Remembered>();
        let with_key = std::mem::size_of::<(NodeKey, Remembered)>();
        println!("Remembered: {record} bytes, with its key: {with_key} bytes");
    }

    #[test]
    fn a_node_carries_the_namespace_path_it_was_reached_by() {
        let table = table();
        let root = table.get(ROOT_NODE_ID).expect("installed");
        assert_eq!(root.path, path("/"));
        assert!(root.is_directory());

        // The path is what the *current* policy context of a directory is
        // re-derived from per operation, which is why the node keeps no
        // directory state of its own.
        let file = file(9, "a", 1, EffectiveMode::Rw);
        assert_eq!(file.path, path("/a"));
        assert!(!file.is_directory());
    }
}
