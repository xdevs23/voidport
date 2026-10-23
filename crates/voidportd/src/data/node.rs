//! Node ids come from [`IdSpace`] and are never reused, so a stale id is
//! `ESTALE` after a reconnect instead of a different file. The mount root of
//! every session is node id 1.
//!
//! Non-directories are keyed by `(host_dev, host_ino, effective mode)`: one
//! host inode reachable through rules with different share modes is one node id
//! per mode, each with its own enforcement and presented bits, while all of
//! them share one `ino`. Directories are keyed by namespace path: one host
//! directory grafted at two namespace paths is two nodes, since their children
//! may differ by policy. Directories cannot be hardlinked, so this costs no
//! identity.
//!
//! A node has the mode it was admitted under for its whole life. The policy of
//! its directory is derived again per operation
//! ([`Session::parent_dir`](crate::data::session::Session::parent_dir)).
//!
//! Every entry reply increments a lookup count, FORGET decrements it, and the
//! node is dropped at zero.

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::sync::Arc;

use rustix::io::Errno;

use crate::data::cache::FileCache;
use crate::data::descriptor_budget::NodePin;
use crate::data::ids::IdSpace;
use crate::host::attr::NodeIdentity;
use crate::host::{FileKind, HostIdentity};
use crate::namespace::Namespace;
use crate::reclaim;
use crate::rules::{EffectiveMode, HostBacking, NamespacePath};

pub const ROOT_NODE_ID: u64 = 1;

/// Node ids are never reused within a session, so there is nothing for a
/// generation to distinguish.
pub const GENERATION: u64 = 0;

#[derive(Clone, Debug)]
pub enum NodeBacking {
    Synthesized,
    Host {
        /// Shared so an operation can take it out of the table and do I/O
        /// without holding the table lock.
        pin: Arc<NodePin>,
        mode: EffectiveMode,
        kind: FileKind,
        /// The guest caches the pages of a file for as long as it has the node.
        cache: Option<Arc<FileCache>>,
    },
}

#[derive(Clone, Debug)]
pub struct Node {
    pub id: u64,
    pub ino: u64,
    pub path: NamespacePath,
    pub backing: NodeBacking,
}

impl Node {
    #[must_use]
    pub fn pin(&self) -> Option<&Arc<NodePin>> {
        match &self.backing {
            NodeBacking::Synthesized => None,
            NodeBacking::Host { pin, .. } => Some(pin),
        }
    }

    /// The descriptor comes back owned: it outlives the table lock and an
    /// eviction that happens while the operation is running, since the budget
    /// bounds what the cache holds, never what a caller is using.
    pub fn descriptor(&self, namespace: &Namespace) -> Result<Option<Arc<OwnedFd>>, Errno> {
        match self.pin() {
            None => Ok(None),
            Some(pin) => pin.descriptor(namespace).map(Some),
        }
    }

    #[must_use]
    pub fn cache(&self) -> Option<&Arc<FileCache>> {
        match &self.backing {
            NodeBacking::Synthesized => None,
            NodeBacking::Host { cache, .. } => cache.as_ref(),
        }
    }

    #[must_use]
    pub fn identity(&self) -> Option<NodeIdentity> {
        self.pin().map(|pin| pin.identity())
    }

    /// The recipe, not the location the namespace described when the node was
    /// opened: the two part company wherever the server has since moved the
    /// entry, or a parent it was reached through. A snapshot, because the recipe
    /// is behind the lock of the slot.
    #[must_use]
    pub fn host_recipe(&self) -> Option<HostBacking> {
        self.pin().map(|pin| pin.recipe())
    }

    #[must_use]
    pub fn mode(&self) -> Option<EffectiveMode> {
        match &self.backing {
            NodeBacking::Synthesized => None,
            NodeBacking::Host { mode, .. } => Some(*mode),
        }
    }

    #[must_use]
    pub fn kind(&self) -> FileKind {
        match &self.backing {
            NodeBacking::Synthesized => FileKind::Directory,
            NodeBacking::Host { kind, .. } => *kind,
        }
    }

    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.kind().is_directory()
    }

    /// The presented permission bits only show the mode. This check enforces it.
    pub fn require_writable(&self) -> Result<(), Errno> {
        match self.mode() {
            Some(mode) if mode.is_writable() => Ok(()),
            _ => Err(Errno::ROFS),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NodeKey {
    Directory(NamespacePath),
    Inode {
        device: u64,
        inode: u64,
        mode: EffectiveMode,
    },
}

impl NodeKey {
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

    /// Building the child path for every entry of a listing allocates a new list
    /// of components for a key that, for everything but a directory, contains no
    /// path at all, so this builds one only when the key needs it.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interned {
    Created,
    Existing,
}

/// A link gives an inode a second name and moves nothing. A rename also records
/// the old path, because the recorded paths of the descendants of a directory
/// run through it.
#[derive(Clone, Debug)]
pub struct Move {
    /// Taken before the syscall, because afterwards the old name is gone.
    entry: HostIdentity,
    /// `None` for a link, which adds a name instead of moving one and can carry
    /// no subtree: the host refuses to hard-link a directory.
    from: Option<HostBacking>,
    to: HostBacking,
}

impl Move {
    #[must_use]
    pub fn renamed(entry: HostIdentity, from: HostBacking, to: HostBacking) -> Self {
        Self {
            entry,
            from: Some(from),
            to,
        }
    }

    #[must_use]
    pub fn linked(entry: HostIdentity, to: HostBacking) -> Self {
        Self {
            entry,
            from: None,
            to,
        }
    }

    /// Read by the record store, which needs the same re-pointing: a locator must
    /// follow the entry the server itself moved, or a restart would revalidate
    /// it against a name that is gone.
    #[must_use]
    pub fn entry(&self) -> HostIdentity {
        self.entry
    }

    #[must_use]
    pub fn from(&self) -> Option<&HostBacking> {
        self.from.as_ref()
    }

    #[must_use]
    pub fn to(&self) -> &HostBacking {
        &self.to
    }

    /// Decides between two hash lookups and a scan of the table.
    fn carries_a_subtree(&self) -> bool {
        self.entry.kind.is_directory() && self.from.is_some()
    }

    /// A node is concerned if it is the entry that moved, whatever name it
    /// recorded reaching it (the other name of a hard link, an alias under a
    /// differently spelled graft), or if it recorded a path underneath the one
    /// that moved.
    fn rebound(&self, pin: &NodePin) -> Option<HostBacking> {
        if pin.identity().names(self.entry) {
            return Some(self.to.clone());
        }
        let recipe = pin.recipe();
        let below = recipe.strip_prefix(self.from.as_ref()?)?;
        Some(self.to.extend(below))
    }
}

#[derive(Debug)]
pub struct NodeTable {
    nodes: HashMap<u64, Entry>,
    index: HashMap<NodeKey, u64>,
    ids: IdSpace,
}

#[derive(Debug)]
struct Entry {
    node: Node,
    key: NodeKey,
    lookups: u64,
}

impl NodeTable {
    #[must_use]
    pub fn new(ids: IdSpace) -> Self {
        Self {
            nodes: HashMap::new(),
            index: HashMap::new(),
            ids,
        }
    }

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

    /// `build` is only called when the entry is new, so a repeated lookup costs
    /// no descriptor. The flag shows which happened, because the reply of the
    /// caller must describe the node it got back: they differ when the name of
    /// a directory has been replaced on the host since the session opened it.
    /// `found` decides whether the node already under this key is still the
    /// same file; see [`Self::revisit`].
    ///
    /// The table has no size limit: the host limits the memory of the process.
    pub fn intern(
        &mut self,
        key: NodeKey,
        found: Option<NodeIdentity>,
        build: impl FnOnce(u64) -> Node,
    ) -> (Node, Interned) {
        if let Some(node) = self.revisit(&key, found) {
            return (node, Interned::Existing);
        }
        let id = self.ids.take();
        let node = build(id);
        self.insert(id, key, node.clone());
        (node, Interned::Created)
    }

    /// A caller that can name the key of an entry without opening it needs no
    /// descriptor for an entry the session has seen before.
    ///
    /// A key is not a file: a directory is keyed by its namespace path, which an
    /// external replacement leaves pointing at the old directory, and on a
    /// filesystem that reuses inode numbers a recreated file gets the key of its
    /// predecessor. Where `found` shows the entry there is not the one of the
    /// node, the node is retired: taken out of the table, so its id fails with
    /// `ESTALE` and its key is free, and the caller mints a fresh node. Otherwise
    /// the dead node would block the key and the path would never heal. A
    /// `forget` for a retired id is a no-op, so the accounting is balanced.
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

    /// The id is not reused, so nothing the client still holds against it can
    /// name another file.
    fn retire(&mut self, id: u64) {
        if let Some(entry) = self.nodes.remove(&id) {
            self.index.remove(&entry.key);
            reclaim::released(1);
            self.shrink_if_drained();
        }
    }

    #[must_use]
    pub fn get(&self, id: u64) -> Option<Node> {
        self.nodes.get(&id).map(|entry| entry.node.clone())
    }

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
        }
    }

    /// Removing an entry frees the entry, not the table: a hash table sized for
    /// a walk over a very large tree is tens of megabytes of spine that a drained session
    /// would otherwise hold until it disconnects. Shrinking at a quarter full
    /// keeps it amortized, since the table must then double twice before another
    /// shrink, and the floor keeps ordinary sessions out of it.
    fn shrink_if_drained(&mut self) {
        const FLOOR: usize = 1024;
        if self.nodes.capacity() > FLOOR && self.nodes.len() * 4 <= self.nodes.capacity() {
            self.nodes.shrink_to_fit();
            self.index.shrink_to_fit();
        }
    }

    pub fn clear(&mut self) {
        reclaim::released(self.nodes.len());
        self.nodes.clear();
        self.index.clear();
    }

    #[must_use]
    pub fn caches(&self) -> Vec<Arc<FileCache>> {
        self.nodes
            .values()
            .filter_map(|entry| entry.node.cache().cloned())
            .collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// A node records its whole host path, so a directory move is a subtree
    /// rewrite: the old path is a prefix of the path of every descendant, and
    /// swapping that prefix re-points them all. A move without a subtree, a
    /// file rename or a link, is keyed by host identity, so its nodes are two
    /// hash lookups. A directory move scans, because a subtree is not a key:
    /// only directory renames pay for it, never the file renames a build system
    /// runs on.
    ///
    /// All moves go in one pass and at most one applies per node:
    /// `RENAME_EXCHANGE` swaps two subtrees, and rewriting one prefix and then
    /// the other in turn would carry the nodes of the first subtree straight
    /// back over with the second.
    ///
    /// Nothing here calls the host, so it is safe under the table lock.
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

impl Drop for NodeTable {
    fn drop(&mut self) {
        reclaim::released(self.nodes.len());
    }
}

/// Only two recorded identities can disagree: a synthesized directory has no
/// host entry, and silence is never evidence of a replacement.
fn still_the_same(held: Option<NodeIdentity>, found: Option<NodeIdentity>) -> bool {
    match (held, found) {
        (Some(held), Some(found)) => held.matches(&found),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::descriptor_budget::{DescriptorBudget, Pinned};
    use crate::host::attr::HostAttr;
    use crate::rules::{HostTarget, Name};
    use std::os::fd::AsFd as _;

    fn path(raw: &str) -> NamespacePath {
        NamespacePath::parse(raw).expect("valid namespace path")
    }

    fn backing(name: &str) -> HostBacking {
        HostBacking::graft_root(HostTarget::new("/srv")).child(&Name::new(name).expect("valid"))
    }

    fn table() -> NodeTable {
        let mut table = NodeTable::new(crate::data::ids::Generations::shared().space());
        table.install_root(
            NodeKey::Directory(path("/")),
            1,
            path("/"),
            NodeBacking::Synthesized,
        );
        table
    }

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
                cache: None,
            },
        }
    }

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
                cache: None,
            },
        }
    }

    fn identity_of(entry: &std::path::Path) -> Option<NodeIdentity> {
        node_of(0, entry, EffectiveMode::Rw).identity()
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
        let key = NodeKey::Inode {
            device: 1,
            inode: 2,
            mode: EffectiveMode::Rw,
        };
        let (first, interned) =
            table.intern(key.clone(), None, |id| file(id, "a", 10, EffectiveMode::Rw));
        assert_eq!(interned, Interned::Created);
        let (second, interned) = table.intern(key.clone(), None, |_| {
            unreachable!("the node already exists")
        });
        assert_eq!(interned, Interned::Existing);
        assert_eq!(first.id, second.id);
        assert_eq!(table.nodes[&first.id].lookups, 2);
        assert_eq!(table.len(), 2);

        table.forget(first.id, 1);
        assert!(table.get(first.id).is_some());
        table.forget(first.id, 1);
        assert!(table.get(first.id).is_none());
        assert_eq!(table.len(), 1);

        let (third, _) = table.intern(key, None, |id| file(id, "a", 10, EffectiveMode::Rw));
        assert_ne!(third.id, first.id);
    }

    #[test]
    fn one_inode_under_two_modes_is_two_nodes_sharing_an_ino() {
        let mut table = table();
        let (rw, _) = table.intern(
            NodeKey::Inode {
                device: 1,
                inode: 2,
                mode: EffectiveMode::Rw,
            },
            None,
            |id| file(id, "a", 10, EffectiveMode::Rw),
        );
        let (ro, _) = table.intern(
            NodeKey::Inode {
                device: 1,
                inode: 2,
                mode: EffectiveMode::Ro,
            },
            None,
            |id| file(id, "b", 10, EffectiveMode::Ro),
        );
        assert_ne!(rw.id, ro.id);
        assert_eq!(rw.ino, ro.ino);
        assert_eq!(rw.require_writable(), Ok(()));
        assert_eq!(ro.require_writable(), Err(Errno::ROFS));
    }

    #[test]
    fn teardown_drops_every_node_without_reusing_an_id() {
        let mut table = table();
        let (node, _) = table.intern(
            NodeKey::Inode {
                device: 1,
                inode: 2,
                mode: EffectiveMode::Rw,
            },
            None,
            |id| file(id, "a", 10, EffectiveMode::Rw),
        );
        table.clear();
        assert!(table.is_empty());
        assert!(table.get(node.id).is_none());
        let (fresh, interned) = table.intern(
            NodeKey::Inode {
                device: 1,
                inode: 2,
                mode: EffectiveMode::Rw,
            },
            None,
            |id| file(id, "a", 10, EffectiveMode::Rw),
        );
        assert_eq!(interned, Interned::Created, "the index went with them");
        assert!(fresh.id > node.id, "ids are not reused");
    }

    #[test]
    fn a_replaced_entry_retires_the_node_holding_its_key() {
        let scratch = voidport_test_host::Scratch::new("node-retire");
        let first = scratch.file("first", b"1");
        let second = scratch.file("second", b"2");
        let mut table = table();
        let key = NodeKey::Directory(path("/entry"));

        let (old, interned) = table.intern(key.clone(), identity_of(&first), |id| {
            node_of(id, &first, EffectiveMode::Rw)
        });
        assert_eq!(interned, Interned::Created);

        let (again, interned) = table.intern(key.clone(), identity_of(&first), |_| {
            unreachable!("the node already exists")
        });
        assert_eq!((again.id, interned), (old.id, Interned::Existing));
        assert_eq!(table.nodes[&old.id].lookups, 2);

        let (fresh, interned) = table.intern(key, identity_of(&second), |id| {
            node_of(id, &second, EffectiveMode::Rw)
        });
        assert_eq!(interned, Interned::Created);
        assert_ne!(fresh.id, old.id, "ids are never reused");
        assert!(
            table.get(old.id).is_none(),
            "a retired id names nothing, which is what `ESTALE` means"
        );

        table.forget(old.id, 2);
        assert!(table.get(fresh.id).is_some(), "the fresh node is untouched");
    }

    #[test]
    fn a_node_carries_the_namespace_path_it_was_reached_by() {
        let table = table();
        let root = table.get(ROOT_NODE_ID).expect("installed");
        assert_eq!(root.path, path("/"));
        assert!(root.is_directory());

        let file = file(9, "a", 1, EffectiveMode::Rw);
        assert_eq!(file.path, path("/a"));
        assert!(!file.is_directory());
    }
}
