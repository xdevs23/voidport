use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;

use rustix::io::Errno;

use super::{PrivilegedView, Resolved, Session};
use crate::data::cache::FileCache;
use crate::data::descriptor_budget::{NodePin, Pinned};
use crate::data::handle::ListingEntry;
use crate::data::node::{Interned, Node, NodeBacking, NodeKey};
use crate::host::attr::HostAttr;
use crate::host::open::{pin_child, pin_relative};
use crate::host::{FileKind, synthesized_attr};
use crate::namespace::Namespace;
use crate::rules::{DirContext, EffectiveMode, HostBacking, Name, NamespacePath, Resolution};

#[derive(Debug)]
struct PinnedEntry {
    path: NamespacePath,
    fd: OwnedFd,
    recipe: HostBacking,
    backing: HostBacking,
    mode: EffectiveMode,
}

impl Session {
    pub fn lookup(&self, parent: &Node, name: &Name) -> Result<Resolved, Errno> {
        let namespace = self.namespace();
        let privileged = self.privileged(&namespace);
        let parent = self.parent_dir(&namespace, parent)?;
        let resolution = namespace.rules().resolve(&parent.context, name);
        self.admit(&namespace, &privileged, &parent, name, &resolution)
    }

    /// The context is derived from the snapshot the operation is served against,
    /// so a policy change on a directory (a graft downgraded to read-only,
    /// removed or re-pointed) affects a mounted guest at the next child lookup.
    /// The node does not change its id, its ino or its share mode. Only the
    /// policy its children are resolved under is live.
    pub fn parent_dir(&self, namespace: &Namespace, node: &Node) -> Result<ParentDir, Errno> {
        if !node.is_directory() {
            return Err(Errno::NOTDIR);
        }
        let context = namespace.rules().walk(&node.path).ok_or(Errno::NOENT)?;
        // The slot is taken, not the descriptor: a re-target makes the cached
        // descriptor irrelevant, and reopening a directory only to discard it
        // would turn a re-pointed graft into a spurious `ESTALE`.
        Ok(ParentDir {
            context,
            pinned: node.pin().map(Arc::clone),
        })
    }

    /// The caller passes the snapshot, so one operation cannot resolve a rule
    /// against one snapshot and a graft against the next.
    pub fn admit(
        &self,
        namespace: &Namespace,
        privileged: &PrivilegedView,
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
                let entry = PinnedEntry {
                    path,
                    fd,
                    recipe,
                    backing: backing.clone(),
                    mode: *mode,
                };
                self.admit_pinned_in(namespace, privileged, entry)
            }
        }
    }

    /// For the one caller that already knows which inode the entry is:
    /// `readdirplus` over a listing stat'd once at `opendir`. A node is keyed by
    /// that identity, so an entry the session has already seen is named, and its
    /// lookup counted, without opening it again.
    ///
    /// Its attributes are read here, not carried from `opendir`: a size that
    /// was already old when the reply was built makes a following read of a
    /// file another writer is extending return a stale length.
    ///
    /// No host syscall runs under the node table. Every other operation of the
    /// session needs it, so the lock is taken for the table work of one entry
    /// and released before the open or the stat around it.
    pub fn admit_listed(
        &self,
        namespace: &Namespace,
        privileged: &PrivilegedView,
        parent: &ParentDir,
        entry: &ListingEntry,
    ) -> Result<Resolved, Errno> {
        let (Resolution::HostBacked { backing, mode }, Some(identity)) =
            (&entry.resolution, entry.identity)
        else {
            return match entry.resolution {
                Resolution::SynthesizedDir => {
                    let path = parent.context.path().child(&entry.name);
                    self.admit_synthesized(namespace, path)
                }
                _ => Err(Errno::NOENT),
            };
        };

        let key = NodeKey::listed(parent.context.path(), &entry.name, identity, *mode);
        // Bound to a `let` so the lock is released here instead of at the end
        // of the block below, which stats the host and may need the table again
        // to give the lookup back.
        //
        // The stat taken by the listing shows whether the node under that key is
        // still this entry: a directory replaced on the host since the session
        // opened it has the same namespace path as key, and its node is retired.
        let seen = self
            .nodes()
            .revisit(&key, Some(crate::host::NodeIdentity::listed(identity)));
        if let Some(node) = seen {
            // The stat runs on the cached descriptor of the node, so the reply
            // describes the inode the session listed even if the host has since
            // put something else under that name. The lookup counted by
            // `revisit` prevents the node from being freed while the stat runs
            // unlocked.
            let attr = self.counted_attr(namespace, privileged, &node)?;
            return Ok(Resolved {
                kind: node.kind(),
                node,
                attr,
            });
        }
        let (fd, recipe) = self.pin(namespace, parent, &entry.name, backing)?;
        let pinned = PinnedEntry {
            path: parent.context.path().child(&entry.name),
            fd,
            recipe,
            backing: backing.clone(),
            mode: *mode,
        };
        self.admit_pinned_in(namespace, privileged, pinned)
    }

    fn admit_synthesized(
        &self,
        namespace: &Namespace,
        path: NamespacePath,
    ) -> Result<Resolved, Errno> {
        let ino = self.ino.synthesized(&self.name, &path);
        let (node, _) = self
            .nodes()
            .intern(NodeKey::Directory(path.clone()), None, |id| Node {
                id,
                ino,
                path,
                backing: NodeBacking::Synthesized,
            });
        Ok(Resolved {
            attr: synthesized_attr(node.ino, namespace.ownership(), self.synthesized_times),
            node,
            kind: FileKind::Directory,
        })
    }

    /// The recipe comes from the site, so the node reopens by the name this
    /// operation created it under, and it can still be reopened after a `link`
    /// followed by an unlink of the original name.
    pub fn admit_created(
        &self,
        site: &Site,
        parent: &Node,
        name: &Name,
        fd: OwnedFd,
    ) -> Result<Resolved, Errno> {
        let namespace = self.namespace();
        let privileged = self.privileged(&namespace);
        let entry = PinnedEntry {
            path: parent.path.child(name),
            fd,
            recipe: site.recipe.clone(),
            backing: site.backing.clone(),
            mode: site.mode,
        };
        self.admit_pinned_in(&namespace, &privileged, entry)
    }

    /// The stat of the opened entry runs before the node table is locked, and
    /// the stat of an entry the session already knows runs after the lock is
    /// released: naming a node is table work, reading attributes is host work,
    /// and the two never overlap.
    ///
    /// The cache slot is filed before the table is locked too: admitting a slot
    /// may evict another, and closing the evicted descriptor is a host syscall.
    fn admit_pinned_in(
        &self,
        namespace: &Namespace,
        privileged: &PrivilegedView,
        entry: PinnedEntry,
    ) -> Result<Resolved, Errno> {
        let PinnedEntry {
            path,
            fd,
            recipe,
            backing,
            mode,
        } = entry;
        let host = HostAttr::of(fd.as_fd())?;
        let identity = host.host_identity();
        let ino = self.ino.host(identity);
        // The ownership filter runs on the entry just opened: an entry hidden
        // by the ownership policy does not exist.
        let found = host.node_identity();
        let fresh = host
            .present(ino, mode, namespace.ownership(), privileged.of(&found))
            .ok_or(Errno::NOENT)?;
        let kind = identity.kind;
        let key = NodeKey::of(&path, identity, mode);
        let keyed_by_inode = matches!(key, NodeKey::Inode { .. });
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
                cache: (kind == FileKind::Regular)
                    .then(|| FileCache::new(id, found, self.recalls(), &self.leases)),
            },
        });
        // An existing node is one the table has just proved names this very
        // entry: a key whose node named something else was retired, and this
        // resolution minted a fresh node in its place.
        let (attr, kind) = match interned {
            Interned::Created => (fresh, kind),
            Interned::Existing => {
                // The session already had this entry under another name, above
                // all the other name of a hard link. The recipe just opened is a
                // fresher way back to that inode than the recipe of the node, and
                // adopting it stops a link plus an unlink of the original name
                // from making a node the server itself moved stale.
                if let Some(held) = node.pin() {
                    held.rebind(recipe);
                }
                if keyed_by_inode {
                    // An `NodeKey::Inode` key contains the host identity and the
                    // effective mode, and the table proved both against the node
                    // it handed back, so the stat taken above is what the node
                    // would return, one syscall earlier.
                    //
                    // This is true only for that key shape. A directory is
                    // keyed by namespace path alone: the node behind it may be
                    // a synthesized directory, or one admitted under a
                    // different mode, so the reply re-stats.
                    (fresh, kind)
                } else {
                    (
                        self.counted_attr(namespace, privileged, &node)?,
                        node.kind(),
                    )
                }
            }
        };
        Ok(Resolved { node, attr, kind })
    }

    /// Directory-modifying enforcement lives here, so create, mkdir, symlink,
    /// link, unlink, rmdir and rename cannot drift apart:
    ///
    /// * the parent node must be writable, so a read-only graft, or a
    ///   synthesized directory, fails `EROFS`;
    /// * the name must resolve to an admitted host-backed entry, because a name
    ///   the namespace hides cannot be created or removed; that is `EACCES`;
    /// * the effective mode of the entry must be writable, so a read-only literal
    ///   rule inside a read-write graft still protects its entry.
    ///
    /// The site is always a directory descriptor plus a single component, which
    /// confines the entry-modifying syscalls, that take no resolution flags,
    /// contained.
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
                recipe: child_recipe(&directory, &backing, name),
                directory: fd,
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
            directory: Arc::new(pin_relative(graft, leading)?),
            recipe: backing.clone(),
            name: last.clone(),
            backing,
            mode,
        })
    }

    /// A host child of the directory named by the guest, or an entry put in
    /// another graft by a re-targeted literal rule. The two need different
    /// containment: one component off the parent descriptor, or a contained walk
    /// from the graft descriptor. Deciding it in one place stops the operations
    /// from drifting apart.
    pub(super) fn entry_site<'a>(
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

    /// A child of a host-backed directory is opened from the parent descriptor
    /// and records the recorded path of the parent plus the component. That
    /// path, not the one in the namespace, is right after a rename through the
    /// mount: the namespace still describes the entry where the guest first
    /// found it, and the record of the parent has followed the move.
    ///
    /// A child admitted through a re-targeted literal rule belongs to another
    /// graft, so it is opened, and reopened, from the descriptor of that graft.
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
}

#[derive(Debug)]
pub(super) enum EntrySite<'a> {
    Child {
        directory: HostBacking,
        fd: Arc<OwnedFd>,
    },
    Grafted {
        graft: BorrowedFd<'a>,
        relative: &'a [Name],
    },
}

/// Every entry-modifying syscall takes exactly this shape, which limits them to
/// one component of a contained descriptor.
#[derive(Debug)]
pub struct Site {
    /// Shares the cached descriptor of the directory node. Containment belongs
    /// to the description, so a shared descriptor is contained as a duplicate
    /// is, and a `dup` would only add a `dup` and a `close` to every mutation.
    pub directory: Arc<OwnedFd>,
    /// Not necessarily the name the guest used, since a re-targeted rule renames
    /// as it re-points.
    pub name: Name,
    pub backing: HostBacking,
    /// The whole host path of the entry once the operation has run, from which a
    /// node created here reopens. It differs from `backing` where the parent
    /// directory has been renamed through the mount since the guest resolved it.
    pub recipe: HostBacking,
    pub mode: EffectiveMode,
}

/// One component below the recorded path of the directory, because that is where
/// the host really has it: the namespace still describes a directory the server
/// renamed under its old name.
///
/// Where the two agree, which is almost everywhere, the backing of the
/// resolution already spells that path and is shared, not rebuilt: rebuilding
/// allocates a new list of components for every path the walk resolves.
fn child_recipe(directory: &HostBacking, backing: &HostBacking, name: &Name) -> HostBacking {
    match backing.strip_prefix(directory) {
        Some([below]) if below == name => backing.clone(),
        _ => directory.child(name),
    }
}

type PinnedDir = (HostBacking, Arc<OwnedFd>);

/// The context is derived again per operation by [`Session::parent_dir`]. The
/// slot belongs to the node and records the host location it was opened at. A
/// re-pointed graft makes them disagree, so every use of the slot goes through
/// [`Self::pinned_at`], which hands the descriptor out only while it still names
/// the directory the current policy describes. A stale slot is never reopened:
/// the caller opens the current backing from its graft instead.
#[derive(Debug)]
pub struct ParentDir {
    pub context: DirContext,
    pinned: Option<Arc<NodePin>>,
}

impl ParentDir {
    /// The comparison is the whole staleness check: the slot records an inode
    /// the session opened, `backing` is where the namespace puts this directory
    /// now, and a re-target makes them different directories. It runs before
    /// the descriptor is asked for, so a re-pointed graft never costs a reopen
    /// or turns one into a spurious `ESTALE`.
    pub(super) fn pinned_at(
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
