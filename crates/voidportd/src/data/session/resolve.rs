//! Turning a name into a node: the path-resolution and admission algorithm.
//!
//! This is the session's decision procedure, and the one place a guest's name
//! becomes something it may touch. The engine resolves one component against
//! the parent's **live** policy context, the host is pinned under containment,
//! and ownership policy gets the last word. Every way in — a lookup, an entry
//! of a listing, an entry the session has just created — converges on the same
//! admission, so none of them can admit what another would refuse.
//!
//! The shapes the algorithm hands out live here too: the directory a
//! resolution runs under, where an entry sits relative to what is already
//! pinned, and the site an entry-modifying syscall is applied to.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;

use rustix::io::Errno;

use super::{Resolved, Session};
use crate::data::handle::ListingEntry;
use crate::data::node::{Interned, Node, NodeBacking, NodeKey};
use crate::data::pin::{NodePin, Pinned};
use crate::host::attr::HostAttr;
use crate::host::open::{pin_child, pin_relative};
use crate::host::{FileKind, synthesized_attr};
use crate::namespace::Namespace;
use crate::rules::{DirContext, EffectiveMode, HostBacking, Name, NamespacePath, Resolution};

impl Session {
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
        // Which key shape this entry took decides whether a node the table
        // already holds for it can be answered from the stat above; see below.
        let keyed_by_inode = matches!(key, NodeKey::Inode { .. });
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
                if keyed_by_inode {
                    // An [`NodeKey::Inode`] key carries the host identity *and*
                    // the effective mode, and the table proved both against the
                    // node it handed back — so the node's own stat would read
                    // the same inode and present it under the same mode against
                    // the same ownership policy. The stat taken above is that
                    // answer, one syscall earlier.
                    //
                    // **This holds only for that key shape.** A directory is
                    // keyed by namespace path alone: the node behind it may be
                    // a synthesized directory, or one admitted under a
                    // different mode, and the reply owes the guest *that*
                    // node's attributes — never the ones the resolution just
                    // computed. It re-stats.
                    (fresh, kind)
                } else {
                    (self.counted_attr(namespace, &node)?, node.kind())
                }
            }
        };
        Ok(Resolved { node, attr, kind })
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
}

/// Where an entry lives relative to what the session already holds pinned.
///
/// [`Session::entry_site`] is the only thing that decides between the two, and
/// both arms are containment shapes the host layer enforces: a single component
/// off a pinned directory, or a `RESOLVE_BENEATH` walk from a graft root.
#[derive(Debug)]
pub(super) enum EntrySite<'a> {
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
    ///
    /// A child of a pinned directory takes the **node's own** descriptor, held
    /// for as long as the site is: an in-flight operation keeping a descriptor
    /// alive past an eviction is what the pin ledger is built to allow, so
    /// duplicating the description to own it would buy nothing and cost every
    /// mutation a `dup` and a `close`. Containment is the description's, not
    /// the descriptor's, so a shared one is contained exactly as a private one
    /// would be.
    pub directory: Arc<OwnedFd>,
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
