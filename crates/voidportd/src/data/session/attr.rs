//! Presenting a node: the attributes a guest is told, and the ownership a
//! guest-created entry lands with.
//!
//! Both directions of the ownership map live here. Outward, a stat is
//! forward-mapped and filtered — an entry whose owner the policy hides is
//! `ENOENT`, whatever the session may still hold for it. Inward, a created
//! entry is chown'd to what the policy reverse-maps the caller to, so what the
//! guest made comes back to it as its own.

use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Arc;

use rustix::io::Errno;
use voidport_proto::attr::Attr;

use super::{Session, Site};
use crate::data::node::{Node, NodeBacking};
use crate::host::attr::{HostAttr, NodeIdentity};
use crate::host::synthesized_attr;
use crate::namespace::Namespace;
use crate::records::{HostLocator, Privileged, PrivilegedBits, Records};
use crate::rules::{GuestIds, HostBacking};

/// What one operation needs to present privileged bits: the namespace switch,
/// and the record table.
///
/// Both are resolved **once per operation**, beside the namespace snapshot the
/// operation already takes, and then carried down every path that presents an
/// attribute. A listing walks hundreds of entries against one of these and
/// costs a map lookup per entry — no host syscall, no per-session cache, no
/// invalidation, because the table is the single point of truth.
#[derive(Clone, Debug)]
pub struct PrivilegedView {
    /// Whether the namespace records and presents privileged bits at all.
    enabled: bool,
    /// The table, as it stood when this operation started.
    records: Arc<Records>,
}

impl PrivilegedView {
    /// How one host-backed node presents.
    #[must_use]
    pub fn of(&self, identity: &NodeIdentity) -> Privileged {
        if !self.enabled {
            return Privileged::Masked;
        }
        Privileged::Recorded(self.records.bits(identity))
    }

    /// How a node presents, for a node that may be a synthesized directory.
    ///
    /// A synthesized directory has no backing identity to record against and
    /// keeps its read-only posture, so it presents as the neutral value.
    #[must_use]
    pub fn of_node(&self, node: &Node) -> Privileged {
        match node.identity() {
            Some(identity) => self.of(&identity),
            None => Privileged::Recorded(PrivilegedBits::NONE),
        }
    }

    /// Whether presentation is masked, which is also what decides that a
    /// delivered mode neither records nor deletes.
    #[must_use]
    pub fn is_masked(&self) -> bool {
        !self.enabled
    }
}

impl Session {
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
    pub(super) fn counted_attr(
        &self,
        namespace: &Namespace,
        privileged: &PrivilegedView,
        node: &Node,
    ) -> Result<Attr, Errno> {
        self.attr_in(namespace, privileged, node).inspect_err(|_| {
            self.nodes().forget(node.id, 1);
        })
    }

    /// How this operation presents privileged bits, resolved once.
    #[must_use]
    pub fn privileged(&self, namespace: &Namespace) -> PrivilegedView {
        PrivilegedView {
            enabled: namespace.privileged_bits(),
            records: self.records.records(),
        }
    }

    /// Applies the assignment rule to one host-backed node.
    ///
    /// Setting is an **assignment, never a merge**: the mode a chmod or a
    /// create delivered has already passed the guest kernel's own permission
    /// and setgid-clearing logic under the caller's full credentials — the wire
    /// carries the post-VFS mode, which the mount's unconditional
    /// `default_permissions` posture guarantees — so its privileged bits are
    /// the record's new value. Bits present record; bits absent delete, which
    /// is what makes a plain chmod clear exactly as local semantics demand and
    /// leaves nothing to resurrect through the presentation merge.
    ///
    /// Under a masked presentation the delivered mode neither records nor
    /// deletes: the guest was shown a mode without the bits, so a
    /// read-modify-write chmod from it must not destroy recorded truth other
    /// mounts still present.
    ///
    /// The locator is built from `recipe` — the entry's whole host path as the
    /// host has it now — because that is what a restart's revalidating stat can
    /// find, and it is the space a rename through the server re-points.
    pub fn record_delivered_mode(
        &self,
        privileged: &PrivilegedView,
        identity: NodeIdentity,
        recipe: &HostBacking,
        delivered: u32,
    ) {
        if privileged.is_masked() {
            return;
        }
        self.records.assign(
            identity,
            HostLocator::of(recipe),
            PrivilegedBits::of(delivered),
        );
    }

    /// Applies the strip rule to one host-backed node after a marked write.
    ///
    /// The running kernel marks a direct-io write by a caller without the
    /// file-mode privilege, the client forwards the mark on every chunk of a
    /// split write, and this is what it means: setuid always, setgid where
    /// group-execute is set. A strip that finds nothing recorded costs the
    /// table lookup and no syscall at all, and one that finds nothing to clear
    /// writes nothing.
    ///
    /// The host backing needs no chmod of its own: it never carries a
    /// privileged bit this server set, and a bit it genuinely carries is
    /// cleared by the host kernel's own write-strip on the very write that was
    /// just made.
    ///
    /// # Errors
    ///
    /// The host errno of the stat the setgid half of the predicate needs, which
    /// is taken only where something is recorded.
    pub fn strip_written(
        &self,
        namespace: &Namespace,
        privileged: &PrivilegedView,
        node: &Node,
    ) -> Result<(), Errno> {
        let (Some(identity), Some(recipe)) = (node.identity(), node.host_recipe()) else {
            return Ok(());
        };
        let recorded = privileged.of(&identity);
        let Privileged::Recorded(bits) = recorded else {
            return Ok(());
        };
        if bits.is_empty() {
            return Ok(());
        }
        // The predicate reads group-execute, and the presentation merge does
        // not touch that bit, so the host mode answers it exactly.
        let fd = node.descriptor(namespace)?.ok_or(Errno::STALE)?;
        let mode = HostAttr::of(fd.as_fd())?.host_mode();
        self.records
            .assign(identity, HostLocator::of(&recipe), bits.stripped(mode));
        Ok(())
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
        let namespace = self.namespace();
        let privileged = self.privileged(&namespace);
        self.attr_in(&namespace, &privileged, node)
    }

    /// [`Self::attr`], against snapshots the caller already took.
    pub(super) fn attr_in(
        &self,
        namespace: &Namespace,
        privileged: &PrivilegedView,
        node: &Node,
    ) -> Result<Attr, Errno> {
        let ownership = namespace.ownership();
        let NodeBacking::Host { .. } = &node.backing else {
            return Ok(synthesized_attr(
                node.ino,
                ownership,
                self.synthesized_times,
            ));
        };
        let fd = node.descriptor(namespace)?.ok_or(Errno::STALE)?;
        HostAttr::of(fd.as_fd())?
            .present(node.ino, ownership, privileged.of_node(node))
            .ok_or(Errno::NOENT)
    }
}
