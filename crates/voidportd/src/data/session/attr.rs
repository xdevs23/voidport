use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Arc;

use rustix::io::Errno;
use voidport_proto::attr::Attr;

use super::Session;
use crate::data::node::{Node, NodeBacking};
use crate::host::attr::{HostAttr, NodeIdentity};
use crate::host::synthesized_attr;
use crate::namespace::Namespace;
use crate::records::{HostLocator, Privileged, PrivilegedBits, Records};
use crate::rules::{GuestIds, HostBacking};

/// Resolved once per operation, so a listing costs a map lookup per entry and
/// needs no cache or invalidation.
#[derive(Clone, Debug)]
pub struct PrivilegedView {
    enabled: bool,
    records: Arc<Records>,
}

impl PrivilegedView {
    #[must_use]
    pub fn of(&self, identity: &NodeIdentity) -> Privileged {
        if !self.enabled {
            return Privileged::Masked;
        }
        Privileged::Recorded(self.records.bits(identity))
    }

    /// A synthesized directory has no backing identity to record against, so it
    /// presents as the neutral value.
    #[must_use]
    pub fn of_node(&self, node: &Node) -> Privileged {
        match node.identity() {
            Some(identity) => self.of(&identity),
            None => Privileged::Recorded(PrivilegedBits::NONE),
        }
    }

    #[must_use]
    pub fn is_masked(&self) -> bool {
        !self.enabled
    }
}

impl Session {
    /// Naming a node counted the lookup, so every failing path gives the count
    /// back: no entry reply is sent, so the client could never `forget` it.
    /// `readdirplus` skips an entry whose ownership policy has come to hide it
    /// since the listing was materialized, which would otherwise leave its node
    /// in the table for the life of the session. The stat is taken with no lock
    /// held.
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

    #[must_use]
    pub fn privileged(&self, namespace: &Namespace) -> PrivilegedView {
        PrivilegedView {
            enabled: namespace.privileged_bits(),
            records: self.records.records(),
        }
    }

    /// An assignment, never a merge: the mode delivered by a chmod or a create
    /// has already passed the permission and setgid-clearing logic of the guest
    /// kernel, so its privileged bits are the new value of the record. Bits
    /// present record, bits absent delete.
    ///
    /// Under a masked presentation the delivered mode neither records nor
    /// deletes: the guest was shown a mode without the bits, so a
    /// read-modify-write chmod from it must not destroy recorded truth other
    /// mounts still present.
    ///
    /// The locator is built from `recipe`, the whole host path of the entry as
    /// the host has it now, because that is what the revalidating stat of a
    /// restart can find, and it is the space a rename through the server
    /// re-points.
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

    /// The running kernel marks a direct-io write by a caller without the
    /// file-mode privilege, and the client forwards the mark on every chunk of
    /// a split write: setuid is cleared always, setgid where group-execute is
    /// set. The host backing needs no chmod of its own: it never has a
    /// privileged bit this server set, and a bit it really has is cleared
    /// by the write-strip of the host kernel on the write that follows.
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
        // The predicate reads group-execute, and neither the presentation merge
        // nor the write mask of a read-only graft changes that bit, so the host
        // mode has it exactly.
        let fd = node.descriptor(namespace)?.ok_or(Errno::STALE)?;
        let mode = HostAttr::of(fd.as_fd())?.host_mode();
        self.records
            .assign(identity, HostLocator::of(&recipe), bits.stripped(mode));
        Ok(())
    }

    /// Applying it can fail, because a host id other than the one of the server
    /// needs `CAP_CHOWN`. That is not fatal: the entry has the ids of the
    /// server identity, and presentation forward-maps whatever the host
    /// recorded.
    ///
    /// The chown uses the empty path with `AT_EMPTY_PATH`, so it applies to the
    /// file behind `fd` itself, an `O_PATH` descriptor on a symlink included.
    pub fn apply_create_ownership(&self, fd: BorrowedFd<'_>, caller: GuestIds) {
        let host = self.namespace().ownership().reverse_for_create(caller);
        let result = rustix::fs::chownat(
            fd,
            "",
            Some(rustix::process::Uid::from_raw(host.uid)),
            Some(rustix::process::Gid::from_raw(host.gid)),
            rustix::fs::AtFlags::EMPTY_PATH,
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

    pub fn attr(&self, node: &Node) -> Result<Attr, Errno> {
        let namespace = self.namespace();
        let privileged = self.privileged(&namespace);
        self.attr_in(&namespace, &privileged, node)
    }

    pub(super) fn attr_in(
        &self,
        namespace: &Namespace,
        privileged: &PrivilegedView,
        node: &Node,
    ) -> Result<Attr, Errno> {
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
            .present(node.ino, *mode, ownership, privileged.of_node(node))
            .ok_or(Errno::NOENT)
    }
}
