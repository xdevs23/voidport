//! Presenting a node: the attributes a guest is told, and the ownership a
//! guest-created entry lands with.
//!
//! Both directions of the ownership map live here. Outward, a stat is
//! forward-mapped and filtered — an entry whose owner the policy hides is
//! `ENOENT`, whatever the session may still hold for it. Inward, a created
//! entry is chown'd to what the policy reverse-maps the caller to, so what the
//! guest made comes back to it as its own.

use std::os::fd::{AsFd, BorrowedFd};

use rustix::io::Errno;
use voidport_proto::attr::Attr;

use super::{Session, Site};
use crate::data::node::{Node, NodeBacking};
use crate::host::attr::HostAttr;
use crate::host::synthesized_attr;
use crate::namespace::Namespace;
use crate::rules::GuestIds;

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
    pub(super) fn counted_attr(&self, namespace: &Namespace, node: &Node) -> Result<Attr, Errno> {
        self.attr_in(namespace, node).inspect_err(|_| {
            self.nodes().forget(node.id, 1);
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
}
