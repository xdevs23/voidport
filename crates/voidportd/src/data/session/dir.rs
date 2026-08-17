//! What a directory node yields: its merged, filtered listing, and where the
//! moves made through it leave every node.
//!
//! Materializing a listing is the one operation that decides visibility for
//! many entries at once — the union of host children and literal-rule children,
//! each stat'd once so ownership policy can drop it — and the stat that decided
//! it is carried into the listing so the entry replies need not re-open what
//! was already seen.
//!
//! A rename or a link made through such a directory is the other half: the
//! server has moved a host entry it may still be asked about by node id, and
//! re-pointing the recorded paths — in every mount, not merely this one — is
//! what keeps `ESTALE` to host-side *external* mutation.

use std::cell::Cell;
use std::os::fd::{AsFd, BorrowedFd};

use rustix::fs::{Dir, OFlags};
use rustix::io::Errno;

use super::resolve::EntrySite;
use super::{ParentDir, Session};
use crate::data::handle::{DirListing, ListingEntry};
use crate::data::node::{Move, Node};
use crate::host::HostIdentity;
use crate::host::attr::HostAttr;
use crate::host::open::{pin_relative, reopen};
use crate::namespace::Namespace;
use crate::rules::{HostBacking, Name, Resolution};

impl Session {
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
    /// no assembled path — the same resolution shape
    /// [`pin_child`](crate::host::open::pin_child) runs under
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
