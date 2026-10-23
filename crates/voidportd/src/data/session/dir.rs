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
    /// A host-backed directory lists the union of its host children and its
    /// literal-rule children, so a re-targeted graft appears in `ls` as well as
    /// in `stat`. Host names are consumed one at a time and only admitted
    /// entries are retained, so the memory a listing costs is the size of the
    /// listing, not of the host directory.
    pub fn materialize(&self, node: &Node) -> Result<DirListing, Errno> {
        let namespace = self.namespace();
        let parent = self.parent_dir(&namespace, node)?;
        let keep = |name: &Name, resolution: &Resolution| {
            self.listed(&namespace, &parent, name, resolution)
        };

        let failure = Cell::new(None);
        let pinned;
        let repinned;
        let entries = match parent.context.backing() {
            None => namespace
                .rules()
                .enumerate(&parent.context, std::iter::empty(), keep),
            Some(backing) => {
                let fd = match parent.pinned_at(backing, &namespace)? {
                    Some((_, fd)) => {
                        pinned = fd;
                        pinned.as_fd()
                    }
                    // The cached descriptor of the node no longer names this
                    // directory: the graft was re-pointed.
                    None => {
                        let graft = namespace.grafts().graft_of(backing).ok_or(Errno::NOENT)?;
                        repinned = pin_relative(graft, backing.relative())?;
                        repinned.as_fd()
                    }
                };
                namespace
                    .rules()
                    .enumerate(&parent.context, host_names(fd, &failure)?, keep)
            }
        };
        // A directory the server could not finish reading has not been listed,
        // and saying otherwise would report a short listing as the whole truth.
        if let Some(error) = failure.get() {
            return Err(error);
        }
        let entries = entries
            .into_iter()
            .map(|entry| ListingEntry {
                name: entry.name,
                resolution: entry.resolution,
                identity: entry.kept,
            })
            .collect();
        Ok(DirListing::new(entries))
    }

    /// `unmapped: hide` is decided per file, so it needs the host uid and gid. An
    /// entry that has vanished since the directory was read is dropped, because
    /// a listing that names entries a lookup cannot find is worse than a
    /// listing that is one entry short.
    ///
    /// `Some(None)` keeps a synthesized directory, which has no ids to judge.
    /// `Some(Some(identity))` keeps a host entry together with the identity
    /// reported by the stat that judged it, which names its node when the entry
    /// is emitted.
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
        // The visibility question only: privileged bits are a presentation merge
        // and can hide nothing, so this asks with the neutral value.
        host.present(
            0,
            *mode,
            namespace.ownership(),
            crate::records::Privileged::Recorded(crate::records::PrivilegedBits::NONE),
        )?;
        Some(Some(host.host_identity()))
    }

    /// A child of a host-backed directory is stat'd by name against the cached
    /// descriptor of the parent: one component, `AT_SYMLINK_NOFOLLOW`. That
    /// saves the descriptor a visibility decision would open only to close.
    ///
    /// A child admitted through a re-targeted literal rule belongs to another
    /// graft on the host, so it is stat'd by a contained walk from the
    /// descriptor of that graft.
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

    /// A rename or a link through the mount moves a file the server may still
    /// be asked about by node id. Another mount of the same namespace, or
    /// another namespace grafting the same host directory, has nodes for the
    /// entry that moved, so the nodes of every mount are re-pointed, to a whole
    /// host path from a graft root.
    ///
    /// One table at a time: the peers are taken as a snapshot and each table is
    /// locked and released in turn, so no session locks two node tables and no
    /// lock is held across the registry lock.
    ///
    /// The record store of the namespace is re-pointed here once, in one pass,
    /// so an exchange applies at most one of the moves to any record. A locator
    /// left naming the old place would drop recorded truth at the next restart.
    pub fn rebind(&self, moves: &[Move]) {
        self.records.relocate(moves);
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

/// The cached descriptor is `O_PATH`, which `getdents` cannot use, so the
/// directory is reopened through `/proc/self/fd`. `.` and `..` are dropped: the
/// client kernel synthesizes them.
///
/// A directory that stops being readable part-way ends the stream and records
/// its errno in `failure`, because an iterator cannot fail, and a quietly short
/// listing would look like lost files.
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
