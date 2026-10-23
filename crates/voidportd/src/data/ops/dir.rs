use std::os::fd::AsFd;
use std::sync::Arc;

use rustix::fs::{AtFlags, CWD, Mode, RenameFlags};
use rustix::io::Errno;
use voidport_proto::message::Request;
use voidport_proto::ops::dir::{
    DirEntryHeader, DirEntryWriter, LinkRequest, LinkResponse, MkdirRequest, MkdirResponse,
    MknodRequest, MknodResponse, ReaddirplusRequest, RenameRequest, RenameResponse, RmdirRequest,
    RmdirResponse, SymlinkRequest, SymlinkResponse, UnlinkRequest, UnlinkResponse, rename_flags,
};

use super::node::entry_of;
use super::{Context, OpResult, name_of};
use crate::data::handle::DirListing;
use crate::data::node::Move;
use crate::data::session::{ParentDir, PrivilegedView, Resolved, Session, Site};
use crate::host::open::{MadeEntry, dup, pin_child, proc_path};
use crate::host::{HostAttr, HostIdentity};
use crate::namespace::Namespace;
use crate::rules::GuestIds;

pub fn mkdir(context: &Context<'_>, request: Request<'_, MkdirRequest>) -> OpResult {
    let session = context.session;
    let parent = session.node(request.head().node_id.get())?;
    let name = name_of(request.name())?;
    let site = session.site(&parent, &name)?;
    let body = request.body();
    let mode = permissions(body.mode.get(), body.umask.get());
    rustix::fs::mkdirat(
        site.directory.as_fd(),
        site.name.as_bytes(),
        host_permissions(mode),
    )?;
    let resolved = adopt(
        session,
        &site,
        &parent,
        &name,
        Adoption {
            made: MadeEntry::Directory,
            caller: caller(&request),
            mode: Some(mode),
        },
    )?;
    context.reply(&MkdirResponse {
        entry: entry_of(&resolved),
    })
}

/// Only FIFOs and sockets: a device node is refused with `EPERM` here as well
/// as at the client.
///
/// The host inode is a marker. Once the entry reply has `S_IFIFO`, the guest
/// kernel installs its own pipe operations and no open, read or write for it
/// reaches this server, so two mounts of one host FIFO are two independent
/// pipes.
pub fn mknod(context: &Context<'_>, request: Request<'_, MknodRequest>) -> OpResult {
    let session = context.session;
    let parent = session.node(request.head().node_id.get())?;
    let name = name_of(request.name())?;
    let body = request.body();
    let kind = special_kind(body.mode.get())?;
    let site = session.site(&parent, &name)?;
    let mode = permissions(body.mode.get(), body.umask.get());
    // The device number is never passed on: the only kinds served take none.
    rustix::fs::mknodat(
        site.directory.as_fd(),
        site.name.as_bytes(),
        kind.file_type(),
        host_permissions(mode),
        0,
    )?;
    let resolved = adopt(
        session,
        &site,
        &parent,
        &name,
        Adoption {
            made: kind,
            caller: caller(&request),
            mode: Some(mode),
        },
    )?;
    context.reply(&MknodResponse {
        entry: entry_of(&resolved),
    })
}

/// Device nodes are refused with `EPERM`, and so is every other kind the
/// file-type bits can spell: naming a host device is a privileged decision.
fn special_kind(mode: u32) -> Result<MadeEntry<'static>, Errno> {
    match rustix::fs::FileType::from_raw_mode(mode) {
        rustix::fs::FileType::Fifo => Ok(MadeEntry::Fifo),
        rustix::fs::FileType::Socket => Ok(MadeEntry::Socket),
        _ => Err(Errno::PERM),
    }
}

pub fn unlink(context: &Context<'_>, request: Request<'_, UnlinkRequest>) -> OpResult {
    let session = context.session;
    let parent = session.node(request.head().node_id.get())?;
    let name = name_of(request.name())?;
    let site = session.site(&parent, &name)?;
    rustix::fs::unlinkat(
        site.directory.as_fd(),
        site.name.as_bytes(),
        AtFlags::empty(),
    )?;
    context.reply(&UnlinkResponse {})
}

pub fn rmdir(context: &Context<'_>, request: Request<'_, RmdirRequest>) -> OpResult {
    let session = context.session;
    let parent = session.node(request.head().node_id.get())?;
    let name = name_of(request.name())?;
    let site = session.site(&parent, &name)?;
    rustix::fs::unlinkat(
        site.directory.as_fd(),
        site.name.as_bytes(),
        AtFlags::REMOVEDIR,
    )?;
    context.reply(&RmdirResponse {})
}

/// An evicted node slot is reopened by walking the whole recorded host path.
/// Every node of an entry that moved, in every mount and for a directory every
/// node beneath it, is therefore re-pointed by [`Session::rebind`], or its next
/// reopen would fail with `ESTALE` for a move the guest asked for. The entries
/// are identified before the syscall, because afterwards the old names are
/// gone.
pub fn rename(context: &Context<'_>, request: Request<'_, RenameRequest>) -> OpResult {
    let session = context.session;
    let source_parent = session.node(request.head().node_id.get())?;
    let target_parent = session.node(request.body().new_parent_node_id.get())?;
    let old = name_of(request.old_name())?;
    let new = name_of(request.new_name())?;
    let source = session.site(&source_parent, &old)?;
    let target = session.site(&target_parent, &new)?;
    let flags = rename_flags_of(request.body().flags.get());
    let moved = moving(&source);
    let exchanged = flags
        .contains(RenameFlags::EXCHANGE)
        .then(|| moving(&target))
        .flatten();
    rustix::fs::renameat_with(
        source.directory.as_fd(),
        source.name.as_bytes(),
        target.directory.as_fd(),
        target.name.as_bytes(),
        flags,
    )?;
    // Both directions of an exchange are handed over together, so that one
    // table pass applies at most one of them to any node: rewriting the two
    // subtrees in turn would carry the first straight back over with the
    // second.
    let moves: Vec<Move> = moved
        .map(|moved| Move::renamed(moved, source.recipe.clone(), target.recipe.clone()))
        .into_iter()
        .chain(
            exchanged
                .map(|moved| Move::renamed(moved, target.recipe.clone(), source.recipe.clone())),
        )
        .collect();
    if !moves.is_empty() {
        session.rebind(&moves);
    }
    context.reply(&RenameResponse {})
}

/// `None` where the entry cannot be stat'd: the rename below then fails on the
/// same entry and returns the errno.
fn moving(site: &Site) -> Option<HostIdentity> {
    HostAttr::of_child(site.directory.as_fd(), &site.name)
        .ok()
        .map(|host| host.host_identity())
}

/// The link is made from the `/proc/self/fd` entry of the target with
/// `AT_SYMLINK_FOLLOW`, the unprivileged way to link the inode of a descriptor:
/// `AT_EMPTY_PATH` would need `CAP_DAC_READ_SEARCH`. The descriptor of the node
/// is opened `O_PATH | O_NOFOLLOW`, so for a symlink node the flag follows only
/// the `/proc` magic link to that inode, and the second name is the symlink
/// itself.
///
/// The node of the new name is built from a duplicate of the descriptor of the
/// node linked, so a host rename that puts another file at the new name before
/// the reply changes neither the node nor the reply. A hard link changes no
/// ownership and no mode: a chown would change the file under every one of its
/// names.
///
/// [`Session::site`] checks the destination, but the source node must be
/// writable too: linking a read-only node into a read-write directory would let
/// the guest open that inode for writing under the new name.
pub fn link(context: &Context<'_>, request: Request<'_, LinkRequest>) -> OpResult {
    let session = context.session;
    let target = session.node(request.body().target_node_id.get())?;
    target.require_writable()?;
    let parent = session.node(request.head().node_id.get())?;
    let name = name_of(request.name())?;
    let target_fd = target
        .descriptor(&session.namespace())?
        .ok_or(Errno::PERM)?;
    let site = session.site(&parent, &name)?;
    let linked = dup(target_fd.as_fd())?;
    rustix::fs::linkat(
        CWD,
        proc_path(target_fd.as_fd()).as_str(),
        site.directory.as_fd(),
        site.name.as_bytes(),
        AtFlags::SYMLINK_FOLLOW,
    )?;
    let resolved = session.admit_created(&site, &parent, &name, linked)?;
    // The inode has a second name now, and a node records one path: whichever
    // of the two is unlinked later must not stale a file the guest can still
    // reach. Every node naming the inode, in this mount and in the others, is
    // re-pointed at the name this operation just made.
    if let Some(identity) = resolved.node.identity() {
        session.rebind(&[Move::linked(identity.host_identity(), site.recipe.clone())]);
    }
    context.reply(&LinkResponse {
        entry: entry_of(&resolved),
    })
}

pub fn symlink(context: &Context<'_>, request: Request<'_, SymlinkRequest>) -> OpResult {
    let session = context.session;
    let parent = session.node(request.head().node_id.get())?;
    let name = name_of(request.name())?;
    let site = session.site(&parent, &name)?;
    rustix::fs::symlinkat(
        request.target(),
        site.directory.as_fd(),
        site.name.as_bytes(),
    )?;
    let resolved = adopt(
        session,
        &site,
        &parent,
        &name,
        Adoption {
            made: MadeEntry::Symlink(request.target()),
            caller: caller(&request),
            mode: None,
        },
    )?;
    context.reply(&SymlinkResponse {
        entry: entry_of(&resolved),
    })
}

/// The listing was merged and filtered at opendir, so the cookies are stable
/// over the view of the namespace, not of the host. The snapshot, the record
/// table and the policy context are taken once for the whole reply, so the
/// privileged bits of an entry cost a map lookup.
#[derive(Debug)]
pub struct Listing {
    listing: Arc<DirListing>,
    namespace: Arc<Namespace>,
    privileged: PrivilegedView,
    parent: ParentDir,
    cookie: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admit {
    Entry(Admitted),
    /// The entry went away, or ownership policy now hides it; nothing was
    /// counted.
    Gone,
    /// The entry is still there and does not fit in the room the reply has
    /// left; nothing was counted.
    Unfit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admitted {
    pub node_id: u64,
    pub len: usize,
}

pub fn listing(
    session: &Session,
    request: &Request<'_, ReaddirplusRequest>,
) -> Result<Listing, Errno> {
    let node = session.directory(request.head().node_id.get())?;
    let handle = request.body().handle.get();
    // The listing must belong to this node. It was materialized under the
    // policy of the directory it was opened through, so walking it under another
    // node would admit the entries of that directory, with their share modes,
    // beneath a namespace path they never belonged to.
    session.handles().owned_by(handle, node.id)?;
    let listing = session.handles().listing(handle)?;
    let namespace = session.namespace();
    let privileged = session.privileged(&namespace);
    let parent = session.parent_dir(&namespace, &node)?;
    Ok(Listing {
        listing,
        namespace,
        privileged,
        parent,
        cookie: request.body().cookie.get(),
    })
}

impl Listing {
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.listing.from_cookie(self.cookie).len()
    }

    /// Each entry is an entry reply like any other: it counts a lookup, and the
    /// client balances it with `forget`. Whether the entry is still there is
    /// decided before whether it fits, so an entry that is gone is skipped
    /// whatever its length, and one that does not fit counts nothing.
    ///
    /// An error is the session failing, not the entry vanishing: dropping such
    /// an entry silently would hand the client a short listing with no way to
    /// tell.
    pub fn admit(
        &self,
        session: &Session,
        index: usize,
        piece: &mut [u8],
        room: usize,
    ) -> Result<Admit, Errno> {
        let Some(entry) = self.listing.from_cookie(self.cookie).get(index) else {
            return Ok(Admit::Gone);
        };
        let name = entry.name.as_bytes();
        let resolved =
            match session.admit_listed(&self.namespace, &self.privileged, &self.parent, entry) {
                Ok(resolved) => resolved,
                Err(Errno::NOENT) => return Ok(Admit::Gone),
                Err(error) => return Err(error),
            };
        if size_of::<DirEntryHeader>() + name.len() > room {
            session.nodes().forget(resolved.node.id, 1);
            return Ok(Admit::Unfit);
        }
        let encoded = (|| {
            let name_len = u32::try_from(name.len()).map_err(|_| Errno::NAMETOOLONG)?;
            let header = DirEntryHeader::new(
                entry_of(&resolved),
                self.cookie + index as u64 + 1,
                resolved
                    .kind
                    .dirent_type(resolved.attr.mode.get())
                    .try_into()
                    .map_err(|_| Errno::IO)?,
                name_len,
            );
            let mut stream = DirEntryWriter::new(piece);
            stream.push(&header, name).map_err(|_| Errno::NAMETOOLONG)?;
            Ok(stream.written())
        })();
        match encoded {
            Ok(len) => Ok(Admit::Entry(Admitted {
                node_id: resolved.node.id,
                len,
            })),
            Err(error) => {
                session.nodes().forget(resolved.node.id, 1);
                Err(error)
            }
        }
    }
}

/// The entry is opened by name right after the syscall that made it, because
/// `mkdirat`, `mknodat` and `symlinkat` return no descriptor. Ownership, mode
/// and the record of privileged bits are applied through that descriptor, and
/// only when [`MadeEntry::matches`] shows it refers to the entry made.
/// Otherwise nothing is applied, and the reply describes whatever is at the
/// name.
fn adopt(
    session: &Session,
    site: &Site,
    parent: &crate::data::node::Node,
    name: &crate::rules::Name,
    adoption: Adoption<'_>,
) -> Result<Resolved, Errno> {
    let fd = pin_child(site.directory.as_fd(), &site.name)?;
    // Everything an operation does to the new entry is done to this descriptor.
    // The descriptor of the node would be a different inode whenever the
    // session already has a node under this name (directory nodes are keyed by
    // namespace path, so a host-side replacement leaves one behind), and the mode
    // a guest asked for would be set on a directory it never changed.
    let found = HostAttr::of(fd.as_fd())?;
    let made_by = rustix::process::geteuid().as_raw();
    if adoption.made.matches(fd.as_fd(), &found, made_by)? {
        session.apply_create_ownership(fd.as_fd(), adoption.caller);
        // `mkdirat` and `mknodat` are both subject to the umask of the server,
        // while the umask of the guest has already been subtracted.
        if let Some(mode) = adoption.mode {
            super::file::apply_mode(fd.as_fd(), mode)?;
            // Before the entry reply is built, because that reply presents the
            // recorded bits.
            super::file::record_created_mode(session, fd.as_fd(), &site.recipe, mode)?;
        }
    } else {
        tracing::debug!(
            name = %site.name,
            expected_type = ?adoption.made.file_type(),
            expected_uid = made_by,
            found_mode = %format_args!("{:o}", found.host_mode()),
            found_uid = found.owner().uid,
            found_links = found.link_count(),
            "the entry at a created name is not the entry made, so its ownership and mode \
             are left as they are"
        );
    }
    session.admit_created(site, parent, name, fd)
}

/// For a symlink, the ownership applies to the link itself and never follows to
/// its target.
struct Adoption<'a> {
    made: MadeEntry<'a>,
    caller: GuestIds,
    /// The host takes it less the privileged bits, and the record takes those.
    /// `None` for a symlink.
    mode: Option<u32>,
}

fn caller<M: voidport_proto::message::RequestBody>(request: &Request<'_, M>) -> GuestIds {
    GuestIds::new(request.head().uid.get(), request.head().gid.get())
}

/// The privileged bits are kept, because the record takes its new value from
/// them. [`host_permissions`] is what reaches the host.
pub(super) fn permissions(mode: u32, umask: u32) -> u32 {
    mode & !umask & 0o7777
}

/// The one shared masking rule, the same one a chmod goes through.
pub(super) fn host_permissions(delivered: u32) -> Mode {
    Mode::from_bits_truncate(crate::records::host_mode(delivered))
}

fn rename_flags_of(flags: u32) -> RenameFlags {
    let mut host = RenameFlags::empty();
    if flags & rename_flags::NOREPLACE != 0 {
        host |= RenameFlags::NOREPLACE;
    }
    if flags & rename_flags::EXCHANGE != 0 {
        host |= RenameFlags::EXCHANGE;
    }
    if flags & rename_flags::WHITEOUT != 0 {
        host |= RenameFlags::WHITEOUT;
    }
    host
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_umask_takes_bits_away_and_never_adds_any() {
        assert_eq!(permissions(0o777, 0o022), 0o755);
        assert_eq!(permissions(0o666, 0o077), 0o600);
        assert_eq!(permissions(0o100_644, 0), 0o644);
    }

    #[test]
    fn a_create_masks_the_privileged_bits_out_of_the_host_mode() {
        assert_eq!(permissions(0o6755, 0), 0o6755);
        assert_eq!(
            host_permissions(permissions(0o6755, 0)),
            Mode::from_bits_truncate(0o755)
        );
        assert_eq!(
            host_permissions(permissions(0o4644, 0o022)),
            Mode::from_bits_truncate(0o644)
        );
        assert_eq!(
            host_permissions(permissions(0o1777, 0)),
            Mode::from_bits_truncate(0o1777)
        );
    }

    #[test]
    fn only_fifos_and_sockets_are_creatable() {
        assert_eq!(special_kind(0o010_644), Ok(MadeEntry::Fifo));
        assert_eq!(special_kind(0o140_644), Ok(MadeEntry::Socket));
        assert_eq!(special_kind(0o020_644), Err(Errno::PERM));
        assert_eq!(special_kind(0o060_644), Err(Errno::PERM));
        assert_eq!(special_kind(0o100_644), Err(Errno::PERM));
        assert_eq!(special_kind(0o040_755), Err(Errno::PERM));
        assert_eq!(special_kind(0o644), Err(Errno::PERM));
    }

    #[test]
    fn rename_flags_map_one_for_one() {
        assert_eq!(rename_flags_of(0), RenameFlags::empty());
        assert_eq!(
            rename_flags_of(rename_flags::NOREPLACE),
            RenameFlags::NOREPLACE
        );
        assert_eq!(
            rename_flags_of(rename_flags::EXCHANGE),
            RenameFlags::EXCHANGE
        );
        assert_eq!(
            rename_flags_of(rename_flags::WHITEOUT),
            RenameFlags::WHITEOUT
        );
    }
}
