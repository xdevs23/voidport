//! Directory operations: the entry-modifying set, and readdirplus.
//!
//! Every operation that changes a directory goes through
//! [`Session::site`](crate::data::session::Session::site), which is where
//! share-mode enforcement lives: a read-only or synthesized parent fails
//! `EROFS`, a name the namespace does not admit fails `EACCES`, and a
//! read-only entry inside a read-write graft is still protected. What arrives
//! here is a directory descriptor and one component.
//!
//! `link` names a second node — the inode being given another name — and
//! enforces that one itself, because the site only speaks for the destination.

use std::os::fd::AsFd;

use rustix::fs::{AtFlags, CWD, Mode, RenameFlags};
use rustix::io::Errno;
use voidport_proto::message::Request;
use voidport_proto::ops::dir::{
    DirEntryHeader, DirEntryWriter, LinkRequest, LinkResponse, MkdirRequest, MkdirResponse,
    MknodRequest, MknodResponse, ReaddirplusRequest, ReaddirplusResponse, RenameRequest,
    RenameResponse, RmdirRequest, RmdirResponse, SymlinkRequest, SymlinkResponse, UnlinkRequest,
    UnlinkResponse, rename_flags,
};
use zerocopy::byteorder::little_endian::U32;

use super::node::entry_of;
use super::{Context, OpResult, name_of};
use crate::data::node::Move;
use crate::data::session::{Resolved, Session, Site};
use crate::host::open::{pin_child, proc_path};
use crate::host::{FileKind, HostAttr, HostIdentity};
use crate::rules::GuestIds;

/// Creates a directory.
pub fn mkdir(context: &Context<'_>, request: Request<'_, MkdirRequest>) -> OpResult {
    let session = context.session;
    let parent = session.node(request.head().node_id.get())?;
    let name = name_of(request.name())?;
    let site = session.site(&parent, &name)?;
    let body = request.body();
    let mode = permissions(body.mode.get(), body.umask.get());
    rustix::fs::mkdirat(site.directory.as_fd(), site.name.as_bytes(), mode)?;
    let resolved = adopt(
        session,
        &site,
        &parent,
        &name,
        Adoption::Created {
            caller: caller(&request),
            mode,
        },
    )?;
    context.reply(&MkdirResponse {
        entry: entry_of(&resolved),
    })
}

/// Creates a FIFO or a socket file.
///
/// Two kinds, and no more. Both are unprivileged host objects an ordinary user
/// creates every day; a device node is not, and is refused `EPERM` here as well
/// as at the client, so a privileged opt-in stays future work, not a
/// thing this build half-does.
///
/// **The host inode is a marker, and that is the whole of the server's part.**
/// Once the entry reply says `S_IFIFO`, the guest kernel installs its own pipe
/// operations and no open, read or write for it ever reaches this server; an
/// `AF_UNIX` connection resolves in the connecting process's kernel the same
/// way. Rendezvous and data flow therefore work between processes of one guest
/// and cross no mount boundary — two mounts of one host FIFO are two
/// independent pipes.
pub fn mknod(context: &Context<'_>, request: Request<'_, MknodRequest>) -> OpResult {
    let session = context.session;
    let parent = session.node(request.head().node_id.get())?;
    let name = name_of(request.name())?;
    let body = request.body();
    let kind = special_kind(body.mode.get())?;
    let site = session.site(&parent, &name)?;
    let mode = permissions(body.mode.get(), body.umask.get());
    // The device number is never passed on: the only kinds served take none,
    // and a nonzero one on a FIFO would be a lie the host would ignore.
    rustix::fs::mknodat(site.directory.as_fd(), site.name.as_bytes(), kind, mode, 0)?;
    let resolved = adopt(
        session,
        &site,
        &parent,
        &name,
        Adoption::Created {
            caller: caller(&request),
            mode,
        },
    )?;
    context.reply(&MknodResponse {
        entry: entry_of(&resolved),
    })
}

/// The host file type a `mknod` request asks for.
///
/// # Errors
///
/// Returns `EPERM` for a device node, and for every other kind the file-type
/// bits can spell: a namespace projects a host tree, and handing a guest the
/// power to name a host device is a privileged decision nobody has made.
fn special_kind(mode: u32) -> Result<rustix::fs::FileType, Errno> {
    match rustix::fs::FileType::from_raw_mode(mode) {
        kind @ (rustix::fs::FileType::Fifo | rustix::fs::FileType::Socket) => Ok(kind),
        _ => Err(Errno::PERM),
    }
}

/// Removes a non-directory entry.
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

/// Removes a directory.
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

/// Renames an entry, possibly into another directory.
///
/// Both ends are located and enforced separately, so a rename out of a
/// read-only graft and a rename into one both fail, and a rename can never move
/// an entry to a name the namespace would hide.
///
/// **The server never stales what it moved itself.** A node's descriptor is a
/// cache slot, and an evicted slot is re-pinned by walking the whole host path
/// the node recorded — so an entry this operation moves must have the nodes
/// that name it re-pointed at where it went, or their next re-pin would look at
/// the old name and answer `ESTALE` for a move the guest asked for. That is
/// *every* node naming the entry, in every mount and under every namespace
/// alias, and — for a directory — every node beneath it, whose recorded paths
/// run through the name that just changed. [`Session::rebind`] is what does it.
/// The entries are identified before the syscall, because afterwards the old
/// names are gone.
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
    // An exchange moves *both* entries, each to where the other was.
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

/// What a rename is about to move, as the host has it now.
///
/// `None` where the entry cannot be stat'd: the rename below will fail on the
/// same entry, and answering that failure is the syscall's business, not
/// this one's.
fn moving(site: &Site) -> Option<HostIdentity> {
    HostAttr::of_child(site.directory.as_fd(), &site.name)
        .ok()
        .map(|host| host.host_identity())
}

/// Creates a hard link to an existing node.
///
/// The link is made from the target's `/proc/self/fd` entry with
/// `AT_SYMLINK_FOLLOW`, which is the unprivileged spelling of "link this
/// descriptor's inode"; `AT_EMPTY_PATH` would need `CAP_DAC_READ_SEARCH`.
///
/// Two things are enforced before that syscall, and both are the design's:
///
/// * **The target's kind.** Only a regular file or a directory may be a
///   hard-link target (`EPERM` otherwise). `AT_SYMLINK_FOLLOW` is a *follow*
///   flag, and the one thing this server must never do is resolve a guest's
///   symlink on the host side; refusing the kind outright means the follow flag
///   can never be handed a symlink, whatever a future magic-link or kernel
///   behaviour would make of one.
/// * **Both ends' share modes.** The destination is [`Session::site`]'s
///   business, but the **source node** must be writable too: a hard link is a
///   new name for an inode, so linking a read-only node into a read-write
///   directory would let the guest open that inode for writing under the new
///   name. Read-only means the inode, not the path that reached it.
pub fn link(context: &Context<'_>, request: Request<'_, LinkRequest>) -> OpResult {
    let session = context.session;
    let target = session.node(request.body().target_node_id.get())?;
    if !matches!(target.kind(), FileKind::Regular | FileKind::Directory) {
        return Err(Errno::PERM);
    }
    target.require_writable()?;
    let parent = session.node(request.head().node_id.get())?;
    let name = name_of(request.name())?;
    let target_fd = target
        .descriptor(&session.namespace())?
        .ok_or(Errno::PERM)?;
    let site = session.site(&parent, &name)?;
    rustix::fs::linkat(
        CWD,
        proc_path(target_fd.as_fd()).as_str(),
        site.directory.as_fd(),
        site.name.as_bytes(),
        AtFlags::SYMLINK_FOLLOW,
    )?;
    let resolved = adopt(session, &site, &parent, &name, Adoption::Linked)?;
    // The inode has a second name now, and a node records one path: whichever
    // of the two is unlinked later must not stale a file the guest can still
    // reach. Every node naming the inode — in this mount and in the others — is
    // re-pointed at the name this operation just made.
    if let Some(identity) = resolved.node.identity() {
        session.rebind(&[Move::linked(identity.host_identity(), site.recipe.clone())]);
    }
    context.reply(&LinkResponse {
        entry: entry_of(&resolved),
    })
}

/// Creates a symlink, storing its target verbatim.
///
/// The target is never interpreted by the server — not at creation and not at
/// lookup. Following it is the client kernel's job.
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
        Adoption::CreatedSymlink(caller(&request)),
    )?;
    context.reply(&SymlinkResponse {
        entry: entry_of(&resolved),
    })
}

/// Enumerates a directory from a materialized listing.
///
/// The listing was merged and filtered at opendir, so the cookies are stable
/// over the *namespace's* view of the directory, not over the host's.
/// Each entry emitted is an entry reply like any other: it counts a lookup, and
/// the client balances it with `forget`.
pub fn readdirplus(context: &Context<'_>, request: Request<'_, ReaddirplusRequest>) -> OpResult {
    let session = context.session;
    let node = session.directory(request.head().node_id.get())?;
    let handle = request.body().handle.get();
    // The listing must be *this* node's. It was materialized under the policy
    // of the directory it was opened through, so walking it under another node
    // would admit that directory's entries — with its share modes — beneath a
    // namespace path they never belonged to.
    session.handles().owned_by(handle, node.id)?;
    let listing = session.handles().listing(handle)?;
    let namespace = session.namespace();
    let parent = session.parent_dir(&namespace, &node)?;

    let cookie = request.body().cookie.get();
    let budget = context
        .payload_budget::<ReaddirplusResponse>()
        .min(request.body().size.get() as usize);
    let mut buffer = vec![0u8; budget];
    let mut stream = DirEntryWriter::new(&mut buffer);
    let mut emitted = Vec::new();
    let mut full = false;
    let remaining = listing.from_cookie(cookie);
    // The node table is taken and dropped inside `admit_listed`, once per
    // entry and never across a host syscall. A batch of hundreds of entries is
    // hundreds of pins and stats, and holding the table across them would queue
    // every other operation of this session — a lookup, a getattr, a write's
    // entry reply — behind one listing.
    for (offset, entry) in remaining.iter().enumerate() {
        let resolved = match session.admit_listed(&namespace, &parent, entry) {
            Ok(resolved) => resolved,
            // The entry went away, or ownership policy now hides it. Skipping
            // it keeps the listing honest: every name it reports resolves.
            Err(Errno::NOENT) => continue,
            // Anything else is this *session* failing, not the entry vanishing
            // — the node cap (`ENFILE`) above all. Silently dropping those
            // entries would hand the client a listing that is short with no
            // way to tell, and a directory would appear to have lost files.
            Err(error) => {
                release(session, &emitted);
                return Err(error);
            }
        };
        let next_cookie = cookie + offset as u64 + 1;
        let name = entry.name.as_bytes();
        let name_len = u32::try_from(name.len()).map_err(|_| Errno::OVERFLOW)?;
        let header = DirEntryHeader::new(
            entry_of(&resolved),
            next_cookie,
            resolved.kind.dirent_type(resolved.attr.mode.get()),
            name_len,
        );
        if stream.push(&header, name).is_err() {
            // The entry does not fit, so no entry reply describes it and the
            // client can never balance the lookup `admit_listed` just counted.
            // It is given back here; the next request resumes at this cookie.
            session.nodes().forget(resolved.node.id, 1);
            full = true;
            break;
        }
        emitted.push(resolved.node.id);
    }
    if emitted.is_empty() && full {
        // Not one entry fits the client's budget; saying "end of directory"
        // would lose the rest of the listing. An empty reply because every
        // remaining entry has vanished *is* end of directory, and says so.
        return Err(Errno::OVERFLOW);
    }
    // The finished stream is handed to the reply as a borrow of the buffer it
    // was built in: a listing is the largest payload this server sends, and
    // copying it out to own it would cost a second allocation of that size for
    // nothing — the reply's own buffer is where it is going anyway.
    let entries = stream.finish();
    let entries_len = u32::try_from(entries.len()).map_err(|_| Errno::OVERFLOW)?;
    context.reply_with(
        &ReaddirplusResponse {
            entries_len: U32::new(entries_len),
        },
        entries,
    )
}

/// Gives back the lookups a readdirplus counted but will not report.
///
/// A reply that never leaves is a reply the client cannot `forget` against, so
/// the entries admitted before the failure would otherwise be pinned until the
/// session ends.
fn release(session: &Session, nodes: &[u64]) {
    let mut table = session.nodes();
    for id in nodes {
        table.forget(*id, 1);
    }
}

/// Turns a freshly created entry into a node with an entry reply.
///
/// The entry is pinned from the site it was created at — not looked up again
/// through the namespace — so a concurrent replacement of the name cannot make
/// the reply describe a different inode than the one just created.
fn adopt(
    session: &Session,
    site: &Site,
    parent: &crate::data::node::Node,
    name: &crate::rules::Name,
    adoption: Adoption,
) -> Result<Resolved, Errno> {
    let fd = pin_child(site.directory.as_fd(), &site.name)?;
    // Everything an operation does to the entry it just made is done to *this*
    // descriptor — the inode the syscall above created. Reaching for the node's
    // descriptor instead would be a different inode whenever the session
    // already holds one under this name (directory nodes are keyed by namespace
    // path, so a host-side replacement leaves one behind), and the mode a guest
    // asked for would land on a directory it never touched.
    match adoption {
        // A directory and a FIFO or socket file are adopted identically:
        // `mkdirat` and `mknodat` are both subject to the *server's* umask,
        // while the guest's is the one the design says applies and has already
        // been subtracted.
        Adoption::Created { caller, mode } => {
            session.apply_create_ownership(fd.as_fd(), caller);
            super::file::apply_mode(fd.as_fd(), mode)?;
        }
        // A symlink is the exception: it is owned through the site — the
        // directory descriptor the creation was issued against and the one
        // component it created — because no descriptor on a symlink can be
        // chowned.
        Adoption::CreatedSymlink(caller) => {
            session.apply_create_symlink_ownership(site, caller);
        }
        Adoption::Linked => {}
    }
    let path = parent.path.child(name);
    // The recipe is the site's, so the node re-pins by the very name this
    // operation created it under — which is what makes a `link` followed by an
    // unlink of the original name leave the node re-pinnable.
    session.admit_pinned(
        path,
        fd,
        site.recipe.clone(),
        site.backing.clone(),
        site.mode,
    )
}

/// What an operation owes the entry it just made.
enum Adoption {
    /// A new directory, FIFO or socket file: it lands owned by the caller's
    /// reverse-mapped host identity, per the ownership contract, with exactly
    /// the permission bits the guest asked for.
    Created {
        /// Whose it becomes.
        caller: GuestIds,
        /// The bits it takes, the guest's umask already subtracted.
        mode: Mode,
    },
    /// A new symlink: the same, applied to the link itself and never followed
    /// through to whatever it names.
    CreatedSymlink(GuestIds),
    /// A new *name* for an inode that already exists. A hard link creates no
    /// inode, so it changes no ownership: chowning here would re-own the file
    /// under every one of its names, including the ones the guest did not
    /// touch.
    Linked,
}

/// The guest identity a request was made under.
fn caller<M: voidport_proto::message::RequestBody>(request: &Request<'_, M>) -> GuestIds {
    GuestIds::new(request.head().uid.get(), request.head().gid.get())
}

/// The permission bits a create requests, with the caller's umask applied.
pub(super) fn permissions(mode: u32, umask: u32) -> Mode {
    Mode::from_bits_truncate(mode & !umask & 0o7777)
}

/// The host rename flags a wire request asks for.
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
        assert_eq!(permissions(0o777, 0o022), Mode::from_bits_truncate(0o755));
        assert_eq!(permissions(0o666, 0o077), Mode::from_bits_truncate(0o600));
        // Nothing outside the permission bits survives.
        assert_eq!(permissions(0o100_644, 0), Mode::from_bits_truncate(0o644));
    }

    #[test]
    fn only_fifos_and_sockets_are_creatable() {
        assert_eq!(special_kind(0o010_644), Ok(rustix::fs::FileType::Fifo));
        assert_eq!(special_kind(0o140_644), Ok(rustix::fs::FileType::Socket));
        // Device nodes are the required refusal, and so is everything else the
        // file-type bits can spell — a bare mode with no type included.
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
