use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Weak};
use std::time::Duration;

use rustix::fs::OFlags;
use rustix::io::Errno;
use voidport_control::HostDirectIo;
use voidport_proto::error::FramingError;
use voidport_proto::message::Request;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::file::{
    CreateRequest, CreateResponse, FileLock, FlushRequest, FlushResponse, FsyncRequest,
    FsyncResponse, GetlkRequest, GetlkResponse, OpenRequest, OpenResponse, ReleaseRequest,
    ReleaseResponse, SetlkRequest, SetlkResponse, fsync_flags, lock_type, open_flags,
    release_flags, setlk_flags,
};
use voidport_proto::ops::recall::{
    RecalledRequest, RecalledResponse, RelinquishRequest, RelinquishResponse,
};
use zerocopy::byteorder::little_endian::{U32, U64};

use super::node::entry_of;
use super::{Context, OpResult, Reply, name_of};
use crate::data::cache::{Grant, Pages, Unserved};
use crate::data::handle::{Backing, FileHandle, Handle};
use crate::data::locks::{FileLocks, Placed};
use crate::data::node::Node;
use crate::data::session::{Link, Session};
use crate::host::Io;
use crate::host::lock::{Conflict, LockKind, LockRange};
use crate::host::open::{IfExists, Opened, create_or_pin, reopen};
use crate::rules::GuestIds;

/// `O_CREAT`, `O_EXCL`, `O_NOFOLLOW`, `O_DIRECTORY` and `O_PATH` are dropped,
/// because the server has already resolved the node under containment.
///
/// `O_APPEND` survives: the host descriptor carrying the flag places the
/// appends of a guest at the true end of the file, so removing it would turn
/// concurrent appends from two mounts into silent overwrites.
fn open_flags(raw: u32, posture: HostDirectIo) -> OFlags {
    let requested = OFlags::from_bits_truncate(raw);
    let allowed = OFlags::RDONLY
        | OFlags::WRONLY
        | OFlags::RDWR
        | OFlags::APPEND
        | OFlags::TRUNC
        | OFlags::NONBLOCK
        | OFlags::DSYNC
        | OFlags::SYNC
        | OFlags::NOATIME;
    let direct = match posture {
        HostDirectIo::Cached => OFlags::empty(),
        HostDirectIo::Passthrough => requested & OFlags::DIRECT,
        HostDirectIo::Always => OFlags::DIRECT,
    };
    (requested & allowed) | direct
}

fn writes(flags: OFlags) -> bool {
    flags.contains(OFlags::WRONLY) || flags.contains(OFlags::RDWR) || flags.contains(OFlags::TRUNC)
}

/// Permission is checked exactly here, once: a graft downgraded to read-only
/// afterwards leaves this handle alone, as a local `chmod` leaves open
/// descriptors alone.
///
/// The open waits while the cache recalls the pages of a lease the open would
/// break, including a lease of its own session. Only a session that a recall
/// can contact is leased a file: one with a share subscription and an open
/// window.
pub fn open(context: &Context<'_>, request: Request<'_, OpenRequest>) -> Result<Reply, Unserved> {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    let namespace = session.namespace();
    let flags = open_flags(request.body().flags.get(), namespace.direct_io());
    // Enforcement is unconditional: an open for write through a read-only node
    // is `EROFS` whether that node is a file or a directory.
    if writes(flags) {
        node.require_writable()?;
    }
    if node.is_directory() {
        let listing = session.materialize(&node)?;
        let handle = session
            .handles()
            .insert(node.id, Handle::Directory(Arc::new(listing)));
        return Ok(context.reply(&OpenResponse {
            handle: U64::new(handle),
            flags: U32::ZERO,
            reserved: U32::ZERO,
        })?);
    }

    let pinned = node.descriptor(&namespace)?.ok_or(Errno::STALE)?;
    let file = handle(session, &node, &pinned, flags, None)?;
    let pages = reply_flags(file.grant());
    let handle = session
        .handles()
        .insert(node.id, Handle::File(Arc::new(file)));
    Ok(context.reply(&OpenResponse {
        handle: U64::new(handle),
        flags: U32::new(pages),
        reserved: U32::ZERO,
    })?)
}

/// The cache stores the path descriptor while a handle is open, which lets an
/// open file work through eviction: the budget bounds what the cache stores,
/// and the reference of a handle is separate.
pub(super) fn handle(
    session: &Session,
    node: &Node,
    pinned: &Arc<OwnedFd>,
    flags: OFlags,
    created: Option<OwnedFd>,
) -> Result<FileHandle, Unserved> {
    let locks = session.locks().join(node.identity().ok_or(Errno::STALE)?);
    let backing = match node.cache() {
        Some(cache) => Backing::Session(cache.open(pinned, flags, locks.locks(), created)?),
        None => Backing::Own(Io::reopen(pinned.as_fd(), flags)?),
    };
    Ok(FileHandle::new(backing, locks, flags))
}

fn reply_flags(grant: Option<&Grant>) -> u32 {
    match grant.map(Grant::pages) {
        Some(Pages::Kept) => open_flags::KEEP_CACHE,
        Some(Pages::Uncached) => open_flags::UNCACHED,
        Some(Pages::Taken) | None => 0,
    }
}

/// The new file is opened read-write whatever the guest asked for, which is the
/// description of it used by the session; the handle reads and writes only as
/// its flags allow.
pub fn create(
    context: &Context<'_>,
    request: Request<'_, CreateRequest>,
) -> Result<Reply, Unserved> {
    let session = context.session;
    let parent = session.node(request.head().node_id.get())?;
    let name = name_of(request.name())?;
    let site = session.site(&parent, &name)?;
    let body = request.body();

    let flags = open_flags(body.flags.get(), session.namespace().direct_io());
    let mode = super::dir::permissions(body.mode.get(), body.umask.get());
    let if_exists = if OFlags::from_bits_truncate(body.flags.get()).contains(OFlags::EXCL) {
        IfExists::Refuse
    } else {
        IfExists::Open
    };
    // Whether this call created the entry decides who owns it and what its mode
    // is. A create over something that already exists opens it as an open does,
    // without changing its ownership or mode.
    let Opened { pinned, created } = create_or_pin(
        site.directory.as_fd(),
        &site.name,
        super::dir::host_permissions(mode),
        if_exists,
    )?;
    if let Some(fd) = &created {
        let caller = GuestIds::new(request.head().uid.get(), request.head().gid.get());
        session.apply_create_ownership(fd.as_fd(), caller);
        apply_mode(fd.as_fd(), mode)?;
        // Before the entry reply is built, because that reply presents the
        // recorded bits.
        record_created_mode(session, fd.as_fd(), &site.recipe, mode)?;
    }

    // The node is built from the `O_PATH` descriptor returned by
    // `create_or_pin`, so a rename that puts another file at the name in the
    // meantime changes neither the reply nor the handle.
    let resolved = session.admit_created(&site, &parent, &name, pinned)?;
    let node_pin = resolved
        .node
        .descriptor(&session.namespace())?
        .ok_or(Errno::STALE)?;
    if created.is_none() && writes(flags) {
        resolved.node.require_writable()?;
    }
    let file = handle(session, &resolved.node, &node_pin, flags, created)?;
    let pages = reply_flags(file.grant());
    // The insert is a separate statement so the lock of the handle table is
    // released with it. Written inside the reply below, the lock would be held
    // for the whole reply expression, and holding the handle table across the
    // node table would give the request path a lock order against
    // `Session::summary`.
    let handle = session
        .handles()
        .insert(resolved.node.id, Handle::File(Arc::new(file)));
    Ok(context.reply(&CreateResponse {
        entry: entry_of(&resolved),
        handle: U64::new(handle),
        flags: U32::new(pages),
        reserved: U32::ZERO,
    })?)
}

pub fn file_of(session: &Session, handle: u64) -> Result<Arc<FileHandle>, Errno> {
    let file = session.handles().file(handle)?;
    if let Some(grant) = file.grant() {
        grant.used();
    }
    Ok(file)
}

/// Clear first, write second, which is the order a local filesystem uses. A
/// clear that cannot be carried out fails the write before a byte is written.
/// A handle that is not open for writing clears nothing: a local filesystem
/// refuses that write before it removes any privilege.
pub fn clear_privileged(
    session: &crate::data::session::Session,
    node_id: u64,
) -> Result<(), Errno> {
    let node = session.node(node_id)?;
    let namespace = session.namespace();
    let privileged = session.privileged(&namespace);
    session.strip_written(&namespace, &privileged, &node)
}

/// A reply to a recall that is closed already, or of a node the guest has
/// forgotten, is handled the same way: the cache of the node is what closes its
/// recalls.
pub fn recalled(context: &Context<'_>, request: Request<'_, RecalledRequest>) -> OpResult {
    let recall = request.body().recall.get();
    if let Ok(node) = context.session.node(request.head().node_id.get())
        && let Some(cache) = node.cache()
    {
        cache.recalled(recall);
    }
    context.reply(&RecalledResponse {
        reserved: U32::ZERO,
    })
}

pub fn relinquish(context: &Context<'_>, _request: Request<'_, RelinquishRequest>) -> OpResult {
    context.session.relinquish();
    context.reply(&RelinquishResponse {
        reserved: U32::ZERO,
    })
}

/// The lock set of the file outlives the handle while another handle on the
/// file is open, because a lock belongs to its holder for the whole file. Once
/// the last handle goes, every lock in the set is released.
pub fn release(context: &Context<'_>, request: Request<'_, ReleaseRequest>) -> OpResult {
    let body = request.body();
    let handle = body.handle.get();
    if body.release_flags.get() & release_flags::UNLOCK != 0
        && let Ok(file) = context.session.handles().file(handle)
    {
        file.locks().release_holder(body.lock_owner.get());
    }
    context.session.handles().remove(handle);
    context.reply(&ReleaseResponse {})
}

/// POSIX drops the record locks of a process when it closes any descriptor for
/// the file, and `flush` is where a client reports that. Nothing is synced
/// here.
pub fn flush(context: &Context<'_>, request: Request<'_, FlushRequest>) -> OpResult {
    let body = request.body();
    let file = context.session.handles().file(body.handle.get())?;
    file.locks().release_holder(body.lock_owner.get());
    context.reply(&FlushResponse {})
}

/// A directory handle syncs the host directory, as a local filesystem does: a
/// caller that syncs the directory after syncing a file asks for those entries
/// to be durable.
pub fn fsync(context: &Context<'_>, request: Request<'_, FsyncRequest>) -> Result<Reply, Unserved> {
    let body = request.body();
    let handle = body.handle.get();
    let datasync = body.flags.get() & fsync_flags::DATASYNC != 0;
    // Cloned out, so the handle table is not held across the sync.
    let found = context.session.handles().get(handle);
    match found {
        Some(Handle::File(file)) => sync(file.io()?.fd(), datasync)?,
        Some(Handle::Directory(_)) => sync_directory(context, handle, datasync)?,
        None => return Err(Errno::BADF.into()),
    }
    Ok(context.reply(&FsyncResponse {})?)
}

fn sync(fd: impl AsFd, datasync: bool) -> Result<(), Errno> {
    if datasync {
        rustix::fs::fdatasync(fd)?;
    } else {
        rustix::fs::fsync(fd)?;
    }
    Ok(())
}

/// The handle has a listing and no descriptor, and the cached `O_PATH`
/// descriptor of the node cannot be synced, so the directory is reopened for
/// the sync.
fn sync_directory(context: &Context<'_>, handle: u64, datasync: bool) -> Result<(), Errno> {
    let session = context.session;
    let node_id = session.handles().node_of(handle).ok_or(Errno::BADF)?;
    let node = session.node(node_id)?;
    let Some(pinned) = node.descriptor(&session.namespace())? else {
        return Ok(());
    };
    let directory = reopen(pinned.as_fd(), OFlags::RDONLY | OFlags::DIRECTORY)?;
    sync(&directory, datasync)
}

/// A query never creates a description. The other lock holders of the session
/// are checked first, then everybody else through the description the locks of
/// the session are on, so its own locks return unlocked as POSIX requires.
/// Without a lock on the file the description of the handle is checked, which
/// has no lock either, so a guest cannot make the server spend a host
/// descriptor per invented lock holder id.
pub fn getlk(context: &Context<'_>, request: Request<'_, GetlkRequest>) -> Result<Reply, Unserved> {
    let body = request.body();
    let file = context.session.handles().file(body.handle.get())?;
    let (kind, range) = lock_request(&body.lock)?;
    let conflict =
        file.locks()
            .test(body.lock.owner.get(), kind, range, file.io()?.description())?;
    Ok(context.reply(&GetlkResponse {
        lock: conflict_reply(&body.lock, conflict),
    })?)
}

#[derive(Debug)]
pub enum Locked {
    Answered(Reply),
    Waiting(LockWait),
}

/// The locks of the wire lock holders of the session are on one open file
/// description per file, because locks placed through one description coalesce
/// instead of conflicting. Every handle on the file places the locks of its
/// lock holder there, because a POSIX lock belongs to its process for the whole
/// file (see [`crate::data::locks`]). A lock of a kind the access of the handle
/// does not cover fails with `EBADF`. A lock waits while the requests of the
/// session on the file wait; a release never does.
///
/// The description exists only while a lock holder has a lock through it or a
/// blocking request waits.
///
/// A blocking request never blocks a thread: the host call is always the
/// non-blocking one, and a conflict on a request that asked to wait becomes a
/// [`LockWait`] the connection polls asynchronously.
pub fn setlk(
    context: &Context<'_>,
    request: Request<'_, SetlkRequest>,
) -> Result<Locked, Unserved> {
    let body = request.body();
    let file = context.session.handles().file(body.handle.get())?;
    let (kind, range) = lock_request(&body.lock)?;
    file.permits(kind)?;
    let holder = body.lock.owner.get();
    let wait = body.flags.get() & setlk_flags::WAIT != 0;
    let placed = match kind {
        LockKind::Unlock => file.locks().unlock(holder, range).map(|()| Placed::Done)?,
        LockKind::Read | LockKind::Write => {
            file.locks()
                .place(holder, kind, range, wait, file.io()?.description())?
        }
    };
    match placed {
        Placed::Done => Ok(Locked::Answered(context.reply(&SetlkResponse {})?)),
        Placed::Waiting => Ok(Locked::Waiting(LockWait {
            locks: Arc::downgrade(file.locks()),
            holder,
            kind,
            range,
            request_id: context.request_id,
            attempts: 0,
            settled: false,
        })),
    }
}

/// Small enough that a lock released immediately after a conflict is picked up
/// in about a millisecond.
const LOCK_RETRY_START: Duration = Duration::from_millis(1);

/// The acquisition latency a released lock pays in the worst case. It also
/// bounds the syscall rate of a storm at one `fcntl` per waiter per cap.
const LOCK_RETRY_CAP: Duration = Duration::from_millis(8);

/// A future and not a thread: `F_OFD_SETLKW` sleeps in one syscall for as long
/// as the holder holds, which costs one thread of the shared blocking pool per
/// waiter, and a few hundred stacked waiters would starve every other
/// operation on the server.
///
/// Fairness is best-effort: when a holder releases, whichever waiter wakes
/// first takes the range, and the sleeps are jittered so a storm does not
/// converge on one instant. POSIX guarantees no order for `F_SETLKW` either.
#[derive(Debug)]
pub struct LockWait {
    /// Weak, because the set lives as long as the handles of the session on the
    /// file: a wait does not preserve its locks.
    locks: Weak<FileLocks>,
    holder: u64,
    kind: LockKind,
    range: LockRange,
    request_id: u64,
    attempts: u32,
    /// Tells the drop glue a cancelled wait from a finished one.
    settled: bool,
}

impl LockWait {
    /// Every attempt is made through `link`, so the grant and the close of the
    /// connection come in one order: a close recorded first ends the wait with
    /// `None` and the lock is never taken, and a grant made first runs to its
    /// end.
    ///
    /// Dropping the returned future cancels the wait: the connection is gone, so
    /// nothing is answered. A close of another descriptor of the lock holder
    /// releases its locks and leaves this wait waiting, as it does locally. The
    /// close of the last handle of the session on the file ends it with `EBADF`.
    pub async fn settle(mut self, link: &Link) -> Option<Result<Vec<u8>, FramingError>> {
        loop {
            tokio::time::sleep(self.backoff()).await;
            let attempt = link.unless_closed(|| self.retry())?;
            match attempt {
                Ok(true) => {
                    self.settled = true;
                    return Some(self.encode(Ok(())));
                }
                Ok(false) => {}
                Err(error) => {
                    self.settled = true;
                    self.abandon();
                    return Some(self.encode(Err(error)));
                }
            }
        }
    }

    /// Exponential from [`LOCK_RETRY_START`] to [`LOCK_RETRY_CAP`], jittered down
    /// by up to a quarter. A thousand waiters that all conflicted at the same
    /// instant would otherwise wake at the same instant forever, and every wake
    /// but one is a wasted syscall.
    fn backoff(&mut self) -> Duration {
        let step = LOCK_RETRY_START
            .saturating_mul(1u32 << self.attempts.min(16))
            .min(LOCK_RETRY_CAP);
        self.attempts = self.attempts.saturating_add(1);
        let nanos = u64::from(step.subsec_nanos()) + step.as_secs() * 1_000_000_000;
        Duration::from_nanos(nanos - nanos / 4 * self.jitter() / 255)
    }

    /// Seeded from the request id and the holder, so two waiters of one storm
    /// diverge without a random-number generator.
    fn jitter(&self) -> u64 {
        let mut state = self
            .request_id
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(self.holder)
            .wrapping_add(u64::from(self.attempts))
            | 1;
        state ^= state >> 33;
        state = state.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        state ^= state >> 29;
        state & 0xFF
    }

    fn encode(&self, outcome: Result<(), Errno>) -> Result<Vec<u8>, FramingError> {
        super::encode_outcome(
            self.request_id,
            Opcode::Setlk,
            outcome.map(|()| SetlkResponse {}),
        )
    }
}

impl LockWait {
    /// A set gone with the last handle of the session on the file returns
    /// `EBADF`, as a waiting lock whose descriptor was closed does.
    fn retry(&self) -> Result<bool, Errno> {
        self.locks
            .upgrade()
            .ok_or(Errno::BADF)?
            .retry(self.holder, self.kind, self.range)
    }

    fn abandon(&self) {
        if let Some(locks) = self.locks.upgrade() {
            locks.abandon(self.holder);
        }
    }
}

impl Drop for LockWait {
    /// The connection died while this request was parked, which ends the wait
    /// with no reply.
    fn drop(&mut self) {
        if !self.settled {
            self.abandon();
        }
    }
}

/// The umask of the caller is the one that applies, and the server has already
/// subtracted it. The server process has a umask of its own, which the kernel
/// would apply on top, so the mode of the created entry is set explicitly
/// afterwards.
pub(super) fn apply_mode(fd: std::os::fd::BorrowedFd<'_>, mode: u32) -> Result<(), Errno> {
    rustix::fs::chmodat(
        rustix::fs::CWD,
        crate::host::open::proc_path(fd).as_str(),
        super::dir::host_permissions(mode),
        rustix::fs::AtFlags::empty(),
    )
}

/// Run before the entry reply is built, so the reply presents the mode the guest
/// asked for. A create that delivered no privileged bits records nothing: the
/// entry is a fresh inode, so there is no record for an absent bit to delete.
///
/// `recipe` comes from the site, never its backing: a create under a directory
/// the server itself renamed ends up where the host has that directory now, and
/// a locator spelled from the older description of the namespace would name
/// nothing for the revalidating stat of a restart to find.
pub(super) fn record_created_mode(
    session: &crate::data::session::Session,
    fd: std::os::fd::BorrowedFd<'_>,
    recipe: &crate::rules::HostBacking,
    delivered: u32,
) -> Result<(), Errno> {
    if crate::records::PrivilegedBits::of(delivered).is_empty() {
        return Ok(());
    }
    let namespace = session.namespace();
    let privileged = session.privileged(&namespace);
    let identity = crate::host::attr::HostAttr::of(fd)?.node_identity();
    session.record_delivered_mode(&privileged, identity, recipe, delivered);
    Ok(())
}

fn lock_request(lock: &FileLock) -> Result<(LockKind, LockRange), Errno> {
    let kind = match lock.lock_type.get() {
        lock_type::READ => LockKind::Read,
        lock_type::WRITE => LockKind::Write,
        lock_type::UNLOCK => LockKind::Unlock,
        _ => return Err(Errno::INVAL),
    };
    Ok((kind, LockRange::new(lock.start.get(), lock.end.get())))
}

fn conflict_reply(request: &FileLock, conflict: Option<Conflict>) -> FileLock {
    let Some(conflict) = conflict else {
        return FileLock {
            start: request.start,
            end: request.end,
            owner: request.owner,
            pid: request.pid,
            lock_type: U32::new(lock_type::UNLOCK),
        };
    };
    FileLock {
        start: U64::new(conflict.range.start),
        end: U64::new(conflict.range.end),
        owner: request.owner,
        // An OFD lock belongs to no process, and the kernel reports that with -1.
        pid: U32::new(conflict.pid as u32),
        lock_type: U32::new(match conflict.kind {
            LockKind::Read => lock_type::READ,
            LockKind::Write => lock_type::WRITE,
            LockKind::Unlock => lock_type::UNLOCK,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::Mode;

    fn cached_flags(raw: u32) -> OFlags {
        open_flags(raw, HostDirectIo::Cached)
    }

    #[test]
    fn resolution_flags_never_survive_a_reopen() {
        let raw = OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::DIRECTORY
            | OFlags::APPEND;
        let flags = cached_flags(raw.bits());
        assert!(flags.contains(OFlags::RDWR));
        assert!(flags.contains(OFlags::APPEND));
        assert!(!flags.contains(OFlags::CREATE));
        assert!(!flags.contains(OFlags::EXCL));
        assert!(!flags.contains(OFlags::DIRECTORY));
    }

    /// `O_APPEND` is not a resolution flag, and dropping it would cost the
    /// atomic-append guarantee, so it is asserted on its own.
    #[test]
    fn an_append_open_keeps_its_flag() {
        for access in [OFlags::WRONLY, OFlags::RDWR] {
            let flags = cached_flags((access | OFlags::APPEND).bits());
            assert!(flags.contains(OFlags::APPEND), "{access:?}");
            assert!(writes(flags), "an appending open is an open for write");
        }
        assert!(!cached_flags(OFlags::WRONLY.bits()).contains(OFlags::APPEND));
    }

    #[test]
    fn the_posture_decides_whether_the_backing_open_is_uncached() {
        let asked = (OFlags::RDWR | OFlags::DIRECT).bits();
        let plain = OFlags::RDWR.bits();

        assert!(!open_flags(asked, HostDirectIo::Cached).contains(OFlags::DIRECT));
        assert!(!open_flags(plain, HostDirectIo::Cached).contains(OFlags::DIRECT));

        assert!(open_flags(asked, HostDirectIo::Passthrough).contains(OFlags::DIRECT));
        assert!(!open_flags(plain, HostDirectIo::Passthrough).contains(OFlags::DIRECT));

        assert!(open_flags(asked, HostDirectIo::Always).contains(OFlags::DIRECT));
        assert!(open_flags(plain, HostDirectIo::Always).contains(OFlags::DIRECT));

        for posture in [
            HostDirectIo::Cached,
            HostDirectIo::Passthrough,
            HostDirectIo::Always,
        ] {
            let flags = open_flags((OFlags::RDWR | OFlags::APPEND).bits(), posture);
            assert!(flags.contains(OFlags::APPEND), "{posture}");
            assert_eq!(flags - OFlags::DIRECT, OFlags::RDWR | OFlags::APPEND);
        }
    }

    /// Linux departs from POSIX: `pwrite(2)` on a description opened `O_APPEND`
    /// ignores its offset and appends. The write path depends on it for every
    /// appending handle, so it is asserted against a real file.
    #[test]
    fn a_pwrite_through_an_appending_description_appends() {
        let scratch = voidport_test_host::Scratch::new("append");
        let path = scratch.file("log", b"0123456789");
        let fd = rustix::fs::open(
            &path,
            cached_flags((OFlags::WRONLY | OFlags::APPEND).bits()),
            Mode::empty(),
        )
        .expect("the file opens for appending");

        assert_eq!(rustix::io::pwrite(&fd, b"AB", 0).expect("writable"), 2);
        assert_eq!(rustix::io::pwrite(&fd, b"CD", 4).expect("writable"), 2);
        drop(fd);

        assert_eq!(
            std::fs::read(&path).expect("readable"),
            b"0123456789ABCD",
            "a pwrite through an appending description did not append"
        );
    }

    #[test]
    fn write_access_is_recognized_in_every_spelling() {
        assert!(writes(cached_flags(OFlags::WRONLY.bits())));
        assert!(writes(cached_flags(OFlags::RDWR.bits())));
        assert!(writes(cached_flags(
            (OFlags::RDONLY | OFlags::TRUNC).bits()
        )));
        assert!(!writes(cached_flags(OFlags::RDONLY.bits())));
    }

    #[test]
    fn a_free_range_is_reported_as_unlocked() {
        let request = FileLock {
            start: U64::new(4),
            end: U64::new(9),
            owner: U64::new(7),
            pid: U32::new(11),
            lock_type: U32::new(lock_type::WRITE),
        };
        let free = conflict_reply(&request, None);
        assert_eq!(free.lock_type.get(), lock_type::UNLOCK);
        assert_eq!(free.start.get(), 4);

        let held = conflict_reply(
            &request,
            Some(Conflict {
                kind: LockKind::Read,
                range: LockRange::new(0, 3),
                pid: -1,
            }),
        );
        assert_eq!(held.lock_type.get(), lock_type::READ);
        assert_eq!((held.start.get(), held.end.get()), (0, 3));
        assert_eq!(held.pid.get() as i32, -1);
    }

    #[test]
    fn a_lock_type_the_wire_does_not_define_is_invalid() {
        let lock = FileLock {
            start: U64::ZERO,
            end: U64::new(u64::MAX),
            owner: U64::ZERO,
            pid: U32::ZERO,
            lock_type: U32::new(99),
        };
        assert_eq!(lock_request(&lock).expect_err("unknown type"), Errno::INVAL);
    }
}
