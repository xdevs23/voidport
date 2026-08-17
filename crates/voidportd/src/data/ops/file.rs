//! File operations: open, create, read, write, release, sync, locking.

use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use voidport_proto::error::FramingError;
use voidport_proto::frame::FrameWriter;
use voidport_proto::message::Request;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::file::{
    CreateRequest, CreateResponse, FileLock, FlushRequest, FlushResponse, FsyncRequest,
    FsyncResponse, GetlkRequest, GetlkResponse, OpenRequest, OpenResponse, ReadRequest,
    ReadResponse, ReleaseRequest, ReleaseResponse, SetlkRequest, SetlkResponse, WriteRequest,
    WriteResponse, fsync_flags, lock_type, release_flags, setlk_flags,
};
use zerocopy::byteorder::little_endian::{U32, U64};

use super::node::entry_of;
use super::{Context, OpResult, fixed_len, name_of};
use crate::data::handle::{FileHandle, Handle};
use crate::host::lock::{Conflict, LockKind, LockRange};
use crate::host::open::{create_child, pin_child, reopen};
use crate::rules::GuestIds;

/// The open flags the server honours on a reopen.
///
/// Everything about *name resolution* is the server's business, not the
/// client's: `O_CREAT`, `O_EXCL`, `O_NOFOLLOW`, `O_DIRECTORY` and `O_PATH` are
/// dropped, because the node has already been resolved under containment and
/// the reopen must not re-decide any of it.
///
/// What survives is everything that describes *how this description behaves*,
/// and `O_APPEND` is the one that carries a guarantee: it is the whole of
/// voidport's atomic append. See [`write`] — the host descriptor carrying the
/// flag is what places a guest's appends at the true end of the file, so
/// removing `O_APPEND` from this set would not merely lose a flag, it would
/// turn concurrent appends from two mounts into silent overwrites.
fn open_flags(raw: u32) -> OFlags {
    let requested = OFlags::from_bits_truncate(raw);
    let allowed = OFlags::RDONLY
        | OFlags::WRONLY
        | OFlags::RDWR
        | OFlags::APPEND
        | OFlags::TRUNC
        | OFlags::NONBLOCK
        | OFlags::DSYNC
        | OFlags::SYNC
        | OFlags::NOATIME
        | OFlags::DIRECT;
    requested & allowed
}

/// Whether an open asks for write access.
fn writes(flags: OFlags) -> bool {
    flags.contains(OFlags::WRONLY) || flags.contains(OFlags::RDWR) || flags.contains(OFlags::TRUNC)
}

/// Opens a node.
///
/// A directory open materializes the merged, policy-filtered listing that
/// readdirplus then walks; a file open reopens the pinned descriptor for real
/// I/O. Permission is checked exactly here, once: a graft downgraded to
/// read-only afterwards leaves this handle alone, precisely as a local `chmod`
/// leaves open descriptors alone.
pub fn open(context: &Context<'_>, request: Request<'_, OpenRequest>) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    let flags = open_flags(request.body().flags.get());
    // Enforcement is unconditional, so it happens before the open decides
    // anything else: an open for write through a read-only node is `EROFS`
    // whether that node is a file or a directory.
    if writes(flags) {
        node.require_writable()?;
    }
    if node.is_directory() {
        let listing = session.materialize(&node)?;
        let handle = session
            .handles()
            .insert(node.id, Handle::Directory(Arc::new(listing)))?;
        return context.reply(&OpenResponse {
            handle: U64::new(handle),
            flags: U32::ZERO,
            reserved: U32::ZERO,
        });
    }

    // The handle takes the node's pin with it, which is what keeps an open
    // file working through eviction: the budget bounds what the *cache* holds,
    // and a handle's own reference is its own.
    let pinned = node.descriptor(&session.namespace())?.ok_or(Errno::STALE)?;
    let fd = reopen(pinned.as_fd(), flags)?;
    let handle = session.handles().insert(
        node.id,
        Handle::File(Arc::new(FileHandle::new(fd, pinned, writes(flags)))),
    )?;
    context.reply(&OpenResponse {
        handle: U64::new(handle),
        flags: U32::ZERO,
        reserved: U32::ZERO,
    })
}

/// Creates a file and opens it in one round trip.
pub fn create(context: &Context<'_>, request: Request<'_, CreateRequest>) -> OpResult {
    let session = context.session;
    let parent = session.node(request.head().node_id.get())?;
    let name = name_of(request.name())?;
    let site = session.site(&parent, &name)?;
    let body = request.body();

    let flags = open_flags(body.flags.get());
    let mode = super::dir::permissions(body.mode.get(), body.umask.get());
    let exclusive = OFlags::from_bits_truncate(body.flags.get()).contains(OFlags::EXCL);
    let open = |flags, mode| create_child(site.directory.as_fd(), &site.name, flags, mode);
    // Whether this call *created* the entry decides two things — whose the
    // entry is, and what its mode is — so the exclusive attempt comes first and
    // the plain open is the fallback. A create over something that already
    // exists must not re-own it or re-mode it. The fallback passes no mode at
    // all: `openat2` — unlike `openat` — refuses a nonzero mode on an open that
    // cannot create.
    let (fd, created) = match open(flags | OFlags::CREATE | OFlags::EXCL, mode) {
        Ok(fd) => (fd, true),
        Err(Errno::EXIST) if !exclusive => (open(flags, Mode::empty())?, false),
        Err(error) => return Err(error),
    };

    if created {
        let caller = GuestIds::new(request.head().uid.get(), request.head().gid.get());
        session.apply_create_ownership(fd.as_fd(), caller);
        apply_mode(fd.as_fd(), mode)?;
    }

    // The entry becomes a node pinned from the site it was created at — not
    // looked up again through the namespace — so a concurrent replacement of
    // the name cannot make the reply describe a different inode. The handle
    // then borrows the *node's* pin, which is what its per-owner lock
    // descriptions are reopened from.
    let pinned = pin_child(site.directory.as_fd(), &site.name)?;
    let resolved = session.admit_pinned(
        parent.path.child(&name),
        pinned,
        site.recipe.clone(),
        site.backing.clone(),
        site.mode,
    )?;
    let node_pin = resolved
        .node
        .descriptor(&session.namespace())?
        .ok_or(Errno::STALE)?;
    // The insert is its own statement so its guard is gone before the error arm
    // touches the node table: a guard produced in a `match` scrutinee outlives
    // the arms, and holding the handle table across the node table here would
    // give the request path a lock order that `Session::summary` — which reads
    // both counts for the operator — could deadlock against.
    let inserted = session.handles().insert(
        resolved.node.id,
        Handle::File(Arc::new(FileHandle::new(fd, node_pin, true))),
    );
    let handle = match inserted {
        Ok(handle) => handle,
        Err(error) => {
            // No entry reply leaves, so the client never learns the node id
            // this request interned and could never `forget` it. The lookup it
            // counted is released here instead, which is what lets a client
            // that hit the handle cap close a handle and retry. The created
            // host entry stays: it is the file the guest asked for, and
            // unlinking a name that may already have been replaced would
            // destroy data this request did not make.
            session.nodes().forget(resolved.node.id, 1);
            return Err(error);
        }
    };
    context.reply(&CreateResponse {
        entry: entry_of(&resolved),
        handle: U64::new(handle),
        flags: U32::ZERO,
        reserved: U32::ZERO,
    })
}

/// Reads file data.
///
/// The data lands **straight in the frame buffer**: the payload region is read
/// into before the header is written over the bytes in front of it, so a read
/// costs one copy from the kernel and none after. This is the zero-copy hot
/// path the wire format exists for.
pub fn read(context: &Context<'_>, request: Request<'_, ReadRequest>) -> OpResult {
    let body = request.body();
    let file = context.session.handles().file(body.handle.get())?;
    let size = context
        .payload_budget::<ReadResponse>()
        .min(body.size.get() as usize);

    let fixed = fixed_len::<ReadResponse>();
    let mut buffer = vec![0u8; fixed + size];
    let read = rustix::io::pread(file.fd(), &mut buffer[fixed..], body.offset.get())?;

    let response = ReadResponse {
        data_len: U32::new(u32::try_from(read).map_err(|_| Errno::OVERFLOW)?),
    };
    let length = {
        let mut writer = FrameWriter::response(
            &mut buffer,
            context.max_frame_len,
            context.request_id,
            &response,
        )
        .map_err(|_| Errno::OVERFLOW)?;
        // The payload is already in place; claiming it only tells the writer
        // the frame is complete.
        writer.payload_buf(read).map_err(|_| Errno::OVERFLOW)?;
        writer.finish().map_err(|_| Errno::OVERFLOW)?.len()
    };
    buffer.truncate(length);
    Ok(buffer)
}

/// Writes file data.
///
/// Enforcement happened at open: a handle opened read-only cannot be written,
/// and the kernel says so on its own description.
///
/// # Appending is the host's decision, not the offset's
///
/// The offset in the request is the *guest kernel's*, and on an appending
/// handle it is a guess: `generic_write_checks` moves the position to the inode
/// size the guest has cached before FUSE is called at all, and with a second
/// mount writing the same file that size is stale by construction — nothing
/// tells one guest kernel that another client extended the file. A server that
/// placed the bytes at that offset would let two appending clients overwrite
/// each other, which is precisely what a size-caching network filesystem does.
///
/// This one never places them there. The guest's `O_APPEND` rode the wire open
/// into the host open ([`open_flags`]), and Linux's `pwrite(2)` on a
/// description carrying `O_APPEND` ignores the offset and appends under the
/// inode lock — its documented departure from POSIX, which the test below pins
/// instead of trusting it. The position is therefore chosen by the host kernel,
/// atomically with the write, for every client at once: the guarantee two local
/// processes already have.
///
/// The reply stays coherent for the guest kernel even though the data can land
/// somewhere it did not name, and that needs spelling out. A write
/// reply carries a *count*, never a position, and FUSE requires only that the
/// count not exceed what was sent. The mount negotiates no writeback cache and
/// is writethrough, so no dirty pages are being held whose position the kernel
/// must later reconcile: it takes the count, advances its own file position,
/// and updates its cached size, which the next attribute revalidation corrects
/// from the host. An appending guest may briefly believe the file is shorter
/// than it is — a cache being behind, which every attribute timeout already
/// allows, and not data placed wrongly.
///
/// One bound is inherited and cannot be fixed here: atomicity is per write
/// *request*, and a single guest write larger than the negotiated `max_write`
/// is split by the guest kernel into several, which another client's appends
/// may land between. A record written in one write of at most that size is
/// never torn.
pub fn write(context: &Context<'_>, request: Request<'_, WriteRequest>) -> OpResult {
    let body = request.body();
    let file = context.session.handles().file(body.handle.get())?;
    let written = rustix::io::pwrite(file.fd(), request.data(), body.offset.get())?;
    context.reply(&WriteResponse {
        written: U32::new(u32::try_from(written).map_err(|_| Errno::OVERFLOW)?),
    })
}

/// Releases a handle, closing the host descriptor it held.
///
/// Dropping the handle drops every per-owner lock description with it, so the
/// locks a session held through this handle are gone whether or not the client
/// asked for the unlock.
pub fn release(context: &Context<'_>, request: Request<'_, ReleaseRequest>) -> OpResult {
    let body = request.body();
    let handle = body.handle.get();
    if body.release_flags.get() & release_flags::UNLOCK != 0
        && let Ok(file) = context.session.handles().file(handle)
    {
        file.release_owner(body.lock_owner.get());
    }
    context.session.handles().remove(handle);
    context.reply(&ReleaseResponse {})
}

/// Flushes one guest descriptor's close.
///
/// POSIX drops a process's record locks when it closes *any* descriptor for the
/// file, and `flush` is where a client reports that; the owner's description
/// goes with it. Nothing is synced here — `fsync` is the operation that means
/// durability.
pub fn flush(context: &Context<'_>, request: Request<'_, FlushRequest>) -> OpResult {
    let body = request.body();
    let file = context.session.handles().file(body.handle.get())?;
    file.release_owner(body.lock_owner.get());
    context.reply(&FlushResponse {})
}

/// Flushes a handle to stable storage.
///
/// A directory handle has nothing to sync: its listing is a server-side
/// snapshot, and the host directory it came from was never modified through it.
pub fn fsync(context: &Context<'_>, request: Request<'_, FsyncRequest>) -> OpResult {
    let body = request.body();
    match context.session.handles().get(body.handle.get()) {
        Some(Handle::File(file)) => {
            if body.flags.get() & fsync_flags::DATASYNC != 0 {
                rustix::fs::fdatasync(file.fd())?;
            } else {
                rustix::fs::fsync(file.fd())?;
            }
        }
        Some(Handle::Directory(_)) => {}
        None => return Err(Errno::BADF),
    }
    context.reply(&FsyncResponse {})
}

/// Tests whether a lock could be placed.
///
/// A query never *creates* a description. An owner that already holds one is
/// asked through it, so its own locks answer "unlocked" as POSIX says they
/// must; an owner that holds none is asked through the handle's own descriptor,
/// which is a distinct description that by construction carries no locks — so
/// the answer is identical, and a guest cannot make the server spend a host
/// descriptor per invented owner id.
pub fn getlk(context: &Context<'_>, request: Request<'_, GetlkRequest>) -> OpResult {
    let body = request.body();
    let file = context.session.handles().file(body.handle.get())?;
    let (kind, range) = lock_request(&body.lock)?;
    let held = file.description(body.lock.owner.get());
    let description = held.as_ref().map_or_else(|| file.fd(), |held| held.as_fd());
    let conflict = crate::host::lock::test(description, kind, range)?;
    context.reply(&GetlkResponse {
        lock: conflict_reply(&body.lock, conflict),
    })
}

/// What placing a lock produced: an answer, or a wait the connection drives.
#[derive(Debug)]
pub enum Locked {
    /// The lock was placed or released; here is the encoded reply.
    Answered(Vec<u8>),
    /// The range is held by someone else and the guest asked to wait. The wire
    /// request stays pending until [`LockWait`] settles it.
    Waiting(LockWait),
}

/// Places or releases a lock.
///
/// Each wire owner gets its own open file description, because locks held
/// through one description coalesce instead of conflicting. Releasing the whole
/// file drops the description itself, which is what makes an owner's unlock
/// release exactly that owner's locks.
///
/// A description exists only while its owner may hold a lock through it: an
/// unlock from an owner that has none is answered without opening anything, and
/// a description whose first lock the host refused is dropped again.
///
/// **A blocking request never blocks a thread.** The host call is always the
/// non-blocking one; a conflict on a request that asked to wait becomes a
/// [`LockWait`] the connection polls asynchronously, and the guest sees only
/// what it always saw — no reply until the lock is its own.
pub fn setlk(context: &Context<'_>, request: Request<'_, SetlkRequest>) -> Result<Locked, Errno> {
    let body = request.body();
    let file = context.session.handles().file(body.handle.get())?;
    let (kind, range) = lock_request(&body.lock)?;
    let owner = body.lock.owner.get();
    let held = file.description(owner);
    if held.is_none() && kind == LockKind::Unlock {
        // Nothing is held through this handle by this owner, so there is
        // nothing to release — and releasing nothing must not cost a
        // descriptor.
        return context.reply(&SetlkResponse {}).map(Locked::Answered);
    }
    let fresh = held.is_none();
    let description = match held {
        Some(description) => description,
        None => file.lock_description(owner)?,
    };
    let placement = Placement {
        file,
        description,
        owner,
        kind,
        range,
        fresh,
    };
    match crate::host::lock::set(placement.description.as_fd(), kind, range) {
        Ok(()) => {
            placement.settled();
            context.reply(&SetlkResponse {}).map(Locked::Answered)
        }
        Err(error)
            if crate::host::lock::is_conflict(error)
                && body.flags.get() & setlk_flags::WAIT != 0 =>
        {
            Ok(Locked::Waiting(LockWait {
                placement,
                request_id: context.request_id,
                max_frame_len: context.max_frame_len,
                attempts: 0,
                settled: false,
            }))
        }
        Err(error) => {
            placement.refused();
            Err(error)
        }
    }
}

/// One owner's pending lock placement on one handle.
///
/// It owns the two things the placement outlives its request by: the handle
/// (whose owner map files the description) and the description itself, whose
/// descriptor must stay open for as long as anything may still lock through it.
#[derive(Debug)]
struct Placement {
    file: Arc<FileHandle>,
    description: Arc<OwnedFd>,
    owner: u64,
    kind: LockKind,
    range: LockRange,
    /// Whether this request is what opened the description, and therefore what
    /// must drop it again if the lock never lands.
    fresh: bool,
}

impl Placement {
    /// The host took the lock: the description stays filed, and a whole-file
    /// unlock retires the owner along with it. The descriptor closes when this
    /// placement drops, which is at the end of the request either way.
    fn settled(&self) {
        if self.kind == LockKind::Unlock && self.range == LockRange::whole_file() {
            self.file.release_owner(self.owner);
        }
    }

    /// The lock will never land — refused, or the waiter was cancelled — so a
    /// description this request opened costs nothing.
    fn refused(&self) {
        if self.fresh {
            self.file.discard_unused(self.owner, &self.description);
        }
    }
}

/// How long the first retry of a stacked lock waiter sleeps.
///
/// Small enough that a lock released immediately after a conflict is picked up
/// in about a millisecond, which is under the round trip that carried the
/// request in.
const LOCK_RETRY_START: Duration = Duration::from_millis(1);

/// The longest a waiter sleeps between attempts.
///
/// This is the acquisition latency a released lock pays in the worst case, and
/// the design asks for it to stay unobtrusive; it is also what bounds the
/// syscall rate of a storm, at one `fcntl` per waiter per cap.
const LOCK_RETRY_CAP: Duration = Duration::from_millis(8);

/// A guest's blocking lock request, waiting for the range to come free.
///
/// # Why this is a future and not a thread
///
/// `F_OFD_SETLKW` would express the wait in one syscall, and that syscall
/// sleeps: it costs one thread of the blocking pool for as long as the holder
/// holds. The pool is shared by every session's host I/O and is not large, so a
/// few hundred stacked waiters — one file locked by a build across a dozen
/// mounts is enough — would starve every other operation on the server. The
/// design rules waits async for exactly this: a parked future costs bytes, and
/// a million of them are affordable.
///
/// # Fairness
///
/// Best-effort, and deliberately so. Retry order is not a queue: when a holder
/// releases, whichever waiter wakes first takes the range, and the sleeps are
/// jittered so a storm does not converge on one instant. POSIX guarantees no
/// order for `F_SETLKW` either, so nothing a guest may rely on is lost — but a
/// waiter can be overtaken, and under a sustained storm one may wait
/// noticeably longer than its neighbours.
#[derive(Debug)]
pub struct LockWait {
    placement: Placement,
    request_id: u64,
    max_frame_len: u32,
    /// How many attempts have been made, which is what the backoff grows on.
    attempts: u32,
    /// Whether the placement has been resolved, which is what tells the drop
    /// glue a cancelled wait from a finished one.
    settled: bool,
}

impl LockWait {
    /// Waits until the lock is this owner's, and answers the request.
    ///
    /// Dropping the returned future is the cancellation the contract rules: the
    /// connection is gone, so nothing is answered and a description this
    /// request opened is dropped again.
    pub async fn settle(mut self) -> Result<Vec<u8>, FramingError> {
        loop {
            tokio::time::sleep(self.backoff()).await;
            match crate::host::lock::set(
                self.placement.description.as_fd(),
                self.placement.kind,
                self.placement.range,
            ) {
                Ok(()) => {
                    self.settled = true;
                    self.placement.settled();
                    return self.encode(Ok(()));
                }
                Err(error) if crate::host::lock::is_conflict(error) => {}
                Err(error) => {
                    self.settled = true;
                    self.placement.refused();
                    return self.encode(Err(error));
                }
            }
        }
    }

    /// How long to sleep before the next attempt.
    ///
    /// Exponential from [`LOCK_RETRY_START`] to [`LOCK_RETRY_CAP`], jittered
    /// down by up to a quarter. The jitter is what keeps a storm from
    /// converging: a thousand waiters that all conflicted at the same instant
    /// would otherwise wake at the same instant forever, and every wake but one
    /// is a wasted syscall.
    fn backoff(&mut self) -> Duration {
        let step = LOCK_RETRY_START
            .saturating_mul(1u32 << self.attempts.min(16))
            .min(LOCK_RETRY_CAP);
        self.attempts = self.attempts.saturating_add(1);
        let nanos = u64::from(step.subsec_nanos()) + step.as_secs() * 1_000_000_000;
        Duration::from_nanos(nanos - nanos / 4 * self.jitter() / 255)
    }

    /// A cheap per-waiter pseudorandom byte.
    ///
    /// Seeded from the request id and the owner, so two waiters of one storm
    /// diverge without the server holding a random-number generator.
    fn jitter(&self) -> u64 {
        let mut state = self
            .request_id
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(self.placement.owner)
            .wrapping_add(u64::from(self.attempts))
            | 1;
        state ^= state >> 33;
        state = state.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        state ^= state >> 29;
        state & 0xFF
    }

    /// The reply frame this request ends with.
    fn encode(&self, outcome: Result<(), Errno>) -> Result<Vec<u8>, FramingError> {
        super::encode_outcome(
            self.max_frame_len,
            self.request_id,
            Opcode::Setlk,
            outcome.map(|()| SetlkResponse {}),
        )
    }
}

impl Drop for LockWait {
    /// The connection died while this request was parked. The contract makes
    /// that the end of the wait — nothing is answered — and the description it
    /// was about to lock through is dropped if this request is what opened it.
    fn drop(&mut self) {
        if !self.settled {
            self.placement.refused();
        }
    }
}

/// Applies the exact permission bits a create asked for.
///
/// The design makes the *caller's* umask the one that applies, and the server
/// has already subtracted it. The server process has a umask of its own, which
/// the kernel would apply on top and which has nothing to do with the guest, so
/// the created entry's mode is set explicitly afterwards.
///
/// # Errors
///
/// Returns the host errno of the mode change.
pub(super) fn apply_mode(fd: std::os::fd::BorrowedFd<'_>, mode: Mode) -> Result<(), Errno> {
    rustix::fs::chmodat(
        rustix::fs::CWD,
        crate::host::open::proc_path(fd).as_str(),
        mode,
        rustix::fs::AtFlags::empty(),
    )
}

/// The kind and range a wire lock describes.
fn lock_request(lock: &FileLock) -> Result<(LockKind, LockRange), Errno> {
    let kind = match lock.lock_type.get() {
        lock_type::READ => LockKind::Read,
        lock_type::WRITE => LockKind::Write,
        lock_type::UNLOCK => LockKind::Unlock,
        _ => return Err(Errno::INVAL),
    };
    Ok((kind, LockRange::new(lock.start.get(), lock.end.get())))
}

/// The lock a `getlk` answers with: the conflict, or the request marked
/// unlocked.
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
        // An OFD lock has no owning process, and the kernel says so with -1.
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

    #[test]
    fn resolution_flags_never_survive_a_reopen() {
        let raw = OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::DIRECTORY
            | OFlags::APPEND;
        let flags = open_flags(raw.bits());
        assert!(flags.contains(OFlags::RDWR));
        assert!(flags.contains(OFlags::APPEND));
        assert!(!flags.contains(OFlags::CREATE));
        assert!(!flags.contains(OFlags::EXCL));
        assert!(!flags.contains(OFlags::DIRECTORY));
    }

    /// `O_APPEND` is not a resolution flag, and dropping it would cost the
    /// atomic-append guarantee, not a convenience — so it is asserted on
    /// its own, in both spellings a guest can ask for it.
    #[test]
    fn an_append_open_keeps_its_flag() {
        for access in [OFlags::WRONLY, OFlags::RDWR] {
            let flags = open_flags((access | OFlags::APPEND).bits());
            assert!(flags.contains(OFlags::APPEND), "{access:?}");
            assert!(writes(flags), "an appending open is an open for write");
        }
        assert!(!open_flags(OFlags::WRONLY.bits()).contains(OFlags::APPEND));
    }

    /// The host behaviour the whole append story rests on.
    ///
    /// Linux departs from POSIX here — `pwrite(2)` on a description opened
    /// `O_APPEND` ignores its offset and appends — and [`write`] depends on it
    /// on every write of every appending handle. Depending on it silently would
    /// mean discovering a change to it as data loss, so it is asserted against
    /// a real file: an offset that would land inside the file lands at the end
    /// instead, and the earlier bytes are untouched.
    #[test]
    fn a_pwrite_through_an_appending_description_appends() {
        let scratch = crate::testing::Scratch::new("append");
        let path = scratch.file("log", b"0123456789");
        let fd = rustix::fs::open(
            &path,
            open_flags((OFlags::WRONLY | OFlags::APPEND).bits()),
            Mode::empty(),
        )
        .expect("the file opens for appending");

        // Offset zero: the front of the file, which is where a stale guest
        // kernel would aim a first append.
        assert_eq!(rustix::io::pwrite(&fd, b"AB", 0).expect("writable"), 2);
        // And an offset that is neither the front nor the end.
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
        assert!(writes(open_flags(OFlags::WRONLY.bits())));
        assert!(writes(open_flags(OFlags::RDWR.bits())));
        assert!(writes(open_flags((OFlags::RDONLY | OFlags::TRUNC).bits())));
        assert!(!writes(open_flags(OFlags::RDONLY.bits())));
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
