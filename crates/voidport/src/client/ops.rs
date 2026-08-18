//! The wire operations, one method per opcode.
//!
//! Each method is a translation and nothing more: arguments in, a fixed
//! request struct plus its payload out, the reply's fields copied back. The
//! policy — what is allowed, what an errno means — is the server's, and this
//! module never second-guesses it.
//!
//! What the replay discipline may do with each operation if its connection dies
//! mid-flight is **not** decided here, and no longer stated at each call site:
//! it is the session core's classification table
//! ([`voidport_session::replay::of`]), keyed on the opcode the request carries.
//! The one thing this module still contributes to it is the guest ABI: `open`
//! is the operation whose class depends on its arguments, and which numeric bit
//! is `O_CREAT` is an architecture's business, not the protocol's — so
//! [`open_flags`] names the guest's bits and the core decides what they mean.

use rustix::fs::OFlags;
use rustix::io::Errno;
use voidport_proto::attr::{Attr, Timespec};
use voidport_proto::ops::dir::{
    DirEntryIter, LinkRequest, LinkResponse, MkdirRequest, MkdirResponse, MknodRequest,
    MknodResponse, ReaddirplusRequest, ReaddirplusResponse, RenameRequest, RenameResponse,
    RmdirRequest, RmdirResponse, SymlinkRequest, SymlinkResponse, UnlinkRequest, UnlinkResponse,
};
use voidport_proto::ops::file::{
    CreateRequest, CreateResponse, FileLock, FlushRequest, FlushResponse, FsyncRequest,
    FsyncResponse, GetlkRequest, GetlkResponse, OpenRequest, OpenResponse, ReadRequest,
    ReadResponse, ReleaseRequest, ReleaseResponse, SetlkRequest, SetlkResponse, WriteRequest,
    WriteResponse, fsync_flags, lock_type, release_flags, setlk_flags, write_flags,
};
use voidport_proto::ops::node::{
    ForgetRequest, GetattrRequest, GetattrResponse, LookupRequest, LookupResponse, ReadlinkRequest,
    ReadlinkResponse, SetattrRequest, SetattrResponse, StatfsRequest, StatfsResponse,
    getattr_flags, setattr_valid,
};
use voidport_proto::ops::subscribe::{
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, UnsubscribeResponse,
};
use voidport_proto::ops::xattr::{
    GetxattrRequest, GetxattrResponse, ListxattrRequest, ListxattrResponse, RemovexattrRequest,
    RemovexattrResponse, SetxattrRequest, SetxattrResponse, XattrNameIter,
};
use zerocopy::byteorder::little_endian::{U32, U64};

use voidport_session::replay::OpenFlags;

use super::{Caller, Class, Client, DirEntry, Entry};

/// A time a `setattr` sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeChange {
    /// The server's current time.
    Now,
    /// An explicit instant.
    At(Timespec),
}

/// The fields one `setattr` changes. Everything left `None` is untouched.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttrChange {
    /// New permission bits.
    pub mode: Option<u32>,
    /// New owner, in guest id space.
    pub uid: Option<u32>,
    /// New group, in guest id space.
    pub gid: Option<u32>,
    /// New size (a truncate).
    pub size: Option<u64>,
    /// New access time.
    pub atime: Option<TimeChange>,
    /// New modification time.
    pub mtime: Option<TimeChange>,
    /// New change time.
    pub ctime: Option<Timespec>,
    /// The open handle to apply the change through, where the guest named one.
    pub handle: Option<u64>,
}

/// What kind of lock a request describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockKind {
    /// A shared read lock.
    Read,
    /// An exclusive write lock.
    Write,
    /// A release.
    Unlock,
}

impl LockKind {
    /// The kind a Linux `l_type` names.
    #[must_use]
    pub fn from_raw(raw: i32) -> Option<Self> {
        match u32::try_from(raw).ok()? {
            lock_type::READ => Some(Self::Read),
            lock_type::WRITE => Some(Self::Write),
            lock_type::UNLOCK => Some(Self::Unlock),
            _ => None,
        }
    }

    /// The Linux `l_type` of this kind.
    #[must_use]
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Read => lock_type::READ as i32,
            Self::Write => lock_type::WRITE as i32,
            Self::Unlock => lock_type::UNLOCK as i32,
        }
    }

    fn wire(self) -> u32 {
        match self {
            Self::Read => lock_type::READ,
            Self::Write => lock_type::WRITE,
            Self::Unlock => lock_type::UNLOCK,
        }
    }
}

/// One record lock, as the guest kernel describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lock {
    /// First byte of the range.
    pub start: u64,
    /// Last byte of the range; `u64::MAX` runs to end of file.
    pub end: u64,
    /// The kernel's opaque lock owner, passed through untouched.
    pub owner: u64,
    /// The guest pid holding it; informational.
    pub pid: u32,
    /// What kind of lock it is.
    pub kind: LockKind,
}

impl Lock {
    fn wire(self) -> FileLock {
        FileLock {
            start: U64::new(self.start),
            end: U64::new(self.end),
            owner: U64::new(self.owner),
            pid: U32::new(self.pid),
            lock_type: U32::new(self.kind.wire()),
        }
    }

    fn of(lock: &FileLock) -> Option<Self> {
        Some(Self {
            start: lock.start.get(),
            end: lock.end.get(),
            owner: lock.owner.get(),
            pid: lock.pid.get(),
            kind: LockKind::from_raw(i32::try_from(lock.lock_type.get()).ok()?)?,
        })
    }
}

/// An extended attribute value, or the size of one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XattrValue {
    /// The full size of the value, whether or not it was returned.
    pub size: u32,
    /// The value; empty for a size probe.
    pub value: Vec<u8>,
}

/// The extended attribute names of a node, or the size of the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XattrNames {
    /// The size of the guest's NUL-separated list, whether or not the names
    /// were returned. This is deliberately not the length of the wire stream.
    pub size: u32,
    /// The names.
    pub names: Vec<Vec<u8>>,
}

impl XattrNames {
    /// The names rebuilt into the kernel's NUL-separated list.
    #[must_use]
    pub fn to_kernel_list(&self) -> Vec<u8> {
        let mut list = Vec::with_capacity(self.size as usize);
        for name in &self.names {
            list.extend_from_slice(name);
            list.push(0);
        }
        list
    }
}

/// The guest's open flags, in the terms the core's classification names.
///
/// A translation and nothing else: which bit is `O_CREAT` is the running
/// architecture's ABI, which `rustix` answers for this build, and what a
/// creating or truncating open means for a replay is the core's. Flags the
/// classification does not distinguish are dropped here, because the core has
/// no opinion to give about them.
fn open_flags(flags: u32) -> OpenFlags {
    let flags = OFlags::from_bits_retain(flags);
    [
        (OFlags::CREATE, OpenFlags::CREATE),
        (OFlags::EXCL, OpenFlags::EXCLUSIVE),
        (OFlags::TRUNC, OpenFlags::TRUNCATE),
        (OFlags::APPEND, OpenFlags::APPEND),
    ]
    .into_iter()
    .filter(|(guest, _)| flags.contains(*guest))
    .fold(OpenFlags::NONE, |named, (_, flag)| named.union(flag))
}

impl Client {
    /// Resolves a name in a directory.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn lookup(&self, caller: Caller, parent: u64, name: &[u8]) -> Result<Entry, Errno> {
        let body = LookupRequest {
            name_len: U32::new(length(name)?),
        };
        self.call::<_, LookupResponse, _>(caller, parent, &body, name, |body, _| {
            Ok(Entry::of(&body.entry))
        })
        .await
    }

    /// Drops `nlookup` lookup counts from a node.
    ///
    /// The one request with no reply, and the one that must never fail loudly:
    /// a `forget` the connection could not carry names a node that died with
    /// the session the connection belonged to, and the server drops the whole
    /// node table when a session ends.
    pub async fn forget(&self, caller: Caller, node_id: u64, nlookup: u64) {
        let body = ForgetRequest {
            nlookup: U64::new(nlookup),
        };
        self.send(caller, node_id, &body).await;
    }

    /// Reads a node's attributes.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn getattr(
        &self,
        caller: Caller,
        node_id: u64,
        handle: Option<u64>,
    ) -> Result<Attr, Errno> {
        let body = GetattrRequest {
            handle: U64::new(handle.unwrap_or_default()),
            flags: U32::new(if handle.is_some() {
                getattr_flags::HANDLE
            } else {
                0
            }),
            reserved: U32::ZERO,
        };
        self.call::<_, GetattrResponse, _>(caller, node_id, &body, &[], |body, _| Ok(body.attr))
            .await
    }

    /// Changes a node's attributes.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn setattr(
        &self,
        caller: Caller,
        node_id: u64,
        change: AttrChange,
    ) -> Result<Attr, Errno> {
        let mut valid = 0;
        let mut set = |bit: u32| valid |= bit;
        if change.mode.is_some() {
            set(setattr_valid::MODE);
        }
        if change.uid.is_some() {
            set(setattr_valid::UID);
        }
        if change.gid.is_some() {
            set(setattr_valid::GID);
        }
        if change.size.is_some() {
            set(setattr_valid::SIZE);
        }
        if change.ctime.is_some() {
            set(setattr_valid::CTIME);
        }
        if change.handle.is_some() {
            set(setattr_valid::HANDLE);
        }
        match change.atime {
            Some(TimeChange::Now) => set(setattr_valid::ATIME_NOW),
            Some(TimeChange::At(_)) => set(setattr_valid::ATIME),
            None => {}
        }
        match change.mtime {
            Some(TimeChange::Now) => set(setattr_valid::MTIME_NOW),
            Some(TimeChange::At(_)) => set(setattr_valid::MTIME),
            None => {}
        }

        let body = SetattrRequest {
            valid: U32::new(valid),
            reserved: U32::ZERO,
            handle: U64::new(change.handle.unwrap_or_default()),
            size: U64::new(change.size.unwrap_or_default()),
            mode: U32::new(change.mode.unwrap_or_default()),
            uid: U32::new(change.uid.unwrap_or_default()),
            gid: U32::new(change.gid.unwrap_or_default()),
            reserved2: U32::ZERO,
            atime: instant(change.atime),
            mtime: instant(change.mtime),
            ctime: change.ctime.unwrap_or_else(|| Timespec::new(0, 0)),
        };
        self.call::<_, SetattrResponse, _>(caller, node_id, &body, &[], |body, _| Ok(body.attr))
            .await
    }

    /// Reads a symlink's target, verbatim.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn readlink(&self, caller: Caller, node_id: u64) -> Result<Vec<u8>, Errno> {
        self.call::<_, ReadlinkResponse, _>(
            caller,
            node_id,
            &ReadlinkRequest {},
            &[],
            |_, payload| Ok(payload.to_vec()),
        )
        .await
    }

    /// Creates a symlink.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn symlink(
        &self,
        caller: Caller,
        parent: u64,
        name: &[u8],
        target: &[u8],
    ) -> Result<Entry, Errno> {
        let body = SymlinkRequest {
            name_len: U32::new(length(name)?),
            target_len: U32::new(length(target)?),
        };
        let mut payload = name.to_vec();
        payload.extend_from_slice(target);
        self.call::<_, SymlinkResponse, _>(caller, parent, &body, &payload, |body, _| {
            Ok(Entry::of(&body.entry))
        })
        .await
    }

    /// Creates a directory.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn mkdir(
        &self,
        caller: Caller,
        parent: u64,
        name: &[u8],
        mode: u32,
        umask: u32,
    ) -> Result<Entry, Errno> {
        let body = MkdirRequest {
            mode: U32::new(mode),
            umask: U32::new(umask),
            name_len: U32::new(length(name)?),
            reserved: U32::ZERO,
        };
        self.call::<_, MkdirResponse, _>(caller, parent, &body, name, |body, _| {
            Ok(Entry::of(&body.entry))
        })
        .await
    }

    /// Creates a FIFO or a socket file.
    ///
    /// The kind rides in the file-type bits of `mode`; the server serves those
    /// two and answers `EPERM` for anything else.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount. A server too old to
    /// know the opcode answers `ENOSYS`, which the FUSE adapter surfaces to the
    /// guest as `EPERM` — a clean refusal, not a puzzling one.
    pub async fn mknod(
        &self,
        caller: Caller,
        parent: u64,
        name: &[u8],
        mode: u32,
        umask: u32,
        rdev: u32,
    ) -> Result<Entry, Errno> {
        let body = MknodRequest {
            mode: U32::new(mode),
            umask: U32::new(umask),
            rdev: U32::new(rdev),
            name_len: U32::new(length(name)?),
        };
        self.call::<_, MknodResponse, _>(caller, parent, &body, name, |body, _| {
            Ok(Entry::of(&body.entry))
        })
        .await
    }

    /// Removes a non-directory entry.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn unlink(&self, caller: Caller, parent: u64, name: &[u8]) -> Result<(), Errno> {
        let body = UnlinkRequest {
            name_len: U32::new(length(name)?),
        };
        self.call::<_, UnlinkResponse, _>(caller, parent, &body, name, |_, _| Ok(()))
            .await
    }

    /// Removes a directory.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn rmdir(&self, caller: Caller, parent: u64, name: &[u8]) -> Result<(), Errno> {
        let body = RmdirRequest {
            name_len: U32::new(length(name)?),
        };
        self.call::<_, RmdirResponse, _>(caller, parent, &body, name, |_, _| Ok(()))
            .await
    }

    /// Renames an entry, possibly into another directory.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn rename(
        &self,
        caller: Caller,
        parent: u64,
        name: &[u8],
        new_parent: u64,
        new_name: &[u8],
        flags: u32,
    ) -> Result<(), Errno> {
        let body = RenameRequest {
            new_parent_node_id: U64::new(new_parent),
            flags: U32::new(flags),
            old_name_len: U32::new(length(name)?),
            new_name_len: U32::new(length(new_name)?),
            reserved: U32::ZERO,
        };
        let mut payload = name.to_vec();
        payload.extend_from_slice(new_name);
        self.call::<_, RenameResponse, _>(caller, parent, &body, &payload, |_, _| Ok(()))
            .await
    }

    /// Creates a hard link to an existing node.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn link(
        &self,
        caller: Caller,
        target: u64,
        parent: u64,
        name: &[u8],
    ) -> Result<Entry, Errno> {
        let body = LinkRequest {
            target_node_id: U64::new(target),
            name_len: U32::new(length(name)?),
            reserved: U32::ZERO,
        };
        self.call::<_, LinkResponse, _>(caller, parent, &body, name, |body, _| {
            Ok(Entry::of(&body.entry))
        })
        .await
    }

    /// Opens a file or a directory, returning its handle.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn open(&self, caller: Caller, node_id: u64, flags: u32) -> Result<u64, Errno> {
        let body = OpenRequest {
            flags: U32::new(flags),
            reserved: U32::ZERO,
        };
        // The one operation whose replay class depends on its arguments, so
        // the one that hands the core more than its opcode.
        self.call_on::<_, OpenResponse, _>(
            caller,
            node_id,
            &body,
            &[],
            open_flags(flags),
            Class::Prompt,
            |body, _| Ok(body.handle.get()),
        )
        .await
        .map(|(handle, _)| handle)
    }

    /// Creates and opens a file in one round trip.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn create(
        &self,
        caller: Caller,
        parent: u64,
        name: &[u8],
        flags: u32,
        mode: u32,
        umask: u32,
    ) -> Result<(Entry, u64), Errno> {
        let body = CreateRequest {
            flags: U32::new(flags),
            mode: U32::new(mode),
            umask: U32::new(umask),
            name_len: U32::new(length(name)?),
        };
        self.call::<_, CreateResponse, _>(caller, parent, &body, name, |body, _| {
            Ok((Entry::of(&body.entry), body.handle.get()))
        })
        .await
    }

    /// Reads file data. A short answer means end of file.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn read(
        &self,
        caller: Caller,
        node_id: u64,
        handle: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, Errno> {
        let body = ReadRequest {
            handle: U64::new(handle),
            offset: U64::new(offset),
            size: U32::new(size),
            flags: U32::ZERO,
        };
        self.call::<_, ReadResponse, _>(caller, node_id, &body, &[], |_, payload| {
            Ok(payload.to_vec())
        })
        .await
    }

    /// Writes file data, returning how much was written.
    ///
    /// The core's once-only class carries more weight here than "a mutation
    /// must not be applied twice". A write at an offset that was applied and then repeated
    /// would at least be idempotent in its effect; a write on a handle the
    /// guest opened `O_APPEND` would not, because the server does not place it
    /// at the offset in the request — the host appends it — so a re-sent append
    /// stores a **second copy** of the record. An attempt that was written to a
    /// connection that then died may have been applied, so it fails `EIO`; one
    /// still queued provably was not, and only that one is re-sent.
    ///
    /// `strip_privileged` carries the guest kernel's own suid-kill mark: the
    /// running kernel sets it on a direct-io write by a caller without the
    /// file-mode privilege, and the server clears the recorded bits per the
    /// mode-only local rule. It rides every chunk of a split write, stripping
    /// being idempotent; a server too old to know the flag ignores it and
    /// strips nothing, which is fail-open for stripping under version skew and
    /// is stated, not hidden.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn write(
        &self,
        caller: Caller,
        node_id: u64,
        handle: u64,
        offset: u64,
        data: &[u8],
        strip_privileged: bool,
    ) -> Result<u32, Errno> {
        self.write_framed(
            Class::Prompt,
            caller,
            node_id,
            handle,
            offset,
            data,
            strip_privileged,
        )
        .await
    }

    /// Writes one chunk of a streamed write.
    ///
    /// The same request as [`Self::write`] in every wire byte — the server
    /// cannot tell the two apart, and no clause of the contract distinguishes
    /// them. What differs is the send path's class: a window of chunks is
    /// queued at once, so a chunk is **bulk** and queues one at a time at the
    /// connection's serialization point, which is what admits a pending
    /// metadata request ahead of the rest of the window.
    ///
    /// # Errors
    ///
    /// As [`Self::write`].
    pub async fn write_streamed(
        &self,
        caller: Caller,
        node_id: u64,
        handle: u64,
        offset: u64,
        data: &[u8],
        strip_privileged: bool,
    ) -> Result<u32, Errno> {
        self.write_framed(
            Class::Bulk,
            caller,
            node_id,
            handle,
            offset,
            data,
            strip_privileged,
        )
        .await
    }

    /// The one write request both entry points send, in the class each names.
    #[allow(
        clippy::too_many_arguments,
        reason = "the wire request's own fields, and the class that carries it"
    )]
    async fn write_framed(
        &self,
        class: Class,
        caller: Caller,
        node_id: u64,
        handle: u64,
        offset: u64,
        data: &[u8],
        strip_privileged: bool,
    ) -> Result<u32, Errno> {
        let body = WriteRequest {
            handle: U64::new(handle),
            offset: U64::new(offset),
            data_len: U32::new(length(data)?),
            flags: U32::ZERO,
            write_flags: U32::new(if strip_privileged {
                write_flags::PRIVILEGED_STRIP
            } else {
                0
            }),
            reserved: U32::ZERO,
        };
        self.call_on::<_, WriteResponse, _>(
            caller,
            node_id,
            &body,
            data,
            OpenFlags::NONE,
            class,
            |body, _| Ok(body.written.get()),
        )
        .await
        .map(|(written, _)| written)
    }

    /// Releases a handle.
    ///
    /// A release whose connection died is **moot**: the handle it names died
    /// with the session, so the guest's close is answered as the success it
    /// effectively is, not handed an `EIO` for a resource that no longer
    /// exists anywhere.
    ///
    /// # Errors
    ///
    /// The server's errno, when the server answered at all.
    pub async fn release(
        &self,
        caller: Caller,
        node_id: u64,
        handle: u64,
        flags: u32,
        lock_owner: Option<u64>,
        flush: bool,
    ) -> Result<(), Errno> {
        let mut release = 0;
        if flush {
            release |= release_flags::FLUSH;
        }
        if lock_owner.is_some() {
            release |= release_flags::UNLOCK;
        }
        let body = ReleaseRequest {
            handle: U64::new(handle),
            lock_owner: U64::new(lock_owner.unwrap_or_default()),
            flags: U32::new(flags),
            release_flags: U32::new(release),
        };
        self.call_moot::<_, ReleaseResponse>(caller, node_id, &body, &[])
            .await
    }

    /// Reports one guest descriptor's close, dropping that owner's locks.
    ///
    /// # Errors
    ///
    /// The server's errno — `EBADF` for a handle that did not survive a
    /// reconnect, which is the loss surfacing where POSIX puts it — or `EIO` on
    /// a degraded mount.
    pub async fn flush(
        &self,
        caller: Caller,
        node_id: u64,
        handle: u64,
        lock_owner: u64,
    ) -> Result<(), Errno> {
        let body = FlushRequest {
            handle: U64::new(handle),
            lock_owner: U64::new(lock_owner),
        };
        // A mutation, and not on the design's idempotent list: the server drops
        // the caller's record-lock owner here, so a written attempt that lost
        // its answer has to be assumed applied, not re-sent.
        self.call::<_, FlushResponse, _>(caller, node_id, &body, &[], |_, _| Ok(()))
            .await
    }

    /// Flushes a handle to stable storage.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn fsync(
        &self,
        caller: Caller,
        node_id: u64,
        handle: u64,
        datasync: bool,
    ) -> Result<(), Errno> {
        let body = FsyncRequest {
            handle: U64::new(handle),
            flags: U32::new(if datasync { fsync_flags::DATASYNC } else { 0 }),
            reserved: U32::ZERO,
        };
        // Not on the design's idempotent list either: a durability barrier the
        // guest was told nothing about is not one this client may re-issue on
        // its own, so a written attempt that lost its answer fails.
        self.call::<_, FsyncResponse, _>(caller, node_id, &body, &[], |_, _| Ok(()))
            .await
    }

    /// Reports filesystem statistics.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn statfs(&self, caller: Caller, node_id: u64) -> Result<StatfsResponse, Errno> {
        self.call::<_, StatfsResponse, _>(caller, node_id, &StatfsRequest {}, &[], |body, _| {
            Ok(*body)
        })
        .await
    }

    /// Enumerates a directory from `cookie`, up to `size` bytes of entries.
    ///
    /// Every entry counts a lookup on the server, which the caller must
    /// balance — including for entries it does not pass on to the kernel.
    ///
    /// # Errors
    ///
    /// The server's errno, `EIO` on a degraded mount, or `EIO` for a malformed
    /// entry stream (which poisons the connection).
    pub async fn readdirplus(
        &self,
        caller: Caller,
        node_id: u64,
        handle: u64,
        cookie: u64,
        size: u32,
    ) -> Result<Vec<DirEntry>, Errno> {
        let body = ReaddirplusRequest {
            handle: U64::new(handle),
            cookie: U64::new(cookie),
            size: U32::new(size),
            reserved: U32::ZERO,
        };
        self.call::<_, ReaddirplusResponse, _>(caller, node_id, &body, &[], |_, payload| {
            DirEntryIter::new(payload)
                .map(|item| {
                    let item = item?;
                    Ok(DirEntry {
                        name: item.tail.to_vec(),
                        entry: Entry::of(&item.header.entry),
                        next_cookie: item.header.next_cookie.get(),
                        entry_type: item.header.entry_type.get(),
                    })
                })
                .collect()
        })
        .await
    }

    /// Reads one extended attribute, or probes its size with `size == 0`.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn getxattr(
        &self,
        caller: Caller,
        node_id: u64,
        name: &[u8],
        size: u32,
    ) -> Result<XattrValue, Errno> {
        let body = GetxattrRequest {
            size: U32::new(size),
            name_len: U32::new(length(name)?),
        };
        self.call::<_, GetxattrResponse, _>(caller, node_id, &body, name, |body, payload| {
            Ok(XattrValue {
                size: body.size.get(),
                value: payload.to_vec(),
            })
        })
        .await
    }

    /// Sets one extended attribute.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn setxattr(
        &self,
        caller: Caller,
        node_id: u64,
        name: &[u8],
        value: &[u8],
        flags: u32,
    ) -> Result<(), Errno> {
        let body = SetxattrRequest {
            flags: U32::new(flags),
            name_len: U32::new(length(name)?),
            value_len: U32::new(length(value)?),
            reserved: U32::ZERO,
        };
        let mut payload = name.to_vec();
        payload.extend_from_slice(value);
        self.call::<_, SetxattrResponse, _>(caller, node_id, &body, &payload, |_, _| Ok(()))
            .await
    }

    /// Lists extended attribute names, or probes the list size with
    /// `size == 0`.
    ///
    /// `size` is measured in guest bytes — the length of the NUL-separated
    /// list the kernel wants — never in wire bytes.
    ///
    /// # Errors
    ///
    /// The server's errno, `EIO` on a degraded mount, or `EIO` for a malformed
    /// name stream (which poisons the connection).
    pub async fn listxattr(
        &self,
        caller: Caller,
        node_id: u64,
        size: u32,
    ) -> Result<XattrNames, Errno> {
        let body = ListxattrRequest {
            size: U32::new(size),
            reserved: U32::ZERO,
        };
        self.call::<_, ListxattrResponse, _>(caller, node_id, &body, &[], |body, payload| {
            XattrNameIter::new(payload)
                .map(|item| Ok(item?.tail.to_vec()))
                .collect::<Result<Vec<_>, _>>()
                .map(|names| XattrNames {
                    size: body.size.get(),
                    names,
                })
        })
        .await
    }

    /// Removes one extended attribute.
    ///
    /// # Errors
    ///
    /// The server's errno, or `EIO` on a degraded mount.
    pub async fn removexattr(
        &self,
        caller: Caller,
        node_id: u64,
        name: &[u8],
    ) -> Result<(), Errno> {
        let body = RemovexattrRequest {
            name_len: U32::new(length(name)?),
        };
        self.call::<_, RemovexattrResponse, _>(caller, node_id, &body, name, |_, _| Ok(()))
            .await
    }

    /// Tests whether a lock could be placed.
    ///
    /// # Errors
    ///
    /// The server's errno — `EBADF` for a handle that did not survive a
    /// reconnect, which is how the loss of a lock surfaces — `EIO` on a
    /// degraded mount, or `EIO` for a lock type the wire does not define.
    pub async fn getlk(
        &self,
        caller: Caller,
        node_id: u64,
        handle: u64,
        lock: Lock,
    ) -> Result<Lock, Errno> {
        let body = GetlkRequest {
            handle: U64::new(handle),
            lock: lock.wire(),
        };
        self.call::<_, GetlkResponse, _>(caller, node_id, &body, &[], |body, _| {
            Ok(Lock::of(&body.lock))
        })
        .await?
        .ok_or(Errno::IO)
    }

    /// Places or releases a lock, optionally waiting for it.
    ///
    /// # Errors
    ///
    /// The server's errno — `EAGAIN` for a conflict that was not waited for,
    /// `EBADF` for a handle that did not survive a reconnect — or `EIO` on a
    /// degraded mount.
    pub async fn setlk(
        &self,
        caller: Caller,
        node_id: u64,
        handle: u64,
        lock: Lock,
        wait: bool,
    ) -> Result<(), Errno> {
        let body = SetlkRequest {
            handle: U64::new(handle),
            lock: lock.wire(),
            flags: U32::new(if wait { setlk_flags::WAIT } else { 0 }),
            reserved: U32::ZERO,
        };
        self.call::<_, SetlkResponse, _>(caller, node_id, &body, &[], |_, _| Ok(()))
            .await
    }

    /// Starts — or restarts — this session's share subscription.
    ///
    /// Idempotent by the subscription contract's own resync rule: a
    /// `Subscribe` on an already-subscribed session answers a fresh snapshot on
    /// the same stream, so re-sending one whose reply was lost costs a snapshot
    /// and nothing else. Against the fresh session a reconnect built it is the
    /// resubscription the level-triggered consumer needs anyway.
    ///
    /// # Errors
    ///
    /// `ENOSYS` from a server that predates the subscription — a probe, not a
    /// fault, and the connection lives — `ENOENT` when the namespace has been
    /// deleted, or `EIO` on a degraded mount.
    pub async fn subscribe(&self, caller: Caller) -> Result<(), Errno> {
        self.subscribe_on(caller).await.map(|_| ())
    }

    /// The same, reporting the generation of the connection that answered.
    ///
    /// That is the connection whose session now holds the subscription — the
    /// replay discipline may have carried the request across a reconnect onto a
    /// connection this caller never saw — and it is what
    /// [`Subscription`](crate::subscribe::Subscription) records, so its
    /// reconnect bracket does not re-subscribe on top of a replay that already
    /// did and hand the consumer a second snapshot for one outage.
    ///
    /// # Errors
    ///
    /// As [`Self::subscribe`].
    pub(crate) async fn subscribe_on(&self, caller: Caller) -> Result<u64, Errno> {
        let body = SubscribeRequest {
            reserved: U32::ZERO,
        };
        self.call_on::<_, SubscribeResponse, _>(
            caller,
            0,
            &body,
            &[],
            OpenFlags::NONE,
            Class::Prompt,
            |_, _| Ok(()),
        )
        .await
        .map(|((), generation)| generation)
    }

    /// Ends this session's share subscription.
    ///
    /// Idempotent for the plainest reason: a session that is not subscribed
    /// answers success, so a replay across a reconnect — against a fresh
    /// session that never subscribed — is a no-op, not an error.
    ///
    /// # Errors
    ///
    /// As [`Self::subscribe`].
    pub async fn unsubscribe(&self, caller: Caller) -> Result<(), Errno> {
        let body = UnsubscribeRequest {
            reserved: U32::ZERO,
        };
        self.call::<_, UnsubscribeResponse, _>(caller, 0, &body, &[], |_, _| Ok(()))
            .await
    }
}

/// The wire length of a payload region.
fn length(region: &[u8]) -> Result<u32, Errno> {
    u32::try_from(region.len()).map_err(|_| Errno::OVERFLOW)
}

/// The timestamp a `setattr` field carries. A field the mask does not select
/// carries no meaning, so zero is as good as anything.
fn instant(change: Option<TimeChange>) -> Timespec {
    match change {
        Some(TimeChange::At(time)) => time,
        Some(TimeChange::Now) | None => Timespec::new(0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use voidport_proto::opcode::Opcode;
    use voidport_session::replay::{self, Replay};

    /// The guest bits reach the core's names, so the class the core decides is
    /// the class this architecture's flags describe.
    #[test]
    fn only_an_open_that_creates_or_truncates_is_a_mutation() {
        let class = |flags: u32| replay::of(Opcode::Open, open_flags(flags));
        assert_eq!(class(0), Replay::Idempotent);
        assert_eq!(
            class(OFlags::RDWR.bits() | OFlags::APPEND.bits()),
            Replay::Idempotent,
            "appending is a property of the handle, not a change to the file"
        );
        for mutating in [OFlags::CREATE, OFlags::EXCL, OFlags::TRUNC] {
            assert_eq!(
                class(OFlags::RDWR.bits() | mutating.bits()),
                Replay::Once,
                "{mutating:?} makes an open a mutation"
            );
        }
    }
}
