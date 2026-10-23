use rustix::fs::OFlags;
use rustix::io::Errno;
use voidport_proto::attr::{Attr, Timespec};
use voidport_proto::ops::dir::{
    LinkRequest, LinkResponse, MkdirRequest, MkdirResponse, MknodRequest, MknodResponse,
    ReaddirplusRequest, ReaddirplusResponse, RenameRequest, RenameResponse, RmdirRequest,
    RmdirResponse, SymlinkRequest, SymlinkResponse, UnlinkRequest, UnlinkResponse,
    listing_reply_bound,
};
use voidport_proto::ops::file::{
    CreateRequest, CreateResponse, FileLock, FlushRequest, FlushResponse, FsyncRequest,
    FsyncResponse, GetlkRequest, GetlkResponse, OpenRequest, OpenResponse, ReadRequest,
    ReadResponse, ReleaseRequest, ReleaseResponse, SetlkRequest, SetlkResponse, WriteRequest,
    WriteResponse, fsync_flags, lock_type, release_flags, setlk_flags, write_flags,
};
use voidport_proto::ops::node::{
    GetattrRequest, GetattrResponse, LookupRequest, LookupResponse, ReadlinkRequest,
    ReadlinkResponse, SetattrRequest, SetattrResponse, StatfsRequest, StatfsResponse,
    getattr_flags, setattr_valid,
};
use voidport_proto::ops::recall::{
    RecalledRequest, RecalledResponse, RelinquishRequest, RelinquishResponse, RenewRequest,
    RenewResponse,
};
use voidport_proto::ops::subscribe::{
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, UnsubscribeResponse,
};
use voidport_proto::ops::xattr::{
    GetxattrRequest, GetxattrResponse, ListxattrRequest, ListxattrResponse, RemovexattrRequest,
    RemovexattrResponse, SetxattrRequest, SetxattrResponse, XattrNameIter,
};
use zerocopy::byteorder::little_endian::{U32, U64};

use voidport_proto::message::ResponseBody;
use voidport_proto::opcode::Opcode;
use voidport_session::Window;
use voidport_session::replay::OpenFlags;

use super::connection::{Answer, Connection, Forget, Nothing};
use super::{
    Caller, Client, Data, Entries, Entry, EntrySink, Interrupt, Outgoing, Pages, errno_of,
    interpret,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Streamed {
    pub exhausted: bool,
    /// The errno a later piece failed with. What was received before it stands.
    pub failed: Option<Errno>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Granted {
    pub window: Option<Window>,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewFile<'a> {
    pub parent: u64,
    pub name: &'a [u8],
    pub flags: u32,
    pub mode: u32,
    pub umask: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    pub node_id: u64,
    pub handle: u64,
    pub offset: u64,
}

pub struct Listing {
    pub sink: Box<dyn EntrySink>,
    pub accepted: Vec<u64>,
    /// The generation of the session that counted the lookups of
    /// [`accepted`](Self::accepted).
    pub generation: Option<u64>,
    /// An errno means every entry of the reply was given back, and the reply of
    /// the kernel must answer that errno and not the entries it holds.
    pub outcome: Result<bool, Errno>,
}

impl std::fmt::Debug for Listing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listing")
            .field("accepted", &self.accepted)
            .field("generation", &self.generation)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Settled {
    pub give_back: Vec<u64>,
    pub accepted: Vec<u64>,
    pub outcome: Result<bool, Errno>,
}

pub(crate) fn settle(entries: &Entries, streamed: Result<Streamed, Errno>) -> Settled {
    match streamed {
        Ok(Streamed {
            exhausted,
            failed: None,
        }) => Settled {
            give_back: entries.refused().to_vec(),
            accepted: entries.accepted().to_vec(),
            outcome: Ok(exhausted),
        },
        Ok(Streamed {
            failed: Some(errno),
            ..
        })
        | Err(errno) => Settled {
            give_back: entries
                .accepted()
                .iter()
                .chain(entries.refused())
                .copied()
                .collect(),
            accepted: Vec::new(),
            outcome: Err(errno),
        },
    }
}

fn streamed<R: ResponseBody>(connection: &Connection, answer: &Answer) -> Result<Streamed, Errno> {
    interpret::<R, ()>(connection, &answer.frame, |_, _| Ok(()))?;
    // A successful reply to a streamed request is always read with its
    // closing piece.
    let closing = answer.closing.ok_or(Errno::IO)?;
    Ok(Streamed {
        exhausted: closing.exhausted,
        failed: (closing.status != 0).then(|| errno_of(closing.status)),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeChange {
    Now,
    At(Timespec),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttrChange {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<TimeChange>,
    pub mtime: Option<TimeChange>,
    pub ctime: Option<Timespec>,
    pub handle: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockKind {
    Read,
    Write,
    Unlock,
}

impl LockKind {
    #[must_use]
    pub fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            lock_type::READ => Some(Self::Read),
            lock_type::WRITE => Some(Self::Write),
            lock_type::UNLOCK => Some(Self::Unlock),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_raw(self) -> u32 {
        match self {
            Self::Read => lock_type::READ,
            Self::Write => lock_type::WRITE,
            Self::Unlock => lock_type::UNLOCK,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lock {
    pub start: u64,
    /// `u64::MAX` runs to the end of the file.
    pub end: u64,
    pub owner: u64,
    pub pid: u32,
    pub kind: LockKind,
}

impl Lock {
    fn wire(self) -> FileLock {
        FileLock {
            start: U64::new(self.start),
            end: U64::new(self.end),
            owner: U64::new(self.owner),
            pid: U32::new(self.pid),
            lock_type: U32::new(self.kind.as_raw()),
        }
    }

    fn of(lock: &FileLock) -> Option<Self> {
        Some(Self {
            start: lock.start.get(),
            end: lock.end.get(),
            owner: lock.owner.get(),
            pid: lock.pid.get(),
            kind: LockKind::from_raw(lock.lock_type.get())?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XattrValue {
    pub size: u32,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XattrNames {
    /// The size of the NUL-separated list of the guest, which is not the length
    /// of the wire stream.
    pub size: u32,
    pub names: Vec<Vec<u8>>,
}

impl XattrNames {
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
    pub async fn lookup(&self, caller: Caller, parent: u64, name: &[u8]) -> Result<Entry, Errno> {
        let body = LookupRequest {
            name_len: U32::new(length(name)?),
        };
        self.call::<_, LookupResponse, _>(caller, parent, &body, name, |body, _| {
            Ok(Entry::of(&body.entry))
        })
        .await
    }

    /// A `forget` the session could not carry names a node that died with the
    /// session, because the server drops the whole node table when a session
    /// ends, so it never fails loudly. One whose connection is lost while the
    /// session lives is settled on another connection of the session.
    pub async fn forget(&self, caller: Caller, node_id: u64, nlookup: u64) {
        self.forget_now(Forget {
            caller,
            node_id,
            nlookup,
        })
        .await;
    }

    /// It is sent only within that session. When that session has ended, the
    /// forget is dropped: the lookups it gives back went with it, and a newer
    /// session never counted them.
    pub async fn forget_on(&self, caller: Caller, generation: u64, node_id: u64, nlookup: u64) {
        let forget = Forget {
            caller,
            node_id,
            nlookup,
        };
        self.forget_within(generation, &[forget]).await;
    }

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

    /// `interrupt` ends a change that waits in the server, a truncate of a file
    /// that another opener has open.
    ///
    /// # Errors
    ///
    /// `EINTR` for a change ended by the interrupt.
    pub async fn setattr(
        &self,
        caller: Caller,
        interrupt: &Interrupt,
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
        self.call_interruptible::<_, SetattrResponse, _>(
            caller,
            interrupt,
            node_id,
            &body,
            &[],
            |body, _| Ok(body.attr),
        )
        .await
    }

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

    /// The kind is in the file-type bits of `mode`. The server creates a FIFO
    /// and a socket file and returns `EPERM` for anything else.
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

    pub async fn unlink(&self, caller: Caller, parent: u64, name: &[u8]) -> Result<(), Errno> {
        let body = UnlinkRequest {
            name_len: U32::new(length(name)?),
        };
        self.call::<_, UnlinkResponse, _>(caller, parent, &body, name, |_, _| Ok(()))
            .await
    }

    pub async fn rmdir(&self, caller: Caller, parent: u64, name: &[u8]) -> Result<(), Errno> {
        let body = RmdirRequest {
            name_len: U32::new(length(name)?),
        };
        self.call::<_, RmdirResponse, _>(caller, parent, &body, name, |_, _| Ok(()))
            .await
    }

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

    pub async fn open(&self, caller: Caller, node_id: u64, flags: u32) -> Result<u64, Errno> {
        self.open_file(caller, &Interrupt::none(), node_id, flags)
            .await
            .map(|(handle, _)| handle)
    }

    /// `interrupt` ends an open that waits in the server for another opener of
    /// the file.
    ///
    /// # Errors
    ///
    /// `EINTR` for an open ended by the interrupt.
    pub async fn open_file(
        &self,
        caller: Caller,
        interrupt: &Interrupt,
        node_id: u64,
        flags: u32,
    ) -> Result<(u64, Pages), Errno> {
        let body = OpenRequest {
            flags: U32::new(flags),
            reserved: U32::ZERO,
        };
        // The one operation whose replay class depends on its arguments.
        let request = Outgoing {
            node_id,
            open: open_flags(flags),
            body: &body,
            payload: &[],
            data: &[],
        };
        self.call_on::<_, OpenResponse, _>(caller, interrupt, &request, |body, _| {
            Ok((body.handle.get(), Pages::of(body.flags.get())))
        })
        .await
        .map(|(opened, _)| opened)
    }

    /// `interrupt` ends a create that waits in the server for another opener of
    /// the file.
    ///
    /// # Errors
    ///
    /// `EINTR` for a create ended by the interrupt.
    pub async fn create(
        &self,
        caller: Caller,
        interrupt: &Interrupt,
        file: NewFile<'_>,
    ) -> Result<(Entry, u64, Pages), Errno> {
        let body = CreateRequest {
            flags: U32::new(file.flags),
            mode: U32::new(file.mode),
            umask: U32::new(file.umask),
            name_len: U32::new(length(file.name)?),
        };
        self.call_interruptible::<_, CreateResponse, _>(
            caller,
            interrupt,
            file.parent,
            &body,
            file.name,
            |body, _| {
                Ok((
                    Entry::of(&body.entry),
                    body.handle.get(),
                    Pages::of(body.flags.get()),
                ))
            },
        )
        .await
    }

    /// `data` comes back with what was received whatever the outcome: with the
    /// answer, with the death of the connection, a failed write of the request
    /// included, and with a waiter dropped undelivered, as a reader dropped by a
    /// runtime shutting down drops it. A read that received pieces before an
    /// errno reports the errno in [`Streamed::failed`], and the bytes stand.
    /// `interrupt` ends a read that waits in the server for another opener of
    /// the file.
    ///
    /// # Errors
    ///
    /// The errno of the server when nothing was read, and `EINTR` for a read
    /// ended by the interrupt.
    pub async fn read(
        &self,
        caller: Caller,
        interrupt: &Interrupt,
        node_id: u64,
        handle: u64,
        offset: u64,
        mut data: Data,
    ) -> (Data, Result<Streamed, Errno>) {
        data.begin();
        let body = ReadRequest {
            handle: U64::new(handle),
            offset: U64::new(offset),
            size: U32::new(u32::try_from(data.remaining()).unwrap_or(u32::MAX)),
            flags: U32::ZERO,
        };
        let request = Outgoing {
            node_id,
            open: OpenFlags::NONE,
            body: &body,
            payload: &[],
            data: &[],
        };
        // A read changes nothing on the server: it is sent again, and nothing
        // of its reply is kept.
        let (data, answered) = self
            .exchange(caller, interrupt, Opcode::Read, &request, data, 0)
            .await;
        let outcome = answered.and_then(|answered| {
            let (connection, answer) = answered.ok_or(Errno::IO)?;
            streamed::<ReadResponse>(&connection, &answer)
        });
        (data, outcome)
    }

    /// The data follows the request on the socket, written under the same writer
    /// lock as the request, so it streams into the file as the server reads it.
    /// A short count is the host's, and the caller continues from it.
    ///
    /// A write on a handle opened `O_APPEND` is not idempotent: the host
    /// appends it at the end of the file, so a re-sent append stores the record
    /// twice. An attempt written to a connection that then died may have been
    /// applied, so it fails with `EIO`. Only an attempt still queued is sent
    /// again.
    ///
    /// `strip_privileged` is the suid-kill mark set by the guest kernel on a
    /// direct-io write by a caller without the file-mode privilege. It is sent
    /// with the continuation of a short write too, since stripping twice
    /// changes nothing.
    ///
    /// `interrupt` ends a write that waits in the server for another opener of
    /// the file, before any of it was written.
    ///
    /// # Errors
    ///
    /// `EINTR` for a write ended by the interrupt.
    pub async fn write(
        &self,
        caller: Caller,
        interrupt: &Interrupt,
        at: Placement,
        data: &[u8],
        strip_privileged: bool,
    ) -> Result<u32, Errno> {
        let body = WriteRequest {
            handle: U64::new(at.handle),
            offset: U64::new(at.offset),
            data_len: U32::new(length(data)?),
            flags: U32::ZERO,
            write_flags: U32::new(if strip_privileged {
                write_flags::PRIVILEGED_STRIP
            } else {
                0
            }),
            reserved: U32::ZERO,
        };
        let request = Outgoing {
            node_id: at.node_id,
            open: OpenFlags::NONE,
            body: &body,
            payload: &[],
            data,
        };
        let (Nothing, answered) = self
            .exchange(
                caller,
                interrupt,
                Opcode::Write,
                &request,
                Nothing,
                super::kept_bound::<WriteResponse>(),
            )
            .await;
        let (connection, answer) = answered?.ok_or(Errno::IO)?;
        interpret::<WriteResponse, u32>(&connection, &answer.frame, |body, _| {
            Ok(body.written.get())
        })
    }

    /// A release whose connection died is moot: the handle it names died with the
    /// session, so the close of the guest is answered as the success it is.
    ///
    /// # Errors
    ///
    /// The errno of the server, when the server answered at all.
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

    /// A recall of a session that ended gets a reply without effect.
    ///
    /// # Errors
    ///
    /// The errno of the server, when the server replied at all.
    pub async fn recalled(&self, caller: Caller, node_id: u64, recall: u64) -> Result<(), Errno> {
        let body = RecalledRequest {
            recall: U64::new(recall),
        };
        self.call_moot::<_, RecalledResponse>(caller, node_id, &body, &[])
            .await
    }

    /// A session that ended gets a reply without effect.
    ///
    /// # Errors
    ///
    /// The errno of the server, when the server replied at all.
    pub async fn relinquish(&self, caller: Caller) -> Result<(), Errno> {
        let body = RelinquishRequest {
            reserved: U32::ZERO,
        };
        self.call_moot::<_, RelinquishResponse>(caller, 0, &body, &[])
            .await
    }

    /// The window counts from the moment this was called.
    pub async fn renew(&self, caller: Caller) -> Result<Granted, Errno> {
        let body = RenewRequest {
            reserved: U32::ZERO,
        };
        let window = |body: &RenewResponse, _: &[u8]| {
            Ok(Window::from_nanos(
                body.window_ns.get(),
                body.period_ns.get(),
            ))
        };
        let request = Outgoing {
            node_id: 0,
            open: OpenFlags::NONE,
            body: &body,
            payload: &[],
            data: &[],
        };
        self.call_on::<_, RenewResponse, _>(caller, &Interrupt::none(), &request, window)
            .await
            .map(|(window, generation)| Granted { window, generation })
    }

    /// # Errors
    ///
    /// `EBADF` for a handle that did not survive a reconnect.
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
        // A mutation, and not on the idempotent list: the server drops the
        // record-lock owner of the caller here, so a written attempt that lost
        // its answer is taken as applied and is not sent again.
        self.call::<_, FlushResponse, _>(caller, node_id, &body, &[], |_, _| Ok(()))
            .await
    }

    /// `interrupt` ends a sync that waits in the server for another opener of
    /// the file.
    ///
    /// # Errors
    ///
    /// `EINTR` for a sync ended by the interrupt.
    pub async fn fsync(
        &self,
        caller: Caller,
        interrupt: &Interrupt,
        node_id: u64,
        handle: u64,
        datasync: bool,
    ) -> Result<(), Errno> {
        let body = FsyncRequest {
            handle: U64::new(handle),
            flags: U32::new(if datasync { fsync_flags::DATASYNC } else { 0 }),
            reserved: U32::ZERO,
        };
        // A durability barrier is not re-issued by the client on its own, so a
        // written attempt that lost its answer fails.
        self.call_interruptible::<_, FsyncResponse, _>(
            caller,
            interrupt,
            node_id,
            &body,
            &[],
            |_, _| Ok(()),
        )
        .await
    }

    pub async fn statfs(&self, caller: Caller, node_id: u64) -> Result<StatfsResponse, Errno> {
        self.call::<_, StatfsResponse, _>(caller, node_id, &StatfsRequest {}, &[], |body, _| {
            Ok(*body)
        })
        .await
    }

    /// What the sink took is the caller's to account for, which the kernel does
    /// for `readdirplus` and nobody does for a plain `readdir`.
    pub async fn readdirplus(
        &self,
        caller: Caller,
        node_id: u64,
        handle: u64,
        cookie: u64,
        size: u32,
        sink: Box<dyn EntrySink>,
    ) -> Listing {
        let body = ReaddirplusRequest {
            handle: U64::new(handle),
            cookie: U64::new(cookie),
            size: U32::new(size),
            reserved: U32::ZERO,
        };
        let piece = self.buffer(Entries::piece_len()).await;
        let request = Outgoing {
            node_id,
            open: OpenFlags::NONE,
            body: &body,
            payload: &[],
            data: &[],
        };
        let (entries, answered) = self
            .exchange(
                caller,
                &Interrupt::none(),
                Opcode::Readdirplus,
                &request,
                Entries::new(piece, sink),
                listing_reply_bound(size),
            )
            .await;
        let (generation, settled) = match answered {
            Ok(Some((connection, answer))) => (
                Some(connection.generation()),
                settle(
                    &entries,
                    streamed::<ReaddirplusResponse>(&connection, &answer),
                ),
            ),
            Ok(None) => (
                None,
                Settled {
                    give_back: Vec::new(),
                    accepted: Vec::new(),
                    outcome: Err(Errno::IO),
                },
            ),
            Err(errno) => (
                None,
                Settled {
                    give_back: Vec::new(),
                    accepted: Vec::new(),
                    outcome: Err(errno),
                },
            ),
        };
        if let Some(generation) = generation {
            for node_id in settled.give_back {
                self.forget_on(caller, generation, node_id, 1).await;
            }
        }
        Listing {
            sink: entries.into_sink(),
            accepted: settled.accepted,
            generation,
            outcome: settled.outcome,
        }
    }

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

    /// `size` is measured in guest bytes, the length of the NUL-separated list
    /// the kernel wants, never in wire bytes.
    ///
    /// # Errors
    ///
    /// `EIO` for a malformed name stream, which poisons the connection.
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

    /// `interrupt` ends a test that waits in the server for another opener of the
    /// file.
    ///
    /// # Errors
    ///
    /// `EBADF` for a handle that did not survive a reconnect, `EINTR` for a test
    /// ended by the interrupt, and `EIO` for a lock type the wire does not
    /// define.
    pub async fn getlk(
        &self,
        caller: Caller,
        interrupt: &Interrupt,
        node_id: u64,
        handle: u64,
        lock: Lock,
    ) -> Result<Lock, Errno> {
        let body = GetlkRequest {
            handle: U64::new(handle),
            lock: lock.wire(),
        };
        self.call_interruptible::<_, GetlkResponse, _>(
            caller,
            interrupt,
            node_id,
            &body,
            &[],
            |body, _| Ok(Lock::of(&body.lock)),
        )
        .await?
        .ok_or(Errno::IO)
    }

    /// `interrupt` ends a request that places a lock and waits in the server, for
    /// the lock or for another opener of the file. It never ends a release, so a
    /// program interrupted while it releases a lock leaves no lock behind.
    ///
    /// # Errors
    ///
    /// `EAGAIN` for a conflict that was not waited for, `EBADF` for a handle that
    /// did not survive a reconnect, and `EINTR` for a request ended by the
    /// interrupt.
    pub async fn setlk(
        &self,
        caller: Caller,
        interrupt: &Interrupt,
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
        let interrupt = match lock.kind {
            LockKind::Unlock => &Interrupt::none(),
            LockKind::Read | LockKind::Write => interrupt,
        };
        self.call_interruptible::<_, SetlkResponse, _>(
            caller,
            interrupt,
            node_id,
            &body,
            &[],
            |_, _| Ok(()),
        )
        .await
    }

    /// Idempotent: a `Subscribe` on an already-subscribed session answers a fresh
    /// snapshot on the same stream, so re-sending one whose reply was lost costs
    /// a snapshot and nothing else.
    ///
    /// # Errors
    ///
    /// `ENOENT` when the namespace has been deleted.
    pub async fn subscribe(&self, caller: Caller) -> Result<(), Errno> {
        self.subscribe_on(caller).await.map(|_| ())
    }

    /// A subscription belongs to the connection that subscribed. The client takes
    /// that connection out of its pool and sends the request on it, so that the
    /// bracket of [`Subscription`](crate::subscribe::Subscription) re-subscribes
    /// exactly when the session or that connection is gone, and never on top of
    /// a subscription that stands.
    ///
    /// # Errors
    ///
    /// As [`Self::subscribe`].
    pub(crate) async fn subscribe_on(&self, caller: Caller) -> Result<(u64, u64), Errno> {
        let body = SubscribeRequest {
            reserved: U32::ZERO,
        };
        loop {
            let pool = self.connected().await?;
            // The sink of the mount is on the connection before the request is,
            // so the snapshot the server sends after its confirm has a
            // receiver.
            let Ok(connection) = pool.subscription().await else {
                self.moved_on_from(&pool).await;
                continue;
            };
            if let Some(sink) = self.notification_route() {
                connection.route_notifications(sink);
            }
            let (ticket, frame) = connection
                .compose(Opcode::Subscribe, OpenFlags::NONE, caller, 0, &body, &[])
                .map_err(|_| Errno::IO)?;
            let (Nothing, outcome) = connection.call(ticket, &frame, &[], Nothing).await;
            match outcome {
                Ok(answer) => {
                    let answered =
                        interpret::<SubscribeResponse, ()>(&connection, &answer.frame, |_, _| {
                            Ok(())
                        });
                    if answered.is_err() {
                        pool.unsubscribed(&connection);
                    }
                    answered?;
                    return Ok((pool.generation(), connection.id()));
                }
                Err(_) => pool.lost(&connection),
            }
        }
    }

    /// A session that is not subscribed answers success, and so does a mount
    /// that is not serving.
    ///
    /// # Errors
    ///
    /// The errno of the server.
    pub async fn unsubscribe(&self, caller: Caller) -> Result<(), Errno> {
        let body = UnsubscribeRequest {
            reserved: U32::ZERO,
        };
        let Some(pool) = self.current() else {
            return Ok(());
        };
        let Some(connection) = pool.subscribed() else {
            return Ok(());
        };
        let (ticket, frame) = connection
            .compose(Opcode::Unsubscribe, OpenFlags::NONE, caller, 0, &body, &[])
            .map_err(|_| Errno::IO)?;
        let (Nothing, outcome) = connection.call(ticket, &frame, &[], Nothing).await;
        let answered = match outcome {
            Ok(answer) => {
                interpret::<UnsubscribeResponse, ()>(&connection, &answer.frame, |_, _| Ok(()))
            }
            Err(_) => {
                pool.lost(&connection);
                Ok(())
            }
        };
        pool.unsubscribed(&connection);
        answered
    }
}

fn length(region: &[u8]) -> Result<u32, Errno> {
    u32::try_from(region.len()).map_err(|_| Errno::OVERFLOW)
}

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
