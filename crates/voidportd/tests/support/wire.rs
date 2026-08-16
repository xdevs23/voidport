//! A data-plane client built on `voidport-proto`, for driving a real server over
//! a real socket.
//!
//! This is test support, not a product: the FUSE client is increment 6. What it
//! owes the tests is exactness — every frame it sends is encoded by the
//! protocol crate, every reply it reads is parsed by it, and nothing about the
//! wire is hand-assembled. Where a test needs to be *wrong* on purpose (a
//! malformed frame, a duplicate request id), it says so through
//! [`WireClient::send_bytes`].
#![allow(dead_code, reason = "the data test file uses part of this")]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::attr::{Attr, EntryOut};
use voidport_proto::frame::{
    FLAG_RESPONSE, FRAME_HEADER_LEN, Frame, FrameKind, FrameWriter, MAX_HELLO_FRAME_LEN,
};
use voidport_proto::message::{
    REQUEST_HEAD_LEN, RESPONSE_HEAD_LEN, RequestBody, RequestHead, ResponseBody, ResponseOutcome,
};
use voidport_proto::opcode::NotificationOpcode;
use voidport_proto::ops::dir::{
    LinkRequest, LinkResponse, MkdirRequest, MkdirResponse, MknodRequest, MknodResponse,
    ReaddirplusRequest, ReaddirplusResponse, RenameRequest, RenameResponse, RmdirRequest,
    RmdirResponse, SymlinkRequest, SymlinkResponse, UnlinkRequest, UnlinkResponse,
};
use voidport_proto::ops::file::{
    CreateRequest, CreateResponse, FileLock, FlushRequest, FlushResponse, FsyncRequest,
    FsyncResponse, GetlkRequest, GetlkResponse, OpenRequest, OpenResponse, ReadRequest,
    ReadResponse, ReleaseRequest, ReleaseResponse, SetlkRequest, SetlkResponse, WriteRequest,
    WriteResponse,
};
use voidport_proto::ops::handshake::{HelloReply, HelloRequest};
use voidport_proto::ops::node::{
    ForgetRequest, GetattrRequest, GetattrResponse, LookupRequest, LookupResponse, ReadlinkRequest,
    ReadlinkResponse, SetattrRequest, SetattrResponse, StatfsRequest, StatfsResponse,
};
use voidport_proto::ops::share::{
    SHARE_KIND_DIRECTORY, SHARE_KIND_FILE, SHARE_KIND_UNKNOWN, SHARE_MODE_RO, SHARE_MODE_RW,
    ShareAdded, ShareChanged, ShareEnded, ShareRemoved, ShareSnapshotBegin, ShareSnapshotEnd,
    ShareSnapshotPart,
};
use voidport_proto::ops::subscribe::{
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, UnsubscribeResponse,
};
use voidport_proto::ops::xattr::{
    GetxattrRequest, GetxattrResponse, ListxattrRequest, ListxattrResponse, RemovexattrRequest,
    RemovexattrResponse, SetxattrRequest, SetxattrResponse, XattrNameIter,
};
use zerocopy::byteorder::little_endian::{U32, U64};

/// The errnos the tests assert on, as the wire carries them: negated.
pub mod status {
    /// `EPERM`.
    pub const PERM: i32 = -1;
    /// `ENOENT`.
    pub const NOENT: i32 = -2;
    /// `EBADF`.
    pub const BADF: i32 = -9;
    /// `EAGAIN`.
    pub const AGAIN: i32 = -11;
    /// `EACCES`.
    pub const ACCESS: i32 = -13;
    /// `ENOTDIR`.
    pub const NOTDIR: i32 = -20;
    /// `EINVAL`.
    pub const INVAL: i32 = -22;
    /// `ENFILE`.
    pub const NFILE: i32 = -23;
    /// `EMFILE`.
    pub const MFILE: i32 = -24;
    /// `EROFS`.
    pub const ROFS: i32 = -30;
    /// `ENOSYS`.
    pub const NOSYS: i32 = -38;
    /// `ELOOP`.
    pub const LOOP: i32 = -40;
    /// `ENODATA`.
    pub const NODATA: i32 = -61;
    /// `EPROTO`.
    pub const PROTO: i32 = -71;
    /// `EOVERFLOW`.
    pub const OVERFLOW: i32 = -75;
    /// `ESTALE`.
    pub const STALE: i32 = -116;
    /// `EOPNOTSUPP`.
    pub const OPNOTSUPP: i32 = -95;
}

/// The node id of a session's mount root.
pub const ROOT: u64 = 1;

/// Whichever stream a session arrived on.
#[derive(Debug)]
enum Transport {
    Tcp(TcpStream),
    Unix(UnixStream),
    Vsock(vsock::VsockStream),
}

impl Read for Transport {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer),
            Self::Unix(stream) => stream.read(buffer),
            Self::Vsock(stream) => stream.read(buffer),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buffer),
            Self::Unix(stream) => stream.write(buffer),
            Self::Vsock(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            Self::Unix(stream) => stream.flush(),
            Self::Vsock(stream) => stream.flush(),
        }
    }
}

impl Transport {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_read_timeout(timeout),
            Self::Unix(stream) => stream.set_read_timeout(timeout),
            Self::Vsock(stream) => stream.set_read_timeout(timeout),
        }
    }
}

/// One entry reply, copied out of the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The node id the server assigned.
    pub node_id: u64,
    /// The generation, which the contract pins to 0.
    pub generation: u64,
    /// The attributes it presented.
    pub attr: Attr,
}

impl Entry {
    fn of(entry: &EntryOut) -> Self {
        Self {
            node_id: entry.node_id.get(),
            generation: entry.generation.get(),
            attr: entry.attr,
        }
    }

    /// The presented permission bits, file type excluded.
    #[must_use]
    pub fn permissions(&self) -> u32 {
        self.attr.mode.get() & 0o7777
    }

    /// Whether the entry presents as a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.attr.mode.get() & 0o170_000 == 0o040_000
    }

    /// Whether the entry presents as a symlink.
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.attr.mode.get() & 0o170_000 == 0o120_000
    }
}

/// One readdirplus entry, copied out of the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's name.
    pub name: Vec<u8>,
    /// Its entry reply.
    pub entry: Entry,
    /// The cookie that resumes after it.
    pub next_cookie: u64,
    /// Its `DT_*` type.
    pub entry_type: u32,
}

impl DirEntry {
    /// The name as text, for readable assertions.
    #[must_use]
    pub fn name(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

/// A data-plane client speaking the real protocol over a real socket.
#[derive(Debug)]
pub struct WireClient {
    stream: Transport,
    max_frame_len: u32,
    next_request_id: u64,
    uid: u32,
    gid: u32,
    pid: u32,
}

impl WireClient {
    /// Connects over TCP, without handshaking.
    pub fn tcp(address: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(address)?;
        // As the server does: a request held back by Nagle waiting for a
        // delayed ACK turns a microsecond round trip into forty milliseconds.
        stream.set_nodelay(true)?;
        Ok(Self::new(Transport::Tcp(stream)))
    }

    /// Connects over a unix socket, without handshaking.
    pub fn unix(path: &Path) -> io::Result<Self> {
        Ok(Self::new(Transport::Unix(UnixStream::connect(path)?)))
    }

    /// Connects over vsock, without handshaking.
    ///
    /// The cid dialled is the *local* one: a listener on the wildcard cid is
    /// reachable from this machine itself through the loopback transport, which
    /// is the only guest a test rig has.
    pub fn vsock(port: u32) -> io::Result<Self> {
        Ok(Self::new(Transport::Vsock(
            vsock::VsockStream::connect_with_cid_port(vsock::VMADDR_CID_LOCAL, port)?,
        )))
    }

    fn new(stream: Transport) -> Self {
        // No test may hang forever on a server that owes it an answer.
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("a settable timeout");
        Self {
            stream,
            max_frame_len: MAX_HELLO_FRAME_LEN,
            next_request_id: 1,
            uid: 0,
            gid: 0,
            pid: 4242,
        }
    }

    /// Serves requests as another guest identity.
    pub fn as_user(&mut self, uid: u32, gid: u32) -> &mut Self {
        self.uid = uid;
        self.gid = gid;
        self
    }

    /// The frame bound the server announced.
    #[must_use]
    pub fn max_frame_len(&self) -> u32 {
        self.max_frame_len
    }

    /// How long a read may block before the test gives up.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) {
        self.stream
            .set_read_timeout(timeout)
            .expect("a settable timeout");
    }

    /// Performs the handshake, adopting the announced frame bound.
    ///
    /// Returns the reply on success, or the negated errno the server refused
    /// with.
    pub fn hello(&mut self, namespace: &str, subpath: &str) -> Result<HelloReply, i32> {
        self.hello_versioned(namespace, subpath, PROTOCOL_VERSION, &[])
    }

    /// The handshake, with the version and auth blob under the test's control.
    pub fn hello_versioned(
        &mut self,
        namespace: &str,
        subpath: &str,
        version: u32,
        auth: &[u8],
    ) -> Result<HelloReply, i32> {
        let namespace = namespace.as_bytes();
        let subpath = subpath.as_bytes();
        let body = HelloRequest {
            protocol_version: U32::new(version),
            flags: U32::ZERO,
            namespace_len: U32::new(namespace.len() as u32),
            subpath_len: U32::new(subpath.len() as u32),
            auth_len: U32::new(auth.len() as u32),
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(namespace);
        payload.extend_from_slice(subpath);
        payload.extend_from_slice(auth);

        let reply = self.call::<_, HelloReply, _>(0, &body, &payload, |body, _| *body)?;
        self.max_frame_len = reply.max_frame_len.get();
        Ok(reply)
    }

    /// Resolves a name in a directory.
    pub fn lookup(&mut self, parent: u64, name: &str) -> Result<Entry, i32> {
        let body = LookupRequest {
            name_len: U32::new(name.len() as u32),
        };
        self.call::<_, LookupResponse, _>(parent, &body, name.as_bytes(), |body, _| {
            Entry::of(&body.entry)
        })
    }

    /// Drops lookup counts. No response comes back.
    pub fn forget(&mut self, node: u64, count: u64) {
        let body = ForgetRequest {
            nlookup: U64::new(count),
        };
        let request_id = self.take_request_id();
        let frame = self.encode(request_id, node, &body, &[]);
        self.send_bytes(&frame);
    }

    /// Reads attributes.
    pub fn getattr(&mut self, node: u64) -> Result<Attr, i32> {
        let body = GetattrRequest {
            handle: U64::ZERO,
            flags: U32::ZERO,
            reserved: U32::ZERO,
        };
        self.call::<_, GetattrResponse, _>(node, &body, &[], |body, _| body.attr)
    }

    /// Changes attributes.
    pub fn setattr(&mut self, node: u64, request: SetattrRequest) -> Result<Attr, i32> {
        self.call::<_, SetattrResponse, _>(node, &request, &[], |body, _| body.attr)
    }

    /// Reads a symlink target.
    pub fn readlink(&mut self, node: u64) -> Result<Vec<u8>, i32> {
        self.call::<_, ReadlinkResponse, _>(node, &ReadlinkRequest {}, &[], |_, payload| {
            payload.to_vec()
        })
    }

    /// Filesystem statistics.
    pub fn statfs(&mut self, node: u64) -> Result<StatfsResponse, i32> {
        self.call::<_, StatfsResponse, _>(node, &StatfsRequest {}, &[], |body, _| *body)
    }

    /// Opens a file or a directory.
    pub fn open(&mut self, node: u64, flags: u32) -> Result<u64, i32> {
        let body = OpenRequest {
            flags: U32::new(flags),
            reserved: U32::ZERO,
        };
        self.call::<_, OpenResponse, _>(node, &body, &[], |body, _| body.handle.get())
    }

    /// Creates and opens a file.
    pub fn create(
        &mut self,
        parent: u64,
        name: &str,
        flags: u32,
        mode: u32,
    ) -> Result<(Entry, u64), i32> {
        let body = CreateRequest {
            flags: U32::new(flags),
            mode: U32::new(mode),
            umask: U32::ZERO,
            name_len: U32::new(name.len() as u32),
        };
        self.call::<_, CreateResponse, _>(parent, &body, name.as_bytes(), |body, _| {
            (Entry::of(&body.entry), body.handle.get())
        })
    }

    /// Reads file data.
    pub fn read(&mut self, handle: u64, offset: u64, size: u32) -> Result<Vec<u8>, i32> {
        let body = ReadRequest {
            handle: U64::new(handle),
            offset: U64::new(offset),
            size: U32::new(size),
            flags: U32::ZERO,
        };
        self.call::<_, ReadResponse, _>(0, &body, &[], |_, payload| payload.to_vec())
    }

    /// Writes file data.
    pub fn write(&mut self, handle: u64, offset: u64, data: &[u8]) -> Result<u32, i32> {
        let body = WriteRequest {
            handle: U64::new(handle),
            offset: U64::new(offset),
            data_len: U32::new(data.len() as u32),
            flags: U32::ZERO,
            write_flags: U32::ZERO,
            reserved: U32::ZERO,
        };
        self.call::<_, WriteResponse, _>(0, &body, data, |body, _| body.written.get())
    }

    /// Releases a handle.
    pub fn release(&mut self, handle: u64) -> Result<(), i32> {
        let body = ReleaseRequest {
            handle: U64::new(handle),
            lock_owner: U64::ZERO,
            flags: U32::ZERO,
            release_flags: U32::ZERO,
        };
        self.call::<_, ReleaseResponse, _>(0, &body, &[], |_, _| ())
    }

    /// Flushes one guest descriptor's close, dropping that owner's locks.
    pub fn flush(&mut self, handle: u64, lock_owner: u64) -> Result<(), i32> {
        let body = FlushRequest {
            handle: U64::new(handle),
            lock_owner: U64::new(lock_owner),
        };
        self.call::<_, FlushResponse, _>(0, &body, &[], |_, _| ())
    }

    /// Syncs a handle.
    pub fn fsync(&mut self, handle: u64, datasync: bool) -> Result<(), i32> {
        let body = FsyncRequest {
            handle: U64::new(handle),
            flags: U32::new(u32::from(datasync)),
            reserved: U32::ZERO,
        };
        self.call::<_, FsyncResponse, _>(0, &body, &[], |_, _| ())
    }

    /// Enumerates a directory.
    pub fn readdirplus(
        &mut self,
        node: u64,
        handle: u64,
        cookie: u64,
        size: u32,
    ) -> Result<Vec<DirEntry>, i32> {
        let body = ReaddirplusRequest {
            handle: U64::new(handle),
            cookie: U64::new(cookie),
            size: U32::new(size),
            reserved: U32::ZERO,
        };
        self.call::<_, ReaddirplusResponse, _>(node, &body, &[], |_, payload| {
            voidport_proto::ops::dir::DirEntryIter::new(payload)
                .map(|item| {
                    let item = item.expect("a well-formed entry stream");
                    DirEntry {
                        name: item.tail.to_vec(),
                        entry: Entry::of(&item.header.entry),
                        next_cookie: item.header.next_cookie.get(),
                        entry_type: item.header.entry_type.get(),
                    }
                })
                .collect()
        })
    }

    /// The whole of a directory, opened and walked to exhaustion.
    pub fn list(&mut self, node: u64) -> Result<Vec<DirEntry>, i32> {
        let handle = self.open(node, 0)?;
        let mut entries = Vec::new();
        let mut cookie = 0;
        loop {
            let batch = self.readdirplus(node, handle, cookie, 64 * 1024)?;
            let Some(last) = batch.last() else {
                break;
            };
            cookie = last.next_cookie;
            entries.extend(batch);
        }
        self.release(handle)?;
        Ok(entries)
    }

    /// Creates a directory.
    pub fn mkdir(&mut self, parent: u64, name: &str, mode: u32) -> Result<Entry, i32> {
        let body = MkdirRequest {
            mode: U32::new(mode),
            umask: U32::ZERO,
            name_len: U32::new(name.len() as u32),
            reserved: U32::ZERO,
        };
        self.call::<_, MkdirResponse, _>(parent, &body, name.as_bytes(), |body, _| {
            Entry::of(&body.entry)
        })
    }

    /// Creates a special file. The kind rides in the mode's file-type bits.
    pub fn mknod(&mut self, parent: u64, name: &str, mode: u32) -> Result<Entry, i32> {
        let body = MknodRequest {
            mode: U32::new(mode),
            umask: U32::ZERO,
            rdev: U32::ZERO,
            name_len: U32::new(name.len() as u32),
        };
        self.call::<_, MknodResponse, _>(parent, &body, name.as_bytes(), |body, _| {
            Entry::of(&body.entry)
        })
    }

    /// Removes a non-directory entry.
    pub fn unlink(&mut self, parent: u64, name: &str) -> Result<(), i32> {
        let body = UnlinkRequest {
            name_len: U32::new(name.len() as u32),
        };
        self.call::<_, UnlinkResponse, _>(parent, &body, name.as_bytes(), |_, _| ())
    }

    /// Removes a directory.
    pub fn rmdir(&mut self, parent: u64, name: &str) -> Result<(), i32> {
        let body = RmdirRequest {
            name_len: U32::new(name.len() as u32),
        };
        self.call::<_, RmdirResponse, _>(parent, &body, name.as_bytes(), |_, _| ())
    }

    /// Renames an entry.
    pub fn rename(
        &mut self,
        parent: u64,
        old: &str,
        new_parent: u64,
        new: &str,
    ) -> Result<(), i32> {
        self.rename_with(parent, old, new_parent, new, 0)
    }

    /// Renames an entry with the wire's rename flags — `RENAME_EXCHANGE` above
    /// all, which moves *both* names at once.
    pub fn rename_with(
        &mut self,
        parent: u64,
        old: &str,
        new_parent: u64,
        new: &str,
        flags: u32,
    ) -> Result<(), i32> {
        let body = RenameRequest {
            new_parent_node_id: U64::new(new_parent),
            flags: U32::new(flags),
            old_name_len: U32::new(old.len() as u32),
            new_name_len: U32::new(new.len() as u32),
            reserved: U32::ZERO,
        };
        let mut payload = old.as_bytes().to_vec();
        payload.extend_from_slice(new.as_bytes());
        self.call::<_, RenameResponse, _>(parent, &body, &payload, |_, _| ())
    }

    /// Creates a hard link.
    pub fn link(&mut self, parent: u64, target: u64, name: &str) -> Result<Entry, i32> {
        let body = LinkRequest {
            target_node_id: U64::new(target),
            name_len: U32::new(name.len() as u32),
            reserved: U32::ZERO,
        };
        self.call::<_, LinkResponse, _>(parent, &body, name.as_bytes(), |body, _| {
            Entry::of(&body.entry)
        })
    }

    /// Creates a symlink.
    pub fn symlink(&mut self, parent: u64, name: &str, target: &str) -> Result<Entry, i32> {
        let body = SymlinkRequest {
            name_len: U32::new(name.len() as u32),
            target_len: U32::new(target.len() as u32),
        };
        let mut payload = name.as_bytes().to_vec();
        payload.extend_from_slice(target.as_bytes());
        self.call::<_, SymlinkResponse, _>(parent, &body, &payload, |body, _| {
            Entry::of(&body.entry)
        })
    }

    /// Reads an extended attribute, or probes its size with `size == 0`.
    pub fn getxattr(&mut self, node: u64, name: &str, size: u32) -> Result<(u32, Vec<u8>), i32> {
        let body = GetxattrRequest {
            size: U32::new(size),
            name_len: U32::new(name.len() as u32),
        };
        self.call::<_, GetxattrResponse, _>(node, &body, name.as_bytes(), |body, payload| {
            (body.size.get(), payload.to_vec())
        })
    }

    /// Sets an extended attribute.
    pub fn setxattr(&mut self, node: u64, name: &str, value: &[u8]) -> Result<(), i32> {
        let body = SetxattrRequest {
            flags: U32::ZERO,
            name_len: U32::new(name.len() as u32),
            value_len: U32::new(value.len() as u32),
            reserved: U32::ZERO,
        };
        let mut payload = name.as_bytes().to_vec();
        payload.extend_from_slice(value);
        self.call::<_, SetxattrResponse, _>(node, &body, &payload, |_, _| ())
    }

    /// Lists extended attribute names, or probes the list size.
    pub fn listxattr(&mut self, node: u64, size: u32) -> Result<(u32, Vec<String>), i32> {
        let body = ListxattrRequest {
            size: U32::new(size),
            reserved: U32::ZERO,
        };
        self.call::<_, ListxattrResponse, _>(node, &body, &[], |body, payload| {
            let names = XattrNameIter::new(payload)
                .map(|item| {
                    String::from_utf8_lossy(item.expect("a well-formed name stream").tail)
                        .into_owned()
                })
                .collect();
            (body.size.get(), names)
        })
    }

    /// Removes an extended attribute.
    pub fn removexattr(&mut self, node: u64, name: &str) -> Result<(), i32> {
        let body = RemovexattrRequest {
            name_len: U32::new(name.len() as u32),
        };
        self.call::<_, RemovexattrResponse, _>(node, &body, name.as_bytes(), |_, _| ())
    }

    /// Tests a lock.
    pub fn getlk(&mut self, handle: u64, lock: FileLock) -> Result<FileLock, i32> {
        let body = GetlkRequest {
            handle: U64::new(handle),
            lock,
        };
        self.call::<_, GetlkResponse, _>(0, &body, &[], |body, _| body.lock)
    }

    /// Places or releases a lock.
    pub fn setlk(&mut self, handle: u64, lock: FileLock, wait: bool) -> Result<(), i32> {
        let body = SetlkRequest {
            handle: U64::new(handle),
            lock,
            flags: U32::new(u32::from(wait)),
            reserved: U32::ZERO,
        };
        self.call::<_, SetlkResponse, _>(0, &body, &[], |_, _| ())
    }

    /// Starts — or restarts — this session's share subscription.
    ///
    /// The confirm is read here, so what the caller reads next is the first
    /// snapshot frame: the ordering the contract fixes is a property this
    /// helper depends on, not one it papers over.
    pub fn subscribe(&mut self) -> Result<(), i32> {
        self.call::<_, SubscribeResponse, _>(
            0,
            &SubscribeRequest {
                reserved: U32::ZERO,
            },
            &[],
            |_, _| (),
        )
    }

    /// Ends this session's share subscription.
    pub fn unsubscribe(&mut self) -> Result<(), i32> {
        self.call::<_, UnsubscribeResponse, _>(
            0,
            &UnsubscribeRequest {
                reserved: U32::ZERO,
            },
            &[],
            |_, _| (),
        )
    }

    /// Reads the next share notification.
    ///
    /// It asserts the reserved-class rules on the way through: a notification
    /// carries `request_id` 0, has the response flag clear, and parses as an
    /// ordinary frame.
    pub fn share_event(&mut self) -> ShareNotification {
        let bytes = self.receive().expect("the server sends a notification");
        decode_notification(&bytes, self.max_frame_len)
    }

    /// The same, giving up after `patience`.
    ///
    /// `None` is "nothing arrived", which is what a test asserting *silence* —
    /// hidden churn, an out-of-scope rule, an unsubscribed session — needs.
    pub fn try_share_event(&mut self, patience: Duration) -> Option<ShareNotification> {
        let bytes = self.try_receive(patience)?;
        Some(decode_notification(&bytes, self.max_frame_len))
    }

    /// One `getattr`, timed, with any share notifications in front of it
    /// drained on the way.
    ///
    /// This is what a *draining* consumer that is also doing file I/O looks
    /// like on one socket: notifications and replies share the stream, so the
    /// reply is found by skipping past whatever the server pushed. The elapsed
    /// time is the request's, measured across exactly that.
    pub fn timed_getattr(&mut self, node: u64) -> (Duration, usize) {
        let body = GetattrRequest {
            handle: U64::ZERO,
            flags: U32::ZERO,
            reserved: U32::ZERO,
        };
        let request_id = self.take_request_id();
        let frame = self.encode(request_id, node, &body, &[]);
        let started = std::time::Instant::now();
        self.send_bytes(&frame);
        let mut drained = 0;
        loop {
            let bytes = self.receive().expect("the server answers");
            let parsed = Frame::parse(&bytes, self.max_frame_len).expect("a well-framed frame");
            if parsed.kind() == FrameKind::Notification {
                drained += 1;
                continue;
            }
            assert_eq!(parsed.request_id(), request_id, "replies echo their id");
            parsed
                .response::<GetattrResponse>()
                .expect("a valid response");
            return (started.elapsed(), drained);
        }
    }

    /// Reads a whole snapshot — begin, parts, end — and returns its entries.
    pub fn share_snapshot(&mut self) -> Vec<ShareLine> {
        let ShareNotification::SnapshotBegin { entries } = self.share_event() else {
            panic!("a snapshot starts with its begin marker");
        };
        let mut lines = Vec::new();
        loop {
            match self.share_event() {
                ShareNotification::SnapshotPart(part) => lines.extend(part),
                ShareNotification::SnapshotEnd => break,
                other => panic!("a snapshot carries only parts until its end, not {other:?}"),
            }
        }
        assert_eq!(
            entries as usize,
            lines.len(),
            "the begin marker counts what the parts carry"
        );
        lines
    }

    /// Sends one request and reads its reply.
    pub fn call<M, R, T>(
        &mut self,
        node_id: u64,
        body: &M,
        payload: &[u8],
        extract: impl FnOnce(&R, &[u8]) -> T,
    ) -> Result<T, i32>
    where
        M: RequestBody,
        R: ResponseBody,
    {
        let request_id = self.take_request_id();
        let frame = self.encode(request_id, node_id, body, payload);
        self.send_bytes(&frame);
        let response = self.receive().expect("the server answers");
        let frame = Frame::parse(&response, self.max_frame_len).expect("a well-framed response");
        assert_eq!(frame.request_id(), request_id, "replies echo their id");
        match frame.response::<R>().expect("a valid response") {
            ResponseOutcome::Success(response) => Ok(extract(response.body(), response.payload())),
            ResponseOutcome::Error(status) => Err(status),
        }
    }

    /// Sends a request without waiting for its reply, returning its id.
    pub fn send<M: RequestBody>(&mut self, node_id: u64, body: &M, payload: &[u8]) -> u64 {
        let request_id = self.take_request_id();
        let frame = self.encode(request_id, node_id, body, payload);
        self.send_bytes(&frame);
        request_id
    }

    /// Sends a request under a caller-chosen id, for the duplicate-id case.
    pub fn send_with_id<M: RequestBody>(
        &mut self,
        request_id: u64,
        node_id: u64,
        body: &M,
        payload: &[u8],
    ) {
        let frame = self.encode(request_id, node_id, body, payload);
        self.send_bytes(&frame);
    }

    /// Writes raw bytes, however malformed.
    pub fn send_bytes(&mut self, bytes: &[u8]) {
        let _ = self.stream.write_all(bytes);
        let _ = self.stream.flush();
    }

    /// Reads one raw frame, or `None` when the server closed the connection.
    ///
    /// A read that neither answers nor closes is a failure, not a `None`: a
    /// test asserting "the connection closes" must not pass because the server
    /// merely went quiet.
    pub fn receive(&mut self) -> Option<Vec<u8>> {
        let mut header = [0u8; FRAME_HEADER_LEN];
        match self.stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                panic!("the server neither answered nor closed the connection")
            }
            Err(_) => return None,
        }
        let len = Frame::peek_len(&header, u32::MAX)
            .expect("a length the header declares")
            .expect("a whole header");
        let mut bytes = vec![0u8; len as usize];
        bytes[..FRAME_HEADER_LEN].copy_from_slice(&header);
        self.stream
            .read_exact(&mut bytes[FRAME_HEADER_LEN..])
            .ok()?;
        Some(bytes)
    }

    /// Reads one raw frame, giving up after `patience`.
    ///
    /// `None` means nothing arrived in time — which is what a test observing
    /// backpressure wants to see, and is deliberately distinct from
    /// [`Self::receive`]'s "the connection closed".
    pub fn try_receive(&mut self, patience: Duration) -> Option<Vec<u8>> {
        self.set_read_timeout(Some(patience));
        let mut header = [0u8; FRAME_HEADER_LEN];
        let read = self.stream.read_exact(&mut header);
        self.set_read_timeout(Some(Duration::from_secs(20)));
        read.ok()?;
        let len = Frame::peek_len(&header, u32::MAX)
            .expect("a length the header declares")
            .expect("a whole header");
        let mut bytes = vec![0u8; len as usize];
        bytes[..FRAME_HEADER_LEN].copy_from_slice(&header);
        self.stream
            .read_exact(&mut bytes[FRAME_HEADER_LEN..])
            .ok()?;
        Some(bytes)
    }

    /// Reads one reply and reports its id and status.
    pub fn receive_status<R: ResponseBody>(&mut self) -> (u64, i32) {
        let bytes = self.receive().expect("the server answers");
        let frame = Frame::parse(&bytes, self.max_frame_len).expect("a well-framed response");
        let status = match frame.response::<R>().expect("a valid response") {
            ResponseOutcome::Success(_) => 0,
            ResponseOutcome::Error(status) => status,
        };
        (frame.request_id(), status)
    }

    /// Encodes one request frame.
    fn encode<M: RequestBody>(
        &self,
        request_id: u64,
        node_id: u64,
        body: &M,
        payload: &[u8],
    ) -> Vec<u8> {
        let head = RequestHead::new(node_id, self.uid, self.gid, self.pid);
        let mut buffer =
            vec![0u8; FRAME_HEADER_LEN + REQUEST_HEAD_LEN + size_of::<M>() + payload.len()];
        let mut writer = FrameWriter::request(&mut buffer, u32::MAX, request_id, &head, body)
            .expect("encodable");
        writer.payload(payload).expect("the payload fits");
        writer.finish().expect("a complete frame").to_vec()
    }

    /// The next request id.
    fn take_request_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        id
    }
}

/// One entry of a share snapshot or delta, as a test reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareLine {
    /// The path, relative to the session's mount root.
    pub path: String,
    /// `rw` or `ro`.
    pub mode: &'static str,
    /// `directory`, `file` or `unknown`.
    pub kind: &'static str,
}

impl ShareLine {
    /// Builds one, for comparing against what the server sent.
    #[must_use]
    pub fn new(path: &str, mode: &'static str, kind: &'static str) -> Self {
        Self {
            path: path.to_owned(),
            mode,
            kind,
        }
    }

    fn of(path: &[u8], mode: u16, kind: u16) -> Self {
        Self {
            path: String::from_utf8(path.to_vec()).expect("the fixture's paths are text"),
            mode: match mode {
                SHARE_MODE_RW => "rw",
                SHARE_MODE_RO => "ro",
                other => panic!("unknown share mode {other}"),
            },
            kind: match kind {
                SHARE_KIND_DIRECTORY => "directory",
                SHARE_KIND_FILE => "file",
                SHARE_KIND_UNKNOWN => "unknown",
                other => panic!("unknown target kind {other}"),
            },
        }
    }
}

/// One share notification, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareNotification {
    /// A snapshot starts; the entries it will carry in total.
    SnapshotBegin {
        /// How many entries the parts carry.
        entries: u32,
    },
    /// One chunk of a snapshot's entries.
    SnapshotPart(Vec<ShareLine>),
    /// The snapshot is complete.
    SnapshotEnd,
    /// An entry the session can now see.
    Added(ShareLine),
    /// An entry whose mode or kind changed.
    Changed(ShareLine),
    /// An entry the session can no longer see.
    Removed(String),
    /// The stream is over.
    Ended(u32),
}

/// Decodes one notification frame, asserting the reserved-class rules.
fn decode_notification(bytes: &[u8], max_frame_len: u32) -> ShareNotification {
    let frame = Frame::parse(bytes, max_frame_len).expect("a well-framed notification");
    assert_eq!(
        frame.kind(),
        FrameKind::Notification,
        "a subscribed session receives notifications, not {:?}",
        frame.kind()
    );
    assert_eq!(
        frame.request_id(),
        0,
        "a notification carries no request id"
    );
    assert_eq!(
        frame.header().flags.get() & FLAG_RESPONSE,
        0,
        "a notification is not a response"
    );
    match frame
        .notification_opcode()
        .expect("a notification this build knows")
    {
        NotificationOpcode::ShareSnapshotBegin => ShareNotification::SnapshotBegin {
            entries: frame
                .notification::<ShareSnapshotBegin>()
                .expect("a begin marker")
                .body()
                .entries
                .get(),
        },
        NotificationOpcode::ShareSnapshotPart => {
            let part = frame
                .notification::<ShareSnapshotPart>()
                .expect("a snapshot part");
            ShareNotification::SnapshotPart(
                part.entries()
                    .map(|entry| {
                        let entry = entry.expect("a well-formed entry");
                        ShareLine::of(entry.tail, entry.header.mode.get(), entry.header.kind.get())
                    })
                    .collect(),
            )
        }
        NotificationOpcode::ShareSnapshotEnd => {
            frame
                .notification::<ShareSnapshotEnd>()
                .expect("an end marker");
            ShareNotification::SnapshotEnd
        }
        NotificationOpcode::ShareAdded => {
            let event = frame.notification::<ShareAdded>().expect("an added event");
            ShareNotification::Added(ShareLine::of(
                event.path(),
                event.body().mode.get(),
                event.body().kind.get(),
            ))
        }
        NotificationOpcode::ShareChanged => {
            let event = frame
                .notification::<ShareChanged>()
                .expect("a changed event");
            ShareNotification::Changed(ShareLine::of(
                event.path(),
                event.body().mode.get(),
                event.body().kind.get(),
            ))
        }
        NotificationOpcode::ShareRemoved => {
            let event = frame
                .notification::<ShareRemoved>()
                .expect("a removed event");
            ShareNotification::Removed(
                String::from_utf8(event.path().to_vec()).expect("the fixture's paths are text"),
            )
        }
        NotificationOpcode::ShareEnded => ShareNotification::Ended(
            frame
                .notification::<ShareEnded>()
                .expect("an ended event")
                .body()
                .reason
                .get(),
        ),
    }
}

/// A whole-file lock description for one wire owner.
#[must_use]
pub fn whole_file_lock(owner: u64, kind: u32) -> FileLock {
    FileLock {
        start: U64::ZERO,
        end: U64::new(u64::MAX),
        owner: U64::new(owner),
        pid: U32::new(7),
        lock_type: U32::new(kind),
    }
}

/// The byte length of a response frame carrying `M` and no payload.
#[must_use]
pub fn response_len<M: ResponseBody>() -> usize {
    FRAME_HEADER_LEN + RESPONSE_HEAD_LEN + size_of::<M>()
}
