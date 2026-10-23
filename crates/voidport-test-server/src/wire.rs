use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use rustix::fs::OFlags;
use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::attr::{Attr, EntryOut};
use voidport_proto::frame::{
    FLAG_RESPONSE, FRAME_HEADER_LEN, Frame, FrameKind, FrameWriter, Parsed,
};
use voidport_proto::limits::LIMITS;
use voidport_proto::limits::Limits;
use voidport_proto::message::{
    Follows, RESPONSE_HEAD_LEN, RequestBody, RequestHead, ResponseBody, ResponseOutcome,
};
use voidport_proto::opcode::NotificationOpcode;
use voidport_proto::ops::connection::{
    CancelRequest, OutcomeRequest, OutcomeResponse, RetireRequest, RetireResponse,
};
use voidport_proto::ops::dir::{
    DirEntryHeader, LinkRequest, LinkResponse, MkdirRequest, MkdirResponse, MknodRequest,
    MknodResponse, ReaddirplusRequest, RenameRequest, RenameResponse, RmdirRequest, RmdirResponse,
    SymlinkRequest, SymlinkResponse, UnlinkRequest, UnlinkResponse,
};
use voidport_proto::ops::file::{
    CreateRequest, CreateResponse, FileLock, FlushRequest, FlushResponse, FsyncRequest,
    FsyncResponse, GetlkRequest, GetlkResponse, OpenRequest, OpenResponse, ReadRequest,
    ReleaseRequest, ReleaseResponse, SetlkRequest, SetlkResponse, WriteRequest, WriteResponse,
};
use voidport_proto::ops::handshake::{HelloReply, HelloRequest};
use voidport_proto::ops::node::{
    ForgetRequest, GetattrRequest, GetattrResponse, LookupRequest, LookupResponse, ReadlinkRequest,
    ReadlinkResponse, SetattrRequest, SetattrResponse, StatfsRequest, StatfsResponse,
};
use voidport_proto::ops::recall::{
    Recall, RecalledRequest, RecalledResponse, RelinquishRequest, RelinquishResponse, RenewRequest,
    RenewResponse,
};
use voidport_proto::ops::share::{
    SHARE_KIND_DIRECTORY, SHARE_KIND_FILE, SHARE_KIND_UNKNOWN, SHARE_MODE_RO, SHARE_MODE_RW,
    ShareAdded, ShareChanged, ShareEnded, ShareEntryHeader, ShareRemoved, ShareSnapshotBegin,
    ShareSnapshotEnd,
};
use voidport_proto::ops::subscribe::{
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, UnsubscribeResponse,
};
use voidport_proto::ops::xattr::{
    GetxattrRequest, GetxattrResponse, ListxattrRequest, ListxattrResponse, RemovexattrRequest,
    RemovexattrResponse, SetxattrRequest, SetxattrResponse, XattrNameIter,
};
use voidport_proto::piece::{self, CLOSING_LEN, Closing, ClosingBody, PIECE_LEN_LEN};
use zerocopy::byteorder::little_endian::{U32, U64};

/// No bound on any part, for encoding requests that the server rejects.
const UNBOUNDED: Limits = Limits {
    name_max: u32::MAX,
    path_max: u32::MAX,
    xattr_name_max: u32::MAX,
    xattr_size_max: u32::MAX,
    xattr_list_max: u32::MAX,
};

/// The errnos the tests assert on, as the wire carries them: negated.
pub mod status {
    pub const PERM: i32 = -1;
    pub const NOENT: i32 = -2;
    pub const INTR: i32 = -4;
    pub const IO: i32 = -5;
    pub const BADF: i32 = -9;
    pub const AGAIN: i32 = -11;
    pub const ACCESS: i32 = -13;
    pub const NOTDIR: i32 = -20;
    pub const INVAL: i32 = -22;
    pub const NFILE: i32 = -23;
    pub const MFILE: i32 = -24;
    pub const ROFS: i32 = -30;
    pub const NOSYS: i32 = -38;
    pub const LOOP: i32 = -40;
    pub const NODATA: i32 = -61;
    pub const PROTO: i32 = -71;
    pub const OVERFLOW: i32 = -75;
    pub const STALE: i32 = -116;
    pub const OPNOTSUPP: i32 = -95;
}

pub const ROOT: u64 = 1;

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

impl AsFd for Transport {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Tcp(stream) => stream.as_fd(),
            Self::Unix(stream) => stream.as_fd(),
            Self::Vsock(stream) => stream.as_fd(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub node_id: u64,
    /// The protocol fixes the generation at 0.
    pub generation: u64,
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

    #[must_use]
    pub fn permissions(&self) -> u32 {
        self.attr.mode.get() & 0o7777
    }

    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.attr.mode.get() & 0o170_000 == 0o040_000
    }

    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.attr.mode.get() & 0o170_000 == 0o120_000
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub entry: Entry,
    pub next_cookie: u64,
    pub entry_type: u32,
}

impl DirEntry {
    #[must_use]
    pub fn name(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

#[derive(Clone, Debug)]
pub struct Received {
    pub frame: Vec<u8>,
    pub pieces: Vec<Vec<u8>>,
    pub closing: Option<Closing>,
}

impl Received {
    #[must_use]
    pub fn parsed(&self) -> Frame<'_> {
        Frame::parse(&self.frame, &LIMITS).expect("a well-framed message")
    }
}

#[derive(Debug)]
pub struct WireClient {
    stream: Transport,
    next_request_id: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    token: Vec<u8>,
    connection_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Settled {
    NotStarted,
    Applied,
    Replied(Vec<u8>),
}

impl WireClient {
    pub fn tcp(address: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(address)?;
        // A request held back by Nagle waits for a delayed ACK, which turns a
        // microsecond round trip into forty milliseconds.
        stream.set_nodelay(true)?;
        Ok(Self::new(Transport::Tcp(stream)))
    }

    pub fn unix(path: &Path) -> io::Result<Self> {
        Ok(Self::new(Transport::Unix(UnixStream::connect(path)?)))
    }

    /// Dials the local cid, because the loopback transport connects to a listener on
    /// the wildcard cid.
    pub fn vsock(port: u32) -> io::Result<Self> {
        Ok(Self::new(Transport::Vsock(
            vsock::VsockStream::connect_with_cid_port(vsock::VMADDR_CID_LOCAL, port)?,
        )))
    }

    fn new(stream: Transport) -> Self {
        Self {
            stream,
            next_request_id: 1,
            uid: 0,
            gid: 0,
            pid: 4242,
            token: Vec::new(),
            connection_id: 0,
        }
    }

    #[must_use]
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    #[must_use]
    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }

    pub fn join(&mut self, token: &[u8]) -> Result<HelloReply, i32> {
        self.join_with(token, &[], &[])
    }

    pub fn join_with(
        &mut self,
        token: &[u8],
        namespace: &[u8],
        subpath: &[u8],
    ) -> Result<HelloReply, i32> {
        let body = HelloRequest {
            namespace_len: U32::new(namespace.len() as u32),
            subpath_len: U32::new(subpath.len() as u32),
            ..HelloRequest::join(token.len() as u32)
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(namespace);
        payload.extend_from_slice(subpath);
        payload.extend_from_slice(token);
        let (reply, token) = self
            .call::<_, HelloReply, _>(0, &body, &payload, |body, token| (*body, token.to_vec()))?;
        self.accepted(&reply, token);
        Ok(reply)
    }

    fn accepted(&mut self, reply: &HelloReply, token: Vec<u8>) {
        self.token = token;
        self.connection_id = reply.connection_id.get();
    }

    pub fn outcome(&mut self, connection_id: u64, request_id: u64) -> Result<Settled, i32> {
        let body = OutcomeRequest {
            connection_id: U64::new(connection_id),
            request_id: U64::new(request_id),
        };
        let received = self.exchange(0, &body, &[])?;
        let frame = received.parsed();
        let state = match frame
            .response::<OutcomeResponse>()
            .expect("an outcome reply")
        {
            ResponseOutcome::Success(response) => response.body().state.get(),
            ResponseOutcome::Error(status) => return Err(status),
        };
        let closing = received.closing.expect("an outcome reply streams");
        assert_eq!(closing, Closing::done(false), "the closing piece");
        let kept = received.pieces.concat();
        Ok(match state {
            voidport_proto::ops::connection::outcome_state::NOT_STARTED => {
                assert!(
                    kept.is_empty(),
                    "nothing is kept for a request never started"
                );
                Settled::NotStarted
            }
            voidport_proto::ops::connection::outcome_state::APPLIED => {
                assert!(kept.is_empty(), "nothing is kept for a forget");
                Settled::Applied
            }
            voidport_proto::ops::connection::outcome_state::REPLIED => Settled::Replied(kept),
            other => panic!("an outcome state this protocol does not define: {other}"),
        })
    }

    pub fn retire(&mut self, connection_id: u64) -> Result<(), i32> {
        let body = RetireRequest {
            connection_id: U64::new(connection_id),
        };
        self.call::<_, RetireResponse, _>(0, &body, &[], |_, _| ())
    }

    #[must_use]
    pub fn unread(&self) -> usize {
        let unread = rustix::io::ioctl_fionread(self.stream.as_fd()).expect("the socket's queue");
        usize::try_from(unread).expect("a queue length")
    }

    #[must_use]
    pub fn send_buffer_size(&self) -> usize {
        rustix::net::sockopt::socket_send_buffer_size(self.stream.as_fd())
            .expect("the send buffer size of the socket")
    }

    pub fn shutdown_write(&self) {
        let _ = rustix::net::shutdown(self.stream.as_fd(), rustix::net::Shutdown::Write);
    }

    /// Closes the connection and waits until `server` has dropped its session from
    /// the registry. The server drops a session only after every request read from
    /// its connections has ended.
    pub fn disconnect(self, server: &crate::RunningServer) {
        let token = self.token.clone();
        drop(self);
        let sessions = server.service().sessions();
        server.until(|| {
            !sessions
                .live()
                .iter()
                .any(|session| session.token().as_bytes() == token)
        });
    }

    /// The server reads the requests of a connection in order and applies a forget
    /// before it reads the next request, so any reply to the getattr sent after it
    /// shows that the forget was applied, an error reply included.
    pub fn fence(&mut self) {
        let _ = self.getattr(ROOT);
    }

    pub fn as_user(&mut self, uid: u32, gid: u32) -> &mut Self {
        self.uid = uid;
        self.gid = gid;
        self
    }

    pub fn hello(&mut self, namespace: &str, subpath: &str) -> Result<HelloReply, i32> {
        self.hello_versioned(namespace, subpath, PROTOCOL_VERSION, &[])
    }

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
            token_len: U32::ZERO,
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(namespace);
        payload.extend_from_slice(subpath);
        payload.extend_from_slice(auth);

        let (reply, token) = self
            .call::<_, HelloReply, _>(0, &body, &payload, |body, token| (*body, token.to_vec()))?;
        self.accepted(&reply, token);
        Ok(reply)
    }

    pub fn lookup(&mut self, parent: u64, name: &str) -> Result<Entry, i32> {
        let body = LookupRequest {
            name_len: U32::new(name.len() as u32),
        };
        self.call::<_, LookupResponse, _>(parent, &body, name.as_bytes(), |body, _| {
            Entry::of(&body.entry)
        })
    }

    /// No response comes back. [`Self::fence`] returns once the server applied it.
    pub fn forget(&mut self, node: u64, count: u64) {
        self.forget_counted(node, count);
    }

    /// No response comes back: the effect shows in the reply to the request.
    pub fn cancel(&mut self, request_id: u64) {
        self.send(
            0,
            &CancelRequest {
                request_id: U64::new(request_id),
            },
            &[],
        );
    }

    pub fn forget_counted(&mut self, node: u64, count: u64) -> u64 {
        self.send(
            node,
            &ForgetRequest {
                nlookup: U64::new(count),
            },
            &[],
        )
    }

    pub fn getattr(&mut self, node: u64) -> Result<Attr, i32> {
        let body = GetattrRequest {
            handle: U64::ZERO,
            flags: U32::ZERO,
            reserved: U32::ZERO,
        };
        self.call::<_, GetattrResponse, _>(node, &body, &[], |body, _| body.attr)
    }

    pub fn setattr(&mut self, node: u64, request: SetattrRequest) -> Result<Attr, i32> {
        self.call::<_, SetattrResponse, _>(node, &request, &[], |body, _| body.attr)
    }

    pub fn readlink(&mut self, node: u64) -> Result<Vec<u8>, i32> {
        self.call::<_, ReadlinkResponse, _>(node, &ReadlinkRequest {}, &[], |_, payload| {
            payload.to_vec()
        })
    }

    pub fn statfs(&mut self, node: u64) -> Result<StatfsResponse, i32> {
        self.call::<_, StatfsResponse, _>(node, &StatfsRequest {}, &[], |body, _| *body)
    }

    pub fn open(&mut self, node: u64, flags: OFlags) -> Result<u64, i32> {
        self.open_replying(node, flags).map(|(handle, _)| handle)
    }

    pub fn open_replying(&mut self, node: u64, flags: OFlags) -> Result<(u64, u32), i32> {
        self.call::<_, OpenResponse, _>(node, &open_request(flags), &[], |body, _| {
            (body.handle.get(), body.flags.get())
        })
    }

    pub fn create(
        &mut self,
        parent: u64,
        name: &str,
        flags: OFlags,
        mode: u32,
    ) -> Result<(Entry, u64), i32> {
        let body = CreateRequest {
            flags: U32::new(flags.bits()),
            mode: U32::new(mode),
            umask: U32::ZERO,
            name_len: U32::new(name.len() as u32),
        };
        self.call::<_, CreateResponse, _>(parent, &body, name.as_bytes(), |body, _| {
            (Entry::of(&body.entry), body.handle.get())
        })
    }

    pub fn read(&mut self, handle: u64, offset: u64, size: u32) -> Result<Vec<u8>, i32> {
        let (data, closing) = self.read_closing(handle, offset, size)?;
        match closing.status {
            // Like a client, a read that failed after some pieces returns the
            // bytes it received.
            status if status != 0 && data.is_empty() => Err(status),
            _ => Ok(data),
        }
    }

    pub fn read_closing(
        &mut self,
        handle: u64,
        offset: u64,
        size: u32,
    ) -> Result<(Vec<u8>, Closing), i32> {
        let body = ReadRequest {
            handle: U64::new(handle),
            offset: U64::new(offset),
            size: U32::new(size),
            flags: U32::ZERO,
        };
        let received = self.exchange(0, &body, &[])?;
        let closing = received.closing.expect("a streamed reply");
        Ok((received.pieces.concat(), closing))
    }

    pub fn write(&mut self, handle: u64, offset: u64, data: &[u8]) -> Result<u32, i32> {
        self.write_marked(0, handle, offset, data, 0)
    }

    /// The node id matters only here: the strip that a marked write asks for is
    /// applied to the node that the request head names.
    pub fn write_marked(
        &mut self,
        node: u64,
        handle: u64,
        offset: u64,
        data: &[u8],
        write_flags: u32,
    ) -> Result<u32, i32> {
        let body = WriteRequest {
            handle: U64::new(handle),
            offset: U64::new(offset),
            data_len: U32::new(data.len() as u32),
            flags: U32::ZERO,
            write_flags: U32::new(write_flags),
            reserved: U32::ZERO,
        };
        self.call::<_, WriteResponse, _>(node, &body, data, |body, _| body.written.get())
    }

    pub fn release(&mut self, handle: u64) -> Result<(), i32> {
        let body = ReleaseRequest {
            handle: U64::new(handle),
            lock_owner: U64::ZERO,
            flags: U32::ZERO,
            release_flags: U32::ZERO,
        };
        self.call::<_, ReleaseResponse, _>(0, &body, &[], |_, _| ())
    }

    pub fn flush(&mut self, handle: u64, lock_owner: u64) -> Result<(), i32> {
        let body = FlushRequest {
            handle: U64::new(handle),
            lock_owner: U64::new(lock_owner),
        };
        self.call::<_, FlushResponse, _>(0, &body, &[], |_, _| ())
    }

    pub fn fsync(&mut self, handle: u64, datasync: bool) -> Result<(), i32> {
        let body = FsyncRequest {
            handle: U64::new(handle),
            flags: U32::new(u32::from(datasync)),
            reserved: U32::ZERO,
        };
        self.call::<_, FsyncResponse, _>(0, &body, &[], |_, _| ())
    }

    pub fn readdirplus(
        &mut self,
        node: u64,
        handle: u64,
        cookie: u64,
        size: u32,
    ) -> Result<Vec<DirEntry>, i32> {
        self.readdirplus_page(node, handle, cookie, size)
            .map(|(entries, _)| entries)
    }

    pub fn readdirplus_page(
        &mut self,
        node: u64,
        handle: u64,
        cookie: u64,
        size: u32,
    ) -> Result<(Vec<DirEntry>, bool), i32> {
        let body = ReaddirplusRequest {
            handle: U64::new(handle),
            cookie: U64::new(cookie),
            size: U32::new(size),
            reserved: U32::ZERO,
        };
        let received = self.exchange(node, &body, &[])?;
        let closing = received.closing.expect("a streamed reply");
        if closing.status != 0 {
            // A reply that ends in an errno: every entry it carried counted a
            // lookup, and the receiver gives each back.
            for piece in &received.pieces {
                let item = piece::entry::<DirEntryHeader>(piece, LIMITS.name_max)
                    .expect("one well-formed entry per piece");
                self.forget(item.header.entry.node_id.get(), 1);
            }
            return Err(closing.status);
        }
        let entries = received
            .pieces
            .iter()
            .map(|piece| {
                let item = piece::entry::<DirEntryHeader>(piece, LIMITS.name_max)
                    .expect("one well-formed entry per piece");
                DirEntry {
                    name: item.tail.to_vec(),
                    entry: Entry::of(&item.header.entry),
                    next_cookie: item.header.next_cookie.get(),
                    entry_type: item.header.entry_type().expect("valid entry type") as u32,
                }
            })
            .collect();
        Ok((entries, closing.exhausted))
    }

    pub fn list(&mut self, node: u64) -> Result<Vec<DirEntry>, i32> {
        let handle = self.open(node, OFlags::RDONLY)?;
        let mut entries = Vec::new();
        let mut cookie = 0;
        loop {
            let (batch, exhausted) = self.readdirplus_page(node, handle, cookie, 64 * 1024)?;
            if let Some(last) = batch.last() {
                cookie = last.next_cookie;
            }
            assert!(
                exhausted || !batch.is_empty(),
                "a listing that is not exhausted makes progress"
            );
            entries.extend(batch);
            if exhausted {
                break;
            }
        }
        self.release(handle)?;
        Ok(entries)
    }

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

    /// The kind is in the file-type bits of the mode.
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

    pub fn unlink(&mut self, parent: u64, name: &str) -> Result<(), i32> {
        let body = UnlinkRequest {
            name_len: U32::new(name.len() as u32),
        };
        self.call::<_, UnlinkResponse, _>(parent, &body, name.as_bytes(), |_, _| ())
    }

    pub fn rmdir(&mut self, parent: u64, name: &str) -> Result<(), i32> {
        let body = RmdirRequest {
            name_len: U32::new(name.len() as u32),
        };
        self.call::<_, RmdirResponse, _>(parent, &body, name.as_bytes(), |_, _| ())
    }

    pub fn rename(
        &mut self,
        parent: u64,
        old: &str,
        new_parent: u64,
        new: &str,
    ) -> Result<(), i32> {
        self.rename_with(parent, old, new_parent, new, 0)
    }

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

    pub fn getxattr(&mut self, node: u64, name: &str, size: u32) -> Result<(u32, Vec<u8>), i32> {
        let body = GetxattrRequest {
            size: U32::new(size),
            name_len: U32::new(name.len() as u32),
        };
        self.call::<_, GetxattrResponse, _>(node, &body, name.as_bytes(), |body, payload| {
            (body.size.get(), payload.to_vec())
        })
    }

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

    pub fn removexattr(&mut self, node: u64, name: &str) -> Result<(), i32> {
        let body = RemovexattrRequest {
            name_len: U32::new(name.len() as u32),
        };
        self.call::<_, RemovexattrResponse, _>(node, &body, name.as_bytes(), |_, _| ())
    }

    pub fn getlk(&mut self, handle: u64, lock: FileLock) -> Result<FileLock, i32> {
        let body = GetlkRequest {
            handle: U64::new(handle),
            lock,
        };
        self.call::<_, GetlkResponse, _>(0, &body, &[], |body, _| body.lock)
    }

    pub fn setlk(&mut self, handle: u64, lock: FileLock, wait: bool) -> Result<(), i32> {
        let body = SetlkRequest {
            handle: U64::new(handle),
            lock,
            flags: U32::new(u32::from(wait)),
            reserved: U32::ZERO,
        };
        self.call::<_, SetlkResponse, _>(0, &body, &[], |_, _| ())
    }

    /// The confirm is read here, so what the caller reads next is the first snapshot
    /// frame.
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

    pub fn recalled(&mut self, node: u64, recall: u64) -> Result<(), i32> {
        self.call::<_, RecalledResponse, _>(
            node,
            &RecalledRequest {
                recall: U64::new(recall),
            },
            &[],
            |_, _| (),
        )
    }

    pub fn renew(&mut self) -> Result<(u64, u64), i32> {
        self.call::<_, RenewResponse, _>(0, &RenewRequest::default(), &[], |granted, _| {
            (granted.window_ns.get(), granted.period_ns.get())
        })
    }

    pub fn relinquish(&mut self) -> Result<(), i32> {
        self.call::<_, RelinquishResponse, _>(0, &RelinquishRequest::default(), &[], |_, _| ())
    }

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

    /// Asserts the reserved-class rules: a notification carries `request_id` 0, has
    /// the response flag clear and parses as an ordinary frame.
    pub fn share_event(&mut self) -> ShareNotification {
        let received = self
            .receive_message()
            .expect("the server sends a notification");
        decode_notification(&received)
    }

    pub fn getattr_draining(&mut self, node: u64) -> usize {
        let body = GetattrRequest {
            handle: U64::ZERO,
            flags: U32::ZERO,
            reserved: U32::ZERO,
        };
        let request_id = self.take_request_id();
        let frame = self.encode(request_id, node, &body, &[]);
        self.send_bytes(&frame);
        let mut drained = 0;
        loop {
            let received = self.receive_message().expect("the server answers");
            let parsed = received.parsed();
            if parsed.kind() == FrameKind::Notification {
                drained += 1;
                continue;
            }
            assert_eq!(parsed.request_id(), request_id, "replies echo their id");
            assert!(matches!(
                parsed
                    .response::<GetattrResponse>()
                    .expect("a valid response"),
                ResponseOutcome::Success(_)
            ));
            return drained;
        }
    }

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
        let received = self.exchange(node_id, body, payload)?;
        let frame = received.parsed();
        let ResponseOutcome::Success(response) = frame.response::<R>().expect("a valid response")
        else {
            unreachable!("an error reply was answered by the exchange");
        };
        Ok(extract(response.body(), response.payload()))
    }

    /// The closing piece is left to the caller.
    pub fn exchange<M: RequestBody>(
        &mut self,
        node_id: u64,
        body: &M,
        payload: &[u8],
    ) -> Result<Received, i32> {
        let request_id = self.take_request_id();
        let frame = self.encode(request_id, node_id, body, payload);
        self.send_bytes(&frame);
        let received = self.receive_message().expect("the server answers");
        let parsed = received.parsed();
        assert_eq!(parsed.request_id(), request_id, "replies echo their id");
        let status = parsed.status().expect("a reply");
        if status != 0 {
            return Err(status);
        }
        Ok(received)
    }

    pub fn send<M: RequestBody>(&mut self, node_id: u64, body: &M, payload: &[u8]) -> u64 {
        let request_id = self.take_request_id();
        let frame = self.encode(request_id, node_id, body, payload);
        self.send_bytes(&frame);
        request_id
    }

    pub fn encoded<M: RequestBody>(
        &mut self,
        node_id: u64,
        body: &M,
        payload: &[u8],
    ) -> (u64, Vec<u8>) {
        let request_id = self.take_request_id();
        (request_id, self.encode(request_id, node_id, body, payload))
    }

    pub fn write_request(&mut self, handle: u64, offset: u64, data: &[u8]) -> (u64, Vec<u8>) {
        let body = WriteRequest {
            handle: U64::new(handle),
            offset: U64::new(offset),
            data_len: U32::new(data.len() as u32),
            flags: U32::ZERO,
            write_flags: U32::ZERO,
            reserved: U32::ZERO,
        };
        self.encoded(0, &body, data)
    }

    pub fn receive_written(&mut self) -> (u64, Result<u32, i32>) {
        let received = self.receive_message().expect("the server answers");
        let frame = received.parsed();
        let outcome = match frame
            .response::<WriteResponse>()
            .expect("a valid write reply")
        {
            ResponseOutcome::Success(reply) => Ok(reply.body().written.get()),
            ResponseOutcome::Error(status) => Err(status),
        };
        (frame.request_id(), outcome)
    }

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

    pub fn send_bytes(&mut self, bytes: &[u8]) {
        let _ = self.stream.write_all(bytes);
        let _ = self.stream.flush();
    }

    /// Pieces streamed after the frame are read and dropped.
    pub fn receive(&mut self) -> Option<Vec<u8>> {
        self.receive_message().map(|received| received.frame)
    }

    /// A read that gets neither a reply nor the end of the connection fails the test
    /// instead of returning `None`, so a test asserting that the connection closes
    /// cannot pass on a server that sends nothing.
    pub fn receive_message(&mut self) -> Option<Received> {
        let mut frame = Vec::new();
        let follows = loop {
            let needed = match Frame::parse_prefix(&frame, &LIMITS).expect("a well-framed message")
            {
                Parsed::Frame(parsed) => break parsed.follows(),
                Parsed::Need(needed) => needed,
            };
            let have = frame.len();
            frame.resize(needed, 0);
            self.fill(&mut frame[have..])?;
        };
        let (pieces, closing) = match follows {
            Follows::Pieces(stream) => {
                let mut pieces = Vec::new();
                loop {
                    let mut len = [0u8; PIECE_LEN_LEN];
                    self.fill(&mut len)?;
                    let len = piece::read_length(&len);
                    if len == 0 {
                        let mut body = [0u8; CLOSING_LEN];
                        self.fill(&mut body)?;
                        let closing = ClosingBody::parse(&body).expect("a valid closing piece");
                        break (pieces, Some(closing));
                    }
                    if let Some(bound) = stream.piece_bound(&LIMITS) {
                        assert!(len <= bound, "a piece of {len} bytes is above {bound}");
                    }
                    let mut bytes = vec![0u8; len as usize];
                    self.fill(&mut bytes)?;
                    pieces.push(bytes);
                }
            }
            Follows::Nothing | Follows::Data(_) => (Vec::new(), None),
        };
        Some(Received {
            frame,
            pieces,
            closing,
        })
    }

    fn fill(&mut self, buffer: &mut [u8]) -> Option<()> {
        match self.stream.read_exact(buffer) {
            Ok(()) => Some(()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                panic!("the server neither answered nor closed the connection")
            }
            Err(_) => None,
        }
    }

    pub fn receive_status<R: ResponseBody>(&mut self) -> (u64, i32) {
        let received = self.receive_message().expect("the server answers");
        let frame = received.parsed();
        let status = match frame.response::<R>().expect("a valid response") {
            ResponseOutcome::Success(_) => received.closing.map_or(0, |closing| closing.status),
            ResponseOutcome::Error(status) => status,
        };
        (frame.request_id(), status)
    }

    fn encode<M: RequestBody>(
        &self,
        request_id: u64,
        node_id: u64,
        body: &M,
        payload: &[u8],
    ) -> Vec<u8> {
        let head = RequestHead::new(node_id, self.uid, self.gid, self.pid);
        // A write's data follows its frame on the socket, outside it.
        let data = matches!(body.follows(), Follows::Data(_));
        let mut buffer = vec![0u8; FrameWriter::request_len::<M>(payload.len())];
        let mut writer = FrameWriter::request(&mut buffer, &UNBOUNDED, request_id, &head, body)
            .expect("encodable");
        if !data {
            writer.payload(payload).expect("the payload fits");
        }
        let mut frame = writer.finish().expect("a complete frame").to_vec();
        if data {
            frame.extend_from_slice(payload);
        }
        frame
    }

    fn take_request_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareLine {
    pub path: String,
    pub mode: &'static str,
    pub kind: &'static str,
}

impl ShareLine {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareNotification {
    SnapshotBegin { entries: u32 },
    SnapshotPart(Vec<ShareLine>),
    SnapshotEnd,
    Added(ShareLine),
    Changed(ShareLine),
    Removed(String),
    Ended(u32),
    Recall { node_id: u64, recall: u64 },
}

pub fn decode_notification(received: &Received) -> ShareNotification {
    let frame = received.parsed();
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
            assert_eq!(
                received.closing,
                Some(Closing::done(false)),
                "a snapshot part closes with a zero status and no flag"
            );
            ShareNotification::SnapshotPart(
                received
                    .pieces
                    .iter()
                    .map(|piece| {
                        let entry = piece::entry::<ShareEntryHeader>(piece, LIMITS.path_max - 1)
                            .expect("one well-formed entry per piece");
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
        NotificationOpcode::Recall => {
            let recall = frame.notification::<Recall>().expect("a recall");
            ShareNotification::Recall {
                node_id: recall.body().node_id.get(),
                recall: recall.body().recall.get(),
            }
        }
    }
}

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

#[must_use]
pub fn open_request(flags: OFlags) -> OpenRequest {
    OpenRequest {
        flags: U32::new(flags.bits()),
        reserved: U32::ZERO,
    }
}

#[must_use]
pub fn response_len<M: ResponseBody>() -> usize {
    FRAME_HEADER_LEN + RESPONSE_HEAD_LEN + size_of::<M>()
}
