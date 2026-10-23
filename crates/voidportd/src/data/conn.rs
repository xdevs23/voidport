//! A thread is held for a host call only, and given back before the request
//! waits for the socket. The reader reads no further request while a request of
//! this connection waits for a thread or a finished reply waits for the sink, so
//! nothing is read that cannot be served.
//!
//! The sink is the writing half of the connection behind one asynchronous lock,
//! and every write through it is made from the asynchronous side, never by a
//! pool thread. The reading half is separate from it, so the two directions
//! share no lock.
//!
//! Stopping ends the reader, the notification task, the lock waits, any request
//! waiting for a thread, a write whose data was still arriving (the pieces
//! already written are not undone), and the write of a reply in flight. Every
//! other request already read runs to its end, and the session stores its
//! reply. The connection waits for every task it started before it leaves its
//! session.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rustix::io::Errno;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpStream, UnixStream, tcp, unix};
use tokio::runtime::Handle;
use tokio::sync::{Notify, watch};
use voidport_memory::Buffer;
use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{FRAME_HEADER_LEN, Frame, FrameHeader, FrameKind, FrameWriter, Parsed};
use voidport_proto::limits::LIMITS;
use voidport_proto::message::{REQUEST_HEAD_LEN, RequestHead};
use voidport_proto::opcode::{Opcode, values};
use voidport_proto::ops::connection::CancelRequest;
use voidport_proto::ops::dir::ReaddirplusRequest;
use voidport_proto::ops::file::{ReadRequest, ReadResponse, WriteRequest, WriteResponse};
use voidport_proto::ops::handshake::{HelloReply, HelloRequest};
use voidport_proto::ops::node::ReadlinkResponse;
use voidport_proto::ops::share::{ShareEntryHeader, ShareSnapshotPart};
use voidport_proto::ops::xattr::{
    GetxattrRequest, GetxattrResponse, ListxattrRequest, ListxattrResponse,
};
use voidport_proto::piece::{self, Closing};
use voidport_session::replay::{self, Settle};
use zerocopy::FromBytes as _;
use zerocopy::byteorder::little_endian::{U32, U64};

use super::handle::FileHandle;
use super::ops::{self, Buffers, Reply, Served};
use super::pool::Thread;
use super::server::DataPlane;
use super::session::{Kept, Left, Link, MountTarget, Peer, Session};
use super::subscribe::{Notice, Wake, encode_entry};
use super::wire::{self, End, Ending, FileSink, FileSource, Out, ReplySink, SocketSource, Threads};
use crate::data::cache::{Postponed, Unserved};
use crate::data::node::ROOT_NODE_ID;
use crate::host::{Io, Transfer};

mod chain;
mod listing;
mod renew;
mod settle;

pub(in crate::data) use chain::Channels;
use listing::list;
use renew::renew;
use settle::settle;

/// Used instead of `tokio::io::split`, whose halves share one lock: the reader
/// and the sink run in different tasks at once, and a read of the socket would
/// wait for a write to it.
pub trait DataStream: Send + 'static {
    type Reader: AsyncRead + Unpin + Send + 'static;
    type Writer: AsyncWrite + Unpin + Send + 'static;

    fn split(self) -> (Self::Reader, Self::Writer);
}

impl DataStream for TcpStream {
    type Reader = tcp::OwnedReadHalf;
    type Writer = tcp::OwnedWriteHalf;

    fn split(self) -> (Self::Reader, Self::Writer) {
        self.into_split()
    }
}

impl DataStream for UnixStream {
    type Reader = unix::OwnedReadHalf;
    type Writer = unix::OwnedWriteHalf;

    fn split(self) -> (Self::Reader, Self::Writer) {
        self.into_split()
    }
}

/// An append the guest declares longer than the most bytes one write call
/// transfers on Linux, `0x7ffff000`, could not reach the host as one call, so it
/// is refused as a malformed frame is.
const WRITE_CALL_MAX: u32 = 0x7fff_f000;

/// A piece of a collected append is made large enough that the whole append
/// fits in this many pieces, the most one vectored host call accepts.
const WRITE_CALL_PIECES: usize = linux_raw_sys::general::UIO_MAXIOV as usize;

/// Every error ends the connection, because a byte stream cannot recover from
/// one.
pub async fn serve<S: DataStream>(stream: S, plane: Arc<DataPlane>, peer: Peer) {
    let transport = peer.transport;
    let address = peer.address.clone();
    if let Err(error) = converse(stream, plane, peer).await {
        tracing::debug!(%error, %transport, peer = %address, "data connection ended");
    }
}

async fn converse<S: DataStream>(stream: S, plane: Arc<DataPlane>, peer: Peer) -> io::Result<()> {
    let (mut reader, mut writer) = stream.split();
    let (request_id, session, link) = match handshake(&mut reader, &plane, &peer).await? {
        Hello::Accepted {
            request_id,
            session,
            link,
        } => (request_id, session, link),
        Hello::Refused { request_id, errno } => {
            if let Ok(reply) = ops::error_reply(request_id, Opcode::Hello, errno) {
                writer.write_all(&reply).await?;
                writer.flush().await?;
            }
            return Ok(());
        }
        Hello::Closed => return Ok(()),
    };

    let result = serve_connection(&plane, &session, &link, request_id, &mut reader, writer).await;
    leave(&plane, &session, &link);
    result
}

fn leave(plane: &DataPlane, session: &Session, link: &Link) {
    // It leaves the session before its end is recorded, so a request waiting for
    // this connection to end finds the session in its final state.
    let left = session.detach(link);
    link.end();
    if let Left::Ended(registration) = left {
        // A request still on a pool thread has a reference to the session too,
        // so the teardown is explicit. The session leaves the registry only after
        // it, and outside the session lock: the registry takes its lock and then
        // the session lock.
        session.teardown();
        drop(registration);
    }
    // A connection ending is when this process frees memory, so a request
    // another connection has parked on the allocator is tried again.
    plane.memory().wake();
}

async fn serve_connection<R, W>(
    plane: &Arc<DataPlane>,
    session: &Arc<Session>,
    link: &Arc<Link>,
    request_id: u64,
    reader: &mut R,
    mut writer: W,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let reply = hello_reply(request_id, link.id(), session.token()).map_err(framing)?;
    writer.write_all(&reply).await?;
    writer.flush().await?;

    let connection = Connection::new(
        plane,
        session,
        link,
        Stream {
            writer: tokio::sync::Mutex::new(writer),
        },
    );
    connection.spawn(notify(Arc::clone(&connection)));
    let result = read_requests(&connection, reader).await;

    connection.close().await;
    result
}

enum Hello {
    Accepted {
        request_id: u64,
        session: Arc<Session>,
        link: Arc<Link>,
    },
    Refused {
        request_id: u64,
        errno: Errno,
    },
    /// Nothing to answer: the peer went away, or its first frame was not a
    /// well-formed `Hello` and names no request to answer.
    Closed,
}

/// The declared lengths of the variable parts are checked before any buffer is
/// made for them, so a hello cannot make the server allocate more than the
/// longest path, namespace name or token it accepts.
async fn handshake<R: AsyncRead + Unpin>(
    reader: &mut R,
    plane: &DataPlane,
    peer: &Peer,
) -> io::Result<Hello> {
    const FIXED: usize = FRAME_HEADER_LEN + REQUEST_HEAD_LEN + size_of::<HelloRequest>();
    let mut bytes = vec![0u8; FIXED];
    if !read_whole(reader, &mut bytes).await? {
        return Ok(Hello::Closed);
    }
    let Ok(header) = FrameHeader::parse(&bytes) else {
        return Ok(Hello::Closed);
    };
    if header.kind() != FrameKind::Request || header.opcode.get() != values::HELLO {
        return Ok(Hello::Closed);
    }
    let request_id = header.request_id.get();
    let Ok((head, rest)) = RequestHead::ref_from_prefix(&bytes[FRAME_HEADER_LEN..]) else {
        return Ok(Hello::Closed);
    };
    if head.reserved.get() != 0 {
        return Ok(Hello::Closed);
    }
    let Ok(body) = HelloRequest::read_from_bytes(rest) else {
        return Ok(Hello::Closed);
    };
    let refuse = |errno| Ok(Hello::Refused { request_id, errno });

    if body.protocol_version.get() != PROTOCOL_VERSION {
        return refuse(Errno::PROTO);
    }
    let joins = body.joins();
    if joins {
        if body.namespace_len.get() != 0 || body.subpath_len.get() != 0 {
            return refuse(Errno::INVAL);
        }
        if body.token_len.get() as usize > plane.signer().longest() {
            return refuse(Errno::NOENT);
        }
    } else {
        if body.token_len.get() != 0 {
            return refuse(Errno::INVAL);
        }
        if body.subpath_len.get() > LIMITS.path_max.saturating_sub(1) {
            return refuse(Errno::NAMETOOLONG);
        }
        if body.namespace_len.get() as usize > plane.longest_namespace() {
            return refuse(Errno::NOENT);
        }
    }
    // This version supports only `auth.mode: none`, which sends an empty blob.
    if body.auth_len.get() != 0 {
        return refuse(Errno::INVAL);
    }
    let regions = body.namespace_len.get() as usize
        + body.subpath_len.get() as usize
        + body.token_len.get() as usize;
    bytes.resize(FIXED + regions, 0);
    if !read_whole(reader, &mut bytes[FIXED..]).await? {
        return Ok(Hello::Closed);
    }
    let Ok(frame) = Frame::parse(&bytes, &LIMITS) else {
        return Ok(Hello::Closed);
    };
    let Ok(request) = frame.request::<HelloRequest>() else {
        return Ok(Hello::Closed);
    };

    if joins {
        let session = match plane.signer().verify(request.token()) {
            Err(refused) => return refuse(refused.errno()),
            Ok(id) => match plane.sessions().get(id) {
                Some(session) => session,
                None => return refuse(Errno::NOENT),
            },
        };
        return Ok(match session.attach(plane.memory()).await {
            Ok(link) => Hello::Accepted {
                request_id,
                session,
                link,
            },
            Err(errno) => Hello::Refused { request_id, errno },
        });
    }

    let Some(name) = std::str::from_utf8(request.namespace())
        .ok()
        .and_then(|name| voidport_control::NamespaceName::new(name).ok())
    else {
        return refuse(Errno::INVAL);
    };
    // One snapshot read for both: a namespace deleted between two reads would
    // hand a session a store the registry no longer names.
    let Some((namespace, Some(records))) = plane.mount_of(&name) else {
        return refuse(Errno::NOENT);
    };
    let subpath = match parse_subpath(request.subpath()) {
        Ok(subpath) => subpath,
        Err(errno) => return refuse(errno),
    };
    let id = match plane.sessions().next_id() {
        Ok(id) => id,
        Err(errno) => return refuse(errno),
    };
    let token = match plane.signer().mint(id) {
        Ok(token) => token,
        Err(errno) => return refuse(errno),
    };
    let session = match Session::mount(
        id,
        token,
        peer.clone(),
        plane.registries(),
        MountTarget {
            namespace,
            records,
            subpath,
        },
        plane.identity(),
    ) {
        Ok(session) => Arc::new(session),
        Err(errno) => return refuse(errno),
    };
    let link = match session.attach(plane.memory()).await {
        Ok(link) => link,
        Err(errno) => return refuse(errno),
    };
    // Registered before the reply is written, so a client that has its reply
    // finds the session in the registry.
    session.hold(plane.sessions().register(Arc::clone(&session)));
    Ok(Hello::Accepted {
        request_id,
        session,
        link,
    })
}

fn hello_reply(request_id: u64, connection_id: u64, token: &str) -> Result<Vec<u8>, FramingError> {
    let token = token.as_bytes();
    let mut buffer = vec![0u8; FrameWriter::response_len::<HelloReply>(token.len())];
    let mut writer = FrameWriter::response(
        &mut buffer,
        &LIMITS,
        request_id,
        &HelloReply {
            root_node_id: U64::new(ROOT_NODE_ID),
            protocol_version: U32::new(PROTOCOL_VERSION),
            flags: U32::ZERO,
            connection_id: U64::new(connection_id),
            token_len: U32::new(
                u32::try_from(token.len()).map_err(|_| FramingError::LengthOverflow)?,
            ),
            reserved: U32::ZERO,
        },
    )?;
    writer.payload(token)?;
    let len = writer.finish()?.len();
    buffer.truncate(len);
    Ok(buffer)
}

fn parse_subpath(raw: &[u8]) -> Result<crate::rules::NamespacePath, Errno> {
    if raw.is_empty() {
        return Ok(crate::rules::NamespacePath::root());
    }
    crate::rules::NamespacePath::parse_bytes(raw).map_err(|_| Errno::INVAL)
}

/// Everything else a request does is the same on both transports, so one
/// connection handles the requests of either.
trait Replies: Send + Sync + 'static {
    const NOTIFIES: bool;

    type Reply<'a>: Out
    where
        Self: 'a;

    fn reply(&self, request_id: u64) -> impl Future<Output = Option<Self::Reply<'_>>> + Send;
}

/// The lock orders whole replies in the order the writers wait for it.
struct Stream<W> {
    writer: tokio::sync::Mutex<W>,
}

impl<W: AsyncWrite + Unpin + Send + 'static> Stream<W> {
    async fn lock(&self) -> Locked<'_, W> {
        Locked(self.writer.lock().await)
    }
}

impl<W: AsyncWrite + Unpin + Send + 'static> Replies for Stream<W> {
    const NOTIFIES: bool = true;

    type Reply<'a> = Locked<'a, W>;

    async fn reply(&self, _request_id: u64) -> Option<Locked<'_, W>> {
        Some(self.lock().await)
    }
}

struct Locked<'a, W>(tokio::sync::MutexGuard<'a, W>);

impl<W: AsyncWrite + Unpin + Send> Out for Locked<'_, W> {
    async fn put(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.write_all(bytes).await
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.0.flush().await
    }
}

struct Connection<P> {
    plane: Arc<DataPlane>,
    session: Arc<Session>,
    link: Arc<Link>,
    replies: P,
    outstanding: Mutex<HashMap<u64, bool>>,
    cancels: Notify,
    tasks: Arc<Tasks>,
    waiting: Arc<Waiting>,
    /// Every host call enters it, so that a task spawned from inside one reaches
    /// it.
    runtime: Handle,
}

#[derive(Default)]
struct Tasks {
    running: AtomicUsize,
    done: Notify,
}

impl Tasks {
    async fn finished(&self) {
        loop {
            let done = self.done.notified();
            if self.running.load(Ordering::SeqCst) == 0 {
                return;
            }
            done.await;
        }
    }
}

struct Running(Arc<Tasks>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.running.fetch_sub(1, Ordering::SeqCst);
        self.0.done.notify_waiters();
    }
}

#[derive(Default)]
struct Waiting {
    /// A read or a listing is counted from the moment it is spawned until its
    /// first thread is granted.
    thread: AtomicUsize,
    sink: AtomicUsize,
    changed: Notify,
}

impl Waiting {
    fn for_thread(self: &Arc<Self>) -> Counted {
        Counted::new(self, |waiting| &waiting.thread)
    }

    fn for_sink(self: &Arc<Self>) -> Counted {
        Counted::new(self, |waiting| &waiting.sink)
    }
}

/// A request is counted before its task is spawned and hands the count to that
/// task, which gives it back on drop.
struct Counted {
    waiting: Arc<Waiting>,
    count: fn(&Waiting) -> &AtomicUsize,
}

impl Counted {
    fn new(waiting: &Arc<Waiting>, count: fn(&Waiting) -> &AtomicUsize) -> Self {
        count(waiting).fetch_add(1, Ordering::SeqCst);
        Self {
            waiting: Arc::clone(waiting),
            count,
        }
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        (self.count)(&self.waiting).fetch_sub(1, Ordering::SeqCst);
        self.waiting.changed.notify_waiters();
    }
}

struct Held<'a, P: Replies> {
    reply: P::Reply<'a>,
    stopped: watch::Receiver<bool>,
}

impl<P: Replies> Out for Held<'_, P> {
    async fn put(&mut self, bytes: &[u8]) -> io::Result<()> {
        tokio::select! {
            biased;
            _ = self.stopped.wait_for(|stopped| *stopped) => {
                Err(io::Error::other("the connection is stopping"))
            }
            written = self.reply.put(bytes) => written,
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.reply.flush().await
    }
}

impl<P: Replies> Connection<P> {
    fn new(
        plane: &Arc<DataPlane>,
        session: &Arc<Session>,
        link: &Arc<Link>,
        replies: P,
    ) -> Arc<Self> {
        Arc::new(Self {
            plane: Arc::clone(plane),
            session: Arc::clone(session),
            link: Arc::clone(link),
            replies,
            outstanding: Mutex::default(),
            cancels: Notify::new(),
            tasks: Arc::default(),
            waiting: Arc::default(),
            runtime: Handle::current(),
        })
    }

    /// Stopping first makes the close prompt: a reply in flight abandons its
    /// write, and every task waiting for a thread or for the place of its reply
    /// stops waiting.
    async fn close(&self) {
        self.stop();
        self.tasks.finished().await;
    }

    fn stop(&self) {
        self.link.stop();
    }

    fn stopped(&self) -> watch::Receiver<bool> {
        self.link.stopped()
    }

    /// The copy is a required allocation made through the memory crate: it parks
    /// until the host gives it, and the connection stopping does not end the
    /// wait, because the reply must be kept either way.
    async fn keep_reply(&self, request_id: u64, reply: &[u8]) {
        let mut kept = self.plane.memory().buffer(reply.len(), 1).await;
        kept.copy_from_slice(reply);
        self.link.keep(request_id, Kept::Replied(Arc::new(kept)));
    }

    /// A client asking about the request would otherwise be told it never
    /// started, and send it again.
    fn unkept(&self) {
        tracing::error!(
            session = self.session.id(),
            "a reply could not be kept whole; the session ends"
        );
        self.session.end();
    }

    fn poison(&self, error: &FramingError) {
        tracing::debug!(%error, "closing a data connection on a framing error");
        self.stop();
    }

    fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        self.tasks.running.fetch_add(1, Ordering::SeqCst);
        let running = Running(Arc::clone(&self.tasks));
        tokio::spawn(async move {
            task.await;
            drop(running);
        });
    }

    async fn sink(&self, request_id: u64) -> Result<Held<'_, P>, End> {
        self.held(self.replies.reply(request_id)).await
    }

    async fn held<'a>(
        &'a self,
        reply: impl Future<Output = Option<P::Reply<'a>>>,
    ) -> Result<Held<'a, P>, End> {
        let _waiting = self.waiting.for_sink();
        let mut stopped = self.stopped();
        tokio::select! {
            biased;
            _ = stopped.wait_for(|stopped| *stopped) => Err(End::stopping()),
            reply = reply => reply
                .map(|reply| Held {
                    reply,
                    stopped: self.stopped(),
                })
                .ok_or_else(End::stopping),
        }
    }

    async fn buffer(&self, len: usize, alignment: usize) -> Result<Buffer, End> {
        let mut stopped = self.stopped();
        tokio::select! {
            biased;
            _ = stopped.wait_for(|stopped| *stopped) => Err(End::stopping()),
            buffer = self.plane.memory().buffer(len, alignment) => Ok(buffer),
        }
    }

    async fn servable(&self) {
        let mut stopped = self.stopped();
        loop {
            let changed = self.waiting.changed.notified();
            if self.waiting.thread.load(Ordering::SeqCst) == 0
                && self.waiting.sink.load(Ordering::SeqCst) == 0
            {
                return;
            }
            tokio::select! {
                biased;
                _ = stopped.wait_for(|stopped| *stopped) => return,
                () = changed => {}
            }
        }
    }

    /// A `forget` retires the moment its frame is accepted, so its id is never
    /// tracked here.
    fn track(&self, opcode: Opcode, request_id: u64) -> Result<(), FramingError> {
        if !opcode.has_response() {
            return Ok(());
        }
        match self.outstanding().entry(request_id) {
            Entry::Vacant(entry) => {
                entry.insert(false);
                Ok(())
            }
            Entry::Occupied(_) => Err(FramingError::DuplicateRequestId { request_id }),
        }
    }

    fn cancel(&self, request_id: u64) {
        if let Some(cancelled) = self.outstanding().get_mut(&request_id) {
            *cancelled = true;
            self.cancels.notify_waiters();
        }
    }

    async fn cancelled(&self, request_id: u64) {
        loop {
            let named = self.cancels.notified();
            tokio::pin!(named);
            named.as_mut().enable();
            if self.outstanding().get(&request_id) == Some(&true) {
                return;
            }
            named.await;
        }
    }

    fn outstanding(&self) -> MutexGuard<'_, HashMap<u64, bool>> {
        self.outstanding
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// A client may reuse an id only once it has the whole reply, so an id
    /// retires with the closing piece, or with the whole of a one-piece reply.
    /// It retires as that last write is issued and not after it returns: a
    /// client that has the reply may reuse the id at once, and a reader that
    /// saw the reuse before this retirement would end an innocent connection
    /// over a duplicate id. A write that then fails ends the connection.
    fn retire(&self, request_id: u64) {
        self.outstanding().remove(&request_id);
    }

    async fn answer(&self, request_id: u64, reply: &[u8]) {
        let Ok(mut sink) = self.sink(request_id).await else {
            return;
        };
        self.retire(request_id);
        if sink.put(reply).await.is_err() || sink.flush().await.is_err() {
            self.stop();
        }
    }

    async fn refuse(&self, request_id: u64, opcode: Opcode, errno: Errno) {
        match ops::error_reply(request_id, opcode, errno) {
            Ok(reply) => self.answer(request_id, &reply).await,
            Err(error) => self.poison(&error),
        }
    }
}

impl<P: Replies> Threads for Connection<P> {
    async fn thread(&self) -> Result<Thread, End> {
        self.acquire(self.waiting.for_thread()).await
    }
}

impl<P: Replies> Connection<P> {
    /// The connection stopping does not end the wait.
    async fn thread_to_end(&self) -> Result<Thread, End> {
        let _waiting = self.waiting.for_thread();
        self.plane
            .pool()
            .acquire()
            .await
            .map_err(|_| End::stopping())
    }

    /// The count is given back once the thread is granted or the connection
    /// stops.
    async fn acquire(&self, _waiting: Counted) -> Result<Thread, End> {
        let mut stopped = self.stopped();
        tokio::select! {
            biased;
            _ = stopped.wait_for(|stopped| *stopped) => Err(End::stopping()),
            thread = self.plane.pool().acquire() => thread.map_err(|_| End::stopping()),
        }
    }
}

/// It ends at the end of the stream, on a framing error, and when the
/// connection stops for any other reason.
async fn read_requests<R, P>(connection: &Arc<Connection<P>>, reader: &mut R) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send,
    P: Replies,
{
    let mut stopped = connection.stopped();
    loop {
        connection.servable().await;
        if *stopped.borrow() {
            return Ok(());
        }
        let message = tokio::select! {
            biased;
            _ = stopped.wait_for(|stopped| *stopped) => return Ok(()),
            message = read_request(reader) => message?,
        };
        let Some(bytes) = message else {
            return Ok(());
        };
        if !dispatch(connection, &mut *reader, bytes).await? {
            return Ok(());
        }
    }
}

fn ahead<T>(served: Result<T, Unserved>) -> Result<Result<T, Errno>, Postponed> {
    match served {
        Ok(value) => Ok(Ok(value)),
        Err(Unserved::Failed(errno)) => Ok(Err(errno)),
        Err(Unserved::Postponed(postponed)) => Err(postponed),
    }
}

fn reading(file: &Result<Arc<FileHandle>, Errno>) -> Result<Io, Unserved> {
    file.as_ref()
        .map_err(|errno| Unserved::Failed(*errno))?
        .reading()
}

fn writing(file: &Result<Arc<FileHandle>, Errno>) -> Result<Io, Unserved> {
    file.as_ref()
        .map_err(|errno| Unserved::Failed(*errno))?
        .writing()
}

/// `None` once the connection stops first: the request never started. `EINTR`
/// once a `cancel` for the request arrives first, which ends it unapplied.
async fn until_ahead<P: Replies>(
    connection: &Connection<P>,
    request_id: u64,
    postponed: &Postponed,
) -> Option<Result<(), Errno>> {
    let mut stopped = connection.stopped();
    tokio::select! {
        biased;
        _ = stopped.wait_for(|stopped| *stopped) => None,
        () = connection.cancelled(request_id) => Some(Err(Errno::INTR)),
        ended = postponed.ended() => Some(ended),
    }
}

/// A request the cache delays again waits again. `EINTR` once a `cancel` for
/// the request arrives first, and `None` once the connection stops first.
async fn go_ahead<P: Replies>(
    connection: &Connection<P>,
    request_id: u64,
    mut postponed: Postponed,
    open: impl Fn() -> Result<Io, Unserved>,
) -> Option<Result<Io, Errno>> {
    loop {
        let ended = until_ahead(connection, request_id, &postponed).await?;
        match ahead(ended.map_err(Unserved::Failed).and_then(|()| open())) {
            Ok(io) => return Some(io),
            Err(again) => postponed = again,
        }
    }
}

/// A read that waits for the cache is not counted as waiting for a thread
/// meanwhile: the reader goes on, and the reply to a recall or a request of
/// another handle is handled.
enum Reading {
    Ahead(Result<Io, Errno>, Counted),
    Postponed(Result<Arc<FileHandle>, Errno>, Postponed),
}

impl Reading {
    fn of<P: Replies>(connection: &Connection<P>, file: Result<Arc<FileHandle>, Errno>) -> Self {
        match ahead(reading(&file)) {
            Ok(io) => Self::Ahead(io, connection.waiting.for_thread()),
            Err(postponed) => Self::Postponed(file, postponed),
        }
    }

    /// `None` once the connection stops first: the read never started.
    async fn ahead<P: Replies>(
        self,
        connection: &Connection<P>,
        request_id: u64,
    ) -> Option<(Result<Io, Errno>, Counted)> {
        match self {
            Self::Ahead(io, waiting) => Some((io, waiting)),
            Self::Postponed(file, postponed) => {
                let io = go_ahead(connection, request_id, postponed, || reading(&file)).await?;
                Some((io, connection.waiting.for_thread()))
            }
        }
    }
}

/// A byte stream reads the data of a write from the stream and sends the data
/// of a read reply in pieces through the sink; a descriptor chain has the data
/// of a write after the frame and room for the data of a read reply in its data
/// area.
trait Source<P: Replies>: Send {
    const SPAWNS: bool;

    fn write(
        self,
        connection: &Arc<Connection<P>>,
        bytes: &[u8],
    ) -> impl Future<Output = io::Result<bool>> + Send;

    fn read(
        &self,
        connection: &Arc<Connection<P>>,
        bytes: Vec<u8>,
        reading: Reading,
    ) -> impl Future<Output = ()> + Send + 'static;
}

impl<R, P> Source<P> for &mut R
where
    R: AsyncRead + Unpin + Send,
    P: Replies,
{
    const SPAWNS: bool = true;

    async fn write(self, connection: &Arc<Connection<P>>, bytes: &[u8]) -> io::Result<bool> {
        write(connection, self, bytes).await
    }

    fn read(
        &self,
        connection: &Arc<Connection<P>>,
        bytes: Vec<u8>,
        reading: Reading,
    ) -> impl Future<Output = ()> + Send + 'static {
        read(Arc::clone(connection), bytes, reading)
    }
}

async fn start<P: Replies, S: Source<P>>(
    connection: &Arc<Connection<P>>,
    task: impl Future<Output = ()> + Send + 'static,
) {
    if S::SPAWNS {
        connection.spawn(task);
    } else {
        task.await;
    }
}

/// The requests of the connection start in the order they are dispatched. A
/// `forget` is recorded as read once it is applied: a forget the stop cut off
/// before it ran was never read.
async fn dispatch<P, S>(
    connection: &Arc<Connection<P>>,
    source: S,
    bytes: Vec<u8>,
) -> io::Result<bool>
where
    P: Replies,
    S: Source<P>,
{
    let frame = Frame::parse(&bytes, &LIMITS).map_err(framing)?;
    let request_id = frame.request_id();
    let opcode = frame
        .opcode()
        .map_err(|unknown| framing(FramingError::UnknownOpcode { opcode: unknown.0 }))?;
    connection.track(opcode, request_id).map_err(framing)?;
    if opcode.has_response() {
        connection.link.read(request_id, keeps(opcode));
    }
    match opcode {
        Opcode::Write => return source.write(connection, &bytes).await,
        // A started request is counted as waiting for a thread before its task
        // exists, so a reader that waits until no request does cannot read the
        // next one before this one is counted. The handle a read gives, and the
        // directory and handle a listing gives, are resolved here, so a request
        // read after it cannot change what it works on.
        Opcode::Read => {
            let file = frame
                .request::<ReadRequest>()
                .map_err(framing)
                .map(|request| {
                    ops::file::file_of(&connection.session, request.body().handle.get())
                })?;
            let task = source.read(connection, bytes, Reading::of(connection, file));
            start::<P, S>(connection, task).await;
        }
        Opcode::Readdirplus => {
            let named = frame
                .request::<ReaddirplusRequest>()
                .map_err(framing)
                .map(|request| ops::dir::listing(&connection.session, &request))?;
            let waiting = connection.waiting.for_thread();
            let task = list(Arc::clone(connection), bytes, named, waiting);
            start::<P, S>(connection, task).await;
        }
        Opcode::Forget => return forget(connection, bytes, request_id).await,
        // It ends a request of this connection, read before it, that waits, and
        // has no reply.
        Opcode::Cancel => {
            let cancel = frame.request::<CancelRequest>().map_err(framing)?;
            connection.cancel(cancel.body().request_id.get());
        }
        // They wait for another connection of the session to end, which has no
        // thread, so they wait as tasks.
        Opcode::Outcome | Opcode::Retire => {
            let task = settle(Arc::clone(connection), bytes, opcode);
            start::<P, S>(connection, task).await;
        }
        Opcode::Renew => {
            let task = renew(Arc::clone(connection), bytes);
            start::<P, S>(connection, task).await;
        }
        Opcode::Subscribe if !P::NOTIFIES => {
            connection
                .refuse(request_id, opcode, Errno::OPNOTSUPP)
                .await;
        }
        _ => {
            // The buffers the operation fills are made first, which may park on
            // the allocator, and then its thread is acquired; the reader waits
            // for both.
            let Ok(buffers) = buffers_for(connection, &frame).await else {
                return Ok(false);
            };
            // A request whose reply is kept runs to its end once read, whether
            // or not the connection stops meanwhile.
            let thread = if keeps(opcode) {
                connection.thread_to_end().await
            } else {
                connection.thread().await
            };
            let Ok(thread) = thread else {
                return Ok(false);
            };
            let task = serve_plain(
                Arc::clone(connection),
                bytes,
                buffers,
                thread,
                request_id,
                opcode,
            );
            start::<P, S>(connection, task).await;
        }
    }
    Ok(true)
}

fn keeps(opcode: Opcode) -> bool {
    opcode.has_response() && replay::settle(opcode) == Settle::Ask
}

async fn forget<P: Replies>(
    connection: &Arc<Connection<P>>,
    bytes: Vec<u8>,
    request_id: u64,
) -> io::Result<bool> {
    let Ok(mut thread) = connection.thread().await else {
        return Ok(false);
    };
    let session = Arc::clone(&connection.session);
    let runtime = connection.runtime.clone();
    let served = thread
        .run(move || {
            let _runtime = runtime.enter();
            ops::serve(&session, &bytes, Buffers::default())
        })
        .await;
    drop(thread);
    match served {
        Ok(Ok(_)) => {
            connection.link.read(request_id, false);
            Ok(true)
        }
        Ok(Err(error)) => Err(framing(error)),
        Err(_) => {
            tracing::error!("a forget failed");
            Ok(false)
        }
    }
}

/// `Ok(None)` is end of stream on a frame boundary, or a header that stopped
/// half way, which is a client that went away mid-write and not a protocol
/// fault.
async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = vec![0u8; FRAME_HEADER_LEN];
    if !read_whole(reader, &mut bytes).await? {
        return Ok(None);
    }
    let header = FrameHeader::parse(&bytes).map_err(framing)?;
    if header.kind() != FrameKind::Request {
        return Err(framing(FramingError::UnexpectedFrameKind {
            expected: FrameKind::Request,
            found: header.kind(),
        }));
    }
    // A session accepts exactly one handshake, and it has been read: a second is
    // a framing error before a byte of its body is read.
    if header.opcode.get() == values::HELLO {
        return Err(framing(FramingError::RepeatedHandshake));
    }
    loop {
        match Frame::parse_prefix(&bytes, &LIMITS).map_err(framing)? {
            Parsed::Frame(_) => return Ok(Some(bytes)),
            Parsed::Need(needed) => {
                let have = bytes.len();
                bytes.resize(needed, 0);
                reader.read_exact(&mut bytes[have..]).await?;
            }
        }
    }
}

async fn read_whole<R: AsyncRead + Unpin>(reader: &mut R, buffer: &mut [u8]) -> io::Result<bool> {
    match reader.read_exact(buffer).await {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

/// The reply buffers of a link target, an attribute value and an attribute name
/// list, and the buffer for the name list read from the host.
async fn buffers_for<P: Replies>(
    connection: &Connection<P>,
    frame: &Frame<'_>,
) -> Result<Buffers, End> {
    let reply = |payload| async move { connection.buffer(payload, 1).await.map(Some) };
    Ok(match frame.opcode() {
        Ok(Opcode::Readlink) => Buffers {
            reply: reply(FrameWriter::response_len::<ReadlinkResponse>(
                LIMITS.path_max as usize,
            ))
            .await?,
            list: None,
        },
        Ok(Opcode::Getxattr) => {
            let size = frame
                .request::<GetxattrRequest>()
                .map_or(0, |request| request.body().size.get());
            Buffers {
                reply: if size == 0 {
                    None
                } else {
                    reply(FrameWriter::response_len::<GetxattrResponse>(
                        size.min(LIMITS.xattr_size_max) as usize,
                    ))
                    .await?
                },
                list: None,
            }
        }
        Ok(Opcode::Listxattr) => {
            let size = frame
                .request::<ListxattrRequest>()
                .map_or(0, |request| request.body().size.get());
            // A stream of names has a header per name where the list from the
            // kernel has a terminator, so it is at most that many times the size
            // of the list.
            let stream = size.min(LIMITS.xattr_list_max) as usize
                * size_of::<voidport_proto::ops::xattr::XattrNameHeader>();
            Buffers {
                reply: reply(FrameWriter::response_len::<ListxattrResponse>(stream)).await?,
                list: Some(connection.buffer(LIMITS.xattr_list_max as usize, 1).await?),
            }
        }
        _ => Buffers::default(),
    })
}

/// A handler that unwinds, or that finds a framing error, stops the connection:
/// the client is waiting for an answer that can never come.
async fn serve_plain<P: Replies>(
    connection: Arc<Connection<P>>,
    mut bytes: Vec<u8>,
    mut buffers: Buffers,
    mut thread: Thread,
    request_id: u64,
    opcode: Opcode,
) {
    // Kept until the request is served again: an open that waited to widen the
    // description of the session delays the lease until then.
    let mut waited = None;
    let served = loop {
        let session = Arc::clone(&connection.session);
        let runtime = connection.runtime.clone();
        let handed = std::mem::take(&mut buffers);
        let served = thread
            .run(move || {
                let _runtime = runtime.enter();
                let served = ops::serve(&session, &bytes, handed);
                (served, bytes)
            })
            .await;
        drop(thread);
        // A request whose reply is stored may have run before its handler
        // failed, and it has nothing to store.
        let served = match served {
            Ok((Ok(served), served_bytes)) => {
                bytes = served_bytes;
                served
            }
            Ok((Err(_), _)) if keeps(opcode) => return connection.unkept(),
            Ok((Err(error), _)) => return connection.poison(&error),
            Err(_) => {
                tracing::error!(%opcode, "a request handler failed");
                if keeps(opcode) {
                    return connection.unkept();
                }
                return connection.stop();
            }
        };
        drop(waited.take());
        let Served::Postponed(postponed) = served else {
            break served;
        };
        // The wait is a future, as a lock wait is: a connection that stops
        // meanwhile ends it, and the request never started.
        let ended = until_ahead(&connection, request_id, &postponed).await;
        if let Some(Err(errno)) = ended {
            match ops::error_reply(request_id, opcode, errno) {
                Ok(reply) => break Served::Reply(Reply::Frame(reply)),
                Err(error) => return connection.poison(&error),
            }
        }
        let again = if keeps(opcode) {
            connection.thread_to_end().await
        } else {
            connection.thread().await
        };
        let (Some(_), Ok(again)) = (ended, again) else {
            if keeps(opcode) {
                connection.link.keep(request_id, Kept::NotStarted);
            }
            return;
        };
        thread = again;
        waited = Some(postponed);
    };
    match served {
        Served::Reply(reply) => {
            if keeps(opcode) {
                connection.keep_reply(request_id, reply.bytes()).await;
            }
            connection.answer(request_id, reply.bytes()).await;
        }
        Served::Silent => {}
        Served::Subscribed(reply) => {
            // The subscription is registered, and so shown in the session list,
            // before its confirm is written. Registering it queues the snapshot,
            // which the notification task writes through the same sink, so
            // holding the sink from before the registration until the confirm is
            // flushed puts the snapshot behind the confirm.
            let Ok(mut sink) = connection.sink(request_id).await else {
                return;
            };
            // A connection that closed meanwhile is never registered, and its
            // confirm would confirm nothing.
            if !connection.session.subscribe(&connection.link) {
                return connection.stop();
            }
            connection.retire(request_id);
            if sink.put(reply.bytes()).await.is_err() || sink.flush().await.is_err() {
                connection.stop();
            }
        }
        Served::Postponed(_) => unreachable!("served again above"),
        Served::Waiting(wait) => {
            // Dropping the wait cancels it where a blocking SETLKW would have
            // held a pool thread until the holder let go. The grant and the close
            // are ordered by the link of the connection, so a wait still waiting
            // when the close is recorded never takes the lock and never started,
            // and a lock granted before it runs to its end. A cancel ends a wait
            // that has not obtained the lock, with `EINTR`.
            let mut stopped = connection.stopped();
            let settled = tokio::select! {
                biased;
                _ = stopped.wait_for(|stopped| *stopped) => None,
                () = connection.cancelled(request_id) => {
                    Some(ops::error_reply(request_id, opcode, Errno::INTR))
                }
                settled = wait.settle(&connection.link) => settled,
            };
            let Some(settled) = settled else {
                return connection.link.keep(request_id, Kept::NotStarted);
            };
            match settled {
                Ok(reply) => {
                    connection.keep_reply(request_id, &reply).await;
                    connection.answer(request_id, &reply).await;
                }
                Err(_) => connection.unkept(),
            }
        }
    }
}

/// No byte of the file is read while the sink cannot take it, and no piece is
/// kept after it is written. While one read of a connection is in flight, the
/// other replies of that connection wait behind it.
async fn read<P: Replies>(connection: Arc<Connection<P>>, bytes: Vec<u8>, reading: Reading) {
    let Ok(frame) = Frame::parse(&bytes, &LIMITS) else {
        return connection.stop();
    };
    let request = match frame.request::<ReadRequest>() {
        Ok(request) => request,
        Err(error) => return connection.poison(&error),
    };
    let (request_id, offset, size) = (
        frame.request_id(),
        request.body().offset.get(),
        request.body().size.get(),
    );
    let Some((file, waiting)) = reading.ahead(&connection, request_id).await else {
        return;
    };
    let file = match file {
        Ok(file) => file,
        Err(errno) => return connection.refuse(request_id, Opcode::Read, errno).await,
    };
    let transfer = file.transfer();
    let Ok(buffer) = connection
        .buffer(transfer.piece_len(), transfer.memory_alignment())
        .await
    else {
        return;
    };
    let Ok(mut sink) = connection.sink(request_id).await else {
        return;
    };
    let Ok(mut reply) = ReplySink::new::<ReadResponse>(&mut sink, request_id) else {
        return connection.stop();
    };
    let Ok(first) = connection.acquire(waiting).await else {
        return;
    };
    let mut source = FileSource::new(&*connection, first, file, offset);
    let carried = wire::carry(
        &mut source,
        &mut [],
        &mut reply,
        buffer,
        u64::from(size),
        |_, rest| wire::cut(transfer.piece_len(), rest, transfer.offset_alignment()),
    )
    .await;
    // The piece buffer goes back to the allocator before the closing piece, and
    // so does a first thread a read of no bytes never used.
    let wire::Carried {
        moved,
        ending,
        buffer,
    } = carried;
    drop(buffer);
    drop(source);
    connection.retire(request_id);
    let written = reply.finish(wire::Carried {
        moved,
        ending,
        buffer: None,
    });
    if written.await.is_err() || sink.flush().await.is_err() {
        connection.stop();
    }
}

/// A write on an appending handle is collected and sent to the host as one call
/// with `RWF_APPEND`: `pwritev2(2)` appends under the inode lock, so one guest
/// append is never split by another writer. A write delayed by the cache of its
/// file is collected the same way and waits in a separate task, so the reader
/// continues to the reply to the recall.
///
/// A connection that ends in the middle of the data leaves the pieces already
/// written in the file, as a local process ended in the middle of a write
/// would. The session stores a short write of the bytes already written, or,
/// when none was, a write that never started. An append whose data was cut off
/// never reached its host call, so it never started, even when it had already
/// cleared the privileged bits of the file: clearing them again changes
/// nothing.
async fn write<R, P>(
    connection: &Arc<Connection<P>>,
    reader: &mut R,
    bytes: &[u8],
) -> io::Result<bool>
where
    R: AsyncRead + Unpin + Send,
    P: Replies,
{
    let frame = Frame::parse(bytes, &LIMITS).map_err(framing)?;
    let request = frame.request::<WriteRequest>().map_err(framing)?;
    let body = *request.body();
    let (request_id, node_id) = (frame.request_id(), request.head().node_id.get());
    let data_len = body.data_len.get();

    // The handle and the refusal of a clearing of privileged bits are decided
    // before the data is read.
    let file = ops::file::file_of(&connection.session, body.handle.get());
    let io = ahead(writing(&file));
    let Ok(refused) = refusal(connection, &body, node_id, &io).await else {
        return Ok(false);
    };
    if let Some(errno) = refused {
        let drain = match &io {
            Ok(Ok(io)) => (io.transfer().piece_len(), io.transfer().memory_alignment()),
            _ => (rustix::param::page_size(), 1),
        };
        let Ok(buffer) = connection.buffer(drain.0, drain.1).await else {
            return Ok(false);
        };
        if !drain_data(connection, reader, buffer, u64::from(data_len)).await? {
            return Ok(false);
        }
        spawn_answer(connection, request_id, Err(errno), None);
        return Ok(true);
    }
    let Ok(file) = file else {
        return Ok(false);
    };
    let offset = body.offset.get();
    let io = match io {
        Ok(Ok(io)) if !file.appends() => io,
        Ok(Ok(io)) => {
            if data_len > WRITE_CALL_MAX {
                return Err(io::Error::other(format!(
                    "a write of {data_len} bytes cannot reach the host as one write call"
                )));
            }
            let Some(data) = collect(connection, reader, data_len, io.transfer()).await? else {
                return Ok(false);
            };
            let Ok(mut thread) = connection.thread().await else {
                return Ok(false);
            };
            let flags = file.write_flags();
            let written = thread
                .run(move || wire::write_collected(&io, &data, offset, flags))
                .await
                .unwrap_or(Err(Errno::IO));
            drop(thread);
            spawn_answer(
                connection,
                request_id,
                written.map(|written| written as u64),
                None,
            );
            return Ok(true);
        }
        Ok(Err(_)) => return Ok(false),
        Err(postponed) => {
            let Some(data) = collect(connection, reader, data_len, file.transfer()).await? else {
                return Ok(false);
            };
            connection.spawn(write_postponed(
                Arc::clone(connection),
                request_id,
                file,
                postponed,
                (data, offset),
            ));
            return Ok(true);
        }
    };

    let transfer = io.transfer();
    let Ok(buffer) = connection
        .buffer(transfer.piece_len(), transfer.memory_alignment())
        .await
    else {
        return Ok(false);
    };
    let mut source = SocketSource::new(&mut *reader, connection.stopped());
    let mut sink = FileSink::new(&**connection, io, file.write_flags(), offset);
    let (carried, taken) = {
        let mut counting = Counting::default();
        let carried = wire::carry(
            &mut source,
            &mut [&mut counting],
            &mut sink,
            buffer,
            u64::from(data_len),
            |_, rest| wire::cut(transfer.piece_len(), rest, transfer.offset_alignment()),
        )
        .await;
        (carried, counting.bytes)
    };
    if let Ending::Failed(End::Socket(error)) = carried.ending {
        if carried.moved > 0 {
            match written_reply(request_id, Ok(carried.moved)) {
                Ok(reply) => connection.keep_reply(request_id, &reply).await,
                Err(error) => {
                    connection.unkept();
                    return Err(framing(error));
                }
            }
        }
        return Err(error);
    }
    let outcome = wire::written_or_errno(&carried);
    // The rest of the data the request declared is drained either way. A write
    // refused by the host on a later piece after earlier bytes were written
    // stores its short-write reply first, so a connection lost during the drain
    // still gets it.
    let rest = u64::from(data_len) - taken;
    let kept = if rest > 0 && carried.moved > 0 {
        match written_reply(request_id, outcome) {
            Ok(reply) => {
                connection.keep_reply(request_id, &reply).await;
                Some(reply)
            }
            Err(error) => {
                connection.unkept();
                return Err(framing(error));
            }
        }
    } else {
        None
    };
    if rest > 0 {
        let buffer = match carried.buffer {
            Some(buffer) => buffer,
            None => match connection
                .buffer(transfer.piece_len(), transfer.memory_alignment())
                .await
            {
                Ok(buffer) => buffer,
                Err(_) => return Ok(false),
            },
        };
        if !drain_data(connection, reader, buffer, rest).await? {
            return Ok(false);
        }
    } else {
        drop(carried.buffer);
    }
    spawn_answer(connection, request_id, outcome, kept);
    Ok(true)
}

/// The errno of `io` when it has none, and the errno of the host when the write
/// asks to clear the privileged bits of the file and the host does not allow
/// that. Fails when the connection stops while waiting for the thread of that
/// clearing.
async fn refusal<P: Replies>(
    connection: &Connection<P>,
    body: &WriteRequest,
    node_id: u64,
    io: &Result<Result<Io, Errno>, Postponed>,
) -> Result<Option<Errno>, End> {
    match io {
        Ok(Err(errno)) => Ok(Some(*errno)),
        _ if body.write_flags.get() & voidport_proto::ops::file::write_flags::PRIVILEGED_STRIP
            != 0 =>
        {
            let mut thread = connection.thread().await?;
            let session = Arc::clone(&connection.session);
            let cleared = thread
                .run(move || ops::file::clear_privileged(&session, node_id))
                .await
                .unwrap_or(Err(Errno::IO));
            drop(thread);
            Ok(cleared.err())
        }
        _ => Ok(None),
    }
}

async fn collect<R, P>(
    connection: &Connection<P>,
    reader: &mut R,
    len: u32,
    transfer: Transfer,
) -> io::Result<Option<Vec<Buffer>>>
where
    R: AsyncRead + Unpin,
    P: Replies,
{
    let mut rest = len as usize;
    let piece = transfer
        .piece_len()
        .max(rest.div_ceil(WRITE_CALL_PIECES))
        .next_multiple_of(transfer.piece_len());
    let mut pieces = Vec::with_capacity(rest.div_ceil(piece));
    let mut stopped = connection.stopped();
    while rest > 0 {
        let Ok(mut buffer) = connection
            .buffer(piece.min(rest), transfer.memory_alignment())
            .await
        else {
            return Ok(None);
        };
        tokio::select! {
            biased;
            _ = stopped.wait_for(|stopped| *stopped) => return Ok(None),
            read = reader.read_exact(&mut buffer) => { read?; }
        }
        rest -= buffer.len();
        pieces.push(buffer);
    }
    Ok(Some(pieces))
}

/// A connection that stops while it waits ends the wait, and the write never
/// started; a `cancel` for it ends the wait too, and it receives `EINTR`,
/// nothing written. Once the wait is over, the write runs to its end.
async fn write_postponed<P: Replies>(
    connection: Arc<Connection<P>>,
    request_id: u64,
    file: Arc<FileHandle>,
    postponed: Postponed,
    (data, offset): (Vec<Buffer>, u64),
) {
    let Some(io) = go_ahead(&connection, request_id, postponed, || file.writing()).await else {
        return connection.link.keep(request_id, Kept::NotStarted);
    };
    let Ok(mut thread) = connection.thread_to_end().await else {
        return connection.link.keep(request_id, Kept::NotStarted);
    };
    let flags = file.write_flags();
    let written = thread
        .run(move || wire::write_collected(&io?, &data, offset, flags))
        .await
        .unwrap_or(Err(Errno::IO));
    drop(thread);
    spawn_answer(
        &connection,
        request_id,
        written.map(|written| written as u64),
        None,
    );
}

#[derive(Default)]
struct Counting {
    bytes: u64,
}

impl wire::Stage for Counting {
    fn pass(&mut self, piece: &[u8]) {
        self.bytes += piece.len() as u64;
    }
}

async fn drain_data<R, P>(
    connection: &Connection<P>,
    reader: &mut R,
    mut buffer: Buffer,
    mut len: u64,
) -> io::Result<bool>
where
    R: AsyncRead + Unpin,
    P: Replies,
{
    let mut stopped = connection.stopped();
    while len > 0 {
        let step = usize::try_from(len).unwrap_or(usize::MAX).min(buffer.len());
        tokio::select! {
            biased;
            _ = stopped.wait_for(|stopped| *stopped) => return Ok(false),
            read = reader.read_exact(&mut buffer[..step]) => { read?; }
        }
        len -= step as u64;
    }
    Ok(true)
}

/// `kept` is the reply when the session already stores it; otherwise the reply is
/// made from `outcome` and kept before it is answered.
fn spawn_answer<P: Replies>(
    connection: &Arc<Connection<P>>,
    request_id: u64,
    outcome: Result<u64, Errno>,
    kept: Option<Vec<u8>>,
) {
    let answering = Arc::clone(connection);
    connection.spawn(async move { answer_write(&answering, request_id, outcome, kept).await });
}

async fn answer_write<P: Replies>(
    connection: &Connection<P>,
    request_id: u64,
    outcome: Result<u64, Errno>,
    kept: Option<Vec<u8>>,
) {
    let reply = match kept {
        Some(reply) => reply,
        None => match written_reply(request_id, outcome) {
            Ok(reply) => {
                connection.keep_reply(request_id, &reply).await;
                reply
            }
            Err(_) => return connection.unkept(),
        },
    };
    connection.answer(request_id, &reply).await;
}

fn written_reply(request_id: u64, outcome: Result<u64, Errno>) -> Result<Vec<u8>, FramingError> {
    match outcome {
        Ok(written) => ops::encode_outcome(
            request_id,
            Opcode::Write,
            Ok(WriteResponse {
                written: U32::new(u32::try_from(written).unwrap_or(u32::MAX)),
            }),
        ),
        Err(errno) => ops::error_reply(request_id, Opcode::Write, errno),
    }
}

impl<W: AsyncWrite + Unpin + Send + 'static> Connection<Stream<W>> {
    async fn writer(&self) -> Result<Held<'_, Stream<W>>, End> {
        self.held(async { Some(self.replies.lock().await) }).await
    }
}

/// A snapshot part streams one entry per piece through one buffer of one entry,
/// and has the sink while it does; the other writers of this connection wait
/// behind it. The notifications of the session reach the queue only while this
/// connection has the subscription.
async fn notify<W: AsyncWrite + Unpin + Send + 'static>(connection: Arc<Connection<Stream<W>>>) {
    let queue = Arc::clone(connection.link.queue());
    let mut stopped = connection.stopped();
    loop {
        let wake = tokio::select! {
            biased;
            _ = stopped.wait_for(|stopped| *stopped) => return,
            wake = queue.next() => wake,
        };
        let written = match wake {
            Wake::Lapsed => {
                // The full queue of this consumer was dropped, so the consumer
                // gets a fresh snapshot once it is drained.
                tracing::debug!(
                    session = connection.session.id(),
                    "a share subscription lapsed; resnapshotting"
                );
                connection.session.refresh_subscription();
                continue;
            }
            Wake::Notice(Notice::Frame(bytes)) => {
                let Ok(mut sink) = connection.writer().await else {
                    return;
                };
                sink.put(&bytes).await.is_ok() && sink.flush().await.is_ok()
            }
            Wake::Notice(Notice::Part(entries)) => {
                let Ok(mut piece) = connection
                    .buffer(size_of::<ShareEntryHeader>() + LIMITS.path_max as usize, 1)
                    .await
                else {
                    return;
                };
                let Ok(mut sink) = connection.writer().await else {
                    return;
                };
                stream_part(&mut sink, &entries, &mut piece).await.is_ok()
                    && sink.flush().await.is_ok()
            }
        };
        if !written {
            return connection.stop();
        }
    }
}

async fn stream_part<O: Out>(
    sink: &mut O,
    entries: &[(String, crate::share::ShareEntry)],
    piece: &mut Buffer,
) -> io::Result<()> {
    let mut head = [0u8; FrameWriter::notification_len::<ShareSnapshotPart>(0)];
    let head = FrameWriter::notification(&mut head, &LIMITS, &ShareSnapshotPart)
        .and_then(FrameWriter::finish)
        .map_err(framing)?;
    sink.put(head).await?;
    for (path, entry) in entries {
        let Some(len) = encode_entry(path, entry, piece) else {
            tracing::error!(path, "a share entry could not be encoded");
            continue;
        };
        sink.put(&piece::length(len).map_err(framing)?).await?;
        sink.put(&piece[..len]).await?;
    }
    sink.put(&Closing::done(false).encode()).await
}

fn framing(error: FramingError) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use voidport_proto::ops::node::{ForgetRequest, GetattrRequest};

    fn request<M: voidport_proto::message::RequestBody>(request_id: u64, body: &M) -> Vec<u8> {
        let mut buffer = [0u8; 128];
        let head = RequestHead::new(1, 0, 0, 0);
        FrameWriter::request(&mut buffer, &LIMITS, request_id, &head, body)
            .and_then(FrameWriter::finish)
            .expect("encodable")
            .to_vec()
    }

    fn getattr() -> GetattrRequest {
        GetattrRequest {
            handle: U64::ZERO,
            flags: U32::ZERO,
            reserved: U32::ZERO,
        }
    }

    #[tokio::test]
    async fn the_reader_takes_exactly_one_message() {
        let mut stream = request(1, &getattr());
        let second = request(2, &getattr());
        stream.extend_from_slice(&second);
        let mut reader = std::io::Cursor::new(stream);
        assert_eq!(
            read_request(&mut reader).await.expect("readable"),
            Some(request(1, &getattr()))
        );
        let position = reader.position() as usize;
        assert_eq!(
            &reader.get_ref()[position..],
            second.as_slice(),
            "the second message is left where it was"
        );
        assert_eq!(
            read_request(&mut reader).await.expect("readable"),
            Some(second)
        );
        assert_eq!(
            read_request(&mut reader).await.expect("a clean close"),
            None
        );
    }

    /// A header that never completes is a peer that went away, and a body the
    /// header named and the peer never sent is an error, not a close.
    #[tokio::test]
    async fn a_missing_body_is_not_a_close() {
        let bytes = request(5, &getattr());
        let mut half_header = std::io::Cursor::new(bytes[..8].to_vec());
        assert_eq!(read_request(&mut half_header).await.expect("closed"), None);
        let mut half_body = std::io::Cursor::new(bytes[..bytes.len() - 1].to_vec());
        assert_eq!(
            read_request(&mut half_body)
                .await
                .expect_err("truncated")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn a_repeated_handshake_is_refused_at_its_header() {
        let hello = FrameHeader::new(values::HELLO, 0, 9);
        let mut reader = std::io::Cursor::new(zerocopy::IntoBytes::as_bytes(&hello).to_vec());
        assert!(read_request(&mut reader).await.is_err());
        let reply = FrameHeader::new(values::LOOKUP, voidport_proto::frame::FLAG_RESPONSE, 9);
        let mut reader = std::io::Cursor::new(zerocopy::IntoBytes::as_bytes(&reply).to_vec());
        assert!(read_request(&mut reader).await.is_err());
    }

    #[test]
    fn a_forget_is_never_outstanding() {
        let outstanding = Mutex::new(HashMap::<u64, bool>::new());
        let forget = request(
            9,
            &ForgetRequest {
                nlookup: U64::new(1),
            },
        );
        let frame = Frame::parse(&forget, &LIMITS).expect("a frame");
        assert!(!frame.opcode().expect("known").has_response());
        assert!(outstanding.lock().expect("unpoisoned").is_empty());
    }

    #[test]
    fn an_empty_subpath_mounts_the_namespace_root() {
        assert_eq!(
            parse_subpath(b"").expect("valid"),
            crate::rules::NamespacePath::root()
        );
        assert_eq!(
            parse_subpath(b"/a/b").expect("valid"),
            crate::rules::NamespacePath::parse("/a/b").expect("valid")
        );
        assert_eq!(parse_subpath(b"a/b").expect_err("relative"), Errno::INVAL);
        assert_eq!(parse_subpath(b"/a/..").expect_err("escape"), Errno::INVAL);
    }

    mod harness {
        use super::super::*;
        use std::path::PathBuf;

        use voidport_proto::message::{Follows, ResponseBody};
        use voidport_proto::ops::file::{OpenRequest, OpenResponse};
        use voidport_proto::ops::handshake::{HelloReply, HelloRequest};
        use voidport_proto::ops::node::{LookupRequest, LookupResponse};
        use voidport_proto::piece::ClosingBody;

        use crate::control::Service;
        use crate::data::Transport;
        use crate::data::descriptor_budget::DescriptorLimit;
        use crate::state::{Environment, load};
        use voidport_test_host::Scratch;

        pub struct Plane {
            pub scratch: Scratch,
            pub plane: Arc<DataPlane>,
        }

        impl Plane {
            pub fn start(label: &str) -> Self {
                let scratch = Scratch::new(label);
                let tree = scratch.directory("tree");
                let state = format!(
                    "[[namespaces]]\nname = \"plain\"\n\n[[namespaces.rules]]\npath = \"/tree\"\nmode = \"rw\"\ntarget = \"{tree}\"\n"
                );
                let state_file = scratch.file("state.toml", state.as_bytes());
                let environment = Environment::for_state_file(&state_file);
                let loaded = load(&state_file, &environment).expect("the state loads");
                let service = Arc::new(Service::new(
                    &state_file,
                    scratch.join("control.sock"),
                    environment,
                    loaded,
                    DescriptorLimit::reached(u64::MAX),
                    None,
                ));
                let signer = crate::data::token::Signer::generated().expect("a signing key");
                let plane = DataPlane::new(service, signer).expect("the pool starts");
                Self { scratch, plane }
            }

            pub fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
                self.scratch.file(&format!("tree/{name}"), contents)
            }

            pub async fn mount(&self) -> (Client, tokio::task::JoinHandle<()>) {
                let (mut client, serving) = self.connect().await;
                let namespace = b"plain";
                let body = HelloRequest::new(namespace.len() as u32, 0);
                let reply = client.call_raw(0, &body, namespace).await;
                assert_eq!(parsed(&reply.0).status().expect("a reply"), 0, "mounted");
                client.token = match parsed(&reply.0)
                    .response::<HelloReply>()
                    .expect("a hello reply")
                {
                    voidport_proto::message::ResponseOutcome::Success(reply) => {
                        reply.payload().to_vec()
                    }
                    voidport_proto::message::ResponseOutcome::Error(status) => {
                        panic!("the server answered {status}")
                    }
                };
                (client, serving)
            }

            pub async fn connect(&self) -> (Client, tokio::task::JoinHandle<()>) {
                let (client, server) = UnixStream::pair().expect("a socket pair");
                let serving = tokio::spawn(serve(
                    server,
                    Arc::clone(&self.plane),
                    Peer::new(Transport::Unix, "harness"),
                ));
                let client = Client {
                    stream: client,
                    next: 1,
                    token: Vec::new(),
                };
                (client, serving)
            }
        }

        pub type Reply = (Vec<u8>, Vec<u8>, Option<piece::Closing>);

        pub fn parsed(bytes: &[u8]) -> Frame<'_> {
            Frame::parse(bytes, &LIMITS).expect("a well-framed reply")
        }

        pub struct Client {
            pub stream: UnixStream,
            next: u64,
            pub token: Vec<u8>,
        }

        impl Client {
            pub fn request<M: voidport_proto::message::RequestBody>(
                &mut self,
                node_id: u64,
                body: &M,
                payload: &[u8],
            ) -> (u64, Vec<u8>) {
                let id = self.next;
                self.next += 1;
                let head = RequestHead::new(node_id, 0, 0, 0);
                let data = matches!(body.follows(), Follows::Data(_));
                let mut buffer = vec![0u8; FrameWriter::request_len::<M>(payload.len())];
                let mut writer =
                    FrameWriter::request(&mut buffer, &LIMITS, id, &head, body).expect("encodable");
                if !data {
                    writer.payload(payload).expect("fits");
                }
                let mut bytes = writer.finish().expect("whole").to_vec();
                if data {
                    bytes.extend_from_slice(payload);
                }
                (id, bytes)
            }

            pub async fn send(&mut self, bytes: &[u8]) {
                self.stream
                    .write_all(bytes)
                    .await
                    .expect("the server reads");
            }

            pub async fn reply(&mut self) -> Reply {
                let mut bytes = vec![0u8; FRAME_HEADER_LEN];
                self.stream.read_exact(&mut bytes).await.expect("a reply");
                let follows = loop {
                    let needed = match Frame::parse_prefix(&bytes, &LIMITS).expect("framed") {
                        Parsed::Frame(frame) => break frame.follows(),
                        Parsed::Need(needed) => needed,
                    };
                    let have = bytes.len();
                    bytes.resize(needed, 0);
                    self.stream
                        .read_exact(&mut bytes[have..])
                        .await
                        .expect("a reply");
                };
                let mut pieces = Vec::new();
                let mut closing = None;
                if let Follows::Pieces(_) = follows {
                    loop {
                        let mut len = [0u8; 4];
                        self.stream.read_exact(&mut len).await.expect("a piece");
                        let len = piece::read_length(&len) as usize;
                        if len == 0 {
                            let mut body = [0u8; 8];
                            self.stream.read_exact(&mut body).await.expect("closing");
                            closing = Some(ClosingBody::parse(&body).expect("valid"));
                            break;
                        }
                        let start = pieces.len();
                        pieces.resize(start + len, 0);
                        self.stream
                            .read_exact(&mut pieces[start..])
                            .await
                            .expect("a piece");
                    }
                }
                (bytes, pieces, closing)
            }

            pub async fn call_raw<M: voidport_proto::message::RequestBody>(
                &mut self,
                node_id: u64,
                body: &M,
                payload: &[u8],
            ) -> Reply {
                let (_, bytes) = self.request(node_id, body, payload);
                self.send(&bytes).await;
                self.reply().await
            }

            pub fn body<R: ResponseBody + Copy>(reply: &Reply) -> R {
                match parsed(&reply.0).response::<R>().expect("a valid reply") {
                    voidport_proto::message::ResponseOutcome::Success(response) => *response.body(),
                    voidport_proto::message::ResponseOutcome::Error(status) => {
                        panic!("the server answered {status}")
                    }
                }
            }

            pub async fn open(&mut self, name: &str, flags: u32) -> (u64, u64) {
                let tree = Self::body::<LookupResponse>(
                    &self
                        .call_raw(
                            ROOT_NODE_ID,
                            &LookupRequest {
                                name_len: U32::new(4),
                            },
                            b"tree",
                        )
                        .await,
                )
                .entry
                .node_id
                .get();
                let node = Self::body::<LookupResponse>(
                    &self
                        .call_raw(
                            tree,
                            &LookupRequest {
                                name_len: U32::new(name.len() as u32),
                            },
                            name.as_bytes(),
                        )
                        .await,
                )
                .entry
                .node_id
                .get();
                let handle = Self::body::<OpenResponse>(
                    &self
                        .call_raw(
                            node,
                            &OpenRequest {
                                flags: U32::new(flags),
                                reserved: U32::ZERO,
                            },
                            &[],
                        )
                        .await,
                )
                .handle
                .get();
                (node, handle)
            }
        }
    }

    mod host {
        use super::harness::Plane;
        use super::*;
        use std::os::unix::fs::MetadataExt as _;
        use voidport_proto::ops::file::{ReadRequest, WriteRequest};

        const O_RDWR: u32 = 2;

        fn write(handle: u64, data_len: usize) -> WriteRequest {
            WriteRequest {
                handle: U64::new(handle),
                offset: U64::ZERO,
                data_len: U32::new(data_len as u32),
                flags: U32::ZERO,
                write_flags: U32::ZERO,
                reserved: U32::ZERO,
            }
        }

        fn read(handle: u64, size: usize) -> ReadRequest {
            ReadRequest {
                handle: U64::new(handle),
                offset: U64::ZERO,
                size: U32::new(size as u32),
                flags: U32::ZERO,
            }
        }

        fn hello_status(reply: &super::harness::Reply) -> i32 {
            super::harness::parsed(&reply.0).status().expect("a reply")
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn ending_a_session_closes_every_connection_and_refuses_joins() {
            use voidport_proto::ops::handshake::HelloRequest;

            let plane = Plane::start("conn-end");
            let (first, first_serving) = plane.mount().await;
            let token = first.token.clone();
            let join = HelloRequest::join(token.len() as u32);
            let (mut joined, joined_serving) = plane.connect().await;
            let reply = joined.call_raw(0, &join, &token).await;
            assert_eq!(hello_status(&reply), 0, "joined");
            let session = plane.plane.sessions().live().remove(0);
            assert_eq!(session.open_connections(), 2);

            session.end();
            first_serving.await.expect("the first connection ended");
            joined_serving.await.expect("the joined connection ended");
            assert!(plane.plane.sessions().is_empty(), "the session is gone");
            assert_eq!(session.link(1).err(), Some(Errno::NOENT));
            let (mut late, _late_serving) = plane.connect().await;
            let reply = late.call_raw(0, &join, &token).await;
            assert_eq!(hello_status(&reply), -Errno::NOENT.raw_os_error());
            drop((first, joined));
        }

        async fn drain(queue: &crate::data::subscribe::NotificationQueue) -> usize {
            let mut taken = 0;
            loop {
                let mut next = std::pin::pin!(queue.next());
                let waiting = std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(next.as_mut().poll(cx).is_pending())
                })
                .await;
                if waiting {
                    return taken;
                }
                taken += 1;
            }
        }

        /// The queue of the closed connection is never the one fed by the
        /// registry, and the subscription ends when the connection it was
        /// installed on leaves.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn subscribing_while_a_connection_closes_leaves_one_subscriber() {
            let plane = Plane::start("conn-subscribe-close");
            let (_first, _serving) = plane.mount().await;
            let session = plane.plane.sessions().live().remove(0);
            for round in 0..500 {
                let one = session.attach(plane.plane.memory()).await.expect("one");
                let two = session.attach(plane.plane.memory()).await.expect("two");
                let (closed, open) = if round % 2 == 0 {
                    (&one, &two)
                } else {
                    (&two, &one)
                };
                let start = std::sync::Barrier::new(3);
                std::thread::scope(|scope| {
                    for link in [&one, &two] {
                        let (start, session) = (&start, &session);
                        scope.spawn(move || {
                            start.wait();
                            session.subscribe(link);
                        });
                    }
                    scope.spawn(|| {
                        start.wait();
                        closed.stop();
                        session.detach(closed);
                        closed.end();
                    });
                });

                let subscribed = session.summary().subscribed;
                drain(closed.queue()).await;
                drain(open.queue()).await;
                session.refresh_subscription();
                assert_eq!(
                    drain(closed.queue()).await,
                    0,
                    "round {round}: the registry feeds the closed connection"
                );
                assert_eq!(
                    drain(open.queue()).await > 0,
                    subscribed,
                    "round {round}: the registry feeds the living connection"
                );

                // The first connection the mount opened is not closed, so only
                // the recorded subscriber ends the subscription here.
                open.stop();
                session.detach(open);
                open.end();
                assert!(
                    !session.summary().subscribed,
                    "round {round}: the subscription ends with its connection"
                );
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_subscription_on_a_closed_connection_installs_nothing() {
            let plane = Plane::start("conn-subscribe-closed");
            let (_first, _serving) = plane.mount().await;
            let session = plane.plane.sessions().live().remove(0);
            let closed = session
                .attach(plane.plane.memory())
                .await
                .expect("attached");
            closed.stop();
            assert!(!session.subscribe(&closed), "closed before the step");
            assert!(!session.summary().subscribed);
            assert_eq!(drain(closed.queue()).await, 0, "no snapshot was queued");
            session.detach(&closed);
            closed.end();
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_connection_ending_mid_reply_abandons_it() {
            let plane = Plane::start("conn-stop-reply");
            let large = vec![b'l'; 8 * 1024 * 1024];
            plane.file("large.bin", &large);
            let (mut client, serving) = plane.mount().await;
            let (node, handle) = client.open("large.bin", O_RDWR).await;
            let (_, bytes) = client.request(node, &read(handle, large.len()), &[]);
            client.send(&bytes).await;
            // The reader sees the end of the stream while the reply is stuck
            // on a socket nobody reads.
            client.stream.shutdown().await.expect("shut down");
            serving.await.expect("the connection ended");
            drop(client);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_connection_ending_mid_data_ends_without_the_rest() {
            let plane = Plane::start("conn-stop-data");
            let target = plane.file("target.bin", b"");
            let block = std::fs::metadata(&target).expect("stat").blksize() as usize;
            let (mut client, serving) = plane.mount().await;
            let (node, handle) = client.open("target.bin", O_RDWR).await;
            let data = vec![b'd'; 2 * block];
            let (_, bytes) = client.request(node, &write(handle, data.len()), &data);
            let frame = bytes.len() - data.len();
            client.send(&bytes[..frame + block]).await;
            client.stream.shutdown().await.expect("shut down");
            serving.await.expect("the connection ended");
            assert_eq!(std::fs::read(&target).expect("host bytes"), data[..block]);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_reader_waits_while_a_finished_reply_waits_for_the_sink() {
        let waiting = Arc::new(Waiting::default());
        let (stop, _) = watch::channel(false);
        let servable = |waiting: &Waiting| {
            waiting.thread.load(Ordering::SeqCst) == 0 && waiting.sink.load(Ordering::SeqCst) == 0
        };
        assert!(servable(&waiting), "an idle connection reads");
        {
            let _reply = waiting.for_sink();
            assert!(
                !servable(&waiting),
                "a reply waiting for the sink stops the reader"
            );
        }
        assert!(servable(&waiting), "the written reply lets it read");
        drop(stop);
    }
}
