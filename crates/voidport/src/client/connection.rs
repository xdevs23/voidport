//! One connection generation: a socket, its handshake, and its outstanding
//! requests.
//!
//! A mount outlives its connections. Everything that belongs to *one* socket —
//! the writer that serializes frames onto it, the storage its request table
//! runs over, the frame bound that connection negotiated — lives here, behind a
//! **generation number**. The [`Client`](super::Client) above holds at most one
//! of these at a time and replaces it wholesale when the server comes back,
//! which is what makes a late frame, reply or error of an old generation
//! harmless: it is addressed to an object nothing points at any more.
//!
//! What this module does *not* decide is the session itself. The handshake's
//! validation, the request ids, the fixed-capacity request table and the replay
//! classification are [`voidport_session`]'s, and this module is the I/O around
//! them: it dials, it writes, it reads, and it wakes.
//!
//! **A protocol fault is connection loss.** An invalid frame, a response id
//! nobody is waiting for, the wrong opcode for an outstanding id, a mid-frame
//! EOF, a status that is not an errno — any of them means the byte stream can
//! no longer be trusted, so this connection is atomically marked dead, every
//! caller waiting on it is woken, the socket is shut down, and nothing further
//! is ever written to it. What happens *next* is the mount's business, not this
//! module's.
//!
//! **Death is bounded.** Recording it shuts the socket down through a duplicate
//! descriptor, not through the writer, so a caller parked in a write to
//! a peer that has stopped reading is aborted instead of waited for: teardown
//! never waits out a TCP retransmit timeout. The same shutdown is what makes a
//! partly-written frame safe to re-send — the server never dispatches a frame
//! it has not received whole, and the socket that held the fragment is gone.
//!
//! **The send path has two request classes** ([`SendPath`]): the request-side
//! analog of the server's two reply classes. A streamed write's chunks are
//! queued a window at a time, and on a link whose socket back-pressures the
//! writer's own FIFO order would put a metadata request behind every chunk
//! queued before it. The bulk class takes a single turn before it queues for
//! the writer, so at most one chunk is ever waiting there: a request of the
//! prompt class is passed by that one chunk at most, never by the window
//! behind it.

use std::fmt;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::Mutex;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::sync::oneshot;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{FRAME_HEADER_LEN, Frame, FrameKind, FrameWriter};
use voidport_proto::message::{
    RESPONSE_HEAD_LEN, RequestBody, RequestHead, ResponseHead, is_error_status,
};
use voidport_proto::opcode::Opcode;
use voidport_session::handshake::{self, MAX_FRAME_LEN as MAX_HANDSHAKE_FRAME_LEN, Negotiated};
use voidport_session::replay::{self, Decision, OpenFlags, Sent};
use voidport_session::table::{Answer, Requests, Slot, Ticket};
use zerocopy::FromBytes as _;

use super::transport::{ReadHalf, Stream, WriteHalf};
use super::{Caller, ConnectError, Death, Target};

/// The read buffer one connection holds.
///
/// Framing is length-prefixed, so reading past a frame boundary is safe by
/// construction: whatever arrives after a frame is the beginning of the next
/// one. Buffering that far ahead is what makes the steady state of a busy
/// connection **one `read(2)` per socket-full of frames**, not the two
/// per frame — one for the header, one for the body already sitting in the
/// socket — an unbuffered reader pays. The size is a compromise: large enough
/// that small reply frames arrive many to a syscall, small enough to cost
/// nothing to hold per mount. A reply larger than it is read straight into its
/// own allocation by [`BufReader`], so the rare bulk transfer does not set the
/// per-connection cost.
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// One live connection to the server.
#[derive(Debug)]
pub struct Connection {
    /// Which generation of the mount's connection this is. Monotonic; it is
    /// what tells a death observation whether it is describing the connection
    /// the mount currently holds or one already replaced.
    generation: u64,
    /// The single serialization point, and the class rule in front of it:
    /// every frame is written while it is held. Whether the connection is still
    /// usable is the death's business, not this lock's.
    send: SendPath<WriteHalf>,
    /// A duplicate of the socket descriptor, so the death path can shut the
    /// connection down without queueing behind an in-flight write.
    socket: OwnedFd,
    state: Mutex<State>,
    /// Woken whenever a request table slot frees, so a caller parked at a full
    /// table asks again. The table's capacity is the mount's concurrency bound
    /// and the bulk engines are bounded below it, so this is a wait that
    /// practically never happens — and when it does it is a wait, exactly as
    /// queueing at the writer over a back-pressuring socket is.
    free: tokio::sync::Notify,
    max_frame_len: u32,
    /// Where server-initiated notification frames go, when the mount above has
    /// somewhere to put them.
    ///
    /// Unset by default, which is exactly the v1 posture the wire contract
    /// describes: a client that never subscribes ignores what it never asked
    /// for. The subscription installs a sink on every connection the mount
    /// makes, so the stream outlives any one socket.
    notifications: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>,
}

/// What the reader task and the callers share.
#[derive(Debug)]
struct State {
    /// The session core's request table, over storage this connection owns. A
    /// `forget` never appears in it: it expects no reply and holds no slot.
    requests: Table,
    /// Set once, by whatever ended the connection.
    death: Option<Death>,
}

/// The request table of one connection, sized at the handshake.
type Table = Requests<Waiter, Vec<Slot<Waiter>>>;

/// How a caller waiting for its reply is woken.
type Waiter = oneshot::Sender<Vec<u8>>;

/// Which of the send path's two request classes a frame belongs to.
///
/// Internal scheduling only: not one byte of any frame changes with it, and the
/// server cannot tell the classes apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Everything a guest is waiting on by itself — metadata, locks, reads, and
    /// the writes of the serial path. It queues for the writer directly.
    Prompt,
    /// One chunk of a streamed write. Chunks are queued a window at a time, so
    /// this is the class that yields.
    Bulk,
}

/// The connection's single serialization point, with the class rule in front of
/// it.
///
/// Every frame is written while the writer is held, so two frames never
/// interleave on the socket. What the classes add is **who queues for it**. The
/// writer is a fair FIFO, so without a rule a metadata request handed to a
/// connection that already holds a window of queued chunks is written only
/// after every one of them — on a link whose socket back-pressures, that is the
/// whole window's transfer time. A bulk frame therefore takes a single turn
/// before it queues for the writer, and holds the turn until its frame is
/// written: at most one chunk is ever waiting at the writer, so a prompt frame
/// is passed by that one chunk at most and by no part of the window behind it.
///
/// Bulk is not starved by the rule. The writer's queue is FIFO, so a chunk
/// waiting in it is passed only by prompt frames that were already waiting,
/// never by ones issued afterwards.
#[derive(Debug)]
struct SendPath<W> {
    /// Held for the whole of one frame's write.
    writer: tokio::sync::Mutex<W>,
    /// The one turn a bulk frame takes before it may queue for the writer.
    bulk: tokio::sync::Semaphore,
}

/// The serialization point, held for one frame.
///
/// **The field order is the release order**: fields are dropped in the order
/// they are declared, so the writer is released before the turn. The chunk that
/// takes the turn next therefore finds the writer free or a prompt frame
/// already in front of it, never a second chunk queued at it.
#[derive(Debug)]
struct Sending<'a, W> {
    writer: tokio::sync::MutexGuard<'a, W>,
    _turn: Option<tokio::sync::SemaphorePermit<'a>>,
}

impl<W> SendPath<W> {
    fn new(writer: W) -> Self {
        Self {
            writer: tokio::sync::Mutex::new(writer),
            bulk: tokio::sync::Semaphore::new(1),
        }
    }

    /// Takes the serialization point for one frame of `class`.
    async fn take(&self, class: Class) -> Sending<'_, W> {
        let turn = match class {
            // A closed semaphore is unreachable — nothing ever closes this
            // one — and a frame that could not take a turn is still a frame
            // this connection owes the caller, so it queues without one.
            Class::Bulk => self.bulk.acquire().await.ok(),
            Class::Prompt => None,
        };
        Sending {
            writer: self.writer.lock().await,
            _turn: turn,
        }
    }
}

impl<W> std::ops::Deref for Sending<'_, W> {
    type Target = W;

    fn deref(&self) -> &W {
        &self.writer
    }
}

impl<W> std::ops::DerefMut for Sending<'_, W> {
    fn deref_mut(&mut self) -> &mut W {
        &mut self.writer
    }
}

/// The buffered read half a connection's replies arrive on.
pub type Replies = BufReader<ReadHalf>;

/// A connection freshly handshaken, before its reader task exists.
#[derive(Debug)]
pub struct Established {
    /// The connection itself.
    pub connection: Connection,
    /// Its read half, buffered, for the reader task to drive.
    pub reader: Replies,
}

impl Connection {
    /// Dials `target` and completes the handshake, yielding generation
    /// `generation`.
    ///
    /// The handshake is done inline — one frame out, one frame in, under the
    /// pre-handshake size bound — before the reader task exists, because until
    /// `HelloReply` arrives there is no negotiated frame length to read by. A
    /// completed handshake **is** the probe the reconnection contract asks for:
    /// there is nothing more to test, so the caller may install this connection
    /// the moment it is returned.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError`] for a refused connection, a transport failure,
    /// a malformed reply, or the errno the server refused the mount with.
    ///
    /// `capacity` is how many requests may be outstanding on it at once — the
    /// mount's concurrency bound, which sizes the request table once and for
    /// the connection's whole life.
    pub async fn dial(
        target: &Target,
        generation: u64,
        capacity: usize,
    ) -> Result<Established, ConnectError> {
        let endpoint = &target.endpoint;
        let stream = Stream::connect(endpoint)
            .await
            .map_err(|source| ConnectError::Connect {
                endpoint: endpoint.to_string(),
                source,
            })?;

        let transport = |source: io::Error| ConnectError::Transport {
            endpoint: endpoint.to_string(),
            source,
        };
        let socket = stream.duplicate().map_err(transport)?;
        let (reader, mut writer) = stream.split().map_err(transport)?;
        // The reader is buffered from the handshake on, so bytes a server
        // pipelines behind its `HelloReply` are held, not left in the
        // socket for a second read syscall.
        let mut reader = BufReader::with_capacity(READ_BUFFER_BYTES, reader);

        let mut buffer = [0u8; MAX_HANDSHAKE_FRAME_LEN as usize];
        let hello = handshake::request(&mut buffer, target.namespace.as_bytes(), &target.subpath)?;
        writer.write_all(hello).await.map_err(transport)?;

        let bytes = read_frame(&mut reader, MAX_HANDSHAKE_FRAME_LEN)
            .await
            .map_err(|error| match error {
                ReadError::Transport(error) => transport(error),
                ReadError::Fault(fault) => ConnectError::Protocol {
                    reason: fault.to_string(),
                },
            })?
            .ok_or_else(|| {
                transport(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the server closed the connection during the handshake",
                ))
            })?;
        // Every judgement about the reply is the session core's, including the
        // two v1 never made: the version and the flag bits it answers with.
        let Negotiated { max_frame_len, .. } = handshake::reply(&bytes)?;

        let mut slots = Vec::new();
        slots.resize_with(capacity, Slot::vacant);
        Ok(Established {
            connection: Self {
                generation,
                send: SendPath::new(writer),
                socket,
                state: Mutex::new(State {
                    requests: Requests::new(slots),
                    death: None,
                }),
                free: tokio::sync::Notify::new(),
                max_frame_len,
                notifications: Mutex::new(None),
            },
            reader,
        })
    }

    /// Which generation of the mount's connection this is.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The frame bound this connection negotiated, in both directions.
    #[must_use]
    pub fn max_frame_len(&self) -> u32 {
        self.max_frame_len
    }

    /// Why this connection ended, if it has.
    #[must_use]
    pub fn death(&self) -> Option<Death> {
        self.lock().death.clone()
    }

    /// Takes a request table slot for one request of `opcode`, waiting while
    /// the table is full.
    ///
    /// The core answers "no slot" and this waits: a full table is
    /// backpressure and never an error, and the capacity is the mount's
    /// concurrency bound, so a prompt request always finds a slot in practice.
    /// The ticket carries the id the frame is encoded under.
    pub async fn claim(&self, opcode: Opcode, open: OpenFlags) -> Ticket {
        let replay = replay::of(opcode, open);
        loop {
            // Registered *before* the table is asked, so a slot freed between
            // the question and the wait wakes this caller anyway.
            let free = self.free.notified();
            tokio::pin!(free);
            free.as_mut().enable();
            // The lock is taken and released here, never held across the wait.
            let claimed = self.lock().requests.claim(opcode, replay);
            if let Some(ticket) = claimed {
                return ticket;
            }
            free.await;
        }
    }

    /// Gives a claimed slot back without sending anything on it.
    ///
    /// The request that could not be encoded under this connection's bound.
    pub fn release(&self, ticket: Ticket) {
        self.lock().requests.abandon(ticket);
        self.free.notify_waiters();
    }

    /// The next request id, for a request that expects no reply.
    ///
    /// It retires the moment the frame reaches the transport, so it takes no
    /// slot and gives none back.
    pub fn take_request_id(&self) -> u64 {
        self.lock().requests.take_request_id()
    }

    /// Sends one request of `class` and waits for its reply.
    ///
    /// `Ok(bytes)` is the reply frame. `Err(decision)` means the connection
    /// died first, and carries what the core's discipline makes of that: the
    /// class the ticket holds, against how far the frame got.
    pub async fn call(
        &self,
        ticket: Ticket,
        frame: &[u8],
        class: Class,
    ) -> Result<Vec<u8>, Decision> {
        let (sender, receiver) = oneshot::channel();
        if self.transmit(frame, class, Some((ticket, sender))).await == Sent::Queued {
            self.release(ticket);
            return Err(ticket.decide(Sent::Queued));
        }
        // A dropped sender is the connection dying under us, and the frame was
        // written before it did.
        receiver.await.map_err(|_| ticket.decide(Sent::Written))
    }

    /// Sends one request that has no reply.
    ///
    /// Nothing sent this way carries bulk payload — a `forget` is a request
    /// head and no more — so it is prompt.
    pub async fn send(&self, frame: &[u8]) -> Sent {
        self.transmit(frame, Class::Prompt, None).await
    }

    /// Writes one frame, registering its waiter first.
    ///
    /// Registration happens under the writer lock, so a reply can never arrive
    /// before the waiter that is owed it is in the table.
    ///
    /// **This is the replay contract's linearization point.** A frame is
    /// [`Sent::Written`] exactly when `write_all` reported the whole of it onto
    /// the socket; anything else — a connection already dead, a write that
    /// failed part-way — is [`Sent::Queued`], because the death path shuts the
    /// socket down and the server never dispatches a frame it did not receive
    /// whole.
    ///
    /// `class` decides only how this frame queues for the serialization point
    /// ([`SendPath`]); every frame is written the same way once it holds it.
    async fn transmit(&self, frame: &[u8], class: Class, waiter: Option<(Ticket, Waiter)>) -> Sent {
        let mut stream = self.send.take(class).await;
        {
            let mut state = self.lock();
            if state.death.is_some() {
                return Sent::Queued;
            }
            if let Some((ticket, waiter)) = waiter {
                state.requests.arm(ticket, waiter);
            }
        }
        // A death recorded while this write is in flight shuts the socket down
        // underneath it, so the write fails here instead of putting a frame on
        // a connection that is already dead.
        if let Err(error) = stream.write_all(frame).await {
            self.bury(Death::Transport(format!("the connection failed: {error}")));
            return Sent::Queued;
        }
        Sent::Written
    }

    /// Ends the connection over a protocol fault the caller found.
    pub fn poison(&self, fault: FramingError) {
        self.bury(Death::Protocol(Fault::Framing(fault).to_string()));
    }

    /// Shuts the socket down, records the death, and fails every waiter.
    ///
    /// The shutdown goes through the duplicate descriptor, not the
    /// writer half, so it never waits for whoever holds the writer and aborts
    /// that write if one is in flight — teardown stays bounded however the
    /// connection ended. It happens *first*, so by the time any other thread
    /// can observe the death the socket is already gone: a caller that passed
    /// its liveness check a moment earlier writes into a dead socket and gets
    /// an error, instead of putting a frame on a connection the client has
    /// given up on.
    ///
    /// Dropping a waiter's sender is what wakes its caller, which then asks
    /// its ticket what the discipline makes of the attempt it made.
    pub fn bury(&self, death: Death) {
        // ENOTCONN is the normal answer for a peer that has already gone.
        let _ = rustix::net::shutdown(&self.socket, rustix::net::Shutdown::Both);
        let mut state = self.lock();
        if state.death.is_none() {
            tracing::debug!(generation = self.generation, %death, "the data connection ended");
            state.death = Some(death);
        }
        state.requests.bury(drop);
        drop(state);
        // Nothing will ever be answered on this connection again, but a caller
        // parked at the table is woken all the same: it finds the death on the
        // next attempt instead of waiting for a slot that would never come.
        self.free.notify_waiters();
    }

    /// Routes one reply to the caller waiting for it.
    ///
    /// Every check here is a *framing* check: the caller does the typed one.
    /// Anything wrong at this level means the stream itself can no longer be
    /// trusted, so it is reported as a fault, not as this request's
    /// error.
    fn deliver(&self, bytes: Vec<u8>) -> Result<(), Fault> {
        let frame = Frame::parse(&bytes, self.max_frame_len).map_err(Fault::Framing)?;
        match frame.kind() {
            FrameKind::Response => {}
            // A notification answers nothing, so it touches no waiter and
            // retires no id. It goes to the subscription if one is listening
            // and is dropped otherwise — which is both the v1 posture for a
            // client that never subscribed and the extensibility the reserved
            // range exists for.
            FrameKind::Notification => {
                self.notify(bytes);
                return Ok(());
            }
            FrameKind::Request => return Err(Fault::RequestFromServer),
        }
        let request_id = frame.request_id();
        let raw_opcode = frame.raw_opcode();
        // The core matches the reply to its request and checks the opcode it
        // echoes, because the table is what knows which opcode that id was
        // sent under — raw, so an opcode this client cannot even name still
        // mismatches against the real expectation.
        let answer = self.lock().requests.answer(request_id, raw_opcode);
        self.free.notify_waiters();
        let waiter = match answer {
            Answer::Deliver(waiter) => waiter,
            Answer::Unknown => return Err(Fault::UnknownResponseId { request_id }),
            Answer::Mismatch { expected } => {
                return Err(Fault::Framing(FramingError::OpcodeMismatch {
                    expected: expected.as_u16(),
                    found: raw_opcode,
                }));
            }
        };
        let (head, _) = ResponseHead::ref_from_prefix(frame.body()).map_err(|_| {
            Fault::Framing(FramingError::BodyTooShort {
                needed: RESPONSE_HEAD_LEN,
                found: frame.body().len(),
            })
        })?;
        let status = head.status.get();
        if status != 0 && !is_error_status(status) {
            return Err(Fault::Framing(FramingError::InvalidStatus { status }));
        }
        // A caller that gave up is not an error: its receiver is simply gone.
        let _ = waiter.send(bytes);
        Ok(())
    }

    /// Routes this connection's notification frames to `sink`.
    ///
    /// Installed by the mount before the reader task starts, so no notification
    /// this connection carries is missed.
    pub fn route_notifications(&self, sink: tokio::sync::mpsc::UnboundedSender<Vec<u8>>) {
        *self
            .notifications
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(sink);
    }

    /// Hands one notification frame to the subscription, if one is listening.
    fn notify(&self, bytes: Vec<u8>) {
        let sink = self
            .notifications
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match sink.as_ref() {
            // A closed sink is a consumer that stopped listening, not a
            // protocol fault: the connection carries the mount's file I/O and
            // may not die over a subscription nobody reads.
            Some(sink) => {
                let _ = sink.send(bytes);
            }
            None => {
                tracing::debug!(opcode = ?bytes.get(4..6), "ignoring an unsolicited notification");
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// Reads replies until this connection ends, then reports how it ended.
///
/// The reason travels back to the mount, which decides whether to reconnect;
/// nothing here knows about that.
pub async fn read_replies<R: AsyncRead + Unpin>(
    connection: std::sync::Arc<Connection>,
    mut reader: R,
) -> Death {
    loop {
        let death = match read_frame(&mut reader, connection.max_frame_len).await {
            Ok(Some(bytes)) => match connection.deliver(bytes) {
                Ok(()) => continue,
                Err(fault) => Death::Protocol(fault.to_string()),
            },
            Ok(None) => Death::Transport("the server closed the connection".to_owned()),
            Err(ReadError::Fault(fault)) => Death::Protocol(fault.to_string()),
            Err(ReadError::Transport(error)) => {
                Death::Transport(format!("the connection failed: {error}"))
            }
        };
        connection.bury(death.clone());
        return death;
    }
}

/// What reading a frame off the wire can run into.
#[derive(Debug)]
enum ReadError {
    /// The transport failed.
    Transport(io::Error),
    /// The bytes were not a frame this connection may accept.
    Fault(Fault),
}

/// A response-side protocol fault. Every one of them is treated exactly like
/// connection loss.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// The frame itself is malformed, or is not the response it claims to be.
    Framing(FramingError),
    /// A response arrived for an id nothing is waiting on — a stray reply, or
    /// a second one for an id already answered.
    UnknownResponseId {
        /// The id the response echoed.
        request_id: u64,
    },
    /// End of stream in the middle of a frame: a length was announced and then
    /// not delivered.
    Truncated,
    /// A request frame arrived from the server. Only responses and
    /// notifications may travel in that direction.
    RequestFromServer,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the server sent a frame the protocol does not allow: ")?;
        match self {
            Self::Framing(error) => write!(f, "{error}"),
            Self::UnknownResponseId { request_id } => {
                write!(
                    f,
                    "a response to request {request_id}, which is not pending"
                )
            }
            Self::Truncated => f.write_str("the stream ended in the middle of a frame"),
            Self::RequestFromServer => f.write_str("a request, which only a client may send"),
        }
    }
}

/// Reads exactly one frame, bounded by `max_frame_len`.
///
/// `Ok(None)` is a clean close — end of stream between frames. End of stream
/// *inside* a frame is a fault: the last thing the server said was a length it
/// then did not deliver.
///
/// The bound may change between calls: the handshake is read under the
/// pre-handshake bound and everything after it under the negotiated one, over
/// the same buffered reader, so bytes the server pipelined behind its handshake
/// reply are not lost.
async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_frame_len: u32,
) -> Result<Option<Vec<u8>>, ReadError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    match fill(reader, &mut header).await? {
        Filled::Complete => {}
        Filled::Empty => return Ok(None),
        Filled::Partial => return Err(ReadError::Fault(Fault::Truncated)),
    }
    let len = Frame::peek_len(&header, max_frame_len)
        .map_err(|error| ReadError::Fault(Fault::Framing(error)))?
        .ok_or(ReadError::Fault(Fault::Truncated))?;
    let mut bytes = vec![0u8; len as usize];
    bytes[..FRAME_HEADER_LEN].copy_from_slice(&header);
    if !matches!(
        fill(reader, &mut bytes[FRAME_HEADER_LEN..]).await?,
        Filled::Complete
    ) {
        return Err(ReadError::Fault(Fault::Truncated));
    }
    Ok(Some(bytes))
}

/// How much of a buffer the stream had left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Filled {
    /// The whole buffer.
    Complete,
    /// Nothing at all: the stream ended on a frame boundary.
    Empty,
    /// Some of it, and then end of stream.
    Partial,
}

/// Fills a buffer, distinguishing "nothing arrived" from "not all of it did".
async fn fill<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
) -> Result<Filled, ReadError> {
    if buffer.is_empty() {
        return Ok(Filled::Complete);
    }
    let mut filled = 0;
    while filled < buffer.len() {
        let read = reader
            .read(&mut buffer[filled..])
            .await
            .map_err(ReadError::Transport)?;
        if read == 0 {
            return Ok(if filled == 0 {
                Filled::Empty
            } else {
                Filled::Partial
            });
        }
        filled += read;
    }
    Ok(Filled::Complete)
}

/// Encodes one request frame.
pub fn encode<Q: RequestBody>(
    request_id: u64,
    caller: Caller,
    node_id: u64,
    body: &Q,
    payload: &[u8],
    max_frame_len: u32,
) -> Result<Vec<u8>, FramingError> {
    let head = RequestHead::new(node_id, caller.uid, caller.gid, caller.pid);
    let mut buffer =
        vec![0u8; FRAME_HEADER_LEN + size_of::<RequestHead>() + size_of::<Q>() + payload.len()];
    let mut writer = FrameWriter::request(&mut buffer, max_frame_len, request_id, &head, body)?;
    writer.payload(payload)?;
    let len = writer.finish()?.len();
    buffer.truncate(len);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use voidport_proto::frame::MAX_HELLO_FRAME_LEN;

    /// One small error-response frame, as the server writes them.
    fn frame(request_id: u64) -> Vec<u8> {
        FrameWriter::error_response(
            &mut [0u8; 32],
            MAX_HELLO_FRAME_LEN,
            request_id,
            Opcode::Hello,
            -2,
        )
        .expect("encodable")
        .to_vec()
    }

    /// A reader shaped exactly like the connection's: the buffered wrapper the
    /// mount reads every reply through.
    fn reader(bytes: Vec<u8>) -> BufReader<std::io::Cursor<Vec<u8>>> {
        BufReader::with_capacity(READ_BUFFER_BYTES, std::io::Cursor::new(bytes))
    }

    #[tokio::test]
    async fn a_frame_is_read_whole_and_a_clean_close_is_not_a_fault() {
        let bytes = frame(7);
        let mut stream = reader(bytes.clone());
        assert_eq!(
            read_frame(&mut stream, MAX_HELLO_FRAME_LEN)
                .await
                .expect("a whole frame"),
            Some(bytes)
        );
        // The stream is now exhausted on a frame boundary.
        assert_eq!(
            read_frame(&mut stream, MAX_HELLO_FRAME_LEN)
                .await
                .expect("a clean close"),
            None
        );
    }

    #[tokio::test]
    async fn a_frame_that_stops_half_way_is_a_fault() {
        let bytes = frame(7);
        for cut in [3, bytes.len() - 1] {
            let mut stream = reader(bytes[..cut].to_vec());
            assert!(matches!(
                read_frame(&mut stream, MAX_HELLO_FRAME_LEN).await,
                Err(ReadError::Fault(Fault::Truncated)),
            ));
        }
    }

    /// The whole point of the buffer: frames that arrive together are handed
    /// out one at a time, in order, and the bound applied to each is the one in
    /// force when it is read.
    #[tokio::test]
    async fn buffered_frames_are_served_in_order_under_the_current_bound() {
        let mut bytes = Vec::new();
        for request_id in 1..=8 {
            bytes.extend_from_slice(&frame(request_id));
        }
        let mut stream = reader(bytes);
        for request_id in 1..=8 {
            assert_eq!(
                read_frame(&mut stream, MAX_HELLO_FRAME_LEN)
                    .await
                    .expect("readable"),
                Some(frame(request_id))
            );
        }
        assert_eq!(
            read_frame(&mut stream, MAX_HELLO_FRAME_LEN)
                .await
                .expect("clean"),
            None
        );

        let mut stream = reader(frame(9));
        assert!(matches!(
            read_frame(&mut stream, FRAME_HEADER_LEN as u32).await,
            Err(ReadError::Fault(Fault::Framing(_))),
        ));
    }

    /// How long a class-rule assertion gives a task to reach its wait.
    const SETTLE: std::time::Duration = std::time::Duration::from_millis(50);

    /// The bulk class queues one frame at a time at the writer, and the prompt
    /// class never waits for the bulk turn at all.
    #[tokio::test]
    async fn a_bulk_frame_takes_the_turn_and_a_prompt_frame_takes_none() {
        let path = SendPath::new(());
        let turn = path.bulk.acquire().await.expect("the turn");

        // The writer is free, so a prompt frame is served whatever the bulk
        // class is holding.
        drop(
            tokio::time::timeout(SETTLE, path.take(Class::Prompt))
                .await
                .expect("a prompt frame waits for no turn"),
        );
        assert!(
            tokio::time::timeout(SETTLE, path.take(Class::Bulk))
                .await
                .is_err(),
            "a second chunk waits for the turn instead of queueing at the writer"
        );

        drop(turn);
        drop(
            tokio::time::timeout(SETTLE, path.take(Class::Bulk))
                .await
                .expect("the turn is free"),
        );
    }

    /// The rule itself: a prompt frame issued behind a window of chunks is
    /// written after the one chunk on the socket, not after the window.
    ///
    /// Without the class rule all five frames below would queue at the writer,
    /// whose order is a fair FIFO, and the prompt frame would be written last.
    #[tokio::test]
    async fn a_prompt_frame_is_written_ahead_of_a_window_of_queued_chunks() {
        const CHUNKS: usize = 4;

        let path = std::sync::Arc::new(SendPath::new(()));
        let written = std::sync::Arc::new(Mutex::new(Vec::new()));
        // The frame on the socket: it holds the writer, so everything issued
        // below queues.
        let sending = path.take(Class::Bulk).await;

        let mut window = Vec::new();
        for _ in 0..CHUNKS {
            let (path, written) = (path.clone(), written.clone());
            window.push(tokio::spawn(async move {
                let _sending = path.take(Class::Bulk).await;
                written
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .push("chunk");
            }));
        }
        tokio::time::sleep(SETTLE).await;

        let prompt = {
            let (path, written) = (path.clone(), written.clone());
            tokio::spawn(async move {
                let _sending = path.take(Class::Prompt).await;
                written
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .push("metadata");
            })
        };
        tokio::time::sleep(SETTLE).await;

        drop(sending);
        prompt.await.expect("the metadata request is written");
        for chunk in window {
            chunk.await.expect("every chunk is written");
        }
        let written = written.lock().unwrap_or_else(|poison| poison.into_inner());
        assert_eq!(
            written.first().copied(),
            Some("metadata"),
            "the metadata request passed the whole window: {written:?}"
        );
        assert_eq!(written.len(), CHUNKS + 1);
    }
}
