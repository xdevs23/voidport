//! One connection generation: a socket, its handshake, and its outstanding
//! requests.
//!
//! A mount outlives its connections. Everything that belongs to *one* socket —
//! the writer that serializes frames onto it, the table of requests waiting for
//! replies, the request-id counter the wire contract scopes per connection, the
//! frame bound that connection negotiated — lives here, behind a **generation
//! number**. The [`Client`](super::Client) above holds at most one of these at a
//! time and replaces it wholesale when the server comes back, which is what
//! makes a late frame, reply or error of an old generation harmless: it is
//! addressed to an object nothing points at any more.
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

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::sync::oneshot;
use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{FRAME_HEADER_LEN, Frame, FrameKind, FrameWriter, MAX_HELLO_FRAME_LEN};
use voidport_proto::message::{
    RESPONSE_HEAD_LEN, RequestBody, RequestHead, ResponseHead, ResponseOutcome, is_error_status,
};
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::handshake::{HelloReply, HelloRequest};
use zerocopy::FromBytes as _;
use zerocopy::byteorder::little_endian::U32;

use super::transport::{ReadHalf, Stream, WriteHalf};
use super::{Caller, ConnectError, Death, Target};

/// The request id the handshake carries.
///
/// It is the first id of every connection, and the data-request counter starts
/// after it, so "allocated monotonically and never reused" holds across the
/// whole connection, not only after the handshake. Request ids are
/// per-connection by the wire contract, so a replacement connection starts them
/// over.
pub const HELLO_REQUEST_ID: u64 = 1;

/// The smallest frame bound a session can be served under.
///
/// `max_frame_len` is the server's announcement, and everything the client
/// sizes — a read chunk, a write chunk, a directory batch — is derived from it.
/// A bound below the pre-handshake one leaves no room for a request plus a
/// usable payload: the read chunk saturates to zero and every nonempty file
/// would read as empty with no error anywhere. A mount is refused instead.
pub const MIN_MAX_FRAME_LEN: u32 = MAX_HELLO_FRAME_LEN;

/// The node id the mount root must have.
///
/// The kernel names the root of a FUSE mount `FUSE_ROOT_ID`, which is 1, and
/// nothing can change that; a server announcing another root node id is
/// describing a mount this client cannot serve. It is also the one node id the
/// server's generation-disjoint allocator never hands out, which is what lets a
/// stale mount heal by walking from the root.
pub const ROOT_NODE_ID: u64 = 1;

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
    /// The single serialization point: every frame is written while this is
    /// held. Whether the connection is still usable is the death's business,
    /// not this lock's.
    writer: tokio::sync::Mutex<WriteHalf>,
    /// A duplicate of the socket descriptor, so the death path can shut the
    /// connection down without queueing behind an in-flight write.
    socket: OwnedFd,
    state: Mutex<State>,
    next_request_id: AtomicU64,
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
    /// Response-expecting requests, by id. A `forget` never appears here.
    pending: HashMap<u64, Waiter>,
    /// Set once, by whatever ended the connection.
    death: Option<Death>,
}

/// One caller waiting for its reply.
#[derive(Debug)]
struct Waiter {
    /// The opcode the response must echo. A response carrying any other is a
    /// protocol fault, not a surprise for the caller to puzzle over.
    opcode: Opcode,
    reply: oneshot::Sender<Vec<u8>>,
}

/// How far a request got before its connection died: the replay contract's
/// linearization point, recorded where the frame is actually written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    /// The complete frame reached the socket. The server may have received it,
    /// dispatched it, and applied it — so only an idempotent request may be
    /// sent again.
    Written,
    /// Nothing, or only part of the frame, reached a socket that is now shut
    /// down. The server never dispatches a frame it has not received whole, so
    /// this request provably did not take effect and may be sent as it is.
    Queued,
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
    pub async fn dial(target: &Target, generation: u64) -> Result<Established, ConnectError> {
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

        let hello = encode_hello(target.namespace.as_bytes(), &target.subpath)?;
        writer.write_all(&hello).await.map_err(transport)?;

        let protocol = |fault: Fault| ConnectError::Protocol {
            reason: fault.to_string(),
        };
        let bytes = read_frame(&mut reader, MAX_HELLO_FRAME_LEN)
            .await
            .map_err(|error| match error {
                ReadError::Transport(error) => transport(error),
                ReadError::Fault(fault) => protocol(fault),
            })?
            .ok_or_else(|| {
                transport(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the server closed the connection during the handshake",
                ))
            })?;
        let frame = Frame::parse(&bytes, MAX_HELLO_FRAME_LEN)
            .map_err(|fault| protocol(Fault::Framing(fault)))?;
        // The handshake is matched to its request exactly like every later
        // reply, not as the one frame exempt from that discipline.
        if frame.request_id() != HELLO_REQUEST_ID {
            return Err(ConnectError::Protocol {
                reason: format!(
                    "it answers request {}, and the handshake is request {HELLO_REQUEST_ID}",
                    frame.request_id()
                ),
            });
        }
        let reply = match frame
            .response::<HelloReply>()
            .map_err(|fault| protocol(Fault::Framing(fault)))?
        {
            ResponseOutcome::Success(reply) => *reply.body(),
            ResponseOutcome::Error(status) => return Err(ConnectError::Refused { status }),
        };
        let max_frame_len = reply.max_frame_len.get();
        if max_frame_len < MIN_MAX_FRAME_LEN {
            return Err(ConnectError::FrameBound {
                announced: max_frame_len,
                minimum: MIN_MAX_FRAME_LEN,
            });
        }
        let root_node_id = reply.root_node_id.get();
        if root_node_id != ROOT_NODE_ID {
            return Err(ConnectError::RootNodeId {
                announced: root_node_id,
                expected: ROOT_NODE_ID,
            });
        }

        Ok(Established {
            connection: Self {
                generation,
                writer: tokio::sync::Mutex::new(writer),
                socket,
                state: Mutex::new(State {
                    pending: HashMap::new(),
                    death: None,
                }),
                // The handshake already used the connection's first id.
                next_request_id: AtomicU64::new(HELLO_REQUEST_ID + 1),
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

    /// Sends one request and waits for its reply.
    ///
    /// `Ok(bytes)` is the reply frame. `Err(sent)` means the connection died
    /// first, and says how far the request got — which is exactly what the
    /// replay discipline needs to decide whether sending it again is safe.
    pub async fn call(
        &self,
        request_id: u64,
        opcode: Opcode,
        frame: &[u8],
    ) -> Result<Vec<u8>, Sent> {
        let (sender, receiver) = oneshot::channel();
        let sent = self
            .transmit(
                frame,
                Some((
                    request_id,
                    Waiter {
                        opcode,
                        reply: sender,
                    },
                )),
            )
            .await;
        if sent == Sent::Queued {
            return Err(Sent::Queued);
        }
        // A dropped sender is the connection dying under us.
        receiver.await.map_err(|_| Sent::Written)
    }

    /// Sends one request that has no reply.
    ///
    /// Its id retires the moment the frame reaches the transport, so it is
    /// never registered as outstanding.
    pub async fn send(&self, frame: &[u8]) -> Sent {
        self.transmit(frame, None).await
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
    async fn transmit(&self, frame: &[u8], waiter: Option<(u64, Waiter)>) -> Sent {
        let mut stream = self.writer.lock().await;
        {
            let mut state = self.lock();
            if state.death.is_some() {
                return Sent::Queued;
            }
            if let Some((request_id, waiter)) = waiter {
                state.pending.insert(request_id, waiter);
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
    /// Dropping a waiter's sender is what wakes its caller.
    pub fn bury(&self, death: Death) {
        // ENOTCONN is the normal answer for a peer that has already gone.
        let _ = rustix::net::shutdown(&self.socket, rustix::net::Shutdown::Both);
        let mut state = self.lock();
        if state.death.is_none() {
            tracing::debug!(generation = self.generation, %death, "the data connection ended");
            state.death = Some(death);
        }
        state.pending.clear();
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
        // Removing here is also the duplicate check: a second response for one
        // id finds nothing outstanding.
        let waiter = self
            .lock()
            .pending
            .remove(&request_id)
            .ok_or(Fault::UnknownResponseId { request_id })?;
        if frame.raw_opcode() != waiter.opcode.as_u16() {
            return Err(Fault::Framing(FramingError::OpcodeMismatch {
                expected: waiter.opcode.as_u16(),
                found: frame.raw_opcode(),
            }));
        }
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
        let _ = waiter.reply.send(bytes);
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

    /// The next request id. Monotonic, so an id is never outstanding twice on
    /// this connection.
    pub fn take_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
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

/// Encodes the handshake frame.
fn encode_hello(namespace: &[u8], subpath: &[u8]) -> Result<Vec<u8>, ConnectError> {
    let body = HelloRequest {
        protocol_version: U32::new(PROTOCOL_VERSION),
        flags: U32::ZERO,
        namespace_len: U32::new(len_of(namespace)?),
        subpath_len: U32::new(len_of(subpath)?),
        auth_len: U32::ZERO,
    };
    let mut payload = namespace.to_vec();
    payload.extend_from_slice(subpath);
    // The handshake carries the request head zeroed: it names no node and no
    // caller, and uniformity beats a special case.
    encode(
        HELLO_REQUEST_ID,
        Caller::default(),
        0,
        &body,
        &payload,
        MAX_HELLO_FRAME_LEN,
    )
    .map_err(|_| ConnectError::TooLong {
        max: MAX_HELLO_FRAME_LEN,
    })
}

/// The length of a handshake field, refused if it cannot be one.
fn len_of(field: &[u8]) -> Result<u32, ConnectError> {
    u32::try_from(field.len()).map_err(|_| ConnectError::TooLong {
        max: MAX_HELLO_FRAME_LEN,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
