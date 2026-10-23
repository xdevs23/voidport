//! A protocol fault is connection loss. An invalid frame, a response id nobody
//! is waiting for, the wrong opcode for an outstanding id, a mid-frame EOF or a
//! status that is not an errno means the byte stream can no longer be trusted,
//! so the connection is marked dead atomically, every caller waiting on it is
//! woken, the socket is shut down, and nothing further is written to it.
//!
//! The reader takes exactly one message at a time: the frame header has no
//! length, so a message is sized by its opcode, its status and the length
//! fields inside its body. The pieces of a streamed reply are not part of the
//! message. The reply to a request whose caller went away is still read to its
//! end, so the connection stays in frame.

use std::fmt;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::oneshot;
use voidport_memory::{Buffer, Memory};
use voidport_proto::error::FramingError;
use voidport_proto::frame::{FRAME_HEADER_LEN, Frame, FrameKind, FrameWriter, Parsed};
use voidport_proto::limits::LIMITS;
use voidport_proto::message::{Follows, RequestBody, RequestHead};
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::connection::CancelRequest;
use voidport_proto::ops::dir::DirEntryHeader;
use voidport_proto::piece::{self, CLOSING_LEN, Closing, ClosingBody, PIECE_LEN_LEN, Stream};
use voidport_session::handshake;
use voidport_session::pool::Pooled;
use voidport_session::replay::{self, Decision, OpenFlags, Sent};
use voidport_session::table::{
    AllocationRefused, ClaimError, Requests, RoutingFault, Slot, Ticket,
};
use zerocopy::byteorder::little_endian::U64;

use super::storage::grow_vacant;
use super::transport::{ReadHalf, Stream as Transport, WriteHalf};
use super::{Caller, ConnectError, Death, Entry, Target};

/// A request whose connection was lost while its session lives on may be
/// answered from the reply the server kept for it ([`Self::resume`]), streamed
/// into the same destination.
pub(crate) trait Destination: Send {
    fn stream(&self) -> Option<Stream>;

    /// The length is checked against the room left before anything is read, so
    /// no piece is ever copied past the destination.
    fn slot(&mut self, len: u32) -> Result<&mut [u8], FramingError>;

    fn took(&mut self, len: usize) -> Result<(), FramingError>;

    /// Entries already handed to the reply of the kernel are lookups that
    /// session counted, and are not taken back while it lives.
    fn restartable(&self) -> bool;

    /// Drops what the destination took. Called on a destination that is
    /// [`Destination::restartable`], or after the session of the request ended,
    /// which is owed nothing for what the destination took.
    fn restart(&mut self);

    /// The kept reply begins with the very pieces already received, so dropping
    /// them and taking the whole kept reply is taking only what follows them.
    fn resume(&mut self);

    fn owed(lent: Lent<Self>) -> Owed
    where
        Self: Sized;
}

#[derive(Debug)]
pub struct Nothing;

impl Destination for Nothing {
    fn stream(&self) -> Option<Stream> {
        None
    }

    fn slot(&mut self, len: u32) -> Result<&mut [u8], FramingError> {
        piece::check(len, 0).map(|()| &mut [][..])
    }

    fn took(&mut self, _len: usize) -> Result<(), FramingError> {
        Ok(())
    }

    fn restartable(&self) -> bool {
        true
    }

    fn restart(&mut self) {}

    fn resume(&mut self) {}

    fn owed(lent: Lent<Self>) -> Owed {
        Owed::Nothing(lent)
    }
}

#[derive(Debug)]
pub struct Data {
    buffer: Buffer,
    filled: usize,
    start: usize,
}

impl Data {
    #[must_use]
    pub fn new(buffer: Buffer) -> Self {
        Self {
            buffer,
            filled: 0,
            start: 0,
        }
    }

    #[must_use]
    pub fn filled(&self) -> &[u8] {
        &self.buffer[..self.filled]
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buffer.len() - self.filled
    }

    pub(crate) fn begin(&mut self) {
        self.start = self.filled;
    }
}

impl Destination for Data {
    fn stream(&self) -> Option<Stream> {
        Some(Stream::Data)
    }

    fn slot(&mut self, len: u32) -> Result<&mut [u8], FramingError> {
        piece::check(len, self.remaining() as u64)?;
        let end = self.filled + len as usize;
        Ok(&mut self.buffer[self.filled..end])
    }

    fn took(&mut self, len: usize) -> Result<(), FramingError> {
        self.filled += len;
        Ok(())
    }

    fn restartable(&self) -> bool {
        true
    }

    fn restart(&mut self) {
        self.filled = self.start;
    }

    fn resume(&mut self) {
        self.filled = self.start;
    }

    fn owed(lent: Lent<Self>) -> Owed {
        Owed::Data(lent)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Listed<'a> {
    pub name: &'a [u8],
    pub entry: Entry,
    pub next_cookie: u64,
    pub entry_type: u32,
}

pub trait EntrySink: std::any::Any + Send {
    fn offer(&mut self, entry: &Listed<'_>) -> bool;

    fn take_back(&mut self, count: usize);
}

/// Every entry counts a lookup on the server, so the destination records which
/// entries the sink took and which it refused, for the request to give back what
/// the kernel will not account for.
pub struct Entries {
    piece: Buffer,
    sink: Box<dyn EntrySink>,
    accepted: Vec<u64>,
    refused: Vec<u64>,
    full: bool,
    /// Entries of a kept reply already received before the connection was lost.
    skip: usize,
}

impl fmt::Debug for Entries {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entries")
            .field("accepted", &self.accepted.len())
            .field("refused", &self.refused.len())
            .field("full", &self.full)
            .finish_non_exhaustive()
    }
}

impl Entries {
    #[must_use]
    pub fn piece_len() -> usize {
        Stream::DirEntries
            .piece_bound(&LIMITS)
            .map_or(0, |bound| bound as usize)
    }

    #[must_use]
    pub fn new(piece: Buffer, sink: Box<dyn EntrySink>) -> Self {
        Self {
            piece,
            sink,
            accepted: Vec::new(),
            refused: Vec::new(),
            full: false,
            skip: 0,
        }
    }

    #[must_use]
    pub fn accepted(&self) -> &[u64] {
        &self.accepted
    }

    #[must_use]
    pub fn refused(&self) -> &[u64] {
        &self.refused
    }

    #[must_use]
    pub fn into_sink(self) -> Box<dyn EntrySink> {
        self.sink
    }
}

impl Destination for Entries {
    fn stream(&self) -> Option<Stream> {
        Some(Stream::DirEntries)
    }

    fn slot(&mut self, len: u32) -> Result<&mut [u8], FramingError> {
        piece::check(len, self.piece.len() as u64)?;
        Ok(&mut self.piece[..len as usize])
    }

    fn took(&mut self, len: usize) -> Result<(), FramingError> {
        let item = piece::entry::<DirEntryHeader>(&self.piece[..len], LIMITS.name_max)?;
        if self.skip > 0 {
            self.skip -= 1;
            return Ok(());
        }
        let entry = Entry::of(&item.header.entry);
        let listed = Listed {
            name: item.tail,
            entry,
            next_cookie: item.header.next_cookie.get(),
            entry_type: item.header.entry_type()? as u32,
        };
        if !self.full && self.sink.offer(&listed) {
            self.full = true;
        }
        if self.full {
            self.refused.push(entry.node_id);
        } else {
            self.accepted.push(entry.node_id);
        }
        Ok(())
    }

    fn restartable(&self) -> bool {
        self.accepted.is_empty() && self.refused.is_empty()
    }

    fn restart(&mut self) {
        self.sink.take_back(self.accepted.len());
        self.accepted.clear();
        self.refused.clear();
        self.full = false;
    }

    fn resume(&mut self) {
        self.skip = self.accepted.len() + self.refused.len();
    }

    fn owed(lent: Lent<Self>) -> Owed {
        Owed::Entries(lent)
    }
}

#[derive(Debug)]
pub struct Answer {
    pub frame: Vec<u8>,
    pub closing: Option<Closing>,
}

#[derive(Debug)]
enum Delivery {
    Answered(Answer),
    Buried,
}

/// Whichever of the burial, the answer and the drop comes first wakes the
/// request with its destination. A waiter dropped without a burial, as a reader
/// dropped by a runtime shutting down drops the one it holds, wakes the request
/// exactly as its burial does.
#[derive(Debug)]
struct Waiter {
    owed: Option<Owed>,
}

#[derive(Debug)]
pub(crate) struct Lent<D> {
    wake: oneshot::Sender<(D, Delivery)>,
    destination: D,
}

impl<D> Lent<D> {
    fn give_back(self, delivery: Delivery) {
        // A caller that gave up has no receiver, and the destination is dropped
        // with the delivery.
        let _caller_gave_up = self.wake.send((self.destination, delivery));
    }
}

#[derive(Debug)]
pub(crate) enum Owed {
    Data(Lent<Data>),
    Entries(Lent<Entries>),
    Nothing(Lent<Nothing>),
}

impl Owed {
    fn destination(&mut self) -> &mut dyn Destination {
        match self {
            Self::Data(lent) => &mut lent.destination,
            Self::Entries(lent) => &mut lent.destination,
            Self::Nothing(lent) => &mut lent.destination,
        }
    }

    fn give_back(self, delivery: Delivery) {
        match self {
            Self::Data(lent) => lent.give_back(delivery),
            Self::Entries(lent) => lent.give_back(delivery),
            Self::Nothing(lent) => lent.give_back(delivery),
        }
    }
}

impl Waiter {
    fn new<D: Destination>(wake: oneshot::Sender<(D, Delivery)>, destination: D) -> Self {
        Self {
            owed: Some(D::owed(Lent { wake, destination })),
        }
    }

    fn destination(&mut self) -> Option<&mut dyn Destination> {
        self.owed.as_mut().map(Owed::destination)
    }

    fn bury(mut self) {
        self.deliver(Delivery::Buried);
    }

    fn answer(mut self, frame: Vec<u8>, closing: Option<Closing>) {
        self.deliver(Delivery::Answered(Answer { frame, closing }));
    }

    fn deliver(&mut self, delivery: Delivery) {
        if let Some(owed) = self.owed.take() {
            owed.give_back(delivery);
        }
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        self.deliver(Delivery::Buried);
    }
}

#[derive(Debug)]
pub enum Notice {
    Message(Vec<u8>),
    Entry(Vec<u8>),
}

#[derive(Debug)]
pub struct Connection {
    /// Monotonic. It tells a death observation whether it describes the session
    /// the mount currently holds or one already replaced.
    generation: u64,
    id: u64,
    /// The single serialization point: every request is written while it is
    /// held, a write's data included.
    send: tokio::sync::Mutex<WriteHalf>,
    socket: OwnedFd,
    state: Mutex<State>,
    /// Unset by default: a connection that does not carry the subscription of
    /// the mount reads and drops what it never asked for.
    notifications: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Notice>>>,
    /// The forgets written on this connection since the last reply it delivered,
    /// whose fate only the server knows if the connection is lost.
    forgets: Mutex<Vec<Forgotten>>,
    carried: std::sync::atomic::AtomicBool,
}

#[derive(Clone, Copy, Debug)]
pub struct Forget {
    pub caller: Caller,
    pub node_id: u64,
    pub nlookup: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Forgotten {
    pub request_id: u64,
    pub forget: Forget,
}

#[derive(Debug)]
struct State {
    /// A `forget` never appears in it: it expects no reply and holds no slot.
    requests: Table,
    death: Option<Death>,
}

type Table = Requests<Waiter, Storage>;

#[derive(Debug)]
struct Storage(Vec<Slot<Waiter>>);

impl voidport_session::table::Slots<Waiter> for Storage {
    fn slots(&self) -> &[Slot<Waiter>] {
        &self.0
    }
    fn slots_mut(&mut self) -> &mut [Slot<Waiter>] {
        &mut self.0
    }
    fn grow(&mut self, len: usize) -> Result<(), AllocationRefused> {
        grow_vacant(&mut self.0, len, Slot::vacant)
    }
}

pub type Replies = ReadHalf;

#[derive(Debug)]
pub struct Established {
    pub connection: Connection,
    pub reader: Replies,
}

#[derive(Debug)]
pub(crate) enum Unsent {
    Claim(ClaimError),
    Encode(FramingError),
}

impl Pooled for Connection {
    fn lives(&self) -> bool {
        self.lock().death.is_none()
    }

    fn carried(&self) -> bool {
        self.carried.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Connection {
    /// The handshake is done inline, before the reader task exists, with the same
    /// reader the task uses, so nothing the server sends behind its reply is
    /// taken off the socket here. A completed handshake is the probe of the
    /// reconnect machine, so the caller may install this connection the moment
    /// it is returned.
    pub async fn open(
        target: &Target,
        generation: u64,
        memory: &Arc<Memory>,
    ) -> Result<(Established, Buffer), ConnectError> {
        let namespace = target.namespace.as_bytes();
        let mut buffer = vec![0u8; handshake::request_len(namespace, &target.subpath)];
        let hello = handshake::request(&mut buffer, &LIMITS, namespace, &target.subpath)?;
        Self::handshake(target, hello, generation, async |token: &[u8]| {
            let mut copy = memory.buffer(token.len(), 1).await;
            copy.copy_from_slice(token);
            copy
        })
        .await
    }

    /// Any refusal of the join means the session has ended.
    pub async fn join(
        target: &Target,
        token: &[u8],
        generation: u64,
    ) -> Result<Established, ConnectError> {
        let mut buffer = vec![0u8; handshake::join_request_len(token)];
        let hello = handshake::join_request(&mut buffer, &LIMITS, token)?;
        Self::handshake(target, hello, generation, async |_: &[u8]| {})
            .await
            .map(|(established, ())| established)
    }

    /// `keep` is given the session token that the reply contains. The session
    /// that opens copies it, and a connection that joins saves nothing.
    async fn handshake<T>(
        target: &Target,
        hello: &[u8],
        generation: u64,
        keep: impl AsyncFnOnce(&[u8]) -> T,
    ) -> Result<(Established, T), ConnectError> {
        let endpoint = &target.endpoint;
        let stream =
            Transport::connect(endpoint)
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
        let (mut reader, mut writer) = stream.split().map_err(transport)?;
        writer.write_all(hello).await.map_err(transport)?;

        let bytes = read_message(&mut reader)
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
        // The session core judges the reply, including the version and the flag
        // bits.
        let accepted = handshake::session(&bytes, &LIMITS)?;
        let token = keep(accepted.token).await;

        let connection = Self::over(
            generation,
            accepted.negotiated.connection_id,
            socket,
            writer,
        )
        .map_err(transport)?;
        Ok((Established { connection, reader }, token))
    }

    fn over(generation: u64, id: u64, socket: OwnedFd, writer: WriteHalf) -> io::Result<Self> {
        let mut slots = Vec::new();
        slots.resize_with(voidport_session::table::INITIAL_SLOTS, Slot::vacant);
        let requests = Requests::new(Storage(slots)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid request storage length",
            )
        })?;
        Ok(Self {
            generation,
            id,
            send: tokio::sync::Mutex::new(writer),
            socket,
            state: Mutex::new(State {
                requests,
                death: None,
            }),
            notifications: Mutex::new(None),
            forgets: Mutex::new(Vec::new()),
            carried: std::sync::atomic::AtomicBool::new(false),
        })
    }

    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn wrote_forget(&self, forgotten: Forgotten) {
        self.forgets
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(forgotten);
    }

    pub fn take_forgets(&self) -> Vec<Forgotten> {
        std::mem::take(
            &mut *self
                .forgets
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
        )
    }

    /// The server read every forget written before the request of this reply,
    /// and applied each before it read the next frame.
    fn delivered(&self) {
        self.forgets
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
    }

    pub(crate) fn withdraw_forget(&self, request_id: u64) -> bool {
        let mut forgets = self
            .forgets
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let before = forgets.len();
        forgets.retain(|forgotten| forgotten.request_id != request_id);
        forgets.len() != before
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn death(&self) -> Option<Death> {
        self.lock().death.clone()
    }

    fn claim(&self, opcode: Opcode, open: OpenFlags) -> Result<Ticket, ClaimError> {
        let result = self.lock().requests.claim(opcode, replay::of(opcode, open));
        if matches!(result, Err(ClaimError::Invariant(_))) {
            self.bury(Death::Local("inconsistent request table".to_owned()));
        }
        result
    }

    /// A claim whose frame cannot be encoded is released.
    pub(crate) fn compose<Q: RequestBody>(
        &self,
        opcode: Opcode,
        open: OpenFlags,
        caller: Caller,
        node_id: u64,
        body: &Q,
        payload: &[u8],
    ) -> Result<(Ticket, Vec<u8>), Unsent> {
        let ticket = self.claim(opcode, open).map_err(Unsent::Claim)?;
        match encode(ticket.request_id(), caller, node_id, body, payload) {
            Ok(frame) => Ok((ticket, frame)),
            Err(error) => {
                self.release(ticket);
                Err(Unsent::Encode(error))
            }
        }
    }

    fn release(&self, mut ticket: Ticket) {
        let result = self.lock().requests.abandon(&mut ticket);
        if matches!(
            result,
            Err(voidport_session::table::LifecycleError::Invariant(_))
        ) {
            self.bury(Death::Local("inconsistent request table".to_owned()));
        }
    }

    pub fn take_request_id(&self) -> Result<u64, voidport_session::table::InvariantError> {
        let result = self.lock().requests.take_request_id();
        if result.is_err() {
            self.bury(Death::Local("inconsistent request table".to_owned()));
        }
        result
    }

    pub async fn call<D: Destination>(
        &self,
        mut ticket: Ticket,
        frame: &[u8],
        data: &[u8],
        destination: D,
    ) -> (D, Result<Answer, Decision>) {
        let (wake, woken) = oneshot::channel();
        let waiter = Waiter::new(wake, destination);
        let sent = self
            .transmit(frame, data, Some((&mut ticket, waiter)))
            .await;
        let (destination, delivery) = woken
            .await
            .expect("every waiter wakes its request before it goes");
        let outcome = match (sent, delivery) {
            (Sent::Written, Delivery::Answered(answer)) => Ok(answer),
            // The write failed and the burial woke the waiter, or the waiter was
            // never armed and its drop woke it, or the connection died under a
            // request written whole.
            (_, Delivery::Answered(_) | Delivery::Buried) => Err(ticket.decide(sent)),
        };
        (destination, outcome)
    }

    pub async fn send(&self, frame: &[u8]) -> Sent {
        self.transmit(frame, &[], None).await
    }

    /// A cancel whose write fails is not sent again: the failed write ended the
    /// connection, and the end of a connection ends the waits of the requests on
    /// it in the server.
    pub async fn cancel(&self, request_id: u64) {
        let Ok(id) = self.take_request_id() else {
            return;
        };
        let body = CancelRequest {
            request_id: U64::new(request_id),
        };
        match encode(id, Caller::default(), 0, &body, &[]) {
            Ok(frame) => {
                self.send(&frame).await;
            }
            Err(error) => tracing::error!(%error, "a cancel could not be encoded"),
        }
    }

    /// Registration happens under the writer lock, so a reply can never arrive
    /// before the waiter that is owed it is in the table.
    ///
    /// A request is [`Sent::Written`] exactly when `write_all` reported the
    /// whole of it and its data onto the socket. Anything else, a connection
    /// already dead or a write that failed part-way, is [`Sent::Queued`],
    /// because the death path shuts the socket down and the server never
    /// dispatches a frame it did not receive whole. A write whose data stopped
    /// part-way may have placed the pieces that arrived, so a write is classed
    /// once-only and is not sent again when its answer is lost.
    async fn transmit(
        &self,
        frame: &[u8],
        data: &[u8],
        waiter: Option<(&mut Ticket, Waiter)>,
    ) -> Sent {
        let mut stream = self.send.lock().await;
        {
            let mut state = self.lock();
            if state.death.is_some() {
                if let Some((ticket, _)) = waiter {
                    let _moot_on_a_dead_connection = state.requests.abandon(ticket);
                }
                return Sent::Queued;
            }
            if let Some((ticket, waiter)) = waiter
                && state.requests.arm(ticket, || waiter).is_err()
            {
                drop(state);
                self.bury(Death::Local(
                    "a request lost its claim before transmission".to_owned(),
                ));
                return Sent::Queued;
            }
        }
        self.carried
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // A death recorded while this write is in flight shuts the socket down
        // underneath it, so the write fails here instead of putting a frame on a
        // dead connection.
        let written = match stream.write_all(frame).await {
            Ok(()) => stream.write_all(data).await,
            Err(error) => Err(error),
        };
        if let Err(error) = written {
            self.bury(Death::Transport(format!("the connection failed: {error}")));
            return Sent::Queued;
        }
        Sent::Written
    }

    pub fn poison(&self, fault: FramingError) {
        self.bury(Death::Protocol(Fault::Framing(fault).to_string()));
    }

    /// The shutdown goes through the duplicate descriptor, not the writer half,
    /// so it never waits for whoever holds the writer and aborts that write if
    /// one is in flight. It happens first, so by the time any other thread can
    /// observe the death the socket is already gone: a caller that passed its
    /// liveness check a moment earlier gets an error instead of putting a frame
    /// on a connection the client has given up on.
    pub fn bury(&self, death: Death) {
        // ENOTCONN is the normal answer for a peer that has already gone.
        let _peer_already_gone = rustix::net::shutdown(&self.socket, rustix::net::Shutdown::Both);
        let mut state = self.lock();
        if state.death.is_none() {
            tracing::debug!(generation = self.generation, %death, "the data connection ended");
            state.death = Some(death);
        }
        state.requests.bury(Waiter::bury);
        drop(state);
    }

    /// Every check here is a framing check, and the caller does the typed one.
    /// Anything wrong at this level means the stream can no longer be trusted,
    /// so it is reported as a fault, not as the error of this request.
    fn waiter_for(&self, frame: &Frame<'_>) -> Result<Waiter, Fault> {
        let request_id = frame.request_id();
        let raw_opcode = frame.raw_opcode();
        // The core matches the reply to its request and checks the opcode it
        // echoes, because the table knows which opcode that id was sent under.
        // The opcode is raw, so one this client cannot name still mismatches.
        // Ids are handed out in order, so the id retired here is not claimed
        // again while the pieces of this reply are still arriving.
        let answer = self.lock().requests.answer(request_id, raw_opcode);
        answer.route(request_id, raw_opcode).map_err(|failure| {
            if let Some(waiter) = failure.wake {
                waiter.bury();
            }
            Fault::Routing(failure.fault)
        })
    }

    /// Installed by the mount before the reader task starts, so that no
    /// notification of this connection is missed.
    pub fn route_notifications(&self, sink: tokio::sync::mpsc::UnboundedSender<Notice>) {
        *self
            .notifications
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(sink);
    }

    fn notification_sink(&self) -> Option<tokio::sync::mpsc::UnboundedSender<Notice>> {
        self.notifications
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
            .filter(|sink| !sink.is_closed())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

pub async fn read_replies<R: AsyncRead + Unpin>(
    connection: std::sync::Arc<Connection>,
    mut reader: R,
) -> Death {
    let mut entry = held_entry();
    let death = loop {
        match read_one(&connection, &mut reader, &mut entry).await {
            Ok(true) => {}
            Ok(false) => break Death::Transport("the server closed the connection".to_owned()),
            Err(ReadError::Fault(fault)) => break Death::Protocol(fault.to_string()),
            Err(ReadError::Transport(error)) => {
                break Death::Transport(format!("the connection failed: {error}"));
            }
        }
    };
    connection.bury(death.clone());
    death
}

/// Made once, with the reader, so reading an entry into it allocates nothing.
/// Handing the entry on makes one owned copy per notice, because the
/// notification channel takes owned values.
fn held_entry() -> Vec<u8> {
    vec![0; share_entry_bound() as usize]
}

fn share_entry_bound() -> u32 {
    Stream::ShareEntries
        .piece_bound(&LIMITS)
        .expect("only the data stream has no piece bound")
}

async fn read_one<R: AsyncRead + Unpin>(
    connection: &Connection,
    reader: &mut R,
    entry: &mut [u8],
) -> Result<bool, ReadError> {
    let Some(bytes) = read_message(reader).await? else {
        return Ok(false);
    };
    let frame = Frame::parse(&bytes, &LIMITS).map_err(Fault::Framing)?;
    match frame.kind() {
        FrameKind::Response => {}
        // A notification answers nothing, so it wakes no waiter and retires no
        // id. Without a subscription listening it is read to its end and
        // dropped, since there is nothing to skip it by without a length in the
        // header.
        FrameKind::Notification => {
            let sink = connection.notification_sink();
            let follows = frame.follows();
            if let Some(sink) = &sink {
                let _subscriber_gone = sink.send(Notice::Message(bytes));
            }
            match follows {
                Follows::Pieces(Stream::ShareEntries) => {
                    read_entries(reader, entry, sink.as_ref()).await?;
                }
                Follows::Pieces(_) => return Err(Fault::Unrequested.into()),
                Follows::Nothing | Follows::Data(_) => {}
            }
            return Ok(true);
        }
        FrameKind::Request => return Err(Fault::RequestFromServer.into()),
    }
    let mut waiter = connection.waiter_for(&frame)?;
    // The waiter wakes its request before the caller gives the connection back
    // for the next request and its forgets.
    connection.delivered();
    let closing = match frame.follows() {
        Follows::Pieces(stream) => {
            let streamed = match waiter.destination() {
                Some(destination) if destination.stream() == Some(stream) => {
                    stream_into(reader, destination).await
                }
                _ => Err(Fault::Unrequested.into()),
            };
            match streamed {
                Ok(closing) => Some(closing),
                Err(error) => {
                    waiter.bury();
                    return Err(error);
                }
            }
        }
        Follows::Nothing | Follows::Data(_) => None,
    };
    waiter.answer(bytes, closing);
    Ok(true)
}

pub(crate) async fn kept_answer(
    kept: &[u8],
    request_id: u64,
    opcode: Opcode,
    destination: &mut dyn Destination,
) -> Result<Answer, String> {
    let fault = |error: ReadError| match error {
        ReadError::Transport(error) => error.to_string(),
        ReadError::Fault(fault) => fault.to_string(),
    };
    let mut reader = kept;
    let bytes = read_message(&mut reader)
        .await
        .map_err(fault)?
        .ok_or_else(|| "the kept reply is empty".to_owned())?;
    let frame = Frame::parse(&bytes, &LIMITS).map_err(|error| error.to_string())?;
    if frame.kind() != FrameKind::Response
        || frame.request_id() != request_id
        || frame.raw_opcode() != opcode.as_u16()
    {
        return Err(format!(
            "the kept reply answers request {} of opcode {:#06x}, not request {request_id} of {opcode}",
            frame.request_id(),
            frame.raw_opcode()
        ));
    }
    let closing = match frame.follows() {
        Follows::Pieces(stream) if destination.stream() == Some(stream) => {
            destination.resume();
            Some(stream_into(&mut reader, destination).await.map_err(fault)?)
        }
        Follows::Pieces(_) => return Err(Fault::Unrequested.to_string()),
        Follows::Nothing | Follows::Data(_) => None,
    };
    if !reader.is_empty() {
        return Err("bytes follow the kept reply".to_owned());
    }
    Ok(Answer {
        frame: bytes,
        closing,
    })
}

async fn stream_into<R: AsyncRead + Unpin>(
    reader: &mut R,
    destination: &mut dyn Destination,
) -> Result<Closing, ReadError> {
    loop {
        match read_length(reader).await? {
            Piece::Closing(closing) => return Ok(closing),
            Piece::Of(len) => {
                let slot = destination.slot(len).map_err(Fault::Framing)?;
                fill_whole(reader, slot).await?;
                destination.took(len as usize).map_err(Fault::Framing)?;
            }
        }
    }
}

async fn read_entries<R: AsyncRead + Unpin>(
    reader: &mut R,
    entry: &mut [u8],
    sink: Option<&tokio::sync::mpsc::UnboundedSender<Notice>>,
) -> Result<(), ReadError> {
    let bound = u64::from(share_entry_bound());
    loop {
        let len = match read_length(reader).await? {
            Piece::Closing(_) => return Ok(()),
            Piece::Of(len) => len,
        };
        piece::check(len, bound).map_err(Fault::Framing)?;
        let read = &mut entry[..len as usize];
        fill_whole(reader, read).await?;
        if let Some(sink) = sink {
            let _subscriber_gone = sink.send(Notice::Entry(read.to_vec()));
        }
    }
}

enum Piece {
    Of(u32),
    Closing(Closing),
}

async fn read_length<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Piece, ReadError> {
    let mut len = [0u8; PIECE_LEN_LEN];
    fill_whole(reader, &mut len).await?;
    match piece::read_length(&len) {
        0 => {
            let mut body = [0u8; CLOSING_LEN];
            fill_whole(reader, &mut body).await?;
            Ok(Piece::Closing(
                ClosingBody::parse(&body).map_err(Fault::Framing)?,
            ))
        }
        len => Ok(Piece::Of(len)),
    }
}

#[derive(Debug)]
enum ReadError {
    Transport(io::Error),
    Fault(Fault),
}

impl From<Fault> for ReadError {
    fn from(fault: Fault) -> Self {
        Self::Fault(fault)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Framing(FramingError),
    Routing(RoutingFault),
    Truncated,
    /// Only responses and notifications may travel in that direction.
    RequestFromServer,
    Unrequested,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the server sent a frame the protocol does not allow: ")?;
        match self {
            Self::Framing(error) => write!(f, "{error}"),
            Self::Routing(error) => write!(f, "{error}"),
            Self::Truncated => f.write_str("the stream ended in the middle of a message"),
            Self::RequestFromServer => f.write_str("a request, which only a client may send"),
            Self::Unrequested => f.write_str("pieces the request made no room for"),
        }
    }
}

/// End of stream inside a message is a fault.
async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>, ReadError> {
    let mut bytes = vec![0u8; FRAME_HEADER_LEN];
    match fill(reader, &mut bytes).await? {
        Filled::Complete => {}
        Filled::Empty => return Ok(None),
        Filled::Partial => return Err(Fault::Truncated.into()),
    }
    loop {
        let needed = match Frame::parse_prefix(&bytes, &LIMITS).map_err(Fault::Framing)? {
            Parsed::Frame(_) => return Ok(Some(bytes)),
            Parsed::Need(needed) => needed,
        };
        let have = bytes.len();
        bytes.resize(needed, 0);
        fill_whole(reader, &mut bytes[have..]).await?;
    }
}

async fn fill_whole<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
) -> Result<(), ReadError> {
    match fill(reader, buffer).await? {
        Filled::Complete => Ok(()),
        Filled::Empty | Filled::Partial => Err(Fault::Truncated.into()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Filled {
    Complete,
    Empty,
    Partial,
}

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

pub fn encode<Q: RequestBody>(
    request_id: u64,
    caller: Caller,
    node_id: u64,
    body: &Q,
    payload: &[u8],
) -> Result<Vec<u8>, FramingError> {
    let head = RequestHead::new(node_id, caller.uid, caller.gid, caller.pid);
    let mut buffer = vec![0u8; FrameWriter::request_len::<Q>(payload.len())];
    let mut writer = FrameWriter::request(&mut buffer, &LIMITS, request_id, &head, body)?;
    writer.payload(payload)?;
    let len = writer.finish()?.len();
    buffer.truncate(len);
    Ok(buffer)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Arc;

    use voidport_memory::Memory;
    use voidport_proto::attr::EntryOut;
    use voidport_proto::ops::dir::{DirEntryWriter, EntryType, ReaddirplusResponse};
    use voidport_proto::ops::file::ReadResponse;
    use zerocopy::FromZeros as _;

    use crate::client::ops::{Streamed, settle};

    #[test]
    fn storage_growth_ignores_nonincreasing_lengths() {
        use voidport_session::table::Slots;

        let mut storage = Storage(Vec::new());
        storage.grow(4).unwrap();
        for len in [4, 3, 0] {
            storage.grow(len).unwrap();
            assert_eq!(storage.slots().len(), 4);
        }
        storage.grow(8).unwrap();
        assert_eq!(storage.slots().len(), 8);
    }

    pub(crate) fn over_pair(id: u64) -> (Established, tokio::net::UnixStream) {
        let (client, server) = tokio::net::UnixStream::pair().expect("a socket pair");
        let stream = Transport::Unix(client);
        let socket = stream.duplicate().expect("a duplicate");
        let (reader, writer) = stream.split().expect("two halves");
        let connection = Connection::over(1, id, socket, writer).expect("a connection");
        (Established { connection, reader }, server)
    }

    fn pair() -> (Arc<Connection>, ReadHalf, tokio::net::UnixStream) {
        let (Established { connection, reader }, server) = over_pair(1);
        (Arc::new(connection), reader, server)
    }

    async fn request<D: Destination + 'static>(
        connection: &Arc<Connection>,
        server: &mut tokio::net::UnixStream,
        opcode: Opcode,
        destination: D,
    ) -> (u64, tokio::task::JoinHandle<(D, Result<Answer, Decision>)>) {
        let ticket = connection.claim(opcode, OpenFlags::NONE).expect("a slot");
        let request_id = ticket.request_id();
        let calling = Arc::clone(connection);
        let call = tokio::spawn(async move { calling.call(ticket, b"q", &[], destination).await });
        let mut sent = [0u8; 1];
        server.read_exact(&mut sent).await.expect("the request");
        (request_id, call)
    }

    fn head<R: voidport_proto::message::ResponseBody>(request_id: u64, body: &R) -> Vec<u8> {
        let mut buffer = [0u8; 64];
        FrameWriter::response(&mut buffer, &LIMITS, request_id, body)
            .and_then(FrameWriter::finish)
            .expect("encodable")
            .to_vec()
    }

    fn piece(bytes: &[u8]) -> Vec<u8> {
        let mut out = piece::length(bytes.len()).expect("a length").to_vec();
        out.extend_from_slice(bytes);
        out
    }

    fn closing(status: i32, exhausted: bool) -> Vec<u8> {
        Closing { status, exhausted }.encode().to_vec()
    }

    fn entry(node_id: u64, name: &[u8]) -> Vec<u8> {
        let mut out = EntryOut::new_zeroed();
        out.node_id = zerocopy::byteorder::little_endian::U64::new(node_id);
        let header = DirEntryHeader::new(out, node_id, EntryType::Regular, name.len() as u32);
        let mut buffer = [0u8; 512];
        let mut writer = DirEntryWriter::new(&mut buffer);
        writer.push(&header, name).expect("fits");
        let len = writer.written();
        buffer[..len].to_vec()
    }

    async fn data(len: usize) -> Data {
        Data::new(Memory::host().buffer(len, 1).await)
    }

    #[tokio::test]
    async fn a_read_that_fails_after_its_first_piece_keeps_the_bytes_it_received() {
        let (connection, mut reader, mut server) = pair();
        let (id, call) = request(&connection, &mut server, Opcode::Read, data(8).await).await;
        let mut reply = head(id, &ReadResponse);
        reply.extend(piece(b"abc"));
        reply.extend(closing(-5, false));
        server.write_all(&reply).await.expect("sent");
        assert!(
            read_one(&connection, &mut reader, &mut held_entry())
                .await
                .expect("in frame")
        );
        let (data, answered) = call.await.expect("joined");
        let answer = answered.expect("answered");
        assert_eq!(data.filled(), b"abc");
        assert_eq!(
            answer.closing,
            Some(Closing {
                status: -5,
                exhausted: false
            })
        );
    }

    #[tokio::test]
    async fn a_failed_write_hands_the_destination_back() {
        let (connection, _reader, server) = pair();
        // A shutdown ends the socket itself, where a close ends only this
        // descriptor: a process forked meanwhile by another test can keep a
        // copy of it open until it execs, and the write would then succeed.
        server
            .into_std()
            .expect("a std socket")
            .shutdown(std::net::Shutdown::Both)
            .expect("shut down");
        let ticket = connection
            .claim(Opcode::Read, OpenFlags::NONE)
            .expect("a slot");
        let (data, outcome) = connection.call(ticket, b"q", &[], data(8).await).await;
        let decision = outcome.expect_err("the write failed");
        assert!(
            connection.death().is_some(),
            "the failed write buried the connection"
        );
        assert_eq!(data.remaining(), 8, "the destination comes back");
        assert_eq!(
            decision,
            Decision::Resend,
            "a read that never reached the server is sent again"
        );
    }

    #[tokio::test]
    async fn a_waiter_dropped_without_a_burial_hands_the_destination_back() {
        let (connection, _replies, mut server) = pair();
        let (id, call) = request(&connection, &mut server, Opcode::Read, data(8).await).await;
        // The replies arrive on a stream that stays open, so the reader holds
        // the waiter while it waits for the rest of the reply.
        let (mut far, near) = tokio::io::duplex(64);
        let mut reply = head(id, &ReadResponse);
        reply.extend(piece(b"abc"));
        far.write_all(&reply).await.expect("sent");
        let mut reading = Box::pin(read_replies(Arc::clone(&connection), near));
        let polled =
            std::future::poll_fn(|cx| std::task::Poll::Ready(reading.as_mut().poll(cx))).await;
        assert!(polled.is_pending(), "the reply is not whole");
        assert_eq!(
            connection.lock().requests.outstanding(),
            0,
            "the reader holds the waiter"
        );

        drop(reading);
        let (data, outcome) = call.await.expect("joined");
        let decision = outcome.expect_err("no reply was delivered");
        assert_eq!(data.filled(), b"abc", "with the bytes it received");
        assert_eq!(decision, Decision::Resend);
    }

    #[tokio::test]
    async fn a_piece_longer_than_the_destination_ends_the_connection() {
        let (connection, reader, mut server) = pair();
        let (id, call) = request(&connection, &mut server, Opcode::Read, data(4).await).await;
        let mut reply = head(id, &ReadResponse);
        reply.extend(piece(b"too long"));
        server.write_all(&reply).await.expect("sent");
        let death = read_replies(Arc::clone(&connection), reader).await;
        assert!(matches!(death, Death::Protocol(_)), "{death:?}");
        let (data, outcome) = call.await.expect("joined");
        outcome.expect_err("the connection died");
        assert!(data.filled().is_empty(), "nothing was copied");
    }

    #[tokio::test]
    async fn a_reply_for_a_departed_caller_is_read_to_its_end() {
        let (connection, mut reader, mut server) = pair();
        let (first, departed) =
            request(&connection, &mut server, Opcode::Read, data(8).await).await;
        departed.abort();
        let _aborted = departed.await;
        let (second, call) = request(&connection, &mut server, Opcode::Getattr, Nothing).await;

        let mut stream = head(first, &ReadResponse);
        stream.extend(piece(b"abcd"));
        stream.extend(piece(b"efgh"));
        stream.extend(closing(0, true));
        let mut error = [0u8; FrameWriter::ERROR_RESPONSE_LEN];
        let refused = FrameWriter::error_response(&mut error, second, Opcode::Getattr, -2)
            .expect("encodable")
            .to_vec();
        stream.extend_from_slice(&refused);
        server.write_all(&stream).await.expect("sent");

        assert!(
            read_one(&connection, &mut reader, &mut held_entry())
                .await
                .expect("in frame")
        );
        assert!(
            read_one(&connection, &mut reader, &mut held_entry())
                .await
                .expect("in frame")
        );
        let (Nothing, answered) = call.await.expect("joined");
        let answer = answered.expect("answered");
        assert_eq!(answer.frame, refused, "the next reply is delivered whole");
    }

    struct Recording {
        room: usize,
        taken: Vec<u64>,
    }

    impl EntrySink for Recording {
        fn offer(&mut self, entry: &Listed<'_>) -> bool {
            if self.taken.len() == self.room {
                return true;
            }
            self.taken.push(entry.entry.node_id);
            false
        }

        fn take_back(&mut self, count: usize) {
            self.taken.truncate(self.taken.len().saturating_sub(count));
        }
    }

    async fn listing(room: usize) -> Entries {
        let piece = Memory::host().buffer(Entries::piece_len(), 1).await;
        Entries::new(
            piece,
            Box::new(Recording {
                room,
                taken: Vec::new(),
            }),
        )
    }

    async fn listed(
        room: usize,
        pieces: &[Vec<u8>],
        close: Vec<u8>,
    ) -> (Entries, Result<Streamed, rustix::io::Errno>) {
        let (connection, mut reader, mut server) = pair();
        let (id, call) = request(
            &connection,
            &mut server,
            Opcode::Readdirplus,
            listing(room).await,
        )
        .await;
        let mut stream = head(id, &ReaddirplusResponse);
        for entry in pieces {
            stream.extend(piece(entry));
        }
        stream.extend(close);
        server.write_all(&stream).await.expect("sent");
        assert!(
            read_one(&connection, &mut reader, &mut held_entry())
                .await
                .expect("in frame")
        );
        let (entries, answered) = call.await.expect("joined");
        let closing = answered
            .expect("answered")
            .closing
            .expect("a closing piece");
        let streamed = Streamed {
            exhausted: closing.exhausted,
            failed: (closing.status != 0)
                .then(|| rustix::io::Errno::from_raw_os_error(-closing.status)),
        };
        (entries, Ok(streamed))
    }

    #[tokio::test]
    async fn a_listing_that_fails_partway_gives_every_entry_back() {
        let pieces = [entry(7, b"seven"), entry(8, b"eight")];
        let (entries, streamed) = listed(8, &pieces, closing(-5, false)).await;
        assert_eq!(entries.accepted(), &[7, 8]);
        let settled = settle(&entries, streamed);
        assert_eq!(settled.give_back, vec![7, 8]);
        assert!(settled.accepted.is_empty());
        assert_eq!(settled.outcome, Err(rustix::io::Errno::IO));
    }

    #[tokio::test]
    async fn the_exhausted_bit_and_not_a_short_batch_ends_a_listing() {
        let pieces = [entry(1, b"one"), entry(2, b"two"), entry(3, b"three")];
        let (entries, streamed) = listed(2, &pieces, closing(0, true)).await;
        let settled = settle(&entries, streamed);
        assert_eq!(settled.accepted, vec![1, 2]);
        assert_eq!(
            settled.give_back,
            vec![3],
            "the refused entry is given back"
        );
        assert_eq!(settled.outcome, Ok(true));

        let (entries, streamed) = listed(8, &pieces[..1], closing(0, false)).await;
        let settled = settle(&entries, streamed);
        assert_eq!(settled.outcome, Ok(false), "a short batch is not the end");
        assert!(settled.give_back.is_empty());
    }

    #[tokio::test]
    async fn an_unsubscribed_notification_is_read_through() {
        use voidport_proto::ops::share::ShareSnapshotPart;

        let (connection, mut reader, mut server) = pair();
        let (id, call) = request(&connection, &mut server, Opcode::Getattr, Nothing).await;
        let mut buffer = [0u8; 32];
        let mut stream = FrameWriter::notification(&mut buffer, &LIMITS, &ShareSnapshotPart)
            .and_then(FrameWriter::finish)
            .expect("encodable")
            .to_vec();
        stream.extend(piece(&[0u8; 300]));
        stream.extend(closing(0, false));
        let mut error = [0u8; FrameWriter::ERROR_RESPONSE_LEN];
        let refused = FrameWriter::error_response(&mut error, id, Opcode::Getattr, -2)
            .expect("encodable")
            .to_vec();
        stream.extend_from_slice(&refused);
        server.write_all(&stream).await.expect("sent");
        assert!(
            read_one(&connection, &mut reader, &mut held_entry())
                .await
                .expect("in frame")
        );
        assert!(
            read_one(&connection, &mut reader, &mut held_entry())
                .await
                .expect("in frame")
        );
        let (Nothing, answered) = call.await.expect("joined");
        assert_eq!(answered.expect("answered").frame, refused);
    }

    fn share_entry(path: &[u8]) -> Vec<u8> {
        use voidport_proto::ops::share::{SHARE_KIND_FILE, SHARE_MODE_RW, ShareEntryHeader};
        use zerocopy::IntoBytes as _;

        let header = ShareEntryHeader::new(SHARE_MODE_RW, SHARE_KIND_FILE, path.len() as u32);
        let mut out = header.as_bytes().to_vec();
        out.extend_from_slice(path);
        out
    }

    #[tokio::test]
    async fn a_snapshot_part_hands_each_entry_on_as_it_is_read() {
        use voidport_proto::ops::share::ShareSnapshotPart;

        let (connection, reader, mut server) = pair();
        let (sink, mut notices) = tokio::sync::mpsc::unbounded_channel();
        connection.route_notifications(sink);
        let reading = tokio::spawn(read_replies(Arc::clone(&connection), reader));

        let mut buffer = [0u8; 32];
        let part = FrameWriter::notification(&mut buffer, &LIMITS, &ShareSnapshotPart)
            .and_then(FrameWriter::finish)
            .expect("encodable")
            .to_vec();
        let first = share_entry(b"first");
        let mut sent = part.clone();
        sent.extend(piece(&first));
        server.write_all(&sent).await.expect("sent");

        let Some(Notice::Message(message)) = notices.recv().await else {
            panic!("the part's message comes first");
        };
        assert_eq!(message, part);
        let Some(Notice::Entry(delivered)) = notices.recv().await else {
            panic!("the first entry is handed on");
        };
        assert_eq!(delivered, first);

        let last = share_entry(b"last");
        let mut rest = piece(&last);
        rest.extend(closing(0, false));
        server.write_all(&rest).await.expect("sent");
        let Some(Notice::Entry(delivered)) = notices.recv().await else {
            panic!("the last entry is handed on");
        };
        assert_eq!(delivered, last);

        drop(server);
        assert!(matches!(
            reading.await.expect("joined"),
            Death::Transport(_)
        ));
        assert!(notices.try_recv().is_err(), "nothing else was handed on");
    }

    #[tokio::test]
    async fn a_message_is_read_whole_and_a_clean_close_is_not_a_fault() {
        let mut error = [0u8; FrameWriter::ERROR_RESPONSE_LEN];
        let bytes = FrameWriter::error_response(&mut error, 7, Opcode::Getattr, -2)
            .expect("encodable")
            .to_vec();
        let mut two = bytes.clone();
        two.extend_from_slice(&bytes);
        let mut stream = std::io::Cursor::new(two);
        for _ in 0..2 {
            assert_eq!(
                read_message(&mut stream).await.expect("a whole message"),
                Some(bytes.clone())
            );
        }
        assert_eq!(
            read_message(&mut stream).await.expect("a clean close"),
            None
        );
        for cut in [3, bytes.len() - 1] {
            let mut stream = std::io::Cursor::new(bytes[..cut].to_vec());
            assert!(matches!(
                read_message(&mut stream).await,
                Err(ReadError::Fault(Fault::Truncated)),
            ));
        }
    }
}
