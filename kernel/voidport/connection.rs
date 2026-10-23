// SPDX-License-Identifier: GPL-2.0

use kernel::bindings;
use kernel::prelude::*;
use kernel::sync::{new_mutex, Arc, Mutex};
use kernel::types::Opaque;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{FrameHeader, FrameKind, FRAME_HEADER_LEN};
use voidport_proto::message::{Follows, RequestBody};
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::dir::{listing_reply_bound, DirEntryHeader};
use voidport_proto::ops::file::SetlkRequest;
use voidport_proto::ops::node::ForgetRequest;
use voidport_proto::piece::{self, Closing, Stream as PieceKind};
use voidport_session::replay::{OpenFlags, Replay, Sent};
use voidport_session::settling::{forget_sent, ForgetSent};
use voidport_session::table::{
    AllocationRefused, InvariantError, LifecycleError, Requests, RoutingFault, Slot, Slots, Ticket,
};

use zerocopy::byteorder::little_endian::U64;

use crate::aops::FolioPages;
use crate::buffer::Buffer;
use crate::cleanup::{Callerless, Cleanup};
use crate::handshake;
use crate::part::{ended, for_first_bytes, Part, Step};
use crate::stats::{self, Counted, Event, Gauge};
use crate::wire::{
    encode, read_header, read_piece, read_rest, request_len, Caller, Kept, Piece, ReadError,
    ReadFrame, Source, LIMITS,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Death {
    /// The mount closed it.
    Closed,
    /// The transport failed or the server went away.
    Transport(Error),
    Protocol(Fault),
    /// The client failed to maintain its request lifecycle.
    Local(&'static str),
}

/// A response-side protocol fault. Every one of them is treated exactly like
/// connection loss.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// The frame itself is malformed, or is not the response it claims to be.
    Framing(FramingError),
    Routing(RoutingFault),
    /// A request frame arrived from the server. Only responses and
    /// notifications may travel in that direction.
    RequestFromServer,
    /// Pieces followed a reply whose request made no room for them.
    Unrequested,
    /// No conforming server produces it: every reply is bounded by its
    /// request.
    ReplyTooLong {
        declared: usize,
        allowed: usize,
    },
    /// The link returned a reply in a form that the protocol of the link
    /// does not allow, as the text describes.
    Link(&'static str),
}

mod chain;
mod stream;

use chain::ChannelLink;
use stream::StreamLink;

pub(crate) use voidport_session::table::INITIAL_SLOTS;

/// What the request table contains for a request waiting for a reply.
/// The request is counted in flight from the moment it is armed until it leaves
/// the table, whichever way it leaves.
struct Armed {
    reply: Arc<Reply>,
    opcode: Opcode,
    _requests: Counted,
    _reads: Option<Counted>,
}

impl Armed {
    fn new(reply: Arc<Reply>, opcode: Opcode) -> Self {
        Self {
            reply,
            opcode,
            _requests: Counted::new(Gauge::Requests),
            _reads: matches!(opcode, Opcode::Read).then(|| Counted::new(Gauge::Reads)),
        }
    }

    /// The reply, once the request has left the table. The request no longer
    /// counts as in flight when this returns.
    fn into_reply(self) -> Arc<Reply> {
        self.reply
    }
}

struct Storage {
    slots: KVec<Slot<Armed>>,
}

impl Slots<Armed> for Storage {
    fn slots(&self) -> &[Slot<Armed>] {
        &self.slots
    }

    fn slots_mut(&mut self) -> &mut [Slot<Armed>] {
        &mut self.slots
    }

    fn grow(&mut self, len: usize) -> core::result::Result<(), AllocationRefused> {
        if len <= self.slots.len() {
            return Ok(());
        }
        let old = self.slots.len();
        self.slots
            .reserve(len - old, GFP_KERNEL)
            .map_err(|_| AllocationRefused)?;
        for _ in old..len {
            if self.slots.push(Slot::vacant(), GFP_KERNEL).is_err() {
                self.slots.truncate(old);
                return Err(AllocationRefused);
            }
        }
        Ok(())
    }
}

struct State {
    /// A `forget` never appears in it, since it expects no reply and uses no
    /// slot.
    requests: Requests<Armed, Storage>,
    /// Set once, by whatever ended the connection.
    death: Option<Death>,
    /// Whether a request was ever written to it, in whole or in part.
    carried: bool,
    /// The forgets written since its last reply, recorded before each write.
    forgets: KVVec<Forgotten>,
    /// The request no caller waits for, when the connection died before its
    /// reply arrived.
    owed: Option<Owed>,
    /// The request whose caller left while it settled the loss of the
    /// connection. The caller gives the connection back, unlike for `owed`.
    left: Option<Owed>,
}

impl State {
    fn abandon_claim(&mut self, ticket: &mut Ticket) -> core::result::Result<(), InvariantError> {
        match self.requests.abandon(ticket) {
            Ok(()) | Err(LifecycleError::Armed | LifecycleError::Retired) => Ok(()),
            Err(LifecycleError::Invariant(error)) => Err(error),
        }
    }

    /// Puts `reply` into the slot of the claimed request `ticket`. Returns
    /// whether the table had that claim.
    fn arm(&mut self, ticket: &mut Ticket, reply: Arc<Reply>) -> bool {
        let opcode = ticket.opcode();
        self.requests
            .arm(ticket, || Armed::new(reply, opcode))
            .is_ok()
    }
}

/// Where the data of a read reply streams, straight into the pages it fills:
/// from where this reply starts filling them to their end.
#[derive(Clone)]
pub(crate) struct ReadRange {
    pages: ReadPages,
    start: usize,
    at: usize,
}

#[derive(Clone)]
pub(crate) enum ReadPages {
    Folio(FolioPages),
    Buffer(Arc<Buffer>),
}

impl ReadRange {
    pub(crate) fn new(pages: ReadPages, start: usize) -> Self {
        Self {
            pages,
            start,
            at: start,
        }
    }

    pub(crate) fn pages(&self) -> &ReadPages {
        &self.pages
    }

    fn len(&self) -> usize {
        match &self.pages {
            ReadPages::Folio(folio) => folio.len(),
            ReadPages::Buffer(buffer) => buffer.len(),
        }
    }

    pub(crate) fn filled(&self) -> usize {
        self.at - self.start
    }

    pub(crate) fn remaining(&self) -> u64 {
        (self.len() - self.at) as u64
    }

    /// The caller has checked `len` against [`Self::remaining`].
    fn receive(&mut self, source: &impl Source, len: usize) -> Result {
        match &mut self.pages {
            ReadPages::Folio(folio) => folio.receive(source, self.at, len),
            ReadPages::Buffer(buffer) => buffer.receive(source, self.at, len),
        }?;
        self.at += len;
        Ok(())
    }

    /// The device put the piece in place. The caller has checked `len` against
    /// [`Self::remaining`].
    fn advance(&mut self, len: usize) {
        self.at += len;
    }

    /// Calls `visit` with each part of the rest of the range that lies in one
    /// page, in order, until it stops, and returns the result it stopped
    /// with.
    pub(crate) fn parts(&self, visit: &mut dyn FnMut(Part) -> Step) -> Result {
        let rest = self.len() - self.at;
        ended(match &self.pages {
            ReadPages::Folio(folio) => folio.parts(self.at, rest, visit),
            ReadPages::Buffer(buffer) => buffer.parts(self.at, rest, visit),
        })
    }

    /// Ends the read of a folio that the caller of the read handed over,
    /// when the range is in one, as [`FolioPages::complete`] describes.
    fn end_folio_read(self, closing: Option<Closing>) {
        if let ReadPages::Folio(folio) = self.pages {
            folio.complete(self.at, closing);
        }
    }
}

/// `Entries` has each entry of a listing as one piece, back to back in one
/// buffer of the size the request asked for. `Drained` drops the pieces of a
/// read whose caller left before its reply arrived, as they are read, and
/// `room` is what remains of the request, which every piece is still checked
/// against. `Bytes` receives the reply the server stored for a request that an
/// outcome request asks about.
pub(crate) enum Pieces {
    None,
    Read(ReadRange),
    Entries { buffer: KVVec<u8>, len: usize },
    Drained { room: u64 },
    Bytes { buffer: KVVec<u8>, len: usize },
}

/// How many bytes a link sets aside for the reply to a request whose reply
/// message is at most `capacity` bytes and whose pieces go to `pieces`. The
/// data of a read or of an outcome arrives in one piece. The bytes of a read
/// go to the pages of the read, so only the length in front of them needs
/// room here.
pub(crate) fn reply_area(capacity: usize, pieces: &Pieces) -> usize {
    match pieces {
        Pieces::None => capacity,
        Pieces::Read(_) | Pieces::Drained { .. } => capacity + piece::stream_len(1, 0),
        Pieces::Entries { buffer, .. } => {
            listing_reply_bound(u32::try_from(buffer.len()).unwrap_or(u32::MAX))
        }
        Pieces::Bytes { buffer, .. } => capacity + piece::stream_len(1, buffer.len()),
    }
}

impl Pieces {
    /// What remains of a read's request, for pieces a departed caller's
    /// reply drops instead of keeping; `None` for any other destination.
    fn read_room(&self) -> Option<u64> {
        match self {
            Self::Read(range) => Some(range.remaining()),
            Self::Bytes { buffer, len } => Some((buffer.len() - *len) as u64),
            _ => None,
        }
    }

    pub(crate) fn entries(&self) -> &[u8] {
        match self {
            Self::Entries { buffer, len } => &buffer[..*len],
            _ => &[],
        }
    }
}

pub(crate) struct Landing {
    pub(crate) frame: KVVec<u8>,
    pub(crate) len: usize,
    pub(crate) pieces: Pieces,
    /// The closing piece, for a reply pieces followed.
    pub(crate) closing: Option<Closing>,
}

impl Landing {
    pub(crate) fn new(capacity: usize, pieces: Pieces) -> Result<Self> {
        Ok(Self {
            frame: KVVec::from_elem(0u8, capacity, GFP_KERNEL)?,
            len: 0,
            pieces,
            closing: None,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.frame[..self.len]
    }

    fn reply_area(&self) -> usize {
        reply_area(self.frame.len(), &self.pieces)
    }

    /// The most bytes the reply the server stored for the request of this
    /// landing can take: the message, and for a listing every entry with its
    /// length word and the closing piece.
    pub(crate) fn kept_bound(&self) -> usize {
        match &self.pieces {
            Pieces::Entries { buffer, .. } => {
                listing_reply_bound(u32::try_from(buffer.len()).unwrap_or(u32::MAX))
            }
            _ => self.frame.len(),
        }
    }

    /// Reads the reply the server stored for request `request_id` from `kept`
    /// into this landing, over whatever an attempt cut short left in it.
    pub(crate) fn read_kept(&mut self, kept: &[u8], request_id: u64) -> Result {
        self.len = 0;
        self.closing = None;
        if let Pieces::Entries { len, .. } | Pieces::Bytes { len, .. } = &mut self.pieces {
            *len = 0;
        }
        let source = Kept::new(kept);
        let mut header = [0u8; FRAME_HEADER_LEN];
        if !read_header(&source, &mut header).map_err(|_| EIO)? {
            return Err(EIO);
        }
        let head = FrameHeader::parse(&header).map_err(|_| EIO)?;
        if head.kind() != FrameKind::Response || head.request_id.get() != request_id {
            return Err(EIO);
        }
        fill(&source, &header, self, &mut Arrival::Inline).map_err(|_| EIO)?;
        if !source.is_empty() {
            return Err(EIO);
        }
        Ok(())
    }

    fn complete_folio(self) {
        if let Pieces::Read(range) = self.pieces {
            range.end_folio_read(self.closing);
        }
    }
}

/// A forget written on a connection since its last reply, which a loss of the
/// connection settles.
#[derive(Clone, Copy)]
pub(crate) struct Forgotten {
    pub(crate) request_id: u64,
    pub(crate) caller: Caller,
    pub(crate) node_id: u64,
    pub(crate) nlookup: u64,
}

const FORGET_LEN: usize = request_len::<ForgetRequest>(0);

/// The room for the frame of a request no caller waits for: the release of a
/// handle, a Flush, or the unlock of a record lock, which is the longest.
const CALLERLESS_LEN: usize = request_len::<SetlkRequest>(0);

impl Forgotten {
    fn frame<'a>(&self, frame: &'a mut [u8; FORGET_LEN]) -> Result<&'a [u8]> {
        let body = ForgetRequest {
            nlookup: U64::new(self.nlookup),
        };
        encode(
            frame,
            self.request_id,
            self.caller,
            self.node_id,
            &body,
            &[],
        )
        .map_err(|_| EOVERFLOW)
    }
}

/// A request no caller waits for, in flight on a connection that died before
/// its reply arrived. The thread of the connection settles it.
pub(crate) struct Owed {
    pub(crate) request_id: u64,
    pub(crate) opcode: Opcode,
    pub(crate) reply: Arc<Reply>,
}

impl Owed {
    /// Ends the request once its session ended, which ended the references
    /// its reply would have carried.
    pub(crate) fn end(self) {
        if let Some(Pending::Callerless { completion, .. }) = self.reply.take_unsettled() {
            completion.finish(false);
        }
    }
}

/// What the thread of a lost connection settles of a request no caller
/// waits for.
pub(crate) enum Pending {
    /// A request that admits references on the server, and the cleanup that
    /// the reply the server stored for it needs.
    Admitting {
        landing: Landing,
        orphan: KBox<Cleanup>,
    },
    /// A request of the cleanup worker.
    Callerless {
        landing: Landing,
        completion: Callerless,
    },
    /// Any other request: nothing the server stores for it matters to
    /// anyone.
    Other,
}

/// Who settles a request whose connection died before its reply arrived.
pub(crate) enum Failed {
    /// Its caller, which the death woke, or nobody, since the reply had
    /// arrived already.
    Caller,
    /// The thread of the connection, since no caller waits: the caller left,
    /// or the request is one of the cleanup worker.
    Thread,
}

/// Where a reply is, from the moment a caller allocates it to the moment its
/// last holder lets it go.
enum ReplyState {
    /// Armed or about to be: the caller is waiting, or will.
    Waiting {
        landing: Landing,
        orphan: Option<KBox<Cleanup>>,
    },
    Filling {
        abandoned: bool,
        /// Whether the landing carries the caller's folio, which a caller
        /// that leaves now hands to the reader.
        folio: bool,
        orphan: Option<KBox<Cleanup>>,
    },
    /// The reply arrived; the caller has not taken it yet.
    Delivered {
        landing: Landing,
        orphan: Option<KBox<Cleanup>>,
    },
    /// The connection died before the reply arrived, and the caller settles
    /// the request.
    Failed {
        landing: Landing,
        orphan: Option<KBox<Cleanup>>,
    },
    /// The caller left before the reply arrived; the reader still owes the
    /// reply a read, and the server the cleanup the orphan cleanup performs.
    Abandoned {
        landing: Landing,
        orphan: Option<KBox<Cleanup>>,
    },
    /// The connection died before the reply arrived, and no caller waits:
    /// the thread of the connection settles the request.
    Unsettled {
        landing: Landing,
        orphan: Option<KBox<Cleanup>>,
    },
    /// Consumed: nothing is owed to anyone any more.
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Interrupt {
    Any,
    Fatal,
}

/// Wakes the caller that waits for a reply. A wakeup is counted, so one that
/// comes between the check of the reply and the sleep is not lost.
#[pin_data]
struct Wakeup {
    #[pin]
    completion: Opaque<bindings::completion>,
}

impl Wakeup {
    fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            completion <- Opaque::ffi_init(|slot: *mut bindings::completion| {
                // SAFETY: `slot` is valid storage for an uninitialized completion.
                unsafe { bindings::init_completion(slot) }
            }),
        })
    }

    fn wake(&self) {
        // SAFETY: the completion was initialized by `new`.
        unsafe { bindings::complete(self.completion.get()) };
    }

    /// Sleeps until a wakeup, or until a signal that `interrupt` selects, and
    /// returns whether such a signal ended the sleep.
    fn sleep(&self, interrupt: Interrupt) -> bool {
        let completion = self.completion.get();
        // SAFETY: the completion was initialized by `new`.
        let ended = unsafe {
            match interrupt {
                Interrupt::Any => bindings::wait_for_completion_interruptible(completion),
                Interrupt::Fatal => bindings::wait_for_completion_killable(completion),
            }
        };
        ended != 0
    }
}

// SAFETY: a completion is a counter and a wait queue under its own lock, which
// any task may wake or sleep on.
unsafe impl Send for Wakeup {}
// SAFETY: as above.
unsafe impl Sync for Wakeup {}

#[pin_data]
pub(crate) struct Reply {
    /// Response, interruption and connection failure meet under this lock, so
    /// exactly one of them wins. The share of the reply held by the reader
    /// prevents the `Landing` from being freed until the reply has arrived,
    /// pieces and closing piece included.
    #[pin]
    state: Mutex<ReplyState>,
    #[pin]
    ready: Wakeup,
    #[pin]
    cleanup: Mutex<Option<Callerless>>,
    // Field destruction releases buffers and cleanup before notifying observers.
    live: Counted,
}

pub(crate) enum Wait {
    Answered {
        landing: Landing,
        orphan: Option<KBox<Cleanup>>,
    },
    /// The connection died first; the caller's ticket decides what follows.
    /// A reply the server stored for the request lands in `landing`, and
    /// `orphan` is the cleanup its answer needs.
    Lost {
        landing: Landing,
        orphan: Option<KBox<Cleanup>>,
    },
    /// A signal ended the wait; the reply, if it comes, is the reader's to
    /// consume and the cleanup worker's to clean up after.
    Interrupted,
    /// A signal ended the wait while the reply was streaming into the
    /// caller's folio: the reader ends the folio's read when the reply closes.
    Handed,
}

impl Reply {
    /// The buffer is allocated here, before anything is sent, so an allocation
    /// failure unwinds with nothing on the wire.
    pub(crate) fn new(
        capacity: usize,
        pieces: Pieces,
        orphan: Option<KBox<Cleanup>>,
    ) -> Result<Arc<Self>> {
        let landing = Landing::new(capacity, pieces)?;
        let reply = Arc::pin_init(
            pin_init!(Reply {
                state <- new_mutex!(ReplyState::Waiting { landing, orphan }, "voidport::reply"),
                ready <- Wakeup::new(),
                cleanup <- new_mutex!(None, "voidport::callerless"),
                live: Counted::new(Gauge::Replies),
            }),
            GFP_KERNEL,
        )?;
        Ok(reply)
    }

    pub(crate) fn complete_cleanup(&self, completion: Callerless) {
        *self.cleanup.lock() = Some(completion);
    }

    /// Waits for the reply, or for whatever ends the wait first: the loss of
    /// the connection, or a signal that `interrupt` selects.
    ///
    /// A signal that arrives in the same instant as the reply loses: the state
    /// is read again under the lock after every wakeup, and a reply that has
    /// arrived is the answer whatever else the task has pending.
    pub(crate) fn wait(&self, interrupt: Interrupt) -> Wait {
        let mut state = self.state.lock();
        loop {
            match &*state {
                ReplyState::Delivered { .. } => {
                    // Matching a borrowed enum does not refine the type
                    // returned by replace, even under this lock.
                    if let ReplyState::Delivered { landing, orphan } =
                        core::mem::replace(&mut *state, ReplyState::Done)
                    {
                        return Wait::Answered { landing, orphan };
                    }
                }
                ReplyState::Failed { .. } => {
                    if let ReplyState::Failed { landing, orphan } =
                        core::mem::replace(&mut *state, ReplyState::Done)
                    {
                        return Wait::Lost { landing, orphan };
                    }
                }
                ReplyState::Waiting { .. } | ReplyState::Filling { .. } => {}
                ReplyState::Abandoned { .. } | ReplyState::Unsettled { .. } | ReplyState::Done => {
                    return Wait::Interrupted
                }
            }
            drop(state);
            let signalled = self.ready.sleep(interrupt);
            state = self.state.lock();
            if signalled {
                // The signal is real only if the reply has not arrived since:
                // the loop's next pass decides, and abandoning happens only
                // from a state that is still waiting.
                match core::mem::replace(&mut *state, ReplyState::Done) {
                    ReplyState::Waiting {
                        mut landing,
                        orphan,
                    } => {
                        // A folio the reader never touched stays the caller's
                        // to end; the pieces that come for it are dropped.
                        if let Some(room) = landing.pieces.read_room() {
                            landing.pieces = Pieces::Drained { room };
                        }
                        *state = ReplyState::Abandoned { landing, orphan };
                        return Wait::Interrupted;
                    }
                    ReplyState::Filling { folio, orphan, .. } => {
                        *state = ReplyState::Filling {
                            abandoned: true,
                            folio,
                            orphan,
                        };
                        return if folio {
                            Wait::Handed
                        } else {
                            Wait::Interrupted
                        };
                    }
                    arrived => *state = arrived,
                }
            }
        }
    }

    /// Ends the reply from the death path. A waiting caller is woken with its
    /// loss and settles the request. A request no caller waits for is left
    /// to the thread of the connection.
    pub(crate) fn fail(&self) -> Failed {
        let mut state = self.state.lock();
        let unsettled = match core::mem::replace(&mut *state, ReplyState::Done) {
            ReplyState::Waiting { landing, orphan } if self.cleanup.lock().is_some() => {
                ReplyState::Unsettled { landing, orphan }
            }
            ReplyState::Waiting { landing, orphan } => {
                *state = ReplyState::Failed { landing, orphan };
                drop(state);
                self.ready.wake();
                return Failed::Caller;
            }
            ReplyState::Abandoned { landing, orphan } => ReplyState::Unsettled { landing, orphan },
            other => {
                *state = other;
                return Failed::Caller;
            }
        };
        *state = unsettled;
        Failed::Thread
    }

    /// Leaves the request of a caller that left while it settled the loss of
    /// the connection to the thread of the connection, with the landing and
    /// the orphan cleanup its wait returned.
    pub(crate) fn leave_unsettled(&self, landing: Landing, orphan: Option<KBox<Cleanup>>) {
        *self.state.lock() = ReplyState::Unsettled { landing, orphan };
    }

    /// What the thread of the connection settles of the request, once.
    pub(crate) fn take_unsettled(&self) -> Option<Pending> {
        let mut state = self.state.lock();
        let (landing, orphan) = match core::mem::replace(&mut *state, ReplyState::Done) {
            ReplyState::Unsettled { landing, orphan } => (landing, orphan),
            other => {
                *state = other;
                return None;
            }
        };
        Some(match (self.cleanup.lock().take(), orphan) {
            (Some(completion), _) => Pending::Callerless {
                landing,
                completion,
            },
            (None, Some(orphan)) => Pending::Admitting { landing, orphan },
            (None, None) => Pending::Other,
        })
    }

    /// Makes the reply wait for the request of `completion` again, with the
    /// landing an earlier attempt used, before the request is sent again.
    pub(crate) fn rearm(&self, landing: Landing, completion: Callerless) {
        *self.cleanup.lock() = Some(completion);
        *self.state.lock() = ReplyState::Waiting {
            landing,
            orphan: None,
        };
    }

    /// Returns the request of the cleanup worker this reply was to complete,
    /// which no connection took.
    pub(crate) fn withdraw_callerless(&self) -> Option<Callerless> {
        self.cleanup.lock().take()
    }

    /// How many bytes a link sets aside for the reply, while it waits to be
    /// sent.
    fn reply_area(&self) -> Result<usize> {
        match &*self.state.lock() {
            ReplyState::Waiting { landing, .. } => Ok(landing.reply_area()),
            _ => Err(EIO),
        }
    }

    fn begin_fill(&self) -> Option<Landing> {
        let mut state = self.state.lock();
        match core::mem::replace(&mut *state, ReplyState::Done) {
            ReplyState::Waiting { landing, orphan } => {
                *state = ReplyState::Filling {
                    abandoned: false,
                    folio: matches!(
                        &landing.pieces,
                        Pieces::Read(range) if matches!(range.pages(), ReadPages::Folio(_))
                    ),
                    orphan,
                };
                Some(landing)
            }
            ReplyState::Abandoned { landing, orphan } => {
                *state = ReplyState::Filling {
                    abandoned: true,
                    folio: false,
                    orphan,
                };
                Some(landing)
            }
            other => {
                *state = other;
                None
            }
        }
    }

    /// Complete response validation delegated by a callerless reply's cleanup.
    fn validate(&self, bytes: &[u8]) -> core::result::Result<(), FramingError> {
        if let Some(completion) = self.cleanup.lock().as_ref() {
            completion.validate(bytes)?;
        }
        Ok(())
    }

    /// Hands the filled landing back.
    ///
    /// A waiting caller is woken with it. A caller that left gets nothing: a
    /// folio it handed over has its read ended here, and the reply goes into
    /// the orphan cleanup instead, which is answered to the reader for the
    /// cleanup worker: the server-side references the reply carries are
    /// released there.
    fn end_fill(&self, landing: Landing) -> Received {
        let mut state = self.state.lock();
        // A request of the cleanup worker ends once this reply lets go of its
        // locks: the end of a Flush gives back the handle it went through.
        let mut finished = None;
        let received = match core::mem::replace(&mut *state, ReplyState::Done) {
            ReplyState::Filling {
                abandoned: false,
                orphan,
                ..
            } => {
                if let Some(completion) = self.cleanup.lock().take() {
                    finished = Some(completion);
                    Received::Callerless(None)
                } else {
                    *state = ReplyState::Delivered { landing, orphan };
                    Received::Taken
                }
            }
            ReplyState::Filling {
                abandoned: true,
                orphan,
                ..
            } => {
                stats::record(Event::Orphaned);
                match orphan {
                    Some(mut cleanup) => {
                        cleanup.carry(landing);
                        Received::Callerless(Some(cleanup))
                    }
                    None => {
                        landing.complete_folio();
                        Received::Callerless(None)
                    }
                }
            }
            other => {
                *state = other;
                Received::Taken
            }
        };
        drop(state);
        self.ready.wake();
        if let Some(completion) = finished {
            completion.finish(true);
        }
        received
    }

    /// Puts back the landing of a fill cut short by the death of the
    /// connection, so that the death path ends the reply as it ends one that
    /// was waiting. A folio a departed caller handed over has its read ended
    /// here, as failed.
    fn abort_fill(&self, landing: Option<Landing>) {
        let mut state = self.state.lock();
        *state = match (landing, core::mem::replace(&mut *state, ReplyState::Done)) {
            (
                Some(mut landing),
                ReplyState::Filling {
                    abandoned: true,
                    orphan,
                    ..
                },
            ) => {
                if let Pieces::Read(range) = core::mem::replace(&mut landing.pieces, Pieces::None) {
                    range.end_folio_read(None);
                }
                ReplyState::Abandoned { landing, orphan }
            }
            (
                Some(landing),
                ReplyState::Filling {
                    abandoned: false,
                    orphan,
                    ..
                },
            ) => ReplyState::Waiting { landing, orphan },
            (_, other) => other,
        };
    }
}

pub(crate) enum Received {
    /// It dropped a notification, or a caller receives the reply.
    Taken,
    /// It read a reply no caller waits for, with the cleanup that reply owes,
    /// and nothing more is owed on the connection.
    Callerless(Option<KBox<Cleanup>>),
}

struct Removed {
    request_id: u64,
    opcode: Opcode,
    reply: Arc<Reply>,
    landing: Option<Landing>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transmit {
    /// The whole request reached the link; the caller may wait for its reply.
    Written,
    /// The connection is dead and nothing was written; the caller's ticket
    /// decides what follows, with the attempt at [`Sent::Queued`].
    Dead,
    /// A signal cancelled this request. If any prefix was transmitted, the
    /// source was closed before returning; no departed caller initiates replay.
    Cancelled,
    /// The link could not put the request in its form, and nothing was
    /// written. The request fails with this error, and the connection lives
    /// on.
    Failed(Error),
}

pub(crate) trait Data {
    fn len(&self) -> usize;

    /// Calls `visit` with each part of those bytes that lies in one page, in
    /// order, until it stops, and returns the result it stopped with.
    fn parts(&self, visit: &mut dyn FnMut(Part) -> Step) -> Result;
}

#[derive(Clone, Copy)]
pub(crate) enum PageData<'a> {
    None,
    Write(&'a dyn Data),
    Read(&'a ReadRange),
}

impl PageData<'_> {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Write(data) => data.len(),
            Self::Read(range) => range.remaining() as usize,
        }
    }

    pub(crate) fn parts(&self, visit: &mut dyn FnMut(Part) -> Step) -> Result {
        match self {
            Self::None => Ok(()),
            Self::Write(data) => data.parts(visit),
            Self::Read(range) => range.parts(visit),
        }
    }
}

pub(crate) struct Outbound<'a> {
    pub(crate) frame: &'a [u8],
    /// How many bytes the reply message and its pieces need, without the
    /// bytes a read puts in pages.
    pub(crate) reply_len: usize,
    pub(crate) data: PageData<'a>,
    /// How many bytes of `data` go with the request: the bytes of whole
    /// parts, from the first part on.
    pub(crate) data_len: usize,
}

impl Outbound<'_> {
    /// Calls `each` with each part of the data that goes with the request,
    /// in order, and stops at the first error.
    fn parts(&self, each: impl FnMut(&Part) -> Result) -> Result {
        for_first_bytes(self.data_len, |visit| self.data.parts(visit), each)
    }
}

#[derive(Clone, Copy)]
enum Ending {
    /// Both directions are shut at once, which cuts a request in progress.
    Abrupt,
    /// A request in progress ends first, then only the sending direction is
    /// shut, and the server still sends what it owes.
    Clean,
}

/// The request table, the death and the record of forgets belong to the
/// connection, which each method of a link gets as an argument.
trait Link: Send + Sync {
    /// How many parts of page data fit in a request besides a frame of
    /// `frame_len` bytes and a reply of `reply_len` bytes. `None` when all of
    /// the data of a request fits. `EIO` when not even the frame and the
    /// reply fit.
    fn data_room(&self, frame_len: usize, reply_len: usize) -> Result<Option<usize>>;

    /// Sends `request` with the claim `ticket`, arming `reply` first, as
    /// [`Connection::transmit`] describes. The ticket is armed or retired
    /// when this returns.
    fn transmit(
        &self,
        connection: &Connection,
        ticket: &mut Ticket,
        request: &Outbound<'_>,
        reply: Arc<Reply>,
    ) -> Transmit;

    /// Sends the request `frame` of `ticket` as a request no caller waits
    /// for, armed with `reply`, as [`Connection::send_callerless`] describes.
    fn send_callerless(
        &self,
        connection: &Connection,
        ticket: Ticket,
        frame: &[u8],
        reply: Arc<Reply>,
    ) -> Result;

    /// Records a forget of `nlookup` lookups of `node_id` for `caller` with
    /// [`Connection::record_forget`] and sends it, as [`Connection::forget`]
    /// describes.
    fn forget(&self, connection: &Connection, caller: Caller, node_id: u64, nlookup: u64)
        -> Result;

    /// Reads the next reply and routes it, as [`Connection::receive`]
    /// describes.
    fn receive(&self, connection: &Connection) -> core::result::Result<Received, Death>;

    /// Reads and drops what arrives after a clean close, as
    /// [`Connection::drain`] describes.
    fn drain(&self, connection: &Connection) -> Result;

    /// Ends the link in the way set by `ending` and records `death` on
    /// `connection` with [`Connection::record`], the first time only, and
    /// returns whether this call ended it. A task that sees the death and
    /// ends the connection again finds the link ended already.
    fn end(&self, connection: &Connection, ending: Ending, death: Death) -> bool;

    /// Shuts both directions of a link that ended cleanly, which ends a
    /// drain and cuts a request still in progress.
    fn abort(&self);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Claim {
    Dead,
    /// The host allocator refused request storage.
    Allocation,
}

/// A connection that a clean close has ended. The server still sends what it
/// owes until it closes its side, and only this handle reads that or cuts it
/// off.
#[derive(Clone)]
pub(crate) struct ClosedConnection(Arc<Connection>);

impl ClosedConnection {
    pub(crate) fn drain(&self) -> Result {
        self.0.drain()
    }

    /// Shuts both directions at once, which ends the drain and cuts a request
    /// still in progress.
    pub(crate) fn abort(&self) {
        self.0.link.abort();
    }
}

#[pin_data]
pub(crate) struct Connection {
    /// The id the server gave this connection in its session, with which an
    /// outcome or a retire request identifies it.
    id: u64,
    generation: u64,
    /// What the connection travels on, the only reference to it. The locks of
    /// a link need a place that never moves, and of the kernel pointers to
    /// such places only an `Arc` converts to a trait object.
    link: Arc<dyn Link>,
    #[pin]
    state: Mutex<State>,
    live: Counted,
}

impl Connection {
    pub(crate) fn new(link: handshake::Link, id: u64, generation: u64) -> Result<Arc<Self>> {
        let link: Arc<dyn Link> = match link {
            handshake::Link::Stream(stream) => Arc::pin_init(StreamLink::new(stream), GFP_KERNEL)?,
            handshake::Link::Channel(channel) => {
                Arc::pin_init(ChannelLink::new(channel), GFP_KERNEL)?
            }
        };
        let mut slots = KVec::with_capacity(INITIAL_SLOTS, GFP_KERNEL)?;
        for _ in 0..INITIAL_SLOTS {
            slots.push(Slot::vacant(), GFP_KERNEL)?;
        }
        let requests = Requests::new(Storage { slots }).map_err(|_| EINVAL)?;
        let connection = Arc::pin_init(
            pin_init!(Connection {
                id,
                generation,
                link,
                state <- new_mutex!(State {
                    requests,
                    death: None,
                    carried: false,
                    forgets: KVVec::new(),
                    owed: None,
                    left: None,
                }, "voidport::connection"),
                live: Counted::new(Gauge::Connections),
            }),
            GFP_KERNEL,
        )?;
        Ok(connection)
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// How many parts of page data fit in a request on this connection
    /// besides a frame of `frame_len` bytes and a reply of `reply_len` bytes,
    /// or `None` when all of the data of a request fits. `EIO` when not even
    /// the frame and the reply fit.
    pub(crate) fn data_room(&self, frame_len: usize, reply_len: usize) -> Result<Option<usize>> {
        self.link.data_room(frame_len, reply_len)
    }

    pub(crate) fn death(&self) -> Option<Death> {
        self.state.lock().death
    }

    pub(crate) fn carried(&self) -> bool {
        self.state.lock().carried
    }

    /// The forgets written since its last reply, which a loss of the
    /// connection leaves to settle.
    pub(crate) fn take_forgets(&self) -> KVVec<Forgotten> {
        core::mem::take(&mut self.state.lock().forgets)
    }

    /// The request in flight no caller waits for, which a loss of the
    /// connection leaves to settle.
    pub(crate) fn take_owed(&self) -> Option<Owed> {
        self.state.lock().owed.take()
    }

    /// Leaves `left`, the request of a caller that left while it settled
    /// the loss of this connection, to the thread of the connection.
    pub(crate) fn leave(&self, left: Owed) {
        self.state.lock().left = Some(left);
    }

    /// The request of a caller that left while it settled the loss of this
    /// connection.
    pub(crate) fn take_left(&self) -> Option<Owed> {
        self.state.lock().left.take()
    }

    /// Claims storage without waiting for another request to finish.
    /// Allocation refusal belongs only to this request.
    pub(crate) fn claim(
        &self,
        opcode: Opcode,
        replay: Replay,
    ) -> core::result::Result<Ticket, Claim> {
        let mut state = self.state.lock();
        if state.death.is_some() {
            return Err(Claim::Dead);
        }
        match state.requests.claim(opcode, replay) {
            Ok(ticket) => Ok(ticket),
            Err(voidport_session::table::ClaimError::Allocation) => Err(Claim::Allocation),
            Err(voidport_session::table::ClaimError::Invariant(_)) => {
                drop(state);
                self.bury(Death::Local("inconsistent request table"));
                Err(Claim::Dead)
            }
        }
    }

    pub(crate) fn abandon(&self, mut ticket: Ticket) {
        self.abandon_claim(&mut ticket);
    }

    pub(crate) fn abandon_claim(&self, ticket: &mut Ticket) {
        let result = self.state.lock().abandon_claim(ticket);
        if result.is_err() {
            self.bury(Death::Local("inconsistent request table"));
        }
    }

    /// Sends one request on the link, arming its reply first, so a reply can
    /// never arrive before the waiter that is owed it is in the table.
    ///
    /// A request is [`Transmit::Written`] exactly when the whole of it reached
    /// the link. A connection already dead, or a send that failed part-way and
    /// ended the connection, is [`Transmit::Dead`], and the server never
    /// dispatches a request it did not receive whole. A signal pending before
    /// anything of the request is sent cancels it outright, since nothing is
    /// owed.
    pub(crate) fn transmit(
        &self,
        ticket: &mut Ticket,
        request: &Outbound<'_>,
        reply: Arc<Reply>,
    ) -> Transmit {
        self.link.transmit(self, ticket, request, reply)
    }

    /// Sends a forget of `nlookup` lookups of `node_id` for `caller`.
    ///
    /// The forget expects no reply. It is recorded before it is sent, until
    /// the next reply on the connection shows that the server read it, so a
    /// loss of the connection settles it. `Ok` once it is sent, or left to
    /// that settling. An error when the connection did not accept it, which is
    /// then to be sent again: `EIO` when it died first, or the send failed
    /// and the forget was withdrawn before a loss took it, and `ENOMEM` when
    /// the record could not grow.
    pub(crate) fn forget(&self, caller: Caller, node_id: u64, nlookup: u64) -> Result {
        self.link.forget(self, caller, node_id, nlookup)
    }

    /// Records a forget of `nlookup` lookups of `node_id` for `caller`, before
    /// a link sends it, and encodes its frame into `frame`. Returns the
    /// request id of the forget and the frame. `EIO` when the connection
    /// ended, and `ENOMEM` when the record could not grow.
    fn record_forget<'f>(
        &self,
        caller: Caller,
        node_id: u64,
        nlookup: u64,
        frame: &'f mut [u8; FORGET_LEN],
    ) -> Result<(u64, &'f [u8])> {
        let mut state = self.state.lock();
        if state.death.is_some() {
            return Err(EIO);
        }
        state.forgets.reserve(1, GFP_KERNEL)?;
        let Ok(request_id) = state.requests.take_request_id() else {
            drop(state);
            self.bury(Death::Local("inconsistent request table"));
            return Err(EIO);
        };
        let forgotten = Forgotten {
            request_id,
            caller,
            node_id,
            nlookup,
        };
        let frame = forgotten.frame(frame)?;
        // The room was reserved above, so the push does not allocate.
        state.forgets.push(forgotten, GFP_KERNEL)?;
        state.carried = true;
        Ok((request_id, frame))
    }

    /// Removes the forget `request_id`, which did not get to the server,
    /// from the record, as the session core sets for a forget that was not
    /// sent. Returns `error` when the record still had it, so the forget is
    /// sent again, and `Ok` when a loss of the connection removed it to
    /// settle it.
    fn withdraw_unsent_forget(&self, request_id: u64, error: Error) -> Result {
        match forget_sent(Sent::Queued) {
            ForgetSent::Lost if self.withdraw_forget(request_id) => Err(error),
            ForgetSent::Lost | ForgetSent::Written => Ok(()),
        }
    }

    fn withdraw_forget(&self, request_id: u64) -> bool {
        let mut state = self.state.lock();
        let recorded = state.forgets.len();
        state
            .forgets
            .retain(|forgotten| forgotten.request_id != request_id);
        state.forgets.len() != recorded
    }

    /// Sends the request `body` about `node_id` for `caller` on this exact
    /// connection, as a request no caller waits for: claims it, encodes it,
    /// arms `reply` with it and sends it. The table owns completion so the
    /// producer need not wait for the reply.
    ///
    /// `Ok` once the request is armed: its reply completes it, or the thread
    /// of the connection settles it after a loss. An error when the
    /// connection could not accept it, with `reply` left for another try.
    pub(crate) fn send_callerless<Q: RequestBody>(
        &self,
        caller: Caller,
        node_id: u64,
        body: &Q,
        reply: Arc<Reply>,
    ) -> Result {
        const { assert!(request_len::<Q>(0) <= CALLERLESS_LEN) };
        let replay = voidport_session::replay::of(Q::OPCODE, OpenFlags::NONE);
        let ticket = self.claim(Q::OPCODE, replay).map_err(|error| match error {
            Claim::Dead => EIO,
            Claim::Allocation => ENOMEM,
        })?;
        let mut buffer = [0u8; CALLERLESS_LEN];
        let Ok(frame) = encode(&mut buffer, ticket.request_id(), caller, node_id, body, &[]) else {
            self.abandon(ticket);
            return Err(EOVERFLOW);
        };
        self.link.send_callerless(self, ticket, frame, reply)
    }

    /// The link is shut *first*, so by the time any other task can observe
    /// the death the link is already gone: a sender that passed its liveness
    /// check a moment earlier gets an error, and a reader waiting for a reply
    /// is woken. A waiter whose request a channel still has is failed once
    /// the device returned it.
    ///
    /// Only the first end of the connection shuts the link and records the
    /// death. After a [`Connection::close`], a loss leaves the link to the
    /// [`ClosedConnection`] that close returned.
    pub(crate) fn bury(&self, death: Death) {
        self.link.end(self, Ending::Abrupt, death);
    }

    /// Ends the connection as the mount closes it. After this, a request does
    /// not start, every waiter fails, and only the sending direction is shut,
    /// once a request in progress has ended: the server reads every request
    /// whole, then the end of the connection, and [`ClosedConnection::drain`]
    /// reads what the server still sends. `None` when the connection had
    /// already ended.
    pub(crate) fn close(self: &Arc<Self>) -> Option<ClosedConnection> {
        self.link
            .end(self, Ending::Clean, Death::Closed)
            .then(|| ClosedConnection(self.clone()))
    }

    /// Reads and drops what the server sends after a clean close, up to the
    /// end of the connection, a transport error or a signal.
    pub(crate) fn drain(&self) -> Result {
        self.link.drain(self)
    }

    /// Records the death and fails every waiter. The request no caller waits
    /// for is left to the thread of the connection to settle. Only the
    /// [`Link::end`] of the link calls it, once.
    fn record(&self, death: Death) {
        let mut state = self.state.lock();
        debug_assert!(state.death.is_none());
        state.death = Some(death);
        let mut owed = None;
        state.requests.bury_with(|request_id, opcode, armed| {
            let Some(armed) = armed else {
                return;
            };
            let reply = armed.into_reply();
            if let Failed::Thread = reply.fail() {
                // The pool lends a connection to one request at a time.
                debug_assert!(owed.is_none(), "two requests without a caller");
                owed = Some(Owed {
                    request_id,
                    opcode,
                    reply,
                });
            }
        });
        state.owed = owed;
    }

    /// Every `Err` ends the connection: the reader buries it with the death
    /// it returns.
    pub(crate) fn receive(&self) -> core::result::Result<Received, Death> {
        self.link.receive(self)
    }

    /// Removes the request `request_id`, to which a reply of `raw_opcode`
    /// arrived, from the table.
    ///
    /// The core matches the reply to its request and checks the opcode it
    /// echoes, because the table is what knows which opcode that id was sent
    /// under. Ids are handed out in order, so the id retired here is not
    /// claimed again while the pieces of this reply arrive.
    ///
    /// A failure gives the death it is, and the request when the table took
    /// it out: that reply is outside the table traversal, and the reader ends
    /// it.
    fn route(
        &self,
        request_id: u64,
        raw_opcode: u16,
    ) -> core::result::Result<Armed, (Death, Option<Armed>)> {
        let answer = {
            let mut state = self.state.lock();
            // The death already failed every waiter. After a clean close the
            // drain reads the rest of this reply, and after any other death
            // the link is shut in both directions.
            if let Some(death) = state.death {
                return Err((death, None));
            }
            // The server reads the frames of a connection in order, so a
            // reply shows that it read every forget written before it.
            state.forgets.clear();
            state.requests.answer(request_id, raw_opcode)
        };
        answer
            .route(request_id, raw_opcode)
            .map_err(|failure| (Death::Protocol(Fault::Routing(failure.fault)), failure.wake))
    }

    /// Ends the connection with `death`, then ends `removed`, a reply the
    /// reader took out of the table, as the death path ends the replies in
    /// the table, and returns `death`.
    ///
    /// The reply is ended after the source is terminated, which released the
    /// references to the reply that the peer had. The thread of the
    /// connection settles the request when no caller waits for it.
    fn lose(&self, death: Death, removed: Removed) -> Death {
        self.bury(death);
        self.settle_removed(removed);
        death
    }

    /// Ends `removed`, a reply the reader took out of the table, of a
    /// connection that ended, and leaves the request to the thread of the
    /// connection when no caller waits for it.
    fn settle_removed(&self, removed: Removed) {
        removed.reply.abort_fill(removed.landing);
        if let Failed::Thread = removed.reply.fail() {
            let mut state = self.state.lock();
            // The pool lends a connection to one request at a time.
            debug_assert!(state.owed.is_none(), "two requests without a caller");
            state.owed = Some(Owed {
                request_id: removed.request_id,
                opcode: removed.opcode,
                reply: removed.reply,
            });
        }
    }

    /// Ends this connection over a protocol fault a caller found while
    /// interpreting its own reply.
    pub(crate) fn poison(&self, fault: FramingError) {
        self.bury(Death::Protocol(Fault::Framing(fault)));
    }
}

/// `InPlace` has the device put the pieces in the pages of the read, with room
/// for `room` bytes of them, and `placed` counts the bytes that arrived.
enum Arrival {
    Inline,
    InPlace { room: usize, placed: usize },
}

impl Arrival {
    fn placed(&self) -> usize {
        match self {
            Self::Inline => 0,
            Self::InPlace { placed, .. } => *placed,
        }
    }
}

/// Reads the rest of a reply whose header is read into its landing, from
/// `source`: the message into its buffer, then its pieces, if any, where the
/// request set them to go, or, for the data pieces of a read, where they
/// arrived as `arrival` sets.
fn fill(
    source: &impl Source,
    header: &[u8; FRAME_HEADER_LEN],
    landing: &mut Landing,
    arrival: &mut Arrival,
) -> core::result::Result<(), Death> {
    let allowed = landing.frame.len();
    let Some(front) = landing.frame.get_mut(..FRAME_HEADER_LEN) else {
        return Err(Death::Protocol(Fault::ReplyTooLong {
            declared: FRAME_HEADER_LEN,
            allowed,
        }));
    };
    front.copy_from_slice(header);
    let follows = match read_rest(source, &mut landing.frame, FRAME_HEADER_LEN).map_err(death_of)? {
        ReadFrame::Whole(len, follows) => {
            landing.len = len;
            follows
        }
        ReadFrame::BufferTooSmall { declared, .. } => {
            return Err(Death::Protocol(Fault::ReplyTooLong { declared, allowed }))
        }
        ReadFrame::HeaderClosed => {
            return Err(Death::Transport(crate::errno::econnreset()));
        }
    };
    if let Follows::Pieces(kind) = follows {
        landing.closing = Some(stream_pieces(source, kind, &mut landing.pieces, arrival)?);
    }
    Ok(())
}

/// Reads the pieces of a streamed reply from `source` into `pieces`, up to and
/// including its closing piece. Each length is checked against the room left
/// before a byte of the piece is read, so nothing is copied past the
/// destination.
fn stream_pieces(
    source: &impl Source,
    kind: PieceKind,
    pieces: &mut Pieces,
    arrival: &mut Arrival,
) -> core::result::Result<Closing, Death> {
    let bound = kind.piece_bound(&LIMITS).map_or(u64::MAX, u64::from);
    loop {
        let len = match read_piece(source).map_err(death_of)? {
            Piece::Closing(closing) => return Ok(closing),
            Piece::Of(len) => len,
        };
        let framing = |fault| Death::Protocol(Fault::Framing(fault));
        match (&mut *pieces, kind) {
            (Pieces::Read(range), PieceKind::Data) => match arrival {
                Arrival::Inline => {
                    piece::check(len, range.remaining()).map_err(framing)?;
                    range
                        .receive(source, len as usize)
                        .map_err(Death::Transport)?;
                }
                Arrival::InPlace { room, placed } => {
                    let left = range.remaining().min((*room - *placed) as u64);
                    piece::check(len, left).map_err(framing)?;
                    range.advance(len as usize);
                    *placed += len as usize;
                }
            },
            (Pieces::Entries { buffer, len: have }, PieceKind::DirEntries) => {
                let room = (buffer.len() - *have) as u64;
                piece::check(len, room.min(bound)).map_err(framing)?;
                let end = *have + len as usize;
                source
                    .receive_exact(&mut buffer[*have..end])
                    .map_err(Death::Transport)?;
                // One piece is exactly one entry.
                piece::entry::<DirEntryHeader>(&buffer[*have..end], LIMITS.name_max)
                    .map_err(framing)?;
                *have = end;
            }
            (Pieces::Bytes { buffer, len: have }, PieceKind::Data) => {
                piece::check(len, (buffer.len() - *have) as u64).map_err(framing)?;
                let end = *have + len as usize;
                source
                    .receive_exact(&mut buffer[*have..end])
                    .map_err(Death::Transport)?;
                *have = end;
            }
            (Pieces::Drained { room }, PieceKind::Data) => {
                match arrival {
                    Arrival::Inline => {
                        piece::check(len, *room).map_err(framing)?;
                        source.discard(len as usize).map_err(Death::Transport)?;
                    }
                    Arrival::InPlace { room: area, placed } => {
                        let left = (*room).min((*area - *placed) as u64);
                        piece::check(len, left).map_err(framing)?;
                        *placed += len as usize;
                    }
                }
                *room -= u64::from(len);
            }
            _ => return Err(Death::Protocol(Fault::Unrequested)),
        }
    }
}

fn death_of(error: ReadError) -> Death {
    match error {
        ReadError::Transport(error) => Death::Transport(error),
        ReadError::Framing(fault) => Death::Protocol(Fault::Framing(fault)),
    }
}

pub(crate) fn sent_of(transmit: Transmit) -> Sent {
    match transmit {
        Transmit::Written => Sent::Written,
        Transmit::Dead | Transmit::Cancelled | Transmit::Failed(_) => Sent::Queued,
    }
}
