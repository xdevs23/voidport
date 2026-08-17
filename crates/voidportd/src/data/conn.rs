//! One data-plane connection.
//!
//! The shape of a connection is fixed by the design's concurrency contract:
//!
//! * **one reader task** per connection, which does nothing but frame bytes;
//! * **each request served on the blocking pool**, closure and all: the host
//!   syscalls run there and the very same closure queues the reply, so a slow
//!   disk stalls one request, not the reactor, and a plain request costs one
//!   hop onto the pool and none back;
//! * **a request that waits, waits as a future.** A blocking lock whose range
//!   another owner holds hands back a [`ops::LockWait`] instead of sleeping in
//!   the syscall, and this task polls it. Hundreds of stacked waiters therefore
//!   cost hundreds of parked futures instead of hundreds of pool threads, and
//!   the connection ending cancels every one of them;
//! * **one writer task**, which serializes response frames — replies may
//!   therefore complete out of order, and the `request_id` matches them up. It
//!   drains replies in **two classes**: small ones first, bulk ones after (see
//!   [`Replies`]). It has a **third intake**: the session's share-notification
//!   queue, drained after both. Notifications carry `request_id` 0 and answer
//!   nothing, so they bypass the id bookkeeping entirely, and the in-flight
//!   permit machinery never governs them.
//!
//! **Why two reply classes.** One FIFO for every reply puts a `getattr` behind
//! whatever bulk read replies a pipelining client has already asked for, and a
//! client reading ahead keeps several 128 KiB replies queued at all times —
//! measured at many times the latency an interactive operation is promised.
//! Splitting the queue by payload size fixes that at its cause: a reply above
//! [`BULK_REPLY_BYTES`] drains only when no small reply is waiting, so a
//! metadata answer never queues behind bulk data. Within each class the order
//! is strictly the order replies were finished, which is all the wire contract
//! asks — replies may complete out of order and the `request_id` matches them
//! up. The classes are internal scheduling: not one byte of any frame changes.
//!
//! Bulk is scheduled *below* small replies and *above* notifications, which
//! keeps the subscription contract's required "replies before notifications"
//! exactly as it was. And bulk is never starved: after
//! [`SMALL_REPLIES_BEFORE_BULK`] small replies in a row the writer takes a bulk
//! one regardless, so a client that keeps small replies coming cannot stop its
//! own data.
//!
//! Backpressure is the interesting part, and **every connection runs under
//! it**. A session may have
//! [`Limits::max_inflight`](crate::data::caps::Limits::max_inflight) requests
//! being served; the reader takes a permit *before* it reads the next frame, so
//! at the bound it simply stops reading. The socket buffer fills, the client's
//! own kernel throttles it, and nothing is answered with an error for being
//! busy. That one mechanism also bounds the blocking pool and the reply queue,
//! since neither can outgrow the number of requests in flight.
//!
//! With the cap unconfigured — the default — the number is the server's own,
//! [`RUN_AHEAD_REQUESTS`], and everything else is identical: the same permit
//! per request, the same pause instead of an error, the same reply queue sized
//! by the same number. A read loop with no bound dispatches as fast as frames
//! arrive, so a client that floods cheap requests has them all being served at
//! once (measured 2026-08-17: a `forget` flood after a 200 000-name walk drove
//! the blocking pool to its thread ceiling and the resident set a third above
//! its plateau, where the bound holds the same transient inside the noise).
//! What no bound here ever does is refuse: a full reply queue only makes a
//! finished request wait for the writer's syscall.
//!
//! A framing error anywhere — in the handshake, in a request, in a reply the
//! writer could not deliver — poisons the stream, and the connection closes.
//! Closing drops the session, and with it every handle and node it held. That
//! holds at the cap as well: waiting for a permit watches the shutdown signal,
//! because the requests holding the permits may never complete on their own.
//!
//! Two properties of the byte stream itself are load-bearing for how fast a
//! connection can go, and both live here:
//!
//! * **the halves are split by the transport, not by a lock** ([`DataStream`]),
//!   because `tokio::io::split` puts the whole stream behind one
//!   `std::sync::Mutex` that the reader takes on every poll and the writer on
//!   every reply — measured contention between the two directions of one
//!   connection;
//! * **the read side is buffered** (a [`tokio::io::BufReader`] of
//!   [`READ_BUFFER_BYTES`] around the read half), so a header and the body that
//!   arrived with it cost one `read(2)` between them, not one each.

use std::collections::HashSet;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use rustix::io::Errno;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream, tcp, unix};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{FRAME_HEADER_LEN, Frame, FrameWriter, MAX_HELLO_FRAME_LEN};
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::handshake::{HelloReply, HelloRequest};
use zerocopy::byteorder::little_endian::{U32, U64};

use super::caps::Limits;
use super::ops::{self, Served};
use super::server::DataPlane;
use super::session::{Peer, Session};
use super::sessions::Registered;
use super::subscribe::Wake;
use crate::data::node::ROOT_NODE_ID;

/// A byte stream a data connection can be served over.
///
/// The framing is transport-agnostic, so a transport only has to say how its
/// stream comes apart into a reading and a writing half — and it has to come
/// apart **without a shared lock**, which is why this trait exists instead of
/// a bare `AsyncRead + AsyncWrite` bound with `tokio::io::split`.
///
/// Tcp and unix are implemented below, on tokio's own owned splits; vsock has
/// no owned split that is free of a lock, so it splits by duplicating its
/// descriptor in [`super::vsock`].
pub trait DataStream: Send + 'static {
    /// The reading half, driven by the connection's read loop.
    type Reader: AsyncRead + Unpin + Send + 'static;
    /// The writing half, driven by the connection's writer task.
    type Writer: AsyncWrite + Unpin + Send + 'static;

    /// Takes the stream apart.
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

/// The largest frame the server accepts once a session is established, and the
/// value it announces in `HelloReply`.
///
/// It bounds both directions: a client may not send a larger frame, and the
/// server never encodes one.
pub const MAX_FRAME_LEN: u32 = 1024 * 1024;

/// The read buffer one connection holds.
///
/// Large enough that a saturated connection's small request frames arrive many
/// to a `read(2)`, small enough to cost nothing to hold per session. A frame
/// larger than it — a bulk write, up to [`MAX_FRAME_LEN`] — is read straight
/// into its own allocation by [`BufReader`] itself, so the per-connection cost
/// stays this buffer, not the frame bound.
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// How far a client may run ahead of the server on a connection the operator
/// capped at nothing: the in-flight bound the data plane holds itself to, in
/// requests.
///
/// It is not a cap in the operator's sense. It refuses nothing and it is not
/// configurable — it is the permit the configured cap takes, at a number the
/// server chose, so reaching it pauses the read loop and the socket buffer
/// absorbs the rest. It exists because an unbounded read loop was measured and
/// costly: a `forget` flood behind a 200 000-name walk ran the blocking pool to
/// its 512-thread ceiling and the resident set to 35% above its plateau, where
/// this bound gives 1.9% and 245 threads, settles 12.7 MiB lower, and leaves
/// the walk and 16-client throughput at parity.
///
/// **The value is measured, not a round number to raise.** At 1024 the same
/// flood still cost 5.3% and the full 512 threads, and 16 concurrent clients
/// over one mount lost 19% of their aggregate throughput against no bound at
/// all — worse, on the ceiling that matters most, than either neighbour. Do not
/// round it up.
const RUN_AHEAD_REQUESTS: usize = 64;

/// The payload size at which a reply is scheduled as **bulk**.
///
/// Everything a client waits on interactively — every attribute, entry, lock
/// and status reply — is far below it, and everything that occupies the wire
/// long enough to delay one is above: a prefetching client's 128 KiB read
/// replies, and any other answer large enough that a small reply should not
/// queue behind it.
const BULK_REPLY_BYTES: usize = 64 * 1024;

/// How many small replies may be written in a row while bulk replies wait.
///
/// The anti-starvation bound. Priority without one would let a client that
/// keeps small replies coming hold its own data off the wire indefinitely; with
/// it, bulk drains at worst one frame per this many small ones, and an
/// interactive reply still never waits for more than the frame already being
/// written.
const SMALL_REPLIES_BEFORE_BULK: u32 = 8;

/// Serves one connection until it ends.
///
/// Never fails outward: everything that can go wrong ends the connection, which
/// is the only remedy a byte stream has.
pub async fn serve<S: DataStream>(stream: S, plane: Arc<DataPlane>, peer: Peer) {
    let transport = peer.transport;
    let address = peer.address.clone();
    if let Err(error) = converse(stream, plane, peer).await {
        tracing::debug!(%error, %transport, peer = %address, "data connection ended");
    }
}

/// The request/response loop of one connection, handshake included.
async fn converse<S: DataStream>(stream: S, plane: Arc<DataPlane>, peer: Peer) -> io::Result<()> {
    let (reader, mut writer) = stream.split();
    // Buffered from the handshake on, so anything a client pipelined behind its
    // `Hello` is held, not left in the socket for a second read syscall.
    let mut reader = BufReader::with_capacity(READ_BUFFER_BYTES, reader);

    // Pre-handshake, frames are bounded by a fixed constant: nothing has been
    // negotiated yet, so nothing may be trusted about size.
    let Some(hello) = read_frame(&mut reader, MAX_HELLO_FRAME_LEN).await? else {
        return Ok(());
    };
    let outcome = handshake(&plane, &peer, &hello);
    if let Some(reply) = encode_handshake_reply(&outcome)? {
        writer.write_all(&reply).await?;
        writer.flush().await?;
    }
    let (session, _registration) = match outcome {
        Ok(Accepted {
            session,
            registration,
            ..
        }) => (session, registration),
        Err(_) => return Ok(()),
    };

    // One number governs the whole connection, and there is only ever one
    // posture below it: the permits and the reply queue are both sized by it,
    // capped or not.
    let inflight = inflight_bound(session.limits());
    let (outgoing, incoming) = queues(inflight);
    let (stop, stopped) = watch::channel(false);
    let permits = Arc::new(Semaphore::new(inflight));
    let outstanding = Arc::new(Mutex::new(HashSet::new()));

    let writing = tokio::spawn(write_replies(
        writer,
        incoming,
        stop.clone(),
        stop.subscribe(),
        Arc::clone(&outstanding),
        Arc::clone(&session),
    ));
    let result = read_requests(
        &mut reader,
        &session,
        &outgoing,
        &permits,
        &outstanding,
        stopped,
    )
    .await;

    // However the read loop ended — end of stream, a framing error, or the
    // writer giving up — the connection is over. Signalling *before* awaiting
    // the writer is what makes the close prompt: a request already on the
    // blocking pool cannot be cancelled, and a client must not be left waiting
    // on a socket the server has finished with.
    let _ = stop.send(true);
    drop(outgoing);
    let _ = writing.await;
    // A request still on the blocking pool holds the session too, so the
    // teardown is explicit, not left to the last reference: the
    // connection is over, and the handles, nodes and host descriptors it named
    // go with it. The subscription goes with it as well — the queue it feeds is
    // this connection's, and nothing must be enqueued into a queue nobody
    // drains any more.
    session.unsubscribe();
    session.teardown();
    result
}

/// Reads and dispatches requests until the connection ends.
async fn read_requests<R>(
    reader: &mut R,
    session: &Arc<Session>,
    outgoing: &Outbox,
    permits: &Arc<Semaphore>,
    outstanding: &Arc<Mutex<HashSet<u64>>>,
    mut stopped: watch::Receiver<bool>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        // Taken before the read: at the bound the connection simply stops
        // reading, which is the backpressure the design asks for.
        let Some(permit) = acquire(permits, &mut stopped).await else {
            return Ok(());
        };
        let frame = tokio::select! {
            biased;
            _ = stopped.wait_for(|stopped| *stopped) => return Ok(()),
            frame = read_frame(reader, MAX_FRAME_LEN) => frame?,
        };
        let Some(bytes) = frame else {
            return Ok(());
        };
        if let Err(error) = track(&bytes, outstanding) {
            return Err(framing(error));
        }

        let session = Arc::clone(session);
        let outgoing = outgoing.clone();
        let mut cancelled = stopped.clone();
        // The request is served **from** the blocking closure, which queues its
        // own reply. What this replaced was an outer task that did nothing but
        // await the pool and forward what came back, and that join cost two of
        // the five voluntary context switches every round trip paid.
        //
        // The queue handoff must never park this pool thread: pool threads
        // are a process-global, hard-capped resource shared with every other
        // connection AND the control plane, and a guest that stops draining
        // its socket would otherwise pin one per request until the pool is
        // gone. So the closure only ever try-sends; the rare full-queue case
        // falls back to a spawned task that awaits the send — the same
        // bounded wait the awaited handoff imposed, held by a task again.
        //
        // Replies enter the queue in completion order, from whichever thread
        // finished one, exactly as before: not one byte and not one ordering
        // rule of the two-class outbox changes here.
        tokio::task::spawn_blocking(move || {
            // The permit rides in with the closure and is released when the
            // closure ends, whichever way it ends — or, on the two arms that
            // hand the rest of the request to a task, when *that* task ends.
            // That is what keeps the cap honest: a parked lock wait holds one
            // exactly as the blocking wait it replaced did.
            let request_id = request_id_of(&bytes);
            let message = match serve_request(&session, &bytes) {
                Ok(Served::Reply(bytes)) => Outgoing::Frame { request_id, bytes },
                Ok(Served::Silent) => return,
                Ok(Served::Subscribed(bytes)) => {
                    // The confirm goes on the reply queue *first*, and only
                    // then is the subscription registered — which is what
                    // queues the snapshot. The writer prefers replies over
                    // notifications, so a confirm already queued can never be
                    // overtaken by a snapshot part queued after it. That is the
                    // contract's ordering, established here, not hoped
                    // for downstream. It takes a task because the two steps
                    // must not be split by a queue full enough to park this
                    // pool thread between them.
                    tokio::spawn(async move {
                        let _permit = permit;
                        outgoing.send(Outgoing::Frame { request_id, bytes }).await;
                        session.subscribe();
                    });
                    return;
                }
                Ok(Served::Waiting(wait)) => {
                    // The wait is a future, so the connection dying really does
                    // cancel it: the select drops it where a blocking SETLKW
                    // would have held a pool thread until the holder let go.
                    // Which is the whole reason this arm keeps a task — holding
                    // the wait here would hold the pool thread it exists to
                    // give back.
                    tokio::spawn(async move {
                        let _permit = permit;
                        let settled = tokio::select! {
                            biased;
                            _ = cancelled.wait_for(|stopped| *stopped) => return,
                            settled = wait.settle() => settled,
                        };
                        let message = match settled {
                            Ok(bytes) => Outgoing::Frame { request_id, bytes },
                            Err(error) => Outgoing::Poisoned(error),
                        };
                        outgoing.send(message).await;
                    });
                    return;
                }
                Err(error) => Outgoing::Poisoned(error),
            };
            // Fast path: room in the queue, the reply is in, the permit drops
            // with the closure. Full queue: the wait moves to a task carrying
            // the reply and the permit, so the pool thread is free the moment
            // the closure ends. Within one class the fallback may land after
            // a reply finished later — the wire orders nothing across request
            // ids, so that is permitted, and the writer's class scheduling is
            // untouched either way.
            if let Err(message) = outgoing.try_send(message) {
                tokio::spawn(async move {
                    let _permit = permit;
                    outgoing.send(message).await;
                });
            }
        });
    }
}

/// Serves one request, turning a handler that unwinds into a poisoning.
///
/// Nothing joins the blocking task any more — the closure queues its own reply
/// — so a panic that escaped it would end the request in silence, leaving the
/// client waiting for an answer that can never come and its id outstanding for
/// as long as the connection lives. Catching it keeps exactly what awaiting the
/// join used to do with a failed handler: log it, and close the connection.
fn serve_request(session: &Session, bytes: &[u8]) -> Result<Served, FramingError> {
    let served = panic::catch_unwind(AssertUnwindSafe(|| {
        ops::serve(session, bytes, MAX_FRAME_LEN)
    }));
    served.unwrap_or_else(|_| {
        tracing::error!("a request handler failed");
        Err(FramingError::LengthOverflow)
    })
}

/// How many requests one connection may have in flight.
///
/// A configured cap is used exactly as configured: zero is refused when the
/// state file is loaded, so nothing here has to raise a number the operator
/// wrote and then enforce a different one. Absent, the number is
/// [`RUN_AHEAD_REQUESTS`] — the data plane's own bound, which is not a cap and
/// refuses nothing, so the only thing an operator's setting changes is the
/// number.
fn inflight_bound(limits: Limits) -> usize {
    limits.max_inflight.unwrap_or(RUN_AHEAD_REQUESTS)
}

/// Waits for an in-flight permit, giving up if the connection is stopping.
///
/// The wait has to watch the shutdown signal, because the requests holding the
/// permits are not guaranteed to finish on their own: a host syscall already on
/// the blocking pool cannot be cancelled, and a request parked on a lock is
/// only cancelled *by this very signal*, which it cannot deliver to itself.
/// A bare `acquire_owned` would therefore park a connection sitting at the
/// bound for as long as those requests last, deaf to the writer stopping the
/// stream on a framing error or a failed write. The read loop would never
/// return, [`converse`] would never reach `Session::teardown`, and the
/// session's handles, nodes, pinned descriptors and session-cap slot would
/// outlive the connection — against the required "connection drop or any
/// framing error tears down the session: all handles and nodes close".
async fn acquire(
    permits: &Arc<Semaphore>,
    stopped: &mut watch::Receiver<bool>,
) -> Option<OwnedSemaphorePermit> {
    tokio::select! {
        biased;
        _ = stopped.wait_for(|stopped| *stopped) => None,
        permit = Arc::clone(permits).acquire_owned() => permit.ok(),
    }
}

/// The producing end of the writer's two reply queues.
///
/// Classification happens **at enqueue**, from the encoded frame's own length,
/// so nothing downstream has to guess what a reply is: it is bulk if it is big.
#[derive(Clone, Debug)]
struct Outbox {
    small: mpsc::Sender<Outgoing>,
    bulk: mpsc::Sender<Outgoing>,
}

impl Outbox {
    /// The queue a message belongs in.
    ///
    /// A poisoning is a control signal, not a reply, and it takes the
    /// small queue so that a connection closes on a fault without waiting
    /// behind whatever data is still queued.
    fn queue(&self, message: &Outgoing) -> &mpsc::Sender<Outgoing> {
        match message {
            Outgoing::Frame { bytes, .. } if bytes.len() >= BULK_REPLY_BYTES => &self.bulk,
            Outgoing::Frame { .. } | Outgoing::Poisoned(_) => &self.small,
        }
    }

    /// Queues one message in the class its size puts it in.
    async fn send(&self, message: Outgoing) {
        let _ = self.queue(&message).send(message).await;
    }

    /// Queues one message without waiting, handing it back when the queue
    /// is full so the caller can move the wait somewhere that may hold it.
    ///
    /// Classification is the one [`send`](Self::send) uses, so which class a
    /// reply lands in never depends on which side queued it. A closed queue
    /// swallows the message: the connection is tearing down and the reply has
    /// nowhere to go, exactly as the awaited send treats it.
    fn try_send(&self, message: Outgoing) -> Result<(), Outgoing> {
        use tokio::sync::mpsc::error::TrySendError;
        match self.queue(&message).try_send(message) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(message)) => Err(message),
            Err(TrySendError::Closed(_)) => Ok(()),
        }
    }
}

/// The consuming end: the two queues, and the scheduling between them.
#[derive(Debug)]
struct Replies {
    small: mpsc::Receiver<Outgoing>,
    bulk: mpsc::Receiver<Outgoing>,
    /// How many small replies have been taken since the last bulk one.
    streak: u32,
    small_closed: bool,
    bulk_closed: bool,
}

impl Replies {
    /// The next reply to write, or `None` when both queues have closed — which
    /// is the connection ending.
    ///
    /// Small replies win, so a metadata answer never queues behind bulk data;
    /// after [`SMALL_REPLIES_BEFORE_BULK`] of them in a row a waiting bulk
    /// reply is taken instead, which is what stops priority from becoming
    /// starvation. Within each class the order is exactly the order the replies
    /// were finished in.
    ///
    /// Cancel-safe: `mpsc::Receiver::recv` is, the select is biased, and the
    /// counters only move on the branch that produced a value — so a caller
    /// that drops this future between polls loses nothing.
    async fn next(&mut self) -> Option<Outgoing> {
        loop {
            if self.small_closed && self.bulk_closed {
                return None;
            }
            let bulk_first = self.streak >= SMALL_REPLIES_BEFORE_BULK || self.small_closed;
            let taken = if bulk_first {
                tokio::select! {
                    biased;
                    message = self.bulk.recv(), if !self.bulk_closed => Taken::Bulk(message),
                    message = self.small.recv(), if !self.small_closed => Taken::Small(message),
                }
            } else {
                tokio::select! {
                    biased;
                    message = self.small.recv(), if !self.small_closed => Taken::Small(message),
                    message = self.bulk.recv(), if !self.bulk_closed => Taken::Bulk(message),
                }
            };
            match taken {
                Taken::Small(Some(message)) => {
                    self.streak += 1;
                    return Some(message);
                }
                Taken::Bulk(Some(message)) => {
                    self.streak = 0;
                    return Some(message);
                }
                // One class closing is not the connection ending: the other may
                // still hold replies that were queued before it did.
                Taken::Small(None) => self.small_closed = true,
                Taken::Bulk(None) => self.bulk_closed = true,
            }
        }
    }
}

/// Which queue a reply came off.
#[derive(Debug)]
enum Taken {
    Small(Option<Outgoing>),
    Bulk(Option<Outgoing>),
}

/// Builds one connection's reply queues, each of `depth`.
fn queues(depth: usize) -> (Outbox, Replies) {
    let (small_in, small) = mpsc::channel::<Outgoing>(depth);
    let (bulk_in, bulk) = mpsc::channel::<Outgoing>(depth);
    (
        Outbox {
            small: small_in,
            bulk: bulk_in,
        },
        Replies {
            small,
            bulk,
            streak: 0,
            small_closed: false,
            bulk_closed: false,
        },
    )
}

/// Writes replies in the order they complete.
///
/// It stops on the shutdown signal as well as on the end of the reply channel,
/// so a connection whose stream was poisoned closes at once instead of waiting
/// for requests that are still on the blocking pool.
///
/// It is also where a request id retires, the moment its reply is taken off the
/// queue to be written. An id is therefore outstanding from the acceptance of
/// its request frame until its response is handed to the transport, which is
/// the last instant the server can still be sure the client has not seen the
/// answer. Retiring *after* the flush instead would be a race against a
/// perfectly compliant client: the contract makes an id reusable "once its
/// response has arrived", arrival happens one round trip after the flush, and a
/// writer preempted in between would have the reader kill an innocent session
/// with a duplicate-id framing error. Duplicates that matter — a second request
/// carrying an id whose answer has not been produced — are still caught, which
/// is what keeps two indistinguishable replies off the wire.
/// It drains a **further intake** as well: the session's share-notification
/// queue. Both reply classes are polled first, and that priority is
/// load-bearing, not a preference — the subscription contract requires
/// the `Subscribe` confirm to precede the first snapshot part, the confirm is
/// queued before the registration that queues the snapshot, and preferring
/// replies is what turns "queued first" into "written first". A notification
/// retires no id, because a notification answers nothing.
async fn write_replies<W>(
    mut writer: W,
    mut incoming: Replies,
    stop: watch::Sender<bool>,
    mut stopped: watch::Receiver<bool>,
    outstanding: Arc<Mutex<HashSet<u64>>>,
    session: Arc<Session>,
) where
    W: AsyncWrite + Unpin,
{
    let notifications = Arc::clone(session.notifications());
    loop {
        let intake = tokio::select! {
            biased;
            _ = stopped.wait_for(|stopped| *stopped) => break,
            message = incoming.next() => Intake::Reply(message),
            wake = notifications.next() => Intake::Notification(wake),
        };
        let bytes = match intake {
            // The reply channel closing is the connection ending.
            Intake::Reply(None) => break,
            Intake::Reply(Some(Outgoing::Frame { request_id, bytes })) => {
                retire(request_id, &outstanding);
                bytes
            }
            Intake::Reply(Some(Outgoing::Poisoned(error))) => {
                tracing::debug!(%error, "closing a data connection on a framing error");
                break;
            }
            Intake::Notification(Wake::Frame(bytes)) => bytes,
            Intake::Notification(Wake::Lapsed) => {
                // The queue this consumer let fill was dropped; now that it is
                // drained, the server owes it a fresh snapshot, unprompted.
                tracing::debug!(
                    session = session.id(),
                    "a share subscription lapsed; resnapshotting"
                );
                session.refresh_subscription();
                continue;
            }
        };
        if writer.write_all(&bytes).await.is_err() || writer.flush().await.is_err() {
            break;
        }
    }
    // Whether the stream was poisoned or the client went away, the reader must
    // stop too.
    let _ = stop.send(true);
}

/// What the writer's two intakes hand it.
#[derive(Debug)]
enum Intake {
    /// The reply queue; `None` when it has closed.
    Reply(Option<Outgoing>),
    /// The share-notification queue.
    Notification(Wake),
}

/// What the writer task is handed.
#[derive(Debug)]
enum Outgoing {
    /// A response frame to deliver, and the request id it retires once the
    /// client has it.
    Frame {
        /// The id of the request being answered.
        request_id: Option<u64>,
        /// The encoded response frame.
        bytes: Vec<u8>,
    },
    /// The stream is poisoned; close the connection.
    Poisoned(FramingError),
}

/// A handshake the server accepted.
struct Accepted {
    request_id: u64,
    session: Arc<Session>,
    registration: Registered,
}

/// A handshake the server refused, and the id to answer it on.
struct Refused {
    request_id: Option<u64>,
    errno: Errno,
}

/// Resolves a `Hello` into a session.
///
/// Every refusal below is a *response*, not a dropped connection: the client is
/// owed the reason its mount failed. Only a malformed or misplaced frame — a
/// first frame that is not a `Hello` — poisons the stream.
fn handshake(plane: &DataPlane, peer: &Peer, bytes: &[u8]) -> Result<Accepted, Refused> {
    let frame = Frame::parse(bytes, MAX_HELLO_FRAME_LEN).map_err(|_| Refused {
        request_id: None,
        errno: Errno::PROTO,
    })?;
    let request_id = frame.request_id();
    let request = frame.request::<HelloRequest>().map_err(|_| Refused {
        request_id: None,
        errno: Errno::PROTO,
    })?;
    let refuse = |errno| Refused {
        request_id: Some(request_id),
        errno,
    };

    if request.body().protocol_version.get() != PROTOCOL_VERSION {
        return Err(refuse(Errno::PROTO));
    }
    // v1 serves `auth.mode: none` only, and a nonempty blob under it is a
    // client that believes something the server does not.
    if !request.auth().is_empty() {
        return Err(refuse(Errno::INVAL));
    }
    let name = std::str::from_utf8(request.namespace())
        .ok()
        .and_then(|name| voidport_control::NamespaceName::new(name).ok())
        .ok_or_else(|| refuse(Errno::INVAL))?;
    // One snapshot read for both: the namespace this mount serves and the
    // record store it records through. A namespace deleted between the two
    // would otherwise hand a session a store the registry no longer names.
    let (namespace, records) = plane.mount_of(&name).ok_or_else(|| refuse(Errno::NOENT))?;
    let records = records.ok_or_else(|| refuse(Errno::NOENT))?;
    let subpath = parse_subpath(request.subpath()).map_err(refuse)?;

    let reservation = plane
        .sessions()
        .reserve()
        .ok_or_else(|| refuse(Errno::MFILE))?;
    let session = Session::mount(
        reservation.id(),
        peer.clone(),
        plane.registries(),
        namespace,
        records,
        subpath,
        plane.identity(),
        plane.limits(),
    )
    .map_err(refuse)?;
    let session = Arc::new(session);
    let registration = reservation.attach(Arc::clone(&session));
    Ok(Accepted {
        request_id,
        session,
        registration,
    })
}

/// Encodes the frame that answers a `Hello`, if there is one to send.
///
/// Accepted, it carries the parameters the rest of the session runs under —
/// including [`MAX_FRAME_LEN`], the bound both directions are held to from
/// here on. Refused, it carries the errno, because the client is owed the
/// reason its mount failed.
///
/// Two refusals answer nothing: one whose frame was too malformed to name a
/// request id, and one that cannot be encoded — the connection is closing
/// either way, and a second failure adds nothing. An accepted handshake that
/// cannot be encoded is a framing error, and it poisons the stream.
///
/// The frame is bounded by [`MAX_HELLO_FRAME_LEN`] in both cases: it is written
/// before anything is negotiated, under the pre-handshake bound.
fn encode_handshake_reply(outcome: &Result<Accepted, Refused>) -> io::Result<Option<Vec<u8>>> {
    match outcome {
        Ok(accepted) => {
            let mut buffer = [0u8; 64];
            let reply = FrameWriter::response(
                &mut buffer,
                MAX_HELLO_FRAME_LEN,
                accepted.request_id,
                &HelloReply {
                    root_node_id: U64::new(ROOT_NODE_ID),
                    protocol_version: U32::new(PROTOCOL_VERSION),
                    flags: U32::ZERO,
                    max_frame_len: U32::new(MAX_FRAME_LEN),
                    reserved: U32::ZERO,
                },
            )
            .and_then(FrameWriter::finish)
            .map_err(framing)?;
            Ok(Some(reply.to_vec()))
        }
        Err(refusal) => {
            let Some(request_id) = refusal.request_id else {
                return Ok(None);
            };
            let mut buffer = [0u8; FRAME_HEADER_LEN + 4];
            let reply = FrameWriter::error_response(
                &mut buffer,
                MAX_HELLO_FRAME_LEN,
                request_id,
                Opcode::Hello,
                -refusal.errno.raw_os_error(),
            );
            Ok(reply.ok().map(|reply| reply.to_vec()))
        }
    }
}

/// Parses a mount subpath.
///
/// An empty subpath is the namespace root: a mount URL with nothing after the
/// namespace name means "the whole namespace".
fn parse_subpath(raw: &[u8]) -> Result<crate::rules::NamespacePath, Errno> {
    if raw.is_empty() {
        return Ok(crate::rules::NamespacePath::root());
    }
    crate::rules::NamespacePath::parse_bytes(raw).map_err(|_| Errno::INVAL)
}

/// Records a response-expecting request id, rejecting a duplicate.
///
/// A `forget` retires the moment its frame is accepted — it has no response to
/// wait for — so its id is immediately reusable and never tracked here.
fn track(bytes: &[u8], outstanding: &Mutex<HashSet<u64>>) -> Result<(), FramingError> {
    let Some(header) = frame_header(bytes) else {
        return Ok(());
    };
    if header.opcode().is_ok_and(|opcode| !opcode.has_response()) {
        return Ok(());
    }
    let request_id = header.request_id.get();
    let inserted = outstanding
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .insert(request_id);
    if inserted {
        Ok(())
    } else {
        Err(FramingError::DuplicateRequestId { request_id })
    }
}

/// Retires a request id as its response leaves for the transport.
///
/// A write that then fails closes the connection, so an id retired for a reply
/// the client never receives outlives nothing.
fn retire(request_id: Option<u64>, outstanding: &Mutex<HashSet<u64>>) {
    if let Some(request_id) = request_id {
        outstanding
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&request_id);
    }
}

/// The request id of a buffered frame, if it has a well-formed header.
fn request_id_of(bytes: &[u8]) -> Option<u64> {
    frame_header(bytes).map(|header| header.request_id.get())
}

/// Views the frame header at the front of a buffer.
fn frame_header(bytes: &[u8]) -> Option<&voidport_proto::frame::FrameHeader> {
    use zerocopy::FromBytes as _;
    voidport_proto::frame::FrameHeader::ref_from_prefix(bytes)
        .ok()
        .map(|(header, _)| header)
}

/// Reads exactly one frame, bounded by `max_frame_len`.
///
/// The bound is applied to the *declared* length before anything is allocated,
/// so a peer cannot make the server hold a buffer it announced but will never
/// fill. It may change between calls: the handshake is read under the
/// pre-handshake bound and every later request under the negotiated one, over
/// the same buffered reader, so bytes a client pipelined behind its `Hello` are
/// not lost.
///
/// `Ok(None)` is end of stream on a frame boundary — or a header that stopped
/// half way, which is a client that went away mid-write and not something to
/// report as a protocol fault.
async fn read_frame<R>(reader: &mut R, max_frame_len: u32) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let Some(len) = Frame::peek_len(&header, max_frame_len).map_err(framing)? else {
        return Ok(None);
    };
    let mut bytes = vec![0u8; len as usize];
    bytes[..FRAME_HEADER_LEN].copy_from_slice(&header);
    reader.read_exact(&mut bytes[FRAME_HEADER_LEN..]).await?;
    Ok(Some(bytes))
}

/// A framing error, as the connection's I/O layer reports it.
fn framing(error: FramingError) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use voidport_proto::message::RequestHead;
    use voidport_proto::ops::node::{ForgetRequest, GetattrRequest};

    /// One encoded request frame.
    fn request<M: voidport_proto::message::RequestBody>(request_id: u64, body: &M) -> Vec<u8> {
        let mut buffer = [0u8; 128];
        let head = RequestHead::new(1, 0, 0, 0);
        FrameWriter::request(&mut buffer, MAX_FRAME_LEN, request_id, &head, body)
            .and_then(FrameWriter::finish)
            .expect("encodable")
            .to_vec()
    }

    /// A reader shaped exactly like a connection's: the buffered wrapper every
    /// request is read through.
    fn reader(bytes: Vec<u8>) -> BufReader<std::io::Cursor<Vec<u8>>> {
        BufReader::with_capacity(READ_BUFFER_BYTES, std::io::Cursor::new(bytes))
    }

    /// The two ends of a frame the buffering may not blur: several frames in
    /// one buffer are still handed out one at a time under the bound in force,
    /// and a body a header announced and the peer never sent is an error, not
    /// a close.
    #[tokio::test]
    async fn buffered_frames_are_read_one_at_a_time_and_a_missing_body_is_not_a_close() {
        let getattr = GetattrRequest {
            handle: U64::ZERO,
            flags: U32::ZERO,
            reserved: U32::ZERO,
        };
        let mut stream = Vec::new();
        for request_id in 1..=4 {
            stream.extend_from_slice(&request(request_id, &getattr));
        }
        let mut buffered = reader(stream);
        for request_id in 1..=4 {
            assert_eq!(
                read_frame(&mut buffered, MAX_FRAME_LEN)
                    .await
                    .expect("readable"),
                Some(request(request_id, &getattr))
            );
        }
        assert_eq!(
            read_frame(&mut buffered, MAX_FRAME_LEN)
                .await
                .expect("a clean close"),
            None
        );

        let bytes = request(5, &getattr);
        // A header that never completes is a peer that went away between
        // frames.
        let mut half_header = reader(bytes[..8].to_vec());
        assert_eq!(
            read_frame(&mut half_header, MAX_FRAME_LEN)
                .await
                .expect("closed"),
            None
        );
        // A body the header announced and the peer never sent is not.
        let mut half_body = reader(bytes[..bytes.len() - 1].to_vec());
        assert_eq!(
            read_frame(&mut half_body, MAX_FRAME_LEN)
                .await
                .expect_err("truncated")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        // The bound is applied per frame, to the declared length, before
        // anything is allocated.
        let mut bounded = reader(bytes);
        assert!(
            read_frame(&mut bounded, FRAME_HEADER_LEN as u32)
                .await
                .is_err(),
            "a frame over the bound in force is refused"
        );
    }

    #[test]
    fn a_duplicate_outstanding_id_is_a_framing_error() {
        let outstanding = Mutex::new(HashSet::new());
        let getattr = request(
            7,
            &GetattrRequest {
                handle: U64::ZERO,
                flags: U32::ZERO,
                reserved: U32::ZERO,
            },
        );
        assert!(track(&getattr, &outstanding).is_ok());
        assert!(
            track(&getattr, &outstanding).is_err(),
            "an id may not be outstanding twice"
        );
        retire(Some(7), &outstanding);
        assert!(
            track(&getattr, &outstanding).is_ok(),
            "an answered id is reusable"
        );
    }

    #[test]
    fn forget_ids_retire_on_acceptance_and_may_repeat_freely() {
        let outstanding = Mutex::new(HashSet::new());
        let forget = request(
            9,
            &ForgetRequest {
                nlookup: U64::new(1),
            },
        );
        for _ in 0..100 {
            assert!(
                track(&forget, &outstanding).is_ok(),
                "a no-response request never stays outstanding"
            );
        }
        assert!(outstanding.lock().expect("unpoisoned").is_empty());
    }

    /// A connection at the in-flight bound whose requests never complete — a
    /// blocking lock held by another session is enough — must still notice the
    /// writer stopping the stream, or its session is never torn down.
    #[tokio::test]
    async fn the_wait_for_an_in_flight_permit_ends_when_the_connection_stops() {
        let permits = Arc::new(Semaphore::new(1));
        let held = Arc::clone(&permits)
            .acquire_owned()
            .await
            .expect("the bound is open");
        let (stop, mut stopped) = watch::channel(false);

        // At the bound the reader waits, which is the backpressure.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                acquire(&permits, &mut stopped),
            )
            .await
            .is_err(),
            "an occupied bound pauses the read loop"
        );

        // The writer poisons the stream while the request holding the permit is
        // still on the host: the wait has to end anyway.
        stop.send(true).expect("the reader still waits");
        assert!(
            acquire(&permits, &mut stopped).await.is_none(),
            "a stopping connection stops waiting for a permit"
        );
        drop(held);
    }

    /// The number one connection runs under: the operator's where they wrote
    /// one, and the run-ahead bound where they wrote none. A configured cap is
    /// never quietly replaced by the internal number, in either direction.
    #[test]
    fn an_absent_cap_takes_the_run_ahead_bound_and_a_configured_one_is_used_as_written() {
        assert_eq!(inflight_bound(Limits::default()), RUN_AHEAD_REQUESTS);
        for configured in [1, 8, RUN_AHEAD_REQUESTS, 1024, 65_536] {
            assert_eq!(
                inflight_bound(Limits {
                    max_inflight: Some(configured),
                    ..Limits::default()
                }),
                configured,
                "a configured cap keeps exactly its value"
            );
        }
    }

    /// The default posture, which is a bound and not the absence of one: the
    /// read loop pauses with [`RUN_AHEAD_REQUESTS`] requests in flight, and one
    /// of them completing lets the next frame in.
    #[tokio::test]
    async fn an_unconfigured_connection_pauses_at_the_run_ahead_bound() {
        let permits = Arc::new(Semaphore::new(inflight_bound(Limits::default())));
        let (_stop, mut stopped) = watch::channel(false);
        let mut held = Vec::new();
        for _ in 0..RUN_AHEAD_REQUESTS {
            held.push(
                acquire(&permits, &mut stopped)
                    .await
                    .expect("the bound is open"),
            );
        }
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                acquire(&permits, &mut stopped),
            )
            .await
            .is_err(),
            "a client may not run more than {RUN_AHEAD_REQUESTS} requests ahead"
        );
        drop(held.pop());
        assert!(
            acquire(&permits, &mut stopped).await.is_some(),
            "and a request completing lets the read loop take the next frame"
        );
    }

    /// One reply of each class, as the writer would be handed them.
    fn reply(request_id: u64, bytes: usize) -> Outgoing {
        Outgoing::Frame {
            request_id: Some(request_id),
            bytes: vec![0u8; bytes],
        }
    }

    /// The id of a queued reply, for asserting the order they drain in.
    fn drained(message: Option<Outgoing>) -> u64 {
        match message {
            Some(Outgoing::Frame { request_id, .. }) => request_id.expect("an answered request"),
            other => panic!("expected a reply frame, got {other:?}"),
        }
    }

    /// The scheduler's whole promise: a small reply enqueued **after** a pile
    /// of bulk ones is written **before** them, and neither class is reordered
    /// within itself.
    #[tokio::test]
    async fn a_small_reply_queued_behind_bulk_replies_drains_first() {
        let (outbox, mut replies) = queues(64);
        for id in 1..=8 {
            outbox.send(reply(id, BULK_REPLY_BYTES)).await;
        }
        // The interactive operation arrives last and is answered first.
        outbox.send(reply(100, 128)).await;
        assert_eq!(drained(replies.next().await), 100);
        // And the bulk replies keep the order they were finished in.
        for id in 1..=8 {
            assert_eq!(drained(replies.next().await), id);
        }
    }

    /// Small replies keep their own order too, and a reply just under the
    /// threshold is small: the classifier is the encoded frame's own size.
    #[tokio::test]
    async fn each_class_is_a_fifo_and_the_threshold_is_the_frames_size() {
        let (outbox, mut replies) = queues(64);
        outbox.send(reply(1, BULK_REPLY_BYTES - 1)).await;
        outbox.send(reply(2, BULK_REPLY_BYTES)).await;
        outbox.send(reply(3, 64)).await;
        assert_eq!(drained(replies.next().await), 1, "just under is small");
        assert_eq!(drained(replies.next().await), 3, "and small stays a FIFO");
        assert_eq!(drained(replies.next().await), 2);
    }

    /// Priority is not starvation: a client that keeps small replies coming
    /// still gets its data.
    #[tokio::test]
    async fn a_stream_of_small_replies_never_starves_bulk() {
        let (outbox, mut replies) = queues(256);
        outbox.send(reply(999, BULK_REPLY_BYTES)).await;
        for id in 0..SMALL_REPLIES_BEFORE_BULK * 3 {
            outbox.send(reply(u64::from(id), 128)).await;
        }
        let mut drained_ids = Vec::new();
        for _ in 0..=SMALL_REPLIES_BEFORE_BULK {
            drained_ids.push(drained(replies.next().await));
        }
        assert_eq!(
            drained_ids.last(),
            Some(&999),
            "the bulk reply is taken after {SMALL_REPLIES_BEFORE_BULK} small ones: {drained_ids:?}"
        );
    }

    /// One class closing is not the connection ending: whatever the other still
    /// holds is written, and only when both are done does the writer stop.
    #[tokio::test]
    async fn the_writer_stops_only_when_both_classes_have_closed() {
        let (outbox, mut replies) = queues(8);
        outbox.send(reply(1, BULK_REPLY_BYTES)).await;
        outbox.send(reply(2, 128)).await;
        drop(outbox);
        assert_eq!(drained(replies.next().await), 2);
        assert_eq!(drained(replies.next().await), 1);
        assert!(replies.next().await.is_none(), "and then the writer stops");
    }

    /// A poisoning is a control signal, not data: it takes the small queue, so
    /// a connection closes on a fault instead of waiting behind bulk replies.
    #[tokio::test]
    async fn a_poisoning_is_never_queued_behind_bulk_data() {
        let (outbox, mut replies) = queues(8);
        for id in 1..=4 {
            outbox.send(reply(id, BULK_REPLY_BYTES)).await;
        }
        outbox
            .send(Outgoing::Poisoned(FramingError::LengthOverflow))
            .await;
        assert!(matches!(
            replies.next().await,
            Some(Outgoing::Poisoned(FramingError::LengthOverflow))
        ));
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
}
