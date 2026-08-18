//! The data-plane client: one mount, one connection at a time, many requests in
//! flight.
//!
//! One mount is one session. Requests are written through a **single
//! serialization point** — the connection's writer mutex — and answered out of
//! order; a reply is matched to its caller by the request id the wire contract
//! echoes. Everything that belongs to one socket lives in [`connection`]; this
//! module is the layer above it, and its whole subject is **what happens when
//! that socket dies**.
//!
//! ## What decides, and what performs
//!
//! Nothing here decides the session. The mount state machine and its one
//! monotonic deadline, the backoff schedule, the request table with its
//! request ids and its replay discipline, and the handshake's validation are
//! [`voidport_session`]'s — one authority, shared with the in-kernel client and
//! documented there. This module is the adapter: it owns the sockets, the
//! tasks, the wakeups and the clock, it supplies the core with instants and an
//! operating-system seed, and it performs the verdicts the core returns.
//!
//! The mount is Connected, Reconnecting, Degraded or Closed
//! ([`MountState`]); one reconnect task owns every transition out of
//! Connected, and death observations coalesce onto it by generation. What each
//! phase means, why the deadline wins every tie, and what the replay
//! discipline does with a request whose connection died are the core's
//! documentation, and this module holds nothing that could disagree with it.
//!
//! ## The client remembers nothing about the server's state
//!
//! No node id, handle id or lock is rebuilt across the gap: the client
//! forwards everything to the server anyway, so the server just acts
//! normally. The server's ids are generation-disjoint across
//! sessions and restarts, so an id the kernel still holds from before the gap
//! names *nothing* in the new session and is answered with a plain `ESTALE` (a
//! node) or `EBADF` (a handle). Healing is then the kernel's own machinery:
//! entries expire on their TTL, `ESTALE` makes the VFS re-walk the path from
//! the root, and a path rebuilds on first use with no application-visible
//! error. Descriptors held open across the gap fail until the application
//! reopens them — as if the tree had been replaced underneath, which it was.

mod connection;
mod ops;
mod readahead;
mod transport;
mod writestream;

pub use ops::{AttrChange, Lock, LockKind, TimeChange, XattrNames, XattrValue};
pub use readahead::{CHUNK_BYTES, DEFAULT_POOL_BYTES, ReadData, Readahead, ReadaheadStats};
pub use writestream::{
    DEFAULT_CHUNKS_PER_HANDLE, DEFAULT_CHUNKS_PER_MOUNT, WriteStream, WriteStreamStats,
};

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::Duration;

use rustix::io::Errno;
use tokio::sync::watch;
use voidport_proto::attr::Attr;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{FRAME_HEADER_LEN, Frame};
use voidport_proto::message::{
    RESPONSE_HEAD_LEN, RequestBody, RequestHead, ResponseBody, ResponseOutcome,
};
use voidport_proto::opcode::Opcode;
use voidport_session::handshake::{HandshakeError, TooLong};
use voidport_session::reconnect::{FIRST_GENERATION, Lost, Machine, Phase, Serve, Woke};
use voidport_session::replay::{Decision, OpenFlags};
use voidport_session::{Backoff, Instant};

use crate::url::Endpoint;
use connection::{Class, Connection, Established, encode, read_replies};
pub use voidport_session::handshake::{MIN_MAX_FRAME_LEN, ROOT_NODE_ID};

/// How long the mount stalls before it starts answering `EIO`.
///
/// The number the design set: if the server has not come back after 5 seconds,
/// the mount throws an I/O error.
pub const DEFAULT_RECONNECT_STALL: Duration = Duration::from_secs(5);

/// The guest identity a request is made on behalf of.
///
/// It rides on every request, not on the handshake: one mount serves
/// many guest processes, and both ownership mapping and the server's own
/// enforcement key on the identity of the process that issued the operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caller {
    /// Guest uid.
    pub uid: u32,
    /// Guest gid.
    pub gid: u32,
    /// Guest pid; informational.
    pub pid: u32,
}

/// One entry reply: the node the server resolved, and how it presents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The session-scoped node id naming the file from now on.
    pub node_id: u64,
    /// The node id's generation; the contract pins it to 0.
    pub generation: u64,
    /// The presented attributes.
    pub attr: Attr,
}

impl Entry {
    /// Copies an entry out of a wire reply.
    fn of(entry: &voidport_proto::attr::EntryOut) -> Self {
        Self {
            node_id: entry.node_id.get(),
            generation: entry.generation.get(),
            attr: entry.attr,
        }
    }
}

/// One readdirplus entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's name, as bytes.
    pub name: Vec<u8>,
    /// Its entry reply. Like any entry reply it counts a lookup, which the
    /// client must balance with a `forget`.
    pub entry: Entry,
    /// The cookie that resumes enumeration after this entry.
    pub next_cookie: u64,
    /// Its `DT_*` type.
    pub entry_type: u32,
}

/// How resilient a mount is to its server breaking away.
///
/// The design makes this configurable; these defaults are the ones it chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resilience {
    /// How long requests stall before the mount starts answering `EIO`.
    ///
    /// `Duration::ZERO` is fail-fast: the window closes the instant the server
    /// breaks away, so outstanding and subsequent operations fail immediately.
    /// The probe still runs, so a server that comes back is still picked up —
    /// what zero removes is the waiting, not the recovery.
    pub stall: Duration,
}

impl Default for Resilience {
    fn default() -> Self {
        Self {
            stall: DEFAULT_RECONNECT_STALL,
        }
    }
}

/// How many requests one mount may have outstanding at once.
///
/// The request table is fixed-capacity — it is the replay retention, and it
/// backpressures instead of growing — so its size is **derived at mount from
/// the mount's own bounded engines**, never invented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Concurrency {
    /// The write-streaming engine's per-mount chunk window.
    pub write_chunks_per_mount: usize,
    /// The readahead engine's per-mount prefetch window.
    pub readahead_per_mount: usize,
}

impl Concurrency {
    /// What the table holds for everything that is not bulk traffic.
    ///
    /// At least the server's own per-connection run-ahead bound, so a mount
    /// can have as many prompt requests in flight as the server will run
    /// ahead of — which means a prompt request never waits for the table
    /// before it waits for the server.
    pub const METADATA_ALLOWANCE: usize = 64;

    /// The capacity a mount's request table is sized to.
    ///
    /// The derivation, stated where it is computed: the write window's
    /// per-mount count, plus the readahead engine's per-mount count, plus the
    /// metadata allowance. Each bulk engine is bounded by its own window
    /// *before* it reaches the table, so bulk traffic cannot eat into the
    /// allowance; a prompt request therefore always finds a slot, and the send
    /// path's two-class rule keeps the guarantee it was built for.
    #[must_use]
    pub fn capacity(self) -> usize {
        self.write_chunks_per_mount + self.readahead_per_mount + Self::METADATA_ALLOWANCE
    }
}

impl Default for Concurrency {
    /// The engines' own defaults, for a session that does not configure them.
    fn default() -> Self {
        Self {
            write_chunks_per_mount: DEFAULT_CHUNKS_PER_MOUNT.get(),
            readahead_per_mount: readahead::MAX_INFLIGHT_PER_MOUNT,
        }
    }
}

/// What a mount is doing right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountState {
    /// A connection is installed; requests flow.
    Connected,
    /// The server broke away; requests stall until the window closes.
    Reconnecting,
    /// The window closed; requests fail `EIO` at once and the probe runs on.
    Degraded,
    /// The mount was torn down.
    Closed,
}

impl MountState {
    /// The phase the session core is in, as the mount surface names it.
    fn of(phase: Phase) -> Self {
        match phase {
            Phase::Connected => Self::Connected,
            Phase::Reconnecting => Self::Reconnecting,
            Phase::Degraded => Self::Degraded,
            Phase::Closed => Self::Closed,
        }
    }
}

/// Where a mount points, and what it asks the server for.
///
/// Kept because a reconnect is a fresh handshake: the mount re-asks for exactly
/// the namespace and subpath it was created with, and the server answers with
/// whatever its configuration says *now*.
#[derive(Clone, Debug)]
pub(crate) struct Target {
    /// The endpoint to dial.
    pub endpoint: Endpoint,
    /// The namespace to mount.
    pub namespace: String,
    /// The subpath within it.
    pub subpath: Vec<u8>,
}

/// A mount's connection to the server, across however many sockets it takes.
#[derive(Debug)]
pub struct Client {
    target: Target,
    resilience: Resilience,
    /// How many requests may be outstanding on one connection, derived at
    /// mount from this mount's own engines ([`Concurrency::capacity`]) and
    /// fixed for the mount's life.
    capacity: usize,
    /// The origin of the clock the core reasons about: every instant handed to
    /// the session core is measured from here, and every deadline it answers
    /// with is turned back into a runtime instant against it.
    base: tokio::time::Instant,
    state: Mutex<State>,
    /// Bumped under the state lock on every phase change, so a stalled caller
    /// subscribing under that same lock can never miss one.
    changes: watch::Sender<u64>,
    /// The frame bound of the connection currently installed.
    ///
    /// Held out here so the size accessors stay synchronous: the FUSE adapter
    /// asks for a read chunk on the dispatch path, where taking a lock per
    /// question would be absurd.
    max_frame_len: AtomicU32,
    /// The runtime this mount's tasks run on, captured when it was established.
    ///
    /// Named instead of taken from the ambient context, because not every
    /// caller has one: [`Self::resume_recovery`] is reached from
    /// [`Mount::unmount`](crate::mount::Mount::unmount) on the thread that
    /// asked for the unmount, which is an ordinary blocking thread, and a
    /// bare `tokio::spawn` there panics for want of a reactor. Every task this
    /// client starts — reader and probe alike — goes on the runtime the mount
    /// owns, whoever asked for it.
    runtime: tokio::runtime::Handle,
    /// A weak reference to this very client, so a reconnect task can be spawned
    /// from any `&self` method and lets go the moment the mount does.
    me: OnceLock<Weak<Client>>,
    /// Where the share subscription's notification frames go, if one is open.
    ///
    /// It lives on the mount, not on a connection, because the stream
    /// outlives its socket: a reconnect installs a fresh connection, and the
    /// subscription is re-established on it and keeps feeding the same
    /// consumer. Unset until something subscribes, which is what makes a mount
    /// that never subscribes byte-identical on the wire.
    notifications: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>,
}

/// What the adapter keeps beside the session core's state machine.
///
/// The machine owns the phase, the deadline, the generations, the probe tokens
/// and the connection itself — which it holds as opaque data and hands back to
/// be served over or buried, so "whether a connection is installed" and "which
/// one" cannot drift apart. What is left here is what a value cannot carry: the
/// handle of the task a probe token names, and the prose reason a phase
/// carries. They change under this one lock, together with the machine, so no
/// observer can see one without the other.
#[derive(Debug)]
struct State {
    machine: Machine<Arc<Connection>>,
    /// The reconnect task the machine's probe token names.
    probe: Option<tokio::task::AbortHandle>,
    /// Why the mount is not serving, in the words an operator reads.
    reason: Option<Death>,
    /// The schedule the probe waits out between attempts, seeded per mount.
    backoff: Backoff,
    /// The tick the change channel last published.
    tick: u64,
}

impl State {
    /// Cancels the reconnect task, if the machine just retired its token.
    ///
    /// Cancelling is not synchronous — an attempt already past its last
    /// suspension runs to its end — which is exactly why the machine retires
    /// the token as well: the survivor can no longer transition the mount.
    fn cancel_probe(&mut self) {
        if let Some(probe) = self.probe.take() {
            probe.abort();
        }
    }
}

/// Why a connection is no longer usable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Death {
    /// The mount unmounted it.
    Closed,
    /// The transport failed or the server went away.
    Transport(String),
    /// The server said something the protocol does not allow.
    Protocol(String),
    /// The server is reachable but refuses to serve this mount — an unknown
    /// namespace, an unresolvable subpath. The configuration may come back, so
    /// the probe keeps running; the surface stays `EIO` meanwhile.
    Refused(String),
}

impl fmt::Display for Death {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("the mount closed the connection"),
            Self::Transport(reason) | Self::Protocol(reason) | Self::Refused(reason) => {
                f.write_str(reason)
            }
        }
    }
}

/// A connection to serve one request over, and how the request reached it.
#[derive(Debug)]
struct Serving {
    /// The installed connection.
    connection: Arc<Connection>,
    /// Whether the request stalled through a reconnect to get here. Such a
    /// request was accepted under the frame bound of a connection that is now
    /// gone, which is what makes it *retained* across the gap even though it
    /// was never written.
    stalled: bool,
}

impl Client {
    /// Connects to a server and mounts `namespace` at `subpath`, with the
    /// default resilience.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError`] for a refused connection, a transport failure,
    /// a malformed reply, or the errno the server refused the mount with.
    pub async fn mount(
        endpoint: &Endpoint,
        namespace: &str,
        subpath: &[u8],
    ) -> Result<Arc<Self>, ConnectError> {
        Self::mount_with(
            endpoint,
            namespace,
            subpath,
            Resilience::default(),
            Concurrency::default(),
        )
        .await
    }

    /// The same, with the resilience and the concurrency bound the mount was
    /// configured for.
    ///
    /// The *first* handshake is not resilient: a mount that cannot be
    /// established is a mount error the operator must see, not a mount that
    /// silently starts out degraded. Only a connection that was once live is
    /// recovered.
    ///
    /// # Errors
    ///
    /// As [`Self::mount`].
    pub async fn mount_with(
        endpoint: &Endpoint,
        namespace: &str,
        subpath: &[u8],
        resilience: Resilience,
        concurrency: Concurrency,
    ) -> Result<Arc<Self>, ConnectError> {
        let target = Target {
            endpoint: endpoint.clone(),
            namespace: namespace.to_owned(),
            subpath: subpath.to_vec(),
        };
        let capacity = concurrency.capacity();
        let Established { connection, reader } =
            Connection::dial(&target, FIRST_GENERATION, capacity).await?;
        let max_frame_len = connection.max_frame_len();
        let connection = Arc::new(connection);
        let (changes, _) = watch::channel(0);
        let client = Arc::new(Self {
            target,
            resilience,
            capacity,
            base: tokio::time::Instant::now(),
            state: Mutex::new(State {
                machine: Machine::connected(Arc::clone(&connection)),
                probe: None,
                reason: None,
                backoff: Backoff::seeded(seed()),
                tick: 0,
            }),
            changes,
            max_frame_len: AtomicU32::new(max_frame_len),
            // Established from inside the mount's runtime, which is what makes
            // this the runtime the mount owns.
            runtime: tokio::runtime::Handle::current(),
            me: OnceLock::new(),
            notifications: Mutex::new(None),
        });
        let _ = client.me.set(Arc::downgrade(&client));
        client.watch(connection, reader);
        Ok(client)
    }

    /// The node id of the mount root.
    ///
    /// Always 1: every handshake refuses a server that announces anything else,
    /// and the server's allocator never hands that number to anything but a
    /// mount root — which is what makes it the one id that survives a
    /// reconnect.
    #[must_use]
    pub fn root_node_id(&self) -> u64 {
        ROOT_NODE_ID
    }

    /// The frame bound the current connection announced, in both directions.
    #[must_use]
    pub fn max_frame_len(&self) -> u32 {
        self.max_frame_len.load(Ordering::Relaxed)
    }

    /// What the mount is doing right now.
    #[must_use]
    pub fn state(&self) -> MountState {
        MountState::of(self.lock().machine.phase())
    }

    /// The generation of the connection installed right now, if one is.
    ///
    /// The phase word alone cannot tell "never left Connected" from "died and
    /// came back": phase changes are published on a watch channel, and a watch
    /// receiver coalesces, so a connection replaced inside one scheduling gap of
    /// an observer wakes it exactly once, reading `Connected` with nothing
    /// apparently changed. The generation is monotonic, so it makes that flap
    /// visible — which is what the share subscription keys its resubscribe on,
    /// not on the phase.
    pub(crate) fn connected_generation(&self) -> Option<u64> {
        self.lock().machine.connected_generation()
    }

    /// Why the mount is not serving, if it is not.
    ///
    /// `None` means a connection is installed. A reconnecting mount already has
    /// a reason — the connection that died — even though it is still stalling
    /// and not failing.
    #[must_use]
    pub fn death(&self) -> Option<Death> {
        let state = self.lock();
        match state.machine.phase() {
            Phase::Connected => None,
            Phase::Reconnecting | Phase::Degraded => state.reason.clone(),
            Phase::Closed => Some(Death::Closed),
        }
    }

    /// The largest payload a response of type `M` can carry on this session.
    #[must_use]
    pub fn payload_budget<M: ResponseBody>(&self) -> usize {
        (self.max_frame_len() as usize)
            .saturating_sub(FRAME_HEADER_LEN + RESPONSE_HEAD_LEN + size_of::<M>())
    }

    /// The largest payload a request of type `M` may carry on this session.
    #[must_use]
    pub fn request_budget<M: RequestBody>(&self) -> usize {
        (self.max_frame_len() as usize)
            .saturating_sub(FRAME_HEADER_LEN + size_of::<RequestHead>() + size_of::<M>())
    }

    /// The most data one wire read can answer with.
    #[must_use]
    pub fn read_chunk(&self) -> u32 {
        clamp(self.payload_budget::<voidport_proto::ops::file::ReadResponse>())
    }

    /// The most data one wire write can carry.
    #[must_use]
    pub fn write_chunk(&self) -> u32 {
        clamp(self.request_budget::<voidport_proto::ops::file::WriteRequest>())
    }

    /// Tears the mount down: the reconnect task is cancelled, the connection is
    /// shut down, outstanding operations fail with `EIO`, and nothing is ever
    /// written or reconnected again.
    ///
    /// This is what the unmount path calls once the kernel unmount is under
    /// way — including to release a blocking `setlk` parked on the server, and
    /// to end a stall so a teardown from Reconnecting or Degraded does not wait
    /// out the window. It returns as fast as one `shutdown(2)`: it never waits
    /// for a caller that is mid-write, which is what keeps teardown bounded
    /// when the peer has stopped reading.
    pub fn close(&self) {
        let mut state = self.lock();
        let installed = state.machine.close();
        state.cancel_probe();
        if let Some(connection) = installed {
            connection.bury(Death::Closed);
        }
        self.announce(&mut state);
    }

    /// Cancels the reconnect attempt and its backoff, and stops stalling.
    ///
    /// This is the first step of a teardown that finds the mount Reconnecting
    /// or Degraded: nothing should be dialling or sleeping while the mountpoint
    /// is being taken down, and every stalled callback is owed its `EIO` now
    /// and not at the end of a window nobody is waiting out any more. A
    /// mount that is Connected keeps its connection — it is unmounted the
    /// ordinary way, and the required teardown order closes the connection only
    /// after the kernel unmount — but recovery *ends* from here on either way,
    /// because this teardown never comes back. That is what makes this a
    /// terminal cancellation from every phase and not only from the two that
    /// have an attempt in flight: a server breaking away in the moment after
    /// this call must neither start a probe behind the teardown nor open a
    /// stall window for callbacks the teardown is about to fail anyway
    /// (the core's ended recovery, honoured wherever a death is reported).
    pub fn stop_reconnecting(&self) {
        let mut state = self.lock();
        let closed = state.machine.stop_reconnecting();
        state.cancel_probe();
        if closed {
            self.announce(&mut state);
        }
    }

    /// Cancels the reconnect attempt in flight and the backoff behind it,
    /// without ending the mount.
    ///
    /// The first step of an ordinary unmount, per the resilience contract:
    /// nothing may be dialling a server or sleeping out a backoff while the
    /// mountpoint is coming down. That bar holds until the pause is lifted, so
    /// a connection dying mid-unmount cannot start a probe either, and an
    /// attempt already past its last await cannot install itself. The phase is
    /// left exactly as it was, because the kernel may yet refuse the unmount —
    /// see [`Self::resume_recovery`], which puts back what this took away.
    ///
    /// The machine retires the cancelled task's token as it hands it back, so
    /// the attempt this abort cannot reach in time can no longer transition the
    /// mount or displace its replacement.
    pub fn pause_recovery(&self) {
        let mut state = self.lock();
        state.machine.pause_recovery();
        state.cancel_probe();
    }

    /// Starts the recovery again after a teardown the kernel refused.
    ///
    /// An `EBUSY` unmount leaves the mount live, still ours, and still
    /// disconnected if it was — so it is owed the probe that
    /// [`Self::pause_recovery`] cancelled, and the bar that pause put up is
    /// lifted. A mount that is Connected or Closed has nothing to recover, and
    /// a recovery that *ended* is never resumed: only a pause is lifted here.
    pub fn resume_recovery(&self) {
        // Taken before the core is asked for an attempt, so a client that
        // cannot spawn one never leaves the machine holding a token for a task
        // nobody started.
        let Some(me) = self.weak() else { return };
        let mut state = self.lock();
        if let Some(token) = state.machine.resume_recovery() {
            self.spawn_probe(&mut state, me, token);
        }
    }

    /// The connection to serve a request over, stalling while the mount is
    /// reconnecting.
    ///
    /// # Errors
    ///
    /// `EIO` once the mount is degraded or closed — immediately, without
    /// waiting again — and `EIO` for a stall that reached its deadline.
    async fn connected(&self) -> Result<Serving, Errno> {
        let mut stalled = false;
        loop {
            let (deadline, mut changes) = {
                let state = self.lock();
                match state.machine.serve() {
                    // The core hands out the connection it holds, so a request
                    // is served over exactly the one the phase names.
                    Serve::Now { connection } => {
                        return Ok(Serving {
                            connection: Arc::clone(connection),
                            stalled,
                        });
                    }
                    Serve::Fail => return Err(Errno::IO),
                    // Subscribing under the same lock the phase changes under
                    // is what makes this wait race-free.
                    Serve::Stall { deadline } => (deadline, self.changes.subscribe()),
                }
            };
            stalled = true;
            // Bounded by the mount's one deadline, never by a timer of this
            // request's own: a request arriving late in the window inherits
            // what is left of it and no more.
            let _ = tokio::time::timeout_at(self.wall(deadline), changes.changed()).await;
            // What the wait meant is the core's decision, taken on the instant
            // this adapter reads *after* the wait and never before: the
            // deadline wins every tie, and a caller whose window closed is owed
            // `EIO` whatever else happened in that instant.
            let mut state = self.lock();
            match state.machine.woke(deadline, self.now()) {
                Woke::Expired { degraded } => {
                    if degraded {
                        self.publish_degraded(&mut state);
                    }
                    return Err(Errno::IO);
                }
                Woke::Retry => {}
            }
        }
    }

    /// The installed connection, or `None` if there is none right now.
    ///
    /// Never stalls: it is what a request with nothing to wait for — a
    /// no-response `forget` — asks with, so a mount that is stalling out a
    /// window answers it the same way a degraded one does.
    fn current(&self) -> Option<Arc<Connection>> {
        let state = self.lock();
        match state.machine.serve() {
            Serve::Now { connection } => Some(Arc::clone(connection)),
            Serve::Stall { .. } | Serve::Fail => None,
        }
    }

    /// Sends one request and returns its reply, replaying per the discipline.
    ///
    /// `Ok(None)` is the moot answer, which only an operation the core
    /// classifies as moot can produce.
    ///
    /// `open` is the open flags of the one operation whose replay class depends
    /// on its arguments, and nothing else reads it. `class` says how the frame
    /// queues for the connection's serialization point, and nothing else: it
    /// survives a replay unchanged, because a re-sent chunk is still a chunk.
    #[allow(
        clippy::too_many_arguments,
        reason = "one wire request, described by the fields the frame carries"
    )]
    async fn exchange<Q: RequestBody>(
        &self,
        caller: Caller,
        node_id: u64,
        body: &Q,
        payload: &[u8],
        opcode: Opcode,
        open: OpenFlags,
        class: Class,
    ) -> Result<Option<(Arc<Connection>, Vec<u8>)>, Errno> {
        // A request is *retained* across the gap once it has waited on one: it
        // was accepted under the frame bound of a connection that no longer
        // exists, whether it stalled before its first encode or was re-sent
        // after a lost attempt. Both make the same edge, and the contract gives
        // that edge the same answer.
        let mut retained = false;
        loop {
            let Serving {
                connection,
                stalled,
            } = self.connected().await?;
            retained |= stalled;
            // The table is the mount's concurrency bound, and a full one is a
            // wait: this is where a caller parks if every slot is taken.
            let ticket = connection.claim(opcode, open).await;
            let frame = match encode(
                ticket.request_id(),
                caller,
                node_id,
                body,
                payload,
                connection.max_frame_len(),
            ) {
                Ok(frame) => frame,
                // A retained request that no longer fits the newly negotiated
                // bound is the contract's noted edge: it fails, and it fails as
                // the gap it could not be carried across.
                Err(error) => {
                    connection.release(ticket);
                    return Err(unencodable(error, retained));
                }
            };
            match connection.call(ticket, &frame, class).await {
                Ok(bytes) => return Ok(Some((connection, bytes))),
                Err(decision) => {
                    self.lost(&connection);
                    match decision {
                        Decision::Resend => retained = true,
                        Decision::Fail => return Err(Errno::IO),
                        Decision::Moot => return Ok(None),
                    }
                }
            }
        }
    }

    /// Sends one request and waits for its reply.
    ///
    /// Every request that reaches here is of the send path's prompt class. Only
    /// a streamed write's chunks are bulk, and they take
    /// [`Self::call_on`](Self::call_on) with the class themselves.
    ///
    /// # Errors
    ///
    /// Returns the errno the server answered with, `EIO` for a mount that is
    /// degraded or whose non-idempotent request was lost in flight, and
    /// `EOVERFLOW` for a request that does not fit the negotiated frame length.
    async fn call<Q, R, T>(
        &self,
        caller: Caller,
        node_id: u64,
        body: &Q,
        payload: &[u8],
        extract: impl FnOnce(&R, &[u8]) -> Result<T, FramingError>,
    ) -> Result<T, Errno>
    where
        Q: RequestBody,
        R: ResponseBody,
    {
        self.call_on::<Q, R, T>(
            caller,
            node_id,
            body,
            payload,
            OpenFlags::NONE,
            Class::Prompt,
            extract,
        )
        .await
        .map(|(value, _)| value)
    }

    /// The same, reporting which connection answered.
    ///
    /// The generation matters to a request that *establishes* something on the
    /// session behind the connection — the share subscription is the one such
    /// request. A retained or replayed request is answered by the connection it
    /// finally landed on, never necessarily the one it was first written to, and
    /// only that session holds what it established. Reading the mount's
    /// generation around the call cannot say which: before the call it may name
    /// a connection that died mid-flight, after it one that replaced the
    /// answering one. The answering connection is the only truthful source, and
    /// it is what stops the subscription's own reconnect bracket from
    /// re-subscribing on top of a replay that already did.
    ///
    /// # Errors
    ///
    /// As [`Self::call`].
    #[allow(
        clippy::too_many_arguments,
        reason = "one wire request, described by the fields the frame carries"
    )]
    async fn call_on<Q, R, T>(
        &self,
        caller: Caller,
        node_id: u64,
        body: &Q,
        payload: &[u8],
        open: OpenFlags,
        class: Class,
        extract: impl FnOnce(&R, &[u8]) -> Result<T, FramingError>,
    ) -> Result<(T, u64), Errno>
    where
        Q: RequestBody,
        R: ResponseBody,
    {
        let answered = self
            .exchange(caller, node_id, body, payload, R::OPCODE, open, class)
            .await?;
        // Only a moot operation answers without a reply, and those take
        // `call_moot`; a caller here that somehow reaches this arm has lost its
        // connection and gets what every lost request gets.
        let (connection, bytes) = answered.ok_or(Errno::IO)?;
        let value = interpret::<R, T>(&connection, &bytes, extract)?;
        Ok((value, connection.generation()))
    }

    /// Sends one request whose referent dies with the session.
    ///
    /// A lost attempt is not an error: the handle it names is gone either way,
    /// so the guest is told the close succeeded, not handed an `EIO` for
    /// a resource that no longer exists.
    ///
    /// It never stalls, either. Every handle a guest can name was opened on the
    /// installed connection, so a mount with none installed holds only
    /// dead-generation handles: the request is already moot when it arrives,
    /// and waiting out a reconnect — or failing `EIO` once the window has
    /// closed — would only delay an answer the contract has already fixed as
    /// success.
    ///
    /// # Errors
    ///
    /// The server's errno, when the server answered at all.
    async fn call_moot<Q, R>(
        &self,
        caller: Caller,
        node_id: u64,
        body: &Q,
        payload: &[u8],
    ) -> Result<(), Errno>
    where
        Q: RequestBody,
        R: ResponseBody,
    {
        if self.current().is_none() {
            return Ok(());
        }
        match self
            .exchange(
                caller,
                node_id,
                body,
                payload,
                R::OPCODE,
                OpenFlags::NONE,
                Class::Prompt,
            )
            .await?
        {
            Some((connection, bytes)) => interpret::<R, ()>(&connection, &bytes, |_, _| Ok(())),
            None => Ok(()),
        }
    }

    /// Sends one request that has no reply.
    ///
    /// Its id retires the moment the frame reaches the transport, so it is
    /// never registered as outstanding. It never stalls and is never replayed:
    /// a `forget` whose connection is gone names a node that died with the
    /// session.
    async fn send<Q: RequestBody>(&self, caller: Caller, node_id: u64, body: &Q) {
        let Some(connection) = self.current() else {
            return;
        };
        let request_id = connection.take_request_id();
        let Ok(frame) = encode(
            request_id,
            caller,
            node_id,
            body,
            &[],
            connection.max_frame_len(),
        ) else {
            tracing::error!(opcode = %Q::OPCODE, "a request could not be encoded");
            return;
        };
        let _ = connection.send(&frame).await;
    }

    /// Records that `connection` is dead and starts the recovery, unless the
    /// mount has already moved on from that generation.
    ///
    /// This is where death observations coalesce: the reader task, a failed
    /// write and a caller that found a protocol fault all arrive here, and the
    /// core discards every one that names a generation the mount has already
    /// replaced.
    fn lost(&self, connection: &Arc<Connection>) {
        let reason = connection
            .death()
            .unwrap_or_else(|| Death::Transport("the connection ended".to_owned()));
        let mut state = self.lock();
        let lost = state
            .machine
            .lost(connection.generation(), self.now(), self.resilience.stall);
        if lost == Lost::Ignored {
            return;
        }
        // The mount let this connection go with the phase change, and whoever
        // reports a death is holding the connection it reports: burying it is
        // this caller's own step.
        connection.bury(reason.clone());
        state.reason = Some(reason);
        self.announce(&mut state);
        if lost.wants_probe() {
            self.start_probe(&mut state);
        }
    }

    /// Ends the stall if its deadline has passed.
    ///
    /// Called by the probe between attempts; a stalled caller reaches the same
    /// decision through its own wait ([`Self::connected`]).
    fn expire(&self) {
        let mut state = self.lock();
        if state.machine.expire(self.now()) {
            self.publish_degraded(&mut state);
        }
    }

    /// Reports a window that has just closed, and publishes the phase change.
    fn publish_degraded(&self, state: &mut MutexGuard<'_, State>) {
        if let Some(reason) = state.reason.clone() {
            tracing::warn!(%reason, "the server did not come back within the stall window");
        }
        self.announce(state);
    }

    /// Ends the stall now, whatever the deadline says.
    ///
    /// A server that answers the handshake with a refusal is reachable and
    /// says no: waiting out the window would only delay the `EIO` the guest is
    /// owed. The probe keeps running, because the configuration may return, and
    /// the core admits only the attempt the mount currently owns.
    fn degrade(&self, reason: Death, probe: u64) {
        let mut state = self.lock();
        if state.machine.degrade(probe) {
            tracing::warn!(%reason, "the server refuses to serve this mount");
            state.reason = Some(reason);
            self.announce(&mut state);
        }
    }

    /// Installs a freshly handshaken connection and returns the mount to
    /// Connected, atomically.
    ///
    /// The core says whether this attempt may install at all — a torn-down
    /// mount, a paused recovery and a superseded attempt each answer no — and it
    /// hands a connection it will not take straight back to be buried, which is
    /// what keeps a mount from ever holding two live sessions and splitting its
    /// callbacks across them.
    fn install(&self, established: Established, probe: u64) {
        let Established { connection, reader } = established;
        let connection = Arc::new(connection);
        {
            let mut state = self.lock();
            if let Err(refused) =
                state
                    .machine
                    .install(probe, connection.generation(), Arc::clone(&connection))
            {
                refused.bury(Death::Closed);
                return;
            }
            self.max_frame_len
                .store(connection.max_frame_len(), Ordering::Relaxed);
            state.reason = None;
            // The task that installed a connection is done, so its handle is
            // let go with the token the core just retired.
            state.probe = None;
            self.announce(&mut state);
        }
        self.watch(connection, reader);
    }

    /// Spawns the task that reads this connection's replies and reports its
    /// death back to the mount.
    ///
    /// It holds only a weak reference to the mount, so a client nobody holds
    /// any more cannot be kept alive by its own reader.
    fn watch(&self, connection: Arc<Connection>, reader: connection::Replies) {
        // Installed before the reader starts, so a notification arriving on the
        // very first frame of a replacement connection is not lost between the
        // handshake and the subscription being re-established.
        if let Some(sink) = self
            .notifications
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
        {
            connection.route_notifications(sink);
        }
        let Some(me) = self.weak() else { return };
        self.runtime.spawn(async move {
            read_replies(Arc::clone(&connection), reader).await;
            if let Some(client) = me.upgrade() {
                client.lost(&connection);
            }
        });
    }

    /// The generation the next connection carries.
    fn take_generation(&self) -> u64 {
        self.lock().machine.take_generation()
    }

    /// How long `probe`'s next attempt may take, or `None` when there is
    /// nothing left for it to do: the mount is serving again, it has ended, a
    /// teardown took the recovery away, or this attempt has been superseded.
    fn attempt_bound(&self, probe: u64) -> Option<Duration> {
        self.lock().machine.attempt_bound(probe, self.now())
    }

    /// The next delay between reconnect attempts, off the mount's own seeded
    /// schedule and the schedule the phase calls for.
    fn backoff(&self) -> Duration {
        let mut state = self.lock();
        let schedule = state.machine.schedule();
        state.backoff.next(schedule)
    }

    /// Starts the schedule over, which the probe does when it crosses out of
    /// the stall window: the delay reached inside it says nothing about the one
    /// a degraded mount waits.
    fn restart_backoff(&self) {
        self.lock().backoff.restart();
    }

    /// Starts the single reconnect task, if the core says the mount wants one.
    ///
    /// A teardown holds the bar and an ended mount is past recovering, so
    /// neither gets a task here — which is what stops a connection dying
    /// mid-unmount from putting a dialler behind the teardown.
    fn start_probe(&self, state: &mut MutexGuard<'_, State>) {
        // Taken before the core is asked for an attempt: a client that cannot
        // spawn a task that outlives this call must not leave the machine
        // holding a token for one nobody started. The reference is set the
        // moment the client is built, before anything can lose a connection.
        let Some(me) = self.weak() else { return };
        if let Some(token) = state.machine.start_probe() {
            self.spawn_probe(state, me, token);
        }
    }

    /// Spawns the attempt the core has just handed out a token for.
    fn spawn_probe(&self, state: &mut MutexGuard<'_, State>, me: Weak<Client>, token: u64) {
        // A fresh attempt is a fresh outage as far as the schedule is
        // concerned; the jitter source keeps advancing across all of them.
        state.backoff.restart();
        state.probe = Some(self.runtime.spawn(reconnect(me, token)).abort_handle());
    }

    /// Publishes a phase change to everyone stalled on one.
    ///
    /// Done under the state lock, which is what lets a caller subscribe under
    /// that same lock and be sure it cannot miss the next one.
    fn announce(&self, state: &mut MutexGuard<'_, State>) {
        state.tick += 1;
        let _ = self.changes.send(state.tick);
    }

    /// The instant the session core reasons about, from this mount's clock.
    fn now(&self) -> Instant {
        Instant::from_nanos(u64::try_from(self.base.elapsed().as_nanos()).unwrap_or(u64::MAX))
    }

    /// The runtime instant a core deadline names, so a wait can be bounded by
    /// it.
    fn wall(&self, instant: Instant) -> tokio::time::Instant {
        self.base + Duration::from_nanos(instant.as_nanos())
    }

    /// A weak reference to this client, for a task that outlives the call that
    /// spawned it.
    fn weak(&self) -> Option<Weak<Client>> {
        self.me.get().cloned()
    }

    /// Subscribes to the mount's phase changes.
    ///
    /// Every transition bumps the tick under the state lock, so a consumer that
    /// subscribes and then reads [`Self::state`] cannot miss one. The share
    /// subscription brackets an outage with this: a mount that leaves
    /// `Connected` is a `disconnected`, and one that returns to it is a
    /// `resumed` plus a fresh `Subscribe`.
    #[must_use]
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Routes this mount's server-initiated notifications to `sink`, on this
    /// connection and every connection that replaces it.
    ///
    /// **One subscription per mount**, and this is where that is enforced:
    /// `false` means one is already routed and the caller may not open a
    /// second. There is exactly one notification stream on a connection —
    /// `Subscribe` enables the session's, and the server has no way to say
    /// which of two consumers a frame is for — so a second sink could only
    /// replace the first, silently starving a consumer that believes it is
    /// listening. A sink whose consumer has dropped its receiver is not a
    /// subscription and does not stand in the way of one.
    pub(crate) fn route_notifications(
        &self,
        sink: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) -> bool {
        {
            let mut routed = self
                .notifications
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if routed.as_ref().is_some_and(|held| !held.is_closed()) {
                return false;
            }
            *routed = Some(sink.clone());
        }
        if let Some(connection) = self.current() {
            connection.route_notifications(sink);
        }
        true
    }

    /// Gives up this mount's notification routing, so another subscription may
    /// take it.
    ///
    /// The connection's own sink is left as it is: frames sent into a channel
    /// nobody holds are dropped, and the next subscription installs its own on
    /// whatever connection is current, exactly as the first one did.
    pub(crate) fn release_notifications(&self) {
        *self
            .notifications
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = None;
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

impl Drop for Client {
    /// A mount nobody holds any more has no business keeping a socket open or
    /// a probe running. Closing here is a safety net under the unmount path,
    /// which closes explicitly and in order.
    fn drop(&mut self) {
        self.close();
    }
}

/// The single reconnect task.
///
/// One per mount at a time, owned by the state machine and cancelled by
/// teardown, so a dial or a backoff in flight never delays an unmount. It runs
/// until it installs a connection, until the mount is closed, until the mount
/// replaces it, or until the mount itself is dropped.
///
/// `token` is what the mount knows this task by. Every transition the task
/// makes is gated on it still being the current one, because an abort only
/// takes effect at the next await and this task may already be past its last.
async fn reconnect(client: Weak<Client>, token: u64) {
    loop {
        let Some(client) = client.upgrade() else {
            return;
        };
        // Somebody else installed a connection, the mount is gone, or this
        // attempt has been superseded.
        let Some(bound) = client.attempt_bound(token) else {
            return;
        };
        if bound.is_zero() {
            // The window has closed; the next pass runs under the degraded
            // schedule instead of dialling with no time at all.
            client.expire();
            client.restart_backoff();
            continue;
        }

        let generation = client.take_generation();
        let dial = Connection::dial(&client.target, generation, client.capacity);
        match tokio::time::timeout(bound, dial).await {
            Ok(Ok(established)) => {
                // The deadline is the authority even when the handshake and the
                // timer come ready in the same instant: `timeout` polls the dial
                // before its own timer, so record the crossing first and let a
                // window that closed stay closed. Installing from Degraded is
                // the ordinary return to Connected.
                client.expire();
                tracing::info!(generation, "the data connection is back");
                client.install(established, token);
                return;
            }
            Ok(Err(error)) => {
                if let Some(reason) = refusal(&error) {
                    // Reachable and refusing: degrade now and keep probing.
                    client.degrade(reason, token);
                } else {
                    tracing::debug!(%error, "a reconnect attempt failed");
                }
            }
            Err(_elapsed) => {
                tracing::debug!("a reconnect attempt ran out of its window");
            }
        }
        client.expire();

        let wait = client.backoff();
        // Let go of the mount while sleeping, so a client nobody else holds is
        // dropped at once, not at the end of a five-second backoff.
        drop(client);
        tokio::time::sleep(wait).await;
    }
}

/// The seed the mount's backoff jitter is expanded from.
///
/// Taken from the operating system once per mount, as the extraction contract
/// requires, and threaded into the core as data. Nothing about it needs to be
/// unpredictable — only uncorrelated between two mounts that lost the same
/// server, so they do not retry in lockstep — and the hash builder the standard
/// library seeds from the system is exactly that much randomness with no
/// dependency behind it.
fn seed() -> u64 {
    use std::hash::{BuildHasher as _, Hasher as _, RandomState};

    RandomState::new().build_hasher().finish()
}

/// Whether a failed handshake is the server refusing this mount *for
/// configuration reasons*, not the server being unable to serve it yet.
///
/// The contract's early degradation is for the refusals nothing but a
/// configuration change can lift: an unknown namespace, a subpath that no
/// longer resolves, or an announcement no session can be served under. The
/// mount degrades at once instead of stalling out a window that cannot help
/// it — and the probe runs on, because the configuration may come back.
///
/// A *transient* refusal is a different answer wearing the same shape. The
/// server's session cap answers `EMFILE` on a handshake, and the session
/// holding the last slot may release it inside the stall window that is still
/// open — so those keep the mount on the in-window retry path, exactly as an
/// unreachable server does, instead of surfacing `EIO` for a condition that
/// clears itself.
fn refusal(error: &ConnectError) -> Option<Death> {
    match error {
        ConnectError::Refused { status } if transient(errno_of(*status)) => None,
        ConnectError::Refused { .. }
        | ConnectError::FrameBound { .. }
        | ConnectError::RootNodeId { .. } => Some(Death::Refused(error.to_string())),
        ConnectError::Protocol { .. } => Some(Death::Protocol(error.to_string())),
        ConnectError::Connect { .. }
        | ConnectError::Transport { .. }
        | ConnectError::TooLong { .. } => None,
    }
}

/// Whether an errno a handshake was refused with can clear on its own.
///
/// Resource and admission failures only: everything else a server answers a
/// `Hello` with is a statement about the configuration, which no amount of
/// retrying inside one stall window changes.
fn transient(errno: Errno) -> bool {
    matches!(
        errno,
        Errno::MFILE | Errno::NFILE | Errno::NOMEM | Errno::AGAIN | Errno::BUSY | Errno::INTR
    )
}

/// Reads one reply into the value its caller asked for.
///
/// Every failure here is a *framing* failure, so it poisons the connection
/// exactly as a bad frame read off the socket would: the server sent bytes the
/// protocol does not allow.
fn interpret<R: ResponseBody, T>(
    connection: &Connection,
    bytes: &[u8],
    extract: impl FnOnce(&R, &[u8]) -> Result<T, FramingError>,
) -> Result<T, Errno> {
    let frame = match Frame::parse(bytes, connection.max_frame_len()) {
        Ok(frame) => frame,
        Err(fault) => return Err(poison(connection, fault)),
    };
    match frame.response::<R>() {
        Ok(ResponseOutcome::Success(response)) => {
            match extract(response.body(), response.payload()) {
                Ok(value) => Ok(value),
                Err(fault) => Err(poison(connection, fault)),
            }
        }
        Ok(ResponseOutcome::Error(status)) => Err(errno_of(status)),
        Err(fault) => Err(poison(connection, fault)),
    }
}

/// Ends a connection over a protocol fault its caller found, and reports the
/// errno that caller must answer with.
///
/// The mount notices through the reader task, which is watching the same
/// connection and wakes as soon as its socket is shut down.
fn poison(connection: &Connection, fault: FramingError) -> Errno {
    connection.poison(fault);
    Errno::IO
}

/// The errno for a request this client cannot put on the wire.
///
/// On a request the mount never had to carry across a gap, nothing was sent and
/// the stream is intact, so the caller gets an errno that says the request was
/// too big to express. On a *retained* one — re-sent after a lost attempt, or
/// stalled through a reconnect before its first encode — it means the
/// replacement session negotiated a smaller frame bound than the one the request
/// was accepted under, which the contract makes an `EIO`: the request did not
/// survive the gap.
fn unencodable(error: FramingError, retained: bool) -> Errno {
    tracing::error!(%error, retained, "a request could not be encoded");
    if retained { Errno::IO } else { Errno::OVERFLOW }
}

/// A byte budget as a wire length.
fn clamp(budget: usize) -> u32 {
    u32::try_from(budget).unwrap_or(u32::MAX)
}

/// The errno a wire status carries.
fn errno_of(status: i32) -> Errno {
    Errno::from_raw_os_error(-status)
}

/// Why a mount's connection could not be established.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectError {
    /// The endpoint could not be dialled.
    #[error("cannot connect to {endpoint}")]
    Connect {
        /// The endpoint dialled.
        endpoint: String,
        /// Why not.
        #[source]
        source: io::Error,
    },
    /// The connection failed during the handshake.
    #[error("the handshake with {endpoint} failed")]
    Transport {
        /// The endpoint dialled.
        endpoint: String,
        /// Why it failed.
        #[source]
        source: io::Error,
    },
    /// The server refused the mount, with a reason.
    #[error("the server refused the mount: {}", io::Error::from_raw_os_error(-status))]
    Refused {
        /// The negated errno the server answered with.
        status: i32,
    },
    /// The server's reply was not a legal handshake response.
    #[error("the server's handshake reply is malformed: {reason}")]
    Protocol {
        /// What was wrong with it.
        reason: String,
    },
    /// The server announced a frame bound too small to serve a session with.
    #[error(
        "the server announced a maximum frame length of {announced} bytes, \
         below the {minimum} a session needs"
    )]
    FrameBound {
        /// The bound the server announced.
        announced: u32,
        /// The smallest one this client can serve a mount under.
        minimum: u32,
    },
    /// The server announced a root node id the kernel cannot name.
    #[error("the server announced root node id {announced}, and a FUSE mount root is {expected}")]
    RootNodeId {
        /// The node id the server announced.
        announced: u64,
        /// The only one a FUSE mount root can have.
        expected: u64,
    },
    /// The handshake itself would not fit the pre-handshake bound.
    #[error("the namespace and subpath do not fit a {max}-byte handshake")]
    TooLong {
        /// The pre-handshake frame bound.
        max: u32,
    },
}

impl From<HandshakeError> for ConnectError {
    /// The mount error each of the core's handshake classes surfaces as.
    ///
    /// Three classes have a mount error of their own, because an operator
    /// acting on them acts differently: a refusal names the server's own
    /// answer, and the two announcements name what was announced. The rest —
    /// a version this client does not speak, reserved bits set, a reply to
    /// another request, a frame that is not a handshake at all — are one thing
    /// to an operator: the peer is not speaking this protocol.
    fn from(error: HandshakeError) -> Self {
        match error {
            HandshakeError::Refused { status } => Self::Refused { status },
            HandshakeError::FrameBound { announced, minimum } => {
                Self::FrameBound { announced, minimum }
            }
            HandshakeError::RootNodeId {
                announced,
                expected,
            } => Self::RootNodeId {
                announced,
                expected,
            },
            other => Self::Protocol {
                reason: other.to_string(),
            },
        }
    }
}

impl From<TooLong> for ConnectError {
    fn from(error: TooLong) -> Self {
        Self::TooLong { max: error.max }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mount's table is sized by its own engines and nothing else, and
    /// every prompt request has room the bulk windows cannot take.
    #[test]
    fn the_table_capacity_is_the_engines_plus_the_prompt_allowance() {
        let engines = Concurrency::default();
        assert_eq!(
            engines.capacity(),
            DEFAULT_CHUNKS_PER_MOUNT.get()
                + readahead::MAX_INFLIGHT_PER_MOUNT
                + Concurrency::METADATA_ALLOWANCE
        );
        assert!(
            engines.capacity() - engines.write_chunks_per_mount - engines.readahead_per_mount
                >= Concurrency::METADATA_ALLOWANCE,
            "bulk traffic cannot reach the prompt allowance"
        );
        // A mount that widens its write window widens the table with it.
        let wide = Concurrency {
            write_chunks_per_mount: 512,
            ..engines
        };
        assert_eq!(
            wide.capacity(),
            engines.capacity() + 512 - engines.write_chunks_per_mount
        );
    }

    #[test]
    fn a_reachable_server_that_says_no_degrades_and_an_unreachable_one_does_not() {
        assert!(matches!(
            refusal(&ConnectError::Refused { status: -2 }),
            Some(Death::Refused(_))
        ));
        assert!(matches!(
            refusal(&ConnectError::RootNodeId {
                announced: 7,
                expected: 1
            }),
            Some(Death::Refused(_))
        ));
        assert!(matches!(
            refusal(&ConnectError::Protocol {
                reason: "nonsense".to_owned()
            }),
            Some(Death::Protocol(_))
        ));
        assert!(
            refusal(&ConnectError::Connect {
                endpoint: "127.0.0.1:1".to_owned(),
                source: io::Error::from(io::ErrorKind::ConnectionRefused),
            })
            .is_none(),
            "a server that is not there yet is exactly what the probe waits for"
        );
    }

    #[test]
    fn a_transient_refusal_keeps_the_mount_on_the_in_window_retry_path() {
        // The server's session cap answers a handshake `EMFILE`; the slot may
        // free itself while the stall window is still open, so this is not the
        // configuration refusal that degrades a mount at once.
        assert!(
            refusal(&ConnectError::Refused {
                status: -Errno::MFILE.raw_os_error(),
            })
            .is_none(),
            "a session cap is a resource, not a configuration"
        );
        assert!(
            matches!(
                refusal(&ConnectError::Refused {
                    status: -Errno::NOENT.raw_os_error(),
                }),
                Some(Death::Refused(_))
            ),
            "an unknown namespace only comes back through the configuration"
        );
    }

    #[test]
    fn a_request_that_outgrew_the_new_frame_bound_fails_as_the_gap_it_crossed() {
        assert_eq!(
            unencodable(FramingError::LengthOverflow, false),
            Errno::OVERFLOW
        );
        assert_eq!(unencodable(FramingError::LengthOverflow, true), Errno::IO);
    }
}
