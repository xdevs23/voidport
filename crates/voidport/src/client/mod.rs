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
//! ## The mount is a state machine
//!
//! * **Connected** — a connection is installed and requests flow.
//! * **Reconnecting** — the server broke away. Newly arriving callbacks *stall*
//!   here, bounded by **one monotonic deadline** (`--reconnect-stall`, 5 s by
//!   default) shared by every stalled request — not by a per-request timer, so
//!   a request that arrives late in the window is not given a fresh window of
//!   its own. That deadline wins every tie: a stall that reaches it fails
//!   `EIO`, and a handshake that completes in the same instant finds the window
//!   already closed, so no amount of scheduler delay can serve a request past
//!   its window.
//! * **Degraded** — the deadline passed. Stalled and subsequent requests fail
//!   `EIO` **immediately**, and the probe keeps running on a slower backoff.
//!   The rule: once the window has passed, further errored requests are
//!   returned with errors immediately instead of waiting again.
//! * **Closed** — the mount was torn down. Nothing reconnects.
//!
//! **One reconnect task owns every transition out of Connected.** Death
//! observations coalesce onto it: whoever notices first — the reader task, a
//! failing write, a caller finding a protocol fault — reports the *generation*
//! it observed, and a report naming a generation the mount has already replaced
//! is discarded. That is what stops a dying connection from poisoning its own
//! replacement. A completed handshake **is** the probe, and installing it
//! atomically returns the mount to Connected: once the server comes back,
//! errors stop and everything resumes as usual. The probe carries a token for
//! the same reason the connection carries a generation: cancelling a task is
//! not synchronous, so a superseded attempt is identified and discarded, not
//! allowed to transition the mount that replaced it.
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
//!
//! ## Replay discipline
//!
//! A request is *queued* (never fully written), *written*, or *answered*. The
//! linearization point is the write itself, recorded in
//! [`Connection::transmit`](connection::Connection). After a re-handshake a
//! queued request is simply sent — it provably never reached the server, whose
//! socket is shut down before anything is retried. A written-but-unanswered
//! request is re-sent only if it is idempotent; a written-but-unanswered
//! non-idempotent mutation fails `EIO` instead of risking double application.
//! No-response requests and releases addressing a dead generation are dropped
//! as moot: their referents died with the session.

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
use tokio::time::Instant;
use voidport_proto::attr::Attr;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{FRAME_HEADER_LEN, Frame};
use voidport_proto::message::{
    RESPONSE_HEAD_LEN, RequestBody, RequestHead, ResponseBody, ResponseOutcome,
};
use voidport_proto::opcode::Opcode;

use crate::url::Endpoint;
use connection::{Class, Connection, Established, Sent, encode, read_replies};
pub use connection::{MIN_MAX_FRAME_LEN, ROOT_NODE_ID};

/// How long the mount stalls before it starts answering `EIO`.
///
/// The number the design set: if the server has not come back after 5 seconds,
/// the mount throws an I/O error.
pub const DEFAULT_RECONNECT_STALL: Duration = Duration::from_secs(5);

/// The first delay between reconnect attempts inside the stall window.
const STALL_INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// The ceiling that delay doubles up to inside the stall window.
const STALL_MAX_BACKOFF: Duration = Duration::from_secs(1);

/// The first delay between reconnect attempts once the mount is degraded.
///
/// Slower than inside the window, because nothing is waiting on it any more:
/// the operator TUI worker's schedule, reused here.
const DEGRADED_INITIAL_BACKOFF: Duration = Duration::from_millis(500);

/// The ceiling that delay doubles up to once the mount is degraded.
const DEGRADED_MAX_BACKOFF: Duration = Duration::from_secs(5);

/// How long one degraded reconnect attempt may take before it is abandoned.
///
/// A peer that accepts the socket and never completes the handshake must not
/// hold the probe forever; inside the stall window the window's remainder is
/// the bound, and afterwards this is.
const DEGRADED_ATTEMPT_BOUND: Duration = Duration::from_secs(5);

/// How much of a backoff delay is jitter, as a divisor.
///
/// Two mounts that lost the same server must not retry in lockstep for ever;
/// the delay is shortened by up to a quarter, never lengthened, so the schedule
/// stays an upper bound.
const JITTER_DIVISOR: u32 = 4;

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
    state: Mutex<Machine>,
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

/// The mount's phase, and the bookkeeping around it.
#[derive(Debug)]
struct Machine {
    phase: Phase,
    /// The generation the next connection will carry. Monotonic.
    next_generation: u64,
    /// The single reconnect task, if one is running.
    probe: Option<Probe>,
    /// The token the next reconnect task will carry. Monotonic.
    next_probe: u64,
    /// Whether recovery may run at all.
    recovery: Recovery,
    /// The tick the change channel last published.
    tick: u64,
}

/// Whether a mount is allowed to recover, and for how long it is not.
///
/// The barrier the teardown paths need, and the reason cancelling the probe is
/// not enough on its own: aborting a task is not synchronous, and a connection
/// dying *during* a teardown would otherwise start a fresh one behind it.
/// Anything but [`Recovery::Running`] means nothing dials and nothing is
/// installed, whatever the phase says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recovery {
    /// The ordinary state: a death opens the stall window and starts a probe.
    Running,
    /// An unmount is under way and the kernel may yet refuse it. Nothing dials,
    /// but a death still opens the window an `EBUSY` mount is owed when
    /// [`Client::resume_recovery`] hands the probe back.
    Paused,
    /// A teardown that never comes back. Nothing dials, and a death arriving
    /// now ends the mount instead of opening a window nobody will wait out.
    Ended,
}

/// The single reconnect task, and the token that says which one it is.
#[derive(Debug)]
struct Probe {
    /// Identifies this task among every one the mount has ever spawned.
    token: u64,
    /// Cancels it.
    handle: tokio::task::AbortHandle,
}

impl Machine {
    /// Whether `probe` is the reconnect task the mount owns right now.
    ///
    /// Cancelling a task is not cancelling it *now*: an abort takes effect at
    /// the next await, so a task already past its last one runs to its end
    /// regardless. An `EBUSY` unmount leaves exactly such a task behind —
    /// [`Client::pause_recovery`] aborts it and [`Client::resume_recovery`]
    /// starts its replacement — and the survivor must not install a connection,
    /// end a window, or clear the handle belonging to the task that replaced
    /// it. Every transition a probe makes is therefore gated on this.
    fn owns(&self, probe: u64) -> bool {
        self.probe
            .as_ref()
            .is_some_and(|current| current.token == probe)
    }
}

/// Where a mount is in its life.
#[derive(Debug)]
enum Phase {
    /// Serving over this connection.
    Connected(Arc<Connection>),
    /// Stalling until `deadline`, because `reason` ended the last connection.
    Reconnecting {
        /// The one deadline every stalled request shares.
        deadline: Instant,
        /// What ended the connection.
        reason: Death,
    },
    /// Answering `EIO` at once, with the probe still running.
    Degraded {
        /// What ended the connection, or why the probe cannot re-establish it.
        reason: Death,
    },
    /// Torn down.
    Closed,
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

/// What the replay discipline does with a request whose connection died.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Replay {
    /// Idempotent: applying it twice is applying it once, so it is re-sent
    /// whether or not it reached the server.
    Idempotent,
    /// A mutation that must not be applied twice. A *written* attempt may
    /// already have taken effect, so it fails `EIO`; a *queued* one provably
    /// did not, so it is re-sent.
    Once,
    /// Its referent — a handle, a node — died with the session, so a lost
    /// attempt is moot and answers as though it had succeeded.
    Moot,
}

impl Replay {
    /// What to do with an attempt that got as far as `sent`.
    fn decide(self, sent: Sent) -> Decision {
        match (self, sent) {
            (Self::Moot, _) => Decision::Moot,
            (_, Sent::Queued) | (Self::Idempotent, Sent::Written) => Decision::Resend,
            (Self::Once, Sent::Written) => Decision::Fail,
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

/// What becomes of one lost attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    /// Send it again on the replacement connection.
    Resend,
    /// Answer `EIO`: it may already have been applied.
    Fail,
    /// Answer as though it had succeeded.
    Moot,
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
        Self::mount_with(endpoint, namespace, subpath, Resilience::default()).await
    }

    /// The same, with the resilience the mount was configured for.
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
    ) -> Result<Arc<Self>, ConnectError> {
        let target = Target {
            endpoint: endpoint.clone(),
            namespace: namespace.to_owned(),
            subpath: subpath.to_vec(),
        };
        let Established { connection, reader } = Connection::dial(&target, 1).await?;
        let max_frame_len = connection.max_frame_len();
        let connection = Arc::new(connection);
        let (changes, _) = watch::channel(0);
        let client = Arc::new(Self {
            target,
            resilience,
            state: Mutex::new(Machine {
                phase: Phase::Connected(Arc::clone(&connection)),
                next_generation: 2,
                probe: None,
                next_probe: 1,
                recovery: Recovery::Running,
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
        match &self.lock().phase {
            Phase::Connected(_) => MountState::Connected,
            Phase::Reconnecting { .. } => MountState::Reconnecting,
            Phase::Degraded { .. } => MountState::Degraded,
            Phase::Closed => MountState::Closed,
        }
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
        match &self.lock().phase {
            Phase::Connected(connection) => Some(connection.generation()),
            Phase::Reconnecting { .. } | Phase::Degraded { .. } | Phase::Closed => None,
        }
    }

    /// Why the mount is not serving, if it is not.
    ///
    /// `None` means a connection is installed. A reconnecting mount already has
    /// a reason — the connection that died — even though it is still stalling
    /// and not failing.
    #[must_use]
    pub fn death(&self) -> Option<Death> {
        match &self.lock().phase {
            Phase::Connected(_) => None,
            Phase::Reconnecting { reason, .. } | Phase::Degraded { reason } => Some(reason.clone()),
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
        state.recovery = Recovery::Ended;
        if let Some(probe) = state.probe.take() {
            probe.handle.abort();
        }
        if let Phase::Connected(connection) = &state.phase {
            connection.bury(Death::Closed);
        }
        state.phase = Phase::Closed;
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
    /// ([`Recovery::Ended`], honoured in [`Self::lost`]).
    pub fn stop_reconnecting(&self) {
        let mut state = self.lock();
        state.recovery = Recovery::Ended;
        if let Some(probe) = state.probe.take() {
            probe.handle.abort();
        }
        if matches!(
            state.phase,
            Phase::Reconnecting { .. } | Phase::Degraded { .. }
        ) {
            state.phase = Phase::Closed;
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
    /// Dropping the cancelled task's handle also retires its token, so the
    /// attempt this abort cannot reach in time ([`Machine::owns`]) can no
    /// longer transition the mount or displace its replacement.
    pub fn pause_recovery(&self) {
        let mut state = self.lock();
        // A recovery that has already ended is never handed back, so it is
        // never taken away either: pausing lowers the bar it raised.
        if state.recovery == Recovery::Running {
            state.recovery = Recovery::Paused;
        }
        if let Some(probe) = state.probe.take() {
            probe.handle.abort();
        }
    }

    /// Starts the recovery again after a teardown the kernel refused.
    ///
    /// An `EBUSY` unmount leaves the mount live, still ours, and still
    /// disconnected if it was — so it is owed the probe that
    /// [`Self::pause_recovery`] cancelled, and the bar that pause put up is
    /// lifted. A mount that is Connected or Closed has nothing to recover, and
    /// a recovery that *ended* is never resumed: only a pause is lifted here.
    pub fn resume_recovery(&self) {
        let mut state = self.lock();
        if state.recovery != Recovery::Paused {
            return;
        }
        state.recovery = Recovery::Running;
        if matches!(
            state.phase,
            Phase::Reconnecting { .. } | Phase::Degraded { .. }
        ) {
            self.start_probe(&mut state);
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
                match &state.phase {
                    Phase::Connected(connection) => {
                        return Ok(Serving {
                            connection: Arc::clone(connection),
                            stalled,
                        });
                    }
                    Phase::Degraded { .. } | Phase::Closed => return Err(Errno::IO),
                    // Subscribing under the same lock the phase changes under
                    // is what makes this wait race-free.
                    Phase::Reconnecting { deadline, .. } => (*deadline, self.changes.subscribe()),
                }
            };
            stalled = true;
            // Bounded by the mount's one deadline, never by a timer of this
            // request's own: a request arriving late in the window inherits
            // what is left of it and no more.
            let _ = tokio::time::timeout_at(deadline, changes.changed()).await;
            // The clock, not the wakeup, decides what this wait meant — and it
            // is read after the wait, never before, so nothing is failed early.
            //
            // The deadline wins every tie, which is what makes it *the*
            // deadline. `timeout_at` polls what it wraps before its own timer,
            // so a phase change landing in the same instant the window closes
            // would otherwise send this caller round the loop to be served
            // after its window — under scheduler delay, arbitrarily long after
            // it. A stall that reached the deadline is owed `EIO`, whatever
            // else happened in that instant; short of the deadline the caller
            // looks at the phase again and, if it is still Reconnecting, waits
            // out the rest of the same window.
            if Instant::now() >= deadline {
                self.expire();
                return Err(Errno::IO);
            }
        }
    }

    /// The installed connection, or `None` if there is none right now.
    ///
    /// Never stalls: it is what a request with nothing to wait for — a
    /// no-response `forget` — asks with.
    fn current(&self) -> Option<Arc<Connection>> {
        match &self.lock().phase {
            Phase::Connected(connection) => Some(Arc::clone(connection)),
            _ => None,
        }
    }

    /// Sends one request and returns its reply, replaying per the discipline.
    ///
    /// `Ok(None)` is the moot answer, and only [`Replay::Moot`] can produce it.
    ///
    /// `class` says how the frame queues for the connection's serialization
    /// point, and nothing else: it survives a replay unchanged, because a
    /// re-sent chunk is still a chunk.
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
        replay: Replay,
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
            let request_id = connection.take_request_id();
            let frame = match encode(
                request_id,
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
                Err(error) => return Err(unencodable(error, retained)),
            };
            match connection.call(request_id, opcode, &frame, class).await {
                Ok(bytes) => return Ok(Some((connection, bytes))),
                Err(sent) => {
                    self.lost(&connection);
                    match replay.decide(sent) {
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
        replay: Replay,
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
            replay,
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
        replay: Replay,
        class: Class,
        extract: impl FnOnce(&R, &[u8]) -> Result<T, FramingError>,
    ) -> Result<(T, u64), Errno>
    where
        Q: RequestBody,
        R: ResponseBody,
    {
        let answered = self
            .exchange(caller, node_id, body, payload, R::OPCODE, replay, class)
            .await?;
        // Only `Replay::Moot` answers without a reply, and it takes
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
                Replay::Moot,
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
    /// write and a caller that found a protocol fault all arrive here, and only
    /// the one naming the generation the mount currently holds does anything.
    fn lost(&self, connection: &Arc<Connection>) {
        let reason = connection
            .death()
            .unwrap_or_else(|| Death::Transport("the connection ended".to_owned()));
        let mut state = self.lock();
        match &state.phase {
            Phase::Connected(installed) if installed.generation() == connection.generation() => {}
            // An older generation, or a recovery already under way: whatever
            // this frame or error was, it cannot touch the replacement.
            _ => return,
        }
        connection.bury(reason.clone());
        let stall = self.resilience.stall;
        state.phase = if state.recovery == Recovery::Ended {
            // A teardown that never comes back is already under way: there is
            // nothing left to stall for and nothing will dial again, so the
            // mount ends here instead of opening a window behind the teardown.
            Phase::Closed
        } else if stall.is_zero() {
            // Fail-fast: the window closes the instant the server breaks away.
            Phase::Degraded { reason }
        } else {
            Phase::Reconnecting {
                deadline: Instant::now() + stall,
                reason,
            }
        };
        self.announce(&mut state);
        self.start_probe(&mut state);
    }

    /// Ends the stall if its deadline has passed.
    ///
    /// Called by whoever notices first — a stalled caller whose wait ran out,
    /// or the probe between attempts — so the window's edge is the deadline
    /// itself, not whenever a task happened to be scheduled. It needs no
    /// probe identity for that reason: it reads the clock against the window
    /// the mount is in right now, so a late caller cannot end a window that is
    /// not the one it waited on.
    fn expire(&self) {
        let mut state = self.lock();
        let Phase::Reconnecting { deadline, reason } = &state.phase else {
            return;
        };
        if Instant::now() < *deadline {
            return;
        }
        let reason = reason.clone();
        tracing::warn!(%reason, "the server did not come back within the stall window");
        state.phase = Phase::Degraded { reason };
        self.announce(&mut state);
    }

    /// Ends the stall now, whatever the deadline says.
    ///
    /// A server that answers the handshake with a refusal is reachable and
    /// says no: waiting out the window would only delay the `EIO` the guest is
    /// owed. The probe keeps running, because the configuration may return.
    ///
    /// Only the mount's current probe may cut a window short this way. A
    /// refusal a cancelled attempt observed says nothing about the window a
    /// later death opened, and the contract discards an old attempt's outcomes
    /// exactly as it discards an old connection's frames.
    fn degrade(&self, reason: Death, probe: u64) {
        let mut state = self.lock();
        if state.owns(probe) && matches!(state.phase, Phase::Reconnecting { .. }) {
            tracing::warn!(%reason, "the server refuses to serve this mount");
            state.phase = Phase::Degraded { reason };
            self.announce(&mut state);
        }
    }

    /// Installs a freshly handshaken connection and returns the mount to
    /// Connected, atomically.
    ///
    /// Only a mount that is *waiting* for a connection, and only the probe it
    /// currently owns, may install one. Cancelling an attempt is not
    /// synchronous — an aborted probe can already be past its last await — so a
    /// handshake can arrive here after the mount was torn down, after a
    /// teardown paused the recovery, or after a replacement attempt took this
    /// one's place. Each of those buries the new connection instead of
    /// installing it, which is what keeps a mount from ever holding two live
    /// sessions and splitting its callbacks across them, and what stops a
    /// superseded attempt from clearing the handle its replacement is cancelled
    /// through.
    fn install(&self, established: Established, probe: u64) {
        let Established { connection, reader } = established;
        let connection = Arc::new(connection);
        {
            let mut state = self.lock();
            let wanted = matches!(
                state.phase,
                Phase::Reconnecting { .. } | Phase::Degraded { .. }
            );
            if state.recovery != Recovery::Running || !wanted || !state.owns(probe) {
                connection.bury(Death::Closed);
                return;
            }
            self.max_frame_len
                .store(connection.max_frame_len(), Ordering::Relaxed);
            state.phase = Phase::Connected(Arc::clone(&connection));
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
        let mut state = self.lock();
        let generation = state.next_generation;
        state.next_generation += 1;
        generation
    }

    /// How long `probe`'s next attempt may take, or `None` when there is
    /// nothing left for it to do: the mount is serving again, it has ended, a
    /// teardown took the recovery away, or this attempt has been superseded.
    fn attempt_bound(&self, probe: u64) -> Option<Duration> {
        let state = self.lock();
        if !state.owns(probe) {
            return None;
        }
        match &state.phase {
            // The window's remainder bounds a stalling attempt, so a peer that
            // accepts the socket and never finishes the handshake cannot hold
            // the mount past the deadline.
            Phase::Reconnecting { deadline, .. } => {
                Some(deadline.saturating_duration_since(Instant::now()))
            }
            Phase::Degraded { .. } => Some(DEGRADED_ATTEMPT_BOUND),
            Phase::Connected(_) | Phase::Closed => None,
        }
    }

    /// Whether the stall window has already closed.
    fn is_degraded(&self) -> bool {
        matches!(self.lock().phase, Phase::Degraded { .. })
    }

    /// Starts the single reconnect task, if one is not already running and the
    /// mount is still in a position to want one.
    ///
    /// A teardown holds the bar ([`Machine::recovery`]) and an ended mount is
    /// past recovering, so neither starts a task here — which is what stops a
    /// connection dying mid-unmount from putting a dialler behind the teardown.
    fn start_probe(&self, state: &mut MutexGuard<'_, Machine>) {
        if state.recovery != Recovery::Running
            || state.probe.is_some()
            || matches!(state.phase, Phase::Closed)
        {
            return;
        }
        let Some(me) = self.weak() else { return };
        let token = state.next_probe;
        state.next_probe += 1;
        state.probe = Some(Probe {
            token,
            handle: self.runtime.spawn(reconnect(me, token)).abort_handle(),
        });
    }

    /// Publishes a phase change to everyone stalled on one.
    ///
    /// Done under the state lock, which is what lets a caller subscribe under
    /// that same lock and be sure it cannot miss the next one.
    fn announce(&self, state: &mut MutexGuard<'_, Machine>) {
        state.tick += 1;
        let _ = self.changes.send(state.tick);
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
        if let Phase::Connected(connection) = &self.lock().phase {
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

    fn lock(&self) -> MutexGuard<'_, Machine> {
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
    let mut previous: Option<Duration> = None;
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
            previous = None;
            continue;
        }

        let generation = client.take_generation();
        match tokio::time::timeout(bound, Connection::dial(&client.target, generation)).await {
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

        let wait = backoff(previous, client.is_degraded());
        previous = Some(wait);
        // Let go of the mount while sleeping, so a client nobody else holds is
        // dropped at once, not at the end of a five-second backoff.
        drop(client);
        tokio::time::sleep(wait).await;
    }
}

/// The next backoff delay, capped and jittered.
///
/// Two schedules, because the two phases mean different things: inside the
/// stall window a guest is *waiting*, so retries are quick; once degraded
/// nothing waits on the probe, so it slows to the design's 500 ms-to-5 s.
fn backoff(previous: Option<Duration>, degraded: bool) -> Duration {
    let (initial, max) = if degraded {
        (DEGRADED_INITIAL_BACKOFF, DEGRADED_MAX_BACKOFF)
    } else {
        (STALL_INITIAL_BACKOFF, STALL_MAX_BACKOFF)
    };
    let delay = match previous {
        None => initial,
        Some(previous) => (previous * 2).clamp(initial, max),
    };
    delay - jitter(delay)
}

/// How much to shorten a delay by: up to a quarter of it, from the clock's
/// nanoseconds.
///
/// Nothing here needs to be unpredictable — only uncorrelated between mounts
/// that lost the same server, which the sub-microsecond digits of the wall
/// clock already are. It buys a dependency-free spread instead of a random
/// number generator the crate would otherwise not have.
fn jitter(delay: Duration) -> Duration {
    let spread = delay / JITTER_DIVISOR;
    let nanos = std::time::SystemTime::UNIX_EPOCH
        .elapsed()
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    spread
        .checked_mul(nanos % 1000)
        .map_or(Duration::ZERO, |scaled| scaled / 1000)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_replay_discipline_is_the_contracts() {
        // A queued request provably never reached the server, whatever it is.
        assert_eq!(
            Replay::Idempotent.decide(Sent::Queued),
            Decision::Resend,
            "a queued idempotent request is sent as it is"
        );
        assert_eq!(
            Replay::Once.decide(Sent::Queued),
            Decision::Resend,
            "a queued mutation cannot have been applied, so it is sent as it is"
        );
        // A written one may have been dispatched.
        assert_eq!(Replay::Idempotent.decide(Sent::Written), Decision::Resend);
        assert_eq!(
            Replay::Once.decide(Sent::Written),
            Decision::Fail,
            "a written mutation must not risk a second application"
        );
        // A moot request's referent died with the session either way.
        assert_eq!(Replay::Moot.decide(Sent::Written), Decision::Moot);
        assert_eq!(Replay::Moot.decide(Sent::Queued), Decision::Moot);
    }

    #[test]
    fn the_backoff_doubles_to_its_cap_under_both_schedules() {
        // Jitter only ever shortens, so each delay stays inside its schedule.
        let stalling = backoff(None, false);
        assert!(stalling <= STALL_INITIAL_BACKOFF && stalling * 2 >= STALL_INITIAL_BACKOFF);
        assert!(backoff(Some(STALL_INITIAL_BACKOFF), false) <= STALL_MAX_BACKOFF);
        assert!(backoff(Some(STALL_MAX_BACKOFF), false) <= STALL_MAX_BACKOFF);

        let degraded = backoff(None, true);
        assert!(degraded <= DEGRADED_INITIAL_BACKOFF && degraded * 2 >= DEGRADED_INITIAL_BACKOFF);
        assert!(backoff(Some(DEGRADED_MAX_BACKOFF), true) <= DEGRADED_MAX_BACKOFF);
        // Crossing into the degraded schedule never shortens the delay below
        // its own floor, however small the stalling one had been.
        assert!(backoff(Some(STALL_INITIAL_BACKOFF), true) * 2 >= DEGRADED_INITIAL_BACKOFF);
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

    #[tokio::test]
    async fn only_the_current_probe_owns_the_recovery() {
        let idle = tokio::spawn(std::future::pending::<()>());
        let mut machine = Machine {
            phase: Phase::Closed,
            next_generation: 2,
            probe: None,
            next_probe: 1,
            recovery: Recovery::Running,
            tick: 0,
        };
        assert!(
            !machine.owns(1),
            "a mount with no probe running owns no attempt"
        );
        machine.probe = Some(Probe {
            token: 7,
            handle: idle.abort_handle(),
        });
        assert!(machine.owns(7));
        // What an `EBUSY` unmount leaves behind: attempt 6 was aborted and its
        // handle dropped, but an abort is not synchronous, so the task may
        // still be running. Only the replacement may transition the mount.
        assert!(
            !machine.owns(6),
            "a superseded attempt may not transition the mount that replaced it"
        );
        idle.abort();
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
