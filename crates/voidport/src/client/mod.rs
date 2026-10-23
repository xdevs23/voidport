//! No node id, handle id or lock is rebuilt across a reconnect. The ids handed
//! out by the server never repeat across sessions and restarts, so an id the
//! kernel still has from before the reconnect refers to nothing in the new
//! session, and the server returns `ESTALE` for it (a node) or `EBADF` (a
//! handle). The kernel then heals the tree: entries expire, `ESTALE` makes the
//! VFS walk the path again, and descriptors open across the reconnect fail
//! until they are opened again.

mod caching;
mod connection;
mod forgets;

pub use caching::Pages;
mod interrupt;
mod ops;
mod pool;
mod storage;
mod transport;

pub use connection::{Data, EntrySink, Notice};
pub use interrupt::{Interrupt, Raise};
pub use ops::{
    AttrChange, Granted, Listing, Lock, LockKind, NewFile, Placement, Streamed, TimeChange,
    XattrNames, XattrValue,
};

use std::fmt;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::Duration;

use rustix::io::Errno;
use tokio::sync::watch;
use voidport_memory::{Buffer, Memory};
use voidport_proto::attr::Attr;
use voidport_proto::error::FramingError;
use voidport_proto::frame::Frame;
use voidport_proto::limits::{LIMITS, Part};
use voidport_proto::message::{RequestBody, ResponseBody, ResponseOutcome};
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::connection::OutcomeRequest;
use voidport_session::handshake::{HandshakeError, TooLong};
use voidport_session::probe::{Action as ProbeAction, Degraded, Driver, Event};
use voidport_session::reconnect::{FIRST_GENERATION, Lost, Machine, Phase, Serve, Woke};
use voidport_session::replay::OpenFlags;
use voidport_session::settling::{
    AfterLoss, Concluded, Fate, Settled, Unsettled, conclude, settled,
};
use voidport_session::{Backoff, Instant};
use zerocopy::byteorder::little_endian::U64;

mod clock;

use crate::url::Endpoint;
use connection::{Answer, Connection, Destination, Forget, Nothing, Unsent, kept_answer};
pub use pool::Connections;
use pool::Pool;
pub use voidport_session::handshake::ROOT_NODE_ID;

pub const DEFAULT_RECONNECT_STALL: Duration = voidport_session::options::DEFAULT_RECONNECT_STALL;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caller {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub node_id: u64,
    pub generation: u64,
    pub attr: Attr,
}

impl Entry {
    fn of(entry: &voidport_proto::attr::EntryOut) -> Self {
        Self {
            node_id: entry.node_id.get(),
            generation: entry.generation.get(),
            attr: entry.attr,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub entry: Entry,
    pub next_cookie: u64,
    pub entry_type: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resilience {
    /// `Duration::ZERO` is fail-fast: the window closes the instant the server
    /// breaks away, so outstanding and subsequent operations fail immediately.
    /// The probe still runs, so a server that comes back is still picked up.
    pub stall: Duration,
}

impl Default for Resilience {
    fn default() -> Self {
        Self {
            stall: DEFAULT_RECONNECT_STALL,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountState {
    Connected,
    Reconnecting,
    Degraded,
    Closed,
}

impl MountState {
    fn of(phase: Phase) -> Self {
        match phase {
            Phase::Connected => Self::Connected,
            Phase::Reconnecting => Self::Reconnecting,
            Phase::Degraded => Self::Degraded,
            Phase::Closed => Self::Closed,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub endpoint: Endpoint,
    pub namespace: String,
    pub subpath: Vec<u8>,
}

#[derive(Debug)]
pub struct Client {
    target: Target,
    resilience: Resilience,
    clock: clock::Clock,
    state: Mutex<State>,
    changes: watch::Sender<u64>,
    memory: Arc<Memory>,
    /// Named instead of taken from the ambient context, because not every caller
    /// has one: [`Self::resume_recovery`] is reached from
    /// [`Mount::unmount`](crate::mount::Mount::unmount) on an ordinary blocking
    /// thread, and a bare `tokio::spawn` there panics for want of a reactor.
    runtime: tokio::runtime::Handle,
    me: OnceLock<Weak<Client>>,
    /// It lives on the mount, not on a connection, because the stream outlives
    /// its socket: when the connection it is subscribed on goes, the
    /// subscription is re-established on another and keeps feeding the same
    /// consumer. Unset until something subscribes, so a mount that never
    /// subscribes is byte-identical on the wire.
    notifications: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Notice>>>,
    /// Unbounded, because a dispatch thread queues on it and must not wait.
    /// Each forget gives back lookups that the server answered, so the queue
    /// grows only as fast as lookups complete, and each pass of the sending
    /// task empties it.
    forgets: tokio::sync::mpsc::UnboundedSender<forgets::QueuedForget>,
    sending_forgets: tokio::task::AbortHandle,
}

#[derive(Debug)]
struct State {
    machine: Machine<Arc<Pool>>,
    probe: Option<tokio::task::AbortHandle>,
    reason: Option<Death>,
    backoff: Backoff,
    tick: u64,
}

impl State {
    /// Cancelling is not synchronous, since an attempt already past its last
    /// suspension runs to its end. That is why the machine retires the token as
    /// well: the survivor can no longer transition the mount.
    fn cancel_probe(&mut self) {
        if let Some(probe) = self.probe.take() {
            probe.abort();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Death {
    Closed,
    Transport(String),
    Protocol(String),
    Local(String),
    /// The server is reachable but refuses to serve this mount. The
    /// configuration may come back, so the probe keeps running.
    Refused(String),
}

impl fmt::Display for Death {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("the mount closed the connection"),
            Self::Local(reason) => write!(f, "the client failed: {reason}"),
            Self::Transport(reason) | Self::Protocol(reason) | Self::Refused(reason) => {
                f.write_str(reason)
            }
        }
    }
}

impl Client {
    pub async fn mount(
        endpoint: &Endpoint,
        namespace: &str,
        subpath: &[u8],
    ) -> Result<Arc<Self>, ConnectError> {
        Self::mount_with(endpoint, namespace, subpath, Resilience::default()).await
    }

    /// The first handshake is not resilient: a mount that cannot be established
    /// is a mount error, not a mount that silently starts out degraded.
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
        let memory = Memory::host();
        let (first, token) = Connection::open(&target, FIRST_GENERATION, &memory).await?;
        let first = pool::First::new(first, &memory).await;
        let (changes, _) = watch::channel(0);
        let runtime = tokio::runtime::Handle::current();
        let mut unwatched = None;
        let (forgets, queued) = tokio::sync::mpsc::unbounded_channel();
        let client = Arc::new_cyclic(|me| {
            let sending_forgets = runtime
                .spawn(forgets::send_queued(me.clone(), queued))
                .abort_handle();
            let (pool, first) = Pool::open(
                me.clone(),
                target.clone(),
                FIRST_GENERATION,
                token,
                Arc::clone(&memory),
                runtime.clone(),
                first,
            );
            unwatched = Some(first);
            Self {
                target,
                resilience,
                clock: clock::Clock::new(),
                state: Mutex::new(State {
                    machine: Machine::connected(pool),
                    probe: None,
                    reason: None,
                    backoff: Backoff::seeded(seed()),
                    tick: 0,
                }),
                changes,
                memory,
                runtime,
                me: OnceLock::new(),
                notifications: Mutex::new(None),
                forgets,
                sending_forgets,
            }
        });
        let _fresh_lock_is_empty = client.me.set(Arc::downgrade(&client));
        // The loss of the first connection is reported through the reference of
        // the pool to the mount, which leads nowhere until the mount exists, and
        // the probe the report starts needs `me`.
        if let Some(first) = unwatched {
            first.watch();
        }
        Ok(client)
    }

    /// Always 1: every handshake refuses a server that announces anything else,
    /// and the allocator of the server never hands that number to anything but a
    /// mount root, which makes it the one id that survives a reconnect.
    #[must_use]
    pub fn root_node_id(&self) -> u64 {
        ROOT_NODE_ID
    }

    #[must_use]
    pub fn state(&self) -> MountState {
        MountState::of(self.lock().machine.phase())
    }

    /// The phase word alone cannot tell "never left Connected" from "died and
    /// came back": a watch receiver coalesces, so a session replaced inside one
    /// scheduling gap of an observer wakes it once, reading `Connected`. The
    /// generation is monotonic, so it makes that flap visible.
    #[must_use]
    pub fn connected_generation(&self) -> Option<u64> {
        self.lock().machine.connected_generation()
    }

    pub(crate) fn subscription_key(&self) -> Option<(u64, u64)> {
        let pool = self.current()?;
        pool.subscribed_id().map(|id| (pool.generation(), id))
    }

    #[must_use]
    pub fn connections(&self) -> Option<Connections> {
        self.current().map(|pool| pool.connections())
    }

    #[must_use]
    pub fn death(&self) -> Option<Death> {
        let state = self.lock();
        match state.machine.phase() {
            Phase::Connected => None,
            Phase::Reconnecting | Phase::Degraded => state.reason.clone(),
            Phase::Closed => Some(Death::Closed),
        }
    }

    /// The FUSE library reuses its buffer when the callback returns, and a lost
    /// connection may require sending the data again. Made on the thread of the
    /// callback, which is not one of the runtime: a refusal parks that call until
    /// a buffer of this mount is released.
    #[must_use]
    pub fn copy_of(&self, data: &[u8]) -> Buffer {
        let mut copy = match self.memory.make(data.len(), 1) {
            Ok(copy) => copy,
            Err(_) => self.runtime.block_on(self.memory.buffer(data.len(), 1)),
        };
        copy.copy_from_slice(data);
        copy
    }

    /// A refusal parks the asking request, and never the reader task, until a
    /// buffer of this mount is released, which a reply arriving for any request
    /// in flight brings about.
    pub async fn buffer(&self, len: usize) -> Buffer {
        self.memory.buffer(len, 1).await
    }

    /// It never waits for a caller that is mid-write, which keeps teardown
    /// bounded when the peer has stopped reading.
    pub fn close(&self) {
        let mut state = self.lock();
        let installed = state.machine.close();
        state.cancel_probe();
        // The forgets still queued name nodes of the session that ends here.
        self.sending_forgets.abort();
        if let Some(pool) = installed {
            pool.close(Death::Closed);
        }
        self.announce(&mut state);
    }

    /// Recovery ends from here on in every phase, so a server breaking away after
    /// this call neither starts a probe behind the teardown nor opens a stall
    /// window for callbacks the teardown is about to fail anyway. A mount that is
    /// Connected keeps its connection, because the teardown order closes the
    /// connection only after the kernel unmount.
    pub fn stop_reconnecting(&self) {
        let mut state = self.lock();
        let closed = state.machine.stop_reconnecting();
        state.cancel_probe();
        if closed {
            self.announce(&mut state);
        }
    }

    /// The bar holds until the pause is lifted, so a connection dying
    /// mid-unmount cannot start a probe either, and an attempt already past its
    /// last await cannot install itself. The phase is left as it was, because the
    /// kernel may yet refuse the unmount (see [`Self::resume_recovery`]).
    pub fn pause_recovery(&self) {
        let mut state = self.lock();
        state.machine.pause_recovery();
        state.cancel_probe();
    }

    /// A recovery that ended is never resumed: only a pause is lifted here.
    pub fn resume_recovery(&self) {
        // Taken before the core is asked for an attempt, so that a client that
        // cannot spawn one never leaves the machine holding a token for a task
        // nobody started.
        let Some(me) = self.weak() else { return };
        let mut state = self.lock();
        if let Some(token) = state.machine.resume_recovery() {
            self.spawn_probe(&mut state, me, token);
        }
    }

    /// # Errors
    ///
    /// `EIO` once the mount is degraded or closed, without waiting again, and
    /// for a stall that reached its deadline.
    async fn connected(&self) -> Result<Arc<Pool>, Errno> {
        loop {
            let (deadline, mut changes) = {
                let state = self.lock();
                match state.machine.serve() {
                    Serve::Now { connection } => return Ok(Arc::clone(connection)),
                    Serve::Fail => return Err(Errno::IO),
                    Serve::Stall { deadline } => (deadline, self.changes.subscribe()),
                }
            };
            // Bounded by the one deadline of the mount, so that a request arriving
            // late in the window inherits what is left of it and no more.
            tokio::select! {
                biased;
                _ = changes.changed() => {},
                () = self.clock.until(deadline.as_duration()) => {},
            }
            // The core decides what the wait meant on the instant read after the
            // wait: the deadline wins every tie, and a caller whose window closed
            // is owed `EIO` whatever else happened in that instant.
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

    /// The end of a session is reported to the mount just after the session ends.
    /// A request that asked for a session in between would be handed the ended
    /// one again, and again, without ever waiting. Subscribing under the lock the
    /// report changes the phase under makes the wait race-free.
    async fn moved_on_from(&self, ended: &Pool) {
        let mut changes = {
            let state = self.lock();
            if state.machine.serving(ended.generation()).is_none() {
                return;
            }
            self.changes.subscribe()
        };
        let _sender_gone_ends_the_wait_too = changes.changed().await;
    }

    /// Never stalls: a request with nothing to wait for, a `forget`, asks with
    /// it, so a mount that is stalling out a window answers it the same way a
    /// degraded one does.
    fn current(&self) -> Option<Arc<Pool>> {
        let state = self.lock();
        match state.machine.serve() {
            Serve::Now { connection } => Some(Arc::clone(connection)),
            Serve::Stall { .. } | Serve::Fail => None,
        }
    }

    /// `Ok(None)` is the moot answer, which only an operation the core classifies
    /// as moot can produce.
    ///
    /// When the connection is lost while the session lives, the request is
    /// settled on another connection of the same session as the session core
    /// decides ([`voidport_session::pool`]). When the session ends first, the
    /// replay decision of the session core for the attempt stands.
    ///
    /// `destination` comes back with every outcome, an error before any attempt
    /// included. A destination that cannot be restarted while its session lives,
    /// one that already received entries, fails the request instead of being
    /// sent again in that session.
    ///
    /// `kept` is the most bytes the kept reply of the server to this request can
    /// take.
    ///
    /// `interrupt` ends the request with `EINTR` wherever it would otherwise be
    /// sent, or sent again. While the request is in flight, a cancel of it
    /// follows it on the connection it uses.
    async fn exchange<Q: RequestBody, D: Destination>(
        &self,
        caller: Caller,
        interrupt: &Interrupt,
        opcode: Opcode,
        request: &Outgoing<'_, Q>,
        mut destination: D,
        kept: usize,
    ) -> (D, Result<Option<(Arc<Connection>, Answer)>, Errno>) {
        let Outgoing {
            node_id,
            open,
            body,
            payload,
            data,
        } = *request;
        let mut interrupt = interrupt.clone();
        loop {
            if interrupt.raised() {
                return (destination, Err(Errno::INTR));
            }
            let pool = tokio::select! {
                biased;
                () = interrupt.wait() => continue,
                connected = self.connected() => match connected {
                    Ok(pool) => pool,
                    Err(errno) => return (destination, Err(errno)),
                },
            };
            let taken = tokio::select! {
                biased;
                () = interrupt.wait() => continue,
                taken = pool.take() => taken,
            };
            let Ok(connection) = taken else {
                // The session ended while this request waited for a connection, so
                // the request takes the reconnect path once the mount has moved on
                // from the session, unless it is interrupted first.
                tokio::select! {
                    biased;
                    () = interrupt.wait() => {}
                    () = self.moved_on_from(&pool) => {}
                }
                continue;
            };
            let (ticket, frame) =
                match connection.compose(opcode, open, caller, node_id, body, payload) {
                    Ok(composed) => composed,
                    Err(unsent) => {
                        connection.give_back();
                        return (destination, Err(unsent_errno(unsent)));
                    }
                };
            let request_id = ticket.request_id();
            let (returned, outcome) = {
                let call = connection.call(ticket, &frame, data, destination);
                tokio::pin!(call);
                tokio::select! {
                    biased;
                    called = &mut call => called,
                    () = interrupt.wait() => {
                        // Joined, so that the request continues to be written while
                        // the cancel waits to follow it.
                        let ((), called) = tokio::join!(connection.cancel(request_id), call);
                        called
                    }
                }
            };
            destination = returned;
            let decision = match outcome {
                Ok(answer) => return (destination, Ok(Some((connection.give_back(), answer)))),
                Err(decision) => decision,
            };
            connection.lost();
            let settled = match pool.after_loss(opcode) {
                AfterLoss::Settled(unasked) => unasked.into(),
                AfterLoss::Ask => {
                    let question = OutcomeRequest {
                        connection_id: U64::new(connection.id()),
                        request_id: U64::new(request_id),
                    };
                    settle(&pool, question, opcode, kept).await
                }
            };
            // Given back after it is settled, because the lost connection is
            // retired only once its request is.
            let connection = connection.give_back();
            match conclude(settled, decision, destination.restartable()) {
                Concluded::Answer(reply) => {
                    let answer = read_kept(&reply, request_id, opcode, &mut destination).await;
                    return (destination, answer.map(|answer| Some((connection, answer))));
                }
                Concluded::SendAgain => destination.restart(),
                Concluded::Fail => return (destination, Err(Errno::IO)),
                Concluded::Moot => return (destination, Ok(None)),
            }
        }
    }

    /// # Errors
    ///
    /// The errno the server answered with, `EIO` for a mount that is degraded or
    /// whose non-idempotent request was lost in flight, and the errno the kernel
    /// gives a part longer than its interface takes.
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
        self.call_interruptible::<Q, R, T>(
            caller,
            &Interrupt::none(),
            node_id,
            body,
            payload,
            extract,
        )
        .await
    }

    /// # Errors
    ///
    /// As [`Self::call`], and `EINTR` for a request ended by the interrupt.
    async fn call_interruptible<Q, R, T>(
        &self,
        caller: Caller,
        interrupt: &Interrupt,
        node_id: u64,
        body: &Q,
        payload: &[u8],
        extract: impl FnOnce(&R, &[u8]) -> Result<T, FramingError>,
    ) -> Result<T, Errno>
    where
        Q: RequestBody,
        R: ResponseBody,
    {
        let request = Outgoing {
            node_id,
            open: OpenFlags::NONE,
            body,
            payload,
            data: &[],
        };
        self.call_on::<Q, R, T>(caller, interrupt, &request, extract)
            .await
            .map(|(value, _)| value)
    }

    /// A replayed request is answered by the session whose connection carried its
    /// last attempt, not necessarily the one it was first written to. The
    /// generation of the mount read around the call cannot say which, so the
    /// answering connection is the source.
    async fn call_on<Q, R, T>(
        &self,
        caller: Caller,
        interrupt: &Interrupt,
        request: &Outgoing<'_, Q>,
        extract: impl FnOnce(&R, &[u8]) -> Result<T, FramingError>,
    ) -> Result<(T, u64), Errno>
    where
        Q: RequestBody,
        R: ResponseBody,
    {
        let (Nothing, answered) = self
            .exchange(
                caller,
                interrupt,
                R::OPCODE,
                request,
                Nothing,
                kept_bound::<R>(),
            )
            .await;
        let answered = answered?;
        // Only a moot operation answers without a reply, and those take
        // `call_moot`. A caller here that reaches this arm has lost its
        // connection and gets what every lost request gets.
        let (connection, answer) = answered.ok_or(Errno::IO)?;
        let value = interpret::<R, T>(&connection, &answer.frame, extract)?;
        Ok((value, connection.generation()))
    }

    /// An attempt lost with its session is not an error: the handle it names is
    /// gone either way, so the guest is told the close succeeded. It never
    /// stalls, since a mount with no session installed holds only
    /// dead-generation handles and the request is already moot.
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
        let request = Outgoing {
            node_id,
            open: OpenFlags::NONE,
            body,
            payload,
            data: &[],
        };
        let (Nothing, answered) = self
            .exchange(
                caller,
                &Interrupt::none(),
                R::OPCODE,
                &request,
                Nothing,
                kept_bound::<R>(),
            )
            .await;
        match answered? {
            Some((connection, answer)) => {
                interpret::<R, ()>(&connection, &answer.frame, |_, _| Ok(()))
            }
            None => Ok(()),
        }
    }

    /// It never stalls, and a mount with no session installed drops it, since a
    /// `forget` whose session is gone names a node that died with the session.
    async fn forget_now(&self, forget: Forget) {
        if let Some(pool) = self.current() {
            pool.forget(&[forget]).await;
        }
    }

    /// A mount with another session installed, or none, drops them: the
    /// lookups they give back were counted by a session that is gone.
    async fn forget_within(&self, generation: u64, forgets: &[Forget]) {
        let serving = self.lock().machine.serving(generation).map(Arc::clone);
        if let Some(pool) = serving {
            pool.forget(forgets).await;
        }
    }

    /// This is where session losses coalesce: the pool reports one when a join
    /// is refused and when the last connection of the session, the subscribed one
    /// included, is lost, and the core discards every report that names a
    /// generation the mount has already replaced.
    fn session_lost(&self, generation: u64, reason: Death) {
        let mut state = self.lock();
        let lost = state
            .machine
            .lost(generation, self.now(), self.resilience.stall);
        if lost == Lost::Ignored {
            return;
        }
        state.reason = Some(reason);
        self.announce(&mut state);
        if lost.wants_probe() {
            self.start_probe(&mut state);
        }
    }

    fn touch(&self) {
        let mut state = self.lock();
        self.announce(&mut state);
    }

    fn probe_action(
        &self,
        driver: &mut Driver,
        event: Event,
        reason: Option<Death>,
    ) -> ProbeAction {
        let mut state = self.lock();
        let State {
            machine, backoff, ..
        } = &mut *state;
        let action = driver.advance(event, machine, backoff, self.now());
        if let ProbeAction::Publish(cause) = action {
            match cause {
                Degraded::Expired => self.publish_degraded(&mut state),
                Degraded::Refused => {
                    if let Some(reason) = reason {
                        tracing::warn!(%reason, "the server refuses to serve this mount");
                        state.reason = Some(reason);
                    }
                    self.announce(&mut state);
                }
            }
        }
        action
    }

    fn publish_degraded(&self, state: &mut MutexGuard<'_, State>) {
        if let Some(reason) = state.reason.clone() {
            tracing::warn!(%reason, "the server did not come back within the stall window");
        }
        self.announce(state);
    }

    /// The core says whether this attempt may install at all: a torn-down mount,
    /// a paused recovery and a superseded attempt each answer no. It hands a
    /// session it will not take straight back to be closed, which keeps a mount
    /// from ever holding two live sessions and splitting its callbacks across
    /// them.
    fn install(&self, opened: Opened, probe: u64) {
        let Opened {
            first,
            token,
            generation,
        } = opened;
        let Some(me) = self.weak() else { return };
        let (pool, first) = Pool::open(
            me,
            self.target.clone(),
            generation,
            token,
            Arc::clone(&self.memory),
            self.runtime.clone(),
            first,
        );
        let mut state = self.lock();
        if let Err(refused) = state.machine.install(probe, generation, pool) {
            refused.close(Death::Closed);
            return;
        }
        // Read once the mount holds the session, the only session a report of
        // its end is acted on for.
        first.watch();
        state.reason = None;
        // The task that installed a session is done, so its handle is let go with
        // the token the core just retired.
        state.probe = None;
        self.announce(&mut state);
    }

    /// A teardown holds the bar and an ended mount is past recovering, so
    /// neither gets a task here, which stops a connection dying mid-unmount from
    /// putting a dialler behind the teardown.
    fn start_probe(&self, state: &mut MutexGuard<'_, State>) {
        // Taken before the core is asked for an attempt: a client that cannot
        // spawn a task must not leave the machine holding a token for one nobody
        // started. The reference is set the moment the client is built, before
        // anything can lose a connection.
        let Some(me) = self.weak() else { return };
        if let Some(token) = state.machine.start_probe() {
            self.spawn_probe(state, me, token);
        }
    }

    fn spawn_probe(&self, state: &mut MutexGuard<'_, State>, me: Weak<Client>, token: u64) {
        // A fresh attempt is a fresh outage as far as the schedule is concerned,
        // and the jitter source keeps advancing across all of them.
        state.backoff.restart();
        state.probe = Some(self.runtime.spawn(reconnect(me, token)).abort_handle());
    }

    /// Done under the state lock, so that a caller subscribing under that same
    /// lock cannot miss the next one.
    fn announce(&self, state: &mut MutexGuard<'_, State>) {
        state.tick += 1;
        let _nobody_subscribed = self.changes.send(state.tick);
    }

    fn now(&self) -> Instant {
        Instant::from_duration(self.clock.now())
    }

    fn weak(&self) -> Option<Weak<Client>> {
        self.me.get().cloned()
    }

    /// Every transition bumps the tick under the state lock, so a consumer that
    /// subscribes and then reads [`Self::state`] cannot miss one.
    #[must_use]
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// `false` means one is already routed and the caller may not open a second.
    /// There is exactly one notification stream on a connection, and the server
    /// has no way to say which of two consumers a frame is for, so a second sink
    /// could only replace the first and starve a consumer that believes it is
    /// listening. A sink whose consumer has dropped its receiver does not stand
    /// in the way of a new one.
    pub(crate) fn route_notifications(
        &self,
        sink: tokio::sync::mpsc::UnboundedSender<Notice>,
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
        if let Some(connection) = self.current().and_then(|pool| pool.subscribed()) {
            connection.route_notifications(sink);
        }
        true
    }

    fn notification_route(&self) -> Option<tokio::sync::mpsc::UnboundedSender<Notice>> {
        self.notifications
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
            .filter(|sink| !sink.is_closed())
    }

    /// The sink of the connection is left as it is: frames sent into a channel
    /// nobody holds are dropped, and the next subscription installs its own on
    /// the connection it subscribes on.
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
    /// A safety net under the unmount path, which closes explicitly and in
    /// order.
    fn drop(&mut self) {
        self.close();
    }
}

/// One per mount at a time, owned by the state machine and cancelled by
/// teardown, so that a dial or a backoff in flight never delays an unmount.
/// `token` identifies this task to the mount. Every transition of the task
/// first checks that `token` is still the current one, because an abort takes
/// effect only at the next await and this task may already be past its last.
async fn reconnect(client: Weak<Client>, token: u64) {
    let mut driver = Driver::new(token);
    let mut event = Event::Continue;
    let mut established = None;
    let mut reason = None;
    loop {
        let Some(client) = client.upgrade() else {
            return;
        };
        match client.probe_action(&mut driver, event, reason.take()) {
            ProbeAction::Dial { generation, bound } => {
                let dial = Connection::open(&client.target, generation, &client.memory);
                let deadline = client.clock.now() + bound;
                let result = tokio::select! {
                    biased;
                    result = dial => Some(result),
                    () = client.clock.until(deadline) => None,
                };
                event = match result {
                    Some(Ok((first, token))) => {
                        established = Some(Opened {
                            first: pool::First::new(first, &client.memory).await,
                            token,
                            generation,
                        });
                        Event::Dialed(Ok(()))
                    }
                    Some(Err(error)) => {
                        reason = refusal(&error);
                        let disposition = if reason.is_some() {
                            voidport_session::handshake::Disposition::Degrade
                        } else {
                            tracing::debug!(%error, "a reconnect attempt failed");
                            voidport_session::handshake::Disposition::Retry
                        };
                        Event::Dialed(Err(disposition))
                    }
                    None => {
                        tracing::debug!("a reconnect attempt ran out of its window");
                        Event::Dialed(Err(voidport_session::handshake::Disposition::Retry))
                    }
                };
            }
            ProbeAction::Publish(_) => event = Event::Continue,
            ProbeAction::Prepare => event = Event::Prepared(established.is_some()),
            ProbeAction::Install => {
                if let Some(opened) = established.take() {
                    tracing::info!("the data connection is back");
                    client.install(opened, token);
                }
                return;
            }
            ProbeAction::Sleep(wait) => {
                drop(client);
                tokio::time::sleep(wait).await;
                event = Event::Continue;
            }
            ProbeAction::Stop => return,
        }
    }
}

#[derive(Debug)]
struct Opened {
    first: pool::First,
    token: Buffer,
    generation: u64,
}

async fn settle(
    pool: &Arc<Pool>,
    question: OutcomeRequest,
    opcode: Opcode,
    bound: usize,
) -> Settled<Data> {
    let fate = pool.ask(question, bound).await;
    if let Fate::Unsettled(unsettled) = &fate {
        let errno = match unsettled {
            Unsettled::Refused(errno) => Errno::from_raw_os_error(errno.get()),
            Unsettled::Unanswerable => Errno::IO,
        };
        tracing::warn!(%errno, %opcode, "the server refused to say what became of a request");
    }
    settled(fate)
}

async fn read_kept<D: Destination>(
    reply: &Data,
    request_id: u64,
    opcode: Opcode,
    destination: &mut D,
) -> Result<Answer, Errno> {
    kept_answer(reply.filled(), request_id, opcode, destination)
        .await
        .map_err(|reason| {
            tracing::warn!(%reason, %opcode, "a kept reply could not be read");
            Errno::IO
        })
}

fn unsent_errno(unsent: Unsent) -> Errno {
    match unsent {
        Unsent::Claim(voidport_session::table::ClaimError::Allocation) => Errno::NOMEM,
        Unsent::Claim(voidport_session::table::ClaimError::Invariant(_)) => Errno::IO,
        Unsent::Encode(error) => unencodable(error),
    }
}

#[derive(Clone, Copy)]
struct Outgoing<'a, Q> {
    node_id: u64,
    open: OpenFlags,
    body: &'a Q,
    payload: &'a [u8],
    data: &'a [u8],
}

/// No request whose reply is kept carries a variable part in it but a listing,
/// whose bound its caller states.
const fn kept_bound<R: ResponseBody>() -> usize {
    let reply = voidport_proto::frame::FrameWriter::response_len::<R>(0);
    let error = voidport_proto::frame::FrameWriter::ERROR_RESPONSE_LEN;
    if reply > error { reply } else { error }
}

/// Nothing about it needs to be unpredictable, only uncorrelated between two
/// mounts that lost the same server, so that they do not retry in lockstep. The
/// hash builder the standard library seeds from the system is exactly that much
/// randomness with no dependency behind it.
fn seed() -> u64 {
    use std::hash::{BuildHasher as _, Hasher as _, RandomState};

    RandomState::new().build_hasher().finish()
}

fn connect_failure(error: &ConnectError) -> (voidport_session::handshake::Failure, Death) {
    use voidport_session::handshake::Failure;
    let failure = failure(error);
    let reason = error.to_string();
    let death = match (failure, error) {
        (Failure::Transport, _) => Death::Transport(reason),
        (_, ConnectError::Protocol { .. }) => Death::Protocol(reason),
        _ => Death::Refused(reason),
    };
    (failure, death)
}

fn failure(error: &ConnectError) -> voidport_session::handshake::Failure {
    use voidport_session::handshake::Failure;
    match error {
        ConnectError::Refused { status } => {
            Failure::Refused(voidport_session::handshake::Refusal::from_linux_errno(
                errno_of(*status).raw_os_error(),
            ))
        }
        ConnectError::RootNodeId { .. } | ConnectError::Protocol { .. } => {
            Failure::InvalidHandshake
        }
        ConnectError::Connect { .. } | ConnectError::Transport { .. } => Failure::Transport,
        ConnectError::TooLong => Failure::Local,
    }
}

fn refusal(error: &ConnectError) -> Option<Death> {
    use voidport_session::handshake::Disposition;
    let (failure, death) = connect_failure(error);
    match failure.disposition() {
        Disposition::Retry => None,
        Disposition::Degrade => Some(death),
    }
}

/// Every failure here poisons the connection exactly as a bad frame read off
/// the socket would.
fn interpret<R: ResponseBody, T>(
    connection: &Connection,
    bytes: &[u8],
    extract: impl FnOnce(&R, &[u8]) -> Result<T, FramingError>,
) -> Result<T, Errno> {
    let frame = match Frame::parse(bytes, &LIMITS) {
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

/// The mount notices through the reader task, which watches the same connection
/// and wakes as soon as its socket is shut down.
fn poison(connection: &Connection, fault: FramingError) -> Errno {
    connection.poison(fault);
    Errno::IO
}

/// The only thing a well-formed request can get wrong here is a part longer
/// than the interface of the kernel takes.
fn unencodable(error: FramingError) -> Errno {
    match error {
        FramingError::RegionTooLong {
            part: Part::Name | Part::Path,
            ..
        } => Errno::NAMETOOLONG,
        FramingError::RegionTooLong {
            part: Part::XattrName,
            ..
        } => Errno::RANGE,
        FramingError::RegionTooLong { .. } => Errno::TOOBIG,
        error => {
            tracing::error!(%error, "a request could not be encoded");
            Errno::IO
        }
    }
}

fn errno_of(status: i32) -> Errno {
    Errno::from_raw_os_error(-status)
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectError {
    #[error("cannot connect to {endpoint}")]
    Connect {
        endpoint: String,
        #[source]
        source: io::Error,
    },
    #[error("the handshake with {endpoint} failed")]
    Transport {
        endpoint: String,
        #[source]
        source: io::Error,
    },
    #[error("the server refused the mount: {}", io::Error::from_raw_os_error(-status))]
    Refused { status: i32 },
    #[error("the server's handshake reply is malformed: {reason}")]
    Protocol { reason: String },
    #[error("the server announced root node id {announced}, and a FUSE mount root is {expected}")]
    RootNodeId { announced: u64, expected: u64 },
    #[error("{}", TooLong)]
    TooLong,
}

impl From<HandshakeError> for ConnectError {
    /// Two classes have a mount error of their own, because an operator acting
    /// on them acts differently: a refusal names the answer of the server, and
    /// the root node id names what was announced. The rest are one thing to an
    /// operator: the peer is not speaking this protocol.
    fn from(error: HandshakeError) -> Self {
        match error {
            HandshakeError::Refused { status } => Self::Refused { status },
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
    fn from(TooLong: TooLong) -> Self {
        Self::TooLong
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_errnos_are_mapped_without_changing_the_shared_disposition() {
        use voidport_session::handshake::{Disposition, Failure, Refusal};
        for value in 1..=4095 {
            let errno = Errno::from_raw_os_error(value);
            let class = Refusal::from_linux_errno(value);
            assert_eq!(
                refusal(&ConnectError::Refused {
                    status: -errno.raw_os_error()
                })
                .is_some(),
                Failure::Refused(class).disposition() == Disposition::Degrade,
            );
            assert!(
                refusal(&ConnectError::Transport {
                    endpoint: "test".to_owned(),
                    source: io::Error::from_raw_os_error(errno.raw_os_error()),
                })
                .is_none()
            );
        }
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
        // A handshake `EMFILE` is the host of the server out of descriptors. They
        // may come back while the stall window is still open, so this is not the
        // configuration refusal that degrades a mount at once.
        assert!(
            refusal(&ConnectError::Refused {
                status: -Errno::MFILE.raw_os_error(),
            })
            .is_none(),
            "a host out of descriptors is a resource, not a configuration"
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
    fn a_part_longer_than_the_interface_takes_answers_the_kernels_errno() {
        let too_long = |part| FramingError::RegionTooLong {
            part,
            declared: 1,
            bound: 0,
        };
        assert_eq!(unencodable(too_long(Part::Name)), Errno::NAMETOOLONG);
        assert_eq!(unencodable(too_long(Part::Path)), Errno::NAMETOOLONG);
        assert_eq!(unencodable(too_long(Part::XattrName)), Errno::RANGE);
        assert_eq!(unencodable(too_long(Part::XattrValue)), Errno::TOOBIG);
        assert_eq!(unencodable(FramingError::LengthOverflow), Errno::IO);
    }
}
