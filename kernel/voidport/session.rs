// SPDX-License-Identifier: GPL-2.0

use core::time::Duration;

use kernel::prelude::*;
use kernel::sync::{new_condvar, new_mutex, Arc, ArcBorrow, CondVar, CondVarTimeoutResult, Mutex};
use voidport_proto::message::ResponseOutcome;
use voidport_session::backoff::Backoff;
use voidport_session::cleanup::Disposition;
use voidport_session::reconnect::{Lost, Machine, Phase, Serve, Woke};
use voidport_session::replay::{self, Decision};
use voidport_session::settling::{conclude, settled, Concluded};
use voidport_session::time::{deadline_verdict, DeadlineVerdict};

use crate::cleanup::{Cleanup, EndedSession, Records, Retiring};
use crate::clock::{now, timeout_of};
use crate::connection::{
    reply_area, sent_of, Claim, ClosedConnection, Connection, Death, Interrupt, Landing, Outbound,
    Owed, PageData, Pieces, ReadPages, Received, Reply, Transmit, Wait,
};
use crate::diag::{info_limited, warn_limited};
use crate::handle::Handle;
use crate::handshake::{Dial, Dialed, Dialer, Server, Token};
use crate::helpers::{FatalSignalsOnly, Killable};
use crate::ops::{Expect, Operation, Request};
use crate::part::fitting;
use crate::pool::{Joiner, Member, Pool};
use crate::socket::Network;
use crate::stats;
use crate::thread::Thread;
use crate::wire::{encode, request_len, Caller, LIMITS};

mod probe;
mod worker;

/// What a read answers when its caller left while the reply was streaming
/// into the caller's folio: the reader ends the folio's read.
pub(crate) fn handed() -> Error {
    crate::errno::einprogress()
}

/// The error a peer's status is answered with.
///
/// `EINPROGRESS` from the peer is answered as `EIO`, so that [`handed`]
/// comes only from this module and a read that sees it can trust that the
/// reader ends its folio.
pub(crate) fn peer_error(status: i32) -> Error {
    let error = Error::from_errno(status);
    if error == handed() {
        EIO
    } else {
        error
    }
}

/// Local extraction failures do not invalidate a peer's well-formed reply.
pub(crate) enum ExtractError {
    Protocol(voidport_proto::error::FramingError),
    Local(Error),
}

impl From<voidport_proto::error::FramingError> for ExtractError {
    fn from(error: voidport_proto::error::FramingError) -> Self {
        Self::Protocol(error)
    }
}

struct State {
    machine: Machine<Arc<Pool>>,
    reason: Option<Death>,
    backoff: Backoff,
    tick: u64,
}

impl State {
    fn bump(&mut self) {
        self.tick = self.tick.wrapping_add(1);
    }
}

#[pin_data]
pub(crate) struct Session {
    stall: Duration,
    dialer: Arc<Dialer>,
    #[pin]
    state: Mutex<State>,
    #[pin]
    changes: CondVar,
    /// The threads of the connections, of the dials and of the probes,
    /// joined at teardown. A thread that has exited is joined when the next
    /// one starts.
    #[pin]
    threads: Mutex<KVec<Thread>>,
    /// The first connection of the session the mount opened, until its
    /// thread starts.
    #[pin]
    first: Mutex<Option<Member>>,
    #[pin]
    cleanup: Mutex<Option<Thread>>,
    #[pin]
    records: Mutex<Records>,
    #[pin]
    cleanup_ready: CondVar,
}

pub(crate) struct Owned {
    landing: Landing,
    source: Arc<Connection>,
    orphan: Option<KBox<Cleanup>>,
}

impl Owned {
    pub(crate) fn bytes(&self) -> &[u8] {
        self.landing.bytes()
    }

    pub(crate) fn into_pieces(self) -> Pieces {
        self.landing.pieces
    }
}

pub(crate) enum Attempt<Q> {
    Answered(Owned, Q),
    /// The connection had died before the request was claimed on it.
    Dead,
    Lost(Unanswered<Q>),
    /// The request ended with this error, and nothing of it is owed a reply.
    Failed(Error),
    /// The caller left with this error while the reply is owed: the thread
    /// of the connection reads it and gives the connection back.
    Left(Error),
}

pub(crate) struct Unanswered<Q> {
    /// The replay decision for its attempt, which stands when the session
    /// ended.
    pub(crate) decision: Decision,
    request_id: u64,
    body: Q,
    /// Where a reply the server stored for it lands, and the cleanup that
    /// reply needs.
    landing: Landing,
    orphan: Option<KBox<Cleanup>>,
    reply: Arc<Reply>,
}

impl<Q> Unanswered<Q> {
    /// The request of `opcode`, left to the thread of its lost connection,
    /// which settles it: the reply the server stored for it lands where this
    /// attempt had it land.
    fn into_owed(self, opcode: voidport_proto::opcode::Opcode) -> Owed {
        let Unanswered {
            request_id,
            landing,
            orphan,
            reply,
            ..
        } = self;
        reply.leave_unsettled(landing, orphan);
        Owed {
            request_id,
            opcode,
            reply,
        }
    }
}

/// A claimed ticket is returned on every setup failure. Once armed, the shared
/// table owns its completion and refuses abandonment through this same path.
struct Claimed<'a> {
    connection: Option<&'a Connection>,
    ticket: voidport_session::table::Ticket,
}

impl Drop for Claimed<'_> {
    fn drop(&mut self) {
        if let Some(connection) = self.connection {
            connection.abandon_claim(&mut self.ticket);
        }
    }
}

struct RequestAttempt<'a, Q> {
    claim: Claimed<'a>,
    body: Q,
    frame: KVVec<u8>,
    /// How many bytes the reply needs, without the bytes a read puts in
    /// pages.
    reply_len: usize,
    data_len: usize,
    reply: Arc<Reply>,
    interrupt: Interrupt,
}

enum AttemptBuildError {
    Claim(Claim),
    Local(Error),
}

impl From<Error> for AttemptBuildError {
    fn from(error: Error) -> Self {
        Self::Local(error)
    }
}

impl<'a, Q: Operation> RequestAttempt<'a, Q> {
    fn new(
        connection: &'a Connection,
        request: &Request<'a, Q>,
        data: &PageData<'_>,
        orphan: Option<KBox<Cleanup>>,
        replay: replay::Replay,
    ) -> core::result::Result<Self, AttemptBuildError> {
        let claim = Claimed {
            connection: Some(connection),
            ticket: connection
                .claim(Q::OPCODE, replay)
                .map_err(AttemptBuildError::Claim)?,
        };
        let pieces = match &request.expect {
            Expect::Nothing => Pieces::None,
            Expect::Read(range) => Pieces::Read(range.clone()),
            Expect::Entries(size) => Pieces::Entries {
                buffer: KVVec::from_elem(0u8, *size, GFP_KERNEL).map_err(|_| ENOMEM)?,
                len: 0,
            },
            Expect::Bytes(size) => Pieces::Bytes {
                buffer: KVVec::from_elem(0u8, *size, GFP_KERNEL).map_err(|_| ENOMEM)?,
                len: 0,
            },
        };
        let body = request.body.prepare();
        let request_len = request_len::<Q>(request.payload.len());
        let reply_len = reply_area(body.reply_capacity(), &pieces);
        // A link that has room for only some parts of the data beside the
        // frame and the reply sends the data of those parts, and the caller
        // asks again for the rest.
        let (body, data_len) = match connection.data_room(request_len, reply_len)? {
            Some(count) => cut(body, request, data, count)?,
            None => (body, data.len()),
        };
        let mut frame = KVVec::from_elem(0u8, request_len, GFP_KERNEL).map_err(|_| ENOMEM)?;
        let frame_len = encode(
            &mut frame,
            claim.ticket.request_id(),
            request.caller,
            request.node_id,
            &body,
            request.payload,
        )
        // A part longer than the kernel's interface takes is refused as the
        // interface refuses it.
        .map_err(|_| crate::errno::enametoolong())?
        .len();
        frame.truncate(frame_len);
        let interrupt = interrupt_of(replay, &pieces);
        let reply = Reply::new(body.reply_capacity(), pieces, orphan)?;
        Ok(Self {
            claim,
            body,
            frame,
            reply_len,
            data_len,
            reply,
            interrupt,
        })
    }
}

/// `body`, cut to the bytes in the first `count` parts of `data`, the data
/// of `request` in pages, and how many bytes that is. `EIO` for data of which
/// no part fits.
fn cut<Q>(
    body: Q,
    request: &Request<'_, Q>,
    data: &PageData<'_>,
    count: usize,
) -> Result<(Q, usize)> {
    // Only a request with data in pages has a cut.
    let Some(cut) = request.cut else {
        return Ok((body, 0));
    };
    let len = fitting(count, |visit| data.parts(visit))?;
    if len == 0 && data.len() != 0 {
        return Err(EIO);
    }
    Ok((cut(body, len), len))
}

/// Which signals end the wait for the reply to a request sent whole. A
/// request that must not be sent twice waits through every signal but a fatal
/// one, since its caller could not tell whether it took effect. So does a
/// request whose reply streams into the buffer of a direct read: the reader
/// writes that buffer until the reply ends, and a program must not see it
/// change after the read returned.
fn interrupt_of(replay: replay::Replay, pieces: &Pieces) -> Interrupt {
    if matches!(pieces, Pieces::Read(range) if matches!(range.pages(), ReadPages::Buffer(_))) {
        return Interrupt::Fatal;
    }
    match replay {
        replay::Replay::Once => Interrupt::Fatal,
        replay::Replay::Idempotent | replay::Replay::Moot => Interrupt::Any,
    }
}

/// Mount setup preserves transport and handshake failures for context errors.
pub(crate) enum OpenError {
    /// Local startup allocation failed before a usable session existed.
    Allocation,
    Dial(Dial),
}

impl OpenError {
    pub(crate) fn errno(&self) -> Error {
        match self {
            Self::Allocation => ENOMEM,
            Self::Dial(error) => error.errno(),
        }
    }

    pub(crate) fn diagnostic(&self) -> &'static core::ffi::CStr {
        match self {
            Self::Allocation => c"cannot allocate mount session state",
            Self::Dial(Dial::FamilyUnavailable) => c"the endpoint's address family is unavailable",
            Self::Dial(Dial::Connect(error)) if *error == ENOMEM => {
                c"cannot allocate the connection"
            }
            Self::Dial(Dial::Connect(_)) => c"cannot connect to the endpoint",
            Self::Dial(Dial::Transport(_)) => c"transport I/O failed during the handshake",
            Self::Dial(Dial::Refused(_)) => c"the server refused the mount",
            Self::Dial(Dial::Handshake(_)) => c"the server sent an invalid handshake",
            Self::Dial(Dial::TooLong) => {
                c"the namespace or the path is longer than a handshake can fit"
            }
            Self::Dial(Dial::NoDevice) => c"no voidport virtio device has the tag",
        }
    }
}

impl Session {
    /// Every socket, the first and each reconnect, is dialled from the
    /// network namespace `network`, which the session has until it is
    /// dropped.
    ///
    /// That first attempt carries no deadline of its own. It ends when the
    /// handshake completes, when the connection fails, or when a signal
    /// interrupts the mounting task, which already holds the means to abandon
    /// it. The stall window `stall` bounds requests once the mount exists,
    /// and the background reconnect probe keeps its own bound.
    pub(crate) fn open(
        server: Server,
        stall: Duration,
        namespace: KVec<u8>,
        path: KVec<u8>,
        network: Network,
    ) -> core::result::Result<Arc<Self>, OpenError> {
        let _scope = crate::helpers::NoFsScope::enter();
        let dialer =
            Dialer::new(network, server, namespace, path).map_err(|_| OpenError::Allocation)?;
        let dialed = dialer.dial(None).map_err(OpenError::Dial)?;
        let (pool, first) = Pool::open(voidport_session::reconnect::FIRST_GENERATION, dialed)
            .map_err(|_| OpenError::Allocation)?;
        Arc::pin_init(
            pin_init!(Session {
                stall,
                dialer,
                state <- new_mutex!(State {
                    machine: Machine::connected(pool),
                    reason: None,
                    backoff: Backoff::seeded(crate::helpers::random_seed()),
                    tick: 0,
                }, "voidport::session"),
                changes <- new_condvar!("voidport::changes"),
                threads <- new_mutex!(KVec::new(), "voidport::threads"),
                first <- new_mutex!(Some(first), "voidport::first"),
                cleanup <- new_mutex!(None, "voidport::cleanup"),
                records <- new_mutex!(Records::default(), "voidport::records"),
                cleanup_ready <- new_condvar!("voidport::cleanup_ready"),
            }),
            GFP_KERNEL,
        )
        .map_err(|_| OpenError::Allocation)
    }

    pub(crate) fn namespace(&self) -> &[u8] {
        self.dialer.namespace()
    }

    pub(crate) fn path(&self) -> &[u8] {
        self.dialer.path()
    }

    /// Starts the thread that reads the first connection. It starts once, and a
    /// later call fails with `EIO`.
    pub(crate) fn start_reading(&self) -> Result {
        let pool = self.current().ok_or(EIO)?;
        let member = self.first.lock().take().ok_or(EIO)?;
        self.spawn(
            c"voidport-conn",
            move |session| serve(session, pool, member),
            || {},
        )
    }

    fn shared(&self) -> Arc<Self> {
        // SAFETY: a session exists only inside the `Arc` that `open` returns,
        // so `self` is the pointer `Arc::as_ptr` returns for it, and the
        // borrow of the caller keeps that `Arc` alive for this call.
        Arc::from(unsafe { ArcBorrow::from_raw(self) })
    }

    /// Runs `f` on a new thread of this session, which teardown cancels with
    /// `cancel` and joins. The threads that have exited are joined first.
    pub(crate) fn spawn(
        &self,
        name: &'static core::ffi::CStr,
        f: impl FnOnce(Arc<Self>) + Send + 'static,
        cancel: impl Fn() + Send + 'static,
    ) -> Result {
        let mut threads = self.threads.lock();
        threads.retain(|thread| !thread.exited());
        // The room for the handle is reserved before the thread starts, so a
        // failed allocation leaves nothing running, and the push below does
        // not allocate.
        threads.reserve(1, GFP_KERNEL)?;
        let session = self.shared();
        // Teardown ends every connection, cancels every dial and closes the
        // dialler before it joins, which ends every wait of the thread.
        threads.push(Thread::spawn(name, move || f(session), cancel)?, GFP_KERNEL)?;
        Ok(())
    }

    /// Publish a complete ownership record, and then the record paired with
    /// it. Validation precedes accounting so a malformed suffix cannot hide a
    /// partially admitted directory batch. A record whose reply leaves nothing
    /// to give back is dropped.
    pub(crate) fn record(
        &self,
        source: Arc<Connection>,
        mut cleanup: KBox<Cleanup>,
        disposition: Disposition,
    ) {
        if let Err(error) = cleanup.admit(source.generation()) {
            source.poison(error);
            return;
        }
        if !cleanup.owes(disposition) {
            return;
        }
        let paired = cleanup.take_paired();
        // The insert runs under the session state lock, so either the end of
        // the session finds the record, or the record finds the ended session
        // and ends it the same way.
        let state = self.state.lock();
        let mut records = self.records.lock();
        records.insert(cleanup, disposition);
        let ended = match state.machine.serving(source.generation()) {
            Some(_) => EndedSession::default(),
            None => records.session_ended(source.generation()),
        };
        drop(records);
        drop(state);
        ended.complete();
        self.cleanup_ready.notify_one();
        if let Some(paired) = paired {
            self.record(source, paired, disposition);
        }
    }

    /// Transfer cleanup without allocating or waiting for a peer. The live
    /// list records the session of each reference, including after reconnect.
    pub(crate) fn retire(&self, retiring: Retiring, caller: Caller) {
        if !self.records.lock().release(retiring, caller) {
            warn_limited!(Cleanup, "cleanup has no matching live reference");
        }
        self.cleanup_ready.notify_one();
    }

    /// Hands the cleanup worker `flush`, the record of a Flush that the
    /// process closing a descriptor of `handle` could not send as it died.
    /// Once the session of the handle ended, the locks of the Flush ended with
    /// it, and the record drops.
    pub(crate) fn flush_after_close(&self, flush: KBox<Cleanup>, handle: &Arc<Handle>) {
        let flush = flush.through(handle.clone());
        // An unsent record drops after the lock: the handle it holds may be
        // the last, and its release takes the lock.
        let unsent = self.records.lock().flush_after_close(flush, handle.id());
        drop(unsent);
        self.cleanup_ready.notify_one();
    }

    /// The pool of the session to serve a request in, stalling while
    /// reconnecting.
    fn connected(&self) -> Result<Arc<Pool>> {
        loop {
            let mut state = self.state.lock();
            let deadline = match state.machine.serve() {
                Serve::Now { connection: pool } => return Ok(pool.clone()),
                Serve::Fail => return Err(EIO),
                Serve::Stall { deadline } => deadline,
            };
            let signalled = match deadline_verdict(deadline, now()) {
                DeadlineVerdict::Proceed => false,
                DeadlineVerdict::Wait(remaining) => matches!(
                    self.changes
                        .wait_interruptible_timeout(&mut state, timeout_of(remaining)),
                    CondVarTimeoutResult::Signal { .. }
                ),
            };
            match state.machine.woke(deadline, now()) {
                Woke::Expired { degraded } => {
                    if degraded {
                        warn_limited!(
                            Transport,
                            "the server did not come back within the stall window"
                        );
                        state.bump();
                        drop(state);
                        self.changes.notify_all();
                    }
                    return Err(EIO);
                }
                Woke::Retry => {
                    if signalled {
                        return Err(ERESTARTSYS);
                    }
                }
            }
        }
    }

    /// The pool of the installed session, or `None`. Never stalls.
    fn current(&self) -> Option<Arc<Pool>> {
        match self.state.lock().machine.serve() {
            Serve::Now { connection: pool } => Some(pool.clone()),
            _ => None,
        }
    }

    /// The pool of the session of `generation`, or `None` once that session
    /// ended. Never stalls.
    fn serving(&self, generation: u64) -> Option<Arc<Pool>> {
        self.state.lock().machine.serving(generation).cloned()
    }

    /// Waits until the session of `pool`, which ended, is no longer the
    /// installed one.
    fn replaced(&self, pool: &Arc<Pool>) -> Result {
        let mut state = self.state.lock();
        while matches!(state.machine.serve(), Serve::Now { connection } if Arc::ptr_eq(connection, pool))
        {
            if self.changes.wait_interruptible(&mut state) {
                return Err(ERESTARTSYS);
            }
        }
        Ok(())
    }

    /// Sends `request` on a connection of the installed session until it is
    /// answered, or until the core ends it after the loss of its connection.
    fn exchange<Q: Operation>(&self, request: &Request<'_, Q>) -> Result<Option<(Owned, Q)>> {
        loop {
            let pool = self.connected()?;
            let Some(lent) = pool.take(self)? else {
                // The session ended while this request waited for a
                // connection: it follows the reconnect path.
                self.replaced(&pool)?;
                continue;
            };
            let lost = match self.attempt(lent.connection(), request) {
                Attempt::Answered(owned, body) => return Ok(Some((owned, body))),
                Attempt::Dead => continue,
                Attempt::Failed(error) => return Err(error),
                Attempt::Left(error) => {
                    lent.leave_to_thread();
                    return Err(error);
                }
                Attempt::Lost(lost) => lost,
            };
            let source = lent.connection().clone();
            let fate = {
                // The question about a request sent only once ends only on a
                // fatal signal, as the wait for its reply does.
                let once = replay::of(Q::OPCODE, request.body.open_flags()) == replay::Replay::Once;
                let _signals = once.then(FatalSignalsOnly::enter);
                self.fate_after_loss(
                    &pool,
                    &source,
                    Q::OPCODE,
                    lost.request_id,
                    lost.landing.kept_bound(),
                )
            };
            // The lost connection is given back after its request is
            // settled, since it is retired only once its request is. A
            // caller that leaves first leaves the request to the thread of
            // the connection, which settles it.
            let fate = match fate {
                Ok(fate) => fate,
                Err(error) => {
                    source.leave(lost.into_owed(Q::OPCODE));
                    return Err(error);
                }
            };
            drop(lent);
            // Every attempt lands in storage of its own, so a request can
            // always be sent again.
            match conclude(settled(fate), lost.decision, true) {
                Concluded::Answer(kept) => return self.kept(&kept, lost, &source).map(Some),
                Concluded::SendAgain => {}
                Concluded::Fail => return Err(EIO),
                Concluded::Moot => return Ok(None),
            }
        }
    }

    /// The answer to the request that `lost` describes, from `kept`, the
    /// reply the server stored for it on `source`.
    fn kept<Q: Operation>(
        &self,
        kept: &[u8],
        lost: Unanswered<Q>,
        source: &Arc<Connection>,
    ) -> Result<(Owned, Q)> {
        let Unanswered {
            request_id,
            body,
            mut landing,
            orphan,
            ..
        } = lost;
        landing.read_kept(kept, request_id)?;
        Ok((
            Owned {
                landing,
                source: source.clone(),
                orphan,
            },
            body,
        ))
    }

    pub(crate) fn attempt<Q: Operation>(
        &self,
        connection: &Arc<Connection>,
        request: &Request<'_, Q>,
    ) -> Attempt<Q> {
        let replay = replay::of(Q::OPCODE, request.body.open_flags());
        // Cleanup storage must exist before the peer can admit a reference.
        let orphan = match request.body.cleanup(request.caller, request.node_id) {
            Ok(orphan) => orphan,
            Err(error) => return Attempt::Failed(error),
        };
        let data = request.page_data();
        let attempt = match RequestAttempt::new(connection, request, &data, orphan, replay) {
            Ok(attempt) => attempt,
            Err(AttemptBuildError::Claim(Claim::Dead)) => return Attempt::Dead,
            Err(AttemptBuildError::Claim(Claim::Allocation)) => return Attempt::Failed(ENOMEM),
            Err(AttemptBuildError::Local(error)) => return Attempt::Failed(error),
        };
        self.finish_attempt(connection, attempt, data)
    }

    /// Reply completion, interruption and loss share one outcome matrix. Only
    /// loss reaches the core's replay decision; a departed caller never does.
    fn finish_attempt<Q: Operation>(
        &self,
        connection: &Arc<Connection>,
        mut attempt: RequestAttempt<'_, Q>,
        data: PageData<'_>,
    ) -> Attempt<Q> {
        let outbound = Outbound {
            frame: &attempt.frame,
            reply_len: attempt.reply_len,
            data,
            data_len: attempt.data_len,
        };
        let transmit =
            connection.transmit(&mut attempt.claim.ticket, &outbound, attempt.reply.clone());
        // Transmission either arms the ticket or retires it before returning.
        attempt.claim.connection = None;
        let wait = match transmit {
            Transmit::Written => attempt.reply.wait(attempt.interrupt),
            Transmit::Cancelled => {
                stats::record(stats::Event::Cancelled);
                return Attempt::Failed(ERESTARTSYS);
            }
            Transmit::Failed(error) => return Attempt::Failed(error),
            // A reply that was never armed is failed here, as the death of
            // the connection fails an armed one.
            Transmit::Dead => {
                attempt.reply.fail();
                attempt.reply.wait(attempt.interrupt)
            }
        };
        match wait {
            Wait::Answered { landing, orphan } => {
                let owned = Owned {
                    landing,
                    source: connection.clone(),
                    orphan,
                };
                Attempt::Answered(owned, attempt.body)
            }
            Wait::Interrupted => {
                stats::record(stats::Event::Interrupted);
                Attempt::Left(ERESTARTSYS)
            }
            Wait::Handed => {
                stats::record(stats::Event::Interrupted);
                Attempt::Left(handed())
            }
            Wait::Lost { landing, orphan } => Attempt::Lost(Unanswered {
                decision: attempt.claim.ticket.decide(sent_of(transmit)),
                request_id: attempt.claim.ticket.request_id(),
                body: attempt.body,
                landing,
                orphan,
                reply: attempt.reply,
            }),
        }
    }

    pub(crate) fn call<Q: Operation>(&self, request: Request<'_, Q>) -> Result<Q::Output> {
        let _scope = crate::helpers::NoFsScope::enter();
        let (mut owned, body) = self.exchange(&request)?.ok_or(EIO)?;
        let result = self.interpret(&owned, &body);
        if let Some(mut cleanup) = owned.orphan.take() {
            let disposition = if result.is_ok() {
                Disposition::Retain
            } else {
                Disposition::GiveBack
            };
            cleanup.carry(owned.landing);
            self.record(owned.source, cleanup, disposition);
        }
        result
    }

    pub(crate) fn interpret<Q: Operation>(&self, owned: &Owned, body: &Q) -> Result<Q::Output> {
        let frame = match voidport_proto::frame::Frame::parse(owned.bytes(), &LIMITS) {
            Ok(frame) => frame,
            Err(_) => return Err(self.poison_source(owned)),
        };
        let read = match frame.response::<Q::Response>() {
            Ok(ResponseOutcome::Success(response)) => {
                body.extract(response.body(), response.payload(), &owned.landing)
            }
            Ok(ResponseOutcome::Error(status)) => body.refused(status),
            Err(_) => return Err(self.poison_source(owned)),
        };
        read.map_err(|error| match error {
            ExtractError::Local(error) => error,
            ExtractError::Protocol(error) => {
                owned.source.poison(error);
                EIO
            }
        })
    }

    /// A late parser error belongs only to the connection that sent the reply.
    fn poison_source(&self, owned: &Owned) -> Error {
        owned
            .source
            .poison(voidport_proto::error::FramingError::LengthOverflow);
        EIO
    }

    /// Reports to the mount that the session of `pool` ended over `reason`,
    /// once: requests stall until the probe brings a session back, and every
    /// reference of the session ended with it. Every connection of the session
    /// is closed by then.
    pub(crate) fn session_ended(&self, pool: &Pool, reason: Death) {
        let mut state = self.state.lock();
        let lost = state.machine.lost(pool.generation(), now(), self.stall);
        if lost == Lost::Ignored {
            return;
        }
        let ended = self.records.lock().session_ended(pool.generation());
        stats::record(stats::Event::ConnectionLost);
        state.reason = Some(reason);
        match reason {
            Death::Protocol(_) => {
                warn_limited!(
                    Protocol,
                    "the server sent a frame the protocol does not allow"
                );
            }
            Death::Local(message) => {
                warn_limited!(Transport, "the client failed: {message}");
            }
            _ => info_limited!(Transport, "the server connection ended; reconnecting"),
        }
        state.bump();
        drop(state);
        self.changes.notify_all();
        ended.complete();
    }

    /// Ends peer waits without joining, including from a worker handle's drop.
    pub(crate) fn begin_close(&self) {
        self.shut(|connection| connection.bury(Death::Closed));
    }

    /// Moves the mount to closed and ends every connection of the installed
    /// session cleanly. Returns the ends of those connections.
    fn close_cleanly(&self) -> KVec<ClosedConnection> {
        let mut closed = KVec::new();
        self.shut(|connection| {
            let Some(end) = connection.close() else {
                return;
            };
            match closed.reserve(1, GFP_KERNEL) {
                // The room was reserved, so the push does not allocate.
                Ok(()) => drop(closed.push_within_capacity(end)),
                // An end that cannot be kept is cut at once.
                Err(_) => end.abort(),
            }
        });
        closed
    }

    /// Moves the mount to closed, which fails every stalled caller, ends every
    /// connection of the installed session with `end`, and stops dialling.
    fn shut(&self, end: impl FnMut(Arc<Connection>)) {
        let _scope = crate::helpers::NoFsScope::enter();
        let mut state = self.state.lock();
        let installed = state.machine.close();
        state.bump();
        drop(state);
        self.changes.notify_all();
        if let Some(pool) = installed {
            pool.end(end);
            let ended = self.records.lock().session_ended(pool.generation());
            ended.complete();
        }
        self.dialer.close();
    }

    /// A task that a fatal signal can stop ends each connection cleanly: the
    /// server reads every frame whole and then an end of file, and this task
    /// waits until the server has closed its side, while the thread of each
    /// connection, or this task when the session started no thread, reads and
    /// drops what still arrives. A fatal signal shuts both directions of every
    /// connection and ends the wait, and so does any signal that ends the read
    /// of this task. Any other task, a kernel thread among them, shuts both
    /// directions at once, since a signal cannot end its wait.
    pub(crate) fn close(&self) {
        let _scope = crate::helpers::NoFsScope::enter();
        // Once the session has started a thread, every connection it installs
        // is read by a thread of its own.
        let threaded = !self.threads.lock().is_empty();
        match crate::helpers::current_killable() {
            Some(killable) if threaded => {
                let closed = self.close_cleanly();
                self.join_threads(Some((&closed, &killable)));
            }
            Some(_) => {
                for closed in self.close_cleanly() {
                    if closed.drain().is_err() {
                        closed.abort();
                    }
                }
            }
            None => {
                self.begin_close();
                self.join_threads(None);
            }
        }
        self.end_cleanup();
    }

    /// Joins every thread of the session, the ones started meanwhile
    /// included: the shutdown of each connection ended the reads, the end of
    /// the pool every wait for a connection, the cancellation every dial, and
    /// the closed phase the probe. With `draining`, it first waits until each
    /// thread has exited, so that the thread of each connection a clean close
    /// ended drains it. A fatal signal ends that wait and shuts both
    /// directions of those connections.
    fn join_threads(&self, draining: Option<(&KVec<ClosedConnection>, &Killable)>) {
        loop {
            let threads = core::mem::take(&mut *self.threads.lock());
            if threads.is_empty() {
                return;
            }
            for thread in &threads {
                thread.cancel();
            }
            for thread in threads {
                if let Some((closed, killable)) = draining {
                    if thread.wait_exited_killable(killable).is_err() {
                        for closed in closed.iter() {
                            closed.abort();
                        }
                    }
                }
                thread.stop();
            }
        }
    }

    /// Wait for the core's delay or teardown. Teardown closes the machine and
    /// notifies changes under the same mutex as this wait.
    pub(crate) fn wait_backoff(&self, duration: Duration) {
        let deadline = now().saturating_add(duration);
        let mut state = self.state.lock();
        while !matches!(state.machine.phase(), Phase::Closed) && !Thread::should_stop() {
            let DeadlineVerdict::Wait(remaining) = deadline_verdict(deadline, now()) else {
                break;
            };
            let _ = self
                .changes
                .wait_interruptible_timeout(&mut state, timeout_of(remaining));
        }
    }
}

/// The thread of the connection `member` of `pool`: reads every reply on it
/// until it ends, gives the connection back after a reply no caller waits
/// for, settles what its loss left, drains it after a clean close, and starts
/// the probe thread when the session ended.
pub(crate) fn serve(session: Arc<Session>, pool: Arc<Pool>, member: Member) {
    let _scope = crate::helpers::NoFsScope::enter();
    let death = loop {
        match member.connection.receive() {
            Ok(Received::Taken) => {}
            Ok(Received::Callerless(cleanup)) => {
                if let Some(cleanup) = cleanup {
                    session.record(member.connection.clone(), cleanup, Disposition::GiveBack);
                }
                pool.give_back(&member);
            }
            Err(death) => break death,
        }
    };
    member.connection.bury(death);
    session.settle_loss(&pool, &member, death);
    // A clean close leaves the rest of the connection it ended to this
    // thread. The teardown goes on whether the server closed or the read
    // failed.
    if member.connection.death() == Some(Death::Closed) {
        let _ = member.connection.drain();
    }
    // The connection is freed before a probe thread that may have to wait
    // until it can start.
    drop(member);
    drop(pool);
    session.start_probe_thread();
}

impl Joiner for Session {
    fn spawn_dial(
        &self,
        body: impl FnOnce(Arc<Self>) + Send + 'static,
        cancel: impl Fn() + Send + 'static,
    ) -> Result {
        self.spawn(c"voidport-conn", body, cancel)
    }

    fn dial_joining(&self, token: &Token) -> core::result::Result<Dialed<()>, Dial> {
        self.dialer.join(token)
    }

    fn serve(this: Arc<Self>, pool: Arc<Pool>, member: Member) {
        serve(this, pool, member);
    }
}
