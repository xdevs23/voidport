// SPDX-License-Identifier: GPL-2.0

use kernel::prelude::*;
use kernel::sync::aref::ARef;
use kernel::sync::{new_condvar, new_mutex, Arc, CondVar, CondVarTimeoutResult, Mutex, MutexGuard};
use kernel::task::Task;
use voidport_proto::opcode::Opcode;
use voidport_session::handshake::Failure;
use voidport_session::pool::{
    self, Cell, DialFailed, Joined, Loss, Next, Place, Pooled, Remaining, Retire, Take, Taking,
};
use voidport_session::settling::AfterLoss;
use voidport_session::table::{AllocationRefused, InvariantError};
use voidport_session::time::{deadline_verdict, DeadlineVerdict};

use crate::clock::{now, timeout_of};
use crate::connection::{Connection, Death};
use crate::handshake::{Dial, Dialed, Token};
use crate::thread::Thread;

struct Cells(KVec<Cell<Arc<Connection>>>);

impl pool::Cells<Arc<Connection>> for Cells {
    fn cells(&self) -> &[Cell<Arc<Connection>>] {
        &self.0
    }

    fn cells_mut(&mut self) -> &mut [Cell<Arc<Connection>>] {
        &mut self.0
    }

    fn grow(&mut self, len: usize) -> core::result::Result<(), AllocationRefused> {
        let more = len.saturating_sub(self.0.len());
        self.0
            .reserve(more, GFP_KERNEL)
            .map_err(|_| AllocationRefused)?;
        while self.0.len() < len {
            // The room was reserved above, so the push does not allocate.
            self.0
                .push(Cell::vacant(), GFP_KERNEL)
                .map_err(|_| AllocationRefused)?;
        }
        Ok(())
    }
}

impl Pooled for Connection {
    fn lives(&self) -> bool {
        self.death().is_none()
    }

    fn carried(&self) -> bool {
        Connection::carried(self)
    }
}

type Core = pool::Pool<Arc<Connection>, Cells>;

struct Shared {
    core: Core,
    /// The retires the core returned for lost connections, until the thread
    /// of the lost connection sends the retire of it. It has room for the
    /// retire of every connection in `unretired`, so the loss of a
    /// connection never allocates.
    retires: KVec<Retire>,
    /// How many connections joined the session whose thread has not taken
    /// their retire yet.
    unretired: usize,
}

impl Shared {
    fn make_room(&mut self) -> Result {
        let room = (self.unretired + 1).saturating_sub(self.retires.len());
        Ok(self.retires.reserve(room, GFP_KERNEL)?)
    }

    /// Stores `retire` for the thread of its connection, in the room made
    /// when that connection joined.
    fn store(&mut self, retire: Retire) -> core::result::Result<(), InvariantError> {
        self.retires
            .push_within_capacity(retire)
            .map_err(|_| InvariantError)
    }
}

/// What a pool needs of the session whose connections it lends: a thread for
/// each dial, the dial of a connection that joins the session, and the reads
/// of that connection once it joined.
pub(crate) trait Joiner: Send + Sync + Sized + 'static {
    /// Runs `body` on a new thread of the session, which teardown cancels
    /// with `cancel` and joins.
    fn spawn_dial(
        &self,
        body: impl FnOnce(Arc<Self>) + Send + 'static,
        cancel: impl Fn() + Send + 'static,
    ) -> Result;

    fn dial_joining(&self, token: &Token) -> core::result::Result<Dialed<()>, Dial>;

    fn serve(this: Arc<Self>, pool: Arc<Pool>, member: Member);
}

#[derive(Clone)]
pub(crate) struct Member {
    pub(crate) connection: Arc<Connection>,
    pub(crate) place: Place,
}

pub(crate) struct Lent<'a> {
    pool: &'a Pool,
    member: Member,
    left: bool,
}

impl Lent<'_> {
    pub(crate) fn connection(&self) -> &Arc<Connection> {
        &self.member.connection
    }

    /// Leaves the connection to its thread, which gives it back after the
    /// reply still owed on it.
    pub(crate) fn leave_to_thread(mut self) {
        self.left = true;
    }
}

impl Drop for Lent<'_> {
    fn drop(&mut self) {
        if !self.left {
            self.pool.give_back(&self.member);
        }
    }
}

#[pin_data]
pub(crate) struct Pool {
    generation: u64,
    token: Token,
    #[pin]
    shared: Mutex<Shared>,
    /// Notified whenever the pool changes: a connection given back, lost or
    /// joined, and the end of the session.
    #[pin]
    changed: CondVar,
}

enum Outcome {
    Joined(Member),
    /// None joined: the request tries again, with its dials so far.
    Again(Taking),
    /// One joined, and the pool could not store it.
    NoRoom,
}

/// One dial, shared by the request that waits for it and the thread that
/// makes it.
#[pin_data]
struct Dialing {
    #[pin]
    state: Mutex<DialState>,
    #[pin]
    done: CondVar,
}

struct DialState {
    taking: Taking,
    /// The thread that dials, while a signal can end its dial.
    task: Option<ARef<Task>>,
    outcome: Option<Outcome>,
    /// Whether the request stopped waiting, or teardown cancelled the dial.
    left: bool,
}

impl Dialing {
    fn cancel(&self) {
        let mut state = self.state.lock();
        state.left = true;
        if let Some(task) = &state.task {
            Thread::signal(task);
        }
        drop(state);
        self.done.notify_all();
    }
}

impl Pool {
    pub(crate) fn open(generation: u64, dialed: Dialed) -> Result<(Arc<Self>, Member)> {
        let connection = Connection::new(dialed.link, dialed.negotiated.connection_id, generation)?;
        let (core, place) = Core::first(Cells(KVec::new()), connection.id(), connection.clone())
            .map_err(|_| ENOMEM)?;
        let retires = KVec::with_capacity(1, GFP_KERNEL)?;
        let pool = Arc::pin_init(
            pin_init!(Self {
                generation,
                token: dialed.token,
                shared <- new_mutex!(Shared {
                    core,
                    retires,
                    unretired: 1,
                }, "voidport::pool"),
                changed <- new_condvar!("voidport::pool_changed"),
            }),
            GFP_KERNEL,
        )?;
        Ok((pool, Member { connection, place }))
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn is_ended(&self) -> bool {
        self.shared.lock().core.is_ended()
    }

    /// Lends a connection to a request: the one given back last, or one
    /// dialed for it, after waiting while the core returns wait. `None` once
    /// the session ended.
    pub(crate) fn take<J: Joiner>(self: &Arc<Self>, joiner: &J) -> Result<Option<Lent<'_>>> {
        let mut taking = Taking::default();
        loop {
            let mut shared = self.shared.lock();
            let taken = shared.core.take(&taking, now()).map(|take| match take {
                Take::Idle(open) => Ok(Member {
                    connection: open.connection.clone(),
                    place: open.place,
                }),
                Take::Next(next) => Err(next),
            });
            let next = match self.sound(&mut shared, taken) {
                Some(Ok(member)) => return Ok(Some(self.lend(member))),
                Some(Err(next)) => next,
                None => return Ok(None),
            };
            match next {
                Next::Dial => {
                    drop(shared);
                    taking = match self.dial(joiner, taking)? {
                        Outcome::Joined(member) => return Ok(Some(self.lend(member))),
                        Outcome::Again(taking) => taking,
                        Outcome::NoRoom => return Err(ENOMEM),
                    };
                }
                Next::Wait => {
                    if self.changed.wait_interruptible(&mut shared) {
                        return Err(ERESTARTSYS);
                    }
                }
                Next::WaitUntil(at) => {
                    if let DeadlineVerdict::Wait(remaining) = deadline_verdict(at, now()) {
                        let woke = self
                            .changed
                            .wait_interruptible_timeout(&mut shared, timeout_of(remaining));
                        if matches!(woke, CondVarTimeoutResult::Signal { .. }) {
                            return Err(ERESTARTSYS);
                        }
                    }
                }
                Next::Ended => return Ok(None),
            }
        }
    }

    fn lend(&self, member: Member) -> Lent<'_> {
        Lent {
            pool: self,
            member,
            left: false,
        }
    }

    /// Starts the thread that dials a connection for the request `taking`,
    /// and waits until it joined, a signal ends the wait, or teardown
    /// cancels the dial.
    fn dial<J: Joiner>(self: &Arc<Self>, joiner: &J, taking: Taking) -> Result<Outcome> {
        let dialing = Arc::pin_init(
            pin_init!(Dialing {
                state <- new_mutex!(DialState {
                    taking,
                    task: None,
                    outcome: None,
                    left: false,
                }, "voidport::dialing"),
                done <- new_condvar!("voidport::dialed"),
            }),
            GFP_KERNEL,
        )?;
        let (pool, joining, cancelling) = (self.clone(), dialing.clone(), dialing.clone());
        joiner.spawn_dial(
            move |joiner| join(joiner, pool, joining),
            move || cancelling.cancel(),
        )?;
        let mut state = dialing.state.lock();
        loop {
            if let Some(outcome) = state.outcome.take() {
                return Ok(outcome);
            }
            // Teardown ended the session before it cancelled the dial, which
            // the next take returns.
            if state.left {
                return Ok(Outcome::Again(core::mem::take(&mut state.taking)));
            }
            if dialing.done.wait_interruptible(&mut state) && state.outcome.is_none() {
                state.left = true;
                return Err(ERESTARTSYS);
            }
        }
    }

    /// Adds `connection`, which joined the session, lent to the request that
    /// dialed it. A connection the pool does not store is closed.
    fn add(&self, connection: &Arc<Connection>) -> Joined {
        let mut shared = self.shared.lock();
        let joined = match shared.make_room() {
            Ok(()) => {
                let joined = shared.core.join(connection.id(), connection.clone());
                self.sound(&mut shared, joined).unwrap_or(Joined::Ended)
            }
            Err(_) => Joined::NoRoom,
        };
        match joined {
            Joined::Added(_) => shared.unretired += 1,
            Joined::NoRoom | Joined::Ended => connection.bury(Death::Closed),
        }
        joined
    }

    /// A dial of the request `taking` did not join, for `failure`. A failed
    /// join ends the session when the core returns that it does.
    fn dial_failed(&self, taking: &mut Taking, failure: Failure) {
        let mut shared = self.shared.lock();
        if shared
            .core
            .dial_failed(taking, failure, now(), crate::helpers::random_seed())
            == DialFailed::SessionEnds
        {
            self.close(&mut shared, |connection| connection.bury(Death::Closed));
        }
    }

    pub(crate) fn give_back(&self, member: &Member) {
        let mut shared = self.shared.lock();
        let retire = shared.core.give_back(member.place);
        if let Some(retire) = self.sound(&mut shared, retire).flatten() {
            let stored = shared.store(retire);
            self.sound(&mut shared, stored);
        }
        drop(shared);
        self.changed.notify_all();
    }

    /// Reports the loss of `member`, with `forgets` forgets written on it
    /// left for its thread to settle. A loss that ends the session closes every
    /// connection left.
    pub(crate) fn lost(&self, member: &Member, forgets: usize) -> Loss {
        let mut shared = self.shared.lock();
        let loss = shared.core.lost(member.place, forgets);
        let loss = self.sound(&mut shared, loss).unwrap_or(Loss::Handled);
        match loss {
            Loss::SessionEnds => {
                self.close(&mut shared, |connection| connection.bury(Death::Closed))
            }
            Loss::Left { remaining } | Loss::SubscriptionEnded { remaining } => {
                if let Remaining::Retire(retire) = remaining {
                    let stored = shared.store(retire);
                    self.sound(&mut shared, stored);
                }
                self.changed.notify_all();
            }
            Loss::Handled => {}
        }
        loss
    }

    pub(crate) fn forgets_settled(&self, member: &Member) {
        let mut shared = self.shared.lock();
        let retire = shared.core.forgets_settled(member.place);
        if let Some(retire) = self.sound(&mut shared, retire).flatten() {
            let stored = shared.store(retire);
            self.sound(&mut shared, stored);
        }
    }

    /// How a request of `opcode` whose connection was lost is settled before
    /// anything is asked about it.
    pub(crate) fn after_loss(&self, opcode: Opcode) -> AfterLoss {
        self.shared.lock().core.after_loss(opcode)
    }

    /// The retire of the lost `member`, once nothing of it is settling:
    /// `None` when it is not to be retired, or the session ended.
    pub(crate) fn retire_of(&self, member: &Member) -> Option<Retire> {
        let mut shared = self.shared.lock();
        while shared.core.settling(member.place) {
            // The request settling what it had on the connection gives it
            // back.
            let _ = self.changed.wait_interruptible(&mut shared);
        }
        // The thread takes the retire of its connection now, and the room for
        // it is the room of the connection that joins next.
        shared.unretired = shared.unretired.saturating_sub(1);
        if shared.core.is_ended() {
            return None;
        }
        let id = member.connection.id();
        let retire = shared
            .retires
            .iter()
            .find(|retire| retire.connection_id == id)
            .copied();
        shared.retires.retain(|retire| retire.connection_id != id);
        retire
    }

    pub(crate) fn end(&self, end: impl FnMut(Arc<Connection>)) {
        self.close(&mut self.shared.lock(), end);
    }

    /// Ends the session, unless it ended already, hands every open connection
    /// left to `end`, and wakes every wait for the pool.
    fn close(&self, shared: &mut MutexGuard<'_, Shared>, mut end: impl FnMut(Arc<Connection>)) {
        shared.core.end();
        while let Some(connection) = shared.core.next_to_close() {
            end(connection);
        }
        self.changed.notify_all();
    }

    /// The value of `result`, a call into the core. A record of the pool
    /// that no report produces ends the session, and is `None`.
    fn sound<T>(
        &self,
        shared: &mut MutexGuard<'_, Shared>,
        result: core::result::Result<T, InvariantError>,
    ) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(InvariantError) => {
                self.close(shared, |connection| {
                    connection.bury(Death::Local("inconsistent connection pool"))
                });
                None
            }
        }
    }
}

/// The thread that dials a connection for one request: joins it to the
/// session, lends it to the request or leaves it idle, and is then the
/// thread of that connection.
fn join<J: Joiner>(joiner: Arc<J>, pool: Arc<Pool>, dialing: Arc<Dialing>) {
    let _scope = crate::helpers::NoFsScope::enter();
    Thread::allow_cancel();
    {
        let mut state = dialing.state.lock();
        if state.left {
            return;
        }
        state.task = Some(ARef::from(&**kernel::current!()));
    }
    let joined = joiner.dial_joining(&pool.token).and_then(|dialed| {
        Connection::new(
            dialed.link,
            dialed.negotiated.connection_id,
            pool.generation,
        )
        .map_err(Dial::Transport)
    });
    let mut state = dialing.state.lock();
    state.task = None;
    let outcome = match joined {
        Ok(connection) => match pool.add(&connection) {
            Joined::Added(place) => Outcome::Joined(Member { connection, place }),
            Joined::NoRoom => Outcome::NoRoom,
            Joined::Ended => Outcome::Again(core::mem::take(&mut state.taking)),
        },
        Err(dial) => {
            pool.dial_failed(&mut state.taking, dial.failure());
            Outcome::Again(core::mem::take(&mut state.taking))
        }
    };
    let serving = match &outcome {
        Outcome::Joined(member) => Some(member.clone()),
        Outcome::Again(_) | Outcome::NoRoom => None,
    };
    if !state.left {
        state.outcome = Some(outcome);
    } else if let Some(member) = &serving {
        pool.give_back(member);
    }
    drop(state);
    dialing.done.notify_all();
    if let Some(member) = serving {
        J::serve(joiner, pool, member);
    }
}
