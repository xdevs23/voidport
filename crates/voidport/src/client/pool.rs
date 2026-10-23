use std::future::Future;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use tokio::sync::Notify;
use tokio::task::JoinSet;
use voidport_memory::{Buffer, Memory, Refused};
use voidport_session::Instant;
use voidport_session::handshake::Failure;
use voidport_session::pool::{
    Cell, Cells, DialFailed, Install, Joined, Loss, Next, Open, Place, Remaining, Retire,
    Subscription, Take, Taking, Unsubscribed,
};
use voidport_session::settling::AfterLoss;
use voidport_session::table::{AllocationRefused, InvariantError};

use super::connection::{Connection, Established, Forgotten, Replies, read_replies};
use super::storage::grow_vacant;
use super::{Client, Death, Target};

mod requests;
pub(crate) use requests::Counted;
#[cfg(test)]
pub(crate) mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ended;

type Core = voidport_session::pool::Pool<Arc<Connection>, Storage>;

#[derive(Debug, Default)]
struct Storage(Vec<Cell<Arc<Connection>>>);

impl Cells<Arc<Connection>> for Storage {
    fn cells(&self) -> &[Cell<Arc<Connection>>] {
        &self.0
    }

    fn cells_mut(&mut self) -> &mut [Cell<Arc<Connection>>] {
        &mut self.0
    }

    fn grow(&mut self, len: usize) -> Result<(), AllocationRefused> {
        grow_vacant(&mut self.0, len, Cell::vacant)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connections {
    /// The connections of its pool: idle ones, busy ones, and ones whose
    /// death is recorded and whose loss is not yet reported.
    pub pooled: usize,
    pub subscribed: bool,
}

#[derive(Debug)]
pub struct Pool {
    generation: u64,
    token: Buffer,
    target: Target,
    client: Weak<Client>,
    runtime: tokio::runtime::Handle,
    memory: Arc<Memory>,
    origin: tokio::time::Instant,
    state: Mutex<Core>,
    /// Raised on every change a waiting request may be waiting for: a
    /// connection given back, lost or added, and the end of the session.
    changed: Notify,
    /// The tasks that receive the answers of requests whose callers left.
    unattended: Mutex<JoinSet<()>>,
}

#[derive(Clone, Debug)]
pub struct Placed {
    connection: Arc<Connection>,
    place: Place,
}

impl From<Open<'_, Arc<Connection>>> for Placed {
    fn from(open: Open<'_, Arc<Connection>>) -> Self {
        Self {
            connection: Arc::clone(open.connection),
            place: open.place,
        }
    }
}

impl Deref for Placed {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.connection
    }
}

/// Dropped before it is given back, it reports that the request departed from
/// the connection ([`voidport_session::pool::Pool::departed`]). A request
/// written to it may still be in transmission or owed its reply, so a living
/// connection is left out of use, and a lost one counts its request as settled.
#[derive(Debug)]
pub struct Checkout {
    pool: Arc<Pool>,
    placed: Placed,
    reported: bool,
}

impl Checkout {
    pub fn give_back(mut self) -> Arc<Connection> {
        self.reported = true;
        self.pool.returned(&self.placed);
        Arc::clone(&self.placed.connection)
    }

    pub fn lost(&self) {
        self.pool.lost(&self.placed);
    }

    fn into_subscribed(mut self) -> Placed {
        self.reported = true;
        self.placed.clone()
    }
}

impl Deref for Checkout {
    type Target = Placed;

    fn deref(&self) -> &Placed {
        &self.placed
    }
}

impl Drop for Checkout {
    fn drop(&mut self) {
        if !self.reported {
            self.pool.departed(&self.placed);
        }
    }
}

/// The pool is opened before [`Pool`] is, because [`Pool`] is opened where
/// nothing may wait for memory.
#[derive(Debug)]
pub(crate) struct First {
    placed: Placed,
    reader: Replies,
    core: Core,
}

impl First {
    pub(crate) async fn new(established: Established, memory: &Memory) -> Self {
        let Established { connection, reader } = established;
        let connection = Arc::new(connection);
        let (core, place) = memory
            .obtain(|| {
                Core::first(Storage::default(), connection.id(), Arc::clone(&connection))
                    .map_err(|AllocationRefused| Refused)
            })
            .await;
        Self {
            placed: Placed { connection, place },
            reader,
            core,
        }
    }
}

/// The mount starts reading the first connection once it holds the pool, so that
/// a first connection the server closed right after the handshake is reported to
/// a mount that acts on it, instead of ending a session the mount goes on
/// serving requests in.
#[derive(Debug)]
#[must_use = "nothing reads the first connection until it is watched"]
pub(crate) struct Unwatched {
    pool: Arc<Pool>,
    placed: Placed,
    reader: Replies,
}

impl Unwatched {
    pub(crate) fn watch(self) {
        self.pool.watch(self.placed, self.reader);
    }
}

impl Pool {
    pub(crate) fn open(
        client: Weak<Client>,
        target: Target,
        generation: u64,
        token: Buffer,
        memory: Arc<Memory>,
        runtime: tokio::runtime::Handle,
        first: First,
    ) -> (Arc<Self>, Unwatched) {
        let First {
            placed,
            reader,
            core,
        } = first;
        let pool = Arc::new(Self {
            generation,
            token,
            target,
            client,
            runtime,
            memory,
            origin: tokio::time::Instant::now(),
            state: Mutex::new(core),
            changed: Notify::new(),
            unattended: Mutex::new(JoinSet::new()),
        });
        let unwatched = Unwatched {
            pool: Arc::clone(&pool),
            placed,
            reader,
        };
        (pool, unwatched)
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn connections(&self) -> Connections {
        let state = self.lock();
        Connections {
            pooled: state.connections(),
            subscribed: state.subscribed().is_some(),
        }
    }

    #[must_use]
    pub fn subscribed_id(&self) -> Option<u64> {
        self.lock().subscribed().map(|open| open.connection.id())
    }

    pub async fn take(self: &Arc<Self>) -> Result<Checkout, Ended> {
        let mut taking = Taking::default();
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let now = self.now();
            let next = match self.lock().take(&taking, now) {
                Ok(Take::Idle(open)) => return Ok(self.checkout(open.into())),
                Ok(Take::Next(next)) => Ok(next),
                Err(broken) => Err(broken),
            };
            match next {
                Ok(Next::Dial) => match self.dial().await {
                    Ok(checkout) => return Ok(checkout),
                    Err(Dialed::Ended) => return Err(Ended),
                    Err(Dialed::Failed(failure, reason)) => {
                        let (now, seed) = (self.now(), super::seed());
                        let failed = self.lock().dial_failed(&mut taking, failure, now, seed);
                        if failed == DialFailed::SessionEnds {
                            self.end(reason);
                            return Err(Ended);
                        }
                    }
                },
                Ok(Next::Wait) => changed.await,
                Ok(Next::WaitUntil(at)) => {
                    let at = self.origin + at.as_duration();
                    tokio::select! {
                        () = changed => {}
                        () = tokio::time::sleep_until(at) => {}
                    }
                }
                Ok(Next::Ended) => return Err(Ended),
                Err(InvariantError) => {
                    self.inconsistent();
                    return Err(Ended);
                }
            }
        }
    }

    async fn dial(self: &Arc<Self>) -> Result<Checkout, Dialed> {
        let established = match Connection::join(&self.target, &self.token, self.generation).await {
            Ok(established) => established,
            Err(error) => {
                tracing::debug!(%error, "a connection could not join the session");
                let (failure, reason) = super::connect_failure(&error);
                return Err(Dialed::Failed(failure, reason));
            }
        };
        let Established { connection, reader } = established;
        let connection = Arc::new(connection);
        let joining = &connection;
        // The room is made under the lock, so no other connection takes it
        // before this one is added, and a refusal parks with the lock let go
        // and reads the state again on every try.
        let added = self
            .memory
            .obtain(|| {
                let joined = self.lock().join(joining.id(), Arc::clone(joining));
                match joined {
                    Ok(Joined::Added(place)) => Ok(Some(place)),
                    Ok(Joined::NoRoom) => Err(Refused),
                    Ok(Joined::Ended) => Ok(None),
                    Err(InvariantError) => {
                        self.inconsistent();
                        Ok(None)
                    }
                }
            })
            .await;
        let Some(place) = added else {
            connection.bury(Death::Closed);
            return Err(Dialed::Ended);
        };
        let placed = Placed { connection, place };
        self.watch(placed.clone(), reader);
        self.changed.notify_waiters();
        Ok(self.checkout(placed))
    }

    fn checkout(self: &Arc<Self>, placed: Placed) -> Checkout {
        Checkout {
            pool: Arc::clone(self),
            placed,
            reported: false,
        }
    }

    fn returned(self: &Arc<Self>, placed: &Placed) {
        let given = self.lock().give_back(placed.place);
        self.retire_if(given);
        self.changed.notify_waiters();
    }

    /// No connection becomes idle, so nothing a waiting request waits for
    /// changes.
    fn departed(self: &Arc<Self>, placed: &Placed) {
        let departed = self.lock().departed(placed.place);
        self.retire_if(departed);
    }

    fn retire_if(self: &Arc<Self>, verdict: Result<Option<Retire>, InvariantError>) {
        match verdict {
            Ok(Some(retire)) => self.spawn_retire(retire),
            Ok(None) => {}
            Err(InvariantError) => self.inconsistent(),
        }
    }

    pub fn lost(self: &Arc<Self>, placed: &Placed) {
        let connection = &placed.connection;
        let reason = connection
            .death()
            .unwrap_or_else(|| Death::Transport("the connection ended".to_owned()));
        // Shut down whatever way it was noticed, so its reader ends too.
        connection.bury(reason.clone());
        let (forgets, loss) = {
            let mut state = self.lock();
            // Taken in the same lock hold as the report, so a second report
            // of this loss finds no forgets.
            let forgets = connection.take_forgets();
            let loss = state.lost(placed.place, forgets.len());
            (forgets, loss)
        };
        let remaining = match loss {
            Ok(Loss::Handled) => return,
            Ok(Loss::SessionEnds) => return self.end(reason),
            Ok(Loss::Left { remaining }) => remaining,
            Ok(Loss::SubscriptionEnded { remaining }) => {
                if let Some(client) = self.client.upgrade() {
                    // The subscription ended with its connection; the stream
                    // takes it up again on another.
                    client.touch();
                }
                remaining
            }
            Err(InvariantError) => return self.inconsistent(),
        };
        self.changed.notify_waiters();
        match remaining {
            Remaining::Nothing => {}
            Remaining::Forgets => self.spawn_settle_forgets(placed, forgets),
            Remaining::Retire(retire) => self.spawn_retire(retire),
        }
    }

    /// Settles the forgets of lost connection `placed` from a separate task,
    /// and carries out the verdict of the core once they are settled.
    fn spawn_settle_forgets(self: &Arc<Self>, placed: &Placed, forgets: Vec<Forgotten>) {
        let pool = Arc::clone(self);
        let place = placed.place;
        let lost_id = placed.id();
        self.runtime.spawn(async move {
            pool.settle_forgets(lost_id, forgets).await;
            let settled = pool.lock().forgets_settled(place);
            pool.retire_if(settled);
        });
    }

    /// The subscribed connection is closed too, which ends the session on the
    /// server as well.
    fn end(&self, reason: Death) {
        self.close(reason.clone());
        if let Some(client) = self.client.upgrade() {
            client.session_lost(self.generation, reason);
        }
    }

    /// Runs `work` until it ends or the session closes.
    pub(crate) fn finish_after_caller(&self, work: impl Future<Output = ()> + Send + 'static) {
        let mut unattended = self.unattended();
        while let Some(ended) = unattended.try_join_next() {
            if let Err(error) = ended
                && error.is_panic()
            {
                tracing::error!(%error, "a task receiving a late answer panicked");
            }
        }
        let _aborted_by_close = unattended.spawn_on(work, &self.runtime);
    }

    /// Ends the session, unless a decision of the core already did, and
    /// closes every connection still open in it, one at a time with the lock
    /// of the core let go, without reporting anything to the mount. A late
    /// answer has nothing to give back to a session that ended, so the tasks
    /// receiving them are aborted.
    pub(crate) fn close(&self, death: Death) {
        self.unattended().abort_all();
        self.lock().end();
        self.changed.notify_waiters();
        loop {
            let next = self.lock().next_to_close();
            let Some(connection) = next else {
                return;
            };
            connection.bury(death.clone());
        }
    }

    /// Ends the session over a record of the pool of the session core that no
    /// sequence of reports produces, as a broken request table ends its
    /// connection.
    fn inconsistent(&self) {
        tracing::error!("the records of the connection pool are inconsistent");
        self.end(Death::Local("inconsistent connection pool".to_owned()));
    }

    pub fn after_loss(&self, opcode: voidport_proto::opcode::Opcode) -> AfterLoss {
        self.lock().after_loss(opcode)
    }

    /// Whether a subscription is used is decided by the session core: one
    /// whose connection died is reported lost, which ends it. A connection
    /// taken for the subscription is installed only as the session core
    /// returns, checked under the same lock its loss is recorded under, and
    /// one it does not install is given back.
    pub async fn subscription(self: &Arc<Self>) -> Result<Placed, Ended> {
        loop {
            let dead = match self.lock().subscription() {
                Subscription::Held(subscribed) => return Ok(subscribed.into()),
                Subscription::Dead(subscribed) => Some(Placed::from(subscribed)),
                Subscription::Vacant => None,
            };
            if let Some(dead) = dead {
                self.lost(&dead);
            }
            let connection = self.take().await?;
            let installed = self.lock().install(connection.place);
            match installed {
                Ok(Install::Installed) => return Ok(connection.into_subscribed()),
                Ok(Install::Again) => {
                    connection.give_back();
                }
                Ok(Install::Ended) => return Err(Ended),
                Err(InvariantError) => {
                    self.inconsistent();
                    return Err(Ended);
                }
            }
        }
    }

    pub fn unsubscribed(&self, placed: &Placed) {
        let unsubscribed = self.lock().unsubscribed(placed.place);
        match unsubscribed {
            Ok(Unsubscribed::Returned | Unsubscribed::Leaving) => self.changed.notify_waiters(),
            Ok(Unsubscribed::Unchanged) => {}
            Err(InvariantError) => self.inconsistent(),
        }
    }

    #[must_use]
    pub fn subscribed(&self) -> Option<Placed> {
        self.lock().subscribed().map(Placed::from)
    }

    fn watch(self: &Arc<Self>, placed: Placed, reader: Replies) {
        let pool = Arc::downgrade(self);
        self.runtime.spawn(async move {
            read_replies(Arc::clone(&placed.connection), reader).await;
            if let Some(pool) = pool.upgrade() {
                pool.lost(&placed);
            }
        });
    }

    fn now(&self) -> Instant {
        Instant::from_duration(self.origin.elapsed())
    }

    fn unattended(&self) -> MutexGuard<'_, JoinSet<()>> {
        self.unattended
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn lock(&self) -> MutexGuard<'_, Core> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

enum Dialed {
    Failed(Failure, Death),
    Ended,
}
