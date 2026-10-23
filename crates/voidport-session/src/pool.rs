//! A lost connection leaves the pool at once. When a request was written to it,
//! the server stores what it read from it until the client retires it, so the
//! pool records the connection until everything of it is settled: the request
//! in flight on it, and the forgets written on it since its last reply.
//! Whichever of them is settled last returns a [`Retire`].
//!
//! An open connection of the session is idle (in the pool, the one given back
//! last is taken first), busy (in the pool, with one request on it), resting
//! (in the pool and never handed out again until its loss is reported),
//! subscribed (out of the pool), or leaving (given back by the subscription
//! after its death was recorded, and in the pool no more). The session lives
//! while it has a connection of the pool or a subscribed one.
//!
//! A [`Place`] leads to the cell of a connection without a search. The id that
//! the session gave a connection is only sent in the retire request. A record
//! that no sequence of reports produces is returned as [`InvariantError`], and
//! the adapter ends the session over it ([`Pool::end`]).

use core::ops::Deref;

use voidport_proto::opcode::Opcode;

use crate::handshake::{Failure, Join};
use crate::replay::{self, Settle};
use crate::settling::{AfterLoss, Unasked};
use crate::table::{AllocationRefused, InvariantError};
use crate::time::Instant;

mod cells;
mod dials;

pub use cells::{Cell, Cells, Open, Place};
pub use dials::{Next, Taking};

use cells::{Content, Idle, Outstanding, Role, Storage, Unplaced};

pub trait Pooled {
    /// Whether its death is still unrecorded. Handling its loss records one
    /// first.
    fn lives(&self) -> bool;

    /// Whether a request was ever written to it, in whole or in part. The
    /// server stores nothing of a connection that no request was written to.
    fn carried(&self) -> bool;
}

#[derive(Debug)]
pub struct Pool<C, S> {
    storage: Storage<C, S>,
    state: State,
}

#[derive(Debug)]
enum State {
    Live(Live),
    Ended { next: usize },
}

#[derive(Debug)]
struct Live {
    idle: Idle,
    pooled: usize,
    subscribed: Option<usize>,
}

impl Live {
    fn has_connection(&self) -> bool {
        self.pooled != 0 || self.subscribed.is_some()
    }

    fn leave(&mut self) -> Result<(), InvariantError> {
        self.pooled = self.pooled.checked_sub(1).ok_or(InvariantError)?;
        Ok(())
    }
}

/// A lost connection to retire now: every request of it is settled, and the
/// server drops what it stored for it once the adapter sends the retire
/// request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct Retire {
    pub connection_id: u64,
}

#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub enum Take<'a, C> {
    /// The adapter gives the connection back once the request has ended and
    /// nothing the request wrote is still owed a reply on it.
    Idle(Open<'a, C>),
    Next(Next),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum DialFailed {
    /// The session lives on, or it had already ended, which the next take
    /// returns.
    TakeAgain,
    /// The adapter closes the connections left in the storage
    /// ([`Pool::next_to_close`]) and reports the end, and the request takes the
    /// reconnect path.
    SessionEnds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Joined {
    Added(Place),
    /// Nothing changed, and the adapter tries again once memory is freed.
    NoRoom,
    Ended,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Loss {
    /// Nothing more: its loss was already handled, or the session had already
    /// ended.
    Handled,
    SessionEnds,
    Left {
        remaining: Remaining,
    },
    SubscriptionEnded {
        remaining: Remaining,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remaining {
    /// Nothing now. When the request in flight on it is settled and its
    /// connection given back, the pool returns whether to retire it.
    Nothing,
    /// The forgets written on it since its last reply are to be settled: the
    /// adapter asks about each and then reports [`Pool::forgets_settled`].
    Forgets,
    Retire(Retire),
}

#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub enum Subscription<'a, C> {
    Held(Open<'a, C>),
    /// None yet. The connection with the subscription on it died: the adapter
    /// reports its loss ([`Pool::lost`]), which ends that subscription, and
    /// then takes a connection for a new one.
    Dead(Open<'a, C>),
    /// None yet. No connection has the subscription: the adapter takes a
    /// connection ([`Pool::take`]) and installs it ([`Pool::install`]).
    Vacant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Install {
    Installed,
    /// It is not: another connection has the subscription, or this one no
    /// longer lives. The adapter gives it back and looks again.
    Again,
    Ended,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Unsubscribed {
    Returned,
    Leaving,
    /// Nothing changed: the subscription is on another connection or on
    /// none, or the session ended.
    Unchanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    GaveBack,
    Departed,
}

impl<C, S> Pool<C, S>
where
    C: Deref,
    C::Target: Pooled,
    S: Cells<C>,
{
    pub fn first(storage: S, id: u64, connection: C) -> Result<(Self, Place), AllocationRefused> {
        let mut storage = Storage::new(storage);
        let idle = Role::Idle {
            above: None,
            below: None,
        };
        let place = storage
            .put(id, connection, idle)
            .map_err(|_| AllocationRefused)?;
        let live = Live {
            idle: Idle::only(place.index),
            pooled: 1,
            subscribed: None,
        };
        let pool = Self {
            storage,
            state: State::Live(live),
        };
        Ok((pool, place))
    }

    #[must_use]
    pub fn is_ended(&self) -> bool {
        matches!(self.state, State::Ended { .. })
    }

    /// How many connections the pool has: idle, busy and resting ones, and
    /// none once the session ended. The subscribed connection is not one of
    /// them.
    #[must_use]
    pub fn connections(&self) -> usize {
        match &self.state {
            State::Live(live) => live.pooled,
            State::Ended { .. } => 0,
        }
    }

    #[must_use]
    pub fn subscribed(&self) -> Option<Open<'_, C>> {
        let State::Live(live) = &self.state else {
            return None;
        };
        self.storage.open(live.subscribed?)
    }

    /// A subscription is used only while its connection lives. One whose
    /// connection died is given up: reporting that loss ends it.
    pub fn subscription(&self) -> Subscription<'_, C> {
        match self.subscribed() {
            None => Subscription::Vacant,
            Some(open) if open.connection.lives() => Subscription::Held(open),
            Some(open) => Subscription::Dead(open),
        }
    }

    /// An idle connection is taken while one is. Otherwise the request dials
    /// or waits as its dials so far call for ([`Taking`]).
    pub fn take(&mut self, taking: &Taking, now: Instant) -> Result<Take<'_, C>, InvariantError> {
        let State::Live(live) = &mut self.state else {
            return Ok(Take::Next(Next::Ended));
        };
        let Some(index) = live.idle.pop(&mut self.storage)? else {
            return Ok(Take::Next(taking.next(live.pooled, now)));
        };
        let open = self.storage.open(index).ok_or(InvariantError)?;
        Ok(Take::Idle(open))
    }

    /// A refused join ends the session ([`Failure::join`]). A dial that could
    /// not reach the server leaves it in place while the pool has a
    /// connection, and the request then waits for one of them. While only the
    /// subscribed connection is left, the request dials again after the next
    /// delay of the stall schedule the reconnect path uses. With no connection
    /// left, the session ends. After a session has ended, the request takes
    /// again.
    pub fn dial_failed(
        &mut self,
        taking: &mut Taking,
        failure: Failure,
        now: Instant,
        seed: u64,
    ) -> DialFailed {
        let State::Live(live) = &self.state else {
            return DialFailed::TakeAgain;
        };
        match failure.join() {
            Join::Unreachable if live.pooled != 0 => {
                taking.wait_for_the_pool();
                return DialFailed::TakeAgain;
            }
            Join::Unreachable if live.has_connection() => {
                taking.space(now, seed);
                return DialFailed::TakeAgain;
            }
            Join::Unreachable | Join::Refused => {}
        }
        self.stop();
        DialFailed::SessionEnds
    }

    pub fn join(&mut self, id: u64, connection: C) -> Result<Joined, InvariantError> {
        let State::Live(live) = &mut self.state else {
            return Ok(Joined::Ended);
        };
        match self.storage.put(id, connection, Role::Busy) {
            Ok(place) => {
                live.pooled += 1;
                Ok(Joined::Added(place))
            }
            Err(Unplaced::Refused) => Ok(Joined::NoRoom),
            Err(Unplaced::Broken) => Err(InvariantError),
        }
    }

    /// A living busy connection of a session that lives becomes idle. One
    /// that no longer lives rests until its loss is reported. One whose loss
    /// was already handled, while this request was being settled, is retired
    /// now when nothing else of it is still being settled. A connection that
    /// is not busy is left as it is.
    pub fn give_back(&mut self, place: Place) -> Result<Option<Retire>, InvariantError> {
        self.ended(place, Ended::GaveBack)
    }

    /// A request written to the connection may still be in transmission or
    /// owed its reply, so a busy connection rests until its loss is reported.
    /// One whose loss was already handled counts its request as settled, and
    /// it is retired now when nothing else of it is still being settled.
    pub fn departed(&mut self, place: Place) -> Result<Option<Retire>, InvariantError> {
        self.ended(place, Ended::Departed)
    }

    /// The connection leaves the pool. When it was the last connection of the
    /// session, the subscribed one included, the session ended, and its
    /// forgets are moot. Otherwise its forgets are settled, and once they and
    /// the request its caller is settling are, it is retired, unless no
    /// request was ever written to it: then the server stores nothing of it.
    pub fn lost(&mut self, place: Place, forgets: usize) -> Result<Loss, InvariantError> {
        let State::Live(live) = &mut self.state else {
            return Ok(Loss::Handled);
        };
        let Some(index) = self.storage.index(place) else {
            return Ok(Loss::Handled);
        };
        let (id, role, carried) = match self.storage.content(index) {
            Some(Content::Open {
                id,
                role,
                connection,
                ..
            }) => (*id, *role, connection.carried()),
            // Being settled: its loss was handled.
            _ => return Ok(Loss::Handled),
        };
        match role {
            Role::Idle { above, below } => {
                live.idle.unlink(&mut self.storage, index, above, below)?;
                live.leave()?;
            }
            Role::Busy | Role::Resting => live.leave()?,
            Role::Subscribed => live.subscribed = None,
            Role::Leaving => {}
        }
        if !live.has_connection() {
            self.storage.vacate(index)?;
            self.stop();
            return Ok(Loss::SessionEnds);
        }
        let outstanding = Outstanding::of(role, forgets).filter(|_| carried);
        match outstanding {
            Some(outstanding) => {
                *self.storage.content_mut(index).ok_or(InvariantError)? = Content::Settling {
                    id,
                    stamp: place.stamp,
                    outstanding,
                };
            }
            None => self.storage.vacate(index)?,
        }
        let remaining = if forgets != 0 {
            Remaining::Forgets
        } else if carried && outstanding.is_none() {
            Remaining::Retire(Retire { connection_id: id })
        } else {
            Remaining::Nothing
        };
        Ok(if role == Role::Subscribed {
            Loss::SubscriptionEnded { remaining }
        } else {
            Loss::Left { remaining }
        })
    }

    pub fn forgets_settled(&mut self, place: Place) -> Result<Option<Retire>, InvariantError> {
        if self.is_ended() {
            return Ok(None);
        }
        self.settled(place, Outstanding::Forgets)
    }

    /// Whether something of the lost connection at `place` is still
    /// outstanding while the session lives: the request that was in flight
    /// on it, or the forgets written on it. Once nothing is, the report that
    /// settled the last of it returned the [`Retire`] of the connection,
    /// unless no request was ever written to it.
    #[must_use]
    pub fn settling(&self, place: Place) -> bool {
        !self.is_ended()
            && self.storage.index(place).is_some_and(|index| {
                matches!(self.storage.content(index), Some(Content::Settling { .. }))
            })
    }

    /// When the session ended, the replay decision of an ended session
    /// stands. While it lives, [`replay::settle`] sets whether the request is
    /// sent again or asked about.
    pub fn after_loss(&self, opcode: Opcode) -> AfterLoss {
        if self.is_ended() {
            return AfterLoss::Settled(Unasked::Ended);
        }
        match replay::settle(opcode) {
            Settle::Resend => AfterLoss::Settled(Unasked::Again),
            Settle::Ask => AfterLoss::Ask,
        }
    }

    /// It is installed only while it is busy, it lives and no other
    /// connection has the subscription, and it leaves the pool then.
    pub fn install(&mut self, place: Place) -> Result<Install, InvariantError> {
        let State::Live(live) = &mut self.state else {
            return Ok(Install::Ended);
        };
        if live.subscribed.is_some() {
            return Ok(Install::Again);
        }
        let Some(index) = self.storage.index(place) else {
            return Ok(Install::Again);
        };
        let Some(Content::Open {
            role, connection, ..
        }) = self.storage.content_mut(index)
        else {
            return Ok(Install::Again);
        };
        if *role != Role::Busy || !connection.lives() {
            return Ok(Install::Again);
        }
        *role = Role::Subscribed;
        live.leave()?;
        live.subscribed = Some(index);
        Ok(Install::Installed)
    }

    pub fn unsubscribed(&mut self, place: Place) -> Result<Unsubscribed, InvariantError> {
        let State::Live(live) = &mut self.state else {
            return Ok(Unsubscribed::Unchanged);
        };
        let Some(index) = self.storage.index(place) else {
            return Ok(Unsubscribed::Unchanged);
        };
        if live.subscribed != Some(index) {
            return Ok(Unsubscribed::Unchanged);
        }
        live.subscribed = None;
        let Some(Content::Open {
            role, connection, ..
        }) = self.storage.content_mut(index)
        else {
            return Err(InvariantError);
        };
        if !connection.lives() {
            *role = Role::Leaving;
            return Ok(Unsubscribed::Leaving);
        }
        live.pooled += 1;
        live.idle.push(&mut self.storage, index)?;
        Ok(Unsubscribed::Returned)
    }

    pub fn end(&mut self) {
        if !self.is_ended() {
            self.stop();
        }
    }

    /// Once the session ended, the next open connection left in the storage,
    /// the subscribed one included, for the adapter to close. Each is handed
    /// over once.
    #[must_use]
    pub fn next_to_close(&mut self) -> Option<C> {
        let State::Ended { next } = &mut self.state else {
            return None;
        };
        self.storage.take_open(next)
    }

    fn stop(&mut self) {
        self.state = State::Ended { next: 0 };
    }

    fn ended(&mut self, place: Place, ended: Ended) -> Result<Option<Retire>, InvariantError> {
        let State::Live(live) = &mut self.state else {
            return Ok(None);
        };
        let Some(index) = self.storage.index(place) else {
            return Ok(None);
        };
        match self.storage.content_mut(index) {
            Some(Content::Settling { .. }) => return self.settled(place, Outstanding::Request),
            Some(Content::Open {
                role: role @ Role::Busy,
                connection,
                ..
            }) => {
                if ended == Ended::Departed || !connection.lives() {
                    *role = Role::Resting;
                    return Ok(None);
                }
            }
            _ => return Ok(None),
        }
        live.idle.push(&mut self.storage, index)?;
        Ok(None)
    }

    fn settled(
        &mut self,
        place: Place,
        settled: Outstanding,
    ) -> Result<Option<Retire>, InvariantError> {
        let Some(index) = self.storage.index(place) else {
            return Ok(None);
        };
        let Some(Content::Settling {
            id, outstanding, ..
        }) = self.storage.content_mut(index)
        else {
            return Ok(None);
        };
        let id = *id;
        match outstanding.without(settled) {
            Some(left) => {
                *outstanding = left;
                Ok(None)
            }
            None => {
                self.storage.vacate(index)?;
                Ok(Some(Retire { connection_id: id }))
            }
        }
    }
}

#[cfg(test)]
mod tests;
