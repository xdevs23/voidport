use super::*;

use std::boxed::Box;
use std::vec::Vec;

use crate::backoff::{Backoff, Schedule};
use crate::handshake::Refusal;

#[derive(Debug, PartialEq, Eq)]
struct Link {
    name: &'static str,
    died: core::cell::Cell<bool>,
    carried: core::cell::Cell<bool>,
}

impl Pooled for Link {
    fn lives(&self) -> bool {
        !self.died.get()
    }

    fn carried(&self) -> bool {
        self.carried.get()
    }
}

fn link(name: &'static str) -> &'static Link {
    Box::leak(Box::new(Link {
        name,
        died: core::cell::Cell::new(false),
        carried: core::cell::Cell::new(true),
    }))
}

#[derive(Debug)]
struct Limited {
    cells: Vec<Cell<&'static Link>>,
    limit: usize,
}

impl Cells<&'static Link> for Limited {
    fn cells(&self) -> &[Cell<&'static Link>] {
        &self.cells
    }

    fn cells_mut(&mut self) -> &mut [Cell<&'static Link>] {
        &mut self.cells
    }

    fn grow(&mut self, len: usize) -> Result<(), AllocationRefused> {
        if len > self.limit {
            return Err(AllocationRefused);
        }
        self.cells.resize_with(len, Cell::vacant);
        Ok(())
    }
}

type TestPool = Pool<&'static Link, Limited>;

const NOW: Instant = Instant::from_nanos(1_000_000_000);

const SEED: u64 = 0x5EED;

fn limited(limit: usize) -> Limited {
    Limited {
        cells: Vec::new(),
        limit,
    }
}

fn opened(limit: usize) -> (TestPool, Place, &'static Link) {
    let one = link("one");
    let (pool, place) = Pool::first(limited(limit), 1, one).expect("room for the first connection");
    (pool, place, one)
}

fn only_subscribed_left() -> (TestPool, Place, &'static Link) {
    let (mut pool, _, _) = opened(8);
    let (two, subscription) = subscribed(&mut pool, 2, "subscribed");
    let (one, _) = take_idle(&mut pool);
    assert_eq!(lost(&mut pool, one, 0), left(Remaining::Nothing));
    assert_eq!(pool.connections(), 0);
    (pool, two, subscription)
}

fn first_dial_failed(pool: &mut TestPool, now: Instant) -> Taking {
    let mut taking = Taking::default();
    assert_eq!(next(pool, &taking, now), Next::Dial);
    assert_eq!(
        pool.dial_failed(&mut taking, Failure::Transport, now, SEED),
        DialFailed::TakeAgain
    );
    taking
}

fn joined(pool: &mut TestPool, id: u64, name: &'static str) -> (Place, &'static Link) {
    let connection = link(name);
    match pool.join(id, connection) {
        Ok(Joined::Added(place)) => (place, connection),
        other => panic!("{name} joins, not {other:?}"),
    }
}

fn idle(pool: &mut TestPool, id: u64, name: &'static str) -> (Place, &'static Link) {
    let (place, connection) = joined(pool, id, name);
    assert_eq!(given_back(pool, place), None);
    (place, connection)
}

fn subscribed(pool: &mut TestPool, id: u64, name: &'static str) -> (Place, &'static Link) {
    let (place, connection) = joined(pool, id, name);
    assert_eq!(installed(pool, place), Install::Installed);
    (place, connection)
}

fn take_idle(pool: &mut TestPool) -> (Place, &'static str) {
    match pool.take(&Taking::default(), NOW) {
        Ok(Take::Idle(open)) => (open.place, open.connection.name),
        other => panic!("an idle connection, not {other:?}"),
    }
}

fn next(pool: &mut TestPool, taking: &Taking, now: Instant) -> Next {
    match pool.take(taking, now) {
        Ok(Take::Next(next)) => next,
        other => panic!("no idle connection, not {other:?}"),
    }
}

fn fresh(pool: &mut TestPool) -> Next {
    next(pool, &Taking::default(), NOW)
}

fn given_back(pool: &mut TestPool, place: Place) -> Option<Retire> {
    pool.give_back(place).expect("a consistent pool")
}

fn departed(pool: &mut TestPool, place: Place) -> Option<Retire> {
    pool.departed(place).expect("a consistent pool")
}

fn lost(pool: &mut TestPool, place: Place, forgets: usize) -> Loss {
    pool.lost(place, forgets).expect("a consistent pool")
}

fn forgets_settled(pool: &mut TestPool, place: Place) -> Option<Retire> {
    pool.forgets_settled(place).expect("a consistent pool")
}

fn installed(pool: &mut TestPool, place: Place) -> Install {
    pool.install(place).expect("a consistent pool")
}

fn unsubscribed(pool: &mut TestPool, place: Place) -> Unsubscribed {
    pool.unsubscribed(place).expect("a consistent pool")
}

fn left(remaining: Remaining) -> Loss {
    Loss::Left { remaining }
}

fn retired_now(connection_id: u64) -> Loss {
    left(Remaining::Retire(Retire { connection_id }))
}

fn open<'a>(place: Place, connection: &'a &'static Link) -> Open<'a, &'static Link> {
    Open { place, connection }
}

fn ended(pool: &mut TestPool) -> Vec<&'static str> {
    pool.end();
    let mut closed = Vec::new();
    while let Some(connection) = pool.next_to_close() {
        closed.push(connection.name);
    }
    closed.sort_unstable();
    closed
}

#[test]
fn a_pool_whose_storage_refuses_its_first_connection_is_not_opened() {
    assert!(matches!(
        Pool::first(limited(0), 1, link("one")),
        Err(AllocationRefused)
    ));
}

#[test]
fn the_first_connection_is_idle_and_the_one_given_back_last_is_taken_first() {
    let (mut pool, one, _) = opened(8);
    let (two, _) = idle(&mut pool, 2, "two");
    let (three, _) = idle(&mut pool, 3, "three");
    assert_eq!(pool.connections(), 3);
    assert_eq!(take_idle(&mut pool), (three, "three"));
    assert_eq!(take_idle(&mut pool), (two, "two"));
    assert_eq!(take_idle(&mut pool), (one, "one"));
    assert_eq!(pool.connections(), 3, "busy connections are in the pool");
    assert_eq!(fresh(&mut pool), Next::Dial);
}

#[test]
fn a_request_with_no_idle_connection_dials_and_after_a_failed_dial_waits_for_one() {
    let (mut pool, one, first) = opened(8);
    assert_eq!(take_idle(&mut pool), (one, "one"));
    let taking = first_dial_failed(&mut pool, NOW);
    assert_eq!(
        next(&mut pool, &taking, NOW),
        Next::Wait,
        "it waits for a connection of the pool and dials nothing"
    );
    assert_eq!(given_back(&mut pool, one), None);
    assert_eq!(pool.take(&taking, NOW), Ok(Take::Idle(open(one, &first))));
}

#[test]
fn a_refused_join_ends_the_session_at_once_whatever_the_pool_has() {
    for failure in [
        Failure::Refused(Refusal::Other),
        Failure::Refused(Refusal::Unavailable),
        Failure::InvalidHandshake,
        Failure::Local,
    ] {
        let (mut pool, one, _) = opened(8);
        subscribed(&mut pool, 2, "subscribed");
        assert_eq!(take_idle(&mut pool), (one, "one"));
        let mut taking = Taking::default();
        assert_eq!(next(&mut pool, &taking, NOW), Next::Dial);
        assert_eq!(
            pool.dial_failed(&mut taking, failure, NOW, SEED),
            DialFailed::SessionEnds,
            "{failure:?}"
        );
        assert!(pool.is_ended(), "{failure:?}");
        assert_eq!(fresh(&mut pool), Next::Ended);
        assert_eq!(pool.join(3, link("three")), Ok(Joined::Ended));
        assert_eq!(pool.subscription(), Subscription::Vacant);
        assert_eq!(pool.connections(), 0);
        assert_eq!(
            ended(&mut pool),
            Vec::from(["one", "subscribed"]),
            "closing hands over every open connection"
        );
    }
}

#[test]
fn a_failed_dial_with_only_the_subscription_left_dials_again_after_each_stall_delay() {
    let (mut pool, _, _) = only_subscribed_left();
    let mut schedule = Backoff::seeded(SEED);
    let mut taking = Taking::default();
    let mut now = NOW;
    assert_eq!(next(&mut pool, &taking, now), Next::Dial);
    for failed in 1..=3 {
        let seed = SEED + failed - 1;
        assert_eq!(
            pool.dial_failed(&mut taking, Failure::Transport, now, seed),
            DialFailed::TakeAgain,
            "the subscribed connection keeps the session open"
        );
        let at = now.saturating_add(schedule.next(Schedule::Stalling));
        assert_eq!(
            next(&mut pool, &taking, now),
            Next::WaitUntil(at),
            "dial {failed}"
        );
        let before = Instant::from_nanos(at.as_nanos() - 1);
        assert_eq!(next(&mut pool, &taking, before), Next::WaitUntil(at));
        assert_eq!(next(&mut pool, &taking, at), Next::Dial, "dial {failed}");
        now = at;
    }
}

#[test]
fn a_waiting_request_whose_pool_loses_its_last_connection_dials_at_once() {
    let (mut pool, _, _) = opened(8);
    subscribed(&mut pool, 2, "subscribed");
    let (one, _) = take_idle(&mut pool);
    let taking = first_dial_failed(&mut pool, NOW);
    assert_eq!(next(&mut pool, &taking, NOW), Next::Wait);
    assert_eq!(lost(&mut pool, one, 0), left(Remaining::Nothing));
    assert_eq!(next(&mut pool, &taking, NOW), Next::Dial);
}

#[test]
fn a_connection_that_joins_and_is_lost_during_a_delay_leaves_the_delay_unchanged() {
    let (mut pool, _, _) = only_subscribed_left();
    let taking = first_dial_failed(&mut pool, NOW);
    let Next::WaitUntil(at) = next(&mut pool, &taking, NOW) else {
        panic!("a delay before the next dial");
    };
    assert_eq!(fresh(&mut pool), Next::Dial);
    let (three, _) = joined(&mut pool, 3, "three");
    assert_eq!(
        next(&mut pool, &taking, NOW),
        Next::Wait,
        "it waits for the connection of the pool"
    );
    assert_eq!(lost(&mut pool, three, 0), left(Remaining::Nothing));
    let before = Instant::from_nanos(at.as_nanos() - 1);
    assert_eq!(
        next(&mut pool, &taking, before),
        Next::WaitUntil(at),
        "the delay it had is unchanged"
    );
    assert_eq!(next(&mut pool, &taking, at), Next::Dial);
}

#[test]
fn a_dial_that_fails_while_a_connection_joined_meanwhile_ends_the_schedule() {
    let (mut pool, _, _) = only_subscribed_left();
    let mut taking = first_dial_failed(&mut pool, NOW);
    let Next::WaitUntil(at) = next(&mut pool, &taking, NOW) else {
        panic!("a delay before the next dial");
    };
    assert_eq!(next(&mut pool, &taking, at), Next::Dial, "the spaced dial");
    assert_eq!(next(&mut pool, &Taking::default(), at), Next::Dial);
    let (three, _) = joined(&mut pool, 3, "three");
    assert_eq!(
        pool.dial_failed(&mut taking, Failure::Transport, at, SEED),
        DialFailed::TakeAgain
    );
    assert_eq!(next(&mut pool, &taking, at), Next::Wait);
    assert_eq!(lost(&mut pool, three, 0), left(Remaining::Nothing));
    assert_eq!(
        next(&mut pool, &taking, at),
        Next::Dial,
        "the schedule ended while the pool had a connection"
    );
}

#[test]
fn a_failed_dial_with_no_connection_left_ends_the_session() {
    let (mut pool, two, subscription) = only_subscribed_left();
    let mut taking = Taking::default();
    assert_eq!(next(&mut pool, &taking, NOW), Next::Dial);
    subscription.died.set(true);
    assert_eq!(unsubscribed(&mut pool, two), Unsubscribed::Leaving);
    assert_eq!(
        pool.dial_failed(&mut taking, Failure::Transport, NOW, SEED),
        DialFailed::SessionEnds
    );
    assert!(pool.is_ended());
    assert_eq!(next(&mut pool, &taking, NOW), Next::Ended);
    assert_eq!(ended(&mut pool), Vec::from(["subscribed"]));
}

#[test]
fn a_dial_that_fails_after_the_session_ended_leaves_the_session_ended() {
    let (mut pool, _, _) = opened(8);
    let (one, _) = take_idle(&mut pool);
    let mut taking = Taking::default();
    assert_eq!(next(&mut pool, &taking, NOW), Next::Dial);
    assert_eq!(lost(&mut pool, one, 0), Loss::SessionEnds);
    for failure in [Failure::Transport, Failure::InvalidHandshake] {
        assert_eq!(
            pool.dial_failed(&mut taking, failure, NOW, SEED),
            DialFailed::TakeAgain,
            "the loss ended it already: {failure:?}"
        );
    }
    assert_eq!(next(&mut pool, &taking, NOW), Next::Ended);
}

#[test]
fn a_joined_connection_is_busy_and_one_that_joins_an_ended_session_is_not_added() {
    let (mut pool, _, _) = opened(8);
    take_idle(&mut pool);
    joined(&mut pool, 2, "two");
    assert_eq!(pool.connections(), 2);
    assert_eq!(fresh(&mut pool), Next::Dial, "nothing idle");
    pool.end();
    assert_eq!(pool.join(3, link("three")), Ok(Joined::Ended));
    assert_eq!(fresh(&mut pool), Next::Ended);
}

#[test]
fn a_join_the_storage_has_no_room_for_is_refused_and_a_vacated_cell_is_used_again() {
    let (mut pool, _, _) = opened(2);
    let (two, second) = joined(&mut pool, 2, "two");
    assert_eq!(pool.join(3, link("three")), Ok(Joined::NoRoom));
    assert_eq!(pool.connections(), 2, "a refused join changes nothing");
    second.carried.set(false);
    assert_eq!(lost(&mut pool, two, 0), left(Remaining::Nothing));
    let (three, _) = joined(&mut pool, 3, "three");
    assert_eq!(three.index, two.index, "the vacated cell");
    assert_eq!(pool.connections(), 2);
}

#[test]
fn every_vacated_cell_is_used_again_before_the_storage_grows() {
    let (mut pool, _, _) = opened(4);
    let (two, _) = idle(&mut pool, 2, "two");
    let (three, _) = idle(&mut pool, 3, "three");
    let (four, _) = idle(&mut pool, 4, "four");
    assert_eq!(lost(&mut pool, three, 0), retired_now(3));
    assert_eq!(lost(&mut pool, two, 0), retired_now(2));
    let (five, _) = joined(&mut pool, 5, "five");
    let (six, _) = joined(&mut pool, 6, "six");
    assert_eq!((five.index, six.index), (two.index, three.index));
    assert_eq!(pool.join(7, link("seven")), Ok(Joined::NoRoom));
    assert_eq!(lost(&mut pool, four, 0), retired_now(4));
    let (seven, _) = joined(&mut pool, 7, "seven");
    assert_eq!(seven.index, four.index);
}

#[test]
fn a_place_whose_connection_left_refers_to_no_connection_after_another_took_it() {
    let (mut pool, _, _) = opened(8);
    take_idle(&mut pool);
    let (two, _) = joined(&mut pool, 2, "two");
    assert_eq!(lost(&mut pool, two, 0), left(Remaining::Nothing));
    assert_eq!(
        given_back(&mut pool, two),
        Some(Retire { connection_id: 2 })
    );
    let (three, _) = joined(&mut pool, 3, "three");
    assert_eq!(three.index, two.index, "the same cell");
    assert_ne!(three, two);

    assert_eq!(given_back(&mut pool, two), None);
    assert_eq!(departed(&mut pool, two), None);
    assert_eq!(forgets_settled(&mut pool, two), None);
    assert_eq!(installed(&mut pool, two), Install::Again);
    assert_eq!(unsubscribed(&mut pool, two), Unsubscribed::Unchanged);
    assert_eq!(lost(&mut pool, two, 1), Loss::Handled);
    assert_eq!(
        fresh(&mut pool),
        Next::Dial,
        "the connection there now is still busy"
    );
    assert_eq!(pool.connections(), 2);
    assert_eq!(given_back(&mut pool, three), None);
    assert_eq!(take_idle(&mut pool), (three, "three"));
}

#[test]
fn a_connection_after_many_that_left_is_given_back_at_its_place() {
    let (mut pool, one, _) = opened(64);
    let left: Vec<(u64, Place)> = (2..=40)
        .map(|id| (id, idle(&mut pool, id, "left").0))
        .collect();
    let (survivor, _) = idle(&mut pool, 41, "survivor");
    for (id, place) in left {
        assert_eq!(lost(&mut pool, place, 0), retired_now(id));
    }
    assert_eq!(lost(&mut pool, one, 0), retired_now(1));
    assert_eq!(pool.connections(), 1);
    assert_eq!(take_idle(&mut pool), (survivor, "survivor"));
    assert_eq!(given_back(&mut pool, survivor), None);
    assert_eq!(take_idle(&mut pool), (survivor, "survivor"));
}

#[test]
fn connections_announced_with_the_same_id_are_told_apart() {
    let (mut pool, one, _) = opened(8);
    assert_eq!(take_idle(&mut pool), (one, "one"));
    let (twin, _) = joined(&mut pool, 1, "twin");
    assert_ne!(twin, one);

    assert_eq!(given_back(&mut pool, twin), None);
    assert_eq!(take_idle(&mut pool), (twin, "twin"));
    assert_eq!(fresh(&mut pool), Next::Dial, "one is busy");

    assert_eq!(given_back(&mut pool, twin), None);
    assert_eq!(lost(&mut pool, twin, 0), retired_now(1));
    assert_eq!(pool.connections(), 1);
    assert_eq!(given_back(&mut pool, one), None);
    assert_eq!(take_idle(&mut pool), (one, "one"));

    let (other, other_link) = idle(&mut pool, 1, "other");
    assert_eq!(take_idle(&mut pool), (other, "other"));
    assert_eq!(installed(&mut pool, other), Install::Installed);
    assert_eq!(pool.subscribed(), Some(open(other, &other_link)));
    assert_eq!(pool.connections(), 1);
    assert_eq!(given_back(&mut pool, one), None);
    assert_eq!(take_idle(&mut pool), (one, "one"));
}

#[test]
fn a_connection_being_settled_is_told_apart_from_one_with_the_same_id() {
    let (mut pool, one, _) = opened(8);
    assert_eq!(take_idle(&mut pool), (one, "one"));
    let (twin, twin_link) = joined(&mut pool, 1, "twin");
    assert_eq!(lost(&mut pool, one, 1), left(Remaining::Forgets));
    assert_eq!(
        given_back(&mut pool, twin),
        None,
        "no retire of the lost one"
    );
    assert_eq!(take_idle(&mut pool), (twin, "twin"));
    assert_eq!(installed(&mut pool, twin), Install::Installed);
    assert_eq!(
        given_back(&mut pool, one),
        None,
        "its forgets are not settled"
    );
    assert_eq!(
        forgets_settled(&mut pool, one),
        Some(Retire { connection_id: 1 })
    );
    assert_eq!(pool.subscribed(), Some(open(twin, &twin_link)));
}

#[test]
fn a_connection_given_back_dead_is_never_handed_out_again() {
    let (mut pool, one, _) = opened(8);
    let (two, second) = idle(&mut pool, 2, "two");
    assert_eq!(take_idle(&mut pool), (two, "two"));
    second.died.set(true);
    assert_eq!(given_back(&mut pool, two), None);
    assert_eq!(pool.connections(), 2, "it is in the pool until its loss");
    assert_eq!(take_idle(&mut pool), (one, "one"));
    assert_eq!(fresh(&mut pool), Next::Dial);
    assert_eq!(given_back(&mut pool, two), None, "it is not busy any more");
    assert_eq!(fresh(&mut pool), Next::Dial);
    assert_eq!(
        lost(&mut pool, two, 0),
        retired_now(2),
        "no request of it is left to settle"
    );
    assert_eq!(pool.connections(), 1);
}

#[test]
fn a_living_connection_a_request_departed_from_is_never_handed_out_again() {
    let (mut pool, one, _) = opened(8);
    let (two, _) = idle(&mut pool, 2, "two");
    assert_eq!(take_idle(&mut pool), (two, "two"));
    assert_eq!(departed(&mut pool, two), None);
    assert_eq!(pool.connections(), 2, "it is in the pool until its loss");
    assert_eq!(take_idle(&mut pool), (one, "one"));
    assert_eq!(fresh(&mut pool), Next::Dial);
    assert_eq!(given_back(&mut pool, two), None, "it is not busy any more");
    assert_eq!(fresh(&mut pool), Next::Dial);
    assert_eq!(
        lost(&mut pool, two, 0),
        retired_now(2),
        "no request of it is left to settle"
    );
    assert_eq!(departed(&mut pool, two), None);
    assert_eq!(pool.connections(), 1);
}

#[test]
fn a_lost_connection_whose_request_departs_is_retired_once_everything_of_it_is_settled() {
    let (mut pool, _, _) = opened(8);
    let (two, _) = idle(&mut pool, 2, "two");
    assert_eq!(take_idle(&mut pool), (two, "two"));
    assert_eq!(lost(&mut pool, two, 1), left(Remaining::Forgets));
    assert_eq!(departed(&mut pool, two), None);
    assert_eq!(
        forgets_settled(&mut pool, two),
        Some(Retire { connection_id: 2 })
    );
    assert_eq!(departed(&mut pool, two), None, "retired once");

    let (mut pool, _, _) = opened(8);
    let (two, _) = idle(&mut pool, 2, "two");
    assert_eq!(take_idle(&mut pool), (two, "two"));
    assert_eq!(lost(&mut pool, two, 1), left(Remaining::Forgets));
    assert_eq!(forgets_settled(&mut pool, two), None);
    assert_eq!(departed(&mut pool, two), Some(Retire { connection_id: 2 }));
    assert_eq!(forgets_settled(&mut pool, two), None, "retired once");

    let (mut pool, _, _) = opened(8);
    let (two, _) = idle(&mut pool, 2, "two");
    assert_eq!(take_idle(&mut pool), (two, "two"));
    assert_eq!(lost(&mut pool, two, 0), left(Remaining::Nothing));
    assert_eq!(departed(&mut pool, two), Some(Retire { connection_id: 2 }));
    assert_eq!(given_back(&mut pool, two), None, "retired once");
}

#[test]
fn a_connection_given_back_after_the_session_ended_goes_nowhere() {
    let (mut pool, one, _) = opened(8);
    take_idle(&mut pool);
    pool.end();
    assert_eq!(given_back(&mut pool, one), None);
    assert_eq!(departed(&mut pool, one), None);
    assert_eq!(pool.connections(), 0);
    assert_eq!(fresh(&mut pool), Next::Ended);
}

#[test]
fn a_loss_is_handled_once() {
    let (mut pool, one, _) = opened(8);
    let (two, _) = idle(&mut pool, 2, "two");
    assert_eq!(lost(&mut pool, two, 0), retired_now(2));
    assert_eq!(lost(&mut pool, two, 1), Loss::Handled);
    let unknown = Place {
        index: 9,
        stamp: cells::Stamp(0),
    };
    assert_eq!(
        lost(&mut pool, unknown, 1),
        Loss::Handled,
        "an unknown place"
    );
    pool.end();
    assert_eq!(lost(&mut pool, one, 1), Loss::Handled, "an ended session");
}

#[test]
fn losing_the_last_connection_ends_the_session_at_once() {
    let (mut pool, one, _) = opened(8);
    let (two, subscription) = subscribed(&mut pool, 2, "subscribed");
    subscription.died.set(true);
    assert_eq!(unsubscribed(&mut pool, two), Unsubscribed::Leaving);
    assert_eq!(take_idle(&mut pool), (one, "one"));
    assert_eq!(lost(&mut pool, one, 1), Loss::SessionEnds);
    assert!(pool.is_ended());
    assert_eq!(fresh(&mut pool), Next::Ended);
    assert_eq!(pool.join(3, link("three")), Ok(Joined::Ended));
    assert_eq!(pool.connections(), 0);
    assert_eq!(lost(&mut pool, one, 1), Loss::Handled);
    assert_eq!(
        ended(&mut pool),
        Vec::from(["subscribed"]),
        "the loss ended it, and closing hands over the open connection left"
    );
}

#[test]
fn losing_the_subscribed_connection_ends_its_subscription_and_the_session_lives() {
    let (mut pool, _, _) = opened(8);
    let (two, subscription) = subscribed(&mut pool, 2, "subscribed");
    assert_eq!(pool.subscribed(), Some(open(two, &subscription)));
    assert_eq!(
        lost(&mut pool, two, 0),
        Loss::SubscriptionEnded {
            remaining: Remaining::Retire(Retire { connection_id: 2 }),
        }
    );
    assert_eq!(pool.subscribed(), None);
    assert_eq!(pool.connections(), 1);
}

#[test]
fn losing_the_subscribed_connection_when_nothing_else_is_left_ends_the_session() {
    let (mut pool, two, _) = only_subscribed_left();
    assert_eq!(lost(&mut pool, two, 0), Loss::SessionEnds);
    assert!(pool.is_ended());
}

#[test]
fn a_lost_connection_no_request_was_written_to_is_never_retired() {
    let (mut pool, _, _) = opened(8);
    let (two, second) = idle(&mut pool, 2, "two");
    assert_eq!(take_idle(&mut pool), (two, "two"));
    second.carried.set(false);
    assert_eq!(
        lost(&mut pool, two, 1),
        left(Remaining::Forgets),
        "its forgets are still settled"
    );
    assert_eq!(given_back(&mut pool, two), None);
    assert_eq!(forgets_settled(&mut pool, two), None);
}

#[test]
fn a_lost_busy_connection_is_retired_once_its_request_is_given_back() {
    let (mut pool, _, _) = opened(8);
    let (two, _) = idle(&mut pool, 2, "two");
    assert_eq!(take_idle(&mut pool), (two, "two"));
    assert_eq!(lost(&mut pool, two, 0), left(Remaining::Nothing));
    assert_eq!(pool.connections(), 1, "it left the pool");
    assert_eq!(
        given_back(&mut pool, two),
        Some(Retire { connection_id: 2 })
    );
    assert_eq!(given_back(&mut pool, two), None, "retired once");
}

#[test]
fn a_lost_connection_is_settling_until_everything_of_it_is_settled() {
    let (mut pool, one, _) = opened(8);
    let (two, _) = idle(&mut pool, 2, "two");
    assert!(!pool.settling(one), "an open connection is not settling");
    assert_eq!(take_idle(&mut pool), (two, "two"));
    assert_eq!(lost(&mut pool, two, 1), left(Remaining::Forgets));
    assert!(pool.settling(two));
    assert_eq!(forgets_settled(&mut pool, two), None);
    assert!(pool.settling(two), "its request is still outstanding");
    assert_eq!(
        given_back(&mut pool, two),
        Some(Retire { connection_id: 2 })
    );
    assert!(!pool.settling(two), "retired");

    let (three, connection) = idle(&mut pool, 3, "three");
    connection.carried.set(false);
    assert_eq!(lost(&mut pool, three, 0), left(Remaining::Nothing));
    assert!(!pool.settling(three));

    let (four, _) = idle(&mut pool, 4, "four");
    assert_eq!(take_idle(&mut pool), (four, "four"));
    assert_eq!(lost(&mut pool, four, 0), left(Remaining::Nothing));
    pool.end();
    assert!(!pool.settling(four));
}

#[test]
fn a_lost_connection_is_retired_once_its_request_and_its_forgets_are_settled() {
    let (mut pool, _, _) = opened(8);
    let (two, _) = idle(&mut pool, 2, "two");
    assert_eq!(take_idle(&mut pool), (two, "two"));
    assert_eq!(lost(&mut pool, two, 2), left(Remaining::Forgets));
    assert_eq!(given_back(&mut pool, two), None);
    assert_eq!(
        forgets_settled(&mut pool, two),
        Some(Retire { connection_id: 2 })
    );
    assert_eq!(given_back(&mut pool, two), None, "retired once");

    let (mut pool, _, _) = opened(8);
    let (two, _) = idle(&mut pool, 2, "two");
    assert_eq!(take_idle(&mut pool), (two, "two"));
    assert_eq!(lost(&mut pool, two, 2), left(Remaining::Forgets));
    assert_eq!(forgets_settled(&mut pool, two), None);
    assert_eq!(
        given_back(&mut pool, two),
        Some(Retire { connection_id: 2 })
    );
    assert_eq!(forgets_settled(&mut pool, two), None, "retired once");
}

#[test]
fn a_lost_idle_connection_is_retired_at_once_or_once_its_forgets_are_settled() {
    let (mut pool, _, _) = opened(8);
    let (two, _) = idle(&mut pool, 2, "two");
    let (three, _) = idle(&mut pool, 3, "three");
    assert_eq!(lost(&mut pool, two, 0), retired_now(2));
    assert_eq!(lost(&mut pool, three, 1), left(Remaining::Forgets));
    assert_eq!(
        forgets_settled(&mut pool, three),
        Some(Retire { connection_id: 3 })
    );
}

#[test]
fn nothing_is_retired_after_the_session_ended() {
    let (mut pool, _, _) = opened(8);
    let (two, _) = idle(&mut pool, 2, "two");
    assert_eq!(take_idle(&mut pool), (two, "two"));
    assert_eq!(lost(&mut pool, two, 1), left(Remaining::Forgets));
    assert_eq!(
        ended(&mut pool),
        Vec::from(["one"]),
        "a lost connection is not closed again"
    );
    assert_eq!(given_back(&mut pool, two), None);
    assert_eq!(departed(&mut pool, two), None);
    assert_eq!(forgets_settled(&mut pool, two), None);
}

#[test]
fn nothing_is_retired_once_a_loss_ended_the_session() {
    let (mut pool, one, _) = opened(8);
    let (two, _) = subscribed(&mut pool, 2, "subscribed");
    assert_eq!(take_idle(&mut pool), (one, "one"));
    assert_eq!(lost(&mut pool, one, 1), left(Remaining::Forgets));
    assert_eq!(lost(&mut pool, two, 0), Loss::SessionEnds);
    assert_eq!(
        given_back(&mut pool, one),
        None,
        "before the adapter closes"
    );
    assert_eq!(departed(&mut pool, one), None);
    assert_eq!(forgets_settled(&mut pool, one), None);
}

#[test]
fn a_lost_idle_connection_leaves_the_idle_ones_in_their_order() {
    let (mut pool, one, first) = opened(8);
    let (two, _) = idle(&mut pool, 2, "two");
    let (three, third) = idle(&mut pool, 3, "three");
    let (four, _) = idle(&mut pool, 4, "four");
    let (five, fifth) = idle(&mut pool, 5, "five");
    third.carried.set(false);
    first.carried.set(false);
    fifth.carried.set(false);
    assert_eq!(lost(&mut pool, three, 0), left(Remaining::Nothing));
    assert_eq!(lost(&mut pool, one, 0), left(Remaining::Nothing));
    assert_eq!(lost(&mut pool, five, 0), left(Remaining::Nothing));
    assert_eq!(take_idle(&mut pool), (four, "four"));
    assert_eq!(take_idle(&mut pool), (two, "two"));
    assert_eq!(fresh(&mut pool), Next::Dial);
    assert_eq!(pool.connections(), 2);
    assert_eq!(given_back(&mut pool, four), None);
    assert_eq!(given_back(&mut pool, two), None);
    assert_eq!(take_idle(&mut pool), (two, "two"));
    assert_eq!(take_idle(&mut pool), (four, "four"));
}

#[test]
fn a_broken_record_of_the_pool_is_reported() {
    let (mut pool, _, _) = opened(8);
    let State::Live(live) = &mut pool.state else {
        panic!("a live session");
    };
    live.idle = Idle::only(5);
    assert_eq!(pool.take(&Taking::default(), NOW), Err(InvariantError));

    let (mut pool, one, _) = opened(8);
    take_idle(&mut pool);
    let State::Live(live) = &mut pool.state else {
        panic!("a live session");
    };
    live.pooled = 0;
    assert_eq!(pool.lost(one, 0), Err(InvariantError));
}

#[test]
fn a_subscription_is_used_only_while_its_connection_lives() {
    let (mut pool, _, _) = opened(8);
    assert_eq!(pool.subscription(), Subscription::Vacant);
    let (two, subscription) = subscribed(&mut pool, 2, "subscribed");
    assert_eq!(
        pool.subscription(),
        Subscription::Held(open(two, &subscription))
    );
    subscription.died.set(true);
    assert_eq!(
        pool.subscription(),
        Subscription::Dead(open(two, &subscription)),
        "its death is recorded"
    );
    assert_eq!(
        lost(&mut pool, two, 0),
        Loss::SubscriptionEnded {
            remaining: Remaining::Retire(Retire { connection_id: 2 }),
        },
        "reporting the loss ends the subscription"
    );
    assert_eq!(pool.subscription(), Subscription::Vacant);

    subscribed(&mut pool, 3, "again");
    pool.end();
    assert_eq!(
        pool.subscription(),
        Subscription::Vacant,
        "an ended session has no subscription"
    );
}

#[test]
fn a_connection_taken_for_the_subscription_is_installed_only_while_it_lives() {
    let (mut pool, one, _) = opened(8);
    let (two, second) = idle(&mut pool, 2, "two");

    assert_eq!(take_idle(&mut pool), (two, "two"));
    second.died.set(true);
    assert_eq!(
        installed(&mut pool, two),
        Install::Again,
        "its death is recorded"
    );
    assert_eq!(given_back(&mut pool, two), None);

    assert_eq!(take_idle(&mut pool), (one, "one"));
    assert_eq!(lost(&mut pool, one, 0), left(Remaining::Nothing));
    assert_eq!(
        installed(&mut pool, one),
        Install::Again,
        "its loss was handled"
    );
    assert_eq!(
        given_back(&mut pool, one),
        Some(Retire { connection_id: 1 })
    );

    let (three, third) = joined(&mut pool, 3, "three");
    assert_eq!(installed(&mut pool, three), Install::Installed);
    assert_eq!(pool.subscribed(), Some(open(three, &third)));
    assert_eq!(pool.connections(), 1, "it left the pool");

    let (four, _) = joined(&mut pool, 4, "four");
    assert_eq!(
        installed(&mut pool, four),
        Install::Again,
        "another connection has the subscription"
    );
    assert_eq!(given_back(&mut pool, four), None);
    assert_eq!(
        take_idle(&mut pool),
        (four, "four"),
        "it went back to the pool"
    );

    pool.end();
    assert_eq!(installed(&mut pool, four), Install::Ended);
}

#[test]
fn a_connection_that_is_not_busy_is_never_installed() {
    let (mut pool, one, _) = opened(8);
    assert_eq!(installed(&mut pool, one), Install::Again, "an idle one");
    let unknown = Place {
        index: 9,
        stamp: cells::Stamp(0),
    };
    assert_eq!(
        installed(&mut pool, unknown),
        Install::Again,
        "an unknown one"
    );
    assert_eq!(take_idle(&mut pool), (one, "one"));
}

#[test]
fn an_ended_subscription_gives_a_living_connection_back_to_the_pool() {
    let (mut pool, one, _) = opened(8);
    assert_eq!(
        unsubscribed(&mut pool, one),
        Unsubscribed::Unchanged,
        "nothing was subscribed"
    );
    let (two, _) = subscribed(&mut pool, 2, "subscribed");
    take_idle(&mut pool);
    assert_eq!(unsubscribed(&mut pool, two), Unsubscribed::Returned);
    assert_eq!(pool.subscribed(), None);
    assert_eq!(pool.connections(), 2);
    assert_eq!(take_idle(&mut pool), (two, "subscribed"));
}

#[test]
fn an_ended_subscription_leaves_a_subscription_installed_since_in_place() {
    let (mut pool, _, _) = opened(8);
    let (two, _) = subscribed(&mut pool, 2, "subscribed");
    assert_eq!(
        lost(&mut pool, two, 0),
        Loss::SubscriptionEnded {
            remaining: Remaining::Retire(Retire { connection_id: 2 }),
        }
    );
    let (three, again) = subscribed(&mut pool, 3, "again");
    assert_eq!(unsubscribed(&mut pool, two), Unsubscribed::Unchanged);
    assert_eq!(pool.subscribed(), Some(open(three, &again)));
}

#[test]
fn an_ended_subscription_whose_connection_died_leaves_it_out_of_the_pool() {
    let (mut pool, _, _) = opened(8);
    let (two, subscription) = subscribed(&mut pool, 2, "subscribed");
    subscription.died.set(true);
    assert_eq!(unsubscribed(&mut pool, two), Unsubscribed::Leaving);
    assert_eq!(pool.subscribed(), None);
    assert_eq!(pool.connections(), 1);
    take_idle(&mut pool);
    assert_eq!(fresh(&mut pool), Next::Dial);
    assert_eq!(lost(&mut pool, two, 0), retired_now(2));

    let (mut pool, two, subscription) = only_subscribed_left();
    subscription.died.set(true);
    assert_eq!(unsubscribed(&mut pool, two), Unsubscribed::Leaving);
    assert_eq!(lost(&mut pool, two, 0), Loss::SessionEnds);
}

#[test]
fn ending_the_session_hands_every_open_connection_over_once() {
    let (mut pool, _, _) = opened(8);
    idle(&mut pool, 2, "idle");
    let (subscribed_at, _) = subscribed(&mut pool, 3, "subscribed");
    joined(&mut pool, 4, "busy");
    let (resting, rested) = joined(&mut pool, 5, "resting");
    rested.died.set(true);
    assert_eq!(given_back(&mut pool, resting), None);
    let (settling, _) = joined(&mut pool, 6, "settling");
    assert_eq!(lost(&mut pool, settling, 0), left(Remaining::Nothing));
    assert_eq!(
        pool.next_to_close(),
        None,
        "nothing while the session lives"
    );
    assert_eq!(
        ended(&mut pool),
        Vec::from(["busy", "idle", "one", "resting", "subscribed"])
    );
    assert!(pool.is_ended());
    assert_eq!(pool.connections(), 0);
    assert_eq!(pool.subscribed(), None);
    pool.end();
    assert_eq!(pool.next_to_close(), None, "each is handed over once");
    assert_eq!(
        unsubscribed(&mut pool, subscribed_at),
        Unsubscribed::Unchanged
    );
}

#[test]
fn a_request_of_a_lost_connection_is_asked_about_or_settled_by_the_session() {
    let (mut pool, _, _) = opened(8);
    for opcode in Opcode::ALL {
        let expected = match replay::settle(opcode) {
            Settle::Resend => AfterLoss::Settled(Unasked::Again),
            Settle::Ask => AfterLoss::Ask,
        };
        assert_eq!(pool.after_loss(opcode), expected, "{opcode}");
    }
    pool.end();
    for opcode in Opcode::ALL {
        assert_eq!(
            pool.after_loss(opcode),
            AfterLoss::Settled(Unasked::Ended),
            "{opcode}"
        );
    }
}
