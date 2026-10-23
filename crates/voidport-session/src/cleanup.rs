//! A reply that resolves a name admits a lookup of a node on the server, and a
//! reply to an open admits a handle. The server counts both per session and
//! drops every reference of a session when that session ends. Once the client
//! retires a reference, it owes the server a FORGET or a RELEASE, sent within
//! the session that admitted the reference
//! ([`Machine::serving`](crate::reconnect::Machine::serving)).

use core::time::Duration;

use crate::time::{DeadlineVerdict, Instant, deadline_verdict};

/// A refused attempt leaves the references owed, and only the passing of time
/// makes the next attempt more likely to succeed. The delay sets how soon the
/// next attempt starts. It does not limit how many attempts there are.
pub const RETRY_DELAY: Duration = Duration::from_millis(100);

/// The server drops every reference of a session when the session ends, so
/// what a lasting session admitted is owed to the server, and what an ended
/// session admitted is owed to nobody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Lasting,
    Ended,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Retain,
    /// The references go back at once: the request failed, or its caller left
    /// before the reply arrived.
    GiveBack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// The lookups of a node: retired in any number, and given back together
    /// by one FORGET.
    Lookups { owed: u64, refused: bool },
    /// The opens of a handle: retired one at a time, each given back by a
    /// separate RELEASE.
    Opens,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceCount {
    shape: Shape,
    live: u64,
    session: SessionState,
}

impl ReferenceCount {
    #[must_use]
    pub const fn lookups() -> Self {
        Self {
            shape: Shape::Lookups {
                owed: 0,
                refused: false,
            },
            live: 0,
            session: SessionState::Lasting,
        }
    }

    #[must_use]
    pub const fn opens() -> Self {
        Self {
            shape: Shape::Opens,
            live: 0,
            session: SessionState::Lasting,
        }
    }

    #[must_use]
    pub fn aggregates(&self) -> bool {
        matches!(self.shape, Shape::Lookups { .. })
    }

    #[must_use]
    pub fn session(&self) -> SessionState {
        self.session
    }

    /// Counts one more admission. Returns the state of the session: an
    /// admission into an ended session ends with it at once.
    #[must_use]
    pub fn admit(&mut self) -> SessionState {
        self.live += 1;
        self.session
    }

    /// Records that the session ended. Returns how many live references ended
    /// with it, or `None` when it had ended already.
    pub fn end(&mut self) -> Option<u64> {
        if self.session == SessionState::Ended {
            return None;
        }
        self.session = SessionState::Ended;
        Some(self.live)
    }

    /// The mount closes: every live reference of a lasting session is owed
    /// now, the lookups of a node as one count and each open of a handle as a
    /// separate RELEASE. Returns the state of the session, which owes nothing
    /// once it ended.
    pub fn mount_closed(&mut self) -> SessionState {
        if self.session == SessionState::Lasting {
            let live = core::mem::take(&mut self.live);
            if let Shape::Lookups { owed, .. } = &mut self.shape {
                *owed += live;
            }
        }
        self.session
    }

    /// Removes everything owed and returns it, which one FORGET gives back as
    /// its lookup count. For the opens of a handle it returns zero: a separate
    /// RELEASE gives back each retired open.
    pub fn take_owed(&mut self) -> u64 {
        match &mut self.shape {
            Shape::Lookups { owed, refused } => {
                *refused = false;
                core::mem::take(owed)
            }
            Shape::Opens => 0,
        }
    }

    /// The pass could not send the `count` lookups it took: they are owed
    /// again.
    pub fn refused(&mut self, count: u64) {
        if let Shape::Lookups { owed, refused } = &mut self.shape {
            *owed += count;
            *refused = true;
        }
    }

    #[must_use]
    pub fn after_pass(&self) -> AfterPass {
        match self.shape {
            Shape::Lookups { refused: true, .. } => AfterPass::Refused,
            Shape::Lookups { owed, .. } if owed != 0 => AfterPass::Again,
            Shape::Lookups { .. } | Shape::Opens => AfterPass::Settled,
        }
    }

    fn retire(&mut self, requested: u64) -> Retired {
        let count = requested.min(self.live);
        self.live -= count;
        if let Shape::Lookups { owed, .. } = &mut self.shape
            && self.session == SessionState::Lasting
        {
            *owed += count;
        }
        Retired {
            count,
            emptied: self.live == 0,
            session: self.session,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retired {
    count: u64,
    pub emptied: bool,
    pub session: SessionState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AfterPass {
    /// Nothing is owed: the record returns to the count it came from until the
    /// next retirement.
    Settled,
    /// Lookups retired while the pass was sending are owed: the record goes to
    /// the worker again.
    Again,
    /// The pass could not send what was owed: the record waits with the
    /// records whose attempt was refused.
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retirement {
    left: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charge {
    Session(u64),
    Done,
    /// References are left, and the identity is not live in any session: the
    /// client retires more references than the server admitted.
    Unmatched,
}

impl Retirement {
    #[must_use]
    pub const fn new(count: u64) -> Self {
        Self { left: count }
    }

    /// Where the rest of the retirement goes, among the `generations` of the
    /// sessions in which the identity is live: the oldest session, the one with
    /// the lowest generation, whose references were admitted first.
    #[must_use]
    pub fn next_charge(&self, generations: impl IntoIterator<Item = u64>) -> Charge {
        if self.left == 0 {
            return Charge::Done;
        }
        generations
            .into_iter()
            .min()
            .map_or(Charge::Unmatched, Charge::Session)
    }

    /// Charges the rest of the retirement to `count`, the references of the
    /// session that [`Retirement::next_charge`] returned. A charge to the lookups
    /// of a node retires as many as are live, up to the rest. A charge to a
    /// handle retires one open, so each retired open owes a separate RELEASE.
    pub fn charge(&mut self, count: &mut ReferenceCount) -> Retired {
        let requested = if count.aggregates() { self.left } else { 1 };
        let retired = count.retire(requested);
        self.left -= retired.count;
        retired
    }
}

/// How far the worker got through the forgets of the entries of one
/// directory listing, each of which admitted one lookup. A pass resumes after
/// the entries sent, and the end of the session ends only the rest.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Listing {
    sent: usize,
}

impl Listing {
    #[must_use]
    pub const fn owes(&self, index: usize) -> bool {
        index >= self.sent
    }

    pub fn sent_one(&mut self) {
        self.sent += 1;
    }
}

pub trait List: Default {
    type Record;
    fn push(&mut self, record: Self::Record);
    fn is_empty(&self) -> bool;
}

#[derive(Debug, Default)]
pub struct Backlog<L> {
    arrived: L,
    refused: L,
    retry: Option<Instant>,
    closed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WorkerStep<L> {
    Pass { refused: L, arrived: L },
    Retry { deadline: Instant },
    Sleep,
    Exit,
}

impl<L: List> Backlog<L> {
    pub fn arrive(&mut self, record: L::Record) {
        self.arrived.push(record);
    }

    /// Whether the record of admitted references waits in the records until
    /// the client retires them. Otherwise it arrives in the backlog at once.
    /// Once the mount closed, nothing retires a reference any more.
    #[must_use]
    pub fn retains(&self, disposition: Disposition) -> bool {
        disposition == Disposition::Retain && !self.closed
    }

    /// The mount closed. Every wait of the worker ends, and the records left
    /// get one more pass.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// What the worker does next, on the instant `now`.
    ///
    /// Records that arrive run a pass at once, which attempts the refused
    /// records too. Refused records alone wait [`RETRY_DELAY`], and records
    /// that arrive meanwhile wait for that pass as well. Once the mount closed,
    /// the worker runs a pass over what is left, and ends when nothing is.
    pub fn step(&mut self, now: Instant) -> WorkerStep<L> {
        let idle = self.arrived.is_empty() && self.refused.is_empty();
        if self.closed && idle {
            return WorkerStep::Exit;
        }
        if !self.closed {
            match self.retry {
                Some(deadline) if deadline_verdict(deadline, now) != DeadlineVerdict::Proceed => {
                    return WorkerStep::Retry { deadline };
                }
                None if idle => return WorkerStep::Sleep,
                None if self.arrived.is_empty() => {
                    let deadline = now.saturating_add(RETRY_DELAY);
                    self.retry = Some(deadline);
                    return WorkerStep::Retry { deadline };
                }
                _ => {}
            }
        }
        self.retry = None;
        WorkerStep::Pass {
            refused: core::mem::take(&mut self.refused),
            arrived: core::mem::take(&mut self.arrived),
        }
    }

    /// Where a record goes after its attempt was refused: back to the backlog,
    /// for a later pass. Once the mount closed, the record is returned instead,
    /// and the adapter ends the references of the record with the session,
    /// unsent. The close ended the session, which gave them back, and a refusal
    /// that repeats does not make the worker run forever.
    pub fn refuse(&mut self, record: L::Record) -> Option<L::Record> {
        if self.closed {
            return Some(record);
        }
        self.refused.push(record);
        None
    }
}

#[cfg(test)]
mod tests {
    use std::vec;
    use std::vec::Vec;

    use super::*;

    impl List for Vec<u32> {
        type Record = u32;

        fn push(&mut self, record: u32) {
            Vec::push(self, record);
        }

        fn is_empty(&self) -> bool {
            <[u32]>::is_empty(self)
        }
    }

    fn node(live: u64) -> ReferenceCount {
        let mut count = ReferenceCount::lookups();
        for _ in 0..live {
            assert_eq!(count.admit(), SessionState::Lasting);
        }
        count
    }

    #[test]
    fn retired_lookups_are_owed_and_go_out_as_one_count() {
        let mut count = node(257);
        assert_eq!(
            Retirement::new(2).charge(&mut count),
            Retired {
                count: 2,
                emptied: false,
                session: SessionState::Lasting,
            }
        );
        let _ = Retirement::new(254).charge(&mut count);
        assert_eq!(count.take_owed(), 256, "both, in one FORGET");
        assert_eq!(count.after_pass(), AfterPass::Settled);
        assert!(Retirement::new(1).charge(&mut count).emptied);
        assert_eq!(count.take_owed(), 1);
    }

    #[test]
    fn lookups_retired_during_a_pass_go_out_on_the_next_one() {
        let mut count = node(3);
        let _ = Retirement::new(1).charge(&mut count);
        assert_eq!(count.take_owed(), 1, "the first pass");
        assert_eq!(
            Retirement::new(2).charge(&mut count).session,
            SessionState::Lasting
        );
        assert_eq!(count.after_pass(), AfterPass::Again);
        assert_eq!(count.take_owed(), 2, "the second pass");
        assert_eq!(count.after_pass(), AfterPass::Settled);
        assert_eq!(count.take_owed(), 0, "nothing is sent twice");
    }

    #[test]
    fn a_refused_count_waits_for_the_retry_pass_and_goes_out_with_later_ones() {
        let mut count = node(3);
        let _ = Retirement::new(1).charge(&mut count);
        let taken = count.take_owed();
        let _ = Retirement::new(1).charge(&mut count);
        count.refused(taken);
        assert_eq!(count.after_pass(), AfterPass::Refused);
        assert_eq!(count.take_owed(), 2, "the retry pass");
        assert_eq!(count.after_pass(), AfterPass::Settled);
    }

    #[test]
    fn each_retired_open_of_a_handle_owes_a_separate_release() {
        let mut count = ReferenceCount::opens();
        assert!(!count.aggregates());
        let _ = count.admit();
        let _ = count.admit();
        let mut retirement = Retirement::new(2);
        let first = retirement.charge(&mut count);
        assert_eq!(
            (first.emptied, first.session),
            (false, SessionState::Lasting)
        );
        assert_eq!(
            retirement.next_charge([1]),
            Charge::Session(1),
            "one is left"
        );
        let second = retirement.charge(&mut count);
        assert_eq!(
            (second.emptied, second.session),
            (true, SessionState::Lasting)
        );
        assert_eq!(retirement.next_charge([1]), Charge::Done);
        assert_eq!(count.take_owed(), 0, "a RELEASE gives back each open");
    }

    #[test]
    fn an_ended_session_ends_its_references_once_and_owes_nothing() {
        let mut count = node(2);
        assert_eq!(count.end(), Some(2));
        assert_eq!(count.end(), None, "a second end ends nothing");
        assert_eq!(count.admit(), SessionState::Ended, "a late admission ends");
        assert_eq!(
            Retirement::new(3).charge(&mut count),
            Retired {
                count: 3,
                emptied: true,
                session: SessionState::Ended,
            }
        );
        assert_eq!(count.take_owed(), 0);
        assert_eq!(count.mount_closed(), SessionState::Ended, "nothing to send");
    }

    #[test]
    fn what_was_owed_before_the_end_still_runs_a_pass() {
        let mut count = node(1);
        let _ = Retirement::new(1).charge(&mut count);
        assert_eq!(count.end(), Some(0));
        assert_eq!(count.after_pass(), AfterPass::Again);
        assert_eq!(count.take_owed(), 1);
        assert_eq!(count.after_pass(), AfterPass::Settled);
        assert_eq!(count.session(), SessionState::Ended);
    }

    #[test]
    fn a_closing_mount_owes_every_live_reference_of_a_lasting_session() {
        let mut count = node(3);
        let _ = Retirement::new(1).charge(&mut count);
        assert_eq!(count.mount_closed(), SessionState::Lasting);
        assert_eq!(count.take_owed(), 3);
        assert!(Retirement::new(1).charge(&mut count).emptied);

        let mut opens = ReferenceCount::opens();
        let _ = opens.admit();
        assert_eq!(opens.mount_closed(), SessionState::Lasting);
        assert!(Retirement::new(1).charge(&mut opens).emptied);
    }

    #[test]
    fn a_retirement_is_charged_to_the_oldest_session_first() {
        let (mut older, mut newer) = (node(3), node(2));
        assert_eq!(older.end(), Some(3));
        assert_eq!(newer.session(), SessionState::Lasting);

        let mut retirement = Retirement::new(4);
        assert_eq!(retirement.next_charge([8, 5]), Charge::Session(5));
        let retired = retirement.charge(&mut older);
        assert_eq!(
            (retired.emptied, retired.session),
            (true, SessionState::Ended)
        );
        assert_eq!(retirement.next_charge([8]), Charge::Session(8));
        let retired = retirement.charge(&mut newer);
        assert_eq!(
            (retired.emptied, retired.session),
            (false, SessionState::Lasting)
        );
        assert_eq!(retirement.next_charge([8]), Charge::Done);
        assert_eq!(newer.take_owed(), 1, "only the newer one owes");

        assert_eq!(Retirement::new(1).next_charge([]), Charge::Unmatched);
        assert_eq!(Retirement::new(0).next_charge([]), Charge::Done);
    }

    #[test]
    fn a_listing_whose_session_ends_midway_ends_only_its_unsent_entries() {
        let mut listing = Listing::default();
        listing.sent_one();
        let owed = (0..3).filter(|&index| listing.owes(index)).count();
        assert_eq!(owed, 2, "the first entry was sent");
        listing.sent_one();
        assert!(!listing.owes(1), "a later pass resumes after the second");
        assert!(listing.owes(2));
    }

    #[test]
    fn only_a_kept_reference_on_an_open_mount_is_retained() {
        let mut backlog = Backlog::<Vec<u32>>::default();
        assert!(backlog.retains(Disposition::Retain));
        assert!(!backlog.retains(Disposition::GiveBack));
        backlog.close();
        assert!(!backlog.retains(Disposition::Retain));
    }

    #[test]
    fn an_idle_worker_sleeps_and_an_arrival_runs_a_pass_with_the_refused_ones() {
        let now = Instant::from_nanos(7);
        let mut backlog = Backlog::<Vec<u32>>::default();
        assert_eq!(backlog.step(now), WorkerStep::Sleep);
        assert_eq!(backlog.refuse(1), None);
        backlog.arrive(2);
        assert_eq!(
            backlog.step(now),
            WorkerStep::Pass {
                refused: vec![1],
                arrived: vec![2],
            }
        );
        assert_eq!(backlog.step(now), WorkerStep::Sleep);
    }

    #[test]
    fn a_pass_attempts_each_refused_record_once_and_keeps_those_refused_again() {
        let start = Instant::from_nanos(7);
        let deadline = start.saturating_add(RETRY_DELAY);
        let mut backlog = Backlog::<Vec<u32>>::default();
        for record in 0..8 {
            assert_eq!(backlog.refuse(record), None);
        }
        assert_eq!(backlog.step(start), WorkerStep::Retry { deadline });
        backlog.arrive(8);
        assert_eq!(backlog.step(start), WorkerStep::Retry { deadline });

        let WorkerStep::Pass { refused, arrived } = backlog.step(deadline) else {
            panic!("the delay ended");
        };
        assert_eq!(refused, (0..8).collect::<Vec<_>>());
        assert_eq!(arrived, [8]);
        for record in refused.into_iter().filter(|record| record % 2 == 0) {
            assert_eq!(backlog.refuse(record), None);
        }

        let next = deadline.saturating_add(RETRY_DELAY);
        assert_eq!(backlog.step(deadline), WorkerStep::Retry { deadline: next });
        assert_eq!(
            backlog.step(next),
            WorkerStep::Pass {
                refused: vec![0, 2, 4, 6],
                arrived: vec![],
            }
        );
    }

    #[test]
    fn a_closed_mount_attempts_its_refused_records_once_more_and_ends() {
        let now = Instant::ORIGIN;
        let mut backlog = Backlog::<Vec<u32>>::default();
        assert_eq!(backlog.refuse(1), None);
        assert!(matches!(backlog.step(now), WorkerStep::Retry { .. }));
        backlog.close();
        assert_eq!(
            backlog.step(now),
            WorkerStep::Pass {
                refused: vec![1],
                arrived: vec![],
            }
        );
        assert_eq!(backlog.refuse(1), Some(1));
        assert_eq!(backlog.step(now), WorkerStep::Exit);
    }
}
