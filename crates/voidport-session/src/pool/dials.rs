use crate::backoff::{Backoff, Schedule};
use crate::time::{DeadlineVerdict, Instant, deadline_verdict};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    Dial,
    Wait,
    WaitUntil(Instant),
    Ended,
}

#[derive(Clone, Debug, Default)]
pub struct Taking(Dials);

#[derive(Clone, Debug, Default)]
enum Dials {
    #[default]
    Undialed,
    Failed,
    Spaced(Spacing),
}

#[derive(Clone, Debug)]
struct Spacing {
    backoff: Backoff,
    at: Instant,
}

impl Taking {
    /// A request that has not dialed dials. One whose dial failed waits for a
    /// connection of the pool while the pool has any, and dials nothing
    /// meanwhile. Once the pool has none, it dials, after the delay its
    /// schedule gave when it has one.
    pub(super) fn next(&self, pooled: usize, now: Instant) -> Next {
        match &self.0 {
            Dials::Undialed => Next::Dial,
            _ if pooled != 0 => Next::Wait,
            Dials::Failed => Next::Dial,
            Dials::Spaced(spacing) => match deadline_verdict(spacing.at, now) {
                DeadlineVerdict::Wait(_) => Next::WaitUntil(spacing.at),
                DeadlineVerdict::Proceed => Next::Dial,
            },
        }
    }

    pub(super) fn wait_for_the_pool(&mut self) {
        self.0 = Dials::Failed;
    }

    pub(super) fn space(&mut self, now: Instant, seed: u64) {
        let mut backoff = match core::mem::take(&mut self.0) {
            Dials::Spaced(spacing) => spacing.backoff,
            Dials::Undialed | Dials::Failed => Backoff::seeded(seed),
        };
        let delay = backoff.next(Schedule::Stalling);
        self.0 = Dials::Spaced(Spacing {
            backoff,
            at: now.saturating_add(delay),
        });
    }
}
