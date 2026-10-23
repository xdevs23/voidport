//! Two schedules, because the two phases mean different things: inside the
//! stall window a guest is *waiting*, so retries are quick; once degraded
//! nothing waits on the probe, so it slows down.
//!
//! The seed of the jitter only needs to be uncorrelated between two mounts that
//! lost the same server, so they do not retry in lockstep. A seed chosen by the
//! caller makes the schedule reproducible under test.

use core::time::Duration;

pub const STALL_INITIAL: Duration = Duration::from_millis(100);

pub const STALL_MAX: Duration = Duration::from_secs(1);

/// Slower than inside the window, because nothing is waiting on it any more.
pub const DEGRADED_INITIAL: Duration = Duration::from_millis(500);

pub const DEGRADED_MAX: Duration = Duration::from_secs(5);

/// A peer that accepts the socket and never completes the handshake must not
/// hold the probe forever; inside the stall window the window's remainder is
/// the bound, and afterwards this is.
pub const DEGRADED_ATTEMPT_BOUND: Duration = Duration::from_secs(5);

/// A server that accepts the socket and never replies to the hello must not
/// block the request that dials. Past this bound the dial counts as one that
/// could not reach the server. It is the bound of a degraded reconnect
/// attempt, which is one handshake with a server that may not answer as well.
pub const JOIN_ATTEMPT_BOUND: Duration = DEGRADED_ATTEMPT_BOUND;

/// The delay is shortened by up to a quarter, never lengthened, so the schedule
/// stays an upper bound.
const JITTER_DIVISOR: u32 = 4;

const JITTER_STEPS: u32 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Schedule {
    Stalling,
    Degraded,
}

impl Schedule {
    const fn bounds(self) -> (Duration, Duration) {
        match self {
            Self::Stalling => (STALL_INITIAL, STALL_MAX),
            Self::Degraded => (DEGRADED_INITIAL, DEGRADED_MAX),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Backoff {
    previous: Option<Duration>,
    jitter: Jitter,
}

impl Backoff {
    #[must_use]
    pub const fn seeded(seed: u64) -> Self {
        Self {
            previous: None,
            jitter: Jitter::seeded(seed),
        }
    }

    /// What the probe does when it crosses from one schedule into the other:
    /// the delay it had reached inside the window is no guide to the one a
    /// degraded mount should wait.
    pub fn restart(&mut self) {
        self.previous = None;
    }

    pub fn next(&mut self, schedule: Schedule) -> Duration {
        let (initial, max) = schedule.bounds();
        let delay = match self.previous {
            None => initial,
            Some(previous) => (previous * 2).clamp(initial, max),
        };
        // The next delay doubles the delay that was actually waited, so the
        // schedule follows the jittered wait and not a nominal figure.
        let waited = delay - self.cut(delay);
        self.previous = Some(waited);
        waited
    }

    fn cut(&mut self, delay: Duration) -> Duration {
        let spread = delay / JITTER_DIVISOR;
        let step = u32::try_from(self.jitter.next() % u64::from(JITTER_STEPS)).unwrap_or(0);
        spread
            .checked_mul(step)
            .map_or(Duration::ZERO, |scaled| scaled / JITTER_STEPS)
    }
}

/// SplitMix64, because it is four arithmetic operations of state and needs no
/// dependency, which matters in the kernel build where every dependency needs
/// a hand-written build rule, and a jitter spread is not a cryptographic
/// question.
#[derive(Clone, Debug)]
struct Jitter(u64);

impl Jitter {
    const fn seeded(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut word = self.0;
        word = (word ^ (word >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        word = (word ^ (word >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        word ^ (word >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_doubles_to_its_cap_under_both_schedules() {
        let mut backoff = Backoff::seeded(1);
        let stalling = backoff.next(Schedule::Stalling);
        assert!(stalling <= STALL_INITIAL && stalling * 2 >= STALL_INITIAL);
        assert!(backoff.next(Schedule::Stalling) <= STALL_MAX);
        for _ in 0..8 {
            assert!(backoff.next(Schedule::Stalling) <= STALL_MAX);
        }

        let mut backoff = Backoff::seeded(2);
        let degraded = backoff.next(Schedule::Degraded);
        assert!(degraded <= DEGRADED_INITIAL && degraded * 2 >= DEGRADED_INITIAL);
        for _ in 0..8 {
            assert!(backoff.next(Schedule::Degraded) <= DEGRADED_MAX);
        }

        let mut backoff = Backoff::seeded(3);
        let _ = backoff.next(Schedule::Stalling);
        assert!(backoff.next(Schedule::Degraded) * 2 >= DEGRADED_INITIAL);
    }

    #[test]
    fn a_restarted_schedule_starts_at_its_initial_delay() {
        let mut backoff = Backoff::seeded(4);
        for _ in 0..6 {
            let _ = backoff.next(Schedule::Stalling);
        }
        backoff.restart();
        let first = backoff.next(Schedule::Stalling);
        assert!(first <= STALL_INITIAL && first * 2 >= STALL_INITIAL);
    }

    #[test]
    fn one_seed_is_one_schedule_and_two_seeds_differ() {
        let run = |seed| {
            let mut backoff = Backoff::seeded(seed);
            let mut delays = std::vec::Vec::new();
            for _ in 0..8 {
                delays.push(backoff.next(Schedule::Stalling));
            }
            delays
        };
        assert_eq!(
            run(0x5EED),
            run(0x5EED),
            "a seeded schedule is reproducible"
        );
        assert_ne!(
            run(0x5EED),
            run(0x5EEE),
            "two mounts that lost the same server do not retry in lockstep"
        );
    }

    #[test]
    fn the_jitter_only_ever_shortens_and_never_below_three_quarters() {
        for seed in 0..64u64 {
            let mut backoff = Backoff::seeded(seed.wrapping_mul(0x1234_5678));
            for _ in 0..16 {
                let delay = backoff.next(Schedule::Degraded);
                assert!(delay <= DEGRADED_MAX);
                assert!(delay * 4 >= DEGRADED_INITIAL * 3, "{delay:?}");
            }
        }
    }
}
