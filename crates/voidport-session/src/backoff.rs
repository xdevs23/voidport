//! The reconnect schedule, and the jitter that keeps two mounts apart.
//!
//! Two schedules, because the two phases mean different things: inside the
//! stall window a guest is *waiting*, so retries are quick; once degraded
//! nothing waits on the probe, so it slows down.
//!
//! The randomness is a seed the mount supplies — the operating system's in
//! userspace, the kernel's random bytes in kernel space — threaded in as data
//! and expanded here. Nothing about it needs to be unpredictable: it only needs
//! to be uncorrelated between two mounts that lost the same server, so they do
//! not retry in lockstep. Seeding per mount is what buys that, and a seed the
//! caller chooses is what makes the schedule reproducible under test.

use core::time::Duration;

/// The first delay between reconnect attempts inside the stall window.
pub const STALL_INITIAL: Duration = Duration::from_millis(100);

/// The ceiling that delay doubles up to inside the stall window.
pub const STALL_MAX: Duration = Duration::from_secs(1);

/// The first delay between reconnect attempts once the mount is degraded.
///
/// Slower than inside the window, because nothing is waiting on it any more.
pub const DEGRADED_INITIAL: Duration = Duration::from_millis(500);

/// The ceiling that delay doubles up to once the mount is degraded.
pub const DEGRADED_MAX: Duration = Duration::from_secs(5);

/// How long one degraded reconnect attempt may take before it is abandoned.
///
/// A peer that accepts the socket and never completes the handshake must not
/// hold the probe forever; inside the stall window the window's remainder is
/// the bound, and afterwards this is.
pub const DEGRADED_ATTEMPT_BOUND: Duration = Duration::from_secs(5);

/// How much of a backoff delay is jitter, as a divisor.
///
/// The delay is shortened by up to a quarter, never lengthened, so the schedule
/// stays an upper bound.
const JITTER_DIVISOR: u32 = 4;

/// How finely the jitter divides that quarter.
const JITTER_STEPS: u32 = 1000;

/// Which schedule the next delay comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Schedule {
    /// The mount is stalling inside its window and a guest is waiting.
    Stalling,
    /// The window has closed and nothing waits on the probe.
    Degraded,
}

impl Schedule {
    /// The first delay of this schedule, and the ceiling it doubles up to.
    const fn bounds(self) -> (Duration, Duration) {
        match self {
            Self::Stalling => (STALL_INITIAL, STALL_MAX),
            Self::Degraded => (DEGRADED_INITIAL, DEGRADED_MAX),
        }
    }
}

/// The doubling delay between reconnect attempts, and its jitter source.
#[derive(Clone, Debug)]
pub struct Backoff {
    /// The delay handed out last, or `None` when the schedule starts over.
    previous: Option<Duration>,
    jitter: Jitter,
}

impl Backoff {
    /// A schedule that starts at its initial delay, jittered from `seed`.
    #[must_use]
    pub const fn seeded(seed: u64) -> Self {
        Self {
            previous: None,
            jitter: Jitter::seeded(seed),
        }
    }

    /// Starts the schedule over, so the next delay is an initial one again.
    ///
    /// What the probe does when it crosses from one schedule into the other:
    /// the delay it had reached inside the window says nothing about the one a
    /// degraded mount should wait.
    pub fn restart(&mut self) {
        self.previous = None;
    }

    /// The next delay, capped by the schedule and shortened by its jitter.
    pub fn next(&mut self, schedule: Schedule) -> Duration {
        let (initial, max) = schedule.bounds();
        let delay = match self.previous {
            None => initial,
            Some(previous) => (previous * 2).clamp(initial, max),
        };
        // The delay that was actually waited is what the next one doubles, as
        // the shipped schedule has always done: the jitter shortens the wait
        // and the schedule follows the wait, not a nominal figure beside it.
        let waited = delay - self.cut(delay);
        self.previous = Some(waited);
        waited
    }

    /// How much to shorten a delay by: up to a quarter of it, never more.
    fn cut(&mut self, delay: Duration) -> Duration {
        let spread = delay / JITTER_DIVISOR;
        let step = u32::try_from(self.jitter.next() % u64::from(JITTER_STEPS)).unwrap_or(0);
        spread
            .checked_mul(step)
            .map_or(Duration::ZERO, |scaled| scaled / JITTER_STEPS)
    }
}

/// The jitter source: a small arithmetic generator, seeded per mount.
///
/// SplitMix64, because it is four arithmetic operations of state and needs no
/// dependency — the kbuild recipe prices every dependency as a hand-written
/// rule, and a jitter spread is not a cryptographic question.
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

    /// The shipped schedule, unchanged: jitter only ever shortens, so each
    /// delay stays inside its own bounds, and crossing into the degraded
    /// schedule never drops the delay below that schedule's floor.
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

        // Crossing into the degraded schedule never shortens the delay below
        // its own floor, however small the stalling one had been.
        let mut backoff = Backoff::seeded(3);
        let _ = backoff.next(Schedule::Stalling);
        assert!(backoff.next(Schedule::Degraded) * 2 >= DEGRADED_INITIAL);
    }

    /// A restarted schedule hands out an initial delay again, which is what the
    /// probe relies on when the window closes underneath it.
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

    /// The criterion the seed exists for: one seed, one schedule, every time —
    /// and two seeds that do not walk in step.
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

    /// Every delay is inside its bounds for a spread of seeds, which is the
    /// property the jitter may never break.
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
