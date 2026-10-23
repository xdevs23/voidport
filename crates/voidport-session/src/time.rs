//! Only differences and orderings of an [`Instant`] are meaningful.

use core::time::Duration;

/// Ordered and subtractable; both operations saturate, so an adapter whose
/// clock is coarse or whose origin is far in the past cannot produce a wrapped
/// deadline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

impl Instant {
    pub const ORIGIN: Self = Self(0);

    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    #[must_use]
    pub fn from_duration(since: Duration) -> Self {
        Self(nanos_of(since))
    }

    #[must_use]
    pub const fn as_duration(self) -> Duration {
        Duration::from_nanos(self.0)
    }

    #[must_use]
    pub fn saturating_add(self, later: Duration) -> Self {
        Self(self.0.saturating_add(nanos_of(later)))
    }

    #[must_use]
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadlineVerdict {
    Proceed,
    Wait(Duration),
}

/// The deadline itself proceeds, so a wait never runs past it by the clock's
/// resolution. A reading from before the deadline was computed waits the whole
/// distance, and a deadline saturated at the clock's end stays ahead of every
/// reading but the last one. The adapter converts the duration to its own
/// timeout and compares nothing.
#[must_use]
pub fn deadline_verdict(deadline: Instant, now: Instant) -> DeadlineVerdict {
    let remaining = deadline.saturating_duration_since(now);
    if remaining.is_zero() {
        DeadlineVerdict::Proceed
    } else {
        DeadlineVerdict::Wait(remaining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tick(usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TickSpan(usize);

impl Tick {
    #[must_use]
    pub const fn new(reading: usize) -> Self {
        Self(reading)
    }

    #[must_use]
    pub const fn since(self, earlier: Self) -> TickSpan {
        TickSpan(self.0.wrapping_sub(earlier.0))
    }
}

impl TickSpan {
    #[must_use]
    pub const fn new(ticks: usize) -> Self {
        Self(ticks)
    }

    /// Whether a span between two readings points forward in time. A span
    /// from a later reading to an earlier one wraps to more than half of the
    /// counter, which is negative in the signed comparison of the kernel.
    const fn points_forward(self) -> bool {
        self.0 <= usize::MAX / 2
    }
}

/// The elapsed ticks are the wrapping difference from `resolved` to `now`, so
/// a value resolved just before the counter wraps is judged the same way
/// right after it. The lifetime ends on its last tick: a reading exactly
/// `lifetime` ticks after `resolved` has outlived it, and a lifetime of zero
/// has always ended. A reading taken before `resolved` has not ended the
/// lifetime. Another processor can resolve the value between the moment the
/// caller read the counter and the moment it read `resolved`, and the value
/// is not stale for that.
#[must_use]
pub fn lifetime_ended(resolved: Tick, lifetime: TickSpan, now: Tick) -> bool {
    let elapsed = now.since(resolved);
    lifetime == TickSpan(0) || (elapsed.points_forward() && elapsed >= lifetime)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptVerdict {
    Expired,
    Closed,
    Complete,
    Wait(Option<Duration>),
}

/// The two observations are independent and both may hold. The adapter reports
/// each as it stands, and [`attempt_verdict`] returns which one wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptStatus {
    pub closed: bool,
    pub complete: bool,
}

/// Closure is judged first and discards the result, even one reported complete
/// in the same status. Completion is judged next and needs no further wait, so
/// only a pending attempt can exhaust its budget. The reconnect stall deadline
/// is separate: the adapter that runs the probe expires that window before
/// installing even a successful handshake. With no bound, instants do not
/// affect the verdict. Subtraction uses the same saturating monotonic
/// arithmetic as reconnect.
#[must_use]
pub fn attempt_verdict(
    started: Instant,
    now: Instant,
    bound: Option<Duration>,
    status: AttemptStatus,
) -> AttemptVerdict {
    if status.closed {
        return AttemptVerdict::Closed;
    }
    if status.complete {
        return AttemptVerdict::Complete;
    }
    let remaining = bound.map(|bound| bound.saturating_sub(now.saturating_duration_since(started)));
    if remaining.is_some_and(|remaining| remaining.is_zero()) {
        AttemptVerdict::Expired
    } else {
        AttemptVerdict::Wait(remaining)
    }
}

fn nanos_of(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PENDING: AttemptStatus = AttemptStatus {
        closed: false,
        complete: false,
    };

    #[test]
    fn a_deadline_waits_until_its_own_instant_and_proceeds_on_it() {
        let deadline = Instant::from_nanos(1_000);
        assert_eq!(
            deadline_verdict(deadline, Instant::from_nanos(999)),
            DeadlineVerdict::Wait(Duration::from_nanos(1)),
            "one nanosecond before the deadline waits one nanosecond"
        );
        assert_eq!(
            deadline_verdict(deadline, deadline),
            DeadlineVerdict::Proceed,
            "the deadline itself proceeds"
        );
        assert_eq!(
            deadline_verdict(deadline, Instant::from_nanos(1_001)),
            DeadlineVerdict::Proceed
        );
    }

    #[test]
    fn a_reading_before_the_origin_of_a_deadline_saturates() {
        // The deadline was computed from a reading of 900. An earlier reading
        // waits the whole distance, and the subtraction the other way round
        // is no time at all instead of a wrapped span.
        let origin = Instant::from_nanos(900);
        let deadline = origin.saturating_add(Duration::from_nanos(100));
        assert_eq!(
            deadline_verdict(deadline, Instant::ORIGIN),
            DeadlineVerdict::Wait(Duration::from_nanos(1_000))
        );
        assert_eq!(
            deadline_verdict(Instant::ORIGIN, origin),
            DeadlineVerdict::Proceed
        );
    }

    #[test]
    fn the_largest_deadline_and_reading_do_not_wrap() {
        let end = Instant::from_nanos(u64::MAX);
        assert_eq!(
            deadline_verdict(end, Instant::ORIGIN),
            DeadlineVerdict::Wait(Duration::from_nanos(u64::MAX))
        );
        assert_eq!(
            deadline_verdict(end, Instant::from_nanos(u64::MAX - 1)),
            DeadlineVerdict::Wait(Duration::from_nanos(1))
        );
        assert_eq!(deadline_verdict(end, end), DeadlineVerdict::Proceed);
        assert_eq!(
            deadline_verdict(Instant::ORIGIN, end),
            DeadlineVerdict::Proceed
        );
        // The largest window a mount can ask for saturates at the clock's end
        // and is still a wait from any reading a running clock can produce.
        let never = Instant::from_nanos(1).saturating_add(Duration::MAX);
        assert_eq!(never, end);
        assert_eq!(
            deadline_verdict(never, Instant::from_nanos(u64::MAX - 1)),
            DeadlineVerdict::Wait(Duration::from_nanos(1))
        );
    }

    fn ended(resolved: usize, lifetime: usize, now: usize) -> bool {
        lifetime_ended(Tick::new(resolved), TickSpan::new(lifetime), Tick::new(now))
    }

    #[test]
    fn a_lifetime_ends_on_its_last_tick() {
        assert!(!ended(1_000, 5, 1_004), "one tick before the end");
        assert!(ended(1_000, 5, 1_005), "exactly at the end");
        assert!(ended(1_000, 0, 1_000), "a zero lifetime");
    }

    #[test]
    fn a_lifetime_counts_across_the_wrap_of_the_counter() {
        let resolved = usize::MAX - 2;
        assert!(!ended(resolved, 5, usize::MAX));
        assert!(!ended(resolved, 5, 1), "one tick before the end");
        assert!(ended(resolved, 5, 2), "exactly at the end");
    }

    #[test]
    fn a_reading_before_the_resolution_has_not_ended_the_lifetime() {
        assert!(!ended(1_000, 5, 999));
        assert!(ended(1_000, 0, 999), "a zero lifetime has always ended");
    }

    #[test]
    fn whole_attempt_budget_and_completion_ties() {
        let start = Instant::from_nanos(100);
        let bound = Duration::from_nanos(100);
        for closed in [false, true] {
            for complete in [false, true] {
                for elapsed in [100, 101, u64::MAX - 100] {
                    assert_eq!(
                        attempt_verdict(
                            start,
                            Instant::from_nanos(100 + elapsed),
                            Some(bound),
                            AttemptStatus { closed, complete }
                        ),
                        if closed {
                            AttemptVerdict::Closed
                        } else if complete {
                            AttemptVerdict::Complete
                        } else {
                            AttemptVerdict::Expired
                        },
                    );
                }
            }
        }
        for elapsed in [0, 40, 80, 99] {
            let now = Instant::from_nanos(100 + elapsed);
            assert_eq!(
                attempt_verdict(start, now, Some(bound), PENDING),
                AttemptVerdict::Wait(Some(Duration::from_nanos(100 - elapsed)))
            );
            assert_eq!(
                attempt_verdict(
                    start,
                    now,
                    Some(bound),
                    AttemptStatus {
                        closed: false,
                        complete: true
                    }
                ),
                AttemptVerdict::Complete
            );
            assert_eq!(
                attempt_verdict(
                    start,
                    now,
                    Some(bound),
                    AttemptStatus {
                        closed: true,
                        complete: true
                    }
                ),
                AttemptVerdict::Closed,
                "closure outranks a completion reported with it"
            );
        }
        for complete in [false, true] {
            assert_eq!(
                attempt_verdict(
                    start,
                    start,
                    Some(Duration::ZERO),
                    AttemptStatus {
                        closed: false,
                        complete
                    }
                ),
                if complete {
                    AttemptVerdict::Complete
                } else {
                    AttemptVerdict::Expired
                }
            );
        }
    }

    #[test]
    fn attempt_instants_saturate_and_large_bounds_do_not_truncate() {
        let start = Instant::from_nanos(u64::MAX - 50);
        let bound = Duration::from_nanos(100);
        assert_eq!(
            attempt_verdict(start, Instant::from_nanos(u64::MAX), Some(bound), PENDING),
            AttemptVerdict::Wait(Some(Duration::from_nanos(50)))
        );
        assert_eq!(
            attempt_verdict(start, Instant::ORIGIN, Some(bound), PENDING),
            AttemptVerdict::Wait(Some(bound))
        );
        assert_eq!(
            attempt_verdict(
                Instant::ORIGIN,
                Instant::from_nanos(u64::MAX),
                Some(Duration::MAX),
                PENDING
            ),
            AttemptVerdict::Wait(Some(Duration::MAX - Duration::from_nanos(u64::MAX)))
        );
    }

    #[test]
    fn unbounded_attempt_waits_only_for_completion_or_closure() {
        for start in [Instant::ORIGIN, Instant::from_nanos(u64::MAX)] {
            for now in [Instant::ORIGIN, Instant::from_nanos(u64::MAX)] {
                for closed in [false, true] {
                    for complete in [false, true] {
                        assert_eq!(
                            attempt_verdict(start, now, None, AttemptStatus { closed, complete }),
                            if closed {
                                AttemptVerdict::Closed
                            } else if complete {
                                AttemptVerdict::Complete
                            } else {
                                AttemptVerdict::Wait(None)
                            }
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn an_instant_converts_to_and_from_its_duration_after_the_origin() {
        let instant = Instant::from_duration(Duration::from_secs(2));
        assert_eq!(instant, Instant::from_nanos(2_000_000_000));
        assert_eq!(instant.as_duration(), Duration::from_secs(2));
        assert_eq!(
            Instant::from_duration(Duration::MAX),
            Instant::from_nanos(u64::MAX),
            "a duration past the end of the clock saturates"
        );
    }

    #[test]
    fn instants_order_and_subtract_without_wrapping() {
        let base = Instant::from_nanos(1_000);
        assert!(base.saturating_add(Duration::from_nanos(1)) > base);
        assert_eq!(
            base.saturating_add(Duration::from_secs(1))
                .saturating_duration_since(base),
            Duration::from_secs(1)
        );
        assert_eq!(
            base.saturating_duration_since(Instant::from_nanos(2_000)),
            Duration::ZERO,
            "an instant before the other is no time at all, never a wrap"
        );
        assert_eq!(
            Instant::from_nanos(u64::MAX).saturating_add(Duration::from_secs(1)),
            Instant::from_nanos(u64::MAX)
        );
    }
}
