//! The host kernel delays a writer for the holder of a lease only for the
//! lease break time of the system, so the pages that a guest caches are valid
//! only within a window that it renews. The window and one renewal period
//! after it must fit into the break time. Half the break time for the window
//! and a quarter for the period leave a quarter between the server letting the
//! writer go and the kernel doing so.

use core::ops::Add;
use core::time::Duration;

/// A validity window, and how often it is renewed. The period is never zero
/// and always shorter than the window, so a renewal is sent before the window
/// it renews ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    length: Duration,
    period: Duration,
}

impl Window {
    #[must_use]
    pub fn new(length: Duration, period: Duration) -> Option<Self> {
        (!period.is_zero() && period < length).then_some(Self { length, period })
    }

    /// The window for a host whose lease break time is `break_time`. `None`
    /// when that leaves no window, as a break time of zero does, which the
    /// kernel reads as delaying a writer for as long as the lease is held.
    #[must_use]
    pub fn of(break_time: Duration) -> Option<Self> {
        Self::new(break_time / 2, break_time / 4)
    }

    #[must_use]
    pub fn to_nanos(window: Option<Self>) -> (u64, u64) {
        let nanos = |duration: Duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        window.map_or((0, 0), |window| {
            (nanos(window.length), nanos(window.period))
        })
    }

    #[must_use]
    pub fn from_nanos(length_ns: u64, period_ns: u64) -> Option<Self> {
        Self::new(
            Duration::from_nanos(length_ns),
            Duration::from_nanos(period_ns),
        )
    }

    #[must_use]
    pub fn length(self) -> Duration {
        self.length
    }

    #[must_use]
    pub fn period(self) -> Duration {
        self.period
    }

    #[must_use]
    pub fn surely_passed(self) -> Duration {
        self.length + self.period
    }

    /// The instant by which this window has surely passed, for a server that
    /// replied to the renewal that granted it at `replied`, on any clock.
    #[must_use]
    pub fn surely_passed_from<I: Add<Duration, Output = I>>(self, replied: I) -> I {
        replied + self.surely_passed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_and_its_period_end_before_the_lease_break_time() {
        for seconds in [1, 45, 300] {
            let break_time = Duration::from_secs(seconds);
            let window = Window::of(break_time).expect("a window");
            assert!(window.length < break_time - window.period, "{seconds} s");
            assert!(window.surely_passed() < break_time, "{seconds} s");
        }
    }

    #[test]
    fn a_window_surely_passes_between_the_guest_drop_and_the_kernel_break() {
        let break_time = Duration::from_secs(45);
        let window = Window::of(break_time).expect("a window");
        let sent = std::time::Instant::now();
        let replied = sent + Duration::from_millis(3);

        let passed = window.surely_passed_from(replied);
        // The guest counts the window from the moment it sent the renewal, and
        // drops every page within one period after it ends.
        assert!(passed >= sent + window.length() + window.period());
        // A writer that breaks the lease after the reply waits in the host
        // kernel for the break time.
        assert!(passed < replied + break_time);
    }

    #[test]
    fn a_break_time_of_zero_leaves_no_window() {
        assert_eq!(Window::of(Duration::ZERO), None);
        assert_eq!(Window::of(Duration::from_nanos(3)), None);
    }

    #[test]
    fn only_a_period_shorter_than_its_window_makes_one() {
        let second = Duration::from_secs(1);
        assert_eq!(Window::new(second, Duration::ZERO), None);
        assert_eq!(Window::new(second, second), None);
        assert!(Window::new(second * 2, second).is_some());
    }

    #[test]
    fn a_window_crosses_the_wire_as_two_counts_of_nanoseconds() {
        let window = Window::of(Duration::from_secs(45));
        let (length_ns, period_ns) = Window::to_nanos(window);
        assert_eq!(Window::from_nanos(length_ns, period_ns), window);
        assert_eq!(Window::to_nanos(None), (0, 0));
        assert_eq!(Window::from_nanos(0, 0), None);
    }
}
