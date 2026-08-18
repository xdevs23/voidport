//! The instants the adapter supplies.
//!
//! The core reads no clock, so every instant it reasons about arrives as an
//! argument. [`Instant`] is what an adapter's monotonic clock is expressed in:
//! nanoseconds from an origin the adapter picks — the mount's start, the
//! runtime's base, the kernel's boot — and never anything else. Only
//! differences and orderings are meaningful, which is exactly what the stall
//! deadline and the attempt bound are made of.

use core::time::Duration;

/// A point on the adapter's monotonic clock.
///
/// Ordered and subtractable; both operations saturate, so an adapter whose
/// clock is coarse or whose origin is far in the past cannot produce a wrapped
/// deadline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

impl Instant {
    /// The origin of the adapter's clock: the instant every other one is
    /// measured from.
    pub const ORIGIN: Self = Self(0);

    /// The instant `nanos` nanoseconds after the origin.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// How many nanoseconds after the origin this instant is.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// The instant `later` after this one, saturating at the clock's end.
    #[must_use]
    pub fn saturating_add(self, later: Duration) -> Self {
        Self(self.0.saturating_add(nanos_of(later)))
    }

    /// How long this instant is after `earlier`, or zero if it is not.
    #[must_use]
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }
}

/// A duration as whole nanoseconds, saturating instead of wrapping.
fn nanos_of(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

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
