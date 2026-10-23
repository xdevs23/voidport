// SPDX-License-Identifier: GPL-2.0
//! The kernel clock as the session core sees it: one reading of the monotonic
//! clock, and one conversion of a core duration into a kernel timeout. The
//! core owns every comparison, so nothing here compares two instants.

use core::time::Duration;

use kernel::time::{ClockSource, Jiffies, Monotonic};
use voidport_session::Instant;

/// The instant the core reasons about, read from the kernel monotonic clock.
/// Only differences between two readings are meaningful.
/// The monotonic clock counts up from zero at boot and is never negative, so
/// the magnitude is the reading itself.
pub fn now() -> Instant {
    Instant::from_nanos(Monotonic::ktime_get().unsigned_abs())
}

/// The kernel timeout that carries out a wait the core asked for.
///
/// A duration beyond the signed nanosecond range of the kernel becomes the
/// longest `Delta`, and a `Delta` beyond the millisecond range of the jiffies
/// conversion becomes the longest timeout. A wait cut short by either step
/// returns to the core, which hands out the rest, so an oversized duration
/// waits in several pieces and never wraps into a short one.
pub fn timeout_of(duration: Duration) -> Jiffies {
    let nanos = i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX);
    crate::wire::jiffies_of(crate::compat::delta_from_nanos(nanos))
}
