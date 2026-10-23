// SPDX-License-Identifier: GPL-2.0

//! Decimal seconds for kernel mount options, without floating-point execution.
//!
//! The fixed-point parser accepts decimal exponents and arbitrary fractional
//! input length. Its 64 fractional bits exceed the nanosecond precision of
//! Duration.

#![no_std]
#![forbid(unsafe_code)]

use core::time::Duration;
use fixed::types::U64F64;

/// Why a seconds value cannot be represented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The decimal syntax is invalid.
    Invalid,
    /// The value exceeds the duration representation.
    Overflow,
}

/// Rounds fractional seconds to the nearest nanosecond. Ties round to even, as
/// in the floating-point conversion of Duration.
pub fn seconds(text: &str) -> Result<Duration, Error> {
    let (value, overflow) = U64F64::overflowing_from_str(text).map_err(|_| Error::Invalid)?;
    if overflow {
        return Err(Error::Overflow);
    }
    let bits = value.to_bits();
    // The upper half of a u128 fits exactly in u64.
    let secs = (bits >> 64) as u64;
    let fraction = u128::from(bits as u64) * 1_000_000_000;
    let nanos = fraction >> 64;
    let remainder = fraction as u64;
    let round = remainder > (1u64 << 63) || (remainder == (1u64 << 63) && nanos & 1 != 0);
    Duration::from_secs(secs)
        .checked_add(Duration::from_nanos(nanos as u64 + u64::from(round)))
        .ok_or(Error::Overflow)
}

/// Round up to kernel ticks, saturating only at its safe jiffies-span limit.
pub fn ticks(duration: Duration, hz: u32, max: u64) -> u64 {
    let scaled = duration.as_nanos() * u128::from(hz);
    let ticks = scaled.div_ceil(1_000_000_000);
    ticks.min(u128::from(max)) as u64
}
