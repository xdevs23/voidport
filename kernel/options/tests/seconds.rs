// SPDX-License-Identifier: GPL-2.0
//! The parsing of mount option seconds and their conversion to kernel ticks,
//! through the public functions of the options crate.

use core::time::Duration;
use voidport_kernel_options::{seconds, ticks};

#[test]
fn seconds_domain() {
    for (text, expected) in [
        ("0", Duration::ZERO),
        ("1", Duration::from_secs(1)),
        ("5", Duration::from_secs(5)),
        ("0.125", Duration::from_millis(125)),
        ("1.000000001", Duration::new(1, 1)),
        (
            "0.123456789123456789123456789",
            Duration::from_nanos(123456789),
        ),
        ("1e-100", Duration::ZERO),
        ("1e10", Duration::from_secs(10_000_000_000)),
        ("18446744073709551615", Duration::from_secs(u64::MAX)),
    ] {
        assert_eq!(seconds(text), Ok(expected), "{text}");
    }
    for text in ["", "NaN", "inf", "-1", "1.2.3", "1_000", "1e"] {
        assert!(seconds(text).is_err(), "{text}");
    }
    assert!(seconds("18446744073709551616").is_err());
}

#[test]
fn checked_kernel_tick_limits() {
    for hz in [100, 250, 1000] {
        for max in [(i32::MAX as u64 >> 1) - 1, (i64::MAX as u64 >> 1) - 1] {
            assert_eq!(ticks(Duration::ZERO, hz, max), 0);
            assert_eq!(ticks(Duration::from_nanos(1), hz, max), 1);
            assert_eq!(ticks(Duration::from_secs(1), hz, max), u64::from(hz));
            assert_eq!(ticks(Duration::from_secs(u64::MAX), hz, max), max);
        }
    }
    assert_eq!(
        ticks(seconds("4294967.296").unwrap(), 1000, u64::MAX),
        4_294_967_296
    );
}
