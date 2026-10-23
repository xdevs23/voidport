// SPDX-License-Identifier: GPL-2.0

#[path = "../voidport/division.rs"]
mod division;

use division::divide;

#[test]
fn zero_divisor_returns_zero() {
    for numerator in [0, 1, u128::MAX] {
        assert_eq!(divide(numerator, 0), 0);
    }
}

#[test]
fn full_width_division_matches_the_host_runtime() {
    for numerator in [0, 1, u64::MAX as u128, 1u128 << 64, 1u128 << 127, u128::MAX] {
        for denominator in [
            1,
            3,
            10,
            1_000_000_000,
            u64::MAX as u128,
            1u128 << 64,
            (1u128 << 127) + 1,
            u128::MAX,
        ] {
            assert_eq!(divide(numerator, denominator), numerator / denominator);
        }
    }
    let mut value = 1u128;
    for _ in 0..10_000 {
        value = value.wrapping_mul(6364136223846793005).wrapping_add(1);
        let denominator = value.rotate_left(47) | 1;
        assert_eq!(divide(value, denominator), value / denominator);
    }
}
