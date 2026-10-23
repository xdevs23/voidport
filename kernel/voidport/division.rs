// SPDX-License-Identifier: GPL-2.0

//! Reads no kernel object: the host tests compile this file on its own.

/// Zero for a zero `denominator`.
pub(crate) fn divide(mut numerator: u128, denominator: u128) -> u128 {
    if denominator == 0 {
        return 0;
    }
    if numerator < denominator {
        return 0;
    }
    let shift = denominator.leading_zeros() - numerator.leading_zeros();
    let mut divisor = denominator << shift;
    let mut quotient = 0;
    for bit in (0..=shift).rev() {
        if numerator >= divisor {
            numerator -= divisor;
            quotient |= 1u128 << bit;
        }
        divisor >>= 1;
    }
    quotient
}
