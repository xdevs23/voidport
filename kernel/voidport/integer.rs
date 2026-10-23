// SPDX-License-Identifier: GPL-2.0

/// The compiler ABI for unsigned 128-bit division. Rust checks a zero divisor
/// before calling it, so direct calls with zero return zero instead of
/// entering the panic handler of the kernel.
///
/// This is not an EXPORT_SYMBOL: the module loader resolves defined symbols
/// locally, so another definition of the name in the kernel does not
/// interpose on this one.
///
/// The kernel does not export this compiler helper, and the decimal conversion
/// of the fixed-point parser needs 128-bit division even when the resulting
/// seconds and jiffies fit in 64 bits. `no_mangle` resolves the
/// compiler-generated references inside this module.
#[no_mangle]
pub(crate) extern "C" fn __udivti3(numerator: u128, denominator: u128) -> u128 {
    crate::division::divide(numerator, denominator)
}
