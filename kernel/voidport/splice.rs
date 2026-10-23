// SPDX-License-Identifier: GPL-2.0

//! Reads no kernel object: the host tests compile this file on its own.

/// Calls `stamp` with the dentry retained by a splice of `dentry`: the alias
/// in `spliced`, or `dentry` itself when the splice returned none. A failed
/// splice retains neither.
pub(crate) fn stamp_retained<T, E>(
    dentry: *mut T,
    spliced: Result<*mut T, E>,
    stamp: impl FnOnce(*mut T),
) {
    match spliced {
        Ok(alias) if alias.is_null() => stamp(dentry),
        Ok(alias) => stamp(alias),
        Err(_) => {}
    }
}
