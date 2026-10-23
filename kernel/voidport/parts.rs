// SPDX-License-Identifier: GPL-2.0

//! Reads no kernel object: the host tests compile this file on its own.

/// Each part as `(start, length)`, in order.
pub(crate) fn within_pages(
    position: usize,
    len: usize,
    page: usize,
) -> impl Iterator<Item = (usize, usize)> {
    let end = position + len;
    let mut at = position;
    core::iter::from_fn(move || {
        if at >= end {
            return None;
        }
        let step = (page - at % page).min(end - at);
        let part = (at, step);
        at += step;
        Some(part)
    })
}
