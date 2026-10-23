// SPDX-License-Identifier: GPL-2.0

#[path = "../voidport/parts.rs"]
mod parts;

use parts::within_pages;

#[test]
fn a_run_splits_where_each_page_ends() {
    let split: Vec<_> = within_pages(10, 20, 8).collect();
    assert_eq!(split, [(10, 6), (16, 8), (24, 6)]);
}

#[test]
fn a_run_inside_one_page_is_one_part() {
    let split: Vec<_> = within_pages(16, 8, 8).collect();
    assert_eq!(split, [(16, 8)]);
}

#[test]
fn an_empty_run_has_no_part() {
    assert_eq!(within_pages(5, 0, 8).count(), 0);
}
