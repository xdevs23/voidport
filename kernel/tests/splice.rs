// SPDX-License-Identifier: GPL-2.0

#[path = "../voidport/splice.rs"]
mod splice;

use splice::stamp_retained;

fn stamped(dentry: *mut u8, spliced: Result<*mut u8, ()>) -> Option<*mut u8> {
    let mut stamped = None;
    stamp_retained(dentry, spliced, |retained| stamped = Some(retained));
    stamped
}

#[test]
fn an_alias_is_stamped_in_place_of_the_dentry() {
    let (mut dentry, mut alias) = (0u8, 0u8);
    assert_eq!(
        stamped(&raw mut dentry, Ok(&raw mut alias)),
        Some(&raw mut alias)
    );
}

#[test]
fn the_dentry_is_stamped_when_the_splice_returns_no_alias() {
    let mut dentry = 0u8;
    assert_eq!(
        stamped(&raw mut dentry, Ok(core::ptr::null_mut())),
        Some(&raw mut dentry)
    );
}

#[test]
fn a_failed_splice_stamps_nothing() {
    let mut dentry = 0u8;
    assert_eq!(stamped(&raw mut dentry, Err(())), None);
}
