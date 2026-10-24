//! What the tests of the guest page cache share.

use voidport_test_client as support;

use std::fs::{self, File};
use std::os::fd::AsFd as _;
use std::os::unix::fs::FileExt as _;
use std::time::Duration;

use support::Fixture;
use voidport::mount::MountOptions;
use voidportd::host::lease;

pub(crate) const PAGE: usize = 4096;

/// Reads from an already-open descriptor with `pread`: reopening the path would
/// issue a `lookup` and a fresh `open`.
pub(crate) fn page_at_zero(file: &File) -> Vec<u8> {
    let mut page = vec![0u8; PAGE];
    file.read_exact_at(&mut page, 0).expect("the page reads");
    page
}

pub(crate) fn require_leases(fixture: &Fixture) {
    let probe = fixture.host("tree").join("lease-probe");
    fs::write(&probe, b"probe").expect("writable");
    let file = File::open(&probe).expect("readable");
    let granted = lease::take(file.as_fd(), lease::Kind::Read, rustix::thread::gettid()).is_ok();
    if granted {
        lease::give_up(file.as_fd());
    }
    drop(file);
    fs::remove_file(&probe).expect("removable");
    assert!(granted, "the filesystem of the fixture grants a lease");
}

pub(crate) fn cached_for_an_hour() -> MountOptions {
    MountOptions {
        attr_timeout: Duration::from_secs(3600),
        entry_timeout: Duration::from_secs(3600),
        ..MountOptions::default()
    }
}
