use super::*;
use crate::host::attr::HostAttr;
use crate::host::open::reopen;
use std::fs;
use std::os::fd::{AsFd, OwnedFd};
use voidport_test_host::Scratch;

const READ_ONLY: LockAccess = LockAccess {
    read: true,
    write: false,
};
const READ_WRITE: LockAccess = LockAccess {
    read: true,
    write: true,
};

fn pin(path: &std::path::Path) -> Arc<OwnedFd> {
    Arc::new(
        rustix::fs::openat(
            rustix::fs::CWD,
            path,
            OFlags::PATH,
            rustix::fs::Mode::empty(),
        )
        .expect("the file pins"),
    )
}

fn identity(pinned: &Arc<OwnedFd>) -> NodeIdentity {
    HostAttr::of(pinned.as_fd())
        .expect("stattable")
        .node_identity()
}

fn described(pinned: &OwnedFd, flags: OFlags) -> Arc<Description> {
    Description::open(pinned.as_fd(), flags).expect("reopens")
}

fn file(scratch: &Scratch, name: &str) -> (FileLocks, Arc<Description>, OwnedFd) {
    let path = scratch.file(name, &[0u8; 64]);
    let pinned = pin(&path);
    let probe = reopen(pinned.as_fd(), OFlags::RDWR).expect("reopens");
    (
        FileLocks::default(),
        described(&pinned, OFlags::RDWR),
        probe,
    )
}

fn range(start: u64, end: u64) -> LockRange {
    LockRange::new(start, end)
}

fn taken(probe: &OwnedFd, span: LockRange) -> bool {
    test(probe.as_fd(), LockKind::Write, span)
        .expect("testable")
        .is_some()
}

#[test]
fn a_holder_locks_through_any_handle_and_never_conflicts_with_itself() {
    let scratch = Scratch::new("locks");
    let (locks, description, probe) = file(&scratch, "file");
    for _ in 0..2 {
        locks
            .place(1, LockKind::Write, range(0, 9), false, &description)
            .expect("the holder's own lock");
    }
    assert_eq!(
        locks
            .test(1, LockKind::Write, range(0, 9), &description)
            .expect("testable"),
        None,
        "a holder does not conflict with itself"
    );
    assert_eq!(
        locks
            .place(2, LockKind::Write, range(5, 6), false, &description)
            .expect_err("another holder does"),
        Errno::AGAIN
    );
    assert!(taken(&probe, range(0, 9)));

    locks.release_holder(1);
    assert!(!taken(&probe, range(0, 9)));
    assert_eq!(locks.state().holders.len(), 0);
}

#[test]
fn a_record_is_kept_only_while_its_holder_has_a_lock_or_a_wait() {
    let scratch = Scratch::new("locks");
    let (locks, description, probe) = file(&scratch, "file");
    locks
        .place(1, LockKind::Unlock, range(0, 9), false, &description)
        .expect("nothing to release");
    assert_eq!(
        locks.state().holders.len(),
        0,
        "releasing nothing opens nothing"
    );

    locks
        .place(1, LockKind::Write, range(0, 9), false, &description)
        .expect("free");
    locks
        .place(2, LockKind::Write, range(0, 9), false, &description)
        .expect_err("locked by lock holder 1");
    assert_eq!(
        locks.state().holders.len(),
        1,
        "a refused lock holder has no record"
    );

    locks
        .place(2, LockKind::Write, range(20, 29), false, &description)
        .expect("free");
    locks
        .place(2, LockKind::Write, range(0, 9), false, &description)
        .expect_err("still locked by lock holder 1");
    assert!(
        taken(&probe, range(20, 29)),
        "lock holder 2's range survives"
    );

    locks
        .place(1, LockKind::Unlock, range(0, 4), false, &description)
        .expect("releases");
    assert_eq!(locks.state().holders.len(), 2);
    locks
        .place(1, LockKind::Unlock, range(5, 9), false, &description)
        .expect("releases");
    assert_eq!(locks.state().holders.len(), 1);
    assert!(!taken(&probe, range(0, 9)));
}

#[test]
fn read_locks_move_to_the_description_the_session_opens_again() {
    let scratch = Scratch::new("locks");
    let path = scratch.file("file", &[0u8; 64]);
    let pinned = pin(&path);
    let probe = reopen(pinned.as_fd(), OFlags::RDWR).expect("reopens");
    let locks = FileLocks::default();
    let read_only = described(&pinned, OFlags::RDONLY);
    for span in [range(0, 9), range(20, 29)] {
        locks
            .place(1, LockKind::Read, span, false, &read_only)
            .expect("free");
    }
    assert_eq!(
        locks
            .place(1, LockKind::Write, range(40, 49), false, &read_only)
            .expect_err("a read-only description has no write lock"),
        Errno::BADF
    );

    let both = described(&pinned, OFlags::RDWR);
    locks.move_to(&both).expect("read locks move");
    assert!(
        test(read_only.fd(), LockKind::Write, range(0, 29))
            .expect("testable")
            .is_some(),
        "the old description is another opener's now, and meets the set's locks"
    );
    locks
        .place(1, LockKind::Write, range(40, 49), false, &both)
        .expect("the new description accepts it");
    for span in [range(0, 9), range(20, 29), range(40, 49)] {
        assert!(taken(&probe, span), "{span:?} is still the holder's");
    }
    locks
        .place(1, LockKind::Write, range(0, 9), false, &both)
        .expect("converts");
    assert!(
        test(probe.as_fd(), LockKind::Read, range(0, 9))
            .expect("testable")
            .is_some(),
        "now exclusive"
    );
}

fn waiting(locks: &FileLocks, description: &Arc<Description>, holder: u64, span: LockRange) {
    assert!(
        matches!(
            locks.place(holder, LockKind::Write, span, true, description),
            Ok(Placed::Waiting)
        ),
        "the range is locked, so the request waits"
    );
}

#[test]
fn a_waiting_request_keeps_its_record_until_it_ends() {
    let scratch = Scratch::new("locks");
    let (locks, description, probe) = file(&scratch, "file");
    locks
        .place(1, LockKind::Write, range(0, 9), false, &description)
        .expect("free");
    waiting(&locks, &description, 2, range(0, 9));
    let retry = |holder| locks.retry(holder, LockKind::Write, range(0, 9));
    assert!(!retry(2).expect("retries"));
    locks.release_holder(1);
    assert!(retry(2).expect("placed"));

    // A close of another descriptor of the lock holder releases what it has
    // locked and leaves its pending wait waiting, as it does locally.
    locks
        .place(3, LockKind::Read, range(20, 29), false, &description)
        .expect("free");
    waiting(&locks, &description, 3, range(0, 9));
    locks.release_holder(3);
    assert!(!taken(&probe, range(20, 29)), "lock holder 3's lock went");
    assert!(!retry(3).expect("waits on"));

    waiting(&locks, &description, 4, range(0, 9));
    assert_eq!(locks.state().holders.len(), 3);
    locks.abandon(4);
    assert_eq!(locks.state().holders.len(), 2);

    locks.release_holder(2);
    assert!(retry(3).expect("placed"));
}

#[test]
fn a_failed_request_leaves_the_wait_of_its_holder_alone() {
    let scratch = Scratch::new("locks");
    let (locks, description, _probe) = file(&scratch, "file");
    locks
        .place(1, LockKind::Write, range(0, 9), false, &description)
        .expect("free");
    waiting(&locks, &description, 2, range(0, 9));
    assert_eq!(
        locks
            .place(2, LockKind::Write, range(0, 9), false, &description)
            .expect_err("still held"),
        Errno::AGAIN
    );
    locks.release_holder(1);
    assert!(
        locks
            .retry(2, LockKind::Write, range(0, 9))
            .expect("placed")
    );
}

#[test]
fn a_lock_to_the_end_of_the_file_ends_at_the_kernels_last_offset() {
    let scratch = Scratch::new("locks");
    let (locks, description, _probe) = file(&scratch, "file");
    let last = u64::try_from(i64::MAX).expect("positive");
    locks
        .place(
            1,
            LockKind::Read,
            LockRange::whole_file(),
            false,
            &description,
        )
        .expect("free");
    locks
        .place(1, LockKind::Unlock, range(0, last - 1), false, &description)
        .expect("releases");
    locks
        .place(1, LockKind::Unlock, range(last, last), false, &description)
        .expect("releases");
    assert_eq!(
        locks.state().holders.len(),
        0,
        "nothing is left past the last offset"
    );
}

#[test]
fn ranges_are_kept_as_the_kernel_holds_them() {
    let scratch = Scratch::new("locks");
    let (locks, description, _probe) = file(&scratch, "file");
    let last = u64::try_from(i64::MAX).expect("positive");
    // The kernel holds a lock past its offset range at the last offset.
    locks
        .place(
            1,
            LockKind::Read,
            range(last + 1, last + 1),
            false,
            &description,
        )
        .expect("free");
    locks
        .place(1, LockKind::Unlock, range(last, last), false, &description)
        .expect("releases");
    assert_eq!(
        locks.state().holders.len(),
        0,
        "the lock holder has no lock any more"
    );
}

#[test]
fn the_last_handle_closing_releases_every_lock_a_wait_still_has() {
    let scratch = Scratch::new("locks");
    let (locks, description, probe) = file(&scratch, "file");
    let other = FileLocks::default();
    let theirs = Description::of(
        reopen(probe.as_fd(), OFlags::RDWR).expect("reopens"),
        OFlags::RDWR,
    );
    other
        .place(9, LockKind::Write, range(20, 29), false, &theirs)
        .expect("free");
    locks
        .place(1, LockKind::Write, range(0, 9), false, &description)
        .expect("free");
    waiting(&locks, &description, 1, range(20, 29));

    locks.release_all();
    assert!(
        !taken(&probe, range(0, 9)),
        "the holder's placed lock went with the file's last handle"
    );
    assert_eq!(
        locks.retry(1, LockKind::Write, range(20, 29)),
        Err(Errno::BADF)
    );
}

#[test]
fn the_union_of_the_lock_holders_locks_remains_on_the_description() {
    let scratch = Scratch::new("locks");
    let (locks, description, probe) = file(&scratch, "file");
    locks
        .place(1, LockKind::Read, range(0, 9), false, &description)
        .expect("free");
    locks
        .place(2, LockKind::Read, range(5, 14), false, &description)
        .expect("read locks of two lock holders share a range");
    assert_eq!(
        locks
            .test(3, LockKind::Write, range(7, 7), &description)
            .expect("testable")
            .map(|conflict| conflict.range),
        Some(range(0, 9)),
        "another lock holder of the session meets the first lock in the way"
    );

    locks.release_holder(1);
    assert!(!taken(&probe, range(0, 4)));
    assert!(taken(&probe, range(5, 14)));
    locks
        .place(2, LockKind::Unlock, range(5, 9), false, &description)
        .expect("releases");
    assert!(!taken(&probe, range(0, 9)) && taken(&probe, range(10, 14)));
}

#[test]
fn the_set_drops_the_description_once_it_has_no_lock() {
    let scratch = Scratch::new("locks");
    let (locks, description, probe) = file(&scratch, "file");
    locks
        .place(1, LockKind::Read, range(0, 9), false, &description)
        .expect("free");
    assert_eq!(
        Arc::strong_count(&description),
        2,
        "the set references the description its lock is on"
    );
    locks.release_holder(1);
    assert_eq!(
        Arc::strong_count(&description),
        1,
        "and drops it once it has no lock"
    );
    assert!(!taken(&probe, range(0, 9)));
}

#[test]
fn write_locks_remain_on_the_description_they_are_on() {
    let scratch = Scratch::new("locks");
    let (locks, description, probe) = file(&scratch, "file");
    locks
        .place(1, LockKind::Write, range(0, 9), false, &description)
        .expect("free");
    let again = Description::of(
        reopen(probe.as_fd(), OFlags::RDWR).expect("reopens"),
        OFlags::RDWR,
    );
    locks.move_to(&again).expect("nothing moves");
    locks
        .place(2, LockKind::Write, range(20, 29), false, &again)
        .expect("free");
    for span in [range(0, 9), range(20, 29)] {
        assert!(
            test(again.fd(), LockKind::Write, span)
                .expect("testable")
                .is_some(),
            "{span:?} is on the description the set's locks are on"
        );
        assert!(taken(&probe, span));
    }
}

#[test]
fn adjacent_ranges_of_one_kind_are_one_range() {
    let mut held = Held::default();
    held.apply(LockKind::Read, range(0, 99));
    for byte in 0..50 {
        held.apply(LockKind::Read, range(byte, byte));
    }
    assert_eq!(held.ranges, vec![(LockKind::Read, range(0, 99))]);
    held.apply(LockKind::Read, range(100, 109));
    assert_eq!(held.ranges, vec![(LockKind::Read, range(0, 109))]);
}

#[test]
fn held_ranges_follow_the_kernels_record_of_them() {
    let mut held = Held::default();
    held.apply(LockKind::Read, range(0, 99));
    held.apply(LockKind::Write, range(10, 19));
    held.apply(LockKind::Unlock, range(50, 59));
    assert_eq!(
        held.ranges,
        vec![
            (LockKind::Read, range(0, 9)),
            (LockKind::Write, range(10, 19)),
            (LockKind::Read, range(20, 49)),
            (LockKind::Read, range(60, 99)),
        ]
    );
    held.apply(LockKind::Write, LockRange::whole_file());
    assert_eq!(
        held.ranges,
        vec![(LockKind::Write, LockRange::whole_file())]
    );
    held.apply(LockKind::Unlock, range(0, 0));
    assert_eq!(held.ranges, vec![(LockKind::Write, range(1, u64::MAX))]);
    held.apply(LockKind::Unlock, LockRange::whole_file());
    assert!(held.is_empty());
}

#[test]
fn a_handle_permits_the_lock_kinds_its_access_covers() {
    let reader = LockAccess::of(OFlags::RDONLY);
    let writer = LockAccess::of(OFlags::WRONLY);
    let both = LockAccess::of(OFlags::RDWR);
    assert_eq!((reader, both), (READ_ONLY, READ_WRITE));
    assert!(reader.permits(LockKind::Read) && !reader.permits(LockKind::Write));
    assert!(!writer.permits(LockKind::Read) && writer.permits(LockKind::Write));
    assert!(both.permits(LockKind::Read) && both.permits(LockKind::Write));
    for access in [reader, writer, both] {
        assert!(
            access.permits(LockKind::Unlock),
            "releasing needs no access"
        );
    }
    assert_eq!(
        LockAccess::of(OFlags::RDONLY | OFlags::TRUNC),
        READ_ONLY,
        "truncating does not make a descriptor writable"
    );
    let neither = LockAccess::of(OFlags::WRONLY | OFlags::RDWR);
    assert!(
        !neither.permits(LockKind::Read) && !neither.permits(LockKind::Write),
        "the access mode with both bits set opens for neither"
    );
}

#[test]
fn every_handle_on_a_file_shares_its_lock_set() {
    let scratch = Scratch::new("locks");
    let path = scratch.file("file", &[0u8; 64]);
    let sets = Arc::new(LockSets::default());
    let (one, two) = (pin(&path), pin(&path));
    let first = sets.join(identity(&one));
    let second = sets.join(identity(&two));
    assert!(
        Arc::ptr_eq(first.locks(), second.locks()),
        "one set per file"
    );

    let other = pin(&scratch.file("other", &[0u8; 64]));
    assert!(!Arc::ptr_eq(
        first.locks(),
        sets.join(identity(&other)).locks()
    ));
}

#[test]
fn the_last_handle_to_leave_releases_the_set_before_another_starts() {
    let scratch = Scratch::new("locks");
    let path = scratch.file("file", &[0u8; 64]);
    let pinned = pin(&path);
    let probe = reopen(pinned.as_fd(), OFlags::RDWR).expect("reopens");
    let description = described(&pinned, OFlags::RDWR);
    let sets = Arc::new(LockSets::default());
    let first = sets.join(identity(&pinned));
    let second = sets.join(identity(&pinned));
    first
        .locks()
        .place(1, LockKind::Write, range(0, 9), false, &description)
        .expect("free");
    let old = Arc::clone(first.locks());

    drop(first);
    assert!(taken(&probe, range(0, 9)), "a handle is still open");
    drop(second);
    assert!(
        !taken(&probe, range(0, 9)),
        "the last handle released the set's locks"
    );

    let again = sets.join(identity(&pinned));
    assert!(
        !Arc::ptr_eq(&old, again.locks()),
        "a new set, not the old one"
    );
    again
        .locks()
        .place(1, LockKind::Write, range(0, 9), false, &description)
        .expect("the holder meets nothing of the old set");
}

#[test]
fn a_waiting_request_is_counted_until_it_ends() {
    let scratch = Scratch::new("locks");
    let sets = Arc::new(LockSets::default());
    let locked = |name| {
        let pinned = pin(&scratch.file(name, &[0u8; 64]));
        let joined = sets.join(identity(&pinned));
        let description = described(&pinned, OFlags::RDWR);
        joined
            .locks()
            .place(1, LockKind::Write, range(0, 9), false, &description)
            .expect("free");
        (joined, description)
    };
    let (one, one_description) = locked("one");
    let (two, two_description) = locked("two");
    waiting(one.locks(), &one_description, 2, range(0, 9));
    waiting(one.locks(), &one_description, 3, range(0, 9));
    waiting(two.locks(), &two_description, 2, range(0, 9));
    assert_eq!(sets.waiting_requests(), 3);

    one.locks().release_holder(1);
    assert!(
        one.locks()
            .retry(2, LockKind::Write, range(0, 9))
            .expect("placed")
    );
    two.locks().abandon(2);
    assert_eq!(sets.waiting_requests(), 1, "only lock holder 3 still waits");
}

#[test]
fn two_names_of_one_file_share_its_lock_set() {
    let scratch = Scratch::new("locks");
    let path = scratch.file("file", &[0u8; 64]);
    let link = path.with_file_name("link");
    fs::hard_link(&path, &link).expect("linkable");
    let sets = Arc::new(LockSets::default());
    let (one, two) = (pin(&path), pin(&link));
    assert!(Arc::ptr_eq(
        sets.join(identity(&one)).locks(),
        sets.join(identity(&two)).locks()
    ));
}
