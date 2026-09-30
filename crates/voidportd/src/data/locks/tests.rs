use super::*;
use crate::host::attr::HostAttr;
use crate::testing::Scratch;
use std::fs;

const READ_ONLY: LockAccess = LockAccess {
    read: true,
    write: false,
};
const READ_WRITE: LockAccess = LockAccess {
    read: true,
    write: true,
};
const WRITE_ONLY: LockAccess = LockAccess {
    read: false,
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

/// A lock set over a fresh file, and a description of that file that carries
/// no locks, to ask what another owner would see.
fn file(scratch: &Scratch, name: &str) -> (FileLocks, OwnedFd) {
    let path = scratch.file(name, &[0u8; 64]);
    let pinned = pin(&path);
    let probe = reopen(pinned.as_fd(), OFlags::RDWR).expect("reopens");
    (FileLocks::new(pinned), probe)
}

fn range(start: u64, end: u64) -> LockRange {
    LockRange::new(start, end)
}

/// Whether a description that holds nothing would be refused a write lock on
/// `span`.
fn taken(probe: &OwnedFd, span: LockRange) -> bool {
    test(probe.as_fd(), LockKind::Write, span)
        .expect("testable")
        .is_some()
}

#[test]
fn an_owner_locks_through_any_handle_and_never_conflicts_with_itself() {
    let scratch = Scratch::new("locks");
    let (locks, probe) = file(&scratch, "file");
    for _ in 0..2 {
        locks
            .place(1, LockKind::Write, range(0, 9), READ_WRITE, false)
            .expect("the owner's own lock");
    }
    assert_eq!(
        locks
            .test(1, LockKind::Write, range(0, 9), probe.as_fd())
            .expect("testable"),
        None,
        "an owner does not conflict with itself"
    );
    assert_eq!(
        locks
            .place(2, LockKind::Write, range(5, 6), READ_WRITE, false)
            .expect_err("another owner does"),
        Errno::AGAIN
    );
    assert!(taken(&probe, range(0, 9)));

    // Releasing the owner releases its locks, and only its record.
    locks.release_owner(1);
    assert!(!taken(&probe, range(0, 9)));
    assert_eq!(locks.lock_owners(), 0);
}

#[test]
fn a_record_is_kept_only_while_its_owner_holds_something() {
    let scratch = Scratch::new("locks");
    let (locks, probe) = file(&scratch, "file");
    locks
        .place(1, LockKind::Unlock, range(0, 9), READ_WRITE, false)
        .expect("nothing to release");
    assert_eq!(locks.lock_owners(), 0, "releasing nothing opens nothing");

    locks
        .place(1, LockKind::Write, range(0, 9), READ_WRITE, false)
        .expect("free");
    locks
        .place(2, LockKind::Write, range(0, 9), READ_WRITE, false)
        .expect_err("held by owner 1");
    assert_eq!(locks.lock_owners(), 1, "a refused owner keeps no record");

    // A refusal of an owner that holds another range keeps that range.
    locks
        .place(2, LockKind::Write, range(20, 29), READ_WRITE, false)
        .expect("free");
    locks
        .place(2, LockKind::Write, range(0, 9), READ_WRITE, false)
        .expect_err("still held by owner 1");
    assert!(taken(&probe, range(20, 29)), "owner 2's range survives");

    // Unlocking what an owner holds, piece by piece, closes its record at the
    // end.
    locks
        .place(1, LockKind::Unlock, range(0, 4), READ_WRITE, false)
        .expect("releases");
    assert_eq!(locks.lock_owners(), 2);
    locks
        .place(1, LockKind::Unlock, range(5, 9), READ_WRITE, false)
        .expect("releases");
    assert_eq!(locks.lock_owners(), 1);
    assert!(!taken(&probe, range(0, 9)));
}

#[test]
fn a_read_only_description_widens_and_keeps_every_range_it_held() {
    let scratch = Scratch::new("locks");
    let (locks, probe) = file(&scratch, "file");
    locks
        .place(1, LockKind::Read, range(0, 9), READ_ONLY, false)
        .expect("free");
    locks
        .place(1, LockKind::Read, range(20, 29), READ_ONLY, false)
        .expect("free");
    assert_eq!(
        locks
            .place(1, LockKind::Write, range(40, 49), READ_ONLY, false)
            .expect_err("a read-only description carries no write lock"),
        Errno::BADF
    );

    // Through a writable handle the description widens, and the owner's read
    // locks come with it.
    locks
        .place(1, LockKind::Write, range(40, 49), READ_WRITE, false)
        .expect("the widened description takes it");
    for span in [range(0, 9), range(20, 29), range(40, 49)] {
        assert!(taken(&probe, span), "{span:?} is still the owner's");
    }
    // And the owner's read lock converts to a write lock in place.
    locks
        .place(1, LockKind::Write, range(0, 9), READ_WRITE, false)
        .expect("converts");
    assert!(
        test(probe.as_fd(), LockKind::Read, range(0, 9))
            .expect("testable")
            .is_some(),
        "now exclusive"
    );
}

#[test]
fn a_waiting_request_keeps_its_record_until_it_ends() {
    let scratch = Scratch::new("locks");
    let (locks, probe) = file(&scratch, "file");
    locks
        .place(1, LockKind::Write, range(0, 9), READ_WRITE, false)
        .expect("free");
    let Placed::Waiting(record) = locks
        .place(2, LockKind::Write, range(0, 9), READ_WRITE, true)
        .expect("waits")
    else {
        panic!("the range is held, so the request waits");
    };
    assert!(!record.retry(LockKind::Write, range(0, 9)).expect("retries"));
    locks.release_owner(1);
    assert!(record.retry(LockKind::Write, range(0, 9)).expect("placed"));

    // A close of another of the owner's descriptors releases what the owner
    // holds and leaves its pending wait waiting, as it does locally.
    locks
        .place(3, LockKind::Read, range(20, 29), READ_WRITE, false)
        .expect("free");
    let Placed::Waiting(pending) = locks
        .place(3, LockKind::Write, range(0, 9), READ_WRITE, true)
        .expect("waits")
    else {
        panic!("owner 2 holds the range");
    };
    locks.release_owner(3);
    assert!(!taken(&probe, range(20, 29)), "owner 3's lock went");
    assert!(
        !pending
            .retry(LockKind::Write, range(0, 9))
            .expect("waits on")
    );

    // A cancelled wait that held nothing leaves no record behind.
    let Placed::Waiting(cancelled) = locks
        .place(4, LockKind::Write, range(0, 9), READ_WRITE, true)
        .expect("waits")
    else {
        panic!("owner 2 holds the range");
    };
    assert_eq!(locks.lock_owners(), 3);
    locks.abandon(4, &cancelled);
    assert_eq!(locks.lock_owners(), 2);

    // The wait that survived the close is granted once the range frees.
    locks.release_owner(2);
    assert!(pending.retry(LockKind::Write, range(0, 9)).expect("placed"));
}

#[test]
fn a_refused_request_leaves_its_owners_wait_alone() {
    let scratch = Scratch::new("locks");
    let (locks, _probe) = file(&scratch, "file");
    locks
        .place(1, LockKind::Write, range(0, 9), READ_WRITE, false)
        .expect("free");
    let Placed::Waiting(record) = locks
        .place(2, LockKind::Write, range(0, 9), READ_WRITE, true)
        .expect("waits")
    else {
        panic!("the range is held, so the request waits");
    };
    // Another request of the waiting owner is refused without waiting, and
    // the record the wait holds stays open.
    assert_eq!(
        locks
            .place(2, LockKind::Write, range(0, 9), READ_WRITE, false)
            .expect_err("still held"),
        Errno::AGAIN
    );
    locks.release_owner(1);
    assert!(record.retry(LockKind::Write, range(0, 9)).expect("placed"));
}

#[test]
fn a_lock_to_the_end_of_the_file_ends_at_the_kernels_last_offset() {
    let scratch = Scratch::new("locks");
    let (locks, _probe) = file(&scratch, "file");
    let last = u64::try_from(i64::MAX).expect("positive");
    locks
        .place(1, LockKind::Read, LockRange::whole_file(), READ_ONLY, false)
        .expect("free");
    locks
        .place(1, LockKind::Unlock, range(0, last - 1), READ_ONLY, false)
        .expect("releases");
    locks
        .place(1, LockKind::Unlock, range(last, last), READ_ONLY, false)
        .expect("releases");
    assert_eq!(
        locks.lock_owners(),
        0,
        "nothing is left past the last offset"
    );
}

#[test]
fn ranges_are_kept_as_the_kernel_holds_them() {
    let scratch = Scratch::new("locks");
    let (locks, _probe) = file(&scratch, "file");
    let last = u64::try_from(i64::MAX).expect("positive");
    // The kernel holds a lock past its offset range at the last offset.
    locks
        .place(
            1,
            LockKind::Read,
            range(last + 1, last + 1),
            READ_ONLY,
            false,
        )
        .expect("free");
    locks
        .place(1, LockKind::Unlock, range(last, last), READ_ONLY, false)
        .expect("releases");
    assert_eq!(locks.lock_owners(), 0, "the owner holds nothing any more");
}

#[test]
fn a_write_only_handle_gets_a_description_that_also_reads() {
    let scratch = Scratch::new("locks");
    let (locks, probe) = file(&scratch, "file");
    locks
        .place(1, LockKind::Write, range(0, 9), WRITE_ONLY, false)
        .expect("free");
    // A read lock through a readable handle needs no wider description, so
    // the write lock never has to move.
    locks
        .place(1, LockKind::Read, range(20, 29), READ_ONLY, false)
        .expect("the description reads too");
    assert!(taken(&probe, range(0, 9)) && taken(&probe, range(20, 29)));
}

#[test]
fn the_last_handle_closing_releases_every_lock_a_wait_still_holds() {
    let scratch = Scratch::new("locks");
    let (locks, probe) = file(&scratch, "file");
    let other = FileLocks::new(Arc::clone(&locks.pinned));
    other
        .place(9, LockKind::Write, range(20, 29), READ_WRITE, false)
        .expect("free");
    locks
        .place(1, LockKind::Write, range(0, 9), READ_WRITE, false)
        .expect("free");
    let Placed::Waiting(record) = locks
        .place(1, LockKind::Write, range(20, 29), READ_WRITE, true)
        .expect("waits")
    else {
        panic!("another session holds the range");
    };

    drop(locks);
    assert!(
        !taken(&probe, range(0, 9)),
        "the owner's placed lock went with the file's last handle"
    );
    assert_eq!(
        record.retry(LockKind::Write, range(20, 29)),
        Err(Errno::BADF)
    );
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
    let first = sets.join(identity(&one), &one);
    let second = sets.join(identity(&two), &two);
    assert!(
        Arc::ptr_eq(first.locks(), second.locks()),
        "one set per file"
    );

    let other = pin(&scratch.file("other", &[0u8; 64]));
    assert!(!Arc::ptr_eq(
        first.locks(),
        sets.join(identity(&other), &other).locks()
    ));
}

#[test]
fn the_last_handle_to_leave_releases_the_set_before_another_starts() {
    let scratch = Scratch::new("locks");
    let path = scratch.file("file", &[0u8; 64]);
    let pinned = pin(&path);
    let probe = reopen(pinned.as_fd(), OFlags::RDWR).expect("reopens");
    let sets = Arc::new(LockSets::default());
    let first = sets.join(identity(&pinned), &pinned);
    let second = sets.join(identity(&pinned), &pinned);
    first
        .locks()
        .place(1, LockKind::Write, range(0, 9), READ_WRITE, false)
        .expect("free");
    let old = Arc::clone(first.locks());

    drop(first);
    assert!(taken(&probe, range(0, 9)), "a handle is still open");
    drop(second);
    assert!(
        !taken(&probe, range(0, 9)),
        "the last handle released the set's locks"
    );

    let again = sets.join(identity(&pinned), &pinned);
    assert!(
        !Arc::ptr_eq(&old, again.locks()),
        "a new set, not the old one"
    );
    again
        .locks()
        .place(1, LockKind::Write, range(0, 9), READ_WRITE, false)
        .expect("the owner meets nothing of the old set");
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
        sets.join(identity(&one), &one).locks(),
        sets.join(identity(&two), &two).locks()
    ));
}
