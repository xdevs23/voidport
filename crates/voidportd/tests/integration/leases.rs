//! Whether a filesystem grants a lease depends on the filesystem, so every test
//! asks it first, on a separate file in the same directory.

use voidport_test_server as support;

use std::fs::{self, File, OpenOptions};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::path::Path;

use rustix::fs::{OFlags, inotify};
use rustix::io::Errno;
use support::Dial as _;
use support::fixture::Fixture;
use support::wire::Received;
use support::wire::{
    ROOT, ShareNotification, WireClient, decode_notification, open_request, status,
};
use voidport_proto::frame::FrameKind;
use voidport_proto::message::ResponseOutcome;
use voidport_proto::ops::file::open_flags::{KEEP_CACHE, UNCACHED};
use voidport_proto::ops::file::{FileLock, OpenResponse, ReadRequest, ReleaseRequest, lock_type};
use voidport_proto::ops::recall::{RecalledRequest, RelinquishRequest, RenewRequest};
use voidport_session::Window;
use voidportd::host::lease;
use voidportd::host::lock::{self, LockKind, LockRange};
use zerocopy::byteorder::little_endian::{U32, U64};

const DATA: &[u8] = b"0123456789";

fn leased_reply(directory: &Path) -> u32 {
    let probe = directory.join("lease-probe");
    fs::write(&probe, b"probe").expect("writable");
    let file = File::open(&probe).expect("readable");
    let granted = lease::take(file.as_fd(), lease::Kind::Read, rustix::thread::gettid()).is_ok();
    if granted {
        lease::give_up(file.as_fd());
    }
    drop(file);
    fs::remove_file(&probe).expect("removable");
    if granted { KEEP_CACHE } else { UNCACHED }
}

/// The reply of the open that gets the lease, given by `held`: it caches no pages
/// beyond its handle, so the guest drops the pages it read before the lease.
fn taken(held: u32) -> u32 {
    if held == KEEP_CACHE { 0 } else { held }
}

fn mounted(fixture: &Fixture, subscribe: bool) -> (WireClient, u64) {
    let mut guest = fixture.server.mount("plain", "/tree");
    if subscribe {
        guest.subscribe().expect("the session subscribes");
        guest.share_snapshot();
        guest.renew().expect("the window renews");
    }
    let file = guest.lookup(ROOT, "data.bin").expect("the file").node_id;
    (guest, file)
}

fn leased(fixture: &Fixture) -> (WireClient, u64) {
    assert_eq!(
        leased_reply(fixture.graft_root()),
        KEEP_CACHE,
        "the filesystem of the fixture grants a lease"
    );
    let (mut guest, file) = mounted(fixture, true);
    assert_eq!(read_reply(&mut guest, file), 0);
    assert_eq!(read_reply(&mut guest, file), KEEP_CACHE);
    (guest, file)
}

fn recall_of(guest: &mut WireClient, file: u64) -> u64 {
    let ShareNotification::Recall { node_id, recall } = guest.share_event() else {
        panic!("a lease break recalls the pages");
    };
    assert_eq!(node_id, file);
    recall
}

/// The handle is read through, which shows the server that the guest kernel
/// finished the open.
fn read_reply(guest: &mut WireClient, file: u64) -> u32 {
    let (handle, flags) = guest
        .open_replying(file, OFlags::RDONLY)
        .expect("the file opens");
    guest.read(handle, 0, 1).expect("the handle reads");
    guest.release(handle).expect("the handle releases");
    flags
}

/// Opens `path` for writing without waiting for a lease to break. The open
/// fails with `EWOULDBLOCK` while a lease is held, and starts the break.
fn host_writer(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .custom_flags(OFlags::NONBLOCK.bits() as i32)
        .open(path)
}

fn held_back(path: &Path) -> bool {
    refused(host_writer(path))
}

fn reader_held_back(path: &Path) -> bool {
    refused(
        OpenOptions::new()
            .read(true)
            .custom_flags(OFlags::NONBLOCK.bits() as i32)
            .open(path),
    )
}

fn refused(opened: io::Result<File>) -> bool {
    match opened {
        Ok(_) => false,
        Err(error) => {
            assert_eq!(Errno::from_io_error(&error), Some(Errno::WOULDBLOCK));
            true
        }
    }
}

fn writing(fixture: &Fixture) -> (WireClient, u64, u64) {
    assert_eq!(
        leased_reply(fixture.graft_root()),
        KEEP_CACHE,
        "the filesystem of the fixture grants a lease"
    );
    let (mut guest, file) = mounted(fixture, true);
    let (written, flags) = guest
        .open_replying(file, OFlags::RDWR)
        .expect("the file opens");
    assert_eq!(flags, 0, "the pages of the handle are cached");
    (guest, file, written)
}

#[test]
fn the_open_reply_relays_whether_the_file_is_leased() {
    let fixture = Fixture::start("lease-relayed");
    let path = fixture.tree("data.bin");
    let held = leased_reply(fixture.graft_root());
    let (mut guest, file) = mounted(&fixture, true);

    let writer = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("the host writer opens");
    assert_eq!(read_reply(&mut guest, file), UNCACHED);

    drop(writer);
    assert_eq!(read_reply(&mut guest, file), taken(held));
    assert_eq!(read_reply(&mut guest, file), held);
}

#[test]
fn opens_reuse_the_pages_only_after_the_guest_kernel_finished_an_open_under_the_lease() {
    let fixture = Fixture::start("lease-covered");
    let held = leased_reply(fixture.graft_root());
    let (mut guest, file) = mounted(&fixture, true);

    let (first, flags) = guest
        .open_replying(file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(flags, taken(held));
    let (second, flags) = guest
        .open_replying(file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(flags, taken(held));

    guest.read(second, 0, 1).expect("the handle reads");
    assert_eq!(read_reply(&mut guest, file), held);
    guest.release(first).expect("the handle releases");
    guest.release(second).expect("the handle releases");
}

#[test]
fn a_host_writer_waits_until_the_guest_has_dropped_the_pages() {
    let fixture = Fixture::start("lease-recalled");
    let path = fixture.tree("data.bin");
    let (mut guest, file) = leased(&fixture);

    assert!(held_back(&path), "the lease outlives the handle");
    let recall = recall_of(&mut guest, file);
    assert!(held_back(&path), "the writer waits for the reply");
    assert_eq!(
        read_reply(&mut guest, file),
        UNCACHED,
        "an open while the pages are recalled caches none"
    );

    guest.recalled(file, recall).expect("the reply is received");
    assert!(
        !held_back(&path),
        "the writer goes ahead once the guest replied"
    );
    guest
        .recalled(file, recall)
        .expect("a reply sent again is received the same way");
}

#[test]
fn a_recall_without_a_reply_is_sent_again_on_the_next_subscription() {
    let fixture = Fixture::start("lease-resent");
    let path = fixture.tree("data.bin");
    let (mut guest, file) = leased(&fixture);
    assert!(held_back(&path));
    let recall = recall_of(&mut guest, file);

    guest.unsubscribe().expect("the session unsubscribes");
    guest.subscribe().expect("the session subscribes again");
    // The recall and the snapshot are queued together, in either order.
    let (mut again, mut snapshot) = (None, false);
    while again.is_none() || !snapshot {
        match guest.share_event() {
            ShareNotification::Recall { node_id, recall } => again = Some((node_id, recall)),
            ShareNotification::SnapshotEnd => snapshot = true,
            _ => {}
        }
    }
    assert_eq!(again, Some((file, recall)));

    guest.recalled(file, recall).expect("the reply is received");
    assert!(!held_back(&path));
}

#[test]
fn a_session_without_a_subscription_is_not_leased_a_file() {
    let fixture = Fixture::start("lease-unsubscribed");
    let path = fixture.tree("data.bin");
    let (mut guest, file) = mounted(&fixture, false);

    assert_eq!(read_reply(&mut guest, file), UNCACHED);
    assert!(!held_back(&path));
}

#[test]
fn an_open_for_writing_takes_a_write_lease_once_the_read_lease_is_recalled() {
    let fixture = Fixture::start("lease-written");
    let path = fixture.tree("data.bin");
    let (mut guest, file) = leased(&fixture);

    let opening = guest.send(file, &open_request(OFlags::RDWR), &[]);
    let recall = recall_of(&mut guest, file);
    assert!(
        held_back(&path),
        "the read lease remains until the guest replies"
    );
    assert_eq!(
        read_reply(&mut guest, file),
        UNCACHED,
        "an open while the pages are recalled caches none"
    );

    // The open for writing gets its reply once the recall closed, before or
    // after the reply to the recall.
    let replying = guest.send(
        file,
        &RecalledRequest {
            recall: U64::new(recall),
        },
        &[],
    );
    let mut written = None;
    for _ in 0..2 {
        let received = guest.receive_message().expect("the server replies");
        let frame = received.parsed();
        if frame.request_id() == opening {
            let ResponseOutcome::Success(opened) =
                frame.response::<OpenResponse>().expect("an open reply")
            else {
                panic!("the file opens for writing");
            };
            written = Some((opened.body().handle.get(), opened.body().flags.get()));
        } else {
            assert_eq!(frame.request_id(), replying);
            assert_eq!(
                frame.status().expect("a reply"),
                0,
                "the reply to the recall is received"
            );
        }
    }
    let (written, flags) = written.expect("the open for writing got its reply");
    assert_eq!(flags, 0, "the pages of the written file are cached");
    assert_eq!(
        read_reply(&mut guest, file),
        0,
        "a reader of the session reads through its description"
    );

    assert!(reader_held_back(&path));
    let recall = recall_of(&mut guest, file);
    guest.recalled(file, recall).expect("the reply is received");
    assert!(
        !reader_held_back(&path),
        "the reader goes ahead once the guest replied"
    );
    let recall = recall_of(&mut guest, file);
    guest.recalled(file, recall).expect("the reply is received");
    guest.release(written).expect("the handle releases");
}

#[test]
fn a_second_open_for_writing_waits_for_the_recall_of_the_first() {
    let fixture = Fixture::start("lease-written-twice");
    let (mut guest, file) = leased(&fixture);
    let writing = open_request(OFlags::RDWR);

    let first = guest.send(file, &writing, &[]);
    let recall = recall_of(&mut guest, file);
    let second = guest.send(file, &writing, &[]);
    guest.getattr(file).expect("the server replies meanwhile");

    let replying = guest.send(
        file,
        &RecalledRequest {
            recall: U64::new(recall),
        },
        &[],
    );
    let mut replied: Vec<u64> = (0..3)
        .map(|_| {
            let received = guest.receive_message().expect("the server replies");
            let frame = received.parsed();
            assert_eq!(frame.status().expect("a reply"), 0);
            frame.request_id()
        })
        .collect();
    replied.sort_unstable();
    assert_eq!(replied, [first, second, replying]);
    guest
        .renew()
        .expect("no recall is left open, so the window renews");
}

#[test]
fn an_open_for_writing_while_the_host_has_the_file_open_is_uncached() {
    let fixture = Fixture::start("lease-written-beside");
    let path = fixture.tree("data.bin");
    assert_eq!(leased_reply(fixture.graft_root()), KEEP_CACHE);
    let (mut guest, file) = mounted(&fixture, true);

    let reader = File::open(&path).expect("the host reader opens");
    let (written, flags) = guest
        .open_replying(file, OFlags::RDWR)
        .expect("the file opens");
    assert_eq!(flags, UNCACHED);
    drop(reader);
    assert_eq!(
        read_reply(&mut guest, file),
        0,
        "the uncached writer reads and writes through the session's one \
         description, which keeps no lease from it"
    );
    guest.release(written).expect("the handle releases");
}

#[test]
fn a_handle_the_session_opened_while_it_waited_keeps_no_lease_from_its_writer() {
    let fixture = Fixture::start("lease-own-handle");
    let path = fixture.tree("data.bin");
    let (mut guest, file) = leased(&fixture);
    let (_cached, flags) = guest
        .open_replying(file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(flags, KEEP_CACHE);

    assert!(held_back(&path));
    let recall = recall_of(&mut guest, file);
    guest.recalled(file, recall).expect("the reply is received");
    let writer = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("the host writer goes ahead");
    let (beside, flags) = guest
        .open_replying(file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(
        flags, UNCACHED,
        "an open while the handles wait caches none"
    );
    let read = send_read(&mut guest, beside, 10);
    drop(writer);
    let replies = replied_and_settled(&mut guest, &[read], file);
    assert_eq!(replies[0].pieces.concat(), DATA);

    let opening = guest.send(file, &open_request(OFlags::RDWR), &[]);
    let recall = recall_of(&mut guest, file);
    let replying = guest.send(
        file,
        &RecalledRequest {
            recall: U64::new(recall),
        },
        &[],
    );
    let replies = replied_and_settled(&mut guest, &[opening, replying], file);
    let ResponseOutcome::Success(opened) = replies[0]
        .parsed()
        .response::<OpenResponse>()
        .expect("an open reply")
    else {
        panic!("the file opens for writing");
    };
    assert_eq!(opened.body().flags.get(), 0, "the pages are cached");
    assert_eq!(
        guest.read(beside, 0, 10).expect("the handle reads"),
        DATA,
        "the handles of the session go on under the write lease"
    );
    assert!(reader_held_back(&path), "nothing else may open the file");
}

#[test]
fn the_handles_of_a_writing_guest_wait_until_a_host_reader_closes_the_file() {
    let fixture = Fixture::start("lease-written-waits");
    let path = fixture.tree("data.bin");
    let (mut guest, file, written) = writing(&fixture);
    guest.write(written, 0, b"guest").expect("the guest writes");

    assert!(reader_held_back(&path));
    let recall = recall_of(&mut guest, file);
    guest.recalled(file, recall).expect("the reply is received");
    let reader = File::open(&path).expect("the host reader goes ahead");
    let mut seen = [0u8; 5];
    reader.read_exact_at(&mut seen, 0).expect("the host reads");
    assert_eq!(&seen, b"guest", "the host reads what the guest wrote");

    let (write, bytes) = guest.write_request(written, 5, b"again");
    guest.send_bytes(&bytes);
    let read = send_read(&mut guest, written, 5);
    guest.getattr(file).expect("the server replies meanwhile");

    drop(reader);
    let replies = replied_and_settled(&mut guest, &[write, read], file);
    assert_eq!(replies[0].parsed().status().expect("a reply"), 0);
    assert_eq!(replies[1].pieces.concat(), b"guest");
    assert_eq!(
        guest.read(written, 0, 64).expect("the guest reads"),
        b"guestagain"
    );
}

#[test]
fn a_cancelled_write_that_waits_for_a_host_reader_writes_nothing() {
    let fixture = Fixture::start("lease-cancelled-write");
    let path = fixture.tree("data.bin");
    let (mut guest, file, written) = writing(&fixture);
    assert!(reader_held_back(&path));
    let recall = recall_of(&mut guest, file);
    guest.recalled(file, recall).expect("the reply is received");
    let reader = File::open(&path).expect("the host reader goes ahead");

    let (write, bytes) = guest.write_request(written, 0, b"guest");
    guest.send_bytes(&bytes);
    guest.cancel(write);
    assert_eq!(guest.receive_written(), (write, Err(status::INTR)));

    drop(reader);
    let read = send_read(&mut guest, written, 64);
    assert_eq!(
        read_and_settle(&mut guest, read, file),
        DATA,
        "the cancelled write wrote nothing"
    );
}

#[test]
fn another_session_opening_the_file_recalls_the_writing_session_first() {
    let fixture = Fixture::start("lease-written-shared");
    let (mut guest, file, written) = writing(&fixture);
    guest.write(written, 0, b"first").expect("the guest writes");
    let (mut other, other_file) = mounted(&fixture, true);

    let opening = other.send(other_file, &open_request(OFlags::RDONLY), &[]);
    let recall = recall_of(&mut guest, file);
    guest.recalled(file, recall).expect("the reply is received");
    let opened = other.receive_message().expect("the open receives a reply");
    let frame = opened.parsed();
    assert_eq!(frame.request_id(), opening);
    let ResponseOutcome::Success(opened) = frame.response::<OpenResponse>().expect("an open reply")
    else {
        panic!("the other session opens the file");
    };
    let handle = opened.body().handle.get();
    assert_eq!(
        opened.body().flags.get(),
        0,
        "the writing session's handles wait, so the other session is leased \
         the file"
    );
    assert_eq!(
        other.read(handle, 0, 5).expect("the other session reads"),
        b"first"
    );

    let read = send_read(&mut guest, written, 5);
    guest.getattr(file).expect("the server replies meanwhile");
    let released = send_release(&mut other, handle);
    replied_and_settled(&mut other, &[released], other_file);
    let replies = replied_and_settled(&mut guest, &[read], file);
    assert_eq!(replies[0].pieces.concat(), b"first");
}

#[test]
fn a_handle_opened_while_the_cached_handles_wait_goes_on_once_they_are_released() {
    let fixture = Fixture::start("lease-wait-ends");
    let path = fixture.tree("data.bin");
    let (mut guest, file, cached) = writing(&fixture);

    assert!(held_back(&path));
    let recall = recall_of(&mut guest, file);
    guest.recalled(file, recall).expect("the reply is received");
    let writer = host_writer(&path).expect("the host writer goes ahead");
    let (mut other, other_file) = mounted(&fixture, true);
    let (reading, flags) = other
        .open_replying(other_file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(flags, UNCACHED);
    drop(writer);

    // The description of the other session stops the lease from going to the
    // cached handle, so a write of a handle opened meanwhile waits for it.
    let (again, flags) = guest
        .open_replying(file, OFlags::RDWR)
        .expect("the file opens");
    assert_eq!(
        flags, UNCACHED,
        "an open while the cached handles wait caches none"
    );
    let (write, bytes) = guest.write_request(again, 0, b"guest");
    guest.send_bytes(&bytes);
    guest.getattr(file).expect("the server replies meanwhile");

    let released = send_release(&mut guest, cached);
    assert_eq!(statuses(&mut guest, &[write, released]), [0, 0]);
    assert_eq!(
        other.read(reading, 0, 5).expect("the other session reads"),
        b"guest"
    );
}

#[test]
fn two_sessions_that_read_the_file_hand_it_over_to_the_one_that_writes() {
    let fixture = Fixture::start("lease-two-sessions");
    let (mut first, file) = leased(&fixture);
    let (cached, flags) = first
        .open_replying(file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(flags, KEEP_CACHE);
    let (mut second, second_file) = leased(&fixture);
    let (reading, flags) = second
        .open_replying(second_file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(flags, KEEP_CACHE, "both sessions have a read lease");

    let opening = first.send(file, &open_request(OFlags::RDWR), &[]);
    let recall = recall_of(&mut second, second_file);
    second
        .recalled(second_file, recall)
        .expect("the reply is received");
    let recall = recall_of(&mut first, file);
    let replying = first.send(
        file,
        &RecalledRequest {
            recall: U64::new(recall),
        },
        &[],
    );
    let replies = replied_and_settled(&mut first, &[opening, replying], file);
    let ResponseOutcome::Success(opened) = replies[0]
        .parsed()
        .response::<OpenResponse>()
        .expect("an open reply")
    else {
        panic!("the file opens for writing");
    };
    assert_eq!(
        opened.body().flags.get(),
        0,
        "the writing session is leased the file"
    );
    let written = opened.body().handle.get();
    first
        .write(written, 0, b"first")
        .expect("the session writes");
    assert_eq!(
        first.read(cached, 0, 5).expect("the session reads"),
        b"first"
    );

    let read = send_read(&mut second, reading, 5);
    second
        .getattr(second_file)
        .expect("the server replies meanwhile");
    first.release(written).expect("the handle releases");
    let released = send_release(&mut first, cached);
    replied_and_settled(&mut first, &[released], file);
    let replies = replied_and_settled(&mut second, &[read], second_file);
    assert_eq!(replies[0].pieces.concat(), b"first");
}

#[test]
fn the_locks_of_a_writing_guest_hold_against_host_processes() {
    let fixture = Fixture::start("lease-written-locks");
    let path = fixture.tree("data.bin");
    let (mut guest, file, written) = writing(&fixture);
    let lock = FileLock {
        start: U64::ZERO,
        end: U64::new(9),
        owner: U64::new(1),
        pid: U32::new(1),
        lock_type: U32::new(lock_type::WRITE),
    };
    guest.setlk(written, lock, false).expect("the guest locks");
    assert!(
        reader_held_back(&path),
        "the lock lies on the description under the write lease"
    );

    let recall = recall_of(&mut guest, file);
    guest.recalled(file, recall).expect("the reply is received");
    let reader = File::open(&path).expect("the host reader goes ahead");
    let conflict = lock::test(reader.as_fd(), LockKind::Read, LockRange::new(0, 9))
        .expect("the host tests the lock");
    assert_eq!(
        conflict.map(|conflict| conflict.kind),
        Some(LockKind::Write),
        "the guest's lock still applies against a host process after the lease broke"
    );
}

#[test]
fn appends_of_a_writing_guest_land_at_the_end_of_the_file() {
    let fixture = Fixture::start("lease-written-appends");
    let path = fixture.tree("data.bin");
    let (mut guest, file, written) = writing(&fixture);
    let appending = guest
        .open(file, OFlags::RDWR | OFlags::APPEND)
        .expect("the file opens to append");

    guest
        .write(appending, 0, b"tail")
        .expect("the guest appends");
    assert_eq!(
        fs::metadata(&path).expect("the file stats").len(),
        (DATA.len() + 4) as u64
    );
    assert_eq!(
        guest
            .read(written, 0, 64)
            .expect("the guest reads the file"),
        [DATA, b"tail"].concat()
    );
}

#[test]
fn a_lease_tried_again_while_a_host_reader_stays_opens_and_closes_nothing() {
    let fixture = Fixture::start("lease-tried-quietly");
    let path = fixture.tree("data.bin");
    let (mut guest, file, written) = writing(&fixture);
    assert!(reader_held_back(&path));
    let recall = recall_of(&mut guest, file);
    guest.recalled(file, recall).expect("the reply is received");
    let reader = File::open(&path).expect("the host reader goes ahead");

    // From here on the host kernel reports every open of the file, and every
    // close of a description open for writing, which only the server has.
    let seen = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK)
        .expect("an inotify instance");
    inotify::add_watch(
        &seen,
        &path,
        inotify::WatchFlags::OPEN | inotify::WatchFlags::CLOSE_WRITE,
    )
    .expect("the file is watched");

    // A second host reader opens and closes the file, and a read of the
    // session waits: both try the lease again, which the first reader has
    // and the server does not get.
    drop(File::open(&path).expect("a second host reader opens"));
    let read = send_read(&mut guest, written, 5);
    guest.getattr(file).expect("the server replies meanwhile");

    drop(reader);
    let replies = replied_and_settled(&mut guest, &[read], file);
    assert_eq!(replies[0].pieces.concat(), &DATA[..5]);
    assert_eq!(
        events(&seen),
        [inotify::ReadFlags::OPEN],
        "the host kernel saw the open of the second reader, and no open or close by the server"
    );
}

fn events(inotify: &OwnedFd) -> Vec<inotify::ReadFlags> {
    let mut buffer = [MaybeUninit::<u8>::uninit(); 4096];
    let mut reader = inotify::Reader::new(inotify, &mut buffer);
    let mut events = Vec::new();
    loop {
        match reader.next() {
            Ok(event) => events.push(event.events()),
            Err(Errno::AGAIN) => return events,
            Err(errno) => panic!("the events of the file cannot be read: {errno}"),
        }
    }
}

fn send_read(guest: &mut WireClient, handle: u64, size: u32) -> u64 {
    guest.send(
        0,
        &ReadRequest {
            handle: U64::new(handle),
            offset: U64::ZERO,
            size: U32::new(size),
            flags: U32::ZERO,
        },
        &[],
    )
}

fn send_release(guest: &mut WireClient, handle: u64) -> u64 {
    guest.send(
        0,
        &ReleaseRequest {
            handle: U64::new(handle),
            lock_owner: U64::ZERO,
            flags: U32::ZERO,
            release_flags: U32::ZERO,
        },
        &[],
    )
}

fn statuses(guest: &mut WireClient, requests: &[u64]) -> Vec<i32> {
    let mut statuses = vec![0; requests.len()];
    for _ in requests {
        let received = guest.receive_message().expect("the server replies");
        let frame = received.parsed();
        let at = requests
            .iter()
            .position(|request| *request == frame.request_id())
            .expect("a reply to one of the requests");
        statuses[at] = frame.status().expect("a reply");
    }
    statuses
}

fn replied_and_settled(guest: &mut WireClient, requests: &[u64], file: u64) -> Vec<Received> {
    let mut replies: Vec<Option<Received>> = requests.iter().map(|_| None).collect();
    let mut recall = None;
    while recall.is_none() || replies.iter().any(Option::is_none) {
        let received = guest.receive_message().expect("the server sends");
        let frame = received.parsed();
        if frame.kind() == FrameKind::Notification {
            let ShareNotification::Recall {
                node_id,
                recall: id,
            } = decode_notification(&received)
            else {
                panic!("the lease gained again recalls the pages");
            };
            assert_eq!(node_id, file);
            recall = Some(id);
        } else {
            let at = requests
                .iter()
                .position(|request| *request == frame.request_id())
                .expect("a reply to one of the requests");
            replies[at] = Some(received);
        }
    }
    let recall = recall.expect("a recall");
    guest.recalled(file, recall).expect("the reply is received");
    replies.into_iter().flatten().collect()
}

fn read_and_settle(guest: &mut WireClient, read: u64, file: u64) -> Vec<u8> {
    let mut replies = replied_and_settled(guest, &[read], file);
    replies.remove(0).pieces.concat()
}

#[test]
fn a_cached_handle_reads_once_the_host_writer_has_closed_the_file() {
    let fixture = Fixture::start("lease-waited");
    let path = fixture.tree("data.bin");
    assert_eq!(leased_reply(fixture.graft_root()), KEEP_CACHE);
    let (mut guest, file) = mounted(&fixture, true);
    let writer = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("the host writer opens");
    let (uncached, flags) = guest
        .open_replying(file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(flags, UNCACHED);
    drop(writer);
    assert_eq!(read_reply(&mut guest, file), 0);
    let (cached, flags) = guest
        .open_replying(file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(flags, KEEP_CACHE);

    assert!(held_back(&path));
    let recall = recall_of(&mut guest, file);
    guest.recalled(file, recall).expect("the reply is received");
    let writer = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("the host writer goes ahead");
    writer.write_all_at(b"written", 0).expect("the host writes");
    let (joined, flags) = guest
        .open_replying(file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(
        flags, UNCACHED,
        "an open while the cached handles wait caches none"
    );

    let read = send_read(&mut guest, cached, 7);
    // A private mapping of the uncached handle would read into the pages the
    // cached handle reads from, so its reads wait too.
    let beside = send_read(&mut guest, uncached, 7);
    let joining = send_read(&mut guest, joined, 7);
    guest.getattr(file).expect("the server replies meanwhile");

    drop(writer);
    let replies = replied_and_settled(&mut guest, &[read, beside, joining], file);
    for reply in &replies {
        assert_eq!(reply.pieces.concat(), b"written");
    }
    guest.release(joined).expect("the handle releases");
    guest.release(uncached).expect("the handle releases");
    assert_eq!(
        read_reply(&mut guest, file),
        KEEP_CACHE,
        "the file is leased again"
    );
}

#[test]
fn a_cached_handle_reads_once_a_host_truncate_by_path_is_done() {
    let fixture = Fixture::start("lease-truncated");
    let path = fixture.tree("data.bin");
    let (mut guest, file) = leased(&fixture);
    let (cached, flags) = guest
        .open_replying(file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(flags, KEEP_CACHE);

    // A truncate by path opens nothing, so no close ever follows it.
    let truncated =
        std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("a path without NUL");
    let truncating = std::thread::spawn(move || {
        // SAFETY: Unavoidable: `File::set_len` of std and `ftruncate` of rustix,
        // the safe forms, truncate through a descriptor, and an open is what
        // this test leaves out. The path is a NUL-terminated string that
        // outlives the call.
        let result = unsafe { libc::truncate(truncated.as_ptr(), 3) };
        assert_eq!(result, 0, "the host truncates the file");
    });
    let recall = recall_of(&mut guest, file);
    guest.recalled(file, recall).expect("the reply is received");
    truncating.join().expect("the truncate returns");

    let read = send_read(&mut guest, cached, 64);
    let bytes = read_and_settle(&mut guest, read, file);
    assert_eq!(bytes.len(), 3, "the read sees the truncated file");
}

#[test]
fn a_renewal_grants_the_window_the_lease_break_time_leaves() {
    let fixture = Fixture::start("lease-window");
    let (mut guest, _) = mounted(&fixture, true);
    let break_time = lease::break_time().expect("the lease break time");

    assert_eq!(
        guest.renew().expect("the window renews"),
        Window::to_nanos(Window::of(break_time))
    );
}

#[test]
fn a_session_that_never_renewed_is_not_leased_a_file() {
    let fixture = Fixture::start("lease-unrenewed");
    let path = fixture.tree("data.bin");
    let mut guest = fixture.server.mount("plain", "/tree");
    guest.subscribe().expect("the session subscribes");
    guest.share_snapshot();
    let file = guest.lookup(ROOT, "data.bin").expect("the file").node_id;

    assert_eq!(read_reply(&mut guest, file), UNCACHED);
    assert!(!held_back(&path));
}

#[test]
fn a_renewal_waits_until_the_open_recalls_are_replied_to() {
    let fixture = Fixture::start("lease-renewal-waits");
    let path = fixture.tree("data.bin");
    let (mut guest, file) = leased(&fixture);
    assert!(held_back(&path));
    let recall = recall_of(&mut guest, file);

    let renewal = guest.send(0, &RenewRequest::default(), &[]);
    guest.getattr(file).expect("the server replies meanwhile");

    let reply = guest.send(
        file,
        &RecalledRequest {
            recall: U64::new(recall),
        },
        &[],
    );
    let mut replies = [0; 2].map(|_| {
        let reply = guest.receive_message().expect("the server replies");
        assert_eq!(reply.parsed().status().expect("a reply"), 0);
        reply.parsed().request_id()
    });
    replies.sort_unstable();
    assert_eq!(replies, [renewal, reply]);
}

#[test]
fn a_lease_outlives_the_session_of_the_guest_caching_the_pages() {
    let fixture = Fixture::start("lease-lingers");
    let path = fixture.tree("data.bin");
    let (guest, _) = leased(&fixture);

    guest.disconnect(&fixture.server);
    assert!(
        held_back(&path),
        "the pages may still be cached until the window has passed"
    );
}

#[test]
fn a_relinquish_gives_up_at_once_a_lease_whose_recall_has_no_reply() {
    let fixture = Fixture::start("lease-relinquished");
    let path = fixture.tree("data.bin");
    let (mut guest, file) = leased(&fixture);
    assert!(
        held_back(&path),
        "a host writer waits while the guest may cache the pages"
    );
    recall_of(&mut guest, file);

    guest.relinquish().expect("the server gives the leases up");
    assert!(
        !held_back(&path),
        "the lease went without a reply to its recall"
    );
    assert_eq!(read_reply(&mut guest, file), UNCACHED);
    assert_eq!(guest.renew(), Ok((0, 0)), "a renewal grants no window");
}

#[test]
fn a_relinquish_gives_up_at_once_a_lease_held_for_cached_handles() {
    let fixture = Fixture::start("lease-relinquished-held");
    let path = fixture.tree("data.bin");
    let (mut guest, file) = leased(&fixture);
    let (cached, flags) = guest
        .open_replying(file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(flags, KEEP_CACHE);

    guest.relinquish().expect("the server gives the leases up");
    assert!(!held_back(&path), "the lease went without a recall");
    assert_eq!(
        guest.read(cached, 0, 1),
        Err(status::IO),
        "a handle that caches pages fails, since nothing bounds them"
    );
}

#[test]
fn a_relinquish_fails_the_requests_that_wait_for_a_host_writer() {
    let fixture = Fixture::start("lease-relinquished-waiting");
    let path = fixture.tree("data.bin");
    let (mut guest, file) = leased(&fixture);
    let (cached, flags) = guest
        .open_replying(file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(flags, KEEP_CACHE);
    assert!(held_back(&path));
    let recall = recall_of(&mut guest, file);
    guest.recalled(file, recall).expect("the reply is received");
    let _writer = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("the host writer goes ahead");

    let read = send_read(&mut guest, cached, 1);
    guest.getattr(file).expect("the server replies meanwhile");
    let relinquishing = guest.send(0, &RelinquishRequest::default(), &[]);
    assert_eq!(
        statuses(&mut guest, &[read, relinquishing]),
        [status::IO, 0],
        "the read fails, since the host writer may never be watched again"
    );
}

#[test]
fn an_open_after_a_relinquish_does_not_get_a_lease() {
    let fixture = Fixture::start("lease-relinquished-open");
    let path = fixture.tree("data.bin");
    let (mut guest, file) = leased(&fixture);

    guest.relinquish().expect("the server gives the leases up");
    assert!(!held_back(&path), "the lease went without a recall");
    assert_eq!(read_reply(&mut guest, file), UNCACHED);
    assert!(!held_back(&path), "the open did not take a lease");
}

#[test]
fn a_read_after_a_relinquish_waits_for_the_release_of_a_handle_that_cached_pages() {
    let fixture = Fixture::start("lease-relinquished-released-late");
    let (mut guest, file) = leased(&fixture);
    let (cached, flags) = guest
        .open_replying(file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(flags, KEEP_CACHE);
    guest.relinquish().expect("the server gives the leases up");
    let (uncached, flags) = guest
        .open_replying(file, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(flags, UNCACHED);

    let read = send_read(&mut guest, uncached, 1);
    guest.getattr(file).expect("the server replies meanwhile");
    let released = send_release(&mut guest, cached);
    assert_eq!(
        statuses(&mut guest, &[read, released]),
        [0, 0],
        "the read goes on once no handle caches the pages"
    );
}
