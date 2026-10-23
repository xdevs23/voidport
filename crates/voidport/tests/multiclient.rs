//! Runs as root, which is what a guest's `root` is in this model.

#![forbid(unsafe_code)]

use voidport_test_client as support;

use std::fs;
use std::io::Write as _;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::sync::Barrier;
use support::{Fixture, errno};

/// Fixed, so the host file can be cut back into records with no framing: a
/// chunk that is not one of the records anybody wrote is a torn write.
const RECORD: usize = 64;

const RECORDS: usize = 300;

fn record(client: u8, index: usize) -> Vec<u8> {
    let text = format!("client-{client} record {index:06}");
    let mut bytes = text.into_bytes();
    assert!(bytes.len() < RECORD, "the record has to fit its slot");
    bytes.resize(RECORD - 1, b'.');
    bytes.push(b'\n');
    bytes
}

/// `create` decides which server operation opens the handle: a plain `open`, or
/// the `create` that opens and creates in one round trip. Both have to carry
/// the append flag to the host, on separate code paths.
fn append_records(path: &Path, client: u8, start: &Barrier, create: bool) {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(create)
        .open(path)
        .expect("appendable");
    // Both clients hold their handle before either writes, so the whole run is
    // contended.
    start.wait();
    for index in 0..RECORDS {
        file.write_all(&record(client, index)).expect("writable");
    }
    file.flush().expect("flushable");
}

fn records_of(contents: &[u8]) -> Vec<&[u8]> {
    assert_eq!(
        contents.len() % RECORD,
        0,
        "the file does not divide into whole records: {} bytes",
        contents.len()
    );
    contents.chunks(RECORD).collect()
}

/// The guest kernel picks the offset of every append from its cached size, and
/// with two mounts that size is stale by construction. If the server honoured
/// that offset, records would overwrite each other. The handle is opened
/// `O_APPEND` on the host, so the host kernel puts every write at the true end
/// of the file. The check is made against the host file, because the question
/// is what was stored.
#[test]
fn two_mounts_appending_to_one_file_lose_nothing_and_tear_nothing() {
    support::preflight();
    let fixture = Fixture::start("append-race");
    let first = fixture.mount("append-a", "plain", "/tree");
    let second = fixture.mount("append-b", "plain", "/tree");

    let host = fixture.host("tree/log");
    fs::write(&host, b"").expect("writable");
    assert_eq!(fs::metadata(first.path("log")).expect("stat").len(), 0);
    assert_eq!(fs::metadata(second.path("log")).expect("stat").len(), 0);

    let start = Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| append_records(&first.path("log"), b'a', &start, false));
        scope.spawn(|| append_records(&second.path("log"), b'b', &start, false));
    });

    let stored = fs::read(&host).expect("the host has the file");
    assert_eq!(
        stored.len(),
        2 * RECORDS * RECORD,
        "appends overwrote one another"
    );

    let mut expected: Vec<Vec<u8>> = Vec::with_capacity(2 * RECORDS);
    for client in *b"ab" {
        expected.extend((0..RECORDS).map(|index| record(client, index)));
    }
    let mut seen: Vec<Vec<u8>> = records_of(&stored)
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect();
    seen.sort_unstable();
    expected.sort_unstable();
    assert!(
        seen == expected,
        "the stored records are not exactly the records written"
    );

    // The host places appends under the inode lock, so one appender's writes
    // cannot be reordered among themselves.
    for client in *b"ab" {
        let mine: Vec<&[u8]> = records_of(&stored)
            .into_iter()
            .filter(|chunk| chunk.starts_with(format!("client-{client}").as_bytes()))
            .collect();
        let ordered: Vec<Vec<u8>> = (0..RECORDS).map(|index| record(client, index)).collect();
        assert_eq!(mine.len(), RECORDS);
        assert!(
            mine.iter()
                .zip(&ordered)
                .all(|(seen, want)| *seen == &want[..]),
            "client {client}'s own appends came out of order"
        );
    }

    let reader = fixture.mount_fresh("append-reader", "plain", "/tree");
    assert_eq!(
        fs::read(reader.path("log")).expect("read through a fresh mount"),
        stored
    );
}

/// `open` and `create` are two operations on the wire and two host opens in the
/// server, and only `open` is exercised above.
#[test]
fn an_appending_create_appends_at_the_host_too() {
    support::preflight();
    let fixture = Fixture::start("append-create");
    let first = fixture.mount("create-a", "plain", "/tree");
    let second = fixture.mount("create-b", "plain", "/tree");

    let start = Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| append_records(&first.path("created"), b'a', &start, true));
        scope.spawn(|| append_records(&second.path("created"), b'b', &start, true));
    });

    let stored = fs::read(fixture.host("tree/created")).expect("the host has it");
    assert_eq!(
        stored.len(),
        2 * RECORDS * RECORD,
        "appends through a creating open overwrote one another"
    );
    let mut seen: Vec<Vec<u8>> = records_of(&stored)
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect();
    let mut expected: Vec<Vec<u8>> = Vec::with_capacity(2 * RECORDS);
    for client in *b"ab" {
        expected.extend((0..RECORDS).map(|index| record(client, index)));
    }
    seen.sort_unstable();
    expected.sort_unstable();
    assert!(
        seen == expected,
        "the stored records are not exactly the records written"
    );
}

#[test]
fn one_mount_appends_end_to_end_through_one_handle_and_through_two() {
    support::preflight();
    let fixture = Fixture::start("append-single");
    let guest = fixture.mount("append-one", "plain", "/tree");

    let path = guest.path("single");
    fs::write(&path, b"first").expect("writable");
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("appendable");
    file.write_all(b"-second").expect("writable");
    file.write_all(b"-third").expect("writable");
    drop(file);
    assert_eq!(
        fs::read(fixture.host("tree/single")).expect("the host has it"),
        b"first-second-third"
    );

    let shared = guest.path("single-two");
    fs::write(&shared, b"").expect("writable");
    let start = Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| append_records(&shared, b'a', &start, false));
        scope.spawn(|| append_records(&shared, b'b', &start, false));
    });
    let stored = fs::read(fixture.host("tree/single-two")).expect("the host has it");
    assert_eq!(stored.len(), 2 * RECORDS * RECORD);
    assert!(
        records_of(&stored)
            .into_iter()
            .all(|chunk| chunk.ends_with(b"\n")),
        "a record was torn"
    );
}

#[test]
fn a_plain_handle_writes_exactly_where_it_is_directed() {
    support::preflight();
    let fixture = Fixture::start("offset-writes");
    let guest = fixture.mount("offsets", "plain", "/tree");

    let path = guest.path("directed");
    fs::write(&path, b"0123456789").expect("writable");
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("writable");

    rustix::io::pwrite(file.as_fd(), b"AB", 2).expect("writable at an offset");
    rustix::io::pwrite(file.as_fd(), b"Z", 15).expect("writable past the end");
    rustix::io::pwrite(file.as_fd(), b"*", 0).expect("writable at the front");
    drop(file);

    let stored = fs::read(fixture.host("tree/directed")).expect("the host has it");
    assert_eq!(stored, b"*1AB456789\0\0\0\0\0Z", "an offset write moved");
}

/// Linux departs from POSIX here: `pwrite(2)` on an `O_APPEND` descriptor
/// ignores the offset and appends. The host kernel executes the write on a
/// descriptor with the flag, so the mount and a plain local file are held to
/// the same observation.
#[test]
fn a_positional_write_on_an_appending_handle_appends_as_it_does_locally() {
    support::preflight();
    let fixture = Fixture::start("append-pwrite");
    let guest = fixture.mount("pwrite", "plain", "/tree");

    let observe = |path: &Path| {
        fs::write(path, b"0123456789").expect("writable");
        let file = fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("appendable");
        rustix::io::pwrite(file.as_fd(), b"XY", 0).expect("writable");
        drop(file);
        fs::read(path).expect("readable")
    };

    let local = observe(&fixture.host("tree/local-control"));
    let through_mount = observe(&guest.path("through-mount"));
    assert_eq!(local, b"0123456789XY", "local pwrite stopped appending");
    assert_eq!(
        fs::read(fixture.host("tree/through-mount")).expect("the host has it"),
        local,
        "a pwrite through the mount did not do what a local pwrite does"
    );
    assert_eq!(through_mount, local);
}

#[test]
fn two_mounts_writing_disjoint_regions_both_land() {
    support::preflight();
    const REGION: usize = 128 * 1024;

    let fixture = Fixture::start("disjoint");
    let first = fixture.mount("disjoint-a", "plain", "/tree");
    let second = fixture.mount("disjoint-b", "plain", "/tree");

    let host = fixture.host("tree/regions");
    fs::write(&host, vec![0u8; 2 * REGION]).expect("writable");

    let write_region = |path: &Path, offset: u64, fill: u8, start: &Barrier| {
        let file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("writable");
        let block = vec![fill; 4096];
        start.wait();
        for step in (0..REGION).step_by(block.len()) {
            let at = offset + step as u64;
            let mut written = 0;
            while written < block.len() {
                written += rustix::io::pwrite(file.as_fd(), &block[written..], at + written as u64)
                    .expect("writable at an offset");
            }
        }
    };

    let start = Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| write_region(&first.path("regions"), 0, b'a', &start));
        scope.spawn(|| write_region(&second.path("regions"), REGION as u64, b'b', &start));
    });

    let stored = fs::read(&host).expect("the host has it");
    assert_eq!(stored.len(), 2 * REGION);
    assert!(
        stored[..REGION].iter().all(|byte| *byte == b'a'),
        "the first region is not what its writer wrote"
    );
    assert!(
        stored[REGION..].iter().all(|byte| *byte == b'b'),
        "the second region is not what its writer wrote"
    );
}

#[test]
fn an_exclusive_create_raced_from_two_mounts_has_one_winner() {
    support::preflight();
    const ROUNDS: usize = 40;

    let fixture = Fixture::start("exclusive-create");
    let first = fixture.mount("excl-a", "plain", "/tree");
    let second = fixture.mount("excl-b", "plain", "/tree");

    for round in 0..ROUNDS {
        let name = format!("exclusive-{round}");
        let start = Barrier::new(2);
        let attempt = |path: std::path::PathBuf, mark: &[u8]| {
            start.wait();
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    file.write_all(mark).expect("writable");
                    Ok(())
                }
                Err(error) => Err(errno(&error)),
            }
        };
        let (left, right) = std::thread::scope(|scope| {
            let left = scope.spawn(|| attempt(first.path(&name), b"a"));
            let right = scope.spawn(|| attempt(second.path(&name), b"b"));
            (
                left.join().expect("the thread ran"),
                right.join().expect("the thread ran"),
            )
        });

        let losers = [&left, &right]
            .into_iter()
            .filter(|outcome| outcome.is_err());
        assert_eq!(
            [&left, &right]
                .into_iter()
                .filter(|outcome| outcome.is_ok())
                .count(),
            1,
            "round {round}: {left:?} / {right:?} — an exclusive create must have one winner"
        );
        for loser in losers {
            assert_eq!(
                *loser,
                Err(rustix::io::Errno::EXIST.raw_os_error()),
                "round {round}: the loser was refused for the wrong reason"
            );
        }
        let stored = fs::read(fixture.host(&format!("tree/{name}"))).expect("the host has it");
        assert!(stored == b"a" || stored == b"b", "{stored:?}");
    }
}

#[test]
fn a_rename_over_an_open_file_leaves_its_holder_on_the_old_inode() {
    support::preflight();
    let fixture = Fixture::start("rename-over");
    // The holder does not cache entries or attributes, so its next lookup of
    // the name asks the server.
    let holder = fixture.mount_fresh("rename-a", "plain", "/tree");
    let renamer = fixture.mount("rename-b", "plain", "/tree");

    fs::write(fixture.host("tree/target"), b"original").expect("writable");
    fs::write(fixture.host("tree/replacement"), b"replacement").expect("writable");
    let original_inode = fs::metadata(fixture.host("tree/target"))
        .expect("stat")
        .ino();

    let open = fs::File::open(holder.path("target")).expect("openable");
    fs::rename(renamer.path("replacement"), renamer.path("target")).expect("renamable");

    let mut buffer = vec![0u8; b"original".len()];
    let mut read = 0;
    while read < buffer.len() {
        let count =
            rustix::io::pread(open.as_fd(), &mut buffer[read..], read as u64).expect("readable");
        assert_ne!(count, 0, "the held descriptor hit end of file early");
        read += count;
    }
    assert_eq!(buffer, b"original", "the holder followed the rename");

    assert_eq!(
        fs::read(holder.path("target")).expect("fresh lookup"),
        b"replacement"
    );
    assert_ne!(
        fs::metadata(fixture.host("tree/target"))
            .expect("stat")
            .ino(),
        original_inode,
        "the rename did not replace the inode"
    );
    assert!(
        !fixture.host("tree/replacement").exists(),
        "the source name survived the rename"
    );
}

#[test]
fn an_unlink_from_one_mount_leaves_the_other_mounts_open_handle_working() {
    support::preflight();
    let fixture = Fixture::start("unlink-open");
    // The holder does not cache entries or attributes, so its next lookup of
    // the name asks the server.
    let holder = fixture.mount_fresh("unlink-a", "plain", "/tree");
    let remover = fixture.mount("unlink-b", "plain", "/tree");

    fs::write(fixture.host("tree/doomed"), b"alive").expect("writable");
    let open = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(holder.path("doomed"))
        .expect("openable");

    fs::remove_file(remover.path("doomed")).expect("removable");
    assert!(
        !fixture.host("tree/doomed").exists(),
        "the unlink is passed through to the host, not deferred"
    );

    let mut buffer = [0u8; 5];
    let read = rustix::io::pread(open.as_fd(), &mut buffer, 0).expect("still readable");
    assert_eq!((read, &buffer), (5, b"alive"));
    let written = rustix::io::pwrite(open.as_fd(), b"-more", 5).expect("still writable");
    assert_eq!(written, 5);
    let mut whole = [0u8; 10];
    let mut read = 0;
    while read < whole.len() {
        let count =
            rustix::io::pread(open.as_fd(), &mut whole[read..], read as u64).expect("readable");
        assert_ne!(count, 0, "the held descriptor hit end of file early");
        read += count;
    }
    assert_eq!(&whole, b"alive-more");

    let gone = fs::metadata(remover.path("doomed")).expect_err("the name is gone");
    assert_eq!(
        errno(&gone),
        rustix::io::Errno::NOENT.raw_os_error(),
        "{gone}"
    );
    let gone = fs::metadata(holder.path("doomed")).expect_err("fresh lookup after unlink");
    assert_eq!(errno(&gone), rustix::io::Errno::NOENT.raw_os_error());
    // Closing the last handle frees the inode, as it does locally.
    drop(open);
    assert!(!fixture.host("tree/doomed").exists());
}
