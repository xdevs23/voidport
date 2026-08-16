//! What two mounts of one namespace do to the same file at the same time.
//!
//! The end-to-end suite proves a single guest against the host. This one holds
//! the product to the harder standard the coherence decision implies — "writes
//! and reads are passed through to the host" — by putting two *independent*
//! mounts, each with its own kernel FUSE connection, its own attribute cache
//! and its own session, on one host file and asking whether the result is the
//! one two local processes would have produced.
//!
//! The centrepiece is `O_APPEND`. A network filesystem is free to get this
//! wrong and NFS does: an append is a seek to the end followed by a write, and
//! with a cached size the seek is stale, so two appending clients overwrite one
//! another. voidport does not compute the position at all — the guest's
//! `O_APPEND` rides the wire open into the host open, and the host kernel
//! places every write at the real end of the file under the inode lock. That is
//! the same guarantee two local processes have.
//!
//! The suite runs as root, which is what a guest's `root` is in this model.

mod support;

use std::fs;
use std::io::Write as _;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::sync::Barrier;
use std::time::Duration;

use support::{Fixture, errno, eventually};

/// How long a test waits for something the cache timeouts bound.
const PATIENCE: Duration = Duration::from_secs(10);

/// The width of one append record.
///
/// Fixed, so the host file can be cut back into records with no framing of its
/// own: a record that does not land whole is a chunk that is not one of the
/// records anybody wrote, which is exactly the tearing being excluded.
const RECORD: usize = 64;

/// How many records each appending client writes.
const RECORDS: usize = 300;

/// The record a client writes at one index.
fn record(client: u8, index: usize) -> Vec<u8> {
    let text = format!("client-{client} record {index:06}");
    let mut bytes = text.into_bytes();
    assert!(bytes.len() < RECORD, "the record has to fit its slot");
    bytes.resize(RECORD - 1, b'.');
    bytes.push(b'\n');
    bytes
}

/// Appends [`RECORDS`] records to a path, each in one `write`.
///
/// `create` decides which server operation opens the handle — a plain `open`,
/// or the `create` that opens and creates in one round trip. Both have to carry
/// the append flag to the host, and they are separate code paths there.
fn append_records(path: &Path, client: u8, start: &Barrier, create: bool) {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(create)
        .open(path)
        .expect("appendable");
    // Both clients hold their handle before either writes, so the whole run is
    // contended, not one client finishing while the other is still
    // opening.
    start.wait();
    for index in 0..RECORDS {
        file.write_all(&record(client, index)).expect("writable");
    }
    file.flush().expect("flushable");
}

/// Cuts a file into [`RECORD`]-wide chunks, refusing a trailing partial one.
fn records_of(contents: &[u8]) -> Vec<&[u8]> {
    assert_eq!(
        contents.len() % RECORD,
        0,
        "the file does not divide into whole records: {} bytes",
        contents.len()
    );
    contents.chunks(RECORD).collect()
}

// ---------------------------------------------------------------------------
// Atomic append
// ---------------------------------------------------------------------------

/// Two mounts appending to one file lose nothing and tear nothing.
///
/// This is the property NFS does not have. The guest kernel picks an offset for
/// every append out of its cached size — it has to, `generic_write_checks` runs
/// before the filesystem is called — and with two mounts that size is stale by
/// construction: neither kernel is told when the other's client extends the
/// file. If the server honoured that offset, records would land on top of each
/// other and the file would come out short.
///
/// It does not honour it: the handle was opened `O_APPEND` on the host, so the
/// host kernel puts every write at the true end of the file, whatever offset
/// the write carries. The check is made against the **host** file, because the
/// question is what was stored, not what either guest cache believes.
#[test]
fn two_mounts_appending_to_one_file_lose_nothing_and_tear_nothing() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("append-race");
    let first = fixture.mount("append-a", "plain", "/tree");
    let second = fixture.mount("append-b", "plain", "/tree");

    let host = fixture.host("tree/log");
    fs::write(&host, b"").expect("writable");
    // Both mounts must have resolved the name before the race starts, so the
    // run measures appending and not a lookup.
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
    // One comparison answers both halves of the property: every record is
    // present exactly once, and no chunk is a record nobody wrote — which is
    // what a torn write would leave behind.
    assert!(
        seen == expected,
        "the stored records are not exactly the records written"
    );

    // Each client's own records kept the order that client wrote them in: the
    // host places appends under the inode lock, so one appender's writes cannot
    // be reordered among themselves.
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

    // And the guests converge on what the host holds. An appending guest's own
    // cache is behind while the race runs — it placed its writes at offsets the
    // host overruled — so this is bounded by the attribute timeout, not
    // immediate, exactly as every other cross-mount observation in the suite.
    let path = first.path("log");
    assert!(
        eventually(PATIENCE, || fs::read(&path).ok().as_deref()
            == Some(stored.as_slice())),
        "an appending mount never caught up with the file it had written"
    );
}

/// A handle that *created* the file appends atomically too.
///
/// `open` and `create` are two operations on the wire and two host opens in the
/// server, and only one of them was exercised above. `O_CREAT|O_APPEND` from
/// two mounts on a name that does not exist yet goes through the other: one
/// caller creates the file, the other opens the same one, and both must end up
/// appending at the host, not at the offsets their kernels computed.
#[test]
fn an_appending_create_appends_at_the_host_too() {
    if !support::preflight() {
        return;
    }
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

/// One client appending is unchanged, through one handle and through two.
///
/// The single-client case is the one a local filesystem also has to get right,
/// and it stays exactly as it was: appends land end to end, and two handles on
/// the *same* mount interleave without loss just as two local descriptors do.
#[test]
fn one_mount_appends_end_to_end_through_one_handle_and_through_two() {
    if !support::preflight() {
        return;
    }
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

    // Two descriptors of one mount, appending at once.
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

/// A handle that did not ask to append writes exactly where it is told.
///
/// The append guarantee is a property of the *handle*, and nothing else may
/// acquire it: a plain writable handle still places every byte at the offset
/// the guest chose, including a write that lands inside the file and one that
/// leaves a hole past its end.
#[test]
fn a_plain_handle_writes_exactly_where_it_is_directed() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("offset-writes");
    let guest = fixture.mount("offsets", "plain", "/tree");

    let path = guest.path("directed");
    fs::write(&path, b"0123456789").expect("writable");
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("writable");

    // Inside the file: the bytes are replaced, the length does not change.
    rustix::io::pwrite(file.as_fd(), b"AB", 2).expect("writable at an offset");
    // Past the end: the file grows to exactly there, with a hole in between.
    rustix::io::pwrite(file.as_fd(), b"Z", 15).expect("writable past the end");
    // And at the very front, the offset an appending handle would ignore.
    rustix::io::pwrite(file.as_fd(), b"*", 0).expect("writable at the front");
    drop(file);

    let stored = fs::read(fixture.host("tree/directed")).expect("the host has it");
    assert_eq!(stored, b"*1AB456789\0\0\0\0\0Z", "an offset write moved");
}

/// A positional write on an appending handle appends — as it does locally.
///
/// This is Linux's documented departure from POSIX: `pwrite(2)` on a descriptor
/// opened `O_APPEND` ignores the offset and appends. voidport inherits it
/// instead of emulating it, because the write is executed by the host kernel on a
/// host descriptor that carries the flag — so the mount and a plain local file
/// are held to the *same* observation here, side by side, and the test would
/// fail if either changed.
#[test]
fn a_positional_write_on_an_appending_handle_appends_as_it_does_locally() {
    if !support::preflight() {
        return;
    }
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

    // The control is an ordinary host file, so what is asserted is "the same as
    // local", not a remembered constant.
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

// ---------------------------------------------------------------------------
// The rest of the cross-client cases
// ---------------------------------------------------------------------------

/// Two mounts writing disjoint regions of one file both land.
///
/// Nothing coalesces or serializes whole files: each write goes to the host at
/// the offset it names, so two clients working on separate regions get the
/// result two local processes get.
#[test]
fn two_mounts_writing_disjoint_regions_both_land() {
    if !support::preflight() {
        return;
    }
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

/// An exclusive create raced from two mounts has exactly one winner.
///
/// `O_CREAT|O_EXCL` is decided by the host kernel in the directory the server
/// pinned, not by anything the server remembers, so the race is settled where
/// it would be settled locally: one caller creates the entry, the other is told
/// `EEXIST`, and there is one file with one inode at the end.
#[test]
fn an_exclusive_create_raced_from_two_mounts_has_one_winner() {
    if !support::preflight() {
        return;
    }
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
        // One entry, one inode, holding exactly what its creator wrote.
        let stored = fs::read(fixture.host(&format!("tree/{name}"))).expect("the host has it");
        assert!(stored == b"a" || stored == b"b", "{stored:?}");
    }
}

/// A rename over an open file leaves its holder on the inode it opened.
///
/// A descriptor names an inode, not a path — locally, and here. One mount
/// replaces the name while the other is reading through it: the holder keeps
/// reading the file it opened, and only a fresh lookup sees the replacement.
#[test]
fn a_rename_over_an_open_file_leaves_its_holder_on_the_old_inode() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("rename-over");
    let holder = fixture.mount("rename-a", "plain", "/tree");
    let renamer = fixture.mount("rename-b", "plain", "/tree");

    fs::write(fixture.host("tree/target"), b"original").expect("writable");
    fs::write(fixture.host("tree/replacement"), b"replacement").expect("writable");
    let original_inode = fs::metadata(fixture.host("tree/target"))
        .expect("stat")
        .ino();

    let open = fs::File::open(holder.path("target")).expect("openable");
    fs::rename(renamer.path("replacement"), renamer.path("target")).expect("renamable");

    // The held descriptor still reads the inode it was opened on, even though
    // no name refers to it any more.
    let mut buffer = vec![0u8; b"original".len()];
    let mut read = 0;
    while read < buffer.len() {
        let count =
            rustix::io::pread(open.as_fd(), &mut buffer[read..], read as u64).expect("readable");
        assert_ne!(count, 0, "the held descriptor hit end of file early");
        read += count;
    }
    assert_eq!(buffer, b"original", "the holder followed the rename");

    // And a fresh look at the name — from either mount — finds the new file.
    let renamed = holder.path("target");
    assert!(
        eventually(PATIENCE, || fs::read(&renamed).ok().as_deref()
            == Some(b"replacement".as_slice())),
        "the replacement never became visible under the name"
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

/// An unlink from one mount leaves the other mount's open handle working.
///
/// Unlink-while-open is one of the daily-driver semantics the design promises,
/// and the corner that only two mounts can reach is this one: the name goes
/// away through a session that knows nothing about the holder's handle. The
/// holder must behave exactly as a local process whose file was unlinked under
/// it — reads and writes keep landing on the inode it opened — while both
/// mounts and the host agree the name is gone.
#[test]
fn an_unlink_from_one_mount_leaves_the_other_mounts_open_handle_working() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("unlink-open");
    let holder = fixture.mount("unlink-a", "plain", "/tree");
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

    // The handle still names the inode: it reads what was stored and takes a
    // write, with no name anywhere referring to it.
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

    // The remover sees the name gone at once, and the holder once its entry
    // cache expires — the same bound every other policy and host change has.
    let gone = fs::metadata(remover.path("doomed")).expect_err("the name is gone");
    assert_eq!(
        errno(&gone),
        rustix::io::Errno::NOENT.raw_os_error(),
        "{gone}"
    );
    assert!(
        eventually(PATIENCE, || fs::metadata(holder.path("doomed")).is_err()),
        "the holder never stopped resolving a name that no longer exists"
    );
    // And nothing the holder wrote came back: closing the last handle is what
    // frees the inode, exactly as it does locally.
    drop(open);
    assert!(!fixture.host("tree/doomed").exists());
}
