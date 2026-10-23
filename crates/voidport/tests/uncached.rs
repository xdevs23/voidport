#![forbid(unsafe_code)]

use voidport_test_client as support;

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::time::Duration;

use support::Fixture;
use support::relay::Relay;
use voidport::mount::MountOptions;
use voidport_proto::opcode::Opcode;

const PAGE: usize = 4096;

fn options() -> MountOptions {
    MountOptions {
        attr_timeout: Duration::ZERO,
        entry_timeout: Duration::ZERO,
        ..MountOptions::default()
    }
}

/// Rewrites a host file in place without changing its length. The server holds
/// a descriptor open for the guest's handle, and replacing the file would leave
/// that descriptor on the old inode.
fn rewrite(path: &Path, byte: u8) {
    let file = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("the host file is writable");
    file.write_all_at(&vec![byte; PAGE], 0)
        .expect("the host file is rewritten");
    file.sync_all().expect("the host file is flushed");
}

/// Reads from an already-open descriptor with `pread`: reopening the path would
/// issue a `lookup` and a fresh `open`.
fn page_at_zero(file: &fs::File) -> Vec<u8> {
    let mut page = vec![0u8; PAGE];
    file.read_exact_at(&mut page, 0).expect("the page reads");
    page
}

#[test]
fn a_file_the_server_cannot_lease_is_read_past_the_guest_page_cache() {
    support::preflight();
    let fixture = Fixture::start("unleased-read");
    let host = fixture.host("tree/twice.bin");
    fs::write(&host, vec![b'a'; PAGE]).expect("the host file is created");
    let _writer = fs::OpenOptions::new()
        .write(true)
        .open(&host)
        .expect("the host writer opens");

    let relay = Relay::start(fixture.server.data_unix());
    let guest = fixture.mount_with("unleased", &relay.url("plain", "/tree"), &options());
    let file = fs::File::open(guest.path("twice.bin")).expect("readable");
    let before = relay.carried(Opcode::Read);
    assert_eq!(page_at_zero(&file), vec![b'a'; PAGE]);
    let first = relay.carried(Opcode::Read);
    assert!(first > before, "the first read reached the server");

    rewrite(&host, b'b');
    assert_eq!(page_at_zero(&file), vec![b'b'; PAGE]);
    let second = relay.carried(Opcode::Read);
    assert!(
        second > first,
        "the second read reached the server in a request of its own"
    );
}

/// Reads in whole pages at page-aligned offsets, which an uncached backing file
/// takes as they are.
fn read_to_end(path: &Path) -> Vec<u8> {
    const CHUNK: usize = 16 * PAGE;
    let file = fs::File::open(path).expect("the file opens");
    let mut contents = Vec::new();
    let mut chunk = vec![0u8; CHUNK];
    loop {
        let read = file
            .read_at(&mut chunk, contents.len() as u64)
            .expect("a whole-page read");
        contents.extend_from_slice(&chunk[..read]);
        if read < CHUNK {
            return contents;
        }
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|at| (at % 251) as u8).collect()
}

#[test]
fn whole_files_read_to_their_end_through_cached_and_uncached_mounts() {
    support::preflight();
    let fixture = Fixture::start("whole-files");
    let contents = pattern(8 * 1024 * 1024 + 123);
    fs::write(fixture.host("tree/whole.bin"), &contents).expect("writable");

    for (label, namespace) in [("cached", "plain"), ("uncached", "uncached")] {
        let guest = fixture.mount_with(label, &fixture.tcp_url(namespace, "/tree"), &options());
        assert_eq!(
            read_to_end(&guest.path("whole.bin")),
            contents,
            "{label}: the whole file arrives"
        );
    }

    let guest = fixture.mount_with("pieces", &fixture.tcp_url("uncached", "/tree"), &options());
    let written = pattern(1024 * 1024);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(guest.path("pieces.bin"))
        .expect("the file opens");
    for (index, piece) in written.chunks(64 * 1024).enumerate() {
        file.write_all_at(piece, (index * 64 * 1024) as u64)
            .expect("a piece is written");
    }
    let mut read = vec![0u8; written.len()];
    for (index, piece) in read.chunks_mut(64 * 1024).enumerate() {
        file.read_exact_at(piece, (index * 64 * 1024) as u64)
            .expect("a piece is read");
    }
    assert_eq!(read, written, "the pieces read back as written");
    assert_eq!(
        fs::read(fixture.host("tree/pieces.bin")).expect("host bytes"),
        written
    );
}

#[test]
fn an_uncached_append_answers_what_a_local_appender_gets() {
    support::preflight();
    let fixture = Fixture::start("uncached-append");
    let host = fixture.host("tree/appended.bin");
    fs::write(&host, b"").expect("writable");
    let record = pattern(1000);

    // What a local uncached appender gets back is what the guest is owed.
    let probe = fixture.host("tree/probe.bin");
    fs::write(&probe, b"").expect("writable");
    let mut local = fs::OpenOptions::new()
        .append(true)
        .custom_flags(rustix::fs::OFlags::DIRECT.bits() as i32)
        .open(&probe)
        .expect("the scratch filesystem serves direct I/O");
    let mut buffer = vec![0u8; record.len() + 8192];
    let start = buffer.as_ptr() as usize;
    let skip = start.next_multiple_of(4096) - start;
    buffer[skip..skip + record.len()].copy_from_slice(&record);
    let locally = local.write(&buffer[skip..skip + record.len()]);

    let guest = fixture.mount_with(
        "uncached-append",
        &fixture.tcp_url("uncached", "/tree"),
        &options(),
    );
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(guest.path("appended.bin"))
        .expect("the append handle opens");
    let remotely = file.write(&record);
    assert_eq!(
        remotely.map_err(|error| error.raw_os_error()),
        locally.map_err(|error| error.raw_os_error()),
        "the guest gets what the local appender got"
    );
    assert_eq!(
        fs::read(&host).expect("host bytes"),
        fs::read(&probe).expect("local bytes"),
        "the file has the content of the local appender's file"
    );
}
