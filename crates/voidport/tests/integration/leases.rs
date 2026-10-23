//! The attributes and the entries are cached for an hour, so nothing but a
//! recall makes the guest kernel drop the pages of a file it caches. The host
//! filesystem must grant this process a lease, which is asked first on a file
//! of its own: a test of the lease fails without one.

use voidport_test_client as support;

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead as _, BufReader, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use support::mapping::SharedMapping;
use support::relay::{Cut, Latch, Relay};
use support::signal;
use support::{Fixture, Guest};
use voidport::mount::MountOptions;
use voidport_proto::opcode::Opcode;
use voidport_spawn::{Program, Stream};
use voidportd::host::lease;

const PAGE: usize = 4096;

fn grants_leases(directory: &Path) -> bool {
    let probe = directory.join("lease-probe");
    fs::write(&probe, b"probe").expect("writable");
    let file = File::open(&probe).expect("readable");
    let granted = lease::take(file.as_fd(), lease::Kind::Read).is_ok();
    if granted {
        lease::give_up(file.as_fd());
    }
    drop(file);
    fs::remove_file(&probe).expect("removable");
    granted
}

fn page_at_zero(file: &File) -> Vec<u8> {
    let mut page = vec![0u8; PAGE];
    file.read_exact_at(&mut page, 0).expect("the page reads");
    page
}

fn cached_for_an_hour() -> MountOptions {
    MountOptions {
        attr_timeout: Duration::from_secs(3600),
        entry_timeout: Duration::from_secs(3600),
        ..MountOptions::default()
    }
}

/// Sets the modification time back, so the change shows in no attribute the
/// guest could notice it by.
fn rewrite_unnoticed(host: &Path, byte: u8) {
    let modified = fs::metadata(host)
        .and_then(|metadata| metadata.modified())
        .expect("a modification time");
    let writer = OpenOptions::new()
        .write(true)
        .open(host)
        .expect("the host writer goes ahead");
    writer
        .write_all_at(&vec![byte; PAGE], 0)
        .expect("the host file is rewritten");
    writer
        .set_modified(modified)
        .expect("the modification time is set back");
}

#[test]
fn a_leased_file_is_read_from_guest_memory_until_a_host_writer_recalls_it() {
    support::preflight();
    let fixture = Fixture::start("lease-kept");
    let host = fixture.host("tree/kept.bin");
    fs::write(&host, vec![b'a'; PAGE]).expect("the host file is created");
    assert!(
        grants_leases(&fixture.host("tree")),
        "the filesystem of the fixture grants a lease"
    );

    let relay = Relay::start(fixture.server.data_unix());
    let guest = fixture.mount_with("kept", &relay.url("plain", "/tree"), &cached_for_an_hour());
    let path = guest.path("kept.bin");

    assert_eq!(fs::read(&path).expect("readable"), vec![b'a'; PAGE]);
    let read = relay.carried(Opcode::Read);
    let held = File::open(&path).expect("readable");
    assert_eq!(page_at_zero(&held), vec![b'a'; PAGE]);
    assert_eq!(fs::read(&path).expect("readable"), vec![b'a'; PAGE]);
    assert_eq!(
        relay.carried(Opcode::Read),
        read,
        "the pages of a leased file are cached across opens"
    );

    rewrite_unnoticed(&host, b'b');

    assert_eq!(page_at_zero(&held), vec![b'b'; PAGE], "the open handle");
    assert_eq!(
        fs::read(&path).expect("readable"),
        vec![b'b'; PAGE],
        "a new open"
    );
}

#[test]
fn a_recall_drops_the_pages_a_guest_has_mapped() {
    support::preflight();
    let fixture = Fixture::start("lease-mapped");
    let host = fixture.host("tree/mapped.bin");
    fs::write(&host, vec![b'a'; PAGE]).expect("the host file is created");
    assert!(
        grants_leases(&fixture.host("tree")),
        "the filesystem of the fixture grants a lease"
    );
    let guest = fixture.mount_with(
        "mapped",
        &fixture.unix_url("plain", "/tree"),
        &cached_for_an_hour(),
    );
    let path = guest.path("mapped.bin");
    assert_eq!(fs::read(&path).expect("readable"), vec![b'a'; PAGE]);

    let mut mapping = Mapper::start(&path);
    assert_eq!(mapping.page(), vec![b'a'; PAGE]);

    rewrite_unnoticed(&host, b'b');
    assert_eq!(
        mapping.page(),
        vec![b'b'; PAGE],
        "the mapped page was recalled with the others"
    );
}

const MAPPED_FILE: &str = "VOIDPORT_TEST_MAPPED_FILE";

/// The test harness writes the name of the test on the line before it.
const MAPPED_PAGE: &str = "mapped page: ";

/// A fault on a page of a mount that this process serves waits for a read
/// that a thread of this process replies to, while the fault locks the
/// memory map of this process: another thread that maps or unmaps memory
/// meanwhile, as starting a thread does, waits behind the fault, and the
/// threads that reply to the read wait behind that one. A mapping of such a
/// file is therefore made by this test binary, run again as
/// [`a_mapping_in_its_own_process`].
struct Mapper {
    process: std::process::Child,
    pages: io::Lines<BufReader<std::process::ChildStdout>>,
}

impl Mapper {
    fn start(path: &Path) -> Self {
        let mut process = Program::new(std::env::current_exe().expect("the test binary"))
            .args([
                "--exact",
                "leases::a_mapping_in_its_own_process",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(MAPPED_FILE, path)
            .stdin(Stream::Piped)
            .stdout(Stream::Piped)
            .stderr(Stream::Inherit)
            .spawn()
            .expect("the mapping process starts");
        let pages = BufReader::new(process.stdout.take().expect("a piped stdout")).lines();
        Self { process, pages }
    }

    fn page(&mut self) -> Vec<u8> {
        let stdin = self.process.stdin.as_mut().expect("a piped stdin");
        writeln!(stdin).expect("the mapping process is asked for the page");
        self.pages
            .by_ref()
            .map(|line| line.expect("the mapping process writes"))
            .find_map(|line| {
                line.split_once(MAPPED_PAGE)
                    .map(|(_, page)| Vec::from(page))
            })
            .expect("the mapping process writes the page")
    }
}

impl Drop for Mapper {
    fn drop(&mut self) {
        drop(self.process.stdin.take());
        let _ = self.process.wait();
    }
}

/// The process [`Mapper`] starts. Run any other way, it does nothing.
#[test]
fn a_mapping_in_its_own_process() {
    let Some(path) = std::env::var_os(MAPPED_FILE) else {
        return;
    };
    let mapping =
        SharedMapping::open_read_only(Path::new(&path), PAGE).expect("a leased file maps");
    for request in io::stdin().lines() {
        request.expect("the test asks");
        println!("{MAPPED_PAGE}{}", String::from_utf8_lossy(mapping.bytes()));
    }
}

#[test]
fn an_unmount_gives_the_lease_of_a_cached_file_up_before_it_returns() {
    support::preflight();
    let fixture = Fixture::start("lease-unmounted");
    let host = fixture.host("tree/unmounted.bin");
    fs::write(&host, vec![b'a'; PAGE]).expect("the host file is created");
    assert!(
        grants_leases(&fixture.host("tree")),
        "the filesystem of the fixture grants a lease"
    );
    let relay = Relay::start(fixture.server.data_unix());
    let mut guest = fixture.mount_with(
        "unmounted",
        &relay.url("plain", "/tree"),
        &cached_for_an_hour(),
    );
    let path = guest.path("unmounted.bin");
    assert_eq!(fs::read(&path).expect("readable"), vec![b'a'; PAGE]);
    let read = relay.carried(Opcode::Read);
    assert_eq!(fs::read(&path).expect("readable"), vec![b'a'; PAGE]);
    assert_eq!(
        relay.carried(Opcode::Read),
        read,
        "the guest caches the file under a lease"
    );

    guest
        .unmount_patiently()
        .expect("a quiet mountpoint unmounts");
    OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&host)
        .expect("no lease of the ended mount holds a host writer back");
}

#[test]
fn a_mount_whose_guardian_is_killed_gives_its_leases_up() {
    support::preflight();
    let fixture = Fixture::start("lease-guardian");
    let host = fixture.host("tree/guarded.bin");
    fs::write(&host, vec![b'a'; PAGE]).expect("the host file is created");
    assert!(
        grants_leases(&fixture.host("tree")),
        "the filesystem of the fixture grants a lease"
    );
    let relay = Relay::start(fixture.server.data_unix());
    let guest = fixture.mount_with(
        "guarded",
        &relay.url("plain", "/tree"),
        &cached_for_an_hour(),
    );
    let path = guest.path("guarded.bin");
    assert_eq!(fs::read(&path).expect("readable"), vec![b'a'; PAGE]);
    let read = relay.carried(Opcode::Read);
    assert_eq!(fs::read(&path).expect("readable"), vec![b'a'; PAGE]);
    assert_eq!(
        relay.carried(Opcode::Read),
        read,
        "the guest caches the file under a lease"
    );

    let relinquished = relay.arm(Opcode::Relinquish, Cut::HoldReply(Latch::released()));
    kill_the_guardian_of(&guest);
    relinquished
        .recv()
        .expect("the server has given the leases of the session up");
    drop(
        OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&host)
            .expect("no lease of the mount holds a host writer back"),
    );
    assert_eq!(fs::read(&path).expect("readable"), vec![b'a'; PAGE]);
    assert!(
        relay.carried(Opcode::Read) > read,
        "the mount reads the file from the server"
    );
}

fn kill_the_guardian_of(guest: &support::Guest) {
    let guardian = guest
        .guardian_id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(rustix::process::Pid::from_raw)
        .expect("the mount has a guardian");
    rustix::process::kill_process(guardian, rustix::process::Signal::KILL)
        .expect("the guardian is killed");
}

#[test]
fn a_handle_beside_a_writer_reads_what_a_host_writer_wrote() {
    support::preflight();
    let fixture = Fixture::start("lease-written");
    let host = fixture.host("tree/written.bin");
    fs::write(&host, vec![b'a'; PAGE]).expect("the host file is created");
    assert!(
        grants_leases(&fixture.host("tree")),
        "the filesystem of the fixture grants a lease"
    );
    let guest = fixture.mount_with(
        "written",
        &fixture.unix_url("plain", "/tree"),
        &cached_for_an_hour(),
    );
    let path = guest.path("written.bin");

    let reader = File::open(&path).expect("readable");
    assert_eq!(page_at_zero(&reader), vec![b'a'; PAGE]);
    let writer = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("writable");
    assert_eq!(page_at_zero(&reader), vec![b'a'; PAGE]);

    rewrite_unnoticed(&host, b'b');

    assert_eq!(
        page_at_zero(&reader),
        vec![b'b'; PAGE],
        "the reader reads what the host wrote"
    );
    drop(writer);
}

#[test]
fn a_write_waiting_for_a_host_reader_ends_with_eintr_on_a_signal_and_writes_nothing() {
    support::preflight();
    let fixture = Fixture::start("lease-cancelled-write");
    let host = fixture.host("tree/held.bin");
    fs::write(&host, vec![b'a'; PAGE]).expect("the host file is created");
    assert!(
        grants_leases(&fixture.host("tree")),
        "the filesystem of the fixture grants a lease"
    );
    let relay = Relay::start(fixture.server.data_unix());
    let guest = fixture.mount_with("held", &relay.url("plain", "/tree"), &cached_for_an_hour());
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(guest.path("held.bin"))
        .expect("writable");

    // Left open: the writes of the cached handle wait in the server until it is
    // closed.
    let reader = File::open(&host).expect("the host reader goes ahead");
    let reaching = relay.arm(Opcode::Write, Cut::HoldRequest(Latch::released()));
    let writer = thread::spawn(move || file.write_at(&[b'b'; PAGE], 0));
    reaching
        .recv()
        .expect("the write is on its way to the server");
    signal::interrupt(&writer);
    let written = writer.join().expect("the writer finishes");
    assert_eq!(
        written.map_err(|error| error.kind()),
        Err(io::ErrorKind::Interrupted),
        "the write ends while the host reader still has the file open"
    );
    assert_eq!(
        page_at_zero(&reader),
        vec![b'a'; PAGE],
        "the cancelled write wrote nothing"
    );
}

#[test]
fn a_write_applied_before_a_signal_reports_what_it_wrote() {
    support::preflight();
    let fixture = Fixture::start("lease-interrupted-write");
    let host = fixture.host("tree/written.bin");
    fs::write(&host, vec![b'a'; PAGE]).expect("the host file is created");
    let relay = Relay::start(fixture.server.data_unix());
    let guest = fixture.mount_with(
        "written",
        &relay.url("plain", "/tree"),
        &cached_for_an_hour(),
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(guest.path("written.bin"))
        .expect("writable");

    // The server applies the write, and its reply waits in the relay until
    // the cancel caused by the signal has followed it.
    let latch = Latch::default();
    let answered = relay.arm(Opcode::Write, Cut::HoldReply(latch.clone()));
    let cancelled = relay.arm(Opcode::Cancel, Cut::HoldRequest(Latch::released()));
    let writer = thread::spawn(move || file.write_at(&[b'b'; PAGE], 0));
    answered.recv().expect("the server replied to the write");
    signal::interrupt(&writer);
    cancelled
        .recv()
        .expect("the cancel of the write is on its way to the server");
    latch.release();
    let written = writer.join().expect("the writer finishes");
    assert_eq!(
        written.map_err(|error| error.kind()),
        Ok(PAGE),
        "the write reports what it wrote"
    );
    assert_eq!(fs::read(&host).expect("readable"), vec![b'b'; PAGE]);
}

/// The fields drop in the order of their declaration: the host writer and the
/// guest handle before the mount, and the mount before the relay and the
/// fixture.
struct ReadBehindHostWriter {
    reaching: mpsc::Receiver<usize>,
    writer: File,
    held: File,
    _guest: Guest,
    _relay: Relay,
    _fixture: Fixture,
}

impl ReadBehindHostWriter {
    fn start(label: &str) -> Self {
        let fixture = Fixture::start(label);
        let host = fixture.host("tree/held.bin");
        fs::write(&host, vec![b'a'; PAGE]).expect("the host file is created");
        assert!(
            grants_leases(&fixture.host("tree")),
            "the filesystem of the fixture grants a lease"
        );
        let relay = Relay::start(fixture.server.data_unix());
        let guest = fixture.mount_with("held", &relay.url("plain", "/tree"), &cached_for_an_hour());
        let held = File::open(guest.path("held.bin")).expect("readable");
        assert_eq!(page_at_zero(&held), vec![b'a'; PAGE]);
        let writer = OpenOptions::new()
            .write(true)
            .open(&host)
            .expect("the host writer can open the file");
        let reaching = relay.arm(Opcode::Read, Cut::HoldRequest(Latch::released()));
        Self {
            reaching,
            writer,
            held,
            _guest: guest,
            _relay: relay,
            _fixture: fixture,
        }
    }
}

#[test]
fn a_cached_read_waiting_for_a_host_writer_ends_with_eintr_on_a_signal() {
    support::preflight();
    let behind = ReadBehindHostWriter::start("lease-interrupted-read");
    let held = behind.held;
    let reader = thread::spawn(move || {
        let read = held.read_at(&mut [0; PAGE], 0);
        (held, read)
    });
    behind
        .reaching
        .recv()
        .expect("the read is on its way to the server");
    signal::interrupt(&reader);
    let (held, read) = reader.join().expect("the reader finishes");
    assert_eq!(
        read.map_err(|error| error.kind()),
        Err(io::ErrorKind::Interrupted),
        "the read ends while the host writer still has the file open"
    );

    behind
        .writer
        .write_all_at(&[b'b'; PAGE], 0)
        .expect("the host file is rewritten");
    drop(behind.writer);
    assert_eq!(
        page_at_zero(&held),
        vec![b'b'; PAGE],
        "the read after the cancelled ones returns what the host wrote"
    );
}

#[test]
fn a_program_held_in_a_cached_read_ends_on_sigkill() {
    support::preflight();
    let behind = ReadBehindHostWriter::start("lease-killed-read");
    let mut reader = Program::new("cat")
        .stdin(Stream::Descriptor(behind.held.as_fd()))
        .stderr(Stream::Inherit)
        .spawn()
        .expect("the reader starts");
    drop(behind.held);
    behind
        .reaching
        .recv()
        .expect("the read is on its way to the server");
    reader.kill().expect("SIGKILL is sent");
    let status = reader.wait().expect("the reader's exit is readable");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the reader ends while the host writer still has the file open"
    );
}
