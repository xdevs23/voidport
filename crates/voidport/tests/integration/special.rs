use voidport_test_client as support;

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;
use support::{Fixture, errno};
use voidport_spawn::{Program, Stream};

const PATIENCE: Duration = Duration::from_secs(30);

fn mknod(path: &Path, kind: FileType, permissions: u32) -> Result<(), Errno> {
    rustix::fs::mknodat(
        rustix::fs::CWD,
        path,
        kind,
        Mode::from_bits_truncate(permissions),
        0,
    )
}

#[test]
fn mkfifo_and_socket_nodes_land_on_the_host_and_devices_are_refused() {
    support::preflight();
    let fixture = Fixture::start("special");
    let guest = fixture.mount("special", "plain", "/tree");

    // The bits the guest asked for survive: the server's umask must not apply.
    mknod(&guest.path("pipe"), FileType::Fifo, 0o640).expect("mkfifo lands");
    let host = fixture.host("tree/pipe");
    let metadata = fs::symlink_metadata(&host).expect("the host entry exists");
    assert!(metadata.file_type().is_fifo(), "{metadata:?}");
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o640);
    assert!(
        fs::symlink_metadata(guest.path("pipe"))
            .expect("stat")
            .file_type()
            .is_fifo()
    );

    mknod(&guest.path("sock"), FileType::Socket, 0o600).expect("a socket file lands");
    assert!(
        fs::symlink_metadata(fixture.host("tree/sock"))
            .expect("the host entry exists")
            .file_type()
            .is_socket()
    );
    assert_eq!(
        errno(&UnixStream::connect(guest.path("sock")).expect_err("nobody is listening")),
        Errno::CONNREFUSED.raw_os_error()
    );

    assert_eq!(
        mknod(&guest.path("pipe"), FileType::Fifo, 0o640).expect_err("it is already there"),
        Errno::EXIST
    );

    for kind in [FileType::CharacterDevice, FileType::BlockDevice] {
        assert_eq!(
            mknod(&guest.path("device"), kind, 0o644).expect_err("a device node"),
            Errno::PERM
        );
    }
    assert!(!fixture.host("tree/device").exists());

    let readonly = fixture.mount("special-ro", "plain", "/readonly");
    assert_eq!(
        mknod(&readonly.path("pipe2"), FileType::Fifo, 0o644).expect_err("read-only"),
        Errno::ROFS
    );
}

#[test]
fn a_fifo_carries_data_between_two_processes_of_one_guest() {
    support::preflight();
    let fixture = Fixture::start("fifo-flow");
    let guest = fixture.mount("fifo-flow", "plain", "/tree");
    let fifo = guest.path("rendezvous");
    mknod(&fifo, FileType::Fifo, 0o644).expect("mkfifo lands");

    // The rendezvous happens entirely inside this guest's kernel; the server
    // sees nothing.
    let (sender, receiver) = mpsc::channel();
    let reading = fifo.clone();
    thread::spawn(move || {
        let outcome = fs::File::open(&reading).and_then(|mut file| {
            let mut text = String::new();
            file.read_to_string(&mut text).map(|_| text)
        });
        sender.send(outcome).expect("the test waits for the reader");
    });

    let mut writer = Program::new("sh")
        .arg("-c")
        .arg(format!("printf 'through the pipe' > {}", fifo.display()))
        .stdout(Stream::Inherit)
        .stderr(Stream::Inherit)
        .spawn()
        .expect("a second process starts");
    let received = receiver
        .recv_timeout(PATIENCE)
        .expect("the rendezvous completes")
        .expect("the read succeeds");
    assert_eq!(received, "through the pipe");
    assert!(writer.wait().expect("the writer exits").success());

    assert_eq!(
        fs::symlink_metadata(fixture.host("tree/rendezvous"))
            .expect("the host entry exists")
            .len(),
        0
    );
}

#[test]
fn two_mounts_of_one_host_fifo_are_two_independent_pipes() {
    support::preflight();
    let fixture = Fixture::start("fifo-split");
    let first = fixture.mount("fifo-a", "plain", "/tree");
    let second = fixture.mount("fifo-b", "plain", "/tree");
    mknod(&first.path("shared"), FileType::Fifo, 0o644).expect("mkfifo lands");

    // A non-blocking read end opens whether or not a writer exists.
    let reader = rustix::fs::open(
        first.path("shared"),
        OFlags::RDONLY | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .expect("a read end opens");

    rustix::fs::open(
        first.path("shared"),
        OFlags::WRONLY | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .expect("a writer on the same mount finds the reader");

    // `ENXIO`: there is no reader on this mount's pipe.
    assert_eq!(
        rustix::fs::open(
            second.path("shared"),
            OFlags::WRONLY | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .expect_err("no reader on the second mount"),
        Errno::NXIO,
        "two mounts of one host FIFO must not share a pipe"
    );
    drop(reader);
}

#[test]
fn a_unix_socket_binds_and_connects_within_one_guest() {
    support::preflight();
    let fixture = Fixture::start("unix-socket");
    let guest = fixture.mount("unix-socket", "plain", "/tree");

    let path = guest.path("service.sock");
    let listener = UnixListener::bind(&path).expect("the socket binds through the mount");
    assert!(
        fs::symlink_metadata(fixture.host("tree/service.sock"))
            .expect("the host entry exists")
            .file_type()
            .is_socket()
    );

    let serving = thread::spawn(move || {
        let (mut accepted, _) = listener.accept().expect("a connection arrives");
        let mut request = [0u8; 4];
        accepted.read_exact(&mut request).expect("readable");
        accepted.write_all(&request).expect("writable");
    });
    let mut client = UnixStream::connect(&path).expect("the connection resolves in this kernel");
    client.write_all(b"ping").expect("writable");
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed).expect("readable");
    assert_eq!(&echoed, b"ping");
    serving.join().expect("the server thread finishes");
}
