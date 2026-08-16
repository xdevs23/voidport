//! Special files through a real mount: what the server makes, what it refuses,
//! and where the data actually lives.
//!
//! The server's whole part in a FIFO or a socket file is the host inode. Once an
//! entry reply says `S_IFIFO`, the guest kernel installs its own pipe
//! operations and no open, read or write for it ever reaches the server — so
//! everything below asserts guest-side behaviour, including the one fact an
//! operator has to know before relying on it: **two mounts of one host FIFO are
//! two independent pipes.**

mod support;

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;
use support::{Fixture, errno};

/// How long a rendezvous between two processes of one guest may take before the
/// test calls it stalled, not slow.
const PATIENCE: Duration = Duration::from_secs(30);

/// Creates a special file through a mount, exactly as `mkfifo(3)` does.
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
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("special");
    let guest = fixture.mount("special", "plain", "/tree");

    // A FIFO, made through the mount, is a FIFO on the host — with the bits the
    // guest asked for, which is what proves the server's own umask was not
    // allowed to have an opinion.
    mknod(&guest.path("pipe"), FileType::Fifo, 0o640).expect("mkfifo lands");
    let host = fixture.host("tree/pipe");
    let metadata = fs::symlink_metadata(&host).expect("the host entry exists");
    assert!(metadata.file_type().is_fifo(), "{metadata:?}");
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o640);
    // And the guest sees the same kind back through the mount.
    assert!(
        fs::symlink_metadata(guest.path("pipe"))
            .expect("stat")
            .file_type()
            .is_fifo()
    );

    // A socket file, the same way.
    mknod(&guest.path("sock"), FileType::Socket, 0o600).expect("a socket file lands");
    assert!(
        fs::symlink_metadata(fixture.host("tree/sock"))
            .expect("the host entry exists")
            .file_type()
            .is_socket()
    );
    // Nothing is listening on it, which is the host's own answer and not a
    // policy one.
    assert_eq!(
        errno(&UnixStream::connect(guest.path("sock")).expect_err("nobody is listening")),
        Errno::CONNREFUSED.raw_os_error()
    );

    // The host's own `EEXIST` on a collision, unchanged.
    assert_eq!(
        mknod(&guest.path("pipe"), FileType::Fifo, 0o640).expect_err("it is already there"),
        Errno::EXIST
    );

    // Device nodes are refused — the required `EPERM`, and nothing lands.
    for kind in [FileType::CharacterDevice, FileType::BlockDevice] {
        assert_eq!(
            mknod(&guest.path("device"), kind, 0o644).expect_err("a device node"),
            Errno::PERM
        );
    }
    assert!(!fixture.host("tree/device").exists());

    // And a read-only share answers `EROFS`, like every other creation.
    let readonly = fixture.mount("special-ro", "plain", "/readonly");
    assert_eq!(
        mknod(&readonly.path("pipe2"), FileType::Fifo, 0o644).expect_err("read-only"),
        Errno::ROFS
    );
}

#[test]
fn a_fifo_carries_data_between_two_processes_of_one_guest() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("fifo-flow");
    let guest = fixture.mount("fifo-flow", "plain", "/tree");
    let fifo = guest.path("rendezvous");
    mknod(&fifo, FileType::Fifo, 0o644).expect("mkfifo lands");

    // The reader is this process; the writer is another one. Both ends block
    // until the other arrives, which is the rendezvous itself — and it happens
    // entirely inside this guest's kernel, with the server seeing nothing.
    let (sender, receiver) = mpsc::channel();
    let reading = fifo.clone();
    thread::spawn(move || {
        let outcome = fs::File::open(&reading).and_then(|mut file| {
            let mut text = String::new();
            file.read_to_string(&mut text).map(|_| text)
        });
        let _ = sender.send(outcome);
    });

    let mut writer = Command::new("sh")
        .arg("-c")
        .arg(format!("printf 'through the pipe' > {}", fifo.display()))
        .spawn()
        .expect("a second process starts");
    let received = receiver
        .recv_timeout(PATIENCE)
        .expect("the rendezvous completes")
        .expect("the read succeeds");
    assert_eq!(received, "through the pipe");
    assert!(writer.wait().expect("the writer exits").success());

    // The host inode is still an empty marker: the bytes never went near it.
    assert_eq!(
        fs::symlink_metadata(fixture.host("tree/rendezvous"))
            .expect("the host entry exists")
            .len(),
        0
    );
}

#[test]
fn two_mounts_of_one_host_fifo_are_two_independent_pipes() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("fifo-split");
    let first = fixture.mount("fifo-a", "plain", "/tree");
    let second = fixture.mount("fifo-b", "plain", "/tree");
    mknod(&first.path("shared"), FileType::Fifo, 0o644).expect("mkfifo lands");

    // One reader, on the first mount. A non-blocking read end opens whether or
    // not a writer exists, so this establishes the reader without waiting.
    let reader = rustix::fs::open(
        first.path("shared"),
        OFlags::RDONLY | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .expect("a read end opens");

    // A writer on the *same* mount meets it: same inode, same pipe.
    rustix::fs::open(
        first.path("shared"),
        OFlags::WRONLY | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .expect("a writer on the same mount finds the reader");

    // A writer on the *other* mount does not. One host FIFO, two mounts, two
    // pipes — `ENXIO` is the kernel saying there is no reader on this one.
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
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("unix-socket");
    let guest = fixture.mount("unix-socket", "plain", "/tree");

    // `bind(2)` creates the socket inode through the very `mknod` this
    // increment added — without it the bind fails outright, which is why this
    // is a test of the opcode and not only of AF_UNIX.
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
