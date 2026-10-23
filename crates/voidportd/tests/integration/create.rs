#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use rustix::fs::{CWD, FileType, Mode, OFlags, RenameFlags, mknodat, renameat_with};
use rustix::io::Errno;
use support::Dial as _;
use support::fixture::Fixture;
use support::wire::{Entry, ROOT, WireClient};

/// Sets the flag when dropped, also while a panic unwinds, so the swapping
/// thread ends.
struct SetOnDrop<'a>(&'a AtomicBool);

impl Drop for SetOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// `done` is read before each attempt, so the final attempt without a swap
/// starts after the create returned.
fn swap_once_created(created: &Path, other: &Path, done: &AtomicBool) {
    loop {
        let finished = done.load(Ordering::Acquire);
        match renameat_with(CWD, created, CWD, other, RenameFlags::EXCHANGE) {
            Ok(()) => return,
            Err(Errno::NOENT) if !finished => {}
            Err(Errno::NOENT) => return,
            Err(error) => panic!("the exchange failed: {error}"),
        }
    }
}

fn while_swapped<R>(created: &Path, other: &Path, operation: impl FnOnce() -> R) -> R {
    let done = AtomicBool::new(false);
    thread::scope(|scope| {
        let swap = scope.spawn(|| swap_once_created(created, other, &done));
        let result = {
            let _done = SetOnDrop(&done);
            operation()
        };
        swap.join().expect("the swap ran");
        result
    })
}

#[test]
fn a_create_describes_the_new_file_when_the_name_is_swapped() {
    let fixture = Fixture::start("create-swapped");
    let mut client = fixture.server.mount("plain", "/tree");

    for round in 0..32 {
        let name = format!("made-{round}");
        let made = fixture.tree(&name);
        let other = fixture.tree(&format!("other-{round}"));
        fs::write(&other, b"other").expect("writable");
        fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).expect("writable");

        let (entry, handle) = while_swapped(&made, &other, || {
            client.create(ROOT, &name, OFlags::RDWR | OFlags::EXCL, 0o640)
        })
        .expect("the create succeeds");

        assert_eq!(entry.attr.size.get(), 0, "round {round}: size of the reply");
        assert_eq!(
            entry.permissions(),
            0o640,
            "round {round}: mode of the reply"
        );
        assert_eq!(client.write(handle, 0, b"made").expect("writes"), 4);
        client.release(handle).expect("releases");
        assert_eq!(
            fs::read(&other).expect("readable"),
            b"made",
            "round {round}: the handle writes to the file made by the create"
        );
        assert_eq!(
            fs::read(&made).expect("readable"),
            b"other",
            "round {round}: the file swapped in is unchanged"
        );
    }
}

/// `plain` is passthrough ownership, so these are also the host ids set by a chown.
const CALLER: u32 = 4243;
const OTHER: u32 = 4242;

fn assert_nothing_applied_to_an_entry_swapped_in(
    fixture: &str,
    make_other: impl Fn(&Path),
    mut make: impl FnMut(&mut WireClient, &str) -> Result<Entry, i32>,
) {
    assert!(
        rustix::process::geteuid().is_root(),
        "this test needs root to give an entry to another user"
    );
    let fixture = Fixture::start(fixture);
    let mut client = fixture.server.mount("plain", "/tree");
    client.as_user(CALLER, CALLER);

    for round in 0..32 {
        let name = format!("made-{round}");
        let made = fixture.tree(&name);
        let other = fixture.tree(&format!("other-{round}"));
        make_other(&other);
        std::os::unix::fs::lchown(&other, Some(OTHER), Some(OTHER)).expect("root may chown");
        let given = fs::symlink_metadata(&other).expect("the other entry exists");

        while_swapped(&made, &other, || make(&mut client, &name)).expect("the make succeeds");

        let swapped_in = fs::symlink_metadata(&made).expect("an entry is at the name");
        assert_eq!(
            (
                swapped_in.ino(),
                swapped_in.uid(),
                swapped_in.gid(),
                swapped_in.mode()
            ),
            (given.ino(), given.uid(), given.gid(), given.mode()),
            "round {round}: inode, user, group and mode of the entry swapped in"
        );
    }
}

#[test]
fn a_mkdir_applies_nothing_to_a_directory_swapped_in() {
    assert_nothing_applied_to_an_entry_swapped_in(
        "mkdir-swapped",
        |other| {
            fs::create_dir(other).expect("writable");
            fs::set_permissions(other, fs::Permissions::from_mode(0o700)).expect("writable");
        },
        |client, name| client.mkdir(ROOT, name, 0o750),
    );
}

#[test]
fn a_mknod_applies_nothing_to_a_fifo_swapped_in() {
    assert_nothing_applied_to_an_entry_swapped_in(
        "mknod-swapped",
        |other| {
            mknodat(
                CWD,
                other,
                FileType::Fifo,
                Mode::from_bits_truncate(0o600),
                0,
            )
            .expect("writable");
            fs::set_permissions(other, fs::Permissions::from_mode(0o600)).expect("writable");
        },
        |client, name| client.mknod(ROOT, name, 0o010_640),
    );
}

#[test]
fn a_symlink_applies_nothing_to_a_symlink_swapped_in() {
    assert_nothing_applied_to_an_entry_swapped_in(
        "symlink-swapped",
        |other| std::os::unix::fs::symlink("target", other).expect("writable"),
        |client, name| client.symlink(ROOT, name, "target"),
    );
}
