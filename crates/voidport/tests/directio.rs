//! `--direct-io`: the guest page cache holds no file data, and `mmap` still
//! works.
//!
//! The option exists for one situation: many guests reading the same host tree
//! each keep their own copy of it in their own page cache, and on a host running
//! N VMs that is N copies of the same bytes. Direct I/O removes the copies. What
//! it may **never** remove is `mmap` — a mount that cannot map a file cannot
//! execute a binary from itself and cannot run SQLite's WAL — so the option is
//! only ever honoured on a kernel that allows shared mappings of a
//! `FOPEN_DIRECT_IO` file, and degrades to ordinary caching everywhere else.
//!
//! Every proof here is a real syscall against a real mount:
//!
//! * the cache bypass is observed by changing the file **on the host** between
//!   two reads of one open descriptor. A page-cached mount answers the second
//!   read out of guest RAM and returns the old bytes; a direct mount has no
//!   copy to answer from, so it goes to the wire and returns the new ones. Both
//!   mounts are given hour-long metadata timeouts so that nothing *else* can
//!   explain the difference: no attribute revalidation happens in either arm
//!   within the test, so the only thing being compared is where the data came
//!   from.
//! * `mmap` is observed by mapping a file `MAP_SHARED` and writing through the
//!   mapping, which is exactly what would fail with `ENODEV` if the mount had
//!   asked for direct I/O without the kernel's permission to map it.
//! * exec-from-mount is observed by running a real binary off the mount, which
//!   is the same mapping path taken by the loader instead of by the test.
//! * the cache of a default mount lasting across opens is observed the same
//!   way, with a second open between the two reads: a host change that leaves
//!   the attributes as they were is not seen, a new modification time is seen
//!   once the attributes are fetched again or a mapping follows a new lookup,
//!   and a successful `setattr` or the first record lock granted through a
//!   handle makes the next read come from the server.
//!
//! There is no SQLite in this workspace, so there is no WAL suite to run under
//! the option; the `MAP_SHARED` case above is the mechanism a WAL depends on —
//! a shared mapping of `-shm` whose stores other processes must see — and it is
//! proven directly.

mod support;

use std::fs;
use std::os::unix::fs::{FileExt as _, PermissionsExt as _};
use std::path::Path;
use std::time::{Duration, SystemTime};

use rustix::fs::FlockOperation;
use support::Fixture;
use support::mapping::SharedMapping;
use voidport::mount::MountOptions;

/// Long enough that no attribute or entry validity expires while a test runs.
///
/// The point of the read tests is *data* caching, so metadata caching is pinned
/// out of the way: with these timeouts the guest kernel never revalidates, and
/// `FUSE_AUTO_INVAL_DATA` — which voidport always negotiates — therefore never
/// fires. What is left is the difference the option makes and nothing else.
const NEVER: Duration = Duration::from_secs(3600);

/// How long the host is given to see what a mapping was told to flush.
const PATIENCE: Duration = Duration::from_secs(10);

/// One page: the unit the guest page cache would hold a copy in.
const PAGE: usize = 4096;

/// Mount options with the metadata timeouts pinned, direct I/O as asked.
fn options(direct_io: bool) -> MountOptions {
    MountOptions {
        attr_timeout: NEVER,
        entry_timeout: NEVER,
        direct_io,
        ..MountOptions::default()
    }
}

/// Rewrites a host file in place, without changing its length.
///
/// In place on purpose: the server is holding a descriptor open for the guest's
/// handle, and replacing the file would leave that descriptor pointing at the
/// old inode. This changes the bytes the server's own `pread` will return.
fn rewrite(path: &Path, byte: u8) {
    let file = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("the host file is writable");
    file.write_all_at(&vec![byte; PAGE], 0)
        .expect("the host file is rewritten");
    file.sync_all().expect("the host file is flushed");
}

/// Returns the modification time of a host file.
fn modified(path: &Path) -> SystemTime {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .expect("the host file has a modification time")
}

/// Sets the modification time of a host file.
fn set_modified(path: &Path, time: SystemTime) {
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.set_modified(time))
        .expect("the modification time of the host file is set");
}

/// Reads one page at offset zero from an already-open descriptor.
///
/// `pread` on a held descriptor, not a fresh `read` of the path: reopening
/// would issue a `lookup` and a fresh `open`, which is a different question.
/// This asks only where the *data* of an open file comes from.
fn page_at_zero(file: &fs::File) -> Vec<u8> {
    let mut page = vec![0u8; PAGE];
    file.read_exact_at(&mut page, 0).expect("the page reads");
    page
}

/// Criterion: with `--direct-io`, a file read twice hits the wire twice.
///
/// The host changes the bytes between the two reads and the second read returns
/// them, which it can only do by going to the server: nothing invalidated a
/// cache, because with an hour-long attribute timeout nothing revalidated.
#[test]
fn a_direct_io_mount_reads_past_the_guest_page_cache() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("direct-io-read");
    let host = fixture.host("tree/twice.bin");
    fs::write(&host, vec![b'a'; PAGE]).expect("the host file is created");

    let guest = fixture.mount_with("direct", &fixture.tcp_url("plain", "/tree"), &options(true));
    let file = fs::File::open(guest.path("twice.bin")).expect("readable");
    assert_eq!(page_at_zero(&file), vec![b'a'; PAGE]);

    rewrite(&host, b'b');
    assert_eq!(
        page_at_zero(&file),
        vec![b'b'; PAGE],
        "the second read was answered from a guest-side copy: the page cache was not bypassed"
    );
}

/// The control arm, and the criterion that the default mount is unchanged: the
/// very same sequence on a mount without the option is answered from the guest
/// page cache and returns the *old* bytes.
///
/// This is what makes the test above about direct I/O, not about
/// something incidental to the fixture.
#[test]
fn without_the_option_the_second_read_comes_from_the_guest_page_cache() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("cached-read");
    let host = fixture.host("tree/twice.bin");
    fs::write(&host, vec![b'a'; PAGE]).expect("the host file is created");

    let guest = fixture.mount_with(
        "cached",
        &fixture.tcp_url("plain", "/tree"),
        &options(false),
    );
    let file = fs::File::open(guest.path("twice.bin")).expect("readable");
    assert_eq!(page_at_zero(&file), vec![b'a'; PAGE]);

    rewrite(&host, b'b');
    assert_eq!(
        page_at_zero(&file),
        vec![b'a'; PAGE],
        "an ordinary mount is supposed to hold this page in guest memory"
    );
}

/// Reads a whole file through the mount.
fn read_file(path: &Path) -> Vec<u8> {
    fs::read(path).expect("readable")
}

/// What the guest reads after the host rewrites a file the guest has read.
///
/// The host file starts as `a` bytes and the guest reads it once through a
/// mount made with `options`. The host then rewrites it in place with `b`
/// bytes, which leaves the size as it was, and sets its modification time to
/// the old one plus `shift`. `then` is what the guest does next with the path
/// of the file, and what it returns is the result.
fn read_after_host_rewrite(
    name: &str,
    options: &MountOptions,
    shift: Duration,
    then: impl FnOnce(&Path) -> Vec<u8>,
) -> Vec<u8> {
    let fixture = Fixture::start(name);
    let host = fixture.host("tree/rewritten.bin");
    fs::write(&host, vec![b'a'; PAGE]).expect("the host file is created");

    let guest = fixture.mount_with(name, &fixture.tcp_url("plain", "/tree"), options);
    let path = guest.path("rewritten.bin");
    assert_eq!(read_file(&path), vec![b'a'; PAGE]);

    let written = modified(&host);
    rewrite(&host, b'b');
    set_modified(&host, written + shift);
    then(&path)
}

/// A default mount does not drop the cached pages of a file when the file is
/// opened again, so a second open reads from guest memory and not from the
/// server.
///
/// The host changes the bytes in place and sets the modification time back, and
/// the timeouts are an hour long, so the kernel has no sign that the file
/// changed: only an open that drops the cached pages returns the new bytes.
#[test]
fn a_reopened_file_is_read_from_the_guest_page_cache() {
    if !support::preflight() {
        return;
    }
    let read = read_after_host_rewrite("reopen-cached", &options(false), Duration::ZERO, read_file);
    assert_eq!(
        read,
        vec![b'a'; PAGE],
        "the second open dropped the pages the first open had cached"
    );
}

/// A file that is opened again is read from the server once its refreshed
/// attributes show a new modification time, even when its size is the same.
///
/// The attribute timeout is zero, so the read after the second open fetches the
/// attributes again, and `FUSE_AUTO_INVAL_DATA` drops the cached pages when the
/// modification time differs. The host sets the new time itself, so the change
/// does not depend on the resolution of the host clock.
#[test]
fn a_new_modification_time_drops_the_cached_pages() {
    if !support::preflight() {
        return;
    }
    let options = MountOptions {
        attr_timeout: Duration::ZERO,
        ..options(false)
    };
    let read = read_after_host_rewrite(
        "reopen-changed",
        &options,
        Duration::from_secs(1),
        read_file,
    );
    assert_eq!(
        read,
        vec![b'b'; PAGE],
        "the cached pages outlived a new modification time"
    );
}

/// A successful `setattr` drops the cached pages of the file.
///
/// The host gives the file a new modification time, and then the guest changes
/// the mode of the file, all within the hour-long timeouts. The reply to the
/// `setattr` contains the new modification time and the kernel records it
/// without dropping pages, so only the invalidation the adapter sends makes the
/// next read return the new bytes.
#[test]
fn a_successful_setattr_drops_the_cached_pages() {
    if !support::preflight() {
        return;
    }
    let read = read_after_host_rewrite(
        "setattr-drops",
        &options(false),
        Duration::from_secs(1),
        |path| {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("the mode is set");
            read_file(path)
        },
    );
    assert_eq!(
        read,
        vec![b'b'; PAGE],
        "the setattr left the pages cached before the host changed the file"
    );
}

/// A granted record lock drops the cached pages of the file.
///
/// The host sets the modification time back, so no attribute shows the change.
/// A guest that opens the file, takes a read lock and reads under it must read
/// what the host wrote.
#[test]
fn a_granted_record_lock_drops_the_cached_pages() {
    if !support::preflight() {
        return;
    }
    let read = read_after_host_rewrite("lock-drops", &options(false), Duration::ZERO, |path| {
        let file = fs::File::open(path).expect("readable");
        rustix::fs::fcntl_lock(&file, FlockOperation::NonBlockingLockShared)
            .expect("the range is free");
        page_at_zero(&file)
    });
    assert_eq!(
        read,
        vec![b'b'; PAGE],
        "the lock was granted and the read under it came from pages cached before"
    );
}

/// Only the first lock granted through an open handle drops the cached pages,
/// which is how often an open dropped them before the pages outlived it.
///
/// The guest opens the file, locks and unlocks it, the host rewrites it and
/// sets the modification time back, and a second lock through the same handle
/// still reads the pages the first lock left.
#[test]
fn a_second_lock_on_one_handle_keeps_the_cached_pages() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("lock-once");
    let host = fixture.host("tree/locked.bin");
    fs::write(&host, vec![b'a'; PAGE]).expect("the host file is created");
    let guest = fixture.mount_with(
        "lock-once",
        &fixture.tcp_url("plain", "/tree"),
        &options(false),
    );

    let file = fs::File::open(guest.path("locked.bin")).expect("readable");
    rustix::fs::fcntl_lock(&file, FlockOperation::NonBlockingLockShared)
        .expect("the range is free");
    assert_eq!(page_at_zero(&file), vec![b'a'; PAGE]);
    rustix::fs::fcntl_lock(&file, FlockOperation::Unlock).expect("the lock is released");

    let written = modified(&host);
    rewrite(&host, b'b');
    set_modified(&host, written);
    rustix::fs::fcntl_lock(&file, FlockOperation::NonBlockingLockShared)
        .expect("the range is free");
    assert_eq!(
        page_at_zero(&file),
        vec![b'a'; PAGE],
        "a second lock through the same handle dropped the cached pages"
    );
}

/// A file that is opened again and then mapped shows a new modification time
/// once the entry timeout has passed, even though a mapping refreshes no
/// attributes: the lookup of the path walk fetches them.
#[test]
fn a_mapping_after_a_new_lookup_drops_the_cached_pages() {
    if !support::preflight() {
        return;
    }
    let options = MountOptions {
        entry_timeout: Duration::ZERO,
        ..options(false)
    };
    let read = read_after_host_rewrite("mapped-reopen", &options, Duration::from_secs(1), |path| {
        let mapping = SharedMapping::open(path, PAGE).expect("the file maps");
        mapping.bytes().to_vec()
    });
    assert_eq!(
        read,
        vec![b'b'; PAGE],
        "the mapping read pages cached before the host changed the file"
    );
}

/// A truncate of a file with a dirty shared mapping returns.
///
/// The kernel sends no write of a dirty page until the reply to a change of
/// size, so pages dropped before that reply would wait for a write that
/// cannot start, and the truncate would never return.
#[test]
fn a_truncate_under_a_dirty_mapping_returns() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("truncate-mapped");
    let guest = fixture.mount_with(
        "truncate-mapped",
        &fixture.tcp_url("plain", "/tree"),
        &options(false),
    );
    let path = guest.path("mapped.bin");
    fs::write(&path, vec![b'.'; PAGE]).expect("the file is created through the mount");

    let mut mapping = SharedMapping::open(&path, PAGE).expect("the file maps");
    mapping.bytes_mut()[0] = b'x';
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("writable");
    file.set_len(2 * PAGE as u64)
        .expect("the file is truncated");
    drop(mapping);
    assert_eq!(
        fs::metadata(&path).expect("the file exists").len(),
        2 * PAGE as u64
    );
}

/// Criterion: `mmap` works under the option — the thing the design refuses to
/// give up, in any configuration.
///
/// `MAP_SHARED` with `PROT_WRITE` is the strongest form, and it is the *only*
/// one that discriminates: FUSE refuses a shared mapping of a
/// `FOPEN_DIRECT_IO` file with `ENODEV` unless `FUSE_DIRECT_IO_ALLOW_MMAP` was
/// negotiated, while a private mapping — which is what `execve` makes — is
/// permitted either way. So this test, not the exec one below, is what proves
/// the two flags are being asked for as a pair. Verified by removing the
/// capability from `init` and watching exactly this case fail `ENODEV` (19) on
/// Linux 6.18 while every other case still passed.
#[test]
fn a_shared_mapping_reads_and_writes_under_direct_io() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("direct-io-mmap");
    let guest = fixture.mount_with("mmap", &fixture.tcp_url("plain", "/tree"), &options(true));

    let path = guest.path("mapped.bin");
    fs::write(&path, vec![b'.'; PAGE]).expect("the file is created through the mount");

    let message = b"written through a shared mapping";
    let mut mapping = SharedMapping::open(&path, PAGE)
        .expect("a shared mapping of a direct-io file (ENODEV means mmap was given up)");
    // Reading through the mapping is the exec path's read: the page is
    // demand-paged from the server, not copied by a read syscall.
    assert_eq!(
        &mapping.bytes()[..4],
        b"....",
        "the mapping does not see the file's data"
    );
    mapping.bytes_mut()[..message.len()].copy_from_slice(message);
    mapping.flush().expect("the mapping flushes");
    drop(mapping);

    let host = fixture.host("tree/mapped.bin");
    assert!(
        support::eventually(PATIENCE, || {
            fs::read(&host).is_ok_and(|held| held.starts_with(message))
        }),
        "the host never saw what was written through the mapping: {:?}",
        fs::read(&host).map(|held| String::from_utf8_lossy(&held[..message.len()]).into_owned())
    );
}

/// Criterion: exec-from-mount works under the option.
///
/// Executing a binary is the loader mapping it: every page of text arrives
/// through a mapping, not a read, so this is the criterion in its
/// user-visible form — the thing an operator would notice broken.
///
/// It is a *private* mapping, which FUSE allows under direct I/O regardless of
/// the negotiation, so this case is the outcome and the shared-mapping case
/// above is the mechanism. Both are wanted: the mechanism can be right and the
/// outcome still wrong.
#[test]
fn an_executable_still_runs_from_a_direct_io_mount() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("direct-io-exec");
    let guest = fixture.mount_with("exec", &fixture.tcp_url("plain", "/tree"), &options(true));

    let target = guest.path("voidport-ctl");
    fs::copy(support::ctl_binary(), &target).expect("the binary copies through the mount");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).expect("executable");

    let output = std::process::Command::new(&target)
        .arg("--version")
        .output()
        .expect("the binary runs from the mount");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("voidport-ctl"),
        "{:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// Writes through a direct-io mount land on the host, and the mount is an
/// ordinary filesystem in every other respect.
///
/// The read path is what the option changes; this is the check that the write
/// path, the listing and the metadata it never touched still behave.
#[test]
fn a_direct_io_mount_is_an_ordinary_mount_otherwise() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("direct-io-ordinary");
    let guest = fixture.mount_with(
        "ordinary",
        &fixture.tcp_url("plain", "/tree"),
        &options(true),
    );

    let path = guest.path("written");
    fs::write(&path, b"first").expect("writable");
    assert_eq!(fs::read(&path).expect("readable"), b"first");
    assert_eq!(
        fs::read(fixture.host("tree/written")).expect("the host has it"),
        b"first"
    );

    // A file larger than one frame, in both directions.
    let big: Vec<u8> = (0..3_000_000u32).map(|index| index as u8).collect();
    let big_path = guest.path("big.bin");
    fs::write(&big_path, &big).expect("writable");
    assert_eq!(fs::read(&big_path).expect("readable"), big);

    // Metadata caching is untouched by the option, so an ordinary walk works.
    let mut names: Vec<String> = fs::read_dir(guest.root())
        .expect("listable")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    assert!(names.contains(&"data.bin".to_owned()), "{names:?}");
    assert!(names.contains(&"sub".to_owned()), "{names:?}");
    assert_eq!(
        fs::read(guest.path("sub/inner")).expect("readable"),
        b"inner"
    );
}
