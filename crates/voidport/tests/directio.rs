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
//!
//! There is no SQLite in this workspace, so there is no WAL suite to run under
//! the option; the `MAP_SHARED` case above is the mechanism a WAL depends on —
//! a shared mapping of `-shm` whose stores other processes must see — and it is
//! proven directly.

mod support;

use std::fs;
use std::os::unix::fs::{FileExt as _, PermissionsExt as _};
use std::path::Path;
use std::time::Duration;

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
///
/// The chunk unit is the run's ([`support::write_stream_bytes`]): zero for
/// every ordinary run, and whatever the run named for the pass that puts this
/// suite through the write-streaming engine.
fn options(direct_io: bool) -> MountOptions {
    MountOptions {
        attr_timeout: NEVER,
        entry_timeout: NEVER,
        direct_io,
        write_stream: support::write_stream_bytes(),
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
