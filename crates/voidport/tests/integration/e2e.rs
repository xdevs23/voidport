//! The suite runs as root, which is what a guest's `root` is in this model.

use voidport_test_client as support;

use std::fs;
use std::io::{IsTerminal as _, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{FlockOperation, XattrFlags};
use support::mapping::SharedMapping;
use support::{
    Fixture, MAPPED_GUEST_ID, MAPPED_HOST_ID, NOBODY_ID, errno, eventually, presented_mode,
};
use voidport::mount::{MountOptions, TeardownError};
use voidport_spawn::{Program, Stream};
use voidport_test_support::test_name;

use crate::page_cache::PAGE;

const PATIENCE: Duration = Duration::from_secs(10);

#[test]
fn the_worked_example_is_what_the_guest_sees() {
    support::preflight();
    let fixture = Fixture::start("worked-example");
    let guest = fixture.mount("worked", "project", "/project");

    assert_eq!(presented_mode(&guest.path("foo")), "rwx------");
    assert_eq!(presented_mode(&guest.path("bar")), "r-x------");
    assert_eq!(presented_mode(&guest.path("file.txt")), "rw-------");

    let hidden = fs::metadata(guest.path("secret")).expect_err("secret is hidden");
    assert_eq!(errno(&hidden), libc_errno::NOENT, "{hidden}");
    assert!(
        fs::read(guest.path("secret/key")).is_err(),
        "nothing below a hidden entry is reachable"
    );

    let listing = names(guest.root());
    assert!(listing.contains(&"foo".to_owned()), "{listing:?}");
    assert!(listing.contains(&"bar".to_owned()), "{listing:?}");
    assert!(listing.contains(&"file.txt".to_owned()), "{listing:?}");
    assert!(listing.contains(&"vendor".to_owned()), "{listing:?}");
    assert!(!listing.contains(&"secret".to_owned()), "{listing:?}");

    assert_eq!(
        fs::read(guest.path("file.txt")).expect("readable"),
        b"worked example"
    );
    assert_eq!(
        fs::read(guest.path("vendor/note")).expect("readable"),
        b"re-targeted"
    );
}

#[test]
fn a_unix_socket_mount_serves_the_same_namespace() {
    support::preflight();
    let fixture = Fixture::start("unix-mount");
    let url = fixture.unix_url("project", "/project");
    let guest = fixture.mount_with("unix", &url, &MountOptions::default());

    assert_eq!(
        fs::read(guest.path("file.txt")).expect("readable"),
        b"worked example"
    );
    assert_eq!(presented_mode(&guest.path("bar")), "r-x------");
    let sessions = fixture.sessions();
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    assert_eq!(sessions[0].transport, "unix");
}

#[test]
fn file_io_round_trips_through_the_mount() {
    support::preflight();
    let fixture = Fixture::start("file-io");
    let guest = fixture.mount("io", "plain", "/tree");

    let path = guest.path("written");
    fs::write(&path, b"first").expect("writable");
    assert_eq!(fs::read(&path).expect("readable"), b"first");
    assert_eq!(
        fs::read(fixture.host("tree/written")).expect("the host has it"),
        b"first",
        "what the guest wrote is what the host holds"
    );

    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("appendable")
        .write_all(b"-second")
        .expect("writable");
    assert_eq!(fs::read(&path).expect("readable"), b"first-second");

    let file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("writable");
    file.set_len(5).expect("truncatable");
    drop(file);
    assert_eq!(fs::read(&path).expect("readable"), b"first");
    fs::write(&path, b"").expect("truncatable");
    assert_eq!(fs::metadata(&path).expect("stat").len(), 0);

    let mut existing = fs::File::open(guest.path("data.bin")).expect("readable");
    existing.seek(SeekFrom::Start(4)).expect("seekable");
    let mut tail = Vec::new();
    existing.read_to_end(&mut tail).expect("readable");
    assert_eq!(tail, b"456789");

    let big: Vec<u8> = (0..3_000_000u32).map(|index| index as u8).collect();
    let big_path = guest.path("big.bin");
    fs::write(&big_path, &big).expect("writable");
    assert_eq!(fs::read(&big_path).expect("readable"), big);
}

#[test]
fn an_executable_maps_and_runs_from_the_mount() {
    support::preflight();
    // Executing a binary is an mmap read of it: the kernel demand-pages the file
    // through the page cache, which works under writethrough caching. The
    // mapping is private, which a mount with `direct_io` also allows.
    let fixture = Fixture::start("mmap-exec");
    let direct_io = MountOptions {
        direct_io: true,
        ..MountOptions::default()
    };
    for (label, options) in [
        ("mmap", MountOptions::default()),
        ("mmap-direct", direct_io),
    ] {
        let guest = fixture.mount_with(label, &fixture.tcp_url("plain", "/tree"), &options);
        let target = guest.path("voidport-ctl");
        fs::copy(support::ctl_binary(), &target).expect("the binary copies through the mount");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).expect("executable");

        let output = Program::new(&target)
            .arg("--version")
            .output()
            .expect("the binary runs from the mount");
        assert!(
            output.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("voidport-ctl"),
            "{label}: {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

/// This is the mechanism a SQLite WAL depends on: a shared mapping of `-shm`
/// whose stores other processes must see. The guest kernel fails a shared
/// mapping of a file it reads past the page cache with `ENODEV`.
#[test]
fn a_shared_mapping_of_a_written_file_reads_and_writes() {
    support::preflight();
    let fixture = Fixture::start("mmap-shared");
    let guest = fixture.mount("mmap", "plain", "/tree");

    let path = guest.path("mapped.bin");
    fs::write(&path, vec![b'.'; PAGE]).expect("the file is created through the mount");

    let message = b"written through a shared mapping";
    let mut mapping = SharedMapping::open(&path, PAGE).expect(
        "a shared mapping of a written file (ENODEV means the file is read past the page cache)",
    );
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
        fs::read(&host)
            .expect("host bytes after MS_SYNC")
            .starts_with(message),
        "MS_SYNC returned before the host saw the mapping's writes: {:?}",
        fs::read(&host).map(|held| String::from_utf8_lossy(&held[..message.len()]).into_owned())
    );
}

#[test]
fn every_write_class_operation_in_a_read_only_graft_fails() {
    support::preflight();
    let fixture = Fixture::start("read-only-graft");
    let guest = fixture.mount("ro", "plain", "/readonly");

    assert_eq!(
        fs::read(guest.path("data.bin")).expect("readable"),
        b"0123456789"
    );

    let rofs = |what: &str, error: std::io::Error| {
        assert_eq!(
            errno(&error),
            libc_errno::ROFS,
            "{what} should fail EROFS, got {error}"
        );
    };
    rofs(
        "create",
        fs::write(guest.path("new-file"), b"x").expect_err("create"),
    );
    rofs(
        "mkdir",
        fs::create_dir(guest.path("new-dir")).expect_err("mkdir"),
    );
    rofs(
        "unlink",
        fs::remove_file(guest.path("data.bin")).expect_err("unlink"),
    );
    rofs(
        "rmdir",
        fs::remove_dir(guest.path("sub")).expect_err("rmdir"),
    );
    rofs(
        "rename",
        fs::rename(guest.path("data.bin"), guest.path("moved")).expect_err("rename"),
    );
    rofs(
        "symlink",
        std::os::unix::fs::symlink("data.bin", guest.path("link")).expect_err("symlink"),
    );
    rofs(
        "link",
        fs::hard_link(guest.path("data.bin"), guest.path("hard")).expect_err("link"),
    );
    rofs(
        "chmod",
        fs::set_permissions(guest.path("data.bin"), fs::Permissions::from_mode(0o777))
            .expect_err("chmod"),
    );
    rofs(
        "open for write",
        fs::OpenOptions::new()
            .write(true)
            .open(guest.path("data.bin"))
            .expect_err("open for write"),
    );
    let setxattr = rustix::fs::setxattr(
        guest.path("data.bin"),
        "user.probe",
        b"1",
        XattrFlags::empty(),
    )
    .expect_err("setxattr");
    assert_eq!(setxattr, rustix::io::Errno::ROFS);
    let removexattr =
        rustix::fs::removexattr(guest.path("data.bin"), "user.probe").expect_err("removexattr");
    assert_eq!(removexattr, rustix::io::Errno::ROFS);

    assert!(fixture.host("tree/new-file").symlink_metadata().is_err());
    assert!(fixture.host("tree/data.bin").exists());
}

#[test]
fn an_unprivileged_caller_is_refused_by_the_guest_kernel() {
    support::preflight();
    let fixture = Fixture::start("presented-bits");
    // `allow_other` is what lets another user's request reach the mount at
    // all; without it the refusal would be FUSE's owner check, not the
    // presented-bits check under test.
    let guest = fixture.mount_with(
        "other",
        &fixture.tcp_url("project", "/project"),
        &MountOptions {
            allow_other: true,
            ..MountOptions::default()
        },
    );

    let public = guest.path("public.txt");
    let private = guest.path("file.txt");
    let outcome = std::thread::spawn(move || {
        // Per-thread credentials: only this thread drops privilege.
        rustix::thread::set_thread_res_uid(
            None,
            Some(rustix::process::Uid::from_raw(NOBODY_ID)),
            None,
        )
        .expect("a thread may drop privilege");
        (
            fs::read(&public).map_err(|error| errno(&error)),
            fs::read(&private).map_err(|error| errno(&error)),
        )
    })
    .join()
    .expect("the unprivileged thread finishes");

    assert_eq!(
        outcome
            .0
            .expect("a world-readable file is readable by anyone"),
        b"public"
    );
    assert_eq!(
        outcome
            .1
            .expect_err("the presented bits exclude this caller"),
        libc_errno::ACCES
    );
}

#[test]
fn a_read_only_mount_refuses_writes_in_a_read_write_graft() {
    support::preflight();
    let fixture = Fixture::start("read-only-mount");
    let guest = fixture.mount_with(
        "ro-mount",
        &fixture.tcp_url("plain", "/tree"),
        &MountOptions {
            read_only: true,
            ..MountOptions::default()
        },
    );

    assert_eq!(
        fs::read(guest.path("data.bin")).expect("readable"),
        b"0123456789"
    );
    for (what, error) in [
        (
            "create",
            fs::write(guest.path("nope"), b"x").expect_err("create"),
        ),
        (
            "mkdir",
            fs::create_dir(guest.path("nope-dir")).expect_err("mkdir"),
        ),
        (
            "unlink",
            fs::remove_file(guest.path("data.bin")).expect_err("unlink"),
        ),
        (
            "open for write",
            fs::OpenOptions::new()
                .write(true)
                .open(guest.path("data.bin"))
                .expect_err("open for write"),
        ),
    ] {
        assert_eq!(
            errno(&error),
            libc_errno::ROFS,
            "{what} should fail EROFS on a read-only mount, got {error}"
        );
    }
    let writable = fixture.mount("rw-mount", "plain", "/tree");
    fs::write(writable.path("data.bin"), b"rewritten").expect("writable");
}

#[test]
fn user_xattrs_round_trip_and_reserved_namespaces_are_refused() {
    support::preflight();
    let fixture = Fixture::start("xattrs");
    let guest = fixture.mount("xattr", "plain", "/tree");
    let path = guest.path("data.bin");

    rustix::fs::setxattr(&path, "user.one", b"first", XattrFlags::empty()).expect("settable");
    rustix::fs::setxattr(&path, "user.two", b"second", XattrFlags::empty()).expect("settable");

    let mut value = [0u8; 64];
    let read = rustix::fs::getxattr(&path, "user.one", &mut value[..]).expect("readable");
    assert_eq!(&value[..read], b"first");

    // The size probe, then the list itself: the client rebuilds the kernel's
    // NUL-separated form from the wire's name stream, and the two sizes agree.
    let size = rustix::fs::listxattr(&path, &mut [][..] as &mut [u8]).expect("a size probe");
    let mut list = vec![0u8; size];
    let listed = rustix::fs::listxattr(&path, &mut list[..]).expect("listable");
    assert_eq!(listed, size, "the probe sized the list exactly");
    let mut names: Vec<&[u8]> = list[..listed]
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec![&b"user.one"[..], &b"user.two"[..]]);

    rustix::fs::removexattr(&path, "user.one").expect("removable");
    let gone = rustix::fs::getxattr(&path, "user.one", &mut value[..]).expect_err("removed");
    assert_eq!(gone, rustix::io::Errno::NODATA);

    // With no rules configured the defaults hold: a write outside `user.*` is
    // denied `EPERM` without the host being touched, while a read reaches the
    // host and comes back with the host's own answer.
    let reserved = rustix::fs::setxattr(&path, "trusted.thing", b"x", XattrFlags::empty())
        .expect_err("trusted.* is denied by default");
    assert_eq!(reserved, rustix::io::Errno::PERM);
    let host = fixture.host("tree/data.bin");
    let directly = rustix::fs::getxattr(&host, "trusted.thing", &mut value[..])
        .expect_err("nobody set it on the host either");
    let through =
        rustix::fs::getxattr(&path, "trusted.thing", &mut value[..]).expect_err("nobody set it");
    assert_eq!(through, directly, "the host's answer, passed through");
}

#[test]
fn posix_continuity_survives_the_proxy() {
    support::preflight();
    let fixture = Fixture::start("posix");
    let guest = fixture.mount("posix", "plain", "/tree");

    let path = guest.path("renamed-source");
    fs::write(&path, b"before").expect("writable");
    let mut open = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("openable");
    fs::rename(&path, guest.path("renamed-target")).expect("renamable");
    open.seek(SeekFrom::End(0)).expect("seekable");
    open.write_all(b"-after").expect("still writable");
    open.seek(SeekFrom::Start(0)).expect("seekable");
    let mut contents = String::new();
    open.read_to_string(&mut contents).expect("still readable");
    assert_eq!(contents, "before-after");
    drop(open);
    assert_eq!(
        fs::read(guest.path("renamed-target")).expect("readable"),
        b"before-after"
    );

    let doomed = guest.path("doomed");
    fs::write(&doomed, b"alive").expect("writable");
    let mut open = fs::File::open(&doomed).expect("openable");
    fs::remove_file(&doomed).expect("removable");
    let mut contents = String::new();
    open.read_to_string(&mut contents).expect("still readable");
    assert_eq!(contents, "alive");
    assert!(fs::metadata(&doomed).is_err(), "the name is gone");

    let original = guest.path("linked");
    fs::write(&original, b"shared").expect("writable");
    let link = guest.path("linked-again");
    fs::hard_link(&original, &link).expect("linkable");
    let left = fs::metadata(&original).expect("stat");
    let right = fs::metadata(&link).expect("stat");
    assert_eq!(left.ino(), right.ino(), "hardlinks share one inode number");
    assert_eq!(right.nlink(), 2);
    fs::remove_file(&link).expect("removable");
    assert_eq!(
        fs::metadata(&original).expect("stat").nlink(),
        1,
        "the link count follows the host"
    );

    std::os::unix::fs::symlink("data.bin", guest.path("relative-link")).expect("symlinkable");
    assert_eq!(
        fs::read_link(guest.path("relative-link")).expect("readable"),
        Path::new("data.bin")
    );
    assert_eq!(
        fs::read(guest.path("relative-link")).expect("followable"),
        b"0123456789"
    );

    // An absolute target resolves in the namespace of the guest, because the
    // server never follows it, so it names a file outside the mount entirely.
    let outside = fixture.host("state.toml");
    std::os::unix::fs::symlink(&outside, guest.path("absolute-link")).expect("symlinkable");
    assert_eq!(
        fs::read_link(guest.path("absolute-link")).expect("readable"),
        outside
    );
    assert_eq!(
        fs::read(guest.path("absolute-link")).expect("followed in the guest"),
        fs::read(&outside).expect("readable"),
        "the guest kernel followed the link, in its own namespace"
    );
}

#[test]
fn a_hard_link_of_a_symlink_names_the_symlink_itself() {
    support::preflight();
    let fixture = Fixture::start("link-symlink");
    let outside = fixture.directory.write("outside.txt", "outside the share");
    // The namespace root holds `/tree` read-write and `/readonly`, the same host
    // tree read-only, so one mount reaches both share modes.
    let guest = fixture.mount("link-symlink", "plain", "/");
    let link = |from: &str, to: &str| {
        rustix::fs::linkat(
            rustix::fs::CWD,
            guest.path(from),
            rustix::fs::CWD,
            guest.path(to),
            rustix::fs::AtFlags::empty(),
        )
    };

    std::os::unix::fs::symlink("/nowhere/at/all", guest.path("tree/dangling"))
        .expect("symlinkable");
    std::os::unix::fs::symlink(&outside, guest.path("tree/escape")).expect("symlinkable");
    for (name, target) in [
        ("dangling", Path::new("/nowhere/at/all")),
        ("escape", outside.as_path()),
    ] {
        let original = format!("tree/{name}");
        let second = format!("tree/{name}-again");
        link(&original, &second).expect("a symlink is a hard-link target");
        let left = fs::symlink_metadata(guest.path(&original)).expect("stat");
        let right = fs::symlink_metadata(guest.path(&second)).expect("stat");
        assert!(right.file_type().is_symlink(), "{name}: still a symlink");
        assert_eq!(left.ino(), right.ino(), "{name}: one inode, two names");
        assert_eq!(right.nlink(), 2, "{name}");
        assert_eq!(
            fs::read_link(guest.path(&second)).expect("readable"),
            target,
            "{name}: the target text is carried over verbatim"
        );
    }
    assert_eq!(fs::read(&outside).expect("host-side"), b"outside the share");
    assert_eq!(fs::metadata(&outside).expect("host-side").nlink(), 1);

    link("tree/data.bin", "tree/data-again").expect("a regular file links");
    assert_eq!(
        fs::metadata(guest.path("tree/data-again"))
            .expect("stat")
            .nlink(),
        2
    );

    assert_eq!(
        link("tree/sub", "tree/sub-again").expect_err("a directory is not a hard-link target"),
        rustix::io::Errno::PERM
    );
    assert!(fs::symlink_metadata(fixture.host("tree/sub-again")).is_err());

    assert_eq!(
        link("readonly/data.bin", "tree/escaped")
            .expect_err("a read-only file may not gain a writable name"),
        rustix::io::Errno::ROFS
    );
    assert!(fs::symlink_metadata(fixture.host("tree/escaped")).is_err());
}

/// A host-backed mount root reports its backing filesystem. A mount whose root
/// is a synthesized directory has no filesystem to report and returns zeroes:
/// such a root holds nothing and nothing can be created in it.
#[test]
fn statfs_reports_the_backing_filesystem_and_zeroes_a_synthesized_root() {
    support::preflight();
    let fixture = Fixture::start("statfs");

    let host_backed = fixture.mount("statfs-tree", "plain", "/tree");
    let through = rustix::fs::statvfs(host_backed.root()).expect("the mount answers statfs");
    let directly = rustix::fs::statvfs(fixture.host("tree")).expect("the host answers statfs");
    assert_eq!(
        (through.f_blocks, through.f_bsize, through.f_namemax),
        (directly.f_blocks, directly.f_bsize, directly.f_namemax),
        "a host-backed root reports the filesystem behind the graft"
    );
    assert!(through.f_blocks > 0, "a real filesystem has blocks");

    let synthesized = fixture.mount("statfs-root", "plain", "");
    let empty = rustix::fs::statvfs(synthesized.root()).expect("the mount answers statfs");
    assert_eq!(
        (
            empty.f_blocks,
            empty.f_bfree,
            empty.f_bavail,
            empty.f_files,
            empty.f_ffree,
        ),
        (0, 0, 0, 0, 0),
        "a synthesized root reports a filesystem that holds nothing"
    );
    assert_eq!(empty.f_namemax, 0);
}

#[test]
fn ownership_mapping_is_visible_end_to_end() {
    support::preflight();
    let fixture = Fixture::start("ownership");
    let mapped = fixture.host("project/foo/mapped");
    fs::write(&mapped, b"mapped").expect("writable");
    rustix::fs::chown(
        &mapped,
        Some(rustix::process::Uid::from_raw(MAPPED_HOST_ID)),
        Some(rustix::process::Gid::from_raw(MAPPED_HOST_ID)),
    )
    .expect("the suite runs privileged enough to chown");

    let guest = fixture.mount("ownership", "project", "/project");

    let presented = fs::metadata(guest.path("foo/mapped")).expect("stat");
    assert_eq!(
        presented.uid(),
        MAPPED_GUEST_ID,
        "the map is applied forward"
    );
    assert_eq!(presented.gid(), MAPPED_GUEST_ID);

    let created = guest.path("foo/created");
    fs::write(&created, b"created").expect("writable");
    let host = fs::metadata(fixture.host("project/foo/created")).expect("stat");
    assert_eq!(
        host.uid(),
        rustix::process::getuid().as_raw(),
        "a guest-root create lands as the server identity"
    );
    let guest_view = fs::metadata(&created).expect("stat");
    assert_eq!(guest_view.uid(), 0, "and presents as guest root");
    assert_eq!(guest_view.gid(), 0);
}

#[test]
fn two_mounts_and_the_host_stay_coherent() {
    support::preflight();
    let fixture = Fixture::start("coherence");
    let writer = fixture.mount("writer", "plain", "/tree");
    let reader = fixture.mount("reader", "plain", "/tree");

    fs::write(writer.path("shared"), b"one").expect("writable");
    let shared = reader.path("shared");
    assert!(
        eventually(PATIENCE, || fs::read(&shared).ok().as_deref()
            == Some(b"one")),
        "the reader never saw the writer's file"
    );

    // Even through a descriptor the reader already held open, and even when the
    // overwrite leaves the size identical, which is what `FUSE_AUTO_INVAL_DATA`
    // is for.
    let mut held = fs::File::open(&shared).expect("openable");
    let mut first = [0u8; 3];
    held.read_exact(&mut first).expect("readable");
    assert_eq!(&first, b"one");
    fs::write(writer.path("shared"), b"two").expect("writable");
    assert!(
        eventually(PATIENCE, || {
            let mut buffer = [0u8; 3];
            held.seek(SeekFrom::Start(0)).expect("seekable");
            held.read_exact(&mut buffer).is_ok() && &buffer == b"two"
        }),
        "a held-open descriptor never revalidated its data"
    );

    fs::write(fixture.host("tree/shared"), "六").expect("writable");
    assert!(
        eventually(PATIENCE, || fs::read(&shared).ok().as_deref()
            == Some("六".as_bytes())),
        "a host-side edit never reached the guest"
    );
}

/// The guest caches what an entry reply says about a file for the entry
/// timeout and then serves reads by that size, so an entry reply carrying
/// attributes taken earlier makes a following read of a file that has grown
/// since return the old length. The window is opened here deliberately:
/// `read_dir` opens the directory, the file is written, and only then is the
/// listing walked.
#[test]
fn a_listing_describes_its_entries_as_of_the_reply() {
    support::preflight();
    let fixture = Fixture::start("listing-freshness");
    let guest = fixture.mount("listing", "plain", "/tree");

    let path = guest.path("growing");
    fs::write(&path, b"").expect("writable");
    let payload = vec![b'x'; 64 * 1024];

    let listing = fs::read_dir(guest.path("")).expect("listable");
    fs::write(&path, &payload).expect("writable");
    let listed = listing.count();
    assert!(listed > 0, "the directory listed nothing");

    assert_eq!(
        fs::read(&path).expect("readable").len(),
        payload.len(),
        "the listing froze the file's size for the guest"
    );
}

/// The compensating-FORGET accounting against the reply buffer of the kernel,
/// not a test sink. Every entry the server sent counted a lookup: the walk must
/// resume exactly where the kernel stopped (every name appears), only there (no
/// name appears twice), and once the handle is released and the kernel has
/// given its lookups back, the session holds no more nodes than before the
/// walk. The kernel forgets when its dentry cache is pruned, so the prune is
/// asked for explicitly.
#[test]
fn a_listing_larger_than_the_kernel_buffer_resumes_and_leaves_nothing_behind() {
    support::preflight();
    const ENTRIES: usize = 2400;

    let fixture = Fixture::start("wide-listing");
    let wide = fixture.host("tree/wide");
    // Through the mode-restating helper, not a bare create_dir: another
    // test's socket-bind umask window can strike a concurrently created
    // directory, and the sandbox uid then cannot write into it.
    voidport_test_support::create_directory(&wide);
    let expected: Vec<String> = (0..ENTRIES).map(|index| format!("f{index:05}")).collect();
    for name in &expected {
        fs::write(wide.join(name), b"x").expect("writable");
    }

    let guest = fixture.mount("wide", "plain", "/tree");
    let baseline = session_nodes(&fixture);

    let mut names: Vec<String> = fs::read_dir(guest.path("wide"))
        .expect("listable")
        .map(|entry| {
            entry
                .expect("a readable entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();

    assert_eq!(
        names.len(),
        ENTRIES,
        "the walk did not resume where the kernel stopped"
    );
    names.sort();
    names.dedup();
    assert_eq!(names.len(), ENTRIES, "an entry was listed twice");
    assert_eq!(names, expected, "the walk and the directory disagree");

    fs::write("/proc/sys/vm/drop_caches", b"2\n").expect("a prunable dentry cache (needs root)");
    assert!(
        eventually(PATIENCE, || session_nodes(&fixture) <= baseline),
        "a {ENTRIES}-entry walk left the session holding {} nodes against a baseline of {baseline}",
        session_nodes(&fixture)
    );
}

#[test]
fn a_name_of_name_max_bytes_is_created_looked_up_and_listed() {
    support::preflight();
    let fixture = Fixture::start("name-max");
    let creator = fixture.mount("creator", "plain", "/tree");
    let finder = fixture.mount("finder", "plain", "/tree");
    let name = "n".repeat(255);

    fs::write(creator.path(&name), b"the longest name").expect("a name of NAME_MAX bytes");
    assert_eq!(
        fs::read(fixture.host(&format!("tree/{name}"))).expect("the host has it"),
        b"the longest name"
    );
    assert_eq!(
        fs::read(finder.path(&name)).expect("looked up by its name"),
        b"the longest name"
    );
    assert!(
        names(finder.root()).contains(&name),
        "the listing does not carry the whole name"
    );
}

fn session_nodes(fixture: &Fixture) -> usize {
    let sessions = fixture.sessions();
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    sessions[0].nodes
}

#[test]
fn a_record_lock_conflict_is_observable_across_mounts() {
    support::preflight();
    let fixture = Fixture::start("locks");
    let first = fixture.mount("lock-a", "plain", "/tree");
    let second = fixture.mount("lock-b", "plain", "/tree");

    let held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(first.path("data.bin"))
        .expect("openable");
    rustix::fs::fcntl_lock(&held, FlockOperation::NonBlockingLockExclusive)
        .expect("the range is free");

    let other = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(second.path("data.bin"))
        .expect("openable");
    let conflict = rustix::fs::fcntl_lock(&other, FlockOperation::NonBlockingLockExclusive)
        .expect_err("the other mount holds the range");
    assert!(
        matches!(
            conflict,
            rustix::io::Errno::AGAIN | rustix::io::Errno::ACCESS
        ),
        "a cross-mount conflict is reported as a conflict, got {conflict}"
    );

    rustix::fs::fcntl_lock(&held, FlockOperation::Unlock).expect("releasable");
    rustix::fs::fcntl_lock(&other, FlockOperation::NonBlockingLockExclusive)
        .expect("the range is free again");
}

#[test]
fn a_process_locks_one_file_through_two_descriptors() {
    support::preflight();
    let fixture = Fixture::start("locks-one-process");
    let first = fixture.mount("lock-one", "plain", "/tree");
    let second = fixture.mount("lock-other", "plain", "/tree");
    let open = |path| {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("openable")
    };

    let one = open(first.path("data.bin"));
    let two = open(first.path("data.bin"));
    rustix::fs::fcntl_lock(&one, FlockOperation::NonBlockingLockExclusive)
        .expect("the range is free");
    rustix::fs::fcntl_lock(&two, FlockOperation::NonBlockingLockExclusive)
        .expect("a record lock belongs to the process, so its second descriptor locks too");

    let other = open(second.path("data.bin"));
    let conflict = rustix::fs::fcntl_lock(&other, FlockOperation::NonBlockingLockExclusive)
        .expect_err("the first mount holds the file");
    assert!(
        matches!(
            conflict,
            rustix::io::Errno::AGAIN | rustix::io::Errno::ACCESS
        ),
        "a conflict is reported as a conflict, got {conflict}"
    );

    drop(two);
    rustix::fs::fcntl_lock(&other, FlockOperation::NonBlockingLockExclusive)
        .expect("the file is free again");
    drop(one);
}

#[test]
fn a_rule_added_while_mounted_reaches_the_guest() {
    support::preflight();
    let fixture = Fixture::start("reconfigure");
    let guest = fixture.mount("reconfigure", "plain", "");
    assert!(fs::metadata(guest.path("tree")).expect("stat").is_dir());
    assert!(
        fs::metadata(guest.path("added")).is_err(),
        "nothing is grafted there yet"
    );

    fixture.expect_ctl(&[
        "rule", "add", "plain", "/added", "--mode", "rw", "--target", "added",
    ]);

    assert!(
        eventually(PATIENCE, || fs::metadata(guest.path("added")).is_ok()),
        "the added rule never became visible"
    );
    assert_eq!(
        fs::read(guest.path("added/inside")).expect("readable"),
        b"added"
    );

    // A downgrade applies to fresh opens. An entry a guest already resolved
    // keeps its mode until its cache entry expires.
    fs::write(guest.path("tree/downgrade-probe"), b"before").expect("writable");
    fixture.expect_ctl(&["rule", "remove", "plain", "/tree"]);
    fixture.expect_ctl(&[
        "rule", "add", "plain", "/tree", "--mode", "ro", "--target", "tree",
    ]);

    let probe = guest.path("tree/downgrade-probe");
    assert!(
        eventually(PATIENCE, || {
            fs::OpenOptions::new()
                .write(true)
                .open(&probe)
                .err()
                .is_some_and(|error| errno(&error) == libc_errno::ROFS)
        }),
        "the downgrade never reached a fresh open"
    );
}

#[test]
fn unmounting_is_clean_and_the_mountpoint_remounts() {
    support::preflight();
    let fixture = Fixture::start("unmount");
    let pinned = fixture.host("tree/data.bin");
    let baseline = fixture.open_descriptors(&pinned);

    let mut guest = fixture.mount("unmount", "plain", "/tree");
    let root = guest.root().to_path_buf();
    assert_eq!(
        fs::read(guest.path("data.bin")).expect("readable"),
        b"0123456789"
    );
    assert_eq!(fixture.sessions().len(), 1);

    guest
        .unmount_patiently()
        .expect("a quiet mountpoint unmounts");
    assert!(
        eventually(PATIENCE, || fixture.sessions().is_empty()),
        "the server never tore the session down"
    );
    assert!(
        eventually(PATIENCE, || fixture.open_descriptors(&pinned) == baseline),
        "the session leaked a pinned descriptor"
    );

    let again = fixture.mount_with(
        "unmount",
        &fixture.tcp_url("plain", "/tree"),
        &MountOptions::default(),
    );
    assert_eq!(again.root(), root.as_path());
    assert_eq!(
        fs::read(again.path("data.bin")).expect("readable"),
        b"0123456789"
    );
}

#[test]
fn a_busy_mountpoint_reports_ebusy_and_an_unmount_never_hangs() {
    support::preflight();
    let fixture = Fixture::start("busy");
    let mut guest = fixture.mount("busy", "plain", "/tree");

    // A descriptor open on the mount makes it busy: the kernel says EBUSY and
    // the mount stays.
    let held = fs::File::open(guest.path("data.bin")).expect("openable");
    let TeardownError::Unmount(busy) = guest
        .unmount()
        .expect_err("a busy mountpoint stays mounted")
    else {
        panic!("the kernel is what rejects the unmount");
    };
    assert_eq!(errno(&busy), libc_errno::BUSY, "{busy}");
    assert_eq!(
        fs::read(guest.path("data.bin")).expect("still mounted"),
        b"0123456789"
    );

    // The same with a blocking lock request parked on the server: the unmount
    // call still returns promptly instead of wedging behind it. A parked lock
    // holds a descriptor, so it returns EBUSY.
    let blocker = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(guest.path("data.bin"))
        .expect("openable");
    rustix::fs::fcntl_lock(&blocker, FlockOperation::NonBlockingLockExclusive)
        .expect("the range is free");
    let mut waiter = lock_waiter(&guest.path("data.bin"));
    // Give the blocking request time to reach the server and park there.
    std::thread::sleep(Duration::from_millis(300));

    let started = Instant::now();
    let outcome = guest.unmount();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the unmount took {:?} with a lock parked",
        started.elapsed()
    );
    assert!(
        outcome.is_err(),
        "descriptors are open, so the mountpoint is busy"
    );

    rustix::fs::fcntl_lock(&blocker, FlockOperation::Unlock).expect("releasable");
    let status = waiter.wait().expect("the waiter's exit is readable");
    assert!(
        status.success(),
        "the parked lock is granted once the range frees, got {status}"
    );
    drop(blocker);
    drop(held);
    let started = Instant::now();
    guest
        .unmount_patiently()
        .expect("a quiet mountpoint unmounts");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn parallel_operations_complete_through_one_mount() {
    support::preflight();
    let fixture = Fixture::start("parallel");
    let guest = fixture.mount("parallel", "plain", "/tree");

    let workers: Vec<_> = (0..8u32)
        .map(|worker| {
            let path = guest.path(&format!("worker-{worker}"));
            std::thread::spawn(move || {
                let payload = vec![worker as u8; 64 * 1024];
                for _ in 0..4 {
                    fs::write(&path, &payload).expect("writable");
                    assert_eq!(fs::read(&path).expect("readable"), payload);
                }
                let listing = fs::read_dir(path.parent().expect("a parent")).expect("listable");
                assert!(listing.count() > 0);
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("every worker finishes");
    }
}

#[test]
fn a_parked_blocking_lock_does_not_stall_the_mount() {
    support::preflight();
    let fixture = Fixture::start("parked-lock");
    let guest = fixture.mount("parked", "plain", "/tree");

    let held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(guest.path("data.bin"))
        .expect("openable");
    rustix::fs::fcntl_lock(&held, FlockOperation::NonBlockingLockExclusive)
        .expect("the range is free");

    let mut child = lock_waiter(&guest.path("data.bin"));
    let (granted, is_granted) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let outcome = child.wait();
        granted.send(()).expect("the test is listening");
        outcome
    });
    assert!(
        is_granted.recv_timeout(Duration::from_millis(500)).is_err(),
        "the blocking lock should still be waiting"
    );

    // Unrelated I/O keeps flowing through the same mount.
    for round in 0..4 {
        let path = guest.path(&format!("while-parked-{round}"));
        fs::write(&path, b"unrelated").expect("writable");
        assert_eq!(fs::read(&path).expect("readable"), b"unrelated");
    }
    assert_eq!(
        fs::read(guest.path("sub/inner")).expect("readable"),
        b"inner"
    );

    rustix::fs::fcntl_lock(&held, FlockOperation::Unlock).expect("releasable");
    is_granted
        .recv_timeout(PATIENCE)
        .expect("the parked lock is granted once the range frees");
    let status = waiter
        .join()
        .expect("the waiter finishes")
        .expect("the waiter's exit is readable");
    assert!(status.success(), "the lock was granted, got {status}");
}

const LOCK_WAITER: &str = "VOIDPORT_TEST_LOCK_WAITER";

/// A record lock belongs to its process, so a request that waits on a lock
/// this process holds has to come from another one: this test binary, run
/// again as [`a_blocking_lock_waiter_in_its_own_process`].
fn lock_waiter(path: &std::path::Path) -> std::process::Child {
    Program::new(std::env::current_exe().expect("the test binary"))
        .args([
            "--exact",
            &test_name!(a_blocking_lock_waiter_in_its_own_process),
            "--test-threads=1",
        ])
        .env(LOCK_WAITER, path)
        .stderr(Stream::Inherit)
        .spawn()
        .expect("the waiter starts")
}

/// Run any other way, it does nothing.
#[test]
fn a_blocking_lock_waiter_in_its_own_process() {
    let Some(path) = std::env::var_os(LOCK_WAITER) else {
        return;
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("openable");
    rustix::fs::fcntl_lock(&file, FlockOperation::LockExclusive).expect("the lock is granted");
}

#[test]
fn poll_and_the_terminal_ioctl_answer_like_the_host() {
    support::preflight();
    let fixture = Fixture::start("poll-ioctl");
    let guest = fixture.mount("poll", "plain", "/tree");
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // A regular file is always ready: the guest asks for readability and
    // writability and gets both back. A refused poll would surface as `POLLERR`,
    // not as a failure of `poll(2)`, so the assertion is on the events.
    let file = fs::File::open(guest.path("data.bin")).expect("openable");
    let asked = PollFlags::IN | PollFlags::OUT;
    let mut fds = [PollFd::new(&file, asked)];
    assert_eq!(
        rustix::event::poll(&mut fds, Some(&now)).expect("poll answers"),
        1
    );
    assert_eq!(
        fds[0].revents(),
        asked,
        "the requested events come back ready"
    );

    let directory = fs::File::open(guest.root()).expect("openable");
    let mut fds = [PollFd::new(&directory, PollFlags::IN)];
    assert_eq!(
        rustix::event::poll(&mut fds, Some(&now)).expect("poll answers"),
        1
    );
    assert!(fds[0].revents().contains(PollFlags::IN));
    assert!(!fds[0].revents().contains(PollFlags::ERR));

    // `TCGETS2` is the terminal-attribute query behind `isatty(3)`. A namespace
    // node is never a terminal, and the guest gets what the host gives for a
    // regular file: `ENOTTY`.
    //
    // That does not prove which errno the adapter replied: the kernel's fuse
    // layer translates an `ENOSYS` ioctl reply to `ENOTTY` for the caller (and
    // stops asking the filesystem afterwards). The test proves the guest-visible
    // equivalence with the host.
    assert!(!file.is_terminal(), "a shared file is not a terminal");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc_errno::NOTTY),
        "the guest sees the host's refusal"
    );
    assert!(!directory.is_terminal(), "a directory is not a terminal");
}

fn names(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .expect("listable")
        .map(|entry| {
            entry
                .expect("a readable entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// `libc` is not a dependency of this crate, and these are ABI: the same on
/// every Linux architecture.
mod libc_errno {
    pub const NOENT: i32 = 2;
    pub const ACCES: i32 = 13;
    pub const BUSY: i32 = 16;
    pub const ROFS: i32 = 30;
    pub const NOTTY: i32 = 25;
}
