//! The end-to-end suite: a real server, a real FUSE mount, real syscalls.
//!
//! Every test here goes through the whole product — `voidport-proto` framing on
//! a real socket, a real `voidportd`, the kernel's own FUSE layer, and ordinary
//! `std::fs` and `rustix` calls made against the mountpoint. Nothing about the
//! guest side is simulated: if a test says `ls` shows `r-x------`, that is what
//! `stat(2)` returned.
//!
//! Design criteria 2–12 for increment 6 live in this file; the node-accounting
//! criterion is in `accounting.rs` (it needs a server with a deliberately low
//! cap) and the protocol-fault criterion in `faults.rs` (it needs a server that
//! is wrong on purpose).
//!
//! The suite runs as root, which is what a guest's `root` is in this model.

mod support;

use std::fs;
use std::io::{IsTerminal as _, Read as _, Seek as _, SeekFrom, Write as _};
use std::mem::MaybeUninit;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{FlockOperation, RawDir, XattrFlags};
use support::{
    Fixture, MAPPED_GUEST_ID, MAPPED_HOST_ID, NOBODY_ID, errno, eventually, presented_mode,
};
use voidport::mount::MountOptions;

/// How long a test waits for something the cache timeouts bound.
const PATIENCE: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Criterion 2 — mounting over both transports, and the worked example
// ---------------------------------------------------------------------------

#[test]
fn the_worked_example_is_what_the_guest_sees() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("worked-example");
    let guest = fixture.mount("worked", "project", "/project");

    // The design's own table: foo read-write, bar read-only with the write
    // bits stripped, file.txt read-write.
    assert_eq!(presented_mode(&guest.path("foo")), "rwx------");
    assert_eq!(presented_mode(&guest.path("bar")), "r-x------");
    assert_eq!(presented_mode(&guest.path("file.txt")), "rw-------");

    // `secret/` does not exist as far as the guest can tell.
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
    // A re-targeted graft appears in the listing as well as in a stat.
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
    if !support::preflight() {
        return;
    }
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

// ---------------------------------------------------------------------------
// Criterion 3 — file I/O
// ---------------------------------------------------------------------------

#[test]
fn file_io_round_trips_through_the_mount() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("file-io");
    let guest = fixture.mount("io", "plain", "/tree");

    // Create and read back.
    let path = guest.path("written");
    fs::write(&path, b"first").expect("writable");
    assert_eq!(fs::read(&path).expect("readable"), b"first");
    assert_eq!(
        fs::read(fixture.host("tree/written")).expect("the host has it"),
        b"first",
        "what the guest wrote is what the host holds"
    );

    // Append.
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("appendable")
        .write_all(b"-second")
        .expect("writable");
    assert_eq!(fs::read(&path).expect("readable"), b"first-second");

    // Truncate, both by open and by set_len.
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("writable");
    file.set_len(5).expect("truncatable");
    drop(file);
    assert_eq!(fs::read(&path).expect("readable"), b"first");
    fs::write(&path, b"").expect("truncatable");
    assert_eq!(fs::metadata(&path).expect("stat").len(), 0);

    // Read an existing host file, and one at an offset.
    let mut existing = fs::File::open(guest.path("data.bin")).expect("readable");
    existing.seek(SeekFrom::Start(4)).expect("seekable");
    let mut tail = Vec::new();
    existing.read_to_end(&mut tail).expect("readable");
    assert_eq!(tail, b"456789");

    // A large file, to cross the frame bound in both directions.
    let big: Vec<u8> = (0..3_000_000u32).map(|index| index as u8).collect();
    let big_path = guest.path("big.bin");
    fs::write(&big_path, &big).expect("writable");
    assert_eq!(fs::read(&big_path).expect("readable"), big);
}

#[test]
fn an_executable_maps_and_runs_from_the_mount() {
    if !support::preflight() {
        return;
    }
    // Executing a binary is an mmap read of it: the kernel demand-pages the
    // file through the page cache, which is the mmap path the contract rules
    // works under writethrough caching.
    let fixture = Fixture::start("mmap-exec");
    let guest = fixture.mount("mmap", "plain", "/tree");

    let source = support::ctl_binary();
    let target = guest.path("voidport-ctl");
    fs::copy(&source, &target).expect("the binary copies through the mount");
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

// ---------------------------------------------------------------------------
// Criterion 4 — read-only enforcement, and the guest kernel's own check
// ---------------------------------------------------------------------------

#[test]
fn every_write_class_operation_in_a_read_only_graft_fails() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("read-only-graft");
    let guest = fixture.mount("ro", "plain", "/readonly");

    // Reads work; that is what makes the refusals below about the share mode.
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

    // Nothing of the above reached the host.
    assert!(fixture.host("tree/new-file").symlink_metadata().is_err());
    assert!(fixture.host("tree/data.bin").exists());
}

#[test]
fn an_unprivileged_caller_is_refused_by_the_guest_kernel() {
    if !support::preflight() {
        return;
    }
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
        // Per-thread credentials: only this thread drops privilege, and the
        // saved id stays root so nothing else in the process is affected.
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

// ---------------------------------------------------------------------------
// Criterion 5 — a read-only mount
// ---------------------------------------------------------------------------

#[test]
fn a_read_only_mount_refuses_writes_in_a_read_write_graft() {
    if !support::preflight() {
        return;
    }
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
    // The graft itself is read-write: the refusal is the mount's, and the same
    // file is writable through a mount without the flag.
    let writable = fixture.mount("rw-mount", "plain", "/tree");
    fs::write(writable.path("data.bin"), b"rewritten").expect("writable");
}

// ---------------------------------------------------------------------------
// Criterion 6 — extended attributes
// ---------------------------------------------------------------------------

#[test]
fn user_xattrs_round_trip_and_reserved_namespaces_are_refused() {
    if !support::preflight() {
        return;
    }
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
    // denied `EPERM` without the host being touched, while the blanket
    // `EOPNOTSUPP` this mount used to answer for *reads* is gone — a read now
    // reaches the host and comes back with the host's own answer, whichever it
    // is on this filesystem.
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

// ---------------------------------------------------------------------------
// Criterion 7 — POSIX continuity through the proxy
// ---------------------------------------------------------------------------

#[test]
fn posix_continuity_survives_the_proxy() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("posix");
    let guest = fixture.mount("posix", "plain", "/tree");

    // Rename while open: the handle keeps working on the same inode.
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

    // Unlink while open: likewise.
    let doomed = guest.path("doomed");
    fs::write(&doomed, b"alive").expect("writable");
    let mut open = fs::File::open(&doomed).expect("openable");
    fs::remove_file(&doomed).expect("removable");
    let mut contents = String::new();
    open.read_to_string(&mut contents).expect("still readable");
    assert_eq!(contents, "alive");
    assert!(fs::metadata(&doomed).is_err(), "the name is gone");

    // Hardlinks: one identity, two names, the right link count.
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

    // Symlinks: created, read back verbatim, and followed within the mount.
    std::os::unix::fs::symlink("data.bin", guest.path("relative-link")).expect("symlinkable");
    assert_eq!(
        fs::read_link(guest.path("relative-link")).expect("readable"),
        Path::new("data.bin")
    );
    assert_eq!(
        fs::read(guest.path("relative-link")).expect("followable"),
        b"0123456789"
    );

    // An absolute target resolves in the *guest's* namespace — the server never
    // follows it — so it names a file outside the mount entirely.
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

/// A hard link through the mount behaves as `linkat` without
/// `AT_SYMLINK_FOLLOW` does on a local filesystem: a symlink gets a second name
/// of its own, whatever its target, a regular file links, a directory is refused
/// with `EPERM`, and a read-only file gains no writable name.
#[test]
fn a_hard_link_of_a_symlink_names_the_symlink_itself() {
    if !support::preflight() {
        return;
    }
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
    // Nothing resolved the second symlink's target on the host.
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

/// What `df` reports for a mount, which the design decided per node kind and
/// nothing end to end had ever pinned.
///
/// A host-backed mount root reports its backing filesystem — the same numbers a
/// `statvfs` of the grafted directory gives, because the server answers with an
/// `fstatfs` on the very descriptor it pinned. A mount that lands on a
/// synthesized directory has no filesystem to report and answers zeroes: such a
/// root holds nothing and nothing can be created in it, so a zero-sized
/// filesystem is the honest answer and not a placeholder. Both readings are
/// characterization: a future change to either is a decision somebody has to
/// make deliberately.
#[test]
fn statfs_reports_the_backing_filesystem_and_zeroes_a_synthesized_root() {
    if !support::preflight() {
        return;
    }
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

    // The namespace root of the same namespace is synthesized: the grafts are
    // its children and it has no backing of its own.
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

// ---------------------------------------------------------------------------
// Criterion 8 — ownership mapping, end to end
// ---------------------------------------------------------------------------

#[test]
fn ownership_mapping_is_visible_end_to_end() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("ownership");
    // A host file owned by a mapped id, so the forward direction is visible.
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

    // A file created as guest root lands host-side owned by the server
    // identity, and presents as guest 0 through the map.
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

// ---------------------------------------------------------------------------
// Criterion 9 — coherence between two mounts and the host
// ---------------------------------------------------------------------------

#[test]
fn two_mounts_and_the_host_stay_coherent() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("coherence");
    let writer = fixture.mount("writer", "plain", "/tree");
    let reader = fixture.mount("reader", "plain", "/tree");

    // A writer's change reaches a reader within the cache timeouts.
    fs::write(writer.path("shared"), b"one").expect("writable");
    let shared = reader.path("shared");
    assert!(
        eventually(PATIENCE, || fs::read(&shared).ok().as_deref()
            == Some(b"one")),
        "the reader never saw the writer's file"
    );

    // Even through a descriptor the reader already held open, and even when
    // the overwrite keeps the size identical — which is what
    // FUSE_AUTO_INVAL_DATA buys.
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

    // A host-side edit is visible to the guest just the same.
    fs::write(fixture.host("tree/shared"), "六").expect("writable");
    assert!(
        eventually(PATIENCE, || fs::read(&shared).ok().as_deref()
            == Some("六".as_bytes())),
        "a host-side edit never reached the guest"
    );
}

/// A directory listing must describe its entries as of the reply, not as of
/// the `opendir` that materialized the listing.
///
/// The guest caches what an entry reply says about a file for the entry
/// timeout and then serves reads by that size, so an entry reply carrying
/// attributes taken earlier makes a following read of a file that has grown
/// since return the old length — the very staleness `FUSE_AUTO_INVAL_DATA` is
/// negotiated to avoid. The window is opened here deliberately: `read_dir`
/// opens the directory, the file is written, and only then is the listing
/// walked.
#[test]
fn a_listing_describes_its_entries_as_of_the_reply() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("listing-freshness");
    let guest = fixture.mount("listing", "plain", "/tree");

    let path = guest.path("growing");
    fs::write(&path, b"").expect("writable");
    let payload = vec![b'x'; 64 * 1024];

    // `opendir` here, `getdents` at the first `next()`.
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

/// Files written between two `getdents64` calls of one listing show their new
/// size.
///
/// The kernel sends one readdirplus per `getdents64` call and uses the sizes in
/// that reply over any write that finished before it asked. A reply built from
/// entries the mount fetched for an earlier call therefore sets the size of a
/// file written in between back to the size it had then, and stat, fstat and
/// every read return that size until the attribute timeout runs out. The test
/// opens that window: it reads the entries returned by the first `getdents64`
/// call, grows every file, and only then reads the rest of the listing. Every
/// file grows, so the files listed by the later calls are checked wherever the
/// host filesystem puts them in the listing.
#[test]
fn files_written_during_a_long_listing_show_their_new_size() {
    if !support::preflight() {
        return;
    }
    let page = rustix::param::page_size();
    // More files than one `getdents64` call into a buffer of one page can
    // return, since a record of `getdents64` takes at least 24 bytes.
    let files = page / 24 + 1;
    // Any growth shows an old size. Writing one page and appending one more
    // writes little data on hosts with large pages.
    let first = vec![b'x'; page];
    let rest = vec![b'y'; page];

    let fixture = Fixture::start("long-listing-freshness");
    voidportd::testing::create_directory(&fixture.host("tree/objects"));
    // Timeouts far longer than the test: an old size handed to the kernel is
    // then still in its cache when the sizes are checked, however slowly the
    // machine runs the test.
    let options = MountOptions {
        attr_timeout: Duration::from_secs(3600),
        entry_timeout: Duration::from_secs(3600),
        ..MountOptions::default()
    };
    let guest = fixture.mount_with("long-listing", &fixture.tcp_url("plain", "/tree"), &options);
    let expected: Vec<_> = (0..files)
        .map(|index| format!("object-{index:04}.o"))
        .collect();
    let paths: Vec<_> = expected
        .iter()
        .map(|name| guest.path(&format!("objects/{name}")))
        .collect();
    for path in &paths {
        fs::write(path, &first).expect("writable");
    }

    let directory = fs::File::open(guest.path("objects")).expect("listable");
    let mut buffer = vec![MaybeUninit::uninit(); page];
    let mut listing = RawDir::new(&directory, &mut buffer);
    let mut names = Vec::new();
    loop {
        let entry = listing.next().expect("the first call lists an entry");
        names.push(entry.expect("a readable entry").file_name().to_owned());
        if listing.is_buffer_empty() {
            break;
        }
    }
    let listed_by_the_first_call = names.len();
    for path in &paths {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("appendable");
        file.write_all(&rest).expect("writable");
    }
    while let Some(entry) = listing.next() {
        names.push(entry.expect("a readable entry").file_name().to_owned());
    }
    assert!(
        names.len() > listed_by_the_first_call,
        "the first `getdents64` call returned the whole listing, so no file was \
         written between two calls"
    );
    let mut names: Vec<_> = names
        .into_iter()
        .filter(|name| name.as_c_str() != c"." && name.as_c_str() != c"..")
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, expected, "the listing and the directory differ");

    let size = (first.len() + rest.len()) as u64;
    let stale: Vec<_> = paths
        .iter()
        .filter(|path| {
            let opened = fs::File::open(path).expect("readable");
            fs::metadata(path).expect("stattable").len() != size
                || opened.metadata().expect("fstattable").len() != size
                || fs::read(path).expect("readable").len() as u64 != size
        })
        .collect();
    assert!(
        stale.is_empty(),
        "{} of {files} files show a size from before the write: {stale:?}",
        stale.len()
    );
}

/// A listing far larger than one kernel reply buffer, through a real mount.
///
/// This is the compensating-FORGET accounting where the criterion puts it: the
/// kernel's own buffer, not a test sink standing in for it. The mount asks the
/// wire for a page of entries per call and gives back what does not fit into
/// the reply to the kernel. The kernel takes a few dozen entries per
/// `getdents64` and calls again for the rest. Every entry the server sent
/// counted a lookup, and three things have to be true at once: the walk resumes
/// exactly where the kernel stopped (every name appears), it resumes only there
/// (no name appears twice), and once the handle is released and the kernel has
/// given its own lookups back, the session has no more nodes than it had before
/// the walk.
///
/// The kernel is what forgets, and it does so when its dentry cache is pruned;
/// nothing else makes an idle kernel release inodes it may reuse. So the prune
/// is asked for explicitly, and the counts are read afterwards.
#[test]
fn a_listing_larger_than_the_kernel_buffer_resumes_and_leaves_nothing_behind() {
    if !support::preflight() {
        return;
    }
    const ENTRIES: usize = 2400;

    let fixture = Fixture::start("wide-listing");
    let wide = fixture.host("tree/wide");
    // Through the mode-restating helper, not a bare create_dir: another
    // test's socket-bind umask window can strike a concurrently created
    // directory, and the sandbox uid then cannot write into it.
    voidportd::testing::create_directory(&wide);
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
    // The `ReadDir` is dropped here: `releasedir`.

    assert_eq!(
        names.len(),
        ENTRIES,
        "the walk did not resume where the kernel stopped"
    );
    names.sort();
    names.dedup();
    assert_eq!(names.len(), ENTRIES, "an entry was listed twice");
    assert_eq!(names, expected, "the walk and the directory disagree");

    // The kernel accounts for the entries it accepted, and gives them back when
    // it lets go of the dentries.
    fs::write("/proc/sys/vm/drop_caches", b"2\n").expect("a prunable dentry cache (needs root)");
    assert!(
        eventually(PATIENCE, || session_nodes(&fixture) <= baseline),
        "a {ENTRIES}-entry walk left the session holding {} nodes against a baseline of {baseline}",
        session_nodes(&fixture)
    );
}

/// A file keeps its inode number on the mount after the guest kernel has
/// dropped and re-looked it up, which is what a compiler that tells headers
/// apart by device and inode number needs within one compile.
///
/// The node table recognizes a forgotten file by its birth time, so on a
/// scratch filesystem that reports none only the lookup itself is asserted.
#[test]
fn a_file_keeps_its_inode_number_after_the_kernel_forgets_it() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("stable-inode");
    let host = fixture.host("tree/data.bin");
    let has_birth_time = fs::metadata(&host).expect("stattable").created().is_ok();

    let guest = fixture.mount("stable", "plain", "/tree");
    let baseline = session_nodes(&fixture);
    let before = fs::metadata(guest.path("data.bin"))
        .expect("stattable")
        .ino();
    assert!(
        session_nodes(&fixture) > baseline,
        "the stat looked the file up"
    );

    fs::write("/proc/sys/vm/drop_caches", b"2\n").expect("a prunable dentry cache (needs root)");
    assert!(
        eventually(PATIENCE, || session_nodes(&fixture) <= baseline),
        "the kernel did not give the file back; the session holds {} nodes against a baseline of {baseline}",
        session_nodes(&fixture)
    );

    let after = fs::metadata(guest.path("data.bin"))
        .expect("stattable")
        .ino();
    if has_birth_time {
        assert_eq!(after, before, "the inode number changed across a forget");
    } else {
        eprintln!(
            "the scratch filesystem reports no birth time; NOT PROVEN by this run: a file keeps \
             its inode number after the kernel forgets it"
        );
    }
}

/// How many nodes the one live session holds.
fn session_nodes(fixture: &Fixture) -> usize {
    let sessions = fixture.sessions();
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    sessions[0].nodes
}

#[test]
fn a_record_lock_conflict_is_observable_across_mounts() {
    if !support::preflight() {
        return;
    }
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

    // Releasing on one mount frees the range for the other.
    rustix::fs::fcntl_lock(&held, FlockOperation::Unlock).expect("releasable");
    rustix::fs::fcntl_lock(&other, FlockOperation::NonBlockingLockExclusive)
        .expect("the range is free again");
}

#[test]
fn a_process_locks_one_file_through_two_descriptors() {
    if !support::preflight() {
        return;
    }
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

    // Closing either descriptor releases every lock the process holds on the
    // file.
    drop(two);
    rustix::fs::fcntl_lock(&other, FlockOperation::NonBlockingLockExclusive)
        .expect("the file is free again");
    drop(one);
}

// ---------------------------------------------------------------------------
// Criterion 10 — runtime reconfiguration, seen by a mounted guest
// ---------------------------------------------------------------------------

#[test]
fn a_rule_added_while_mounted_reaches_the_guest() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("reconfigure");
    // Mounted at the namespace root, which is a synthesized directory: the
    // grafts are its children.
    let guest = fixture.mount("reconfigure", "plain", "");
    assert!(fs::metadata(guest.path("tree")).expect("stat").is_dir());
    assert!(
        fs::metadata(guest.path("added")).is_err(),
        "nothing is grafted there yet"
    );

    fixture.expect_ctl(&[
        "rule", "add", "plain", "/added", "--mode", "rw", "--target", "added",
    ]);

    // A fresh lookup sees it, without remounting.
    assert!(
        eventually(PATIENCE, || fs::metadata(guest.path("added")).is_ok()),
        "the added rule never became visible"
    );
    assert_eq!(
        fs::read(guest.path("added/inside")).expect("readable"),
        b"added"
    );

    // A downgrade applies to fresh opens. The entry a guest already resolved
    // keeps its mode until its cache entry expires, which is the bound the design set.
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

// ---------------------------------------------------------------------------
// Criterion 11 — unmounting
// ---------------------------------------------------------------------------

#[test]
fn unmounting_is_clean_and_the_mountpoint_remounts() {
    if !support::preflight() {
        return;
    }
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

    // The same mountpoint takes a fresh mount.
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
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("busy");
    let mut guest = fixture.mount("busy", "plain", "/tree");

    // A descriptor open on the mount makes it busy, and v1 has no lazy or
    // forced unmount: the kernel says EBUSY and the mount stays.
    let held = fs::File::open(guest.path("data.bin")).expect("openable");
    let busy = guest
        .unmount()
        .expect_err("a busy mountpoint stays mounted");
    assert_eq!(errno(&busy), libc_errno::BUSY, "{busy}");
    assert_eq!(
        fs::read(guest.path("data.bin")).expect("still mounted"),
        b"0123456789"
    );

    // The same, with a blocking lock request parked on the server: the unmount
    // call still *returns* — promptly — instead of wedging behind it. A parked
    // lock necessarily holds a descriptor, so what it returns is EBUSY.
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

    // Releasing the lock lets the parked request through, and then the mount
    // comes down cleanly.
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

// ---------------------------------------------------------------------------
// Criterion 12 — concurrency
// ---------------------------------------------------------------------------

#[test]
fn parallel_operations_complete_through_one_mount() {
    if !support::preflight() {
        return;
    }
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
    if !support::preflight() {
        return;
    }
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
    // The lock is held, so the waiter is parked in the server.
    assert!(
        is_granted.recv_timeout(Duration::from_millis(500)).is_err(),
        "the blocking lock should still be waiting"
    );

    // Unrelated I/O keeps flowing through the very same mount, which is what
    // "a callback never blocks the dispatch loop" means in practice.
    for round in 0..4 {
        let path = guest.path(&format!("while-parked-{round}"));
        fs::write(&path, b"unrelated").expect("writable");
        assert_eq!(fs::read(&path).expect("readable"), b"unrelated");
    }
    assert_eq!(
        fs::read(guest.path("sub/inner")).expect("readable"),
        b"inner"
    );

    // And so does the operation that releases the conflict.
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

/// The environment variable that turns this test binary into a process that
/// waits for a lock.
const LOCK_WAITER: &str = "VOIDPORT_TEST_LOCK_WAITER";

/// Starts a process that takes a blocking whole-file lock on `path` and exits
/// once it holds it.
///
/// A record lock belongs to its process, so a request that waits on a lock
/// this process holds has to come from another one: this test binary, run
/// again as [`a_blocking_lock_waiter_in_its_own_process`].
fn lock_waiter(path: &std::path::Path) -> std::process::Child {
    std::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            "--exact",
            "a_blocking_lock_waiter_in_its_own_process",
            "--test-threads=1",
        ])
        .env(LOCK_WAITER, path)
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("the waiter starts")
}

/// The process [`lock_waiter`] starts: it takes a blocking whole-file lock on
/// the file the environment names and exits once it holds it. Run any other
/// way, it does nothing.
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

// ---------------------------------------------------------------------------
// The two callbacks the first real workload asked for
// ---------------------------------------------------------------------------

#[test]
fn poll_and_the_terminal_ioctl_answer_like_the_host() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("poll-ioctl");
    let guest = fixture.mount("poll", "plain", "/tree");
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // A regular file is always ready: the guest asks for readability and
    // writability and gets both back, with no error condition. A refused poll
    // would surface here as `POLLERR`, not as a failure of `poll(2)`,
    // which is why the assertion is on the events and not on the call.
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

    // And so is a directory.
    let directory = fs::File::open(guest.root()).expect("openable");
    let mut fds = [PollFd::new(&directory, PollFlags::IN)];
    assert_eq!(
        rustix::event::poll(&mut fds, Some(&now)).expect("poll answers"),
        1
    );
    assert!(fds[0].revents().contains(PollFlags::IN));
    assert!(!fds[0].revents().contains(PollFlags::ERR));

    // The ioctl the workload issued is the terminal-attribute query behind
    // `isatty(3)` — `TCGETS2` on this platform's libc, which is what
    // `IsTerminal` calls, so this drives the very command that was observed. A
    // namespace node is never a terminal, and what the guest gets is what the
    // host gives for a regular file: not a terminal, `ENOTTY`.
    //
    // That errno does not by itself prove which errno the adapter replied:
    // the kernel's fuse layer translates an `ENOSYS` ioctl reply to `ENOTTY`
    // for the caller (and stops asking the filesystem afterwards). What this
    // proves is the guest-visible equivalence with the host; which errno the
    // adapter answers with, and for which commands, is decided and tested in
    // `voidport::fuse`.
    assert!(!file.is_terminal(), "a shared file is not a terminal");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc_errno::NOTTY),
        "the guest sees the host's refusal"
    );
    assert!(!directory.is_terminal(), "a directory is not a terminal");
}

/// The entry names of a directory, sorted.
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

/// The errno values the assertions above name.
///
/// `libc` is not a dependency of this crate, and these three are ABI: they are
/// the same on every Linux architecture.
mod libc_errno {
    /// `ENOENT`.
    pub const NOENT: i32 = 2;
    /// `EACCES`.
    pub const ACCES: i32 = 13;
    /// `EBUSY`.
    pub const BUSY: i32 = 16;
    /// `EROFS`.
    pub const ROFS: i32 = 30;
    /// `ENOTTY`.
    pub const NOTTY: i32 = 25;
}
