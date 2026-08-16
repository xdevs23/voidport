//! The data plane over real sockets: sessions, policy, host I/O.
//!
//! Every test here drives the real server through the real protocol, with a
//! client built on `voidport-proto` (`support::wire`) — no FUSE, no mocks, and
//! nothing about the wire hand-assembled except where being malformed is the
//! point. The design's acceptance criteria 1–9 for the data plane live in this
//! file; the listener, cap and inspection criteria live in `data_limits.rs`.

mod support;

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::time::Duration;

use support::fixture::{Fixture, supports_user_xattrs};
use support::wire::{ROOT, status};
use support::{Dial as _, open_descriptors};
use voidport_control::{NamespaceName, OwnershipSpec, Request, Rule, ShareMode, UnmappedPolicy};
use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::frame::{FRAME_HEADER_LEN, FrameWriter, MAX_HELLO_FRAME_LEN};
use voidport_proto::message::RequestHead;
use voidport_proto::ops::file::{FileLock, lock_type};
use voidport_proto::ops::node::{GetattrRequest, GetattrResponse, SetattrRequest, setattr_valid};
use zerocopy::byteorder::little_endian::{U32, U64};

/// `O_RDONLY`, `O_WRONLY`, `O_RDWR`, as the guest sends them.
const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;

/// A zeroed setattr request, for the tests that set exactly one field.
fn setattr(valid: u32) -> SetattrRequest {
    SetattrRequest {
        valid: U32::new(valid),
        reserved: U32::ZERO,
        handle: U64::ZERO,
        size: U64::ZERO,
        mode: U32::ZERO,
        uid: U32::ZERO,
        gid: U32::ZERO,
        reserved2: U32::ZERO,
        atime: voidport_proto::attr::Timespec::new(0, 0),
        mtime: voidport_proto::attr::Timespec::new(0, 0),
        ctime: voidport_proto::attr::Timespec::new(0, 0),
    }
}

/// A whole-file lock description for one owner.
fn lock(owner: u64, kind: u32, start: u64, end: u64) -> FileLock {
    FileLock {
        start: U64::new(start),
        end: U64::new(end),
        owner: U64::new(owner),
        pid: U32::new(7),
        lock_type: U32::new(kind),
    }
}

// ---------------------------------------------------------------------------
// Criterion 1 — the handshake, every path
// ---------------------------------------------------------------------------

#[test]
fn a_handshake_mounts_a_namespace_subpath() {
    let fixture = Fixture::start("handshake");
    let mut client = fixture.server.dial();
    let reply = client.hello("plain", "/tree").expect("the mount resolves");

    assert_eq!(
        reply.root_node_id.get(),
        ROOT,
        "the mount root is node id 1"
    );
    assert_eq!(reply.protocol_version.get(), PROTOCOL_VERSION);
    assert_eq!(reply.max_frame_len.get(), 1024 * 1024);
    assert_eq!(reply.flags.get(), 0);

    // The root really is the grafted directory.
    let entry = client
        .lookup(ROOT, "data.bin")
        .expect("the graft is mounted");
    assert_eq!(entry.attr.size.get(), 10);
}

#[test]
fn a_handshake_reports_why_it_was_refused() {
    let fixture = Fixture::start("handshake-refusals");

    let mut wrong_version = fixture.server.dial();
    assert_eq!(
        wrong_version
            .hello_versioned("plain", "/tree", PROTOCOL_VERSION + 1, &[])
            .expect_err("v1 accepts exactly one version"),
        status::PROTO
    );

    let mut authenticated = fixture.server.dial();
    assert_eq!(
        authenticated
            .hello_versioned("plain", "/tree", PROTOCOL_VERSION, b"credentials")
            .expect_err("auth.mode none takes no blob"),
        status::INVAL
    );

    let mut unknown = fixture.server.dial();
    assert_eq!(
        unknown.hello("absent", "/tree").expect_err("no namespace"),
        status::NOENT
    );

    let mut malformed = fixture.server.dial();
    assert_eq!(
        malformed
            .hello("plain", "tree/../escape")
            .expect_err("a subpath is absolute and canonical"),
        status::INVAL
    );

    let mut missing = fixture.server.dial();
    assert_eq!(
        missing
            .hello("plain", "/tree/absent")
            .expect_err("nothing resolves there"),
        status::NOENT
    );

    let mut a_file = fixture.server.dial();
    assert_eq!(
        a_file
            .hello("plain", "/tree/data.bin")
            .expect_err("a mount root is a directory"),
        status::NOTDIR
    );
}

#[test]
fn a_mount_may_land_on_a_synthesized_directory() {
    let fixture = Fixture::start("synthesized-mount");
    let mut client = fixture.server.mount("deep", "/deep");

    // `/deep` exists only because a graft lies beneath it.
    let attr = client.getattr(ROOT).expect("the root stats");
    assert_eq!(attr.mode.get() & 0o7777, 0o555, "read and traverse only");
    assert_eq!(attr.nlink.get(), 2);
    assert_eq!(attr.size.get(), 0);

    // It lists exactly its visible structural children — nothing host-backed
    // is enumerated, because there is no host directory behind it.
    let listing = client.list(ROOT).expect("the root lists");
    let names: Vec<String> = listing.iter().map(support::wire::DirEntry::name).collect();
    assert_eq!(names, ["inside"]);

    let inside = client.lookup(ROOT, "inside").expect("the way down");
    assert!(inside.is_directory());
    let graft = client
        .lookup(inside.node_id, "graft")
        .expect("the graft beneath it");
    assert!(client.lookup(graft.node_id, "data.bin").is_ok());
    assert_eq!(
        client
            .lookup(ROOT, "elsewhere")
            .expect_err("empty by default"),
        status::NOENT
    );
}

#[test]
fn a_synthesized_directory_carries_the_server_start_time() {
    // Observed before the server exists, so the time it captures at startup can
    // only be at or after it.
    let before = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("a host clock at or after the epoch")
        .as_secs();
    let fixture = Fixture::start("synthesized-times");
    let mut control = fixture.server.connect();
    let mut client = fixture.server.mount("deep", "/deep");

    // `/deep` has no host backing, so its times are the injected ones: the
    // server's start time, not the 1970 a zero constant would present.
    let attr = client.getattr(ROOT).expect("the root stats");
    assert_ne!(attr.mtime.sec.get(), 0, "not the epoch");
    assert_eq!(attr.atime, attr.mtime);
    assert_eq!(attr.ctime, attr.mtime);
    assert!(
        attr.mtime.sec.get() >= i64::try_from(before).expect("a representable clock"),
        "the server started at {}, after {before}",
        attr.mtime.sec.get()
    );

    // Stability is the property the injected value exists for: a guest that
    // caches attributes must never see the namespace skeleton change. Neither a
    // repeated stat...
    let again = client.getattr(ROOT).expect("the root stats again");
    assert_eq!(again, attr);

    // ...nor a rule mutation, which rebuilds the namespace snapshot underneath
    // the session, moves it.
    control.expect_ok(&Request::RuleAdd {
        namespace: NamespaceName::new("deep").expect("a valid namespace name"),
        rule: Rule::new("/deep/elsewhere", ShareMode::Ro).with_target(
            fixture
                .graft_root()
                .to_str()
                .expect("a utf-8 fixture path")
                .to_owned(),
        ),
    });
    assert!(client.lookup(ROOT, "elsewhere").is_ok(), "the rule is live");
    let mutated = client.getattr(ROOT).expect("the root stats once more");
    assert_eq!(mutated, attr);

    // And a mount taken after the mutation sees the same skeleton: the value is
    // the server's, not a session's or a snapshot's.
    let mut fresh = fixture.server.mount("deep", "/deep");
    assert_eq!(fresh.getattr(ROOT).expect("the root stats"), attr);
}

#[test]
fn an_oversized_handshake_closes_the_connection() {
    let fixture = Fixture::start("hello-bound");
    let mut client = fixture.server.dial();

    // A `Hello` larger than the pre-handshake bound: nothing has been
    // negotiated, so the server refuses to buffer it at all.
    let namespace = vec![b'x'; MAX_HELLO_FRAME_LEN as usize];
    let body = voidport_proto::ops::handshake::HelloRequest {
        protocol_version: U32::new(PROTOCOL_VERSION),
        flags: U32::ZERO,
        namespace_len: U32::new(namespace.len() as u32),
        subpath_len: U32::ZERO,
        auth_len: U32::ZERO,
    };
    let mut buffer = vec![0u8; MAX_HELLO_FRAME_LEN as usize * 2];
    let head = RequestHead::new(0, 0, 0, 0);
    let frame = {
        let mut writer = FrameWriter::request(&mut buffer, u32::MAX, 1, &head, &body)
            .expect("the client may encode what the server will refuse");
        writer.payload(&namespace).expect("the payload fits");
        writer.finish().expect("a complete frame").to_vec()
    };
    assert!(frame.len() > MAX_HELLO_FRAME_LEN as usize);

    client.send_bytes(&frame);
    assert!(
        client.receive().is_none(),
        "an oversized pre-handshake frame closes the connection"
    );
}

// ---------------------------------------------------------------------------
// Criterion 2 — the worked example over the wire
// ---------------------------------------------------------------------------

#[test]
fn the_worked_example_resolves_and_lists_as_designed() {
    let fixture = Fixture::start("worked-example");
    let mut client = fixture.server.mount("project", "/project");

    let foo = client
        .lookup(ROOT, "foo")
        .expect("foo is shared read-write");
    assert!(foo.is_directory());
    assert_ne!(foo.permissions() & 0o200, 0, "foo keeps its write bits");

    let bar = client.lookup(ROOT, "bar").expect("bar is shared read-only");
    assert_eq!(bar.permissions() & 0o222, 0, "a read-only graft strips w");

    let file = client.lookup(ROOT, "file.txt").expect("file.txt is shared");
    assert_ne!(file.permissions() & 0o200, 0);

    // `secret/` does not exist as far as the guest can tell.
    assert_eq!(
        client.lookup(ROOT, "secret").expect_err("hidden"),
        status::NOENT
    );

    let listing = client.list(ROOT).expect("the root lists");
    let mut names: Vec<String> = listing.iter().map(support::wire::DirEntry::name).collect();
    names.sort();
    assert_eq!(names, ["bar", "file.txt", "foo", "vendor"]);

    // The re-targeted literal rule is absent from the host listing of
    // `project/` and must still appear: ls has to agree with stat.
    let vendor = listing
        .iter()
        .find(|entry| entry.name() == "vendor")
        .expect("the re-targeted graft is listed");
    assert!(vendor.entry.is_directory());
    let vendor_node = client.lookup(ROOT, "vendor").expect("and it resolves");
    assert_eq!(vendor_node.attr.ino.get(), vendor.entry.attr.ino.get());
    assert!(client.lookup(vendor_node.node_id, "note").is_ok());
}

// ---------------------------------------------------------------------------
// Criterion 3 — data, enforcement, and ownership on create
// ---------------------------------------------------------------------------

#[test]
fn data_round_trips_through_a_read_write_graft() {
    let fixture = Fixture::start("io");
    let mut client = fixture.server.mount("plain", "/tree");

    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, O_RDWR).expect("opens");
    assert_eq!(client.read(handle, 0, 64).expect("reads"), b"0123456789");
    assert_eq!(client.read(handle, 4, 3).expect("reads"), b"456");
    assert_eq!(client.write(handle, 2, b"XY").expect("writes"), 2);
    assert_eq!(client.read(handle, 0, 64).expect("reads"), b"01XY456789");
    client.fsync(handle, false).expect("syncs");
    client.release(handle).expect("releases");

    // The host holds what the guest wrote.
    assert_eq!(
        fs::read(fixture.tree("data.bin")).expect("readable"),
        b"01XY456789"
    );

    // And a fresh create is readable straight back.
    let (created, handle) = client
        .create(ROOT, "created", O_RDWR, 0o644)
        .expect("creates");
    assert_eq!(client.write(handle, 0, b"new").expect("writes"), 3);
    client.release(handle).expect("releases");
    assert_eq!(fs::read(fixture.tree("created")).expect("readable"), b"new");
    assert_eq!(created.permissions(), 0o644);

    // A non-exclusive create over a name that already exists opens it, keeping
    // its contents and its mode: only a create that really created the entry
    // owns and modes it.
    let (again, handle) = client
        .create(ROOT, "created", O_RDWR, 0o600)
        .expect("the existing entry opens");
    assert_eq!(again.attr.ino.get(), created.attr.ino.get());
    assert_eq!(
        again.permissions(),
        0o644,
        "an existing entry is not re-moded"
    );
    assert_eq!(client.read(handle, 0, 64).expect("reads"), b"new");
    client.release(handle).expect("releases");
}

#[test]
fn every_write_class_operation_through_a_read_only_node_is_refused() {
    let fixture = Fixture::start("read-only");
    let mut client = fixture.server.mount("plain", "/readonly");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");

    assert_eq!(
        client.open(file.node_id, O_WRONLY).expect_err("open write"),
        status::ROFS
    );
    assert_eq!(
        client.open(file.node_id, O_RDWR).expect_err("open rdwr"),
        status::ROFS
    );
    assert_eq!(
        client
            .create(ROOT, "nope", O_RDWR, 0o644)
            .expect_err("create"),
        status::ROFS
    );
    assert_eq!(
        client.mkdir(ROOT, "nope", 0o755).expect_err("mkdir"),
        status::ROFS
    );
    assert_eq!(
        client.unlink(ROOT, "data.bin").expect_err("unlink"),
        status::ROFS
    );
    assert_eq!(client.rmdir(ROOT, "sub").expect_err("rmdir"), status::ROFS);
    assert_eq!(
        client
            .rename(ROOT, "data.bin", ROOT, "moved")
            .expect_err("rename"),
        status::ROFS
    );
    assert_eq!(
        client
            .link(ROOT, file.node_id, "hardlink")
            .expect_err("link"),
        status::ROFS
    );
    assert_eq!(
        client
            .symlink(ROOT, "link", "data.bin")
            .expect_err("symlink"),
        status::ROFS
    );
    assert_eq!(
        client
            .setattr(file.node_id, setattr(setattr_valid::MODE))
            .expect_err("setattr"),
        status::ROFS
    );
    assert_eq!(
        client
            .setxattr(file.node_id, "user.thing", b"x")
            .expect_err("setxattr"),
        status::ROFS
    );
    assert_eq!(
        client
            .removexattr(file.node_id, "user.thing")
            .expect_err("removexattr"),
        status::ROFS
    );

    // A directory node is no exception: enforcement does not depend on what
    // kind of node an open names, and the mount root here is read-only.
    assert_eq!(
        client
            .open(ROOT, O_WRONLY)
            .expect_err("a read-only directory opened for write"),
        status::ROFS
    );
    assert_eq!(
        client
            .open(ROOT, O_RDWR)
            .expect_err("a read-only directory opened for write"),
        status::ROFS
    );
    assert!(client.open(ROOT, O_RDONLY).is_ok(), "listing it is fine");

    // Reading through the same node is untouched.
    let handle = client.open(file.node_id, O_RDONLY).expect("opens to read");
    assert_eq!(client.read(handle, 0, 4).expect("reads"), b"0123");
    // Nothing was created on the host.
    assert!(!fixture.tree("nope").exists());
}

#[test]
fn a_read_only_node_cannot_be_given_a_writable_name_by_a_hard_link() {
    let fixture = Fixture::start("link-across-policy");
    // `plain` grafts one host tree twice — read-write at `/tree`, read-only at
    // `/readonly` — so a mount of the namespace root holds both policies in one
    // session. That is what makes the cross-policy shape reachable: a read-only
    // source node and a read-write destination parent.
    let mut client = fixture.server.mount("plain", "/");
    let readonly = client.lookup(ROOT, "readonly").expect("resolves");
    let protected = client
        .lookup(readonly.node_id, "data.bin")
        .expect("resolves read-only");
    let writable = client.lookup(ROOT, "tree").expect("resolves read-write");

    // Linking is a write through the *source* node as much as through the
    // destination: a new name in a read-write directory would let the guest open
    // the read-only inode for writing.
    assert_eq!(
        client
            .link(writable.node_id, protected.node_id, "escape")
            .expect_err("a read-only inode may not gain a writable name"),
        status::ROFS
    );
    assert!(!fixture.tree("escape").exists());

    // The same inode reached through the read-write graft links as it should.
    let admitted = client
        .lookup(writable.node_id, "data.bin")
        .expect("resolves");
    client
        .link(writable.node_id, admitted.node_id, "allowed")
        .expect("a read-write node links");
    assert!(fixture.tree("allowed").exists());
}

#[test]
fn a_create_lands_with_reverse_mapped_ownership_and_presents_forward() {
    let fixture = Fixture::start("ownership");
    let mut client = fixture.server.mount("project", "/project");
    // The namespace maps the invoking user to guest 0, so a guest-root create
    // must land owned by the invoking user on the host.
    client.as_user(0, 0);

    let (entry, handle) = client
        .create(ROOT, "new", O_RDWR, 0o600)
        .expect("the namespace admits this name read-write");
    client.release(handle).expect("releases");

    // Presented forward-mapped: the guest sees root.
    assert_eq!(entry.attr.uid.get(), 0);
    assert_eq!(entry.attr.gid.get(), 0);
    // And the host holds the invoking user's ids.
    let metadata = fs::metadata(fixture.join("project/new")).expect("stattable");
    assert_eq!(metadata.uid(), rustix::process::getuid().as_raw());
    assert_eq!(metadata.gid(), rustix::process::getgid().as_raw());

    // A name the namespace hides cannot be created through it: the guest would
    // not be able to see what it made.
    assert_eq!(
        client
            .create(ROOT, "invisible", O_RDWR, 0o600)
            .expect_err("hidden by the wildcard"),
        status::ACCESS
    );
    assert!(!fixture.join("project/invisible").exists());
}

// ---------------------------------------------------------------------------
// Criterion 4 — symlinks and containment
// ---------------------------------------------------------------------------

#[test]
fn a_symlink_is_returned_as_a_symlink_and_never_followed() {
    let fixture = Fixture::start("symlinks");
    symlink("/etc/hostname", fixture.tree("escape")).expect("writable");
    symlink("../../../../etc", fixture.tree("upwards")).expect("writable");
    symlink("data.bin", fixture.tree("inside")).expect("writable");
    let mut client = fixture.server.mount("plain", "/tree");

    for (name, target) in [
        ("escape", "/etc/hostname"),
        ("upwards", "../../../../etc"),
        ("inside", "data.bin"),
    ] {
        let entry = client.lookup(ROOT, name).expect("the symlink resolves");
        assert!(entry.is_symlink(), "{name} must resolve as a symlink");
        // Reading a symlink is not following it: an escaping target comes back
        // verbatim, for the client kernel to resolve in its own namespace.
        assert_eq!(
            client.readlink(entry.node_id).expect("readable"),
            target.as_bytes()
        );
        // Opening one fails instead of following it out of the graft.
        assert!(client.open(entry.node_id, O_RDONLY).is_err());
        // And nothing resolves *through* it.
        assert_eq!(
            client
                .lookup(entry.node_id, "passwd")
                .expect_err("not a directory"),
            status::NOTDIR
        );
    }

    // A symlink in a mount subpath is a mount error, not a redirection: the
    // handshake walk follows nothing, so the subpath below it does not exist.
    symlink("sub", fixture.tree("sublink")).expect("writable");
    let mut through = fixture.server.dial();
    assert_eq!(
        through
            .hello("plain", "/tree/sublink/inner")
            .expect_err("a symlink component is a mount error"),
        status::LOOP
    );
    // And a symlink cannot itself be a mount root.
    let mut onto = fixture.server.dial();
    assert_eq!(
        onto.hello("plain", "/tree/sublink")
            .expect_err("a mount root is a directory"),
        status::NOTDIR
    );
}

#[test]
fn a_symlink_node_is_not_a_hard_link_target() {
    let fixture = Fixture::start("link-symlink");
    fs::write(fixture.join("outside.txt"), b"outside the graft").expect("writable");
    let outside = fixture.join("outside.txt");
    symlink(&outside, fixture.tree("escape")).expect("writable");
    let mut client = fixture.server.mount("plain", "/tree");

    let link = client.lookup(ROOT, "escape").expect("resolves");
    assert!(link.is_symlink());

    // `link` hardlinks through `/proc/self/fd` with `AT_SYMLINK_FOLLOW`, and
    // only the kind check keeps that from being asked to resolve a symlink.
    // Nothing but a regular file or a directory may be a hard-link target.
    assert_eq!(
        client
            .link(ROOT, link.node_id, "copied")
            .expect_err("a symlink is not a hard-link target"),
        status::PERM
    );
    assert!(!fixture.tree("copied").exists(), "and nothing was created");
    assert_eq!(
        fs::metadata(&outside).expect("host-side").nlink(),
        1,
        "the outside file gained no name inside the graft"
    );
}

#[test]
fn a_guest_symlink_to_an_outside_path_cannot_be_linked_into_a_graft() {
    let fixture = Fixture::start("link-symlink-escape");
    let outside = fixture.join("outside.txt");
    fs::write(&outside, b"outside the graft").expect("writable");
    let outside_path = outside.to_str().expect("a utf-8 fixture path");
    let mut client = fixture.server.mount("plain", "/tree");

    // The guest's own symlink, naming an absolute path the namespace never
    // grafted, looked up as the symlink node it is.
    let created = client
        .symlink(ROOT, "escape", outside_path)
        .expect("a guest may create a symlink");
    assert!(created.is_symlink());
    let looked_up = client.lookup(ROOT, "escape").expect("resolves");
    assert!(looked_up.is_symlink());

    // Hard-linking it must not become a way to give the *target* a name inside
    // the graft: the target is whatever the guest wrote, and the server never
    // resolves that.
    assert_eq!(
        client
            .link(ROOT, looked_up.node_id, "escaped")
            .expect_err("a symlink node is not a hard-link target"),
        status::PERM
    );
    assert!(!fixture.tree("escaped").exists());
    assert_eq!(
        fs::metadata(&outside).expect("host-side").nlink(),
        1,
        "no name inside the graft names the outside inode"
    );
    let escaped = client
        .lookup(ROOT, "escaped")
        .expect_err("nothing was made");
    assert_eq!(escaped, status::NOENT);
}

#[test]
fn a_reopen_after_a_rename_over_serves_the_pinned_inode() {
    let fixture = Fixture::start("rename-over");
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");

    // Replace the name on the host, behind the server's back.
    fs::write(fixture.tree("replacement"), b"replacement").expect("writable");
    fs::rename(fixture.tree("replacement"), fixture.tree("data.bin")).expect("writable");

    // The node was pinned before the rename, so the handle it opens is the
    // *pinned* inode — not whatever now answers to the name.
    let handle = client.open(file.node_id, O_RDONLY).expect("opens");
    assert_eq!(client.read(handle, 0, 64).expect("reads"), b"0123456789");
    client.release(handle).expect("releases");

    // A fresh lookup sees the replacement, as it must.
    let fresh = client.lookup(ROOT, "data.bin").expect("resolves");
    assert_ne!(fresh.node_id, file.node_id);
    let handle = client.open(fresh.node_id, O_RDONLY).expect("opens");
    assert_eq!(client.read(handle, 0, 64).expect("reads"), b"replacement");
}

#[test]
fn a_mkdir_modes_the_directory_it_created_and_no_other() {
    let fixture = Fixture::start("mkdir-replaced");
    let mut client = fixture.server.mount("plain", "/tree");

    // The guest holds a node for `sub`, and the host then frees the name behind
    // the server's back — the concurrent host-side modification the design
    // expects. A directory node is keyed by its namespace path, so the session
    // still holds the old inode under that name.
    let sub = client.lookup(ROOT, "sub").expect("resolves");
    fs::rename(fixture.tree("sub"), fixture.tree("moved")).expect("writable");
    let moved = fs::metadata(fixture.tree("moved"))
        .expect("host-side")
        .mode()
        & 0o7777;

    let created = client.mkdir(ROOT, "sub", 0o777).expect("creates");
    assert_eq!(
        fs::metadata(fixture.tree("sub")).expect("host-side").mode() & 0o7777,
        0o777,
        "the guest's bits land on the directory it just created"
    );
    assert_eq!(
        fs::metadata(fixture.tree("moved"))
            .expect("host-side")
            .mode()
            & 0o7777,
        moved,
        "and on nothing else — least of all a directory the guest never named"
    );
    // The entry reply describes the directory that was just *created*, not the
    // node the session happened to hold for that namespace path: a key whose
    // entry has been replaced retires its node and the resolution mints a fresh
    // one. The old id keeps answering `ESTALE`, which is what a node whose host
    // directory moved away owes the guest.
    assert_ne!(created.node_id, sub.node_id);
    assert_eq!(
        client
            .getattr(sub.node_id)
            .expect_err("the retired node names nothing"),
        status::STALE
    );
}

// ---------------------------------------------------------------------------
// Criterion 5 — node identity and lifecycle
// ---------------------------------------------------------------------------

#[test]
fn node_identity_is_stable_shared_by_hardlinks_and_released_by_forget() {
    let fixture = Fixture::start("identity");
    let mut client = fixture.server.mount("plain", "/tree");

    let first = client.lookup(ROOT, "data.bin").expect("resolves");
    let again = client.lookup(ROOT, "data.bin").expect("resolves again");
    assert_eq!(first.node_id, again.node_id, "one entry, one node id");
    assert_eq!(first.attr.ino.get(), again.attr.ino.get(), "and one ino");
    assert_eq!(first.generation, 0, "the generation field is reserved at 0");

    // A hardlink is the same inode: the same ino, a different name.
    let link = client.link(ROOT, first.node_id, "hardlink").expect("links");
    assert_eq!(link.attr.ino.get(), first.attr.ino.get());
    assert_eq!(
        link.node_id, first.node_id,
        "one host inode under one share mode is one node"
    );

    // The pin is real, and forgetting it closes it.
    let path = fixture.tree("data.bin");
    assert!(open_descriptors(&path) > 0, "the node holds a pinned fd");
    // Three lookups are outstanding: two of the name, one of the hardlink.
    client.forget(first.node_id, 3);
    // A forget is answered by nothing and served on its own task, so no later
    // round trip proves it has run: the descriptor count is polled to a
    // deadline, as the teardown observation below is.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while open_descriptors(&path) > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        open_descriptors(&path),
        0,
        "forgetting the last lookup closes the pin"
    );

    // Node ids are never reused within a session.
    let fresh = client.lookup(ROOT, "data.bin").expect("resolves");
    assert!(fresh.node_id > first.node_id);
    assert!(open_descriptors(&path) > 0);

    // Session teardown drops the whole table.
    drop(client);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while open_descriptors(&path) > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        open_descriptors(&path),
        0,
        "a disconnect closes everything the session held"
    );
}

#[test]
fn a_request_naming_a_node_and_a_handle_must_name_one_file() {
    let fixture = Fixture::start("handle-coherence");
    let mut client = fixture.server.mount("plain", "/tree");

    let root_listing = client.open(ROOT, O_RDONLY).expect("the root opens");
    let sub = client.lookup(ROOT, "sub").expect("resolves");
    let sub_listing = client
        .open(sub.node_id, O_RDONLY)
        .expect("the subdirectory opens");

    // A listing belongs to the directory it was opened through: it was
    // materialized under that directory's policy, so walking it under another
    // node would hand out its entries — with its share modes — under a
    // namespace path they never belonged to.
    assert_eq!(
        client
            .readdirplus(sub.node_id, root_listing, 0, 64 * 1024)
            .expect_err("a listing of another directory"),
        status::BADF
    );
    assert!(
        client
            .readdirplus(sub.node_id, sub_listing, 0, 64 * 1024)
            .is_ok(),
        "its own listing walks"
    );

    // The same for a handle-flagged setattr: the truncate has to land on the
    // file whose share mode the request checked.
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, O_RDWR).expect("opens");
    let mut request = setattr(setattr_valid::SIZE | setattr_valid::HANDLE);
    request.handle = U64::new(handle);
    assert_eq!(
        client
            .setattr(sub.node_id, request)
            .expect_err("a handle of another node"),
        status::BADF
    );
    let attr = client
        .setattr(file.node_id, request)
        .expect("its own handle truncates");
    assert_eq!(attr.size.get(), 0);
    assert_eq!(fs::read(fixture.tree("data.bin")).expect("readable"), b"");
}

#[test]
fn a_disconnect_releases_the_session_while_a_request_is_still_blocked() {
    let fixture = Fixture::start("blocked-teardown");
    let mut holder = fixture.server.mount("plain", "/tree");
    let mut client = fixture.server.mount("plain", "/tree");

    // One session takes the whole file, so the other's lock request blocks on
    // the host — where nothing can cancel it.
    let held = holder.lookup(ROOT, "data.bin").expect("resolves");
    let held_handle = holder.open(held.node_id, O_RDWR).expect("opens");
    holder
        .setlk(held_handle, lock(1, lock_type::WRITE, 0, u64::MAX), false)
        .expect("the range is free");

    // The waiting session also holds an unrelated node, and that node's pin is
    // what its teardown has to release.
    let sub = fixture.tree("sub");
    client.lookup(ROOT, "sub").expect("resolves");
    assert!(open_descriptors(&sub) > 0, "the session pinned it");

    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, O_RDWR).expect("opens");
    client.send(
        0,
        &voidport_proto::ops::file::SetlkRequest {
            handle: U64::new(handle),
            lock: lock(2, lock_type::WRITE, 0, u64::MAX),
            flags: U32::new(1),
            reserved: U32::ZERO,
        },
        &[],
    );
    std::thread::sleep(Duration::from_millis(100));

    // The connection goes while that request is still waiting for the lock.
    // Teardown may not wait for it: the session's handles and nodes close now.
    drop(client);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while open_descriptors(&sub) > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        open_descriptors(&sub),
        0,
        "a disconnect releases the session even with a request blocked on the host"
    );

    // The session that stayed is untouched.
    holder
        .setlk(held_handle, lock(1, lock_type::UNLOCK, 0, u64::MAX), false)
        .expect("releases");
    assert!(holder.lookup(ROOT, "data.bin").is_ok());
}

#[test]
fn a_listing_entry_hidden_before_its_reply_gives_its_lookup_back() {
    let fixture = Fixture::start("hidden-listing-accounting");
    let mut control = fixture.server.connect();
    let mut client = fixture.server.mount("plain", "/tree");

    // The session already holds a node for this entry, so the walk below meets
    // it again and counts its lookup against the node instead of pinning one.
    let entry = client.lookup(ROOT, "data.bin").expect("resolves");
    // The listing is materialized while every entry is still visible.
    let handle = client.open(ROOT, O_RDONLY).expect("the root opens");

    // Ownership policy now hides every file whose owner the map does not name,
    // and it names none — the host tree belongs to the invoking identity.
    control.expect_ok(&Request::OwnershipSet {
        namespace: NamespaceName::new("plain").expect("a valid namespace name"),
        ownership: OwnershipSpec::Map {
            unmapped: UnmappedPolicy::Hide,
            squash_uid: 65534,
            squash_gid: 65534,
            uid_map: Vec::new(),
            gid_map: Vec::new(),
        },
    });

    // Every entry of the materialized listing is hidden now, so the reply
    // describes none of them...
    let entries = client
        .readdirplus(ROOT, handle, 0, 64 * 1024)
        .expect("the listing walks");
    assert!(entries.is_empty(), "the walk emitted {entries:?}");

    // ...and a lookup no entry reply describes is one the client can never
    // give back, so the walk gave it back itself. The only count left is the
    // test's own lookup, and forgetting it closes the pin.
    client.forget(entry.node_id, 1);
    let path = fixture.tree("data.bin");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while open_descriptors(&path) > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        open_descriptors(&path),
        0,
        "a skipped listing entry kept the lookup readdirplus counted for it"
    );
}

// ---------------------------------------------------------------------------
// Criterion 6 — concurrency
// ---------------------------------------------------------------------------

#[test]
fn overlapping_requests_complete_out_of_order() {
    let fixture = Fixture::start("out-of-order");
    let mut blocker = fixture.server.mount("plain", "/tree");
    let mut client = fixture.server.mount("plain", "/tree");

    // One session holds a whole-file lock; the other asks for it and blocks.
    let blocked_file = blocker.lookup(ROOT, "data.bin").expect("resolves");
    let blocked_handle = blocker.open(blocked_file.node_id, O_RDWR).expect("opens");
    blocker
        .setlk(
            blocked_handle,
            lock(1, lock_type::WRITE, 0, u64::MAX),
            false,
        )
        .expect("the range is free");

    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, O_RDWR).expect("opens");
    let slow = client.send(
        0,
        &voidport_proto::ops::file::SetlkRequest {
            handle: U64::new(handle),
            lock: lock(2, lock_type::WRITE, 0, u64::MAX),
            flags: U32::new(1),
            reserved: U32::ZERO,
        },
        &[],
    );
    // Behind it, a request that can be served immediately.
    let quick = client.send(
        ROOT,
        &GetattrRequest {
            handle: U64::ZERO,
            flags: U32::ZERO,
            reserved: U32::ZERO,
        },
        &[],
    );

    let (first, status) = client.receive_status::<voidport_proto::ops::node::GetattrResponse>();
    assert_eq!(first, quick, "the fast request answers first");
    assert_eq!(status, 0);

    // Releasing the lock lets the blocked one through.
    blocker
        .setlk(
            blocked_handle,
            lock(1, lock_type::UNLOCK, 0, u64::MAX),
            false,
        )
        .expect("releases");
    let (second, status) = client.receive_status::<voidport_proto::ops::file::SetlkResponse>();
    assert_eq!(second, slow, "and the blocked one answers when it can");
    assert_eq!(status, 0);
}

/// Stacked lock waiters cost memory, not threads.
///
/// This is the property the design's waits-are-async rule exists for, and it is
/// only observable at scale: a blocking `SETLKW` served on the blocking pool
/// parks one pool thread per waiter, and the pool is 512 threads. So the storm
/// below is deliberately larger than that. With the old shape the 513th waiter
/// queues *behind the pool*, and every unrelated request of every other session
/// — each of which also needs a pool thread for its host syscalls — queues
/// behind it too; the bystander's lookup below never returns.
///
/// Three things are asserted, in the order they matter:
///
/// 1. a session with nothing to do with the contended file is served promptly
///    while the storm is parked (the pool is free);
/// 2. releasing the lock wakes a waiter promptly (the backoff cap is a
///    latency, not a stall);
/// 3. dropping the connection releases every parked waiter's descriptor (the
///    wait really is cancelled, and cancellation cleans up).
#[test]
fn hundreds_of_stacked_lock_waiters_leave_the_blocking_pool_free() {
    /// More waiters than tokio's blocking pool has threads.
    const WAITERS: u64 = 700;

    let fixture = Fixture::start("lock-storm");
    let mut holder = fixture.server.mount("plain", "/tree");
    let mut storm = fixture.server.mount("plain", "/tree");
    let mut bystander = fixture.server.mount("plain", "/tree");
    let path = fixture.tree("data.bin");

    // One owner holds the whole file, so every waiter below conflicts.
    let held = holder.lookup(ROOT, "data.bin").expect("resolves");
    let held_handle = holder.open(held.node_id, O_RDWR).expect("opens");
    holder
        .setlk(held_handle, lock(1, lock_type::WRITE, 0, u64::MAX), false)
        .expect("the range is free");

    // The bystander mounts and works before the storm, so what is measured
    // afterwards is the storm and not a first-time resolution.
    bystander.lookup(ROOT, "data.bin").expect("resolves");

    let file = storm.lookup(ROOT, "data.bin").expect("resolves");
    let handle = storm.open(file.node_id, O_RDWR).expect("opens");
    let baseline = open_descriptors(&path);

    // One connection, one handle, hundreds of wire lock owners: each gets its
    // own open file description, and each parks on the holder's lock.
    let mut requests = Vec::with_capacity(WAITERS as usize);
    for owner in 0..WAITERS {
        requests.push(storm.send(
            0,
            &voidport_proto::ops::file::SetlkRequest {
                handle: U64::new(handle),
                lock: lock(100 + owner, lock_type::WRITE, 0, u64::MAX),
                flags: U32::new(1),
                reserved: U32::ZERO,
            },
            &[],
        ));
    }

    // A parked waiter holds exactly one description of the file, so the
    // descriptor count is how the test sees the whole storm arrive.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while open_descriptors(&path) < baseline + WAITERS as usize
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        open_descriptors(&path) >= baseline + WAITERS as usize,
        "only {} of {WAITERS} waiters parked",
        open_descriptors(&path) - baseline
    );

    // 1. The pool is free: an unrelated session is served at once.
    let started = std::time::Instant::now();
    bystander
        .lookup(ROOT, "sub")
        .expect("the server still serves");
    let served = started.elapsed();
    assert!(
        served < Duration::from_secs(2),
        "an unrelated request waited {served:?} behind {WAITERS} parked lock waiters"
    );

    // 2. The release wakes one of them, and quickly: the retry cap is the
    //    worst case, and this bound is many times it.
    let released = std::time::Instant::now();
    holder
        .setlk(held_handle, lock(1, lock_type::UNLOCK, 0, u64::MAX), false)
        .expect("releases");
    let (answered, status) = storm.receive_status::<voidport_proto::ops::file::SetlkResponse>();
    let woken = released.elapsed();
    assert_eq!(status, 0, "the woken waiter took the lock");
    assert!(
        requests.contains(&answered),
        "an answer that belongs to no waiter: {answered}"
    );
    assert!(
        woken < Duration::from_millis(500),
        "a released lock took {woken:?} to wake a waiter"
    );

    // 3. The connection dies with hundreds of waiters still parked, and every
    //    description they were waiting to lock through goes with it.
    drop(storm);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while open_descriptors(&path) > baseline && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        open_descriptors(&path) <= baseline,
        "{} descriptors outlived the cancelled waiters",
        open_descriptors(&path) - baseline
    );
}

/// A listing batch may not queue the rest of its own session behind it.
///
/// Readdirplus admits its batch entry by entry, and each entry costs host work
/// — a pin the first time, a stat every time. That work runs with the node
/// table *not* held: the table is this session's only naming structure, so a
/// batch of thousands of entries holding it would stall every lookup, getattr
/// and entry reply the same mount issues meanwhile, which the design's
/// no-starvation posture refuses.
///
/// The assertion is a *ratio*, not a deadline: the lookup must be answered in
/// well under the time the listing takes, which is load-invariant in a way an
/// absolute bound would not be. A lookup of one name is microseconds of work
/// and the batch below is thousands of entries of it, so the two are orders of
/// magnitude apart when nothing blocks — and equal when the lookup is waiting
/// for the batch to let go of the table. The margin between those is what the
/// quarter below sits in; measured, the same test answers the lookup in
/// ~0.3 ms with the table free and in ~84 ms with the batch holding it.
#[test]
fn a_lookup_is_not_queued_behind_a_large_listing_batch() {
    const ENTRIES: usize = 5000;

    let fixture = Fixture::start("listing-does-not-block");
    let crowded = fixture.tree("crowded");
    // Through the mode-restating helper, not a bare create_dir: another
    // test's socket-bind umask window can strike a concurrently created
    // directory, and the sandbox uid then cannot write into it.
    voidportd::testing::create_directory(&crowded);
    for index in 0..ENTRIES {
        fs::write(crowded.join(format!("entry-{index:05}")), b"x").expect("writable");
    }

    let mut client = fixture.server.mount("plain", "/tree");
    let directory = client.lookup(ROOT, "crowded").expect("resolves");
    let handle = client.open(directory.node_id, O_RDONLY).expect("opens");

    // The whole listing in one batch: the frame bound is a megabyte and an
    // entry is some 150 bytes on the wire.
    let listing = client.send(
        directory.node_id,
        &voidport_proto::ops::dir::ReaddirplusRequest {
            handle: U64::new(handle),
            cookie: U64::ZERO,
            size: U32::new(client.max_frame_len()),
            reserved: U32::ZERO,
        },
        &[],
    );
    // Behind it, on the same session, one ordinary lookup.
    let started = std::time::Instant::now();
    let name = "data.bin";
    let quick = client.send(
        ROOT,
        &voidport_proto::ops::node::LookupRequest {
            name_len: U32::new(name.len() as u32),
        },
        name.as_bytes(),
    );

    let (first, status) = client.receive_status::<voidport_proto::ops::node::LookupResponse>();
    let lookup_took = started.elapsed();
    assert_eq!(first, quick, "the listing answered before the lookup");
    assert_eq!(status, 0);

    let (second, status) = client.receive_status::<voidport_proto::ops::dir::ReaddirplusResponse>();
    let listing_took = started.elapsed();
    assert_eq!(second, listing);
    assert_eq!(status, 0, "the listing itself failed");

    eprintln!(
        "the lookup answered in {lookup_took:?}, the {ENTRIES}-entry listing in {listing_took:?}"
    );
    assert!(
        listing_took >= Duration::from_millis(5),
        "the listing was too cheap for this test to mean anything: {listing_took:?}"
    );
    assert!(
        lookup_took * 4 <= listing_took,
        "the lookup took {lookup_took:?} of the listing's {listing_took:?} — it queued behind the batch"
    );
}

#[test]
fn two_sessions_see_each_others_writes_through_the_server() {
    let fixture = Fixture::start("coherence");
    let mut writer = fixture.server.mount("plain", "/tree");
    let mut reader = fixture.server.mount("plain", "/tree");

    let written = writer.lookup(ROOT, "data.bin").expect("resolves");
    let write_handle = writer.open(written.node_id, O_RDWR).expect("opens");
    let read = reader.lookup(ROOT, "data.bin").expect("resolves");
    let read_handle = reader.open(read.node_id, O_RDONLY).expect("opens");

    writer.write(write_handle, 0, b"AAAA").expect("writes");
    assert_eq!(
        reader.read(read_handle, 0, 4).expect("reads"),
        b"AAAA",
        "the server is the single point of truth"
    );

    // One host inode is one ino, in both sessions — identity is server-global
    // even though node ids are session-scoped (both mounts call their root 1).
    assert_eq!(written.attr.ino.get(), read.attr.ino.get());
    assert_eq!(
        reader.getattr(ROOT).expect("stats").ino.get(),
        writer.getattr(ROOT).expect("stats").ino.get()
    );
}

// ---------------------------------------------------------------------------
// Criterion 7 — the protocol error taxonomy on a live session
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_opcode_answers_enosys_and_the_session_lives() {
    let fixture = Fixture::start("unknown-opcode");
    let mut client = fixture.server.mount("plain", "/tree");

    // A well-framed request the server does not know: a semantic error.
    let mut frame = vec![0u8; FRAME_HEADER_LEN + 24];
    let header = voidport_proto::frame::FrameHeader::new(frame.len() as u32, 0x7FFF, 0, 4242);
    frame[..FRAME_HEADER_LEN].copy_from_slice(zerocopy::IntoBytes::as_bytes(&header));
    frame[FRAME_HEADER_LEN..].copy_from_slice(zerocopy::IntoBytes::as_bytes(&RequestHead::new(
        ROOT, 0, 0, 0,
    )));
    client.send_bytes(&frame);

    let response = client.receive().expect("an unknown opcode is answered");
    let parsed = voidport_proto::frame::Frame::parse(&response, client.max_frame_len())
        .expect("a well-framed response");
    assert_eq!(parsed.raw_opcode(), 0x7FFF, "the opcode is echoed verbatim");
    assert_eq!(parsed.request_id(), 4242);

    // And the session is untouched.
    assert!(client.getattr(ROOT).is_ok());
}

#[test]
fn a_framing_error_closes_the_connection() {
    let fixture = Fixture::start("framing-error");

    // Reserved flag bits in the header: the stream cannot be trusted.
    let mut poisoned = fixture.server.mount("plain", "/tree");
    let mut frame = vec![0u8; FRAME_HEADER_LEN + 24];
    let header = voidport_proto::frame::FrameHeader::new(frame.len() as u32, 0x0004, 0x0002, 5);
    frame[..FRAME_HEADER_LEN].copy_from_slice(zerocopy::IntoBytes::as_bytes(&header));
    poisoned.send_bytes(&frame);
    assert!(
        poisoned.receive().is_none(),
        "a framing error closes the connection"
    );

    // A second handshake on an established session is a framing error of its
    // own: the session's terms are settled, and a peer renegotiating them is a
    // peer the stream can no longer be read for.
    let mut twice = fixture.server.mount("plain", "/tree");
    let namespace = b"plain";
    twice.send(
        0,
        &voidport_proto::ops::handshake::HelloRequest {
            protocol_version: U32::new(PROTOCOL_VERSION),
            flags: U32::ZERO,
            namespace_len: U32::new(namespace.len() as u32),
            subpath_len: U32::ZERO,
            auth_len: U32::ZERO,
        },
        namespace,
    );
    assert!(
        twice.receive().is_none(),
        "a second handshake poisons the stream, and the connection closes"
    );

    // A duplicate *outstanding* request id is a framing error too. The first
    // request has to still be in flight for the id to be a duplicate at all —
    // the contract lets an id be reused once its response has arrived — so it
    // is one another session is blocking.
    let mut holder = fixture.server.mount("plain", "/tree");
    let held = holder.lookup(ROOT, "data.bin").expect("resolves");
    let held_handle = holder.open(held.node_id, O_RDWR).expect("opens");
    holder
        .setlk(held_handle, lock(1, lock_type::WRITE, 0, u64::MAX), false)
        .expect("the range is free");

    let mut duplicate = fixture.server.mount("plain", "/tree");
    let file = duplicate.lookup(ROOT, "data.bin").expect("resolves");
    let handle = duplicate.open(file.node_id, O_RDWR).expect("opens");
    duplicate.send_with_id(
        77,
        0,
        &voidport_proto::ops::file::SetlkRequest {
            handle: U64::new(handle),
            lock: lock(2, lock_type::WRITE, 0, u64::MAX),
            flags: U32::new(1),
            reserved: U32::ZERO,
        },
        &[],
    );
    duplicate.send_with_id(
        77,
        ROOT,
        &GetattrRequest {
            handle: U64::ZERO,
            flags: U32::ZERO,
            reserved: U32::ZERO,
        },
        &[],
    );
    assert!(
        duplicate.receive().is_none(),
        "an id that is already outstanding poisons the stream"
    );

    // Let the blocked request finish, so no host lock outlives the test.
    holder
        .setlk(held_handle, lock(1, lock_type::UNLOCK, 0, u64::MAX), false)
        .expect("releases");

    // The other half of the same rule: an id whose answer has arrived is free
    // again. A client that spends one id on every request in turn is compliant,
    // and a server that mistook that for a duplicate would tear down a mount
    // that did nothing wrong.
    let mut reuser = fixture.server.mount("plain", "/tree");
    for _ in 0..200 {
        reuser.send_with_id(
            9,
            ROOT,
            &GetattrRequest {
                handle: U64::ZERO,
                flags: U32::ZERO,
                reserved: U32::ZERO,
            },
            &[],
        );
        assert_eq!(
            reuser.receive_status::<GetattrResponse>(),
            (9, 0),
            "an answered id is reusable"
        );
    }
}

// ---------------------------------------------------------------------------
// Criterion 8 — extended attributes and locking
// ---------------------------------------------------------------------------

#[test]
fn user_xattrs_round_trip_and_the_default_write_denials_hold() {
    let fixture = Fixture::start("xattrs");
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");

    // With no rules configured the defaults apply: every namespace but `user.*`
    // is write-denied with `EPERM`, and the blanket `EOPNOTSUPP` this server
    // used to answer for reads is gone — a read now reaches the host and comes
    // back with the host's *own* answer, whatever this filesystem's is
    // (`ENODATA` where it stores the namespace, `EOPNOTSUPP` where it does not).
    let host = fixture.tree("data.bin");
    for name in ["trusted.thing", "security.capability", "system.nfs4_acl"] {
        let directly = rustix::fs::getxattr(&host, name, &mut [0u8; 16][..])
            .expect_err("nobody set it on the host either");
        assert_eq!(
            client
                .getxattr(file.node_id, name, 0)
                .expect_err("not set on the host"),
            -directly.raw_os_error(),
            "{name}: the host's own answer, passed through untouched"
        );
        assert_eq!(
            client
                .setxattr(file.node_id, name, b"x")
                .expect_err("denied by the defaults"),
            status::PERM
        );
        assert_eq!(
            client
                .removexattr(file.node_id, name)
                .expect_err("denied by the defaults"),
            status::PERM
        );
    }
    // The ACL guard is not a default: it holds whatever the rules say, and it
    // holds here too.
    assert_eq!(
        client
            .setxattr(file.node_id, "system.posix_acl_access", b"x")
            .expect_err("the guard"),
        status::PERM
    );

    if !supports_user_xattrs(fixture.directory.path()) {
        // Criterion 8 wants a real round trip, and this machine's temporary
        // filesystem cannot store `user.*` attributes (tmpfs could not before
        // Linux 6.6). Say so out loud: a green run that asserted only the
        // refusals above must not be mistaken for coverage.
        eprintln!(
            "skipping the criterion-8 user.* xattr round trip: {} does not support user extended attributes",
            fixture.directory.path().display()
        );
        return;
    }

    client
        .setxattr(file.node_id, "user.first", b"one")
        .expect("sets");
    client
        .setxattr(file.node_id, "user.second", b"two")
        .expect("sets");

    let (size, value) = client
        .getxattr(file.node_id, "user.first", 64)
        .expect("gets");
    assert_eq!(value, b"one");
    assert_eq!(size, 3);
    // A size probe reports the size and returns nothing.
    let (size, value) = client
        .getxattr(file.node_id, "user.first", 0)
        .expect("probes");
    assert_eq!((size, value.len()), (3, 0));

    let (guest_size, mut names) = client.listxattr(file.node_id, 1024).expect("lists");
    names.sort();
    assert_eq!(names, ["user.first", "user.second"]);
    // The guest size counts a NUL per name, not this wire's headers.
    assert_eq!(
        guest_size,
        "user.first".len() as u32 + 1 + "user.second".len() as u32 + 1
    );
    let (probed, names) = client.listxattr(file.node_id, 0).expect("probes");
    assert_eq!((probed, names.len()), (guest_size, 0));

    client
        .removexattr(file.node_id, "user.first")
        .expect("removes");
    assert_eq!(
        client
            .getxattr(file.node_id, "user.first", 64)
            .expect_err("gone"),
        status::NODATA
    );
}

/// The precedence rules, the hiding rule and the ACL guard, over the wire and
/// against a namespace that really configures them.
///
/// The `attrs` namespace of the fixture carries the whole shape: the layering
/// pair on `user.*`, a read denial, an exact tie, a passthrough allow, and an
/// allow the ACL guard overrules.
#[test]
fn xattr_rules_govern_reads_and_writes_by_specificity() {
    let fixture = Fixture::start("xattr-rules");
    if !supports_user_xattrs(fixture.directory.path()) {
        eprintln!(
            "skipping the xattr rule suite: {} does not support user extended attributes",
            fixture.directory.path().display()
        );
        return;
    }
    let mut client = fixture.server.mount("attrs", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");

    // Specificity: `user.*` is write-denied, and the longer literal prefix
    // wins its own name back.
    assert_eq!(
        client
            .setxattr(file.node_id, "user.other", b"x")
            .expect_err("denied by user.*"),
        status::PERM
    );
    client
        .setxattr(file.node_id, "user.build.id", b"7")
        .expect("the longer literal prefix wins");
    // The denied write left the host untouched, which is the half of the rule
    // an errno alone does not prove.
    let host = fixture.tree("data.bin");
    assert_eq!(
        rustix::fs::getxattr(&host, "user.other", &mut [0u8; 16][..]).expect_err("never written"),
        rustix::io::Errno::NODATA
    );
    assert_eq!(
        client
            .removexattr(file.node_id, "user.other")
            .expect_err("removal is a write"),
        status::PERM
    );

    // Reads fall through to the default where only writes were stated.
    let (_, value) = client
        .getxattr(file.node_id, "user.build.id", 16)
        .expect("readable");
    assert_eq!(value, b"7");

    // A denied read hides: absent from the listing, `ENODATA` on a get. The
    // attribute really is on the host, which is what makes this a hiding test
    // and not a missing-attribute one.
    rustix::fs::setxattr(
        &host,
        "user.hidden.key",
        b"secret",
        rustix::fs::XattrFlags::empty(),
    )
    .expect("the host stores it");
    assert_eq!(
        client
            .getxattr(file.node_id, "user.hidden.key", 64)
            .expect_err("hidden"),
        status::NODATA
    );
    let (guest_size, names) = client.listxattr(file.node_id, 1024).expect("lists");
    assert!(
        !names.iter().any(|name| name.starts_with("user.hidden.")),
        "a denied read must not be advertised: {names:?}"
    );
    assert!(names.contains(&"user.build.id".to_owned()), "{names:?}");
    // The reported size counts exactly the names that are there, so it cannot
    // leak how many were hidden.
    let expected: u32 = names.iter().map(|name| name.len() as u32 + 1).sum();
    assert_eq!(guest_size, expected);

    // The exact tie: a name both rules cover reads denied, and each rule alone
    // still decides its own names.
    for (name, hidden) in [
        ("user.secret-public", true),
        ("user.only-secret", true),
        ("user.only-public", false),
    ] {
        rustix::fs::setxattr(&host, name, b"v", rustix::fs::XattrFlags::empty())
            .expect("the host stores it");
        let outcome = client.getxattr(file.node_id, name, 64);
        assert_eq!(
            outcome.is_err(),
            hidden,
            "{name}: deny must win the tie ({outcome:?})"
        );
    }

    // The ACL guard overrules an explicit `system.*` write allow, and the mode
    // bits are demonstrably unchanged afterwards — the measured bypass.
    let before = fs::metadata(&host).expect("stat").mode();
    assert_eq!(
        client
            .setxattr(
                file.node_id,
                "system.posix_acl_access",
                // A valid minimal ACL granting the owner rwx, which is exactly
                // the blob that rewrites the mode when it lands.
                &acl_blob(),
            )
            .expect_err("the guard is unconditional"),
        status::PERM
    );
    assert_eq!(
        fs::metadata(&host).expect("stat").mode(),
        before,
        "a refused ACL write may not change the permission bits"
    );

    // Passthrough honesty: the `security.*` allow lets the attempt reach the
    // host, so what comes back is the host's own answer — asserted against this
    // machine, not against a guessed posture, by making the same call
    // the server would make. The server runs in this very process, so the two
    // attempts have identical credentials.
    let directly = rustix::fs::setxattr(
        &host,
        "security.voidport",
        b"label",
        rustix::fs::XattrFlags::empty(),
    );
    if directly.is_ok() {
        rustix::fs::removexattr(&host, "security.voidport").expect("removable");
    }
    let through = client.setxattr(file.node_id, "security.voidport", b"label");
    assert_eq!(
        through.err(),
        directly.err().map(|errno| -errno.raw_os_error()),
        "an allowed write carries the host's own answer, whatever this posture is"
    );
    if through.is_ok() {
        let (_, value) = client
            .getxattr(file.node_id, "security.voidport", 64)
            .expect("and it reads back");
        assert_eq!(value, b"label");
    }

    // And the share mode still comes first: `EROFS` precedes every rule.
    let mut readonly = fixture.server.mount("attrs", "/readonly");
    let same = readonly.lookup(ROOT, "data.bin").expect("resolves");
    assert_eq!(
        readonly
            .setxattr(same.node_id, "user.build.id", b"9")
            .expect_err("read-only"),
        status::ROFS
    );
    assert_eq!(
        readonly
            .setxattr(same.node_id, "user.other", b"9")
            .expect_err("read-only, before the rule that would also deny it"),
        status::ROFS
    );
}

/// A minimal `system.posix_acl_access` value: version 2, then one entry each
/// for the owner, the owning group and others.
///
/// The owner entry grants `rwx`, which is what makes a landing write rewrite
/// the file's mode — the bypass the guard exists to block.
fn acl_blob() -> Vec<u8> {
    let mut blob = vec![2u8, 0, 0, 0];
    for (tag, permissions) in [(0x0001u16, 0x0007u16), (0x0004, 0x0007), (0x0020, 0x0007)] {
        blob.extend_from_slice(&tag.to_le_bytes());
        blob.extend_from_slice(&permissions.to_le_bytes());
        blob.extend_from_slice(&u32::MAX.to_le_bytes());
    }
    blob
}

/// Special files over the wire: the two kinds served, the kinds refused, and
/// the share mode in front of both.
#[test]
fn mknod_creates_fifos_and_sockets_and_refuses_device_nodes() {
    let fixture = Fixture::start("mknod");
    let mut client = fixture.server.mount("plain", "/tree");

    for (name, mode, kind) in [
        ("pipe", 0o010_640u32, rustix::fs::FileType::Fifo),
        ("sock", 0o140_640, rustix::fs::FileType::Socket),
    ] {
        let entry = client.mknod(ROOT, name, mode).expect("creatable");
        // The entry reply describes the kind, which is what makes the guest
        // kernel install its own operations for it.
        assert_eq!(
            rustix::fs::FileType::from_raw_mode(entry.attr.mode.get()),
            kind
        );
        // And the host really holds one, with the bits the guest asked for.
        let host = fixture.tree(name);
        let metadata = fs::symlink_metadata(&host).expect("the host entry exists");
        assert_eq!(
            rustix::fs::FileType::from_raw_mode(metadata.mode()),
            kind,
            "{name}"
        );
        assert_eq!(metadata.mode() & 0o7777, 0o640, "{name}");
        // A second one collides exactly as the host does.
        assert_eq!(
            client.mknod(ROOT, name, mode).expect_err("exists"),
            -(rustix::io::Errno::EXIST.raw_os_error())
        );
    }

    // Device nodes are the required refusal, at the server as well as the client.
    for mode in [0o020_644u32, 0o060_644] {
        assert_eq!(
            client.mknod(ROOT, "device", mode).expect_err("device node"),
            status::PERM
        );
    }
    assert!(!fixture.tree("device").exists());

    // `mknod` is a creation, so a read-only share answers `EROFS` like every
    // other one.
    let mut readonly = fixture.server.mount("plain", "/readonly");
    assert_eq!(
        readonly
            .mknod(ROOT, "pipe2", 0o010_644)
            .expect_err("read-only"),
        status::ROFS
    );

    // A `user.*` write on a FIFO is refused by the host, not by policy:
    // the kernel permits `user.*` on regular files and directories only. WHICH
    // refusal it is belongs to the posture — an ordinary filesystem answers
    // `EPERM`, while a sandbox that refuses every `setxattr` outright (the
    // release build runs in one) answers `EOPNOTSUPP` — so the answer is
    // asserted against this machine by making the same call the server would
    // make. The server runs in this very process, so the two attempts have
    // identical credentials and the same syscall filter.
    let pipe = client.lookup(ROOT, "pipe").expect("resolves");
    let host_pipe = fixture.tree("pipe");
    let directly = rustix::fs::setxattr(
        &host_pipe,
        "user.thing",
        b"x",
        rustix::fs::XattrFlags::empty(),
    );
    assert!(
        directly.is_err(),
        "the kernel permits `user.*` on regular files and directories only"
    );
    assert_eq!(
        client.setxattr(pipe.node_id, "user.thing", b"x").err(),
        directly.err().map(|errno| -errno.raw_os_error()),
        "the host's refusal passes through untouched, whatever this posture is"
    );
}

#[test]
fn two_wire_owners_on_one_handle_conflict_and_unlock_independently() {
    let fixture = Fixture::start("locks");
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, O_RDWR).expect("opens");

    // One handle, two wire owners: they must conflict like two processes.
    client
        .setlk(handle, lock(1, lock_type::WRITE, 0, 3), false)
        .expect("the range is free");
    assert_eq!(
        client
            .setlk(handle, lock(2, lock_type::WRITE, 2, 6), false)
            .expect_err("overlapping"),
        status::AGAIN
    );

    // And the conflict is visible through getlk.
    let conflict = client
        .getlk(handle, lock(2, lock_type::WRITE, 0, 9))
        .expect("testable");
    assert_eq!(conflict.lock_type.get(), lock_type::WRITE);
    assert_eq!((conflict.start.get(), conflict.end.get()), (0, 3));
    assert_eq!(conflict.pid.get() as i32, -1, "an OFD lock has no pid");

    // A disjoint range does not conflict.
    client
        .setlk(handle, lock(2, lock_type::WRITE, 4, 6), false)
        .expect("disjoint");

    // Owner-specific unlock releases only that owner's locks.
    client
        .setlk(handle, lock(1, lock_type::UNLOCK, 0, u64::MAX), false)
        .expect("releases");
    let free = client
        .getlk(handle, lock(3, lock_type::WRITE, 0, 3))
        .expect("testable");
    assert_eq!(free.lock_type.get(), lock_type::UNLOCK, "owner 1 let go");
    let still_held = client
        .getlk(handle, lock(3, lock_type::WRITE, 4, 6))
        .expect("testable");
    assert_eq!(
        still_held.lock_type.get(),
        lock_type::WRITE,
        "owner 2 did not"
    );

    // Flushing an owner drops its locks too, as a close does.
    client.flush(handle, 2).expect("flushes");
    let free = client
        .getlk(handle, lock(3, lock_type::WRITE, 4, 6))
        .expect("testable");
    assert_eq!(free.lock_type.get(), lock_type::UNLOCK);
}

#[test]
fn a_read_only_handle_takes_no_write_lock() {
    let fixture = Fixture::start("lock-share-mode");
    let mut client = fixture.server.mount("plain", "/readonly");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, O_RDONLY).expect("opens to read");

    // A read lock is what a readable description is for.
    client
        .setlk(handle, lock(1, lock_type::READ, 0, u64::MAX), false)
        .expect("a read lock through a read-only handle");

    // A write lock is not: the kernel refuses one on a description that cannot
    // be written, exactly as it does through a local `O_RDONLY` descriptor. The
    // server must not quietly reopen a read-only graft's file for writing to
    // grant one.
    assert_eq!(
        client
            .setlk(handle, lock(1, lock_type::WRITE, 0, u64::MAX), false)
            .expect_err("a read-only handle holds no write lock"),
        status::BADF
    );
    assert_eq!(
        client
            .setlk(handle, lock(2, lock_type::WRITE, 0, u64::MAX), false)
            .expect_err("nor does a fresh owner on it"),
        status::BADF
    );

    // Through the read-write graft the same inode locks as it always did.
    let mut writer = fixture.server.mount("plain", "/tree");
    let same = writer.lookup(ROOT, "data.bin").expect("resolves");
    let writable = writer.open(same.node_id, O_RDWR).expect("opens");
    writer
        .setlk(writable, lock(1, lock_type::WRITE, 0, u64::MAX), false)
        .expect_err("the read-only handle's read lock conflicts");
}

#[test]
fn a_lock_query_costs_no_host_descriptor() {
    let fixture = Fixture::start("lock-queries");
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, O_RDWR).expect("opens");
    let path = fixture.tree("data.bin");
    let baseline = open_descriptors(&path);

    // A guest picks its own owner ids and has 2^64 of them. Asking whether a
    // lock could be taken is a question, not a claim, so it must not make the
    // server hold an open file description per owner it is asked about — that
    // would be a descriptor budget no cap in the design bounds.
    for owner in 1..=256u64 {
        let free = client
            .getlk(handle, lock(owner, lock_type::WRITE, 0, 3))
            .expect("testable");
        assert_eq!(free.lock_type.get(), lock_type::UNLOCK);
    }
    assert_eq!(open_descriptors(&path), baseline, "a query opens nothing");

    // Nor does releasing what an owner never held.
    for owner in 1..=256u64 {
        client
            .setlk(handle, lock(owner, lock_type::UNLOCK, 0, u64::MAX), false)
            .expect("nothing to release");
    }
    assert_eq!(open_descriptors(&path), baseline);

    // A lock that is really placed still gets its own description.
    client
        .setlk(handle, lock(1, lock_type::WRITE, 0, 3), false)
        .expect("the range is free");
    assert_eq!(
        open_descriptors(&path),
        baseline + 1,
        "a held lock needs a description of its own"
    );
    // A refused one keeps nothing, and the owner that was refused still sees
    // the conflict through getlk.
    assert_eq!(
        client
            .setlk(handle, lock(2, lock_type::WRITE, 0, 3), false)
            .expect_err("owner 1 holds it"),
        status::AGAIN
    );
    let conflict = client
        .getlk(handle, lock(2, lock_type::WRITE, 0, 3))
        .expect("testable");
    assert_eq!(conflict.lock_type.get(), lock_type::WRITE);
    assert_eq!(conflict.pid.get() as i32, -1);
    assert_eq!(
        open_descriptors(&path),
        baseline + 1,
        "a refused lock keeps no description"
    );
}

// ---------------------------------------------------------------------------
// Criterion 9 — statfs
// ---------------------------------------------------------------------------

#[test]
fn statfs_distinguishes_host_backed_from_synthesized_nodes() {
    let fixture = Fixture::start("statfs");

    let mut host_backed = fixture.server.mount("plain", "/tree");
    let stats = host_backed.statfs(ROOT).expect("stats");
    assert!(stats.blocks.get() > 0, "a real filesystem has blocks");
    assert!(stats.bsize.get() > 0);
    assert!(stats.namelen.get() > 0);

    let mut synthesized = fixture.server.mount("deep", "/deep");
    let stats = synthesized.statfs(ROOT).expect("stats");
    assert_eq!(stats.blocks.get(), 0);
    assert_eq!(stats.bfree.get(), 0);
    assert_eq!(stats.files.get(), 0);
    assert_eq!(stats.bsize.get(), 0);
}

// ---------------------------------------------------------------------------
// Attribute changes, which the criteria touch through enforcement
// ---------------------------------------------------------------------------

#[test]
fn setattr_truncates_chmods_and_refuses_an_unexpressible_chown() {
    let fixture = Fixture::start("setattr");
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");

    let mut request = setattr(setattr_valid::SIZE);
    request.size = U64::new(4);
    let attr = client.setattr(file.node_id, request).expect("truncates");
    assert_eq!(attr.size.get(), 4);
    assert_eq!(
        fs::read(fixture.tree("data.bin")).expect("readable"),
        b"0123"
    );

    let mut request = setattr(setattr_valid::MODE);
    request.mode = U32::new(0o640);
    let attr = client.setattr(file.node_id, request).expect("chmods");
    assert_eq!(attr.mode.get() & 0o7777, 0o640);

    // `plain` is passthrough ownership, so a chown to another id is expressible
    // but not permitted; either way the guest is told the truth instead of
    // being lied to.
    let mut request = setattr(setattr_valid::UID);
    request.uid = U32::new(0);
    let result = client.setattr(file.node_id, request);
    if rustix::process::getuid().is_root() {
        assert!(result.is_ok());
    } else {
        assert!(
            result.is_err(),
            "an unprivileged chown must not report success"
        );
    }
}
