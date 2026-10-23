#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};

use rustix::fs::OFlags;
use support::fixture::{Fixture, supports_user_xattrs};
use support::wire::{ROOT, status};
use support::{Dial as _, open_descriptors};
use voidport_control::{NamespaceName, OwnershipSpec, Request, Rule, ShareMode, UnmappedPolicy};
use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::frame::FRAME_HEADER_LEN;
use voidport_proto::limits::LIMITS;
use voidport_proto::message::RequestHead;
use voidport_proto::ops::file::{FileLock, lock_type};
use voidport_proto::ops::node::{GetattrRequest, GetattrResponse, SetattrRequest, setattr_valid};
use zerocopy::byteorder::little_endian::{U32, U64};

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

fn lock(owner: u64, kind: u32, start: u64, end: u64) -> FileLock {
    FileLock {
        start: U64::new(start),
        end: U64::new(end),
        owner: U64::new(owner),
        pid: U32::new(7),
        lock_type: U32::new(kind),
    }
}

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
    assert_eq!(reply.flags.get(), 0);

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

    let attr = client.getattr(ROOT).expect("the root stats");
    assert_eq!(attr.mode.get() & 0o7777, 0o555, "read and traverse only");
    assert_eq!(attr.nlink.get(), 2);
    assert_eq!(attr.size.get(), 0);

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

    let attr = client.getattr(ROOT).expect("the root stats");
    assert_ne!(attr.mtime.sec.get(), 0, "not the epoch");
    assert_eq!(attr.atime, attr.mtime);
    assert_eq!(attr.ctime, attr.mtime);
    assert!(
        attr.mtime.sec.get() >= i64::try_from(before).expect("a representable clock"),
        "the server started at {}, after {before}",
        attr.mtime.sec.get()
    );

    let again = client.getattr(ROOT).expect("the root stats again");
    assert_eq!(again, attr);

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

    let mut fresh = fixture.server.mount("deep", "/deep");
    assert_eq!(fresh.getattr(ROOT).expect("the root stats"), attr);
}

/// The refusal arrives although the declared bytes never do, which shows each
/// check runs on the declared length, before the part is read.
fn refused_hello(namespace_len: u32, subpath_len: u32, auth_len: u32) -> Option<i32> {
    let fixture = Fixture::start("hello-checks");
    let mut client = fixture.server.dial();
    let body = voidport_proto::ops::handshake::HelloRequest {
        protocol_version: U32::new(PROTOCOL_VERSION),
        flags: U32::ZERO,
        namespace_len: U32::new(namespace_len),
        subpath_len: U32::new(subpath_len),
        auth_len: U32::new(auth_len),
        token_len: U32::ZERO,
    };
    // The fixed part only, assembled by hand: an encoder would insist on the
    // declared bytes this test never sends.
    let header = voidport_proto::frame::FrameHeader::new(
        voidport_proto::opcode::Opcode::Hello.as_u16(),
        0,
        1,
    );
    let mut fixed = zerocopy::IntoBytes::as_bytes(&header).to_vec();
    fixed.extend_from_slice(zerocopy::IntoBytes::as_bytes(&RequestHead::new(0, 0, 0, 0)));
    fixed.extend_from_slice(zerocopy::IntoBytes::as_bytes(&body));
    client.send_bytes(&fixed);
    let reply = client.receive().expect("the refusal is answered");
    let frame = voidport_proto::frame::Frame::parse(&reply, &LIMITS).expect("a well-framed reply");
    let status = frame.status().expect("a reply");
    assert!(
        client.receive().is_none(),
        "a refused handshake ends the connection"
    );
    Some(status)
}

#[test]
fn a_subpath_above_the_path_bound_is_refused_before_it_is_read() {
    assert_eq!(
        refused_hello(5, LIMITS.path_max, 0),
        Some(-(rustix::io::Errno::NAMETOOLONG.raw_os_error()))
    );
}

#[test]
fn a_namespace_longer_than_any_registered_is_refused_before_it_is_read() {
    assert_eq!(refused_hello(1 << 20, 0, 0), Some(status::NOENT));
}

#[test]
fn an_authentication_blob_is_refused_before_it_is_read() {
    assert_eq!(refused_hello(5, 0, 1 << 20), Some(status::INVAL));
}

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

    assert_eq!(
        client.lookup(ROOT, "secret").expect_err("hidden"),
        status::NOENT
    );

    let listing = client.list(ROOT).expect("the root lists");
    let mut names: Vec<String> = listing.iter().map(support::wire::DirEntry::name).collect();
    names.sort();
    assert_eq!(names, ["bar", "file.txt", "foo", "vendor"]);

    let vendor = listing
        .iter()
        .find(|entry| entry.name() == "vendor")
        .expect("the re-targeted graft is listed");
    assert!(vendor.entry.is_directory());
    let vendor_node = client.lookup(ROOT, "vendor").expect("and it resolves");
    assert_eq!(vendor_node.attr.ino.get(), vendor.entry.attr.ino.get());
    assert!(client.lookup(vendor_node.node_id, "note").is_ok());
}

#[test]
fn data_round_trips_through_a_read_write_graft() {
    let fixture = Fixture::start("io");
    let mut client = fixture.server.mount("plain", "/tree");

    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, OFlags::RDWR).expect("opens");
    assert_eq!(client.read(handle, 0, 64).expect("reads"), b"0123456789");
    assert_eq!(client.read(handle, 4, 3).expect("reads"), b"456");
    assert_eq!(client.write(handle, 2, b"XY").expect("writes"), 2);
    assert_eq!(client.read(handle, 0, 64).expect("reads"), b"01XY456789");
    client.fsync(handle, false).expect("syncs");
    client.release(handle).expect("releases");

    assert_eq!(
        fs::read(fixture.tree("data.bin")).expect("readable"),
        b"01XY456789"
    );

    let (created, handle) = client
        .create(ROOT, "created", OFlags::RDWR, 0o644)
        .expect("creates");
    assert_eq!(client.write(handle, 0, b"new").expect("writes"), 3);
    client.release(handle).expect("releases");
    assert_eq!(fs::read(fixture.tree("created")).expect("readable"), b"new");
    assert_eq!(created.permissions(), 0o644);

    let (again, handle) = client
        .create(ROOT, "created", OFlags::RDWR, 0o600)
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
        client
            .open(file.node_id, OFlags::WRONLY)
            .expect_err("open write"),
        status::ROFS
    );
    assert_eq!(
        client
            .open(file.node_id, OFlags::RDWR)
            .expect_err("open rdwr"),
        status::ROFS
    );
    assert_eq!(
        client
            .create(ROOT, "nope", OFlags::RDWR, 0o644)
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

    assert_eq!(
        client
            .open(ROOT, OFlags::WRONLY)
            .expect_err("a read-only directory opened for write"),
        status::ROFS
    );
    assert_eq!(
        client
            .open(ROOT, OFlags::RDWR)
            .expect_err("a read-only directory opened for write"),
        status::ROFS
    );
    assert!(
        client.open(ROOT, OFlags::RDONLY).is_ok(),
        "listing it is fine"
    );

    let handle = client
        .open(file.node_id, OFlags::RDONLY)
        .expect("opens to read");
    assert_eq!(client.read(handle, 0, 4).expect("reads"), b"0123");
    assert!(!fixture.tree("nope").exists());
}

#[test]
fn a_read_only_node_cannot_be_given_a_writable_name_by_a_hard_link() {
    let fixture = Fixture::start("link-across-policy");
    // `plain` grafts one host tree twice, so a mount of the namespace root has both
    // policies in one session: a read-only source node and a read-write destination
    // parent.
    let mut client = fixture.server.mount("plain", "/");
    let readonly = client.lookup(ROOT, "readonly").expect("resolves");
    let protected = client
        .lookup(readonly.node_id, "data.bin")
        .expect("resolves read-only");
    let writable = client.lookup(ROOT, "tree").expect("resolves read-write");

    assert_eq!(
        client
            .link(writable.node_id, protected.node_id, "escape")
            .expect_err("a read-only inode may not gain a writable name"),
        status::ROFS
    );
    assert!(!fixture.tree("escape").exists());

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
    client.as_user(0, 0);

    let (entry, handle) = client
        .create(ROOT, "new", OFlags::RDWR, 0o600)
        .expect("the namespace admits this name read-write");
    client.release(handle).expect("releases");

    assert_eq!(entry.attr.uid.get(), 0);
    assert_eq!(entry.attr.gid.get(), 0);
    let metadata = fs::metadata(fixture.join("project/new")).expect("stattable");
    assert_eq!(metadata.uid(), rustix::process::getuid().as_raw());
    assert_eq!(metadata.gid(), rustix::process::getgid().as_raw());

    assert_eq!(
        client
            .create(ROOT, "invisible", OFlags::RDWR, 0o600)
            .expect_err("hidden by the wildcard"),
        status::ACCESS
    );
    assert!(!fixture.join("project/invisible").exists());
}

/// A directory and a special file are chowned after the syscall that made them,
/// which the regular-file create never runs. `plain` is passthrough, so the
/// reverse of guest 4242 is host 4242, which a server without `CAP_CHOWN` cannot
/// apply. `project` maps one id and 4242 is in neither table, so the create
/// falls to the server identity.
#[test]
fn every_created_kind_carries_the_ownership_contract_into_the_host() {
    let fixture = Fixture::start("create-ownership-kinds");
    let server = (
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
    );
    let privileged = rustix::process::getuid().is_root();

    let mut plain = fixture.server.mount("plain", "/tree");
    plain.as_user(4242, 4242);
    for (kind, name, entry) in made_by(&mut plain, ROOT, "plain") {
        let host = fs::symlink_metadata(fixture.tree(&name)).expect("the host entry exists");
        let expected = if privileged { (4242, 4242) } else { server };
        assert_eq!(
            (host.uid(), host.gid()),
            expected,
            "a {kind} lands with the reverse-mapped ids the server can apply"
        );
        assert_eq!(
            (entry.attr.uid.get(), entry.attr.gid.get()),
            (host.uid(), host.gid()),
            "passthrough presents exactly what the host recorded for the {kind}"
        );
    }

    let mut project = fixture.server.mount("project", "/project");
    project.as_user(4242, 4242);
    let foo = project.lookup(ROOT, "foo").expect("resolves");
    for (kind, name, entry) in made_by(&mut project, foo.node_id, "mapped") {
        let host = fs::symlink_metadata(fixture.join(&format!("project/foo/{name}")))
            .expect("the host entry exists");
        assert_eq!(
            (host.uid(), host.gid()),
            server,
            "an unmapped creator's {kind} falls to the server identity, not to 4242"
        );
        assert_eq!(
            (entry.attr.uid.get(), entry.attr.gid.get()),
            (0, 0),
            "and presents as the guest id the server identity maps to"
        );
    }
}

fn made_by(
    client: &mut support::wire::WireClient,
    parent: u64,
    label: &str,
) -> Vec<(&'static str, String, support::wire::Entry)> {
    let fifo = format!("pipe-{label}");
    let directory = format!("dir-{label}");
    vec![
        (
            "fifo",
            fifo.clone(),
            client.mknod(parent, &fifo, 0o010_600).expect("creatable"),
        ),
        (
            "directory",
            directory.clone(),
            client.mkdir(parent, &directory, 0o700).expect("creatable"),
        ),
    ]
}

/// The chown is never followed through to the target of the link.
#[test]
fn a_created_symlink_carries_the_ownership_contract_too() {
    /// `plain` is passthrough ownership, so these are also the host ids the
    /// entries must have.
    const GUEST: (u32, u32) = (4242, 4243);

    let fixture = Fixture::start("symlink-ownership");
    let mut client = fixture.server.mount("plain", "/tree");
    client.as_user(GUEST.0, GUEST.1);

    let link = client
        .symlink(ROOT, "link", "data.bin")
        .expect("a guest may create a symlink");
    assert!(link.is_symlink());
    client.mkdir(ROOT, "dir", 0o755).expect("creatable");
    client.mknod(ROOT, "pipe", 0o010_644).expect("creatable");

    let owner = |name: &str| {
        let metadata = fs::symlink_metadata(fixture.tree(name)).expect("the host entry exists");
        (metadata.uid(), metadata.gid())
    };
    // The file named by the link is a pre-existing entry, and its ids are
    // unchanged.
    assert_eq!(
        owner("data.bin"),
        (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw()
        )
    );
    assert_eq!(owner("link"), owner("dir"), "symlink against directory");
    assert_eq!(owner("link"), owner("pipe"), "symlink against fifo");
    if rustix::process::getuid().is_root() {
        assert_eq!(owner("link"), GUEST);
    } else {
        // Without `CAP_CHOWN` no other id is applicable, and the entries keep the
        // ids of the server.
        assert_eq!(owner("link").0, rustix::process::getuid().as_raw());
    }
}

/// No filesystem promises an order, so the expectation is read from the host
/// each time.
fn host_order(directory: &std::path::Path) -> Vec<String> {
    fs::read_dir(directory)
        .expect("listable")
        .map(|entry| {
            entry
                .expect("readable")
                .file_name()
                .into_string()
                .expect("a text name")
        })
        .collect()
}

#[test]
fn a_listing_keeps_the_order_the_host_returned() {
    let fixture = Fixture::start("listing-order");
    // Created in an order that is neither the name order nor, on a filesystem that
    // hashes names, likely to be the order they come back in.
    for index in (0..300).rev() {
        let name = format!("{:x}-entry-{index}", index * 2_654_435_761_u64 % 4093);
        fs::write(fixture.tree(&name), b"").expect("writable");
    }
    let mut control = fixture.server.connect();
    for name in ["rule-zulu", "rule-alpha"] {
        control.expect_ok(&Request::RuleAdd {
            namespace: NamespaceName::new("plain").expect("a valid namespace name"),
            rule: Rule::new(format!("/tree/{name}"), ShareMode::Ro).with_target(
                fixture
                    .join("external")
                    .to_str()
                    .expect("a utf-8 fixture path")
                    .to_owned(),
            ),
        });
    }
    let mut client = fixture.server.mount("plain", "/tree");

    let names = |client: &mut support::wire::WireClient, node: u64| -> Vec<String> {
        client
            .list(node)
            .expect("lists")
            .iter()
            .map(support::wire::DirEntry::name)
            .collect()
    };
    let mut expected = host_order(fixture.graft_root());
    expected.extend(["rule-alpha".to_owned(), "rule-zulu".to_owned()]);
    assert_eq!(names(&mut client, ROOT), expected);

    let sub = client.lookup(ROOT, "sub").expect("resolves");
    for name in ["zz", "mm", "aa", "0"] {
        fs::write(fixture.tree(&format!("sub/{name}")), b"").expect("writable");
    }
    assert_eq!(
        names(&mut client, sub.node_id),
        host_order(&fixture.tree("sub"))
    );
}

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
        // An escaping target comes back verbatim, for the client kernel to resolve.
        assert_eq!(
            client.readlink(entry.node_id).expect("readable"),
            target.as_bytes()
        );
        assert!(client.open(entry.node_id, OFlags::RDONLY).is_err());
        assert_eq!(
            client
                .lookup(entry.node_id, "passwd")
                .expect_err("not a directory"),
            status::NOTDIR
        );
    }

    symlink("sub", fixture.tree("sublink")).expect("writable");
    let mut through = fixture.server.dial();
    assert_eq!(
        through
            .hello("plain", "/tree/sublink/inner")
            .expect_err("a symlink component is a mount error"),
        status::LOOP
    );
    let mut onto = fixture.server.dial();
    assert_eq!(
        onto.hello("plain", "/tree/sublink")
            .expect_err("a mount root is a directory"),
        status::NOTDIR
    );
}

#[test]
fn a_rule_that_names_a_link_presents_the_link() {
    let fixture = Fixture::start("rule-link");
    let links = [
        ("to-directory", "tree".to_owned()),
        ("to-file", fixture.tree("data.bin").display().to_string()),
        ("dangling", "nowhere/at/all".to_owned()),
    ];
    let mut control = fixture.server.connect();
    let namespace = NamespaceName::new("deep").expect("a valid namespace name");
    for (name, text) in &links {
        symlink(text, fixture.join(name)).expect("writable");
        control.expect_ok(&Request::RuleAdd {
            namespace: namespace.clone(),
            rule: Rule::new(format!("/deep/{name}"), ShareMode::Rw).with_target(
                fixture
                    .join(name)
                    .to_str()
                    .expect("a utf-8 fixture path")
                    .to_owned(),
            ),
        });
    }
    // What the path names is the state of the host, so the table is not refused for
    // it.
    control.expect_ok(&Request::RuleAdd {
        namespace,
        rule: Rule::new("/deep/to-directory/sub", ShareMode::Ro),
    });
    let mut client = fixture.server.mount("deep", "/deep");

    for (name, text) in &links {
        let entry = client.lookup(ROOT, name).expect("the rule resolves");
        assert!(entry.is_symlink(), "{name} must present as a symlink");
        assert_eq!(
            client.readlink(entry.node_id).expect("readable"),
            text.as_bytes(),
            "{name} carries the host's link text unchanged"
        );
        assert!(client.open(entry.node_id, OFlags::RDONLY).is_err());
        for beneath in ["sub", "data.bin"] {
            assert_eq!(
                client
                    .lookup(entry.node_id, beneath)
                    .expect_err("not a directory"),
                status::NOTDIR,
                "{name}/{beneath}"
            );
        }
    }

    let listed = client.list(ROOT).expect("the root lists");
    for (name, _) in &links {
        let entry = listed
            .iter()
            .find(|entry| entry.name() == *name)
            .unwrap_or_else(|| panic!("{name} is listed"));
        assert!(entry.entry.is_symlink(), "{name} lists as a symlink");
    }

    for subpath in ["/deep/to-directory", "/deep/to-directory/sub"] {
        let mut onto = fixture.server.dial();
        assert_eq!(
            onto.hello("deep", subpath)
                .expect_err("a mount root is a directory"),
            status::NOTDIR,
            "{subpath}"
        );
    }
}

#[test]
fn a_symlink_node_gains_a_second_name_by_a_hard_link() {
    let fixture = Fixture::start("link-symlink");
    let outside = fixture.join("outside.txt");
    fs::write(&outside, b"outside the graft").expect("writable");
    let outside_path = outside.to_str().expect("a utf-8 fixture path");
    let mut client = fixture.server.mount("plain", "/tree");

    symlink("/nowhere/at/all", fixture.tree("dangling")).expect("writable");
    client
        .symlink(ROOT, "escape", outside_path)
        .expect("a guest may create a symlink");

    for (name, target) in [("dangling", "/nowhere/at/all"), ("escape", outside_path)] {
        let original = client.lookup(ROOT, name).expect("resolves");
        assert!(original.is_symlink());
        let second = format!("{name}-again");

        let linked = client
            .link(ROOT, original.node_id, &second)
            .expect("a symlink is a hard-link target");
        assert!(linked.is_symlink(), "{name}: the second name is a symlink");
        assert_eq!(linked.attr.ino.get(), original.attr.ino.get(), "{name}");
        assert_eq!(linked.attr.nlink.get(), 2, "{name}");
        assert_eq!(
            client.readlink(linked.node_id).expect("readable"),
            target.as_bytes(),
            "{name}: the target text is carried over verbatim"
        );

        let host_original = fs::symlink_metadata(fixture.tree(name)).expect("host-side");
        let host_second = fs::symlink_metadata(fixture.tree(&second)).expect("host-side");
        assert!(host_second.file_type().is_symlink(), "{name}");
        assert_eq!(host_second.ino(), host_original.ino(), "{name}");
        assert_eq!(host_second.nlink(), 2, "{name}");
        assert_eq!(
            fs::read_link(fixture.tree(&second)).expect("host-side"),
            std::path::Path::new(target),
            "{name}"
        );
    }

    assert_eq!(fs::read(&outside).expect("host-side"), b"outside the graft");
    assert_eq!(fs::metadata(&outside).expect("host-side").nlink(), 1);
}

#[test]
fn a_directory_node_is_refused_a_hard_link_by_the_host() {
    let fixture = Fixture::start("link-directory");
    let mut client = fixture.server.mount("plain", "/tree");
    let sub = client.lookup(ROOT, "sub").expect("resolves");
    assert!(sub.is_directory());

    assert_eq!(
        client
            .link(ROOT, sub.node_id, "sub-again")
            .expect_err("a directory is not a hard-link target"),
        status::PERM
    );
    assert!(
        fs::symlink_metadata(fixture.tree("sub-again")).is_err(),
        "and nothing was created"
    );
}

#[test]
fn a_reopen_after_a_rename_over_serves_the_pinned_inode() {
    let fixture = Fixture::start("rename-over");
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");

    fs::write(fixture.tree("replacement"), b"replacement").expect("writable");
    fs::rename(fixture.tree("replacement"), fixture.tree("data.bin")).expect("writable");

    let handle = client.open(file.node_id, OFlags::RDONLY).expect("opens");
    assert_eq!(client.read(handle, 0, 64).expect("reads"), b"0123456789");
    client.release(handle).expect("releases");

    let fresh = client.lookup(ROOT, "data.bin").expect("resolves");
    assert_ne!(fresh.node_id, file.node_id);
    let handle = client.open(fresh.node_id, OFlags::RDONLY).expect("opens");
    assert_eq!(client.read(handle, 0, 64).expect("reads"), b"replacement");
}

#[test]
fn a_mkdir_modes_the_directory_it_created_and_no_other() {
    let fixture = Fixture::start("mkdir-replaced");
    let mut client = fixture.server.mount("plain", "/tree");

    // A directory node is keyed by its namespace path, so the session still has the
    // old inode under that name.
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
    // A key whose entry was replaced retires its node and the resolution mints a
    // fresh one. The old id still fails with `ESTALE`.
    assert_ne!(created.node_id, sub.node_id);
    assert_eq!(
        client
            .getattr(sub.node_id)
            .expect_err("the retired node names nothing"),
        status::STALE
    );
}

#[test]
fn node_identity_is_stable_shared_by_hardlinks_and_released_by_forget() {
    let fixture = Fixture::start("identity");
    let mut client = fixture.server.mount("plain", "/tree");

    let first = client.lookup(ROOT, "data.bin").expect("resolves");
    let again = client.lookup(ROOT, "data.bin").expect("resolves again");
    assert_eq!(first.node_id, again.node_id, "one entry, one node id");
    assert_eq!(first.attr.ino.get(), again.attr.ino.get(), "and one ino");
    assert_eq!(first.generation, 0, "the generation field is reserved at 0");

    let link = client.link(ROOT, first.node_id, "hardlink").expect("links");
    assert_eq!(link.attr.ino.get(), first.attr.ino.get());
    assert_eq!(
        link.node_id, first.node_id,
        "one host inode under one share mode is one node"
    );

    let path = fixture.tree("data.bin");
    assert!(open_descriptors(&path) > 0, "the node holds a pinned fd");
    client.forget(first.node_id, 3);
    client.fence();
    assert_eq!(
        open_descriptors(&path),
        0,
        "forgetting the last lookup closes the pin"
    );

    let fresh = client.lookup(ROOT, "data.bin").expect("resolves");
    assert!(fresh.node_id > first.node_id);
    assert!(open_descriptors(&path) > 0);

    client.disconnect(&fixture.server);
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

    let root_listing = client.open(ROOT, OFlags::RDONLY).expect("the root opens");
    let sub = client.lookup(ROOT, "sub").expect("resolves");
    let sub_listing = client
        .open(sub.node_id, OFlags::RDONLY)
        .expect("the subdirectory opens");

    // A listing was materialized under the policy of its directory, so walking it
    // under another node would hand out its entries with their share modes under a
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

    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, OFlags::RDWR).expect("opens");
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
fn a_disconnect_releases_the_session_behind_a_blocking_lock_request() {
    let fixture = Fixture::start("blocked-teardown");
    let mut holder = fixture.server.mount("plain", "/tree");
    let mut client = fixture.server.mount("plain", "/tree");

    let held = holder.lookup(ROOT, "data.bin").expect("resolves");
    let held_handle = holder.open(held.node_id, OFlags::RDWR).expect("opens");
    holder
        .setlk(held_handle, lock(1, lock_type::WRITE, 0, u64::MAX), false)
        .expect("the range is free");

    // The reference of the session on this unrelated node is what its teardown has
    // to release.
    let sub = fixture.tree("sub");
    client.lookup(ROOT, "sub").expect("resolves");
    assert!(open_descriptors(&sub) > 0, "the session pinned it");

    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, OFlags::RDWR).expect("opens");
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
    // A reply to a later request shows the server has read the lock request.
    client.fence();

    // Teardown may not wait for the lock request.
    client.disconnect(&fixture.server);
    assert_eq!(
        open_descriptors(&sub),
        0,
        "a disconnect releases the session behind a blocking lock request"
    );

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

    // The session already has a node for this entry, so the walk meets it again
    // and counts its lookup against the node instead of opening one.
    let entry = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(ROOT, OFlags::RDONLY).expect("the root opens");

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

    let entries = client
        .readdirplus(ROOT, handle, 0, 64 * 1024)
        .expect("the listing walks");
    assert!(entries.is_empty(), "the walk emitted {entries:?}");

    // A lookup that no entry reply describes can never be given back by the client,
    // so the walk gave it back itself.
    client.forget(entry.node_id, 1);
    client.fence();
    let path = fixture.tree("data.bin");
    assert_eq!(
        open_descriptors(&path),
        0,
        "a skipped listing entry kept the lookup readdirplus counted for it"
    );
}

#[test]
fn overlapping_requests_complete_out_of_order() {
    let fixture = Fixture::start("out-of-order");
    let mut blocker = fixture.server.mount("plain", "/tree");
    let mut client = fixture.server.mount("plain", "/tree");

    let blocked_file = blocker.lookup(ROOT, "data.bin").expect("resolves");
    let blocked_handle = blocker
        .open(blocked_file.node_id, OFlags::RDWR)
        .expect("opens");
    blocker
        .setlk(
            blocked_handle,
            lock(1, lock_type::WRITE, 0, u64::MAX),
            false,
        )
        .expect("the range is free");

    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, OFlags::RDWR).expect("opens");
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
    // The blocked request cannot finish before the lock is released, whether or
    // not it has parked yet.
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

/// A blocking `SETLKW` served on the pool would park one pool thread per
/// request, so this is only observable at scale. The requests are spread over
/// sessions, one each, because the pool is a resource of the whole process. The
/// server reads the next request of a connection only once the one before it has
/// a thread, so the test waits until a request sent after every lock request is
/// replied to.
#[test]
fn hundreds_of_blocking_lock_requests_leave_the_blocking_pool_free() {
    const REQUESTS: u64 = 700;

    let fixture = Fixture::start("lock-storm");
    let mut holder = fixture.server.mount("plain", "/tree");
    let mut witness = fixture.server.mount("plain", "/tree");
    let mut bystander = fixture.server.mount("plain", "/tree");
    let path = fixture.tree("data.bin");

    // The first range conflicts with every request of the fleet, the second with
    // exactly one, so releasing the second shows whether a release grants a request
    // while the first range is still held.
    let held = holder.lookup(ROOT, "data.bin").expect("resolves");
    let held_handle = holder.open(held.node_id, OFlags::RDWR).expect("opens");
    holder
        .setlk(held_handle, lock(1, lock_type::WRITE, 0, 0), false)
        .expect("the range is free");
    holder
        .setlk(held_handle, lock(1, lock_type::WRITE, 100, 200), false)
        .expect("the range is free");

    // The bystander works before the storm, so the storm is measured and not a
    // first-time resolution.
    bystander.lookup(ROOT, "data.bin").expect("resolves");
    let retained = open_descriptors(&path);

    let witnessed = witness.lookup(ROOT, "data.bin").expect("resolves");
    let witness_handle = witness
        .open(witnessed.node_id, OFlags::RDWR)
        .expect("opens");
    let mut fleet = Vec::with_capacity(REQUESTS as usize);
    let mut handles = Vec::with_capacity(REQUESTS as usize);
    for _ in 0..REQUESTS {
        let mut storm = fixture.server.mount("plain", "/tree");
        let file = storm.lookup(ROOT, "data.bin").expect("resolves");
        handles.push(storm.open(file.node_id, OFlags::RDWR).expect("opens"));
        fleet.push(storm);
    }

    for (storm, handle) in fleet.iter_mut().zip(&handles) {
        storm.send(
            0,
            &voidport_proto::ops::file::SetlkRequest {
                handle: U64::new(*handle),
                lock: lock(100, lock_type::WRITE, 0, 0),
                flags: U32::new(1),
                reserved: U32::ZERO,
            },
            &[],
        );
    }
    let witness_request = witness.send(
        0,
        &voidport_proto::ops::file::SetlkRequest {
            handle: U64::new(witness_handle),
            lock: lock(1, lock_type::WRITE, 100, 200),
            flags: U32::new(1),
            reserved: U32::ZERO,
        },
        &[],
    );
    // A reply to a later request on its connection shows the server has read every
    // lock request.
    for storm in &mut fleet {
        storm.fence();
    }
    witness.fence();

    bystander
        .lookup(ROOT, "sub")
        .expect("the server still serves");

    holder
        .setlk(held_handle, lock(1, lock_type::UNLOCK, 100, 200), false)
        .expect("releases");
    let (answered, status) = witness.receive_status::<voidport_proto::ops::file::SetlkResponse>();
    assert_eq!(status, 0, "the second session took the lock");
    assert_eq!(
        answered, witness_request,
        "the reply belongs to that session's request"
    );
    // Every session has ended before the descriptors are counted.
    witness.disconnect(&fixture.server);
    for storm in fleet {
        storm.disconnect(&fixture.server);
    }
    assert_eq!(
        open_descriptors(&path),
        retained,
        "every session that ended returned its descriptors"
    );
}

/// The descriptors on `path` that can be synced: opened for reading as a
/// directory, which the `O_PATH` descriptor of a node is not.
fn syncable_descriptors(path: &std::path::Path) -> usize {
    support::descriptor_flags(path)
        .into_iter()
        .map(OFlags::from_bits_retain)
        .filter(|flags| flags.contains(OFlags::DIRECTORY) && !flags.contains(OFlags::PATH))
        .count()
}

#[test]
fn a_directory_fsync_keeps_no_descriptor_open() {
    use voidport_proto::ops::file::{FsyncRequest, FsyncResponse, fsync_flags};

    let fixture = Fixture::start("directory-fsync");
    let path = fixture.tree("sub");
    let mut client = fixture.server.mount("plain", "/tree");
    let sub = client.lookup(ROOT, "sub").expect("resolves");
    let handle = client.open(sub.node_id, OFlags::RDONLY).expect("opens");
    assert_eq!(
        syncable_descriptors(&path),
        0,
        "a listing holds no descriptor"
    );

    for flags in [0, fsync_flags::DATASYNC] {
        let request = client.send(
            sub.node_id,
            &FsyncRequest {
                handle: U64::new(handle),
                flags: U32::new(flags),
                reserved: U32::ZERO,
            },
            &[],
        );
        assert_eq!(client.receive_status::<FsyncResponse>(), (request, 0));
        assert_eq!(
            syncable_descriptors(&path),
            0,
            "the sync closed the directory it reopened"
        );
    }

    let mut deep = fixture.server.mount("deep", "/deep");
    let root = deep.open(ROOT, OFlags::RDONLY).expect("opens");
    assert_eq!(deep.fsync(root, false), Ok(()));
    assert_eq!(deep.fsync(root, true), Ok(()));
}

#[test]
fn two_sessions_see_each_others_writes_through_the_server() {
    let fixture = Fixture::start("coherence");
    let mut writer = fixture.server.mount("plain", "/tree");
    let mut reader = fixture.server.mount("plain", "/tree");

    let written = writer.lookup(ROOT, "data.bin").expect("resolves");
    let write_handle = writer.open(written.node_id, OFlags::RDWR).expect("opens");
    let read = reader.lookup(ROOT, "data.bin").expect("resolves");
    let read_handle = reader.open(read.node_id, OFlags::RDONLY).expect("opens");

    writer.write(write_handle, 0, b"AAAA").expect("writes");
    assert_eq!(
        reader.read(read_handle, 0, 4).expect("reads"),
        b"AAAA",
        "the server is the single point of truth"
    );

    // Identity is server-global even though node ids are per session (both mounts
    // call their root 1).
    assert_eq!(written.attr.ino.get(), read.attr.ino.get());
    assert_eq!(
        reader.getattr(ROOT).expect("stats").ino.get(),
        writer.getattr(ROOT).expect("stats").ino.get()
    );
}

#[test]
fn an_unknown_opcode_closes_the_connection() {
    let fixture = Fixture::start("unknown-opcode");
    let mut client = fixture.server.mount("plain", "/tree");

    // Without a length in the header, an opcode the reader does not know leaves
    // nothing to skip by.
    let mut frame = vec![0u8; FRAME_HEADER_LEN + 24];
    let header = voidport_proto::frame::FrameHeader::new(0x7FFF, 0, 4242);
    frame[..FRAME_HEADER_LEN].copy_from_slice(zerocopy::IntoBytes::as_bytes(&header));
    frame[FRAME_HEADER_LEN..].copy_from_slice(zerocopy::IntoBytes::as_bytes(&RequestHead::new(
        ROOT, 0, 0, 0,
    )));
    client.send_bytes(&frame);
    assert!(
        client.receive().is_none(),
        "an unknown opcode is a framing error, and the connection closes"
    );
}

#[test]
fn a_framing_error_closes_the_connection() {
    let fixture = Fixture::start("framing-error");

    let mut poisoned = fixture.server.mount("plain", "/tree");
    let mut frame = vec![0u8; FRAME_HEADER_LEN + 24];
    let header = voidport_proto::frame::FrameHeader::new(0x0004, 0x0002, 5);
    frame[..FRAME_HEADER_LEN].copy_from_slice(zerocopy::IntoBytes::as_bytes(&header));
    poisoned.send_bytes(&frame);
    assert!(
        poisoned.receive().is_none(),
        "a framing error closes the connection"
    );

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
            token_len: U32::ZERO,
        },
        namespace,
    );
    assert!(
        twice.receive().is_none(),
        "a second handshake poisons the stream, and the connection closes"
    );

    // The first request has to be in flight for the id to be a duplicate at all,
    // so another session blocks it.
    let mut holder = fixture.server.mount("plain", "/tree");
    let held = holder.lookup(ROOT, "data.bin").expect("resolves");
    let held_handle = holder.open(held.node_id, OFlags::RDWR).expect("opens");
    holder
        .setlk(held_handle, lock(1, lock_type::WRITE, 0, u64::MAX), false)
        .expect("the range is free");

    let mut duplicate = fixture.server.mount("plain", "/tree");
    let file = duplicate.lookup(ROOT, "data.bin").expect("resolves");
    let handle = duplicate.open(file.node_id, OFlags::RDWR).expect("opens");
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

    // Lets the blocked request finish, so no host lock outlives the test.
    holder
        .setlk(held_handle, lock(1, lock_type::UNLOCK, 0, u64::MAX), false)
        .expect("releases");

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

#[test]
fn user_xattrs_round_trip_and_the_default_write_denials_hold() {
    let fixture = Fixture::start("xattrs");
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");

    // A read reaches the host and comes back with its answer (`ENODATA` where the
    // filesystem stores the namespace, `EOPNOTSUPP` where it does not).
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
    assert_eq!(
        client
            .setxattr(file.node_id, "system.posix_acl_access", b"x")
            .expect_err("the guard"),
        status::PERM
    );

    if !supports_user_xattrs(fixture.directory.path()) {
        // tmpfs cannot store `user.*` attributes before Linux 6.6. The skip is
        // printed, so a passing run that asserted only the refusals above is not
        // mistaken for coverage.
        eprintln!(
            "skipping the user.* xattr round trip: {} does not support user extended attributes",
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
    let (size, value) = client
        .getxattr(file.node_id, "user.first", 0)
        .expect("probes");
    assert_eq!((size, value.len()), (3, 0));

    let (guest_size, mut names) = client.listxattr(file.node_id, 1024).expect("lists");
    names.sort();
    assert_eq!(names, ["user.first", "user.second"]);
    // The guest size counts a NUL per name, not the headers of this wire.
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

    assert_eq!(
        client
            .setxattr(file.node_id, "user.other", b"x")
            .expect_err("denied by user.*"),
        status::PERM
    );
    client
        .setxattr(file.node_id, "user.build.id", b"7")
        .expect("the longer literal prefix wins");
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

    let (_, value) = client
        .getxattr(file.node_id, "user.build.id", 16)
        .expect("readable");
    assert_eq!(value, b"7");

    // The attribute is on the host, which makes this a hiding test and not a
    // missing-attribute one.
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
    let expected: u32 = names.iter().map(|name| name.len() as u32 + 1).sum();
    assert_eq!(guest_size, expected);

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

    let before = fs::metadata(&host).expect("stat").mode();
    assert_eq!(
        client
            .setxattr(
                file.node_id,
                "system.posix_acl_access",
                // A valid minimal ACL granting the owner rwx rewrites the mode
                // when it is set.
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

    // The `security.*` allow lets the attempt reach the host, so the result
    // comes from the host. The server runs in this process, so the same call
    // made directly has identical credentials.
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

/// A minimal `system.posix_acl_access` value: version 2, then one entry each for
/// the owner, the owning group and others. The owner entry grants `rwx`, so a
/// successful write rewrites the mode.
fn acl_blob() -> Vec<u8> {
    let mut blob = vec![2u8, 0, 0, 0];
    for (tag, permissions) in [(0x0001u16, 0x0007u16), (0x0004, 0x0007), (0x0020, 0x0007)] {
        blob.extend_from_slice(&tag.to_le_bytes());
        blob.extend_from_slice(&permissions.to_le_bytes());
        blob.extend_from_slice(&u32::MAX.to_le_bytes());
    }
    blob
}

#[test]
fn mknod_creates_fifos_and_sockets_and_refuses_device_nodes() {
    let fixture = Fixture::start("mknod");
    let mut client = fixture.server.mount("plain", "/tree");

    for (name, mode, kind) in [
        ("pipe", 0o010_640u32, rustix::fs::FileType::Fifo),
        ("sock", 0o140_640, rustix::fs::FileType::Socket),
    ] {
        let entry = client.mknod(ROOT, name, mode).expect("creatable");
        assert_eq!(
            rustix::fs::FileType::from_raw_mode(entry.attr.mode.get()),
            kind
        );
        let host = fixture.tree(name);
        let metadata = fs::symlink_metadata(&host).expect("the host entry exists");
        assert_eq!(
            rustix::fs::FileType::from_raw_mode(metadata.mode()),
            kind,
            "{name}"
        );
        assert_eq!(metadata.mode() & 0o7777, 0o640, "{name}");
        assert_eq!(
            client.mknod(ROOT, name, mode).expect_err("exists"),
            -(rustix::io::Errno::EXIST.raw_os_error())
        );
    }

    for mode in [0o020_644u32, 0o060_644] {
        assert_eq!(
            client.mknod(ROOT, "device", mode).expect_err("device node"),
            status::PERM
        );
    }
    assert!(!fixture.tree("device").exists());

    let mut readonly = fixture.server.mount("plain", "/readonly");
    assert_eq!(
        readonly
            .mknod(ROOT, "pipe2", 0o010_644)
            .expect_err("read-only"),
        status::ROFS
    );

    // The kernel permits `user.*` on regular files and directories only. The
    // refusal is `EPERM` on an ordinary filesystem and `EOPNOTSUPP` in a sandbox
    // that refuses every `setxattr`, so the answer is asserted by making the same
    // call as the server, in this process, with identical credentials and syscall
    // filter.
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
    let handle = client.open(file.node_id, OFlags::RDWR).expect("opens");

    client
        .setlk(handle, lock(1, lock_type::WRITE, 0, 3), false)
        .expect("the range is free");
    assert_eq!(
        client
            .setlk(handle, lock(2, lock_type::WRITE, 2, 6), false)
            .expect_err("overlapping"),
        status::AGAIN
    );

    let conflict = client
        .getlk(handle, lock(2, lock_type::WRITE, 0, 9))
        .expect("testable");
    assert_eq!(conflict.lock_type.get(), lock_type::WRITE);
    assert_eq!((conflict.start.get(), conflict.end.get()), (0, 3));
    assert_eq!(conflict.pid.get() as i32, -1, "an OFD lock has no pid");

    client
        .setlk(handle, lock(2, lock_type::WRITE, 4, 6), false)
        .expect("disjoint");

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

    client.flush(handle, 2).expect("flushes");
    let free = client
        .getlk(handle, lock(3, lock_type::WRITE, 4, 6))
        .expect("testable");
    assert_eq!(free.lock_type.get(), lock_type::UNLOCK);
}

#[test]
fn one_owner_locks_one_file_through_every_handle_it_holds() {
    let fixture = Fixture::start("locks-one-owner");
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let first = client.open(file.node_id, OFlags::RDWR).expect("opens");
    let second = client
        .open(file.node_id, OFlags::RDWR)
        .expect("opens again");

    client
        .setlk(first, lock(1, lock_type::WRITE, 0, u64::MAX), false)
        .expect("the range is free");
    client
        .setlk(second, lock(1, lock_type::WRITE, 0, u64::MAX), false)
        .expect("the owner's own lock");
    for handle in [first, second] {
        let own = client
            .getlk(handle, lock(1, lock_type::WRITE, 0, 3))
            .expect("testable");
        assert_eq!(
            own.lock_type.get(),
            lock_type::UNLOCK,
            "an owner never conflicts with itself"
        );
        assert_eq!(
            client
                .setlk(handle, lock(2, lock_type::WRITE, 0, 3), false)
                .expect_err("another owner still conflicts"),
            status::AGAIN
        );
    }

    client.flush(second, 1).expect("flushes");
    client
        .setlk(first, lock(2, lock_type::WRITE, 0, 3), false)
        .expect("owner 1 let go of the whole file");
}

#[test]
fn an_owner_upgrades_its_read_lock_through_a_writable_handle() {
    let fixture = Fixture::start("locks-upgrade");
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let reader = client
        .open(file.node_id, OFlags::RDONLY)
        .expect("opens to read");
    let writer = client
        .open(file.node_id, OFlags::RDWR)
        .expect("opens to write");

    client
        .setlk(reader, lock(1, lock_type::READ, 0, u64::MAX), false)
        .expect("the range is free");
    assert_eq!(
        client
            .setlk(reader, lock(1, lock_type::WRITE, 0, u64::MAX), false)
            .expect_err("the handle is not writable"),
        status::BADF
    );
    client
        .setlk(writer, lock(1, lock_type::WRITE, 0, u64::MAX), false)
        .expect("the owner's own read lock converts");
    assert_eq!(
        client
            .setlk(reader, lock(2, lock_type::READ, 0, 3), false)
            .expect_err("owner 1 now holds the file exclusively"),
        status::AGAIN
    );
}

#[test]
fn a_read_only_handle_takes_no_write_lock() {
    let fixture = Fixture::start("lock-share-mode");
    let mut client = fixture.server.mount("plain", "/readonly");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client
        .open(file.node_id, OFlags::RDONLY)
        .expect("opens to read");

    client
        .setlk(handle, lock(1, lock_type::READ, 0, u64::MAX), false)
        .expect("a read lock through a read-only handle");

    // The kernel refuses a write lock on a description that cannot be written. The
    // server must not reopen the file of a read-only graft for writing to grant
    // one.
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

    let mut writer = fixture.server.mount("plain", "/tree");
    let same = writer.lookup(ROOT, "data.bin").expect("resolves");
    let writable = writer.open(same.node_id, OFlags::RDWR).expect("opens");
    writer
        .setlk(writable, lock(1, lock_type::WRITE, 0, u64::MAX), false)
        .expect_err("the read-only handle's read lock conflicts");
}

#[test]
fn a_lock_query_costs_no_host_descriptor() {
    let fixture = Fixture::start("lock-queries");
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, OFlags::RDWR).expect("opens");
    let path = fixture.tree("data.bin");
    let baseline = open_descriptors(&path);

    // Asking whether a lock could be taken must not make the server hold an open
    // file description per lock holder id asked about.
    for owner in 1..=256u64 {
        let free = client
            .getlk(handle, lock(owner, lock_type::WRITE, 0, 3))
            .expect("testable");
        assert_eq!(free.lock_type.get(), lock_type::UNLOCK);
    }
    assert_eq!(open_descriptors(&path), baseline, "a query opens nothing");

    for owner in 1..=256u64 {
        client
            .setlk(handle, lock(owner, lock_type::UNLOCK, 0, u64::MAX), false)
            .expect("nothing to release");
    }
    assert_eq!(open_descriptors(&path), baseline);

    client
        .setlk(handle, lock(1, lock_type::WRITE, 0, 3), false)
        .expect("the range is free");
    assert_eq!(
        open_descriptors(&path),
        baseline,
        "a lock in place is on the session's description"
    );
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
        baseline,
        "a refused lock keeps no description"
    );
}

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
