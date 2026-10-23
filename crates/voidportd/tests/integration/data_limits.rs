#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::fs;
use std::os::unix::net::{UnixListener, UnixStream};

use rustix::fs::OFlags;
use support::fixture::Fixture;
use support::wire::{ROOT, WireClient, status, whole_file_lock};
use support::{Dial as _, TempDir, daemon_config};
use voidport_control::{Reply, Request, Rule, ShareMode};
use voidport_proto::frame::Frame;
use voidport_proto::message::{ResponseBody, ResponseOutcome};
use voidport_proto::ops::file::{SetlkRequest, SetlkResponse, lock_type};
use voidport_proto::ops::node::{GetattrRequest, GetattrResponse};
use voidport_test_support::create_directory;
use voidportd::daemon::{Daemon, StartupError};
use voidportd::data::Endpoint;
use zerocopy::byteorder::little_endian::{U32, U64};

fn state(listeners: &str, target: &std::path::Path) -> String {
    format!(
        r#"
[server]
{listeners}

[[namespaces]]
name = "plain"

[[namespaces.rules]]
path = "/tree"
mode = "rw"
target = "{target}"
"#,
        target = target.display()
    )
}

fn start(directory: &TempDir, listeners: &str) -> Result<Daemon, StartupError> {
    let target = directory.directory("tree");
    let state_file = directory.write("state.toml", &state(listeners, &target));
    let config = daemon_config(&state_file);
    Daemon::start(&config)
}

#[test]
fn tcp_and_unix_serve_sessions() {
    let mut fixture = Fixture::start("transports");

    let mut over_tcp = WireClient::tcp(fixture.server.data_tcp()).expect("tcp accepts");
    over_tcp
        .hello("plain", "/tree")
        .expect("the mount resolves");
    assert!(over_tcp.lookup(ROOT, "data.bin").is_ok());

    let mut over_unix = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    over_unix
        .hello("plain", "/tree")
        .expect("the mount resolves");
    assert!(over_unix.lookup(ROOT, "data.bin").is_ok());

    use std::os::unix::fs::PermissionsExt;
    let path = fixture.server.data_unix().to_path_buf();
    let mode = fs::metadata(&path).expect("stattable").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    fixture.server.stop();
    assert!(!path.exists(), "shutdown unlinks the data socket");
    assert!(
        !fixture.join("control.sock").exists(),
        "and the control socket with it"
    );
}

#[test]
fn a_unix_data_socket_follows_the_bind_contract() {
    let directory = TempDir::new("data-socket");
    let socket = directory.join("data.sock");
    let listeners = format!(
        "[[server.listeners]]\ntransport = \"unix\"\npath = \"{}\"\n",
        socket.display()
    );

    drop(UnixListener::bind(&socket).expect("a stale socket binds"));
    assert!(socket.exists());
    {
        let daemon = start(&directory, &listeners).expect("a stale socket is reclaimed");
        assert!(
            UnixStream::connect(&socket).is_ok(),
            "and the new one answers"
        );

        let second = TempDir::new("data-socket-second");
        let refused = start(&second, &listeners).expect_err("the path is in use");
        assert!(matches!(refused, StartupError::Listener(_)), "{refused}");
        drop(daemon);
    }
    assert!(!socket.exists(), "a clean shutdown unlinks the data socket");

    fs::write(&socket, b"not a socket").expect("writable");
    let refused = start(&directory, &listeners).expect_err("not ours to replace");
    assert!(matches!(refused, StartupError::Listener(_)), "{refused}");
    assert!(socket.exists(), "the file is left alone");
}

#[test]
fn a_vsock_listener_binds_from_the_state_file() {
    if !voidport_test_support::vsock::preflight() {
        return;
    }
    let directory = TempDir::new("vsock");
    let daemon = start(
        &directory,
        "[[server.listeners]]\ntransport = \"vsock\"\nport = 0\n",
    )
    .expect("the vsock listener binds");
    let listeners = daemon.service().listeners();
    let port = voidport_test_support::bound_vsock_port(&listeners);
    assert_eq!(
        listeners,
        vec![
            Endpoint::Vsock {
                cid: vsock::VMADDR_CID_ANY,
                port
            }
            .info()
        ],
        "an unnamed cid is the wildcard, which on a host means its guests",
    );
}

#[test]
fn a_vsock_port_outside_the_url_grammar_refuses_startup() {
    let directory = TempDir::new("vsock-port");
    let error = start(
        &directory,
        "[[server.listeners]]\ntransport = \"vsock\"\ncid = 3\nport = 70000\n",
    )
    .expect_err("70000 is not a port a mount URL can carry");
    assert!(matches!(error, StartupError::Load(_)), "{error}");
    let message = error.to_string();
    assert!(message.contains("cid 3 port 70000"), "{message}");
    assert!(message.contains("1..=65535"), "{message}");
}

#[test]
fn one_failing_listener_fails_startup() {
    let directory = TempDir::new("partial-listeners");
    let blocked = directory.write("occupied", "not a socket");
    let listeners = format!(
        "[[server.listeners]]\ntransport = \"tcp\"\naddr = \"127.0.0.1:0\"\n\n\
         [[server.listeners]]\ntransport = \"unix\"\npath = \"{}\"\n",
        blocked.display()
    );
    let error = start(&directory, &listeners).expect_err("the second listener cannot bind");
    assert!(matches!(error, StartupError::Listener(_)), "{error}");
    assert!(
        !directory.join("control.sock").exists(),
        "a server that does not start leaves nothing bound"
    );
}

const RETIRED_NODE_DEFAULT: usize = 65_536;

const RETIRED_HANDLE_DEFAULT: usize = 16_384;

const PACKAGES: usize = 100;
const FILES: usize = 1_000;

fn build_synthetic_tree(root: &std::path::Path) -> usize {
    create_directory(root);
    for package in 0..PACKAGES {
        let directory = root.join(format!("package-{package:04}"));
        create_directory(&directory);
        for file in 0..FILES {
            fs::write(directory.join(format!("source-{file:04}.txt")), b"x").expect("writable");
        }
    }
    PACKAGES * (FILES + 1)
}

#[test]
fn a_walk_past_the_retired_defaults_succeeds() {
    let fixture = Fixture::start("big-walk");
    let entries = build_synthetic_tree(&fixture.tree("big"));
    assert!(
        entries > RETIRED_NODE_DEFAULT,
        "{entries} entries is too few"
    );

    let mut control = fixture.server.connect();
    let mut client = fixture.server.mount("plain", "/tree");
    let big = client.lookup(ROOT, "big").expect("the tree resolves");

    let mut walked = 0;
    let mut packages = Vec::new();
    for entry in client.list(big.node_id).expect("the top level lists") {
        walked += 1;
        packages.push(entry.entry.node_id);
    }
    assert_eq!(packages.len(), PACKAGES);
    let mut files = Vec::new();
    for package in packages {
        let listed = client
            .list(package)
            .unwrap_or_else(|status| panic!("a package listing failed with {status}"));
        assert_eq!(listed.len(), FILES);
        walked += listed.len();
        files.extend(listed.into_iter().map(|entry| entry.entry.node_id));
    }
    assert_eq!(walked, entries);

    let held = sessions(&mut control)[0].nodes;
    assert!(
        held > RETIRED_NODE_DEFAULT,
        "the session holds {held} nodes, which is not past the default-cap count"
    );

    let wanted = RETIRED_HANDLE_DEFAULT + 1;
    assert!(files.len() > wanted, "{} files to open", files.len());
    for (index, node) in files.iter().take(wanted).enumerate() {
        client
            .open(*node, OFlags::RDONLY)
            .unwrap_or_else(|status| panic!("open {index} failed with {status}"));
    }
    let session = &sessions(&mut control)[0];
    assert!(
        session.handles > RETIRED_HANDLE_DEFAULT,
        "the session holds {} handles, which is not past the default-cap count",
        session.handles
    );
    assert!(session.nodes >= held, "the walk's nodes are still held");
}

/// The verdict rests on the answer, the idle fence and the node table, not on
/// time or on how many threads the host gave.
#[test]
fn a_burst_of_forgets_is_served_and_leaves_no_node_behind() {
    let fixture = Fixture::start("forget-burst");
    build_synthetic_tree(&fixture.tree("big"));
    let mut control = fixture.server.connect();
    let mut client = fixture.server.mount("plain", "/tree");
    let big = client.lookup(ROOT, "big").expect("the tree resolves");
    let package = client
        .list(big.node_id)
        .expect("the top level lists")
        .into_iter()
        .next()
        .expect("a package")
        .entry
        .node_id;

    let held_before = sessions(&mut control)[0].nodes;
    let entries = client.list(package).expect("the package lists");
    assert_eq!(entries.len(), FILES);
    let mut names: Vec<Vec<u8>> = entries.iter().map(|entry| entry.name.clone()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), FILES, "every entry appears exactly once");
    let held = sessions(&mut control)[0].nodes;
    assert_eq!(held, held_before + FILES, "one node per entry");

    for entry in &entries {
        client.send(
            entry.entry.node_id,
            &voidport_proto::ops::node::ForgetRequest {
                nlookup: U64::new(1),
            },
            &[],
        );
    }
    // The server applies a forget before it reads the next request, so the answer
    // to the request behind the burst means every forget was applied.
    assert!(
        client.getattr(ROOT).is_ok(),
        "the request behind the burst is answered"
    );
    assert_eq!(
        sessions(&mut control)[0].nodes,
        held_before,
        "the session holds no node for the forgotten entries"
    );
}

const PARKED_PAST_THE_OLD_BOUND: u64 = 65;

#[test]
fn a_request_behind_more_parked_requests_than_the_old_bound_is_answered() {
    let fixture = Fixture::start("parked-past-the-old-bound");

    let mut holder = fixture.server.mount("plain", "/tree");
    let held = holder.lookup(ROOT, "data.bin").expect("resolves");
    let held_handle = holder.open(held.node_id, OFlags::RDWR).expect("opens");
    holder
        .setlk(held_handle, whole_file_lock(1, lock_type::WRITE), false)
        .expect("the range is free");

    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, OFlags::RDWR).expect("opens");

    let blocked: Vec<u64> = (0..PARKED_PAST_THE_OLD_BOUND)
        .map(|waiter| {
            client.send(
                0,
                &SetlkRequest {
                    handle: U64::new(handle),
                    lock: whole_file_lock(2 + waiter, lock_type::READ),
                    flags: U32::new(1),
                    reserved: U32::ZERO,
                },
                &[],
            )
        })
        .collect();
    let behind = client.send(
        ROOT,
        &GetattrRequest {
            handle: U64::ZERO,
            flags: U32::ZERO,
            reserved: U32::ZERO,
        },
        &[],
    );

    let bytes = client.receive().expect("the server answers");
    let frame =
        Frame::parse(&bytes, &voidport_proto::limits::LIMITS).expect("a well-framed response");
    assert_eq!(
        frame.request_id(),
        behind,
        "the request behind the parked ones is answered first"
    );
    assert_eq!(refusal(behind, frame.response::<GetattrResponse>()), None);

    holder
        .setlk(held_handle, whole_file_lock(1, lock_type::UNLOCK), false)
        .expect("releases");
    let mut answered = Vec::new();
    for _ in 0..PARKED_PAST_THE_OLD_BOUND {
        let bytes = client.receive().expect("the server answers");
        let frame =
            Frame::parse(&bytes, &voidport_proto::limits::LIMITS).expect("a well-framed response");
        let id = frame.request_id();
        assert_eq!(
            refusal(id, frame.response::<SetlkResponse>()),
            None,
            "request {id} is served, not refused"
        );
        answered.push(id);
    }
    answered.sort_unstable();
    let mut expected = blocked;
    expected.sort_unstable();
    assert_eq!(
        answered, expected,
        "every parked request is answered exactly once"
    );
}

/// A response that does not decode is a different failure from a refusal, and
/// fails here under its own name.
fn refusal<R: ResponseBody, E: std::fmt::Debug>(
    id: u64,
    outcome: Result<ResponseOutcome<'_, R>, E>,
) -> Option<i32> {
    outcome
        .unwrap_or_else(|error| panic!("the response to request {id} does not decode: {error:?}"))
        .error()
}

#[test]
fn the_control_plane_lists_live_sessions_with_their_counts() {
    let fixture = Fixture::start("session-list");
    let mut control = fixture.server.connect();

    assert_eq!(sessions(&mut control).len(), 0, "nothing is mounted yet");

    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let _handle = client.open(file.node_id, OFlags::RDWR).expect("opens");

    let listed = sessions(&mut control);
    assert_eq!(listed.len(), 1);
    let session = &listed[0];
    assert_eq!(session.namespace.as_str(), "plain");
    assert_eq!(session.subpath, "/tree");
    assert_eq!(session.transport, "tcp");
    assert!(!session.peer.is_empty());
    assert_eq!(session.nodes, 2, "the mount root and the file");
    assert_eq!(session.handles, 1);

    let mut other = fixture.server.mount("plain", "/tree");
    other.lookup(ROOT, "sub").expect("resolves");
    let listed = sessions(&mut control);
    assert_eq!(listed.len(), 2);
    assert_ne!(listed[0].id, listed[1].id);

    other.disconnect(&fixture.server);
    assert_eq!(sessions(&mut control).len(), 1);
}

#[test]
fn forget_ids_may_be_reused_freely_and_at_volume() {
    let fixture = Fixture::start("forget-volume");
    let mut client = fixture.server.mount("plain", "/tree");

    // `forget` gets no answer, so its id retires the moment its frame is accepted
    // and a client may use the same one forever.
    for _ in 0..500 {
        let entry = client.lookup(ROOT, "data.bin").expect("resolves");
        client.send_with_id(
            u64::MAX,
            entry.node_id,
            &voidport_proto::ops::node::ForgetRequest {
                nlookup: U64::new(1),
            },
            &[],
        );
    }
    assert!(client.getattr(ROOT).is_ok());
    let mut control = fixture.server.connect();
    let listed = sessions(&mut control);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].nodes, 1, "every lookup was forgotten");
}

#[test]
fn a_rule_added_or_removed_reaches_a_mounted_session_at_its_next_lookup() {
    let fixture = Fixture::start("live-rules");
    let mut client = fixture.server.mount("project", "/project");
    let mut control = fixture.server.connect();
    let project = voidport_control::NamespaceName::new("project").expect("valid");

    assert_eq!(
        client.lookup(ROOT, "secret").expect_err("hidden"),
        status::NOENT
    );

    control.expect_ok(&Request::RuleAdd {
        namespace: project.clone(),
        rule: Rule::new("/project/secret", ShareMode::Ro),
    });
    let secret = client.lookup(ROOT, "secret").expect("the rule is live");
    assert!(secret.is_directory());
    assert!(
        client
            .list(ROOT)
            .expect("lists")
            .iter()
            .any(|entry| entry.name() == "secret"),
        "and a fresh listing shows it too"
    );

    control.expect_ok(&Request::RuleRemove {
        namespace: project.clone(),
        path: "/project/secret".to_owned(),
        r#match: None,
    });
    assert_eq!(
        client.lookup(ROOT, "secret").expect_err("hidden again"),
        status::NOENT
    );
    assert!(
        !client
            .list(ROOT)
            .expect("lists")
            .iter()
            .any(|entry| entry.name() == "secret")
    );
}

#[test]
fn a_downgrade_to_read_only_binds_at_the_next_lookup_and_spares_open_handles() {
    let fixture = Fixture::start("live-downgrade");
    let mut client = fixture.server.mount("plain", "/tree");
    let mut control = fixture.server.connect();
    let plain = voidport_control::NamespaceName::new("plain").expect("valid");

    let before = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(before.node_id, OFlags::RDWR).expect("opens");
    assert_eq!(client.write(handle, 0, b"A").expect("writes"), 1);

    control.expect_ok(&Request::RuleAdd {
        namespace: plain.clone(),
        rule: Rule::new("/tree/data.bin", ShareMode::Ro),
    });

    let after = client.lookup(ROOT, "data.bin").expect("still resolves");
    assert_ne!(after.node_id, before.node_id);
    assert_eq!(
        client
            .open(after.node_id, OFlags::RDWR)
            .expect_err("write open"),
        status::ROFS
    );
    assert_eq!(
        client.unlink(ROOT, "data.bin").expect_err("unlink"),
        status::ROFS
    );

    // The mode of a node binds at the lookup that admitted it.
    assert_eq!(
        client
            .write(handle, 1, b"B")
            .expect("the open handle still writes"),
        1
    );
    client.release(handle).expect("releases");
    assert!(client.open(before.node_id, OFlags::RDWR).is_ok());
}

#[test]
fn a_directory_graft_downgraded_to_read_only_binds_at_the_next_child_operation() {
    let fixture = Fixture::start("live-directory-downgrade");
    let mut client = fixture.server.mount("plain", "/");
    let mut control = fixture.server.connect();
    let plain = voidport_control::NamespaceName::new("plain").expect("valid");

    let tree = client.lookup(ROOT, "tree").expect("resolves");
    assert!(tree.is_directory());
    client.mkdir(tree.node_id, "before", 0o755).expect("rw");

    control.expect_ok(&Request::RuleRemove {
        namespace: plain.clone(),
        path: "/tree".to_owned(),
        r#match: None,
    });
    control.expect_ok(&Request::RuleAdd {
        namespace: plain.clone(),
        rule: Rule::new("/tree", ShareMode::Ro).with_target(
            fixture
                .join("tree")
                .to_str()
                .expect("a utf-8 fixture path")
                .to_owned(),
        ),
    });

    // Children resolve under the current mode of the graft, so everything through
    // that node is read-only now.
    assert_eq!(
        client
            .mkdir(tree.node_id, "after", 0o755)
            .expect_err("the graft is read-only now"),
        status::ROFS
    );
    assert_eq!(
        client
            .unlink(tree.node_id, "data.bin")
            .expect_err("the graft is read-only now"),
        status::ROFS
    );
    let child = client
        .lookup(tree.node_id, "data.bin")
        .expect("still resolves");
    assert_eq!(
        child.permissions() & 0o222,
        0,
        "a read-only graft strips the write bits it presents"
    );
    assert_eq!(
        client
            .open(child.node_id, OFlags::RDWR)
            .expect_err("write open"),
        status::ROFS
    );
    assert!(!fixture.tree("after").exists());
}

#[test]
fn removing_a_directory_graft_reaches_a_mounted_session_at_its_next_child_lookup() {
    let fixture = Fixture::start("live-directory-removal");
    let mut client = fixture.server.mount("plain", "/");
    let mut control = fixture.server.connect();
    let plain = voidport_control::NamespaceName::new("plain").expect("valid");

    let tree = client.lookup(ROOT, "tree").expect("resolves");
    let file = client.lookup(tree.node_id, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, OFlags::RDWR).expect("opens");

    control.expect_ok(&Request::RuleRemove {
        namespace: plain.clone(),
        path: "/tree".to_owned(),
        r#match: None,
    });

    assert_eq!(
        client.lookup(ROOT, "tree").expect_err("the graft is gone"),
        status::NOENT
    );
    assert_eq!(
        client
            .lookup(tree.node_id, "data.bin")
            .expect_err("nothing resolves under a directory the namespace dropped"),
        status::NOENT
    );
    assert_eq!(
        client
            .mkdir(tree.node_id, "after", 0o755)
            .expect_err("nor may anything be created there"),
        status::NOENT
    );
    assert_eq!(
        client
            .open(tree.node_id, OFlags::RDONLY)
            .expect_err("nor listed"),
        status::NOENT
    );

    assert_eq!(client.write(handle, 0, b"Z").expect("still writes"), 1);
}

#[test]
fn re_targeting_a_directory_graft_reaches_a_mounted_session_at_its_next_child_lookup() {
    let fixture = Fixture::start("live-directory-retarget");
    let mut client = fixture.server.mount("plain", "/");
    let mut control = fixture.server.connect();
    let plain = voidport_control::NamespaceName::new("plain").expect("valid");

    let tree = client.lookup(ROOT, "tree").expect("resolves");
    assert!(client.lookup(tree.node_id, "data.bin").is_ok());

    let elsewhere = fixture.join("elsewhere");
    create_directory(&elsewhere);
    fs::write(elsewhere.join("moved.bin"), b"moved").expect("writable");

    control.expect_ok(&Request::RuleRemove {
        namespace: plain.clone(),
        path: "/tree".to_owned(),
        r#match: None,
    });
    control.expect_ok(&Request::RuleAdd {
        namespace: plain.clone(),
        rule: Rule::new("/tree", ShareMode::Rw)
            .with_target(elsewhere.to_str().expect("a utf-8 fixture path").to_owned()),
    });

    // The cached descriptor of the directory node names the old host directory,
    // but what it resolves is decided by where the namespace points now.
    let moved = client
        .lookup(tree.node_id, "moved.bin")
        .expect("the new target's child resolves");
    let handle = client.open(moved.node_id, OFlags::RDONLY).expect("opens");
    assert_eq!(client.read(handle, 0, 16).expect("reads"), b"moved");
    assert_eq!(
        client
            .lookup(tree.node_id, "data.bin")
            .expect_err("the old target's child is not there"),
        status::NOENT
    );

    let names: Vec<String> = client
        .list(tree.node_id)
        .expect("lists")
        .iter()
        .map(support::wire::DirEntry::name)
        .collect();
    assert_eq!(names, ["moved.bin"]);

    client
        .create(tree.node_id, "fresh", OFlags::RDWR, 0o644)
        .expect("creates");
    assert!(elsewhere.join("fresh").exists());
    assert!(!fixture.tree("fresh").exists());
}

#[test]
fn a_deleted_namespace_keeps_serving_the_sessions_that_mounted_it() {
    let fixture = Fixture::start("namespace-deletion");
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, OFlags::RDWR).expect("opens");

    let mut control = fixture.server.connect();
    control.expect_ok(&Request::NamespaceDelete {
        name: voidport_control::NamespaceName::new("plain").expect("valid"),
    });

    // The registry has nothing left under the name, so the session falls back to
    // the tombstone it captured at handshake time.
    assert!(client.read(handle, 0, 4).is_ok());
    assert!(client.lookup(ROOT, "sub").is_ok());
    assert_eq!(sessions(&mut control).len(), 1, "and it is still listed");

    let mut fresh = fixture.server.dial();
    assert_eq!(
        fresh
            .hello("plain", "/tree")
            .expect_err("no such namespace"),
        status::NOENT
    );
}

fn sessions(control: &mut support::ControlClient) -> Vec<voidport_control::SessionSummary> {
    match control.expect_ok(&Request::SessionList {}) {
        Reply::SessionList { sessions } => sessions,
        other => panic!("expected a session list, got {other:?}"),
    }
}
