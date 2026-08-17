//! Listeners, resource caps, and session inspection.
//!
//! The data plane's acceptance criteria 10–12: what the server binds, what it
//! refuses to bind, what it does when a guest asks for more than it may have,
//! and what the operator can see of the guests that are mounted.

mod support;

use std::fs;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

use support::fixture::Fixture;
use support::wire::{ROOT, WireClient, status, whole_file_lock};
use support::{Dial as _, TempDir, daemon_config};
use voidport_control::{Reply, Request, Rule, ShareMode};
use voidport_proto::ops::file::{SetlkRequest, lock_type};
use voidport_proto::ops::node::{GetattrRequest, GetattrResponse};
use voidportd::daemon::{Daemon, StartupError};
use voidportd::testing::{create_directory, pinned_environment};
use zerocopy::byteorder::little_endian::{U32, U64};

/// `O_RDONLY` and `O_RDWR`, as the guest sends them.
const O_RDONLY: u32 = 0;
const O_RDWR: u32 = 2;

/// How long a test waits before calling silence backpressure.
const PATIENCE: Duration = Duration::from_millis(400);

/// A state file with the given listeners and one namespace grafting `target`.
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

/// Starts a daemon on a state file, without serving it.
fn start(directory: &TempDir, listeners: &str) -> Result<Daemon, StartupError> {
    let target = directory.directory("tree");
    let state_file = directory.write("state.toml", &state(listeners, &target));
    let config = daemon_config(&state_file, pinned_environment(directory.path()));
    Daemon::start(&config)
}

// ---------------------------------------------------------------------------
// Criterion 10 — listeners
// ---------------------------------------------------------------------------

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

    // The unix socket is owner-only, like the control socket.
    use std::os::unix::fs::PermissionsExt;
    let path = fixture.server.data_unix().to_path_buf();
    let mode = fs::metadata(&path).expect("stattable").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    // And a clean shutdown of both planes unlinks it.
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

    // A stale socket — a path left behind by a dead server — is reclaimed.
    drop(UnixListener::bind(&socket).expect("a stale socket binds"));
    assert!(socket.exists());
    {
        let daemon = start(&directory, &listeners).expect("a stale socket is reclaimed");
        assert!(
            UnixStream::connect(&socket).is_ok(),
            "and the new one answers"
        );

        // A live socket belongs to somebody: a second daemon must not steal it.
        let second = TempDir::new("data-socket-second");
        let refused = start(&second, &listeners).expect_err("the path is in use");
        assert!(matches!(refused, StartupError::Listener(_)), "{refused}");
        drop(daemon);
    }
    // Dropping the daemon unlinks the socket it created.
    assert!(!socket.exists(), "a clean shutdown unlinks the data socket");

    // Anything that is not a socket is never deleted by the server.
    fs::write(&socket, b"not a socket").expect("writable");
    let refused = start(&directory, &listeners).expect_err("not ours to replace");
    assert!(matches!(refused, StartupError::Listener(_)), "{refused}");
    assert!(socket.exists(), "the file is left alone");
}

/// A vsock listener binds from the state file the operator wrote, on the
/// wildcard cid when none is named.
#[test]
fn a_vsock_listener_binds_from_the_state_file() {
    if !voidportd::testing::vsock::preflight() {
        return;
    }
    let directory = TempDir::new("vsock");
    let port = voidportd::testing::vsock::free_port().expect("a free vsock port");
    let daemon = start(
        &directory,
        &format!("[[server.listeners]]\ntransport = \"vsock\"\nport = {port}\n"),
    )
    .expect("the vsock listener binds");
    let listeners = daemon.data_listeners().endpoints();
    assert_eq!(listeners.len(), 1);
    assert_eq!(
        listeners[0].vsock_address(),
        Some((vsock::VMADDR_CID_ANY, port)),
        "an unnamed cid is the wildcard, which on a host means its guests",
    );
    assert_eq!(listeners[0].transport().as_str(), "vsock");
}

/// A vsock port no mount URL could name is refused at load, with the listener
/// in the message — bound-and-unreachable is the failure this prevents.
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

// ---------------------------------------------------------------------------
// Criterion 11 — resource caps
//
// The caps are opt-in: the first test here proves that a server nobody
// configured refuses nothing at a scale the retired defaults refused, and every
// test after it configures a cap and proves it is still enforced exactly as it
// says.
// ---------------------------------------------------------------------------

/// The retired node default, and the scale at which it stopped a real walk.
const RETIRED_NODE_DEFAULT: usize = 65_536;

/// The retired handle default, which a parallel module finder reached in the
/// field while the host filesystem carried the same work without complaint.
const RETIRED_HANDLE_DEFAULT: usize = 16_384;

/// The synthetic tree's shape: directories, and files in each.
///
/// The shape is the capacity work's — a build-system source tree of package
/// directories with small files in them — at a hundredth of its scale, which is
/// still well past both retired defaults and cheap enough for the gate.
const PACKAGES: usize = 100;
/// Files per package directory: `PACKAGES * FILES` entries in all.
const FILES: usize = 1_000;

/// Builds the synthetic tree and returns how many entries it holds.
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

/// A walk of every entry the guest can reach, holding every node it is given —
/// which is what a build system's kernel does until it is short of memory.
#[test]
fn a_walk_past_the_retired_defaults_succeeds_with_no_caps_configured() {
    let fixture = Fixture::start("unbounded-caps");
    let entries = build_synthetic_tree(&fixture.tree("big"));
    assert!(
        entries > RETIRED_NODE_DEFAULT,
        "{entries} entries is too few"
    );

    let mut control = fixture.server.connect();
    let mut client = fixture.server.mount("plain", "/tree");
    let big = client.lookup(ROOT, "big").expect("the tree resolves");

    // Every package, every file: one node per entry, and every node held.
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

    // The retired node default would have refused this walk a fifth of the way
    // in with ENFILE. Nothing configured a cap, so nothing refuses it.
    let held = sessions(&mut control)[0].nodes;
    assert!(
        held > RETIRED_NODE_DEFAULT,
        "the session holds {held} nodes, which is not past the retired default"
    );

    // And the handles the field's parallel module finder held: past the retired
    // handle default, open at the same time, on one session.
    let wanted = RETIRED_HANDLE_DEFAULT + 1;
    assert!(files.len() > wanted, "{} files to open", files.len());
    for (index, node) in files.iter().take(wanted).enumerate() {
        client
            .open(*node, O_RDONLY)
            .unwrap_or_else(|status| panic!("open {index} failed with {status}"));
    }
    let session = &sessions(&mut control)[0];
    assert!(
        session.handles > RETIRED_HANDLE_DEFAULT,
        "the session holds {} handles, which is not past the retired default",
        session.handles
    );
    assert!(session.nodes >= held, "the walk's nodes are still held");
}

#[test]
fn the_in_flight_cap_pauses_reads_instead_of_failing_requests() {
    let fixture = Fixture::start_with("inflight", "[server.limits]\nmax_inflight = 1\n");

    // One session holds a lock the other will block on.
    let mut holder = fixture.server.mount("plain", "/tree");
    let held = holder.lookup(ROOT, "data.bin").expect("resolves");
    let held_handle = holder.open(held.node_id, O_RDWR).expect("opens");
    holder
        .setlk(held_handle, whole_file_lock(1, lock_type::WRITE), false)
        .expect("the range is free");

    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, O_RDWR).expect("opens");

    // The one permitted request blocks; the next one is not even read.
    let blocked = client.send(
        0,
        &SetlkRequest {
            handle: U64::new(handle),
            lock: whole_file_lock(2, lock_type::WRITE),
            flags: U32::new(1),
            reserved: U32::ZERO,
        },
        &[],
    );
    let queued = client.send(
        ROOT,
        &GetattrRequest {
            handle: U64::ZERO,
            flags: U32::ZERO,
            reserved: U32::ZERO,
        },
        &[],
    );
    assert!(
        client.try_receive(PATIENCE).is_none(),
        "at the cap the server stops reading — it does not answer with an error"
    );

    // Releasing the lock lets both through, in the order they complete.
    holder
        .setlk(held_handle, whole_file_lock(1, lock_type::UNLOCK), false)
        .expect("releases");
    let (first, status) = client.receive_status::<voidport_proto::ops::file::SetlkResponse>();
    assert_eq!((first, status), (blocked, 0));
    let (second, status) = client.receive_status::<GetattrResponse>();
    assert_eq!(
        (second, status),
        (queued, 0),
        "the paused request is served, not refused"
    );
}

#[test]
fn the_node_cap_refuses_the_lookup_that_would_exceed_it() {
    // Room for the mount root and exactly one more node.
    let fixture = Fixture::start_with("node-cap", "[server.limits]\nmax_nodes = 2\n");
    let mut client = fixture.server.mount("plain", "/tree");

    let first = client.lookup(ROOT, "data.bin").expect("the first fits");
    assert_eq!(
        client.lookup(ROOT, "sub").expect_err("the table is full"),
        status::NFILE
    );
    // The refused lookup took nothing: forgetting the first makes room again. A
    // forget is answered by nothing and served on its own task, so nothing
    // orders a later request behind it — the retry is polled to a deadline.
    client.forget(first.node_id, 1);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while let Err(status) = client.lookup(ROOT, "sub") {
        assert_eq!(status, status::NFILE, "the cap is the only refusal here");
        assert!(
            std::time::Instant::now() < deadline,
            "a forgotten node must give its slot back"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn the_handle_cap_refuses_the_open_that_would_exceed_it() {
    let fixture = Fixture::start_with("handle-cap", "[server.limits]\nmax_handles = 1\n");
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");

    let handle = client.open(file.node_id, O_RDWR).expect("the first fits");
    assert_eq!(
        client
            .open(file.node_id, O_RDWR)
            .expect_err("the table is full"),
        status::MFILE
    );
    // Releasing frees the slot, and the descriptor with it.
    client.release(handle).expect("releases");
    assert!(
        client.open(file.node_id, O_RDWR).is_ok(),
        "the cap released"
    );
}

#[test]
fn a_create_refused_by_the_handle_cap_keeps_no_node() {
    let fixture = Fixture::start_with("create-cap", "[server.limits]\nmax_handles = 1\n");
    let mut control = fixture.server.connect();
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, O_RDWR).expect("the only handle");

    let before = sessions(&mut control)[0].nodes;
    assert_eq!(
        client
            .create(ROOT, "created", O_RDWR, 0o644)
            .expect_err("the handle table is full"),
        status::MFILE
    );
    // No entry reply left the server, so the client never learned a node id it
    // could forget. A create that fails at the cap must therefore keep no node
    // — otherwise the cap would leak one per attempt.
    assert_eq!(
        sessions(&mut control)[0].nodes,
        before,
        "a refused create keeps no node"
    );

    // Freeing a handle makes the retry work, on the entry the first attempt
    // created.
    client.release(handle).expect("releases");
    let (entry, _handle) = client
        .create(ROOT, "created", O_RDWR, 0o644)
        .expect("the retry fits");
    assert!(entry.attr.ino.get() > 0);
}

#[test]
fn the_listing_cap_refuses_to_materialize_a_larger_directory() {
    let fixture = Fixture::start_with("listing-cap", "[server.limits]\nmax_listing_entries = 1\n");
    let mut client = fixture.server.mount("plain", "/tree");

    // `/tree` holds more than one entry, so its listing does not fit.
    assert_eq!(
        client.open(ROOT, 0).expect_err("the listing is too large"),
        status::OVERFLOW
    );
    // A directory that does fit still opens, so nothing was left broken.
    let sub = client.lookup(ROOT, "sub").expect("resolves");
    let handle = client.open(sub.node_id, 0).expect("one entry fits");
    let entries = client
        .readdirplus(sub.node_id, handle, 0, 64 * 1024)
        .expect("lists");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name(), "inner");
}

#[test]
fn a_cap_the_server_would_have_to_raise_refuses_startup() {
    let directory = TempDir::new("zero-cap");
    let target = directory.directory("tree");
    let state_file = directory.write(
        "state.toml",
        &format!(
            "{}\n[server.limits]\nmax_inflight = 0\n",
            state("", &target)
        ),
    );
    let config = daemon_config(&state_file, pinned_environment(directory.path()));

    // A cap of zero cannot be served, and the server must not quietly serve a
    // different number than the operator wrote.
    let error = Daemon::start(&config).expect_err("zero is not a cap");
    assert!(matches!(error, StartupError::Load(_)), "{error}");
    assert!(error.to_string().contains("max_inflight"), "{error}");

    // The same file with a real cap starts.
    let state_file = directory.write(
        "state.toml",
        &format!(
            "{}\n[server.limits]\nmax_inflight = 1\n",
            state("", &target)
        ),
    );
    let config = daemon_config(&state_file, pinned_environment(directory.path()));
    assert!(Daemon::start(&config).is_ok());
}

#[test]
fn readdirplus_surfaces_a_node_cap_failure_instead_of_truncating_the_listing() {
    // Room for the mount root and exactly one entry: `/tree` has two, so the
    // second one readdirplus admits hits the node cap.
    let fixture = Fixture::start_with("readdir-node-cap", "[server.limits]\nmax_nodes = 2\n");
    let mut control = fixture.server.connect();
    let mut client = fixture.server.mount("plain", "/tree");

    let handle = client
        .open(ROOT, 0)
        .expect("the listing itself costs no node");
    assert_eq!(
        client
            .readdirplus(ROOT, handle, 0, 64 * 1024)
            .expect_err("the node table fills mid-listing"),
        status::NFILE,
        "a short listing with no error would look like a directory that lost a file"
    );

    // No entry reply left the server, so the client could never balance the
    // lookups the attempt counted: they are given back with the failure.
    assert_eq!(
        sessions(&mut control)[0].nodes,
        1,
        "a failed listing keeps no node"
    );

    // And the cap is the only thing in the way: one entry at a time still
    // resolves.
    assert!(client.lookup(ROOT, "data.bin").is_ok());
}

#[test]
fn the_session_cap_answers_and_closes_the_excess_connection() {
    let fixture = Fixture::start_with("session-cap", "[server.limits]\nmax_sessions = 1\n");
    let mut first = fixture.server.dial();
    first.hello("plain", "/tree").expect("the first mounts");

    let mut excess = fixture.server.dial();
    assert_eq!(
        excess
            .hello("plain", "/tree")
            .expect_err("the server is full"),
        status::MFILE,
        "an excess connection is answered before it is closed"
    );
    assert!(
        excess.receive().is_none(),
        "and then the connection is closed"
    );

    // The first session is untouched, and a slot comes back when it goes.
    assert!(first.lookup(ROOT, "data.bin").is_ok());
    drop(first);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut retry = fixture.server.dial();
        if retry.hello("plain", "/tree").is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "a disconnected session must give its slot back"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------
// Criterion 12 — session inspection
// ---------------------------------------------------------------------------

#[test]
fn the_control_plane_lists_live_sessions_with_their_counts() {
    let fixture = Fixture::start("session-list");
    let mut control = fixture.server.connect();

    assert_eq!(sessions(&mut control).len(), 0, "nothing is mounted yet");

    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let _handle = client.open(file.node_id, O_RDWR).expect("opens");

    let listed = sessions(&mut control);
    assert_eq!(listed.len(), 1);
    let session = &listed[0];
    assert_eq!(session.namespace.as_str(), "plain");
    assert_eq!(session.subpath, "/tree");
    assert_eq!(session.transport, "tcp");
    assert!(!session.peer.is_empty());
    assert_eq!(session.nodes, 2, "the mount root and the file");
    assert_eq!(session.handles, 1);

    // A second mount is a second session, with its own id.
    let mut other = fixture.server.mount("plain", "/tree");
    other.lookup(ROOT, "sub").expect("resolves");
    let listed = sessions(&mut control);
    assert_eq!(listed.len(), 2);
    assert_ne!(listed[0].id, listed[1].id);

    // And a disconnect takes its session out of the list.
    drop(other);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while sessions(&mut control).len() > 1 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(sessions(&mut control).len(), 1);
}

#[test]
fn forget_ids_may_be_reused_freely_and_at_volume() {
    let fixture = Fixture::start("forget-volume");
    let mut client = fixture.server.mount("plain", "/tree");

    // `forget` is answered by nothing, so its id retires the moment its frame
    // is accepted: a client may use the same one forever.
    for _ in 0..500 {
        let entry = client.lookup(ROOT, "data.bin").expect("resolves");
        client.forget(entry.node_id, 1);
    }
    // The session is alive and the table drains back to just its root. A
    // `forget` is answered by nothing and served on its own task, so no later
    // round trip proves it has run: the count is polled to a deadline instead.
    assert!(client.getattr(ROOT).is_ok());
    let mut control = fixture.server.connect();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let listed = loop {
        let listed = sessions(&mut control);
        assert_eq!(listed.len(), 1);
        if listed[0].nodes == 1 || std::time::Instant::now() >= deadline {
            break listed;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(listed[0].nodes, 1, "every lookup was forgotten");
}

// ---------------------------------------------------------------------------
// Session lifecycle — a mounted guest resolves against the current registry
// ---------------------------------------------------------------------------

#[test]
fn a_rule_added_or_removed_reaches_a_mounted_session_at_its_next_lookup() {
    let fixture = Fixture::start("live-rules");
    let mut client = fixture.server.mount("project", "/project");
    let mut control = fixture.server.connect();
    let project = voidport_control::NamespaceName::new("project").expect("valid");

    // `secret` is hidden by the namespace's `/project/*` rule.
    assert_eq!(
        client.lookup(ROOT, "secret").expect_err("hidden"),
        status::NOENT
    );

    // The operator admits it. No remount: the next lookup consults the
    // registry's current snapshot and sees the new rule.
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

    // Taking the rule away takes the name away again, just as immediately.
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

    // Read-write to begin with.
    let before = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(before.node_id, O_RDWR).expect("opens");
    assert_eq!(client.write(handle, 0, b"A").expect("writes"), 1);

    // The operator downgrades exactly that entry.
    control.expect_ok(&Request::RuleAdd {
        namespace: plain.clone(),
        rule: Rule::new("/tree/data.bin", ShareMode::Ro),
    });

    // A fresh lookup is a fresh node — a share mode keys a node — and it
    // enforces the new mode, as does every entry-modifying operation.
    let after = client.lookup(ROOT, "data.bin").expect("still resolves");
    assert_ne!(after.node_id, before.node_id);
    assert_eq!(
        client.open(after.node_id, O_RDWR).expect_err("write open"),
        status::ROFS
    );
    assert_eq!(
        client.unlink(ROOT, "data.bin").expect_err("unlink"),
        status::ROFS
    );

    // What the guest already holds is untouched: a node's mode binds at the
    // lookup that admitted it, and an open handle keeps working.
    assert_eq!(
        client
            .write(handle, 1, b"B")
            .expect("the open handle still writes"),
        1
    );
    client.release(handle).expect("releases");
    assert!(client.open(before.node_id, O_RDWR).is_ok());
}

#[test]
fn a_directory_graft_downgraded_to_read_only_binds_at_the_next_child_operation() {
    // The mount is the namespace root, so `/tree` is a *directory node* the
    // guest holds — the shape a file-level rule change cannot exercise.
    let fixture = Fixture::start("live-directory-downgrade");
    let mut client = fixture.server.mount("plain", "/");
    let mut control = fixture.server.connect();
    let plain = voidport_control::NamespaceName::new("plain").expect("valid");

    let tree = client.lookup(ROOT, "tree").expect("resolves");
    assert!(tree.is_directory());
    client.mkdir(tree.node_id, "before", 0o755).expect("rw");

    // The operator downgrades the whole graft, not one entry inside it.
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

    // The guest still holds the directory node it looked up while the graft was
    // read-write. Children resolve under the graft's *current* mode, so
    // everything through that node is read-only now.
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
        client.open(child.node_id, O_RDWR).expect_err("write open"),
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
    let handle = client.open(file.node_id, O_RDWR).expect("opens");

    control.expect_ok(&Request::RuleRemove {
        namespace: plain.clone(),
        path: "/tree".to_owned(),
        r#match: None,
    });

    // The name is gone from the namespace, and so is everything under the
    // directory node the guest is still holding.
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
        client.open(tree.node_id, 0).expect_err("nor listed"),
        status::NOENT
    );

    // The handle the guest already holds is grandfathered, as a downgrade
    // spares it: policy binds at lookup, and an open file keeps working.
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

    // Another host directory, with a different child.
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

    // The guest's directory node is pinned to the *old* host directory. What it
    // resolves is decided by where the namespace points now, so its children
    // are the new target's children — and only those.
    let moved = client
        .lookup(tree.node_id, "moved.bin")
        .expect("the new target's child resolves");
    let handle = client.open(moved.node_id, O_RDONLY).expect("opens");
    assert_eq!(client.read(handle, 0, 16).expect("reads"), b"moved");
    assert_eq!(
        client
            .lookup(tree.node_id, "data.bin")
            .expect_err("the old target's child is not there"),
        status::NOENT
    );

    // A listing agrees with lookup, which means it came from the new directory
    // too, not from the stale pin.
    let names: Vec<String> = client
        .list(tree.node_id)
        .expect("lists")
        .iter()
        .map(support::wire::DirEntry::name)
        .collect();
    assert_eq!(names, ["moved.bin"]);

    // And a create lands in the new target, not the old one.
    client
        .create(tree.node_id, "fresh", O_RDWR, 0o644)
        .expect("creates");
    assert!(elsewhere.join("fresh").exists());
    assert!(!fixture.tree("fresh").exists());
}

#[test]
fn a_deleted_namespace_keeps_serving_the_sessions_that_mounted_it() {
    let fixture = Fixture::start("namespace-deletion");
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, O_RDWR).expect("opens");

    // The operator deletes the namespace out from under the mount.
    let mut control = fixture.server.connect();
    control.expect_ok(&Request::NamespaceDelete {
        name: voidport_control::NamespaceName::new("plain").expect("valid"),
    });

    // The registry has nothing left under the name, so the session falls back
    // to the tombstone it captured at handshake time and keeps serving.
    assert!(client.read(handle, 0, 4).is_ok());
    assert!(client.lookup(ROOT, "sub").is_ok());
    assert_eq!(sessions(&mut control).len(), 1, "and it is still listed");

    // New handshakes fail: the namespace is gone from the registry.
    let mut fresh = fixture.server.dial();
    assert_eq!(
        fresh
            .hello("plain", "/tree")
            .expect_err("no such namespace"),
        status::NOENT
    );
}

/// The sessions the control plane reports.
fn sessions(control: &mut support::ControlClient) -> Vec<voidport_control::SessionSummary> {
    match control.expect_ok(&Request::SessionList {}) {
        Reply::SessionList { sessions } => sessions,
        other => panic!("expected a session list, got {other:?}"),
    }
}
