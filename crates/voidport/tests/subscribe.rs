//! The `voidport subscribe` command, end to end against a real server.
//!
//! The command is written on the library's [`Subscription`], so what these
//! tests exercise through the JSONL is the API an embedder would use: there is
//! one stream implementation, and this is it.
//!
//! Two subjects here, matching the criteria:
//!
//! * the documented schema, checked as text — a consumer's `jq` filter breaks
//!   on a renamed field, and that is what these assertions are for;
//! * the reconnect bracket: killing the server under an active subscription
//!   must produce `disconnected`, then `resumed`, then a fresh snapshot a
//!   level-triggered consumer can reconcile to, with `Subscribe` replaying
//!   idempotently across the gap.
//!
//! [`Subscription`]: voidport::subscribe::Subscription

mod support;

use std::io::{BufRead as _, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value;
use support::TempDir;
use support::daemon::Restartable;
use voidport_control::{NamespaceName, Reply, Request, Rule, ShareMode};

/// How long a test waits for a line it expects.
const PATIENCE: Duration = Duration::from_secs(30);

/// The state file these tests serve: one host tree, grafted read-write.
fn state_file(tree: &Path, socket: &Path) -> String {
    format!(
        r#"
[server]

[[server.listeners]]
transport = "unix"
path = "{socket}"

[[namespaces]]
name = "work"

[[namespaces.rules]]
path = "/tree"
mode = "rw"
target = "{tree}"
"#,
        socket = socket.display(),
        tree = tree.display(),
    )
}

/// A running `voidport subscribe`, and its lines.
///
/// The lines are pumped off the pipe by a thread of their own, so a test that
/// waits for an event the command never emits **fails** instead of hanging:
/// `read_line` on a pipe has no timeout, and a suite that wedges tells nobody
/// what went wrong.
struct Stream {
    child: Child,
    lines: mpsc::Receiver<String>,
}

impl Stream {
    /// Starts the command against a mount URL.
    fn open(url: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_voidport"))
            .args(["subscribe", url])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the voidport binary runs");
        let stdout = child.stdout.take().expect("stdout is piped");
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if sender.send(line).is_err() {
                    return;
                }
            }
        });
        Self { child, lines }
    }

    /// The next line, parsed.
    ///
    /// A stream that says nothing in time is a failure, not a `None`: every
    /// test here is waiting for something the command owes it.
    fn next(&mut self) -> Value {
        let line = match self.lines.recv_timeout(PATIENCE) {
            Ok(line) => line,
            Err(error) => panic!(
                "no event in time ({error:?}); child alive={:?}",
                self.child.try_wait()
            ),
        };
        // Every line is parsed, which is also the guard on the *other* stream:
        // a diagnostic that landed on stdout instead of stderr would fail here
        // instead of quietly breaking a consumer's pipeline.
        serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("every line is one JSON object: {error} in {line:?}"))
    }

    /// Reads until an event of that name arrives, and returns it.
    fn next_named(&mut self, event: &str) -> Value {
        let deadline = Instant::now() + PATIENCE;
        loop {
            assert!(Instant::now() < deadline, "no {event} arrived in time");
            let line = self.next();
            if line["event"] == event {
                return line;
            }
        }
    }

    /// Waits for the command to exit, and reports its status.
    fn wait(mut self) -> std::process::ExitStatus {
        self.child.wait().expect("the command is waitable")
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The share paths a snapshot line names, in the order it carried them.
fn paths(snapshot: &Value) -> Vec<String> {
    snapshot["entries"]
        .as_array()
        .expect("a snapshot carries an entry array")
        .iter()
        .map(|entry| entry["path"].as_str().expect("a path is text").to_owned())
        .collect()
}

/// Drives one control-plane request against the server, and expects it to
/// succeed.
fn control(server: &Restartable, request: &Request) -> Reply {
    let mut client = voidport_control::Client::connect(server.control_socket())
        .expect("the control socket accepts connections");
    let answer = client.call(request).expect("the server answers");
    match answer.response {
        voidport_control::Response::Ok { result } => result,
        voidport_control::Response::Error { error } => panic!("the server refused: {error}"),
    }
}

fn namespace(name: &str) -> NamespaceName {
    NamespaceName::new(name).expect("a valid namespace name")
}

/// Criterion 8: the CLI emits the documented JSONL exactly.
#[test]
fn the_command_emits_the_documented_json_lines() {
    let directory = TempDir::new("cli-subscribe-schema");
    let tree = directory.directory("tree");
    let socket = directory.join("data.sock");
    let server = Restartable::start(&directory, &state_file(&tree, &socket));

    let mut stream = Stream::open(&server.url("work", ""));

    // The opening snapshot: `v`, `event`, and an entry array of
    // `{path, mode, kind}` and nothing else.
    let snapshot = stream.next_named("snapshot");
    assert_eq!(snapshot["v"], 1);
    assert_eq!(paths(&snapshot), vec!["/tree".to_owned()]);
    let entry = &snapshot["entries"][0];
    assert_eq!(entry["path"], "/tree");
    assert_eq!(entry["mode"], "rw");
    assert_eq!(entry["kind"], "directory");
    assert_eq!(
        entry.as_object().expect("an entry is an object").len(),
        3,
        "an entry carries exactly path, mode and kind"
    );

    // An added share.
    control(
        &server,
        &Request::RuleAdd {
            namespace: namespace("work"),
            rule: Rule::new("/tree/docs", ShareMode::Ro),
        },
    );
    let added = stream.next_named("added");
    assert_eq!(added["v"], 1);
    assert_eq!(added["path"], "/tree/docs");
    assert_eq!(added["mode"], "ro");
    assert_eq!(added["kind"], "unknown");

    // A removed share carries its path and nothing more: there is nothing left
    // to say about an entry that is gone.
    control(
        &server,
        &Request::RuleRemove {
            namespace: namespace("work"),
            path: "/tree/docs".to_owned(),
            r#match: None,
        },
    );
    let removed = stream.next_named("removed");
    assert_eq!(removed["v"], 1);
    assert_eq!(removed["path"], "/tree/docs");
    assert_eq!(
        removed.as_object().expect("an object").len(),
        3,
        "removed carries v, event and path"
    );

    // Deleting the namespace ends the stream, and the command exits 0 after it.
    control(
        &server,
        &Request::NamespaceDelete {
            name: namespace("work"),
        },
    );
    let ended = stream.next_named("ended");
    assert_eq!(ended["v"], 1);
    assert_eq!(ended["reason"], "namespace-removed");
    assert!(
        stream.wait().success(),
        "the command exits cleanly once the stream has ended"
    );
}

/// Criterion 7: a kill and restart under an active subscription brackets the
/// outage and resumes with a fresh snapshot the consumer can reconcile to.
///
/// The configuration is *changed* across the gap, so a consumer that merely
/// replayed its deltas would end up with the wrong set: only the snapshot the
/// resubscription answers gets it right, which is what "level-triggered" buys.
#[test]
fn a_restart_brackets_the_outage_and_resumes_with_the_correct_set() {
    let directory = TempDir::new("cli-subscribe-restart");
    let tree = directory.directory("tree");
    let other = directory.directory("other");
    let socket = directory.join("data.sock");
    let mut server = Restartable::start(&directory, &state_file(&tree, &socket));

    let mut stream = Stream::open(&server.url("work", ""));
    assert_eq!(paths(&stream.next_named("snapshot")), vec!["/tree"]);

    // The configuration the server comes back with is a different one: a second
    // graft, and the first one downgraded to read-only.
    server.kill();
    server.rewrite_state(&format!(
        r#"
[server]

[[server.listeners]]
transport = "unix"
path = "{socket}"

[[namespaces]]
name = "work"

[[namespaces.rules]]
path = "/tree"
mode = "ro"
target = "{tree}"

[[namespaces.rules]]
path = "/other"
mode = "rw"
target = "{other}"
"#,
        socket = socket.display(),
        tree = tree.display(),
        other = other.display(),
    ));

    // The outage is bracketed.
    let disconnected = stream.next_named("disconnected");
    assert_eq!(disconnected["v"], 1);

    server.start_again();

    let resumed = stream.next_named("resumed");
    assert_eq!(resumed["v"], 1);

    // And the fresh snapshot is the truth, not a replay of what came before.
    let snapshot = stream.next_named("snapshot");
    assert_eq!(
        paths(&snapshot),
        vec!["/other".to_owned(), "/tree".to_owned()]
    );
    let modes: Vec<&str> = snapshot["entries"]
        .as_array()
        .expect("an entry array")
        .iter()
        .map(|entry| entry["mode"].as_str().expect("a mode is text"))
        .collect();
    assert_eq!(
        modes,
        vec!["rw", "ro"],
        "the re-moded graft comes back with the mode the new configuration gives it"
    );

    // The stream is live again: a further edit reaches it as an ordinary delta,
    // which is what proves the resubscription really was re-established and
    // not merely reported.
    control(
        &server,
        &Request::RuleAdd {
            namespace: namespace("work"),
            rule: Rule::new("/other/inner", ShareMode::Rw),
        },
    );
    let added = stream.next_named("added");
    assert_eq!(added["path"], "/other/inner");
}

/// The reconnect contract's replay list, from the other side: re-issuing
/// `Subscribe` and `Unsubscribe` across a gap is harmless.
///
/// `Unsubscribe` against the fresh session a reconnect built has nothing to
/// unsubscribe and answers plain success; `Subscribe` against an
/// already-subscribed session answers a fresh snapshot. Both are exercised here
/// through the library, since that is where the ops live.
#[test]
fn subscribe_and_unsubscribe_replay_idempotently() {
    use voidport::client::{Caller, Client};
    use voidport::url::MountUrl;

    let directory = TempDir::new("cli-subscribe-replay");
    let tree = directory.directory("tree");
    let socket = directory.join("data.sock");
    let mut server = Restartable::start(&directory, &state_file(&tree, &socket));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let url = MountUrl::parse(&server.url("work", "")).expect("a valid url");
    let client = runtime
        .block_on(Client::mount(
            &url.endpoint,
            url.namespace.as_str(),
            &url.subpath,
        ))
        .expect("the mount is established");

    // Repeated either way round, on one session: neither is an error.
    runtime.block_on(async {
        client
            .unsubscribe(Caller::default())
            .await
            .expect("a no-op");
        client
            .subscribe(Caller::default())
            .await
            .expect("subscribed");
        client.subscribe(Caller::default()).await.expect("resynced");
        client
            .unsubscribe(Caller::default())
            .await
            .expect("stopped");
        client
            .unsubscribe(Caller::default())
            .await
            .expect("a no-op");
    });

    // And across a real gap, against the fresh session the reconnect built.
    server.restart();
    assert!(support::eventually(PATIENCE, || client.state()
        == voidport::client::MountState::Connected));
    runtime.block_on(async {
        client
            .unsubscribe(Caller::default())
            .await
            .expect("a replayed unsubscribe is a no-op on a fresh session");
        client
            .subscribe(Caller::default())
            .await
            .expect("a replayed subscribe is the resync");
    });

    let Reply::SessionList { sessions } = control(&server, &Request::SessionList {}) else {
        panic!("a session list answers a session list");
    };
    assert!(
        sessions.iter().any(|session| session.subscribed),
        "the operator sees the replayed subscription"
    );
}

/// One subscription per mount, and the refusal costs the first one nothing.
///
/// A mount carries a single notification stream — `Subscribe` enables the
/// session's, and no frame says which of two consumers it is for — so a second
/// `Subscription::open` on the same client is refused with `EBUSY` instead of
/// quietly replacing the sink the first one is reading. Closing or dropping a
/// subscription hands the mount back.
#[test]
fn one_subscription_per_mount_and_the_second_is_refused() {
    use std::sync::Arc;

    use rustix::io::Errno;
    use voidport::client::Client;
    use voidport::subscribe::{ShareEvent, Subscription};
    use voidport::url::MountUrl;

    let directory = TempDir::new("cli-subscribe-single");
    let tree = directory.directory("tree");
    let socket = directory.join("data.sock");
    let server = Restartable::start(&directory, &state_file(&tree, &socket));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let url = MountUrl::parse(&server.url("work", "")).expect("a valid url");
    let client = runtime
        .block_on(Client::mount(
            &url.endpoint,
            url.namespace.as_str(),
            &url.subpath,
        ))
        .expect("the mount is established");

    let mut first = runtime
        .block_on(Subscription::open(Arc::clone(&client)))
        .expect("the first subscription opens");
    assert!(matches!(
        runtime.block_on(first.next()),
        Some(ShareEvent::Snapshot { .. })
    ));

    assert_eq!(
        runtime
            .block_on(Subscription::open(Arc::clone(&client)))
            .err(),
        Some(Errno::BUSY),
        "a second subscription on one mount is refused, not silently served"
    );

    // And the first stream is exactly as it was: an ordinary delta still
    // reaches it, so the refusal took nothing from it.
    control(
        &server,
        &Request::RuleAdd {
            namespace: namespace("work"),
            rule: Rule::new("/tree/inner", ShareMode::Ro),
        },
    );
    assert!(matches!(
        runtime.block_on(first.next()),
        Some(ShareEvent::Added(_))
    ));

    // Closing hands the mount back, and the next subscription opens on it.
    runtime.block_on(first.close()).expect("closed");
    let mut second = runtime
        .block_on(Subscription::open(Arc::clone(&client)))
        .expect("a closed subscription frees the mount");
    assert!(matches!(
        runtime.block_on(second.next()),
        Some(ShareEvent::Snapshot { .. })
    ));

    // Dropping does the same, without a request of its own.
    drop(second);
    let third = runtime
        .block_on(Subscription::open(Arc::clone(&client)))
        .expect("a dropped subscription frees the mount");
    drop(third);
}

/// The replay discipline and the reconnect bracket must not both re-subscribe.
///
/// A `Subscribe` that was written and never answered is replayed onto the
/// connection that replaces the dead one — the reconnect contract's idempotent
/// list says so — and the session behind *that* connection is then subscribed.
/// A bracket that keyed on the connection the request was first written to
/// would re-subscribe on top of it and charge the consumer a second snapshot,
/// or worse a `lapsed` line for a lapse that never happened. The stream records
/// the connection that **answered** instead, and this is where that is proven:
/// a server that takes the first `Subscribe` and dies without answering it.
#[test]
fn a_subscribe_replayed_across_a_reconnect_subscribes_once() {
    use std::sync::Arc;

    use voidport::client::Client;
    use voidport::subscribe::{ShareEvent, Subscription};
    use voidport::url::Endpoint;

    let (address, observed) = replaying_server();
    let endpoint = Endpoint::Tcp {
        host: address.ip().to_string(),
        port: address.port(),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");

    runtime.block_on(async move {
        let client = Client::mount(&endpoint, "work", b"")
            .await
            .expect("the handshake succeeds");
        // Answered by the replacement connection, since the first one died
        // holding this very request.
        let mut shares = Subscription::open(Arc::clone(&client))
            .await
            .expect("the replayed subscribe establishes the stream");
        assert!(
            matches!(shares.next().await, Some(ShareEvent::Snapshot { entries }) if entries.is_empty()),
            "the stream opens with the snapshot the surviving connection sent"
        );
        // And nothing else: no second snapshot, and no `lapsed` for a lapse
        // that never happened.
        assert!(
            tokio::time::timeout(Duration::from_millis(500), shares.next())
                .await
                .is_err(),
            "one subscribe, one snapshot"
        );
    });

    assert_eq!(
        observed.recv_timeout(PATIENCE).expect("the server reports"),
        1,
        "the replacement connection was asked to subscribe exactly once"
    );
}

/// A server that kills the connection holding an unanswered `Subscribe`, then
/// serves the replay on the next one and counts what it is asked.
///
/// The count is what the test needs and the only thing it reports: how many
/// `Subscribe` requests the *replacement* connection was sent before it went
/// quiet.
fn replaying_server() -> (std::net::SocketAddr, mpsc::Receiver<usize>) {
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};

    use voidport_proto::PROTOCOL_VERSION;
    use voidport_proto::frame::{FRAME_HEADER_LEN, Frame, FrameHeader, FrameWriter};
    use voidport_proto::opcode::Opcode;
    use voidport_proto::ops::handshake::HelloReply;
    use voidport_proto::ops::share::{ShareSnapshotBegin, ShareSnapshotEnd};
    use voidport_proto::ops::subscribe::SubscribeResponse;
    use zerocopy::FromBytes as _;
    use zerocopy::byteorder::little_endian::{U32, U64};

    /// The frame bound this server announces.
    const MAX_FRAME_LEN: u32 = 1024 * 1024;
    /// How long a connection waits before it calls the client quiet.
    const QUIET: Duration = Duration::from_secs(2);

    /// Reads one whole frame, or `None` once the peer goes quiet or away.
    fn read_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
        let mut header = [0u8; FRAME_HEADER_LEN];
        stream.read_exact(&mut header).ok()?;
        let (parsed, _) = FrameHeader::ref_from_prefix(&header).expect("a header");
        let mut bytes = vec![0u8; parsed.len.get() as usize];
        bytes[..FRAME_HEADER_LEN].copy_from_slice(&header);
        stream.read_exact(&mut bytes[FRAME_HEADER_LEN..]).ok()?;
        Some(bytes)
    }

    /// Answers the handshake, as the real server does.
    fn handshake(stream: &mut TcpStream) {
        let hello = read_frame(stream).expect("a hello");
        let request_id = Frame::parse(&hello, MAX_FRAME_LEN)
            .expect("a well-framed hello")
            .request_id();
        let mut buffer = [0u8; 64];
        let reply = FrameWriter::response(
            &mut buffer,
            MAX_FRAME_LEN,
            request_id,
            &HelloReply {
                root_node_id: U64::new(1),
                protocol_version: U32::new(PROTOCOL_VERSION),
                flags: U32::ZERO,
                max_frame_len: U32::new(MAX_FRAME_LEN),
                reserved: U32::ZERO,
            },
        )
        .and_then(FrameWriter::finish)
        .expect("encodable")
        .to_vec();
        stream.write_all(&reply).expect("the client is listening");
    }

    /// One notification frame carrying `body`.
    fn notification<M: voidport_proto::message::NotificationBody>(body: &M) -> Vec<u8> {
        let mut buffer = vec![0u8; FRAME_HEADER_LEN + size_of::<M>()];
        FrameWriter::notification(&mut buffer, MAX_FRAME_LEN, body)
            .and_then(FrameWriter::finish)
            .expect("encodable")
            .to_vec()
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let address = listener.local_addr().expect("a bound address");
    let (report, observed) = mpsc::channel();

    std::thread::spawn(move || {
        // The first connection: it takes the `Subscribe` and dies holding it,
        // which is exactly the written-but-unanswered state the replay
        // discipline is written for.
        let (mut first, _) = listener.accept().expect("the client connects");
        first
            .set_read_timeout(Some(PATIENCE))
            .expect("a settable timeout");
        handshake(&mut first);
        let taken = read_frame(&mut first).expect("a subscribe");
        let (header, _) = FrameHeader::ref_from_prefix(&taken).expect("a header");
        assert_eq!(header.opcode.get(), Opcode::Subscribe.as_u16());
        drop(first);

        // The replacement: it serves whatever it is asked, and counts the
        // subscriptions.
        let (mut second, _) = listener.accept().expect("the client reconnects");
        second
            .set_read_timeout(Some(PATIENCE))
            .expect("a settable timeout");
        handshake(&mut second);
        let mut subscribes = 0;
        while let Some(request) = read_frame(&mut second) {
            let (header, _) = FrameHeader::ref_from_prefix(&request).expect("a header");
            assert_eq!(
                header.opcode.get(),
                Opcode::Subscribe.as_u16(),
                "this server is asked nothing else"
            );
            subscribes += 1;
            let mut buffer = [0u8; 64];
            let confirm = FrameWriter::response(
                &mut buffer,
                MAX_FRAME_LEN,
                header.request_id.get(),
                &SubscribeResponse {
                    reserved: U32::ZERO,
                },
            )
            .and_then(FrameWriter::finish)
            .expect("encodable")
            .to_vec();
            second.write_all(&confirm).expect("the client is listening");
            // An empty snapshot, bracketed as the contract spells it.
            for frame in [
                notification(&ShareSnapshotBegin {
                    entries: U32::ZERO,
                    reserved: U32::ZERO,
                }),
                notification(&ShareSnapshotEnd {
                    reserved: U32::ZERO,
                }),
            ] {
                second.write_all(&frame).expect("the client is listening");
            }
            // From here the client owes this server nothing, so a quiet
            // stretch ends the loop and reports.
            second
                .set_read_timeout(Some(QUIET))
                .expect("a settable timeout");
        }
        let _ = report.send(subscribes);
    });

    (address, observed)
}

/// Criterion 8's second half: the example mount manager drives real mounts and
/// unmounts from the stream, end to end.
///
/// It is the documented consumer, run as documented — `docs/examples/
/// mount-manager.sh`, against a real server, with real FUSE mounts appearing
/// and disappearing under a mount root. A mode change and an `ended` teardown
/// are both in the sequence, because both are places a consumer that merely
/// replayed deltas would get the mount set wrong.
#[test]
fn the_example_mount_manager_drives_real_mounts() {
    if !support::preflight() {
        return;
    }
    let directory = TempDir::new("cli-subscribe-manager");
    let tree = directory.directory("tree");
    let docs = directory.directory("docs");
    std::fs::write(tree.join("data.bin"), b"tree").expect("a writable tree");
    std::fs::write(docs.join("note.txt"), b"docs").expect("a writable tree");
    let socket = directory.join("data.sock");
    let server = Restartable::start(&directory, &state_file(&tree, &socket));
    let root = directory.directory("mounts");

    // The manager needs the binaries it drives on PATH, and the tools the
    // script uses; the dev shell carries both.
    let binaries = Path::new(env!("CARGO_BIN_EXE_voidport"))
        .parent()
        .expect("the binary lives somewhere")
        .to_path_buf();
    let path = format!(
        "{}:{}",
        binaries.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples/mount-manager.sh")
        .canonicalize()
        .expect("the documented example exists");

    let mut manager = Command::new("bash")
        .arg(&script)
        .arg(server.url("work", ""))
        .arg(&root)
        .env("PATH", path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the example script runs");
    // Whatever this test does next, the manager and its mounts come down.
    let cleanup = |root: &Path| {
        for point in std::fs::read_dir(root).into_iter().flatten().flatten() {
            let _ = voidport::mount::unmount(&point.path());
        }
    };

    // The opening snapshot mounts what the namespace shares.
    let mounted = |name: &str| root.join(name).join("data.bin").exists();
    let assertion = support::eventually(PATIENCE, || mounted("tree"));
    if !assertion {
        let _ = manager.kill();
        cleanup(&root);
        panic!("the snapshot's share was never mounted");
    }

    // A share that appears is mounted.
    control(
        &server,
        &Request::RuleAdd {
            namespace: namespace("work"),
            rule: Rule::new("/docs", ShareMode::Rw).with_target(docs.display().to_string()),
        },
    );
    let appeared = support::eventually(PATIENCE, || root.join("docs").join("note.txt").exists());

    // A re-mode: the control plane has no modify operation, so an operator's
    // "make it read-only" is a remove followed by an add, and the manager
    // unmounts and remounts accordingly. The kernel then enforces it.
    control(
        &server,
        &Request::RuleRemove {
            namespace: namespace("work"),
            path: "/docs".to_owned(),
            r#match: None,
        },
    );
    let unmounted = support::eventually(PATIENCE, || !root.join("docs").join("note.txt").exists());
    control(
        &server,
        &Request::RuleAdd {
            namespace: namespace("work"),
            rule: Rule::new("/docs", ShareMode::Ro).with_target(docs.display().to_string()),
        },
    );
    let read_only = support::eventually(PATIENCE, || {
        let note = root.join("docs").join("note.txt");
        note.exists() && std::fs::write(&note, b"nope").is_err()
    });

    // Deleting the namespace ends the stream, and the manager takes its mounts
    // down on the way out.
    control(
        &server,
        &Request::NamespaceDelete {
            name: namespace("work"),
        },
    );
    let ended = support::eventually(PATIENCE, || manager.try_wait().ok().flatten().is_some());
    let torn_down = support::eventually(PATIENCE, || !mounted("tree"));

    let _ = manager.kill();
    let _ = manager.wait();
    cleanup(&root);

    assert!(appeared, "a share that appeared was never mounted");
    assert!(unmounted, "a share that went away was never unmounted");
    assert!(
        read_only,
        "a re-moded share was never remounted with the mode it now has"
    );
    assert!(ended, "the manager exits when the stream ends");
    assert!(torn_down, "the manager unmounts everything on the way out");
}
