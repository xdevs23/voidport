//! Mount resilience: what happens when the server breaks away.
//!
//! Reconnect-increment criteria **1, 2, 3, 5, 8 and 11**. Every server here is
//! a real `voidportd` process, killed with `SIGKILL` and brought back on the
//! same unix socket, because the contract is about a server that dies without
//! warning, not one that shuts down politely.
//!
//! Two levels, deliberately:
//!
//! * the **client level** for anything measured against the stall window or
//!   against the server's configuration, where a straight-line story —
//!   connect, kill, assert — says exactly what is being claimed;
//! * the **mount level** for anything the guest kernel has to carry, above all
//!   the `ESTALE`-retry healing that makes a path-based operation survive a
//!   restart with no error surfaced at all.

mod support;

use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::net::TcpListener;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustix::io::Errno;
use support::daemon::{
    CONTENTS, Ground, PATIENCE, accepts, eventually, runtime, settle, state_file,
    state_file_hiding_children, state_file_read_only, state_file_retargeted,
    state_file_without_the_namespace, state_file_without_the_tree,
};
use support::{errno, preflight};
use voidport::client::{Caller, MountState};
use voidport::url::Endpoint;

/// The stall window these tests run with.
///
/// Shorter than the shipped default so a test that deliberately waits it out
/// takes two seconds, not five; nothing here depends on the number
/// beyond its being the one the mount was configured with.
const STALL: Duration = Duration::from_secs(2);

/// How much longer than the window a stalled request may take before the
/// measurement stops meaning anything.
///
/// It covers scheduling and one backoff step, not a second window: an
/// assertion that passed at twice the deadline would not be testing the
/// deadline.
const SLACK: Duration = Duration::from_millis(1500);

/// How long "immediately" is allowed to be.
///
/// A degraded mount answers without touching the network at all, so this is
/// scheduling noise and nothing else.
const IMMEDIATE: Duration = Duration::from_millis(500);

// ---------------------------------------------------------------------------
// Criterion 1 — a restart inside the window
// ---------------------------------------------------------------------------

/// Path-based work carries on across a restart with nothing surfaced to the
/// application, while work bound to identifiers from the dead session does not
/// — and recovers on reopen.
///
/// The two halves are the whole of the outcome the design requires. Walks, opens by path,
/// creates and statfs are carried by the kernel's own `ESTALE`-retry healing:
/// the mount root is node id 1 in every session, so a re-walk from the root
/// rebuilds any depth of path. Reads and writes on a descriptor opened *before*
/// the restart cannot be: the server's ids are generation-disjoint, so the
/// handle names nothing and says so.
#[test]
fn a_restart_inside_the_window_heals_paths_and_stales_open_descriptors() {
    if !preflight() {
        return;
    }
    let mut ground = Ground::start("heal");
    let guest = ground.mount("heal", STALL);

    // A descriptor from before the gap, and the data it can still read now. It
    // is opened for writing too, because a write is the half of the criterion
    // that cannot be answered from a cache.
    let mut held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(guest.path("tree/data.bin"))
        .expect("opens before the restart");
    let mut before = Vec::new();
    held.read_to_end(&mut before).expect("reads before");
    assert_eq!(before, CONTENTS);

    // Concurrent path-based load across the whole restart.
    let stop = Arc::new(AtomicBool::new(false));
    let failures: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let workers: Vec<_> = (0..4)
        .map(|index| {
            let stop = Arc::clone(&stop);
            let failures = Arc::clone(&failures);
            let root = guest.root().to_path_buf();
            std::thread::spawn(move || walk(&root, index, &stop, &failures))
        })
        .collect();
    std::thread::sleep(Duration::from_millis(200));

    ground.server.kill();
    // Waiting for the mount to notice is what makes the creates below provably
    // *queued* and not merely likely to be: a request issued into a
    // connection the mount still believes in could be written before the socket
    // reports its death, and a written mutation is a different clause of the
    // replay contract.
    let client = guest.client();
    assert!(
        eventually(PATIENCE, || client.state() != MountState::Connected),
        "the mount never noticed its server had gone"
    );

    // Creates issued while the server is down are *queued*: they never reached
    // a socket, so the replay discipline sends them as they are once the
    // handshake is back. They must all succeed.
    let created = {
        let root = guest.root().to_path_buf();
        std::thread::spawn(move || {
            (0..3)
                .map(|index| {
                    let path = root.join(format!("tree/created-{index}"));
                    fs::write(&path, b"queued").map_err(|error| format!("{path:?}: {error}"))
                })
                .collect::<Vec<_>>()
        })
    };
    std::thread::sleep(Duration::from_millis(150));
    ground.server.start_again();

    let created = created.join().expect("the create thread finishes");
    for outcome in created {
        outcome.expect("a create stalled across the gap must complete");
    }
    std::thread::sleep(Duration::from_millis(500));
    stop.store(true, Ordering::Relaxed);
    for worker in workers {
        worker.join().expect("a worker finishes");
    }
    let failures = failures.lock().expect("unpoisoned");
    assert!(
        failures.is_empty(),
        "path-based work must survive a restart inside the window: {failures:?}"
    );
    drop(failures);

    // The other half: the pre-restart descriptor is bound to a dead session.
    //
    // The write is the deterministic one. The mount is writethrough by design,
    // so every write reaches the server, where the handle the dead session
    // issued names nothing.
    let refused = held
        .write_all(b"!")
        .expect_err("a descriptor cannot survive its session");
    assert!(
        stale(&refused),
        "a write through the dead session's handle should report the loss: {refused}"
    );
    // The read is the same loss, arriving when the guest's own cache stops
    // answering: within the attribute TTL the kernel may serve the pages it
    // already has, which is the caching contract working exactly as specified, and
    // the revalidation after it is what asks the server about a node that is
    // gone.
    assert!(
        eventually(PATIENCE, || {
            let mut after = Vec::new();
            held.seek(SeekFrom::Start(0)).is_ok()
                && held
                    .read_to_end(&mut after)
                    .is_err_and(|error| stale(&error))
        }),
        "a read through the dead session's handle never reported the loss"
    );
    // And reopening is all it takes.
    assert_eq!(
        fs::read(guest.path("tree/data.bin")).expect("reopening works"),
        CONTENTS
    );
}

/// Whether an error is the plain stale errno an identifier from a dead session
/// is owed: `ESTALE` for a node, `EBADF` for a handle. Never `EIO` — that would
/// be the mount refusing to serve, not the server answering honestly.
fn stale(error: &std::io::Error) -> bool {
    let code = errno(error);
    code == Errno::STALE.raw_os_error() || code == Errno::BADF.raw_os_error()
}

/// One worker's concurrent load across the restart.
///
/// Two classes, because the criterion has two halves and one worker straddles
/// both:
///
/// * **path resolution** — a stat, an open by path and a statfs. Every one of
///   them resolves from the mount root, which is node id 1 in every session, so
///   the kernel's `ESTALE` retry re-walks and rebuilds whatever the gap
///   invalidated. None of them may ever surface an error.
/// * **content through a descriptor the operation opened for itself** — a read
///   and a listing. An open that lands just before the gap leaves its read on
///   the far side of it, naming a handle the dead session issued: that is
///   precisely the criterion's other half, so these may fail — but only with
///   the plain stale errno that half is owed, never with anything else and
///   never with `EIO`.
///
/// Only violations are collected, and they are collected instead of asserted
/// so that the test can report all of them at once.
fn walk(root: &Path, index: usize, stop: &AtomicBool, failures: &Mutex<Vec<String>>) {
    let mut round = 0usize;
    while !stop.load(Ordering::Relaxed) {
        round += 1;
        let record = |what: &str, error: &std::io::Error| {
            failures
                .lock()
                .expect("unpoisoned")
                .push(format!("worker {index} round {round}: {what}: {error}"));
        };
        let bound_to_a_handle = |what: &str, error: &std::io::Error| {
            if !stale(error) {
                record(what, error);
            }
        };

        if let Err(error) = fs::metadata(root.join("tree/alpha")) {
            record("stat", &error);
        }
        if let Err(error) = fs::File::open(root.join("tree/data.bin")) {
            record("open by path", &error);
        }
        if let Err(error) = rustix::fs::statvfs(root).map_err(std::io::Error::from) {
            record("statfs", &error);
        }
        if let Err(error) = fs::read(root.join("tree/data.bin")) {
            bound_to_a_handle("read by path", &error);
        }
        let listed = fs::read_dir(root.join("tree"))
            .and_then(|entries| entries.collect::<std::io::Result<Vec<_>>>());
        if let Err(error) = listed {
            bound_to_a_handle("readdir", &error);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ---------------------------------------------------------------------------
// Criterion 2 — a server absent past the window
// ---------------------------------------------------------------------------

/// A stalled request fails at the window's edge, and everything after it fails
/// at once.
///
/// The measurement runs from the kill, not from the request, because the
/// deadline is the *mount's*: a request that arrives late in the window
/// inherits what is left of it instead of being given a fresh timer of its
/// own.
#[test]
fn a_server_absent_past_the_window_fails_at_its_edge_and_then_immediately() {
    let mut ground = Ground::start("window");
    let runtime = runtime();
    let client = ground.connect(&runtime, STALL);
    let caller = Caller::default();
    let root = client.root_node_id();
    runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the mount serves");

    let killed = Instant::now();
    ground.server.kill();
    let stalled = runtime
        .block_on(client.getattr(caller, root, None))
        .expect_err("the server is gone");
    let waited = killed.elapsed();
    assert_eq!(stalled, Errno::IO);
    assert!(
        waited >= STALL,
        "the request gave up after {waited:?}, before the {STALL:?} window closed"
    );
    assert!(
        waited <= STALL + SLACK,
        "the request waited {waited:?}, well past the {STALL:?} window"
    );
    assert_eq!(client.state(), MountState::Degraded);

    // Subsequent requests are not given another window.
    for round in 0..5 {
        let started = Instant::now();
        assert_eq!(
            runtime
                .block_on(client.getattr(caller, root, None))
                .expect_err("still gone"),
            Errno::IO
        );
        assert!(
            started.elapsed() < IMMEDIATE,
            "request {round} waited {:?} on a degraded mount",
            started.elapsed()
        );
    }
}

/// A handshake that completes *after* the deadline does not serve the window it
/// missed.
///
/// The black-box half of "the deadline wins every tie". A front holds every
/// connection for longer than the window, so the hello behind the stalled
/// caller provably completes *after* the caller's deadline: the caller is owed
/// its `EIO` at the edge and not the answer that arrives a second later, and
/// the mount is owed its return to Connected once that hello does land.
///
/// The remaining half — a hello and the timer coming ready in the same poll,
/// where `tokio::time::timeout` polls the dial before its own timer — is a
/// sub-millisecond scheduling race that cannot be constructed from outside.
/// It is held instead by the two clock reads in the client: the stalled caller
/// reads `Instant::now()` *after* its wait and before it looks at the phase,
/// and the probe records the crossing before it installs.
#[test]
fn a_handshake_completing_past_the_deadline_does_not_serve_the_window_it_missed() {
    let mut ground = Ground::start("late-hello");
    let runtime = runtime();
    let late = STALL + Duration::from_secs(1);
    let client = ground.connect_to(&runtime, &held_back(&ground.socket(), late), STALL);
    let caller = Caller::default();
    let root = client.root_node_id();
    runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the mount serves");

    // The server comes straight back, so the only thing standing between the
    // mount and a completed hello is the front's delay.
    let killed = Instant::now();
    ground.server.restart();
    let stalled = runtime
        .block_on(client.getattr(caller, root, None))
        .expect_err("the window closed before any hello completed");
    let waited = killed.elapsed();
    assert_eq!(stalled, Errno::IO);
    assert!(
        waited >= STALL,
        "the request gave up after {waited:?}, before the {STALL:?} window closed"
    );
    assert!(
        waited < late,
        "the request waited {waited:?} and was answered by a handshake that \
         completed at {late:?} — past the window it was owed an error at"
    );

    // And the late handshake is not lost: it is the ordinary return from
    // Degraded, which is the other half of the same decision.
    settle(&client);
    runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the mount serves again");
}

/// A loopback front for the server's socket that holds every connection for
/// `delay` before it forwards anything, and then forwards it whole.
///
/// Not a wedged peer: this one *does* complete the handshake, just always too
/// late for the window that was waiting on it.
fn held_back(socket: &Path, delay: Duration) -> Endpoint {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a loopback listener");
    let address = listener.local_addr().expect("the listener is bound");
    let socket = socket.to_path_buf();
    std::thread::spawn(move || {
        while let Ok((guest, _)) = listener.accept() {
            let socket = socket.clone();
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                let Ok(server) = UnixStream::connect(&socket) else {
                    return;
                };
                let (mut upstream, mut downstream) = (
                    guest.try_clone().expect("a cloned guest socket"),
                    server.try_clone().expect("a cloned server socket"),
                );
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut upstream, &mut downstream);
                });
                let (mut back, mut out) = (server, guest);
                let _ = std::io::copy(&mut back, &mut out);
            });
        }
    });
    Endpoint::Tcp {
        host: address.ip().to_string(),
        port: address.port(),
    }
}

/// A peer that accepts the socket and never completes the handshake does not
/// hold the mount past the deadline.
///
/// This is the case the spec review probed: without a bound over the whole
/// attempt — dial, hello write, hello read — a wedged listener keeps the
/// stalled callers waiting for as long as it feels like, and the design's five
/// seconds become unbounded.
#[test]
fn a_wedged_peer_does_not_hold_the_mount_past_the_deadline() {
    let mut ground = Ground::start("wedged");
    let runtime = runtime();
    let client = ground.connect(&runtime, STALL);
    let caller = Caller::default();
    let root = client.root_node_id();
    runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the mount serves");

    let killed = Instant::now();
    ground.server.kill();
    // Something that answers the connect and then says nothing at all.
    let socket = ground.socket();
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("the socket path is free");
    let wedged = Arc::new(AtomicBool::new(false));
    let accepted = Arc::clone(&wedged);
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            accepted.store(true, Ordering::Relaxed);
            // Held, never read, never answered.
            held.push(stream);
        }
    });
    assert!(
        eventually(PATIENCE, || accepts(&socket)),
        "the wedged listener never came up"
    );

    let stalled = runtime
        .block_on(client.getattr(caller, root, None))
        .expect_err("nothing is being served");
    let waited = killed.elapsed();
    assert_eq!(stalled, Errno::IO);
    assert!(
        waited <= STALL + SLACK,
        "a wedged peer held the mount for {waited:?}, past the {STALL:?} window"
    );
    assert!(
        wedged.load(Ordering::Relaxed),
        "the probe never reached the wedged peer, so nothing was proven"
    );
    assert_eq!(client.state(), MountState::Degraded);
}

// ---------------------------------------------------------------------------
// Criterion 3 — a server that returns after degradation
// ---------------------------------------------------------------------------

/// Once the server is back, requests flow again with no remount: a fresh walk
/// from the mount root succeeds and new opens work.
#[test]
fn a_server_returning_after_degradation_resumes_without_a_remount() {
    if !preflight() {
        return;
    }
    let mut ground = Ground::start("returns");
    let guest = ground.mount("returns", STALL);
    assert_eq!(
        fs::read(guest.path("tree/data.bin")).expect("the mount serves"),
        CONTENTS
    );

    ground.server.kill();
    // Ride the window out, so the mount is genuinely degraded and not
    // merely stalling.
    assert!(
        fs::metadata(guest.path("tree/never-seen")).is_err(),
        "a degraded mount answers nothing"
    );
    let started = Instant::now();
    assert!(fs::metadata(guest.path("tree/never-seen-either")).is_err());
    assert!(
        started.elapsed() < IMMEDIATE,
        "the mount is not degraded yet"
    );

    ground.server.start_again();
    // A fresh walk from the mount root, and a new open through it.
    assert!(
        eventually(PATIENCE, || fs::read_dir(guest.root()).is_ok()),
        "the mount never resumed"
    );
    assert_eq!(
        fs::read(guest.path("tree/data.bin")).expect("reads again"),
        CONTENTS
    );
    let mut fresh = fs::File::open(guest.path("tree/alpha")).expect("a new open works");
    let mut contents = Vec::new();
    fresh.read_to_end(&mut contents).expect("reads");
    assert_eq!(contents, b"alpha");
    fs::write(guest.path("tree/after"), b"after").expect("writes again");
    assert_eq!(
        fs::read(ground.tree.join("after")).expect("host side"),
        b"after"
    );
}

// ---------------------------------------------------------------------------
// Criterion 5 — the configuration changed across the gap
// ---------------------------------------------------------------------------

/// A rule removed, re-targeted, downgraded or narrowed, and the namespace
/// itself deleted: each surfaces per request, and none of them wedges the
/// mount.
#[test]
fn configuration_changed_across_the_gap_surfaces_per_request() {
    let mut ground = Ground::start("config");
    let socket = ground.socket();
    let runtime = runtime();
    let client = ground.connect(&runtime, STALL);
    let caller = Caller::default();
    let root = client.root_node_id();
    runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the mount serves");

    // The graft is gone: a fresh walk says the entry does not exist — as if it
    // was rm -rf'ed.
    ground.server.kill();
    ground
        .server
        .rewrite_state(&state_file_without_the_tree(&socket));
    ground.server.start_again();
    settle(&client);
    assert_eq!(
        runtime
            .block_on(client.lookup(caller, root, b"tree"))
            .expect_err("the rule is gone"),
        Errno::NOENT
    );

    // Downgraded to read-only: the entry is back, and writing through it is
    // refused where the policy refuses it.
    ground.server.kill();
    ground
        .server
        .rewrite_state(&state_file_read_only(&ground.tree, &socket));
    ground.server.start_again();
    settle(&client);
    let tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft is back");
    let file = runtime
        .block_on(client.lookup(caller, tree.node_id, b"data.bin"))
        .expect("resolves");
    assert_eq!(
        runtime
            .block_on(client.open(caller, file.node_id, rustix::fs::OFlags::WRONLY.bits()))
            .expect_err("the graft is read-only now"),
        Errno::ROFS
    );

    // Re-targeted: the mount path is unchanged and what stands behind it is
    // not. A fresh walk finds the new target's contents, and a name that only
    // ever existed in the old one is gone — which is the whole difference
    // between this arm and the removal above.
    let elsewhere = ground.directory.directory("elsewhere");
    fs::write(elsewhere.join("moved"), b"moved").expect("a writable tree");
    ground.server.kill();
    ground
        .server
        .rewrite_state(&state_file_retargeted(&elsewhere, &socket));
    ground.server.start_again();
    settle(&client);
    let tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft still resolves");
    let moved = runtime
        .block_on(client.lookup(caller, tree.node_id, b"moved"))
        .expect("the new target's contents are what the graft shows now");
    let handle = runtime
        .block_on(client.open(caller, moved.node_id, 0))
        .expect("opens through the re-targeted graft");
    assert_eq!(
        runtime
            .block_on(client.read(caller, moved.node_id, handle, 0, 16))
            .expect("reads through the re-targeted graft"),
        b"moved"
    );
    assert_eq!(
        runtime
            .block_on(client.lookup(caller, tree.node_id, b"data.bin"))
            .expect_err("the old target is not behind this graft any more"),
        Errno::NOENT
    );

    // Children hidden by a wildcard: a name the namespace hides cannot be
    // created, because the guest would not see what it made.
    ground.server.kill();
    ground
        .server
        .rewrite_state(&state_file_hiding_children(&ground.tree, &socket));
    ground.server.start_again();
    settle(&client);
    let tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft is still there");
    assert_eq!(
        runtime
            .block_on(client.mkdir(caller, tree.node_id, b"made", 0o755, 0))
            .expect_err("the name is hidden now"),
        Errno::ACCESS
    );

    // The namespace itself is gone: the handshake is refused for configuration
    // reasons, so the mount stays degraded with the probe running instead of
    // stalling for ever or giving up.
    ground.server.kill();
    ground
        .server
        .rewrite_state(&state_file_without_the_namespace(&socket));
    ground.server.start_again();
    assert!(
        eventually(PATIENCE, || client.state() == MountState::Degraded),
        "a refused handshake should degrade the mount, not hold it"
    );
    assert_eq!(
        runtime
            .block_on(client.getattr(caller, root, None))
            .expect_err("nothing serves this mount"),
        Errno::IO
    );

    // And the configuration can come back: nothing wedged.
    ground.server.kill();
    ground
        .server
        .rewrite_state(&state_file(&ground.tree, &socket));
    ground.server.start_again();
    settle(&client);
    runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the namespace is served again");
}

// ---------------------------------------------------------------------------
// Criterion 8 — the fail-fast window
// ---------------------------------------------------------------------------

/// `--reconnect-stall 0` restores fail-fast: connection death fails the
/// outstanding operation and every subsequent one immediately.
#[test]
fn a_zero_window_fails_outstanding_and_subsequent_operations_immediately() {
    let mut ground = Ground::start("failfast");
    let runtime = runtime();
    let client = ground.connect(&runtime, Duration::ZERO);
    let caller = Caller::default();
    let root = client.root_node_id();
    runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the mount serves");

    ground.server.kill();
    let started = Instant::now();
    assert_eq!(
        runtime
            .block_on(client.getattr(caller, root, None))
            .expect_err("the server is gone"),
        Errno::IO
    );
    assert!(
        started.elapsed() < IMMEDIATE,
        "a zero window still waited {:?}",
        started.elapsed()
    );
    assert_eq!(client.state(), MountState::Degraded);

    for round in 0..5 {
        let started = Instant::now();
        assert_eq!(
            runtime
                .block_on(client.getattr(caller, root, None))
                .expect_err("still gone"),
            Errno::IO
        );
        assert!(
            started.elapsed() < IMMEDIATE,
            "request {round} waited {:?}",
            started.elapsed()
        );
    }
}

// ---------------------------------------------------------------------------
// Criterion 11 — a degraded mount is responsive, and still unmounts
// ---------------------------------------------------------------------------

/// Failures return immediately once the window has closed, and the mountpoint
/// still comes down cleanly from there.
#[test]
fn a_degraded_mount_answers_at_once_and_unmounts_cleanly() {
    if !preflight() {
        return;
    }
    let mut ground = Ground::start("degraded");
    let mut guest = ground.mount("degraded", STALL);
    assert_eq!(
        fs::read(guest.path("tree/data.bin")).expect("the mount serves"),
        CONTENTS
    );

    ground.server.kill();
    // The first request rides the window out; the rest must not.
    assert!(fs::metadata(guest.path("tree/first")).is_err());
    let started = Instant::now();
    for round in 0..8 {
        assert!(
            fs::metadata(guest.path(&format!("tree/absent-{round}"))).is_err(),
            "a degraded mount cannot answer a lookup"
        );
    }
    let waited = started.elapsed();
    assert!(
        waited < STALL,
        "eight requests on a degraded mount took {waited:?}, which is a mount that is still waiting"
    );

    guest
        .unmount()
        .expect("a degraded mount still unmounts cleanly");
}

/// The same from *inside* the window: the teardown does not wait it out.
///
/// The window here is a minute, so a teardown that waited for its server would
/// be unmistakable. Nothing is left in flight on purpose — a syscall parked in
/// the mount holds a reference to it, and the kernel would answer the unmount
/// `EBUSY` for that reason, not for anything this test is about.
#[test]
fn a_reconnecting_mount_unmounts_without_waiting_out_its_window() {
    if !preflight() {
        return;
    }
    let mut ground = Ground::start("reconnecting");
    let mut guest = ground.mount("reconnecting", Duration::from_secs(60));
    assert_eq!(
        fs::read(guest.path("tree/data.bin")).expect("the mount serves"),
        CONTENTS
    );

    let client = guest.client();
    ground.server.kill();
    assert!(
        eventually(PATIENCE, || client.state() == MountState::Reconnecting),
        "the mount never entered its stall window (it is {:?})",
        client.state()
    );

    let started = Instant::now();
    guest
        .unmount()
        .expect("a reconnecting mount unmounts without waiting for its server");
    let waited = started.elapsed();
    assert!(
        waited < Duration::from_secs(20),
        "the teardown waited {waited:?}, which means it waited out the window"
    );
    assert_eq!(client.state(), MountState::Closed);
}

/// An unmount the kernel refuses hands the recovery back, and hands back
/// exactly one.
///
/// `EBUSY` means *nothing happened*: the mountpoint is still there, the mount
/// is still ours, and the recovery the teardown cancelled on its way in is owed
/// back. The subtle half is that cancelling a task is not synchronous, so the
/// attempt the refused teardown aborted may still be running when its
/// replacement starts — and the mount must end up with one recovery it can
/// still cancel, not two of which it holds the handle to only one. Both halves
/// are observable from here: the mount reconnects after the refusal, and the
/// clean unmount that follows still ends it promptly instead of leaving a
/// dialler behind.
#[test]
fn an_unmount_the_kernel_refuses_hands_the_recovery_back() {
    if !preflight() {
        return;
    }
    let mut ground = Ground::start("ebusy");
    let mut guest = ground.mount("ebusy", Duration::from_secs(60));
    // Opened while the server is still there, so the descriptor is what makes
    // the mountpoint busy — not a syscall parked in a mount with no server.
    let held = fs::File::open(guest.path("tree/data.bin")).expect("opens before the restart");

    let client = guest.client();
    ground.server.kill();
    assert!(
        eventually(PATIENCE, || client.state() == MountState::Reconnecting),
        "the mount never entered its stall window (it is {:?})",
        client.state()
    );

    let refused = guest
        .unmount()
        .expect_err("a mountpoint with an open descriptor cannot be unmounted");
    assert_eq!(errno(&refused), Errno::BUSY.raw_os_error());
    assert_eq!(
        client.state(),
        MountState::Reconnecting,
        "a refused unmount tore something down after all"
    );

    // The recovery really is running again, and it is the mount's own.
    ground.server.start_again();
    settle(&client);
    assert_eq!(
        fs::read(guest.path("tree/data.bin")).expect("the mount serves again"),
        CONTENTS
    );

    drop(held);
    let started = Instant::now();
    guest
        .unmount_patiently()
        .expect("the mountpoint comes down once it is idle");
    assert_eq!(client.state(), MountState::Closed);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the teardown took {:?}, which is a recovery nobody could cancel",
        started.elapsed()
    );
}
