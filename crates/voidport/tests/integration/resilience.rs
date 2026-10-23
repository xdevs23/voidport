//! Every server here is a real `voidportd` process, killed with `SIGKILL` and
//! brought back on the same unix socket, because the subject is a server that
//! dies without warning, not one that shuts down politely.

use voidport_test_client as support;

use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustix::io::Errno;
use support::daemon::{
    CONTENTS, Ground, PATIENCE, accepts, eventually, reconnected_after, runtime, state_file,
    state_file_hiding_children, state_file_read_only, state_file_retargeted,
    state_file_without_the_namespace, state_file_without_the_tree, state_is,
};
use support::relay::{Cut, Latch, Relay};
use support::{errno, preflight};
use voidport::client::{Caller, MountState, Origin};
use voidport::mount::{MountOptions, TeardownError};
use voidport_proto::opcode::Opcode;
use voidport_spawn::{Program, Stream};

/// Shorter than the shipped default so a test that deliberately waits it out
/// takes two seconds.
const STALL: Duration = Duration::from_secs(2);

/// It covers scheduling and one backoff step, not a second window: an assertion
/// that passed at twice the deadline would not be testing the deadline.
const SLACK: Duration = Duration::from_millis(1500);

/// A degraded mount answers without touching the network, so this is scheduling
/// noise.
const IMMEDIATE: Duration = Duration::from_millis(500);

/// Walks, opens by path, creates and statfs are carried by the `ESTALE`-retry
/// healing of the kernel: the mount root is node id 1 in every session, so a
/// re-walk from the root rebuilds any depth of path. Reads and writes on a
/// descriptor opened before the restart cannot be: the server ids are
/// generation-disjoint, so the handle names nothing and says so.
#[test]
fn a_restart_inside_the_window_heals_paths_and_stales_open_descriptors() {
    preflight();
    let mut ground = Ground::start("heal");
    // The window spans as long as a server is given to come up, so the
    // restart below completes inside it on a machine of any speed.
    let guest = ground.mount("heal", PATIENCE);

    // It is opened for writing too, because a write cannot be answered from a
    // cache.
    let mut held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(guest.path("tree/data.bin"))
        .expect("opens before the restart");
    let mut before = Vec::new();
    held.read_to_end(&mut before).expect("reads before");
    assert_eq!(before, CONTENTS);

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
    // Waiting for the mount to notice makes the creates below provably queued:
    // a request issued into a connection the mount still believes in could be
    // written before the socket reports its death, and a written mutation is a
    // not sent again, unlike a request that was only queued.
    let client = guest.client();
    assert!(
        eventually(PATIENCE, || client.state() != MountState::Connected),
        "the mount never noticed its server had gone"
    );

    // Creates issued while the server is down are queued: they never reached a
    // socket, so they are sent as they are once the handshake is back.
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

    // The write is the deterministic one: the mount is writethrough, so every
    // write reaches the server, where the handle of the dead session names
    // nothing.
    let refused = held
        .write_all(b"!")
        .expect_err("a descriptor cannot survive its session");
    assert!(
        stale(&refused),
        "a write through the dead session's handle should report the loss: {refused}"
    );
    // The read is the same loss, arriving when the cache of the guest stops
    // answering: within the attribute TTL the kernel may serve the pages it
    // already has, and the revalidation after it asks the server about a node
    // that is gone.
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
    assert_eq!(
        fs::read(guest.path("tree/data.bin")).expect("reopening works"),
        CONTENTS
    );
}

/// `ESTALE` for a node, `EBADF` for a handle, and never `EIO`: that would be
/// the mount failing to serve, not the server answering honestly.
fn stale(error: &std::io::Error) -> bool {
    let code = errno(error);
    code == Errno::STALE.raw_os_error() || code == Errno::BADF.raw_os_error()
}

/// Path resolution (a stat, an open by path and a statfs) starts at the mount
/// root, which is node id 1 in every session, so the `ESTALE` retry of the
/// kernel re-walks it and none of these may ever surface an error. Content
/// through a descriptor the operation opened for itself (a read and a listing)
/// may fail when an open arrives just before the gap and its read after it, but
/// only with the plain stale errno, never with `EIO`.
///
/// Violations are collected instead of asserted so that the test can report all
/// of them at once.
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

/// The measurement runs from the kill, not from the request, because the
/// deadline is the one of the mount: a request that arrives late in the window
/// inherits what is left of it.
#[test]
fn a_server_absent_past_the_window_fails_at_its_edge_and_then_immediately() {
    let mut ground = Ground::start("window");
    let runtime = runtime();
    let client = ground.connect(&runtime, STALL);
    let origin = Origin::default();
    let root = client.root_node_id();
    runtime
        .block_on(client.lookup(origin, root, b"tree"))
        .expect("the mount serves");

    let killed = Instant::now();
    ground.server.kill();
    let stalled = runtime
        .block_on(client.getattr(origin, root, None))
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

    for round in 0..5 {
        let started = Instant::now();
        assert_eq!(
            runtime
                .block_on(client.getattr(origin, root, None))
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

/// The relay ends the one connection of the session and forwards the hello of
/// the reconnect only once the stalled caller has its result, so that hello
/// provably completes after the deadline of the caller: the caller is owed its
/// `EIO` at the edge, and the mount is owed its return to Connected once the
/// hello goes through.
///
/// The remaining half, a hello and the timer coming ready in the same poll,
/// is a sub-millisecond scheduling race that cannot be constructed from
/// outside. It is held by the two clock reads in the client: the stalled caller
/// reads `Instant::now()` after its wait and before it looks at the phase, and
/// the probe records the crossing before it installs.
#[test]
fn a_handshake_completing_past_the_deadline_does_not_serve_the_window_it_missed() {
    let ground = Ground::start("late-hello");
    let runtime = runtime();
    let relay = Relay::start(&ground.socket());
    let client = ground.connect_to(&runtime, &relay.endpoint(), STALL);
    let origin = Origin::default();
    let root = client.root_node_id();
    runtime
        .block_on(client.lookup(origin, root, b"tree"))
        .expect("the mount serves");
    assert_eq!(
        client.connections().expect("a session").pooled,
        1,
        "the session has only the connection that sent its hello"
    );

    let latch = Latch::default();
    let held = relay.arm(Opcode::Hello, Cut::HoldRequest(latch.clone()));
    reconnected_after(&client, || {
        let lost = Instant::now();
        relay.end_carriers(Opcode::Hello);
        held.recv().expect("the reconnect sends a hello");
        let stalled = runtime
            .block_on(client.getattr(origin, root, None))
            .expect_err("the window closed before the held hello went through");
        let waited = lost.elapsed();
        assert_eq!(stalled, Errno::IO);
        assert!(
            waited >= STALL,
            "the request gave up after {waited:?}, before the {STALL:?} window closed"
        );
        latch.release();
    });
    runtime
        .block_on(client.lookup(origin, root, b"tree"))
        .expect("the mount serves again");
}

/// Without a bound over the whole attempt (dial, hello write, hello read), a
/// wedged listener keeps the stalled callers waiting for as long as it likes.
#[test]
fn a_wedged_peer_does_not_hold_the_mount_past_the_deadline() {
    let mut ground = Ground::start("wedged");
    let runtime = runtime();
    let client = ground.connect(&runtime, STALL);
    let origin = Origin::default();
    let root = client.root_node_id();
    runtime
        .block_on(client.lookup(origin, root, b"tree"))
        .expect("the mount serves");

    let killed = Instant::now();
    ground.server.kill();
    let socket = ground.socket();
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("the socket path is free");
    let wedged = Arc::new(AtomicBool::new(false));
    let accepted = Arc::clone(&wedged);
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            accepted.store(true, Ordering::Relaxed);
            held.push(stream);
        }
    });
    assert!(
        eventually(PATIENCE, || accepts(&socket)),
        "the wedged listener never came up"
    );

    let stalled = runtime
        .block_on(client.getattr(origin, root, None))
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

#[test]
fn a_server_returning_after_degradation_resumes_without_a_remount() {
    preflight();
    let mut ground = Ground::start("returns");
    let guest = ground.mount("returns", STALL);
    assert_eq!(
        fs::read(guest.path("tree/data.bin")).expect("the mount serves"),
        CONTENTS
    );

    ground.server.kill();
    // Wait out the window, so the mount is degraded and not merely stalling.
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

#[test]
fn configuration_changed_across_the_gap_surfaces_per_request() {
    let mut ground = Ground::start("config");
    let socket = ground.socket();
    let runtime = runtime();
    let client = ground.connect(&runtime, STALL);
    let caller = Caller::default();
    let origin = Origin::default();
    let root = client.root_node_id();
    runtime
        .block_on(client.lookup(origin, root, b"tree"))
        .expect("the mount serves");

    reconnected_after(&client, || {
        ground.server.kill();
        ground
            .server
            .rewrite_state(&state_file_without_the_tree(&socket));
        ground.server.start_again();
    });
    assert_eq!(
        runtime
            .block_on(client.lookup(origin, root, b"tree"))
            .expect_err("the rule is gone"),
        Errno::NOENT
    );

    reconnected_after(&client, || {
        ground.server.kill();
        ground
            .server
            .rewrite_state(&state_file_read_only(&ground.tree, &socket));
        ground.server.start_again();
    });
    let tree = runtime
        .block_on(client.lookup(origin, root, b"tree"))
        .expect("the graft is back");
    let file = runtime
        .block_on(client.lookup(origin, tree.node_id, b"data.bin"))
        .expect("resolves");
    assert_eq!(
        runtime
            .block_on(client.open(origin, file.node_id, rustix::fs::OFlags::WRONLY.bits()))
            .expect_err("the graft is read-only now"),
        Errno::ROFS
    );

    // Re-targeted: the mount path is unchanged and what stands behind it is
    // not. A name that only existed in the old target is gone.
    let elsewhere = ground.directory.directory("elsewhere");
    fs::write(elsewhere.join("moved"), b"moved").expect("a writable tree");
    reconnected_after(&client, || {
        ground.server.kill();
        ground
            .server
            .rewrite_state(&state_file_retargeted(&elsewhere, &socket));
        ground.server.start_again();
    });
    let tree = runtime
        .block_on(client.lookup(origin, root, b"tree"))
        .expect("the graft still resolves");
    let moved = runtime
        .block_on(client.lookup(origin, tree.node_id, b"moved"))
        .expect("the new target's contents are what the graft shows now");
    let handle = runtime
        .block_on(client.open(origin, moved.node_id, 0))
        .expect("opens through the re-targeted graft");
    assert_eq!(
        runtime
            .block_on(support::read(&client, caller, moved.node_id, handle, 0, 16))
            .expect("reads through the re-targeted graft"),
        b"moved"
    );
    assert_eq!(
        runtime
            .block_on(client.lookup(origin, tree.node_id, b"data.bin"))
            .expect_err("the old target is not behind this graft any more"),
        Errno::NOENT
    );

    // A name the namespace hides cannot be created, because the guest would not
    // see what it made.
    reconnected_after(&client, || {
        ground.server.kill();
        ground
            .server
            .rewrite_state(&state_file_hiding_children(&ground.tree, &socket));
        ground.server.start_again();
    });
    let tree = runtime
        .block_on(client.lookup(origin, root, b"tree"))
        .expect("the graft is still there");
    assert_eq!(
        runtime
            .block_on(client.mkdir(origin, tree.node_id, b"made", 0o755, 0))
            .expect_err("the name is hidden now"),
        Errno::ACCESS
    );

    // The handshake is refused for configuration reasons, so the mount stays
    // degraded with the probe running instead of stalling for ever or giving
    // up.
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
            .block_on(client.getattr(origin, root, None))
            .expect_err("nothing serves this mount"),
        Errno::IO
    );

    ground.server.kill();
    ground
        .server
        .rewrite_state(&state_file(&ground.tree, &socket));
    ground.server.start_again();
    state_is(&client, |state| state == MountState::Connected);
    runtime
        .block_on(client.lookup(origin, root, b"tree"))
        .expect("the namespace is served again");
}

#[test]
fn a_zero_window_fails_outstanding_and_subsequent_operations_immediately() {
    let mut ground = Ground::start("failfast");
    let runtime = runtime();
    let client = ground.connect(&runtime, Duration::ZERO);
    let origin = Origin::default();
    let root = client.root_node_id();
    runtime
        .block_on(client.lookup(origin, root, b"tree"))
        .expect("the mount serves");

    ground.server.kill();
    let started = Instant::now();
    assert_eq!(
        runtime
            .block_on(client.getattr(origin, root, None))
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
                .block_on(client.getattr(origin, root, None))
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

#[test]
fn a_degraded_mount_answers_at_once_and_unmounts_cleanly() {
    preflight();
    let mut ground = Ground::start("degraded");
    let mut guest = ground.mount("degraded", STALL);
    assert_eq!(
        fs::read(guest.path("tree/data.bin")).expect("the mount serves"),
        CONTENTS
    );

    ground.server.kill();
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

/// The window here is a minute, so a teardown that waited for its server would
/// be unmistakable. Nothing is left in flight on purpose: a syscall parked in
/// the mount holds a reference to it, and the kernel would answer the unmount
/// `EBUSY` for that reason.
#[test]
fn a_reconnecting_mount_unmounts_without_waiting_out_its_window() {
    preflight();
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

/// A child started with a copy of the descriptor table of the process closes
/// its copy of the file in its `execve`, which sends a flush that the stalled
/// mount answers only once its window has passed: the new server and mounts
/// would come up only then, and the stalled mount would be busy until then.
/// The window here is a minute, so the stalled mount is still reconnecting
/// once the new ones are up.
#[test]
fn a_mount_comes_up_while_another_mount_of_the_process_stalls_with_a_file_open() {
    preflight();
    let mut stalled = Ground::start("stalled");
    let other = Ground::start("other");
    let guest = stalled.mount("stalled", Duration::from_secs(60));
    let held = fs::File::open(guest.path("tree/data.bin")).expect("opens while the server serves");

    let client = guest.client();
    stalled.server.kill();
    assert!(
        eventually(PATIENCE, || client.state() == MountState::Reconnecting),
        "the mount never entered its stall window (it is {:?})",
        client.state()
    );

    let _other = other.mount("other", STALL);
    let late = Ground::start("late");
    let _late = late.mount_with(
        "late",
        &MountOptions {
            allow_other: true,
            reconnect_stall: STALL,
            ..MountOptions::default()
        },
    );
    assert_eq!(
        client.state(),
        MountState::Reconnecting,
        "the other server and mounts came up only once the window of the stalled mount had passed"
    );

    stalled.server.start_again();
    state_is(&client, |state| state == MountState::Connected);
    drop(held);
}

/// The helper finds its end of the socket by number, so the end has to be open
/// in the helper without close-on-exec. Clearing that flag in the descriptor
/// table of the process hands the socket for good to every child started from
/// that table until the helper runs, and the `execve` of a helper started from
/// that table waits for the flush of the file held open on the stalled mount.
/// The window here is a minute, and the server comes back once both children
/// have started.
#[test]
fn a_child_started_while_the_fusermount_helper_starts_gets_no_copy_of_its_socket() {
    preflight();
    let helper = voidport_fuse::fusermount().expect("the fusermount3 helper is installed");
    let mut stalled = Ground::start("stalled-helper");
    let guest = stalled.mount("stalled", Duration::from_secs(60));
    let held = fs::File::open(guest.path("tree/data.bin")).expect("opens while the server serves");

    let client = guest.client();
    stalled.server.kill();
    assert!(
        eventually(PATIENCE, || client.state() == MountState::Reconnecting),
        "the mount never entered its stall window (it is {:?})",
        client.state()
    );

    let mountpoint = stalled.directory.directory("mnt-helper");
    let options = voidport_fuse::MountOptions {
        source: voidport_fuse::MountSource::new("voidport-helper").expect("a plain source"),
        default_permissions: false,
        allow_other: true,
        read_only: false,
        auto_unmount: Some(helper),
    };
    let mounting = std::thread::spawn(move || {
        voidport_fuse::Session::mount(&mountpoint, &options, |_| Ok(()))
    });
    let bystander = std::thread::spawn(|| {
        Program::new("cat")
            .stdin(Stream::Piped)
            .spawn()
            .expect("cat starts")
    });
    let session = mounting
        .join()
        .expect("the mounting thread returns")
        .expect("mounts through the helper");
    let mut bystander = bystander.join().expect("the thread returns");
    assert_eq!(
        client.state(),
        MountState::Reconnecting,
        "the children started only once the window of the stalled mount had passed"
    );

    stalled.server.start_again();
    state_is(&client, |state| state == MountState::Connected);
    let sockets = sockets_of(bystander.id());
    drop(bystander.stdin.take());
    let _ended = bystander.wait().expect("cat ends");
    drop(session);
    drop(held);
    assert!(
        sockets.is_empty(),
        "the child started meanwhile has the sockets {sockets:?}"
    );
}

fn sockets_of(pid: u32) -> Vec<PathBuf> {
    fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("the descriptors of the process are listed")
        .map(|entry| fs::read_link(entry.expect("an entry").path()).expect("a descriptor"))
        .filter(|target| target.to_string_lossy().starts_with("socket:"))
        .collect()
}

/// `EBUSY` means nothing happened: the mountpoint is still there, the mount is
/// still ours, and the recovery cancelled by the teardown is owed back.
/// Cancelling a task is not synchronous, so the attempt aborted by the failed
/// teardown may still run when its replacement starts, and the mount must end
/// up with one recovery it can still cancel. The mount reconnects after the
/// failure, and the clean unmount that follows still ends it promptly.
#[test]
fn an_unmount_the_kernel_refuses_hands_the_recovery_back() {
    preflight();
    let mut ground = Ground::start("ebusy");
    let mut guest = ground.mount("ebusy", Duration::from_secs(60));
    // Opened while the server is still there, so that the descriptor makes the
    // mountpoint busy, and no syscall parked in a mount without a server does.
    let held = fs::File::open(guest.path("tree/data.bin")).expect("opens before the restart");

    let client = guest.client();
    ground.server.kill();
    assert!(
        eventually(PATIENCE, || client.state() == MountState::Reconnecting),
        "the mount never entered its stall window (it is {:?})",
        client.state()
    );

    let TeardownError::Unmount(refused) = guest
        .unmount()
        .expect_err("a mountpoint with an open descriptor cannot be unmounted")
    else {
        panic!("the kernel is what rejects the unmount");
    };
    assert_eq!(errno(&refused), Errno::BUSY.raw_os_error());
    assert_eq!(
        client.state(),
        MountState::Reconnecting,
        "a refused unmount tore something down after all"
    );

    ground.server.start_again();
    state_is(&client, |state| state == MountState::Connected);
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
