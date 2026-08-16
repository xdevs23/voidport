//! Ids across a restart, and the locks that die with a session.
//!
//! Reconnect-increment criteria **4 and 7**. The subject is the blocker the
//! spec review demonstrated end to end: with per-session id counters, an id the
//! kernel still holds after a restart is handed out again by the new session
//! and silently names a **different file**, so a read through it returns the
//! wrong bytes with no error anywhere. The fix is that the server's node and
//! handle ids are generation-disjoint across sessions and across restarts, with
//! node id 1 — the mount root — the single eternal exemption.
//!
//! These run at the client level, without a FUSE mount, because the claim is
//! about *ids on the wire*: a mount would only let the kernel's caching decide
//! which of them were still in play.

mod support;

use std::collections::HashSet;
use std::fs;
use std::time::Duration;

use rustix::fs::OFlags;
use rustix::io::Errno;
use support::daemon::{Ground, runtime, settle};
use voidport::client::{Caller, Lock, LockKind, MountState};

/// The window these tests run with.
///
/// Generous on purpose: nothing here is measuring the window, and a mount that
/// degraded mid-test would only make the assertions about ids harder to read.
const STALL: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Criterion 4 — id disjointness
// ---------------------------------------------------------------------------

/// The spec review's reproduction, as a regression test.
///
/// Session one resolves `alpha` first, so `alpha` takes the first id the
/// session hands out. Session two — the same client, after a real restart —
/// resolves `beta` first, so *it* takes the first id of its session. With
/// per-session counters those are the same number, and asking the new session
/// about the old id returns `beta`: a wrong-file read, silently. With
/// generation-disjoint ids the old id names nothing, and the answer is a plain
/// `ESTALE` on a connection that carries on serving.
#[test]
fn a_stale_node_id_never_aliases_another_file() {
    let mut ground = Ground::start("aliasing");
    let runtime = runtime();
    let client = ground.connect(&runtime, STALL);
    let caller = Caller::default();
    let root = client.root_node_id();

    let tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft resolves");
    let alpha = runtime
        .block_on(client.lookup(caller, tree.node_id, b"alpha"))
        .expect("alpha resolves");

    ground.server.restart();
    settle(&client);

    // The new session resolves `beta` first, so a per-session counter would
    // give it exactly the numbers the old session gave `tree` and `alpha`.
    let fresh_tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft resolves again");
    let beta = runtime
        .block_on(client.lookup(caller, fresh_tree.node_id, b"beta"))
        .expect("beta resolves");
    // Distinguished by their contents, not by their inos: the synthetic ino
    // space is per server lifetime by design ("inos are not stable across
    // server restarts"), so the first file each lifetime resolves legitimately
    // gets the same number. Sizes cross a restart because the host files do.
    assert_ne!(
        alpha.attr.size.get(),
        beta.attr.size.get(),
        "the two files must be distinguishable, or this proves nothing"
    );

    // The old id is not the new one, and it names nothing.
    assert_ne!(
        alpha.node_id, beta.node_id,
        "the new session reused the id the old session gave another file"
    );
    assert_ne!(tree.node_id, fresh_tree.node_id, "and so did the directory");
    assert_eq!(
        runtime
            .block_on(client.getattr(caller, alpha.node_id, None))
            .expect_err("the old node id belongs to a dead session"),
        Errno::STALE
    );

    // A plain errno, not a framing violation: the connection is still serving.
    assert_eq!(client.state(), MountState::Connected);
    runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the session survives an answer about a stale id");
}

/// No node or handle id from the old session is accepted by the new one, and
/// every rejection is an ordinary errno.
#[test]
fn no_id_from_the_old_session_is_accepted_by_the_new_one() {
    let mut ground = Ground::start("disjoint");
    let runtime = runtime();
    let client = ground.connect(&runtime, STALL);
    let caller = Caller::default();
    let root = client.root_node_id();

    let tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft resolves");
    let mut old_nodes = HashSet::new();
    let mut old_handles = HashSet::new();
    for name in [&b"alpha"[..], b"beta"] {
        let entry = runtime
            .block_on(client.lookup(caller, tree.node_id, name))
            .expect("resolves");
        old_nodes.insert(entry.node_id);
        old_handles.insert(
            runtime
                .block_on(client.open(caller, entry.node_id, OFlags::RDONLY.bits()))
                .expect("opens"),
        );
    }
    old_nodes.insert(tree.node_id);

    ground.server.restart();
    settle(&client);

    let fresh_tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft resolves again");
    let mut fresh_handles = Vec::new();
    for name in [&b"alpha"[..], b"beta"] {
        let entry = runtime
            .block_on(client.lookup(caller, fresh_tree.node_id, name))
            .expect("resolves");
        assert!(
            !old_nodes.contains(&entry.node_id),
            "node id {} was handed out by both sessions",
            entry.node_id
        );
        let handle = runtime
            .block_on(client.open(caller, entry.node_id, OFlags::RDONLY.bits()))
            .expect("opens");
        assert!(
            !old_handles.contains(&handle),
            "handle {handle} was handed out by both sessions"
        );
        fresh_handles.push((entry.node_id, handle));
    }
    assert!(
        !old_nodes.contains(&fresh_tree.node_id),
        "the directory's node id was handed out by both sessions"
    );

    // Every old id answers with its own plain errno — a node is stale, a handle
    // is bad — and none of them closes the connection.
    for node_id in &old_nodes {
        assert_eq!(
            runtime
                .block_on(client.getattr(caller, *node_id, None))
                .expect_err("a dead session's node"),
            Errno::STALE
        );
    }
    let (live_node, _) = fresh_handles[0];
    for handle in &old_handles {
        assert_eq!(
            runtime
                .block_on(client.read(caller, live_node, *handle, 0, 16))
                .expect_err("a dead session's handle"),
            Errno::BADF
        );
    }
    assert_eq!(client.state(), MountState::Connected);

    // The mount root is the exemption, and it still works.
    runtime
        .block_on(client.getattr(caller, root, None))
        .expect("the mount root is the one id every session shares");
}

// ---------------------------------------------------------------------------
// Criterion 7 — locks do not survive the server
// ---------------------------------------------------------------------------

/// A lock held across the gap surfaces its loss on the next lock-dependent
/// operation through the old handle, and re-acquiring through a reopened handle
/// succeeds.
///
/// No client memory is involved: the handle died with its session, so the
/// server answers `EBADF` and the application does what it would do for any
/// closed descriptor.
#[test]
fn a_lock_lost_with_its_server_surfaces_as_ebadf_and_is_reacquirable() {
    let mut ground = Ground::start("locks");
    let runtime = runtime();
    let client = ground.connect(&runtime, STALL);
    let caller = Caller::default();
    let root = client.root_node_id();
    let owner = 0x5ba7_efc0;

    let tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft resolves");
    let alpha = runtime
        .block_on(client.lookup(caller, tree.node_id, b"alpha"))
        .expect("alpha resolves");
    let handle = runtime
        .block_on(client.open(caller, alpha.node_id, OFlags::RDWR.bits()))
        .expect("opens");
    let exclusive = Lock {
        start: 0,
        end: u64::MAX,
        owner,
        pid: 0,
        kind: LockKind::Write,
    };
    runtime
        .block_on(client.setlk(caller, alpha.node_id, handle, exclusive, false))
        .expect("the range is free");

    ground.server.restart();
    settle(&client);

    // The loss surfaces on the next lock-dependent operation through the old
    // handle, and on nothing before it.
    assert_eq!(
        runtime
            .block_on(client.getlk(caller, alpha.node_id, handle, exclusive))
            .expect_err("the handle died with the session"),
        Errno::BADF
    );
    assert_eq!(
        runtime
            .block_on(client.setlk(caller, alpha.node_id, handle, exclusive, false))
            .expect_err("the handle died with the session"),
        Errno::BADF
    );

    // Re-acquisition through a reopened handle is all it takes.
    let tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft resolves again");
    let alpha = runtime
        .block_on(client.lookup(caller, tree.node_id, b"alpha"))
        .expect("alpha resolves again");
    let reopened = runtime
        .block_on(client.open(caller, alpha.node_id, OFlags::RDWR.bits()))
        .expect("reopens");
    runtime
        .block_on(client.setlk(caller, alpha.node_id, reopened, exclusive, false))
        .expect("the lock is free again, because it died with its server");

    // And the file behind it is still the file it was.
    assert_eq!(
        runtime
            .block_on(client.read(caller, alpha.node_id, reopened, 0, 16))
            .expect("reads"),
        fs::read(ground.tree.join("alpha")).expect("host side")
    );
}
