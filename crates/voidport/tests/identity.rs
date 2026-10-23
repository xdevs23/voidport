//! Runs at the client level, without a FUSE mount: the claim is about ids on
//! the wire, and a mount would let the kernel's caching decide which of them
//! were still in play.

#![forbid(unsafe_code)]

use voidport_test_client as support;

use std::collections::HashSet;
use std::fs;
use std::time::Duration;

use rustix::fs::OFlags;
use rustix::io::Errno;
use support::daemon::{Ground, runtime, settle};
use voidport::client::{Caller, Interrupt, Lock, LockKind, MountState};

const STALL: Duration = Duration::from_secs(30);

/// Session one resolves `alpha` first, session two (after a real restart)
/// resolves `beta` first. With per-session counters both take the same first
/// id, and the old id would return `beta`. With generation-disjoint ids the old
/// id names nothing and the answer is a plain `ESTALE`.
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

    let fresh_tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft resolves again");
    let beta = runtime
        .block_on(client.lookup(caller, fresh_tree.node_id, b"beta"))
        .expect("beta resolves");
    // Distinguished by contents, not by inos: inos are not stable across server
    // restarts, so the first file each lifetime resolves gets the same number.
    assert_ne!(
        alpha.attr.size.get(),
        beta.attr.size.get(),
        "the two files must be distinguishable, or this proves nothing"
    );

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

    assert_eq!(client.state(), MountState::Connected);
    runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the session survives an answer about a stale id");
}

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
                .block_on(support::read(&client, caller, live_node, *handle, 0, 16))
                .expect_err("a dead session's handle"),
            Errno::BADF
        );
    }
    assert_eq!(client.state(), MountState::Connected);

    runtime
        .block_on(client.getattr(caller, root, None))
        .expect("the mount root is the one id every session shares");
}

/// The handle died with its session, so the server answers `EBADF`.
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
        .block_on(client.setlk(
            caller,
            &Interrupt::none(),
            alpha.node_id,
            handle,
            exclusive,
            false,
        ))
        .expect("the range is free");

    ground.server.restart();
    settle(&client);

    assert_eq!(
        runtime
            .block_on(client.getlk(caller, &Interrupt::none(), alpha.node_id, handle, exclusive))
            .expect_err("the handle died with the session"),
        Errno::BADF
    );
    assert_eq!(
        runtime
            .block_on(client.setlk(
                caller,
                &Interrupt::none(),
                alpha.node_id,
                handle,
                exclusive,
                false
            ))
            .expect_err("the handle died with the session"),
        Errno::BADF
    );

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
        .block_on(client.setlk(
            caller,
            &Interrupt::none(),
            alpha.node_id,
            reopened,
            exclusive,
            false,
        ))
        .expect("the lock is free again, because it died with its server");

    assert_eq!(
        runtime
            .block_on(support::read(
                &client,
                caller,
                alpha.node_id,
                reopened,
                0,
                16
            ))
            .expect("reads"),
        fs::read(ground.tree.join("alpha")).expect("host side")
    );
}
