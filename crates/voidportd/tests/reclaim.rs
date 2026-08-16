//! What the host gets back when the guest forgets.
//!
//! Measured at scale on 2026-08-15: a walk of 800 809 names grew the server to
//! ~1.4 GiB, a guest `drop_caches` drained the session to one node within five
//! seconds — every pin closed, every entry freed — and the host got **none** of
//! the memory back, then or after the unmount. The entries were freed; glibc
//! kept them. This suite is the regression for the other half of that
//! lifecycle: a table that drains has to shrink the process, not just the
//! table.
//!
//! It runs against a real server over a real socket, and the server runs in the
//! test's own process — which is what makes `/proc/self/status` the server's
//! own RSS. The scale is chosen for a suite, not for a source tree: tens
//! of thousands of entries is enough to put an order of magnitude more memory
//! behind the walk than the noise of a running test process, and the
//! full-scale numbers live in `docs/PERFORMANCE.md`.

mod support;

use std::fs::File;
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

use support::fixture::Fixture;
use support::wire::{ROOT, WireClient};
use voidport_control::{Reply, Request};
use voidportd::testing::create_directory;

/// How many names the walk resolves.
///
/// At the measured 1.4-1.8 KiB of RSS per entry this is ~100 MiB of table,
/// which is two orders of magnitude above the sampling noise of the test
/// process around it and still a few seconds of work.
const ENTRIES: usize = 60_000;

/// The descriptor budget the server runs under.
///
/// Small on purpose: this suite is about the memory of the *table entries*, not
/// about the descriptors they cache, and a walk that leaves 60 000 descriptors
/// open would be measuring the kernel's slab as well as the server's heap.
const BUDGET_SETTING: &str = "node_descriptor_budget = 4096\n";

/// How long the drain and the reclaim are given.
///
/// Generous on purpose: the memory comes back in two stages, and the second
/// one waits for the request pool to retire the threads whose per-thread
/// caches hold the last of it. Nothing here polls less often for being given
/// longer — the timeout only decides how a broken build fails.
const PATIENCE: Duration = Duration::from_secs(90);

/// This process's resident set, in KiB — which is the server's, because the
/// server runs in it.
fn rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("this process has a status");
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.trim().trim_end_matches(" kB").parse().ok())
        .expect("VmRSS is reported on Linux")
}

/// Builds a directory of `count` empty files.
fn populate(directory: &Path, count: usize) {
    create_directory(directory);
    for index in 0..count {
        File::create(directory.join(format!("entry-{index:06}"))).expect("writable");
    }
}

/// Every node id in a directory, resolved the way a walking guest resolves
/// them: readdirplus, which returns an entry reply — and therefore a lookup
/// count the client owes a forget for — per name.
///
/// Only the ids are kept. The entries themselves are dropped batch by batch, so
/// the memory this test measures is the server's table and not the client's
/// copy of the listing.
fn walk(client: &mut WireClient, directory: u64) -> Vec<u64> {
    let handle = client.open(directory, 0).expect("the directory opens");
    let mut ids = Vec::new();
    let mut cookie = 0;
    loop {
        let batch = client
            .readdirplus(directory, handle, cookie, 64 * 1024)
            .expect("the listing continues");
        let Some(last) = batch.last() else {
            break;
        };
        cookie = last.next_cookie;
        ids.extend(batch.iter().map(|entry| entry.entry.node_id));
    }
    client.release(handle).expect("the handle releases");
    ids
}

/// How many nodes the server's sessions hold between them.
fn nodes(fixture: &Fixture) -> usize {
    let Reply::SessionList { sessions } =
        fixture.server.connect().expect_ok(&Request::SessionList {})
    else {
        panic!("expected a session list");
    };
    sessions.iter().map(|session| session.nodes).sum()
}

/// Polls until `condition` holds, or gives up after [`PATIENCE`] and says what
/// it last saw.
fn until(what: &str, mut condition: impl FnMut() -> Option<String>) {
    let deadline = Instant::now() + PATIENCE;
    let mut last = String::new();
    while Instant::now() < deadline {
        match condition() {
            None => return,
            Some(seen) => last = seen,
        }
        sleep(Duration::from_millis(100));
    }
    panic!("{what} did not happen within {PATIENCE:?}; last seen: {last}");
}

/// A walk grows the server, and forgetting it shrinks the **process** — not
/// only the table.
///
/// The shape is the field's: resolve every name, then forget every one of them
/// as a guest kernel under memory pressure does, and watch the host's memory.
/// The bar is deliberately generous against the ~95% the mechanism returns on
/// the measurement rig, because RSS is a whole process and a test is not a
/// controlled room: what the assertion is defending is the difference between
/// *most of it comes back* and *none of it does*, which is what was measured
/// before this landed.
#[test]
fn forgetting_a_large_table_returns_its_memory_to_the_host() {
    let fixture = Fixture::start_with("reclaim-walk", BUDGET_SETTING);
    populate(&fixture.tree("walk"), ENTRIES);
    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client.hello("plain", "/tree").expect("the mount resolves");
    let directory = client.lookup(ROOT, "walk").expect("the directory resolves");

    let before = rss_kib();
    let ids = walk(&mut client, directory.node_id);
    assert_eq!(ids.len(), ENTRIES, "the walk resolved every name");
    let walked = rss_kib();
    let growth = walked.saturating_sub(before);
    assert!(
        growth > 16 * 1024,
        "a {ENTRIES}-entry table should cost tens of MiB, not {growth} KiB"
    );

    // The drain, as a guest sends it: one forget per node, no replies to wait
    // on — so the table itself is what says when it is done. Paced, because a
    // guest's forget queue is bounded and an unbounded flood would measure the
    // burst this test can produce as much as the table it drains.
    for (index, id) in ids.iter().enumerate() {
        client.forget(*id, 1);
        if index % 1024 == 1023 {
            client.getattr(ROOT).expect("the root keeps answering");
        }
    }
    client.forget(directory.node_id, 1);
    until("the table drains", || {
        let held = nodes(&fixture);
        (held > 1).then(|| format!("{held} nodes"))
    });

    // And now the half the field never got: the process gives the memory back.
    until("the memory comes back", || {
        let returned = walked.saturating_sub(rss_kib());
        (returned * 2 < growth).then(|| {
            format!(
                "{returned} KiB of {growth} KiB returned (RSS {} KiB)",
                rss_kib()
            )
        })
    });

    let settled = rss_kib();
    let returned = walked.saturating_sub(settled);
    println!(
        "entries={ENTRIES} rss_before={before} rss_walked={walked} rss_settled={settled} \
         growth={growth} returned={returned} ({}%)",
        returned * 100 / growth.max(1)
    );
}
