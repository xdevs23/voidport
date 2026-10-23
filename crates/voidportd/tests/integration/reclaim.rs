//! Checks the ownership ledger, not resident memory, which is allocator and
//! host telemetry.

#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::fs::File;
use std::path::Path;

use rustix::fs::OFlags;
use support::Dial;
use support::fixture::Fixture;
use support::wire::{ROOT, WireClient};
use voidport_control::{Reply, Request};
use voidport_test_support::create_directory;

const ENTRIES: usize = 60_000;
const BUDGET_SETTING: &str = "node_descriptor_budget = 4096\n";

fn populate(directory: &Path, count: usize) {
    create_directory(directory);
    for index in 0..count {
        File::create(directory.join(format!("entry-{index:06}"))).expect("writable");
    }
}

fn walk(client: &mut WireClient, directory: u64) -> Vec<u64> {
    let handle = client
        .open(directory, OFlags::RDONLY)
        .expect("the directory opens");
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

fn nodes(fixture: &Fixture) -> usize {
    let Reply::SessionList { sessions } =
        fixture.server.connect().expect_ok(&Request::SessionList {})
    else {
        panic!("expected a session list");
    };
    sessions.iter().map(|session| session.nodes).sum()
}

#[test]
fn forgetting_a_large_table_releases_every_node() {
    let fixture = Fixture::start_with("reclaim-walk", BUDGET_SETTING);
    populate(&fixture.tree("walk"), ENTRIES);
    let mut client = fixture.server.mount("plain", "/tree");
    let directory = client.lookup(ROOT, "walk").expect("the directory resolves");
    let ids = walk(&mut client, directory.node_id);
    assert_eq!(ids.len(), ENTRIES, "the walk resolved every name");
    assert_eq!(nodes(&fixture), ENTRIES + 2);

    for id in ids {
        client.forget(id, 1);
    }
    client.forget(directory.node_id, 1);
    client.fence();
    assert_eq!(nodes(&fixture), 1, "every admitted lookup was returned");
    client.disconnect(&fixture.server);
    assert_eq!(nodes(&fixture), 0, "teardown returned the mount root");
}
