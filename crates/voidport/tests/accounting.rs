//! Runs the directory path of the client directly, with a sink of the test:
//! once `FUSE_DO_READDIRPLUS` is negotiated the kernel never issues a plain
//! `readdir`, so the compensating forgets of that path cannot be reached
//! through a mount.

#![forbid(unsafe_code)]

use voidport_test_client as support;

use std::sync::Arc;

use support::Fixture;
use support::relay::{Cut, Latch, Relay};
use voidport::client::{Caller, Client};
use voidport::fuse::attr::Privileged;
use voidport::fuse::dir::{DirectoryEntry, DirectoryRead, DirectorySink, read_directory};
use voidport::url::MountUrl;
use voidport_proto::opcode::Opcode;

struct Collector {
    names: Vec<Vec<u8>>,
    /// The cookie of each entry accepted, in order.
    offsets: Vec<u64>,
    /// The node ids accepted, which a real kernel accounts for itself and this
    /// test therefore has to give back by hand.
    accepted: Vec<u64>,
    capacity: usize,
    counts: bool,
}

impl Collector {
    fn counting(capacity: usize) -> Self {
        Self {
            names: Vec::new(),
            offsets: Vec::new(),
            accepted: Vec::new(),
            capacity,
            counts: true,
        }
    }

    /// A sink standing in for the plain readdir buffer, whose entries the
    /// kernel does not account for.
    fn plain() -> Self {
        Self {
            names: Vec::new(),
            offsets: Vec::new(),
            accepted: Vec::new(),
            capacity: usize::MAX,
            counts: false,
        }
    }

    fn resume(&self) -> u64 {
        self.offsets.last().copied().unwrap_or(0)
    }
}

impl DirectorySink for Collector {
    fn offer(&mut self, entry: &DirectoryEntry<'_>) -> bool {
        if self.names.len() >= self.capacity {
            return true;
        }
        self.names.push(entry.name.to_vec());
        self.accepted.push(entry.node_id);
        self.offsets.push(entry.offset);
        false
    }

    fn take_back(&mut self, count: usize) {
        let kept = self.names.len().saturating_sub(count);
        self.names.truncate(kept);
        self.accepted.truncate(kept);
        self.offsets.truncate(kept);
    }

    fn counts_lookups(&self) -> bool {
        self.counts
    }
}

fn session(fixture: &Fixture, runtime: &tokio::runtime::Runtime) -> Arc<Client> {
    let url = MountUrl::parse(&fixture.tcp_url("plain", "/tree")).expect("a valid URL");
    runtime
        .block_on(Client::mount(
            &url.endpoint,
            url.namespace.as_str(),
            &url.subpath,
        ))
        .expect("the mount is accepted")
}

fn at(node_id: u64, handle: u64, cookie: u64) -> DirectoryRead {
    DirectoryRead {
        node_id,
        handle,
        cookie,
    }
}

async fn read(
    client: &Client,
    caller: Caller,
    read: DirectoryRead,
    sink: Collector,
) -> Result<Collector, rustix::io::Errno> {
    let (sink, outcome) = read_directory(client, caller, read, Privileged::Present, sink).await;
    outcome.map(|()| sink.expect("the sink comes back"))
}

fn nodes(fixture: &Fixture, runtime: &tokio::runtime::Runtime, client: &Client) -> usize {
    // The server applies a forget before it reads the next request of its
    // connection, so this reply means every forget written before it was
    // applied, when the pool has no other connection.
    assert_eq!(client.connections().expect("a session").pooled, 1);
    runtime
        .block_on(client.getattr(Caller::default(), client.root_node_id(), None))
        .expect("the stream fence replies");
    let sessions = fixture.sessions();
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    sessions[0].nodes
}

#[test]
fn repeated_lookups_and_forgets_leave_nothing_behind() {
    let fixture = Fixture::start("lookup-accounting");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let client = session(&fixture, &runtime);
    let caller = Caller::default();

    assert_eq!(nodes(&fixture, &runtime, &client), 1);

    // The cycles run on one session, so a leak that depends on what earlier
    // cycles left behind can appear.
    runtime.block_on(async {
        for round in 0..320 {
            let entry = client
                .lookup(caller, client.root_node_id(), b"data.bin")
                .await
                .unwrap_or_else(|error| panic!("lookup {round} failed: {error:?}"));
            client.forget(caller, entry.node_id, 1).await;
        }
    });

    assert!(
        nodes(&fixture, &runtime, &client) == 1,
        "the session ended up holding {} nodes",
        nodes(&fixture, &runtime, &client)
    );
}

#[test]
fn a_plain_directory_read_gives_every_counted_lookup_back() {
    let fixture = Fixture::start("plain-readdir");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let client = session(&fixture, &runtime);
    let caller = Caller::default();

    let listed = runtime.block_on(async {
        let root = client.root_node_id();
        let mut listed = 0;
        // The kernel does no accounting for this path, so every entry the
        // server counted must come straight back.
        for round in 0..64 {
            let handle = client
                .open(caller, root, 0)
                .await
                .unwrap_or_else(|error| panic!("opendir {round} failed: {error:?}"));
            let sink = read(&client, caller, at(root, handle, 0), Collector::plain())
                .await
                .unwrap_or_else(|error| panic!("readdir {round} failed: {error:?}"));
            client
                .release(caller, root, handle, 0, None, false)
                .await
                .expect("releasable");
            listed = sink.names.len();
        }
        listed
    });
    assert!(listed >= 3, "the directory listed {listed} entries");

    assert!(
        nodes(&fixture, &runtime, &client) == 1,
        "a plain directory read leaked nodes: {} held",
        nodes(&fixture, &runtime, &client)
    );
}

#[test]
fn entries_a_full_buffer_refuses_are_given_back() {
    let fixture = Fixture::start("refused-entries");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let client = session(&fixture, &runtime);
    let caller = Caller::default();

    let delivered = runtime.block_on(async {
        let root = client.root_node_id();
        let handle = client.open(caller, root, 0).await.expect("opendir");
        // A buffer with room for exactly one entry: the client asks the wire for
        // a page of entries and the "kernel" refuses all but one of them.
        let sink = read(&client, caller, at(root, handle, 0), Collector::counting(1))
            .await
            .expect("readdir");
        assert_eq!(sink.names.len(), 1);
        client
            .release(caller, root, handle, 0, None, false)
            .await
            .expect("releasable");
        sink.names.len()
    });
    assert_eq!(delivered, 1);

    assert!(
        nodes(&fixture, &runtime, &client) == 2,
        "the refused entries were not given back: {} nodes held",
        nodes(&fixture, &runtime, &client)
    );
}

#[test]
fn two_reads_of_one_handle_at_once_leave_nothing_behind() {
    let fixture = Fixture::start("overlapping-reads");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    // The relay withholds the reply to the first read until the second read has
    // arrived at the server, so both reads are in flight at once.
    let relay = Arc::new(Relay::start(fixture.server.data_unix()));
    let client = runtime
        .block_on(Client::mount(&relay.endpoint(), "plain", b"/tree"))
        .expect("the mount is accepted");
    let caller = Caller::default();
    let latch = Latch::default();
    let held = relay.arm(Opcode::Readdirplus, Cut::HoldReply(latch.clone()));

    std::thread::scope(|scope| {
        let (server, relay) = (&fixture.server, &relay);
        let release = scope.spawn(move || {
            held.recv().expect("the reply to the first read is held");
            server.until(|| relay.carried(Opcode::Readdirplus) >= 2);
            latch.release();
        });

        runtime.block_on(async {
            let root = client.root_node_id();
            let handle = client.open(caller, root, 0).await.expect("opendir");
            // Two reads of one handle at the same cookie, in flight together.
            // The kernel serializes readdir per open file description, so a
            // mount never does this; the accounting may not depend on that.
            let (one, two) = tokio::join!(
                read(&client, caller, at(root, handle, 0), Collector::counting(1)),
                read(&client, caller, at(root, handle, 0), Collector::counting(1)),
            );
            let (first, second) = (one.expect("the first read"), two.expect("the second read"));

            for node_id in first.accepted.into_iter().chain(second.accepted) {
                client.forget(caller, node_id, 1).await;
            }
            client
                .release(caller, root, handle, 0, None, false)
                .await
                .expect("releasable");
        });
        release
            .join()
            .expect("both reads arrived before the hold was released");
    });

    // The two reads took a connection each, so the forgets are spread over
    // both: the fence makes the server read everything written on either.
    relay.fence(&runtime, &client);
    assert_eq!(
        fixture.sessions()[0].nodes,
        1,
        "an entry of the overlapping reads was not given back"
    );
}

#[test]
fn a_one_entry_at_a_time_walk_counts_every_entry_exactly_once() {
    let fixture = Fixture::start("small-buffer-walk");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let client = session(&fixture, &runtime);
    let caller = Caller::default();

    let names = runtime.block_on(async {
        let root = client.root_node_id();
        let mut names: Vec<Vec<u8>> = Vec::new();
        for round in 0..64 {
            let handle = client
                .open(caller, root, 0)
                .await
                .unwrap_or_else(|error| panic!("opendir {round} failed: {error:?}"));
            let mut cookie = 0;
            let mut walked: Vec<Vec<u8>> = Vec::new();
            loop {
                let sink = read(
                    &client,
                    caller,
                    at(root, handle, cookie),
                    Collector::counting(1),
                )
                .await
                .unwrap_or_else(|error| panic!("readdirplus {round} failed: {error:?}"));
                if sink.names.is_empty() {
                    break;
                }
                cookie = sink.resume();
                walked.extend(sink.names);
                for node_id in sink.accepted {
                    client.forget(caller, node_id, 1).await;
                }
            }
            client
                .release(caller, root, handle, 0, None, false)
                .await
                .expect("releasable");
            names = walked;
        }
        names
    });

    assert!(names.len() >= 3, "the walk listed {} entries", names.len());
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "an entry was listed twice");

    assert!(
        nodes(&fixture, &runtime, &client) == 1,
        "a one-entry-at-a-time walk leaked nodes: {} held",
        nodes(&fixture, &runtime, &client)
    );
}
