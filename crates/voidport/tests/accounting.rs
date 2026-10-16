//! Node accounting: what the client counts, and what it gives back.
//!
//! Criterion 13. The server counts one lookup per entry reply and expects the
//! client to balance every one of them; the caps make a leak fatal, not
//! merely wasteful, so this file runs against a server with a deliberately tiny
//! node table and repeats each cycle far more often than the cap would survive
//! if anything leaked.
//!
//! It drives the client's own directory path directly, with a sink of its own,
//! for a reason the contract states: once `FUSE_DO_READDIRPLUS` is negotiated
//! the kernel never issues a plain `readdir`, so the compensating forgets that
//! path owes cannot be reached through a mount. They are reached here, against
//! the real server, over the real wire.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{Fixture, eventually};
use voidport::client::{Caller, Client};
use voidport::fuse::attr::Privileged;
use voidport::fuse::dir::{DirectoryEntry, DirectoryRead, DirectorySink, read_directory};
use voidport::url::MountUrl;

/// The node cap the server runs with here: a handful more than one listing.
const MAX_NODES: usize = 16;

/// How long a count is given to settle. A `forget` has no reply, so it is
/// observable only once the server has processed it.
const PATIENCE: Duration = Duration::from_secs(10);

/// A sink that accepts up to `capacity` entries and then reports full.
struct Collector {
    names: Vec<Vec<u8>>,
    /// The cookie of the last entry accepted — what the kernel would resume
    /// the enumeration from.
    resume: u64,
    /// The node ids accepted, which a real kernel accounts for itself and this
    /// test therefore has to give back by hand.
    accepted: Vec<u64>,
    capacity: usize,
    counts: bool,
}

impl Collector {
    /// A sink standing in for the kernel's readdirplus buffer.
    fn counting(capacity: usize) -> Self {
        Self {
            names: Vec::new(),
            resume: 0,
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
            resume: 0,
            accepted: Vec::new(),
            capacity: usize::MAX,
            counts: false,
        }
    }
}

impl DirectorySink for Collector {
    fn offer(&mut self, entry: &DirectoryEntry<'_>) -> bool {
        if self.names.len() >= self.capacity {
            return true;
        }
        self.names.push(entry.name.to_vec());
        self.accepted.push(entry.node_id);
        self.resume = entry.offset;
        false
    }

    fn counts_lookups(&self) -> bool {
        self.counts
    }
}

/// A fixture whose server holds very few nodes per session.
fn fixture(label: &str) -> Fixture {
    Fixture::start_with(
        label,
        &format!("\n[server.limits]\nmax_nodes = {MAX_NODES}\n"),
    )
}

/// A session on the fixture's server, without a FUSE mount in the way.
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

/// One read of a directory handle, at a cookie.
fn at(node_id: u64, handle: u64, cookie: u64) -> DirectoryRead {
    DirectoryRead {
        node_id,
        handle,
        cookie,
    }
}

/// How many nodes the one live session holds.
fn nodes(fixture: &Fixture) -> usize {
    let sessions = fixture.sessions();
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    sessions[0].nodes
}

#[test]
fn repeated_lookups_and_forgets_leave_nothing_behind() {
    let fixture = fixture("lookup-accounting");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let client = session(&fixture, &runtime);
    let caller = Caller::default();

    // The mount root, and nothing else.
    assert_eq!(nodes(&fixture), 1);

    // Far more cycles than the cap could absorb if a single one leaked.
    runtime.block_on(async {
        for round in 0..(MAX_NODES * 20) {
            let entry = client
                .lookup(caller, client.root_node_id(), b"data.bin")
                .await
                .unwrap_or_else(|error| panic!("lookup {round} failed: {error:?}"));
            client.forget(caller, entry.node_id, 1).await;
        }
    });

    assert!(
        eventually(PATIENCE, || nodes(&fixture) == 1),
        "the session ended up holding {} nodes",
        nodes(&fixture)
    );
}

#[test]
fn a_plain_directory_read_gives_every_counted_lookup_back() {
    let fixture = fixture("plain-readdir");
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
        // server counted must come straight back. Repeating it past the cap is
        // what turns "gives them back" into a fact, not a claim.
        for round in 0..(MAX_NODES * 4) {
            let handle = client
                .open(caller, root, 0)
                .await
                .unwrap_or_else(|error| panic!("opendir {round} failed: {error:?}"));
            let mut sink = Collector::plain();
            read_directory(
                &client,
                caller,
                at(root, handle, 0),
                Privileged::Present,
                &mut sink,
            )
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
        eventually(PATIENCE, || nodes(&fixture) == 1),
        "a plain directory read leaked nodes: {} held",
        nodes(&fixture)
    );
}

#[test]
fn entries_a_full_buffer_refuses_are_given_back() {
    let fixture = fixture("refused-entries");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let client = session(&fixture, &runtime);
    let caller = Caller::default();

    let delivered = runtime.block_on(async {
        let root = client.root_node_id();
        let handle = client.open(caller, root, 0).await.expect("opendir");
        // A buffer with room for exactly one entry: the client asks the wire
        // for a page of entries and the "kernel" refuses all but one of them,
        // which is the case the accounting exists for.
        let mut sink = Collector::counting(1);
        read_directory(
            &client,
            caller,
            at(root, handle, 0),
            Privileged::Present,
            &mut sink,
        )
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

    // Exactly one lookup outstanding above the root: the delivered entry.
    assert!(
        eventually(PATIENCE, || nodes(&fixture) == 2),
        "the refused entries were not given back: {} nodes held",
        nodes(&fixture)
    );
}

#[test]
fn a_one_entry_at_a_time_walk_counts_every_entry_exactly_once() {
    let fixture = fixture("small-buffer-walk");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let client = session(&fixture, &runtime);
    let caller = Caller::default();

    let names = runtime.block_on(async {
        let root = client.root_node_id();
        let mut names: Vec<Vec<u8>> = Vec::new();
        // Far more rounds than the node cap could absorb if one entry of one
        // round leaked: every round walks the whole listing a single entry per
        // call, exactly as a kernel with a one-entry reply buffer would.
        for round in 0..(MAX_NODES * 4) {
            let handle = client
                .open(caller, root, 0)
                .await
                .unwrap_or_else(|error| panic!("opendir {round} failed: {error:?}"));
            let mut cookie = 0;
            let mut walked: Vec<Vec<u8>> = Vec::new();
            loop {
                let mut sink = Collector::counting(1);
                read_directory(
                    &client,
                    caller,
                    at(root, handle, cookie),
                    Privileged::Present,
                    &mut sink,
                )
                .await
                .unwrap_or_else(|error| panic!("readdirplus {round} failed: {error:?}"));
                if sink.names.is_empty() {
                    break;
                }
                cookie = sink.resume;
                walked.extend(sink.names);
                // The kernel accounts for what it accepted; this test is the
                // kernel, so it gives those back itself.
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

    // The walk saw the whole directory, one entry per call, with no entry
    // repeated: each call resumes where the buffer stopped.
    assert!(names.len() >= 3, "the walk listed {} entries", names.len());
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "an entry was listed twice");

    assert!(
        eventually(PATIENCE, || nodes(&fixture) == 1),
        "a one-entry-at-a-time walk leaked nodes: {} held",
        nodes(&fixture)
    );
}
