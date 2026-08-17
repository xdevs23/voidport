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
use voidport::fuse::dir::{
    Directories, DirectoryEntry, DirectoryRead, DirectorySink, read_directory, release_directory,
};
use voidport::url::MountUrl;

/// The node cap the server runs with here: a handful more than one listing.
const MAX_NODES: usize = 16;

/// How long a count is given to settle. A `forget` has no reply, so it is
/// observable only once the server has processed it.
const PATIENCE: Duration = Duration::from_secs(10);

/// The attribute timeout the accounting tests pass to the directory path.
///
/// Held surplus is served only within the attr TTL of its fetch, and every test
/// below except the two that are *about* that bound wants the surplus actually
/// used, whatever the machine's load does to the wall clock between calls. The
/// mount's shipped default is one second; this is the same knob, opened wide.
const HELD: Duration = Duration::from_secs(600);

/// The attribute timeout the two expiry tests run under: long enough that a
/// call following its predecessor immediately is inside it, short enough to
/// wait out.
const BRIEF: Duration = Duration::from_millis(200);

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

    let directories = Directories::default();
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
                &directories,
                &client,
                caller,
                at(root, handle, 0),
                HELD,
                Privileged::Present,
                &mut sink,
            )
            .await
            .unwrap_or_else(|error| panic!("readdir {round} failed: {error:?}"));
            release_directory(&directories, &client, caller, handle).await;
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

    let directories = Directories::default();
    let delivered = runtime.block_on(async {
        let root = client.root_node_id();
        let handle = client.open(caller, root, 0).await.expect("opendir");
        // A buffer with room for exactly one entry: the client asks the wire
        // for a whole frame of entries and the "kernel" refuses all but one of
        // them per call, which is the case the accounting exists for.
        let mut sink = Collector::counting(1);
        read_directory(
            &directories,
            &client,
            caller,
            at(root, handle, 0),
            HELD,
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
        // The handle is gone; whatever it was holding is owed back now.
        release_directory(&directories, &client, caller, handle).await;
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
fn two_reads_of_one_handle_at_once_give_every_surplus_back() {
    let fixture = fixture("overlapping-reads");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let client = session(&fixture, &runtime);
    let caller = Caller::default();

    let directories = Directories::default();
    runtime.block_on(async {
        let root = client.root_node_id();
        let handle = client.open(caller, root, 0).await.expect("opendir");
        // Two reads of one handle at the same cookie, in flight together. The
        // kernel serializes readdir per open file description, so this is not
        // how a mount behaves — which is exactly why it is written here: the
        // surplus accounting may not depend on an invariant this module cannot
        // enforce. Both calls find nothing held, both fetch the whole listing,
        // and the second one to finish displaces what the first held.
        let mut first = Collector::counting(1);
        let mut second = Collector::counting(1);
        let (one, two) = tokio::join!(
            read_directory(
                &directories,
                &client,
                caller,
                at(root, handle, 0),
                HELD,
                Privileged::Present,
                &mut first
            ),
            read_directory(
                &directories,
                &client,
                caller,
                at(root, handle, 0),
                HELD,
                Privileged::Present,
                &mut second
            ),
        );
        one.expect("the first read");
        two.expect("the second read");

        // This test is the kernel, so it accounts for what its buffers took.
        for node_id in first.accepted.into_iter().chain(second.accepted) {
            client.forget(caller, node_id, 1).await;
        }
        client
            .release(caller, root, handle, 0, None, false)
            .await
            .expect("releasable");
        // Whatever survived the displacement is owed back with the handle.
        release_directory(&directories, &client, caller, handle).await;
    });

    assert!(
        eventually(PATIENCE, || nodes(&fixture) == 1),
        "a displaced surplus was not given back: {} nodes held",
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

    let directories = Directories::default();
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
                    &directories,
                    &client,
                    caller,
                    at(root, handle, cookie),
                    HELD,
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
            // The handle is released with nothing left held: the walk consumed
            // the whole listing.
            release_directory(&directories, &client, caller, handle).await;
            client
                .release(caller, root, handle, 0, None, false)
                .await
                .expect("releasable");
            names = walked;
        }
        names
    });

    // The walk saw the whole directory, one entry per call, with no entry
    // repeated: the surplus resumes where the buffer stopped.
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

/// Surplus that has outlived the attribute timeout may not be served.
///
/// The mount holds what one wire batch over-fetched and serves the kernel's
/// later calls from it. Those entry replies carry attributes read when the
/// server built them, and a guest is promised nothing older than the attribute
/// timeout — so a walker slow enough to cross it must be given fresh entries,
/// not the ones fetched before the files changed. The staleness is created here
/// deliberately: the listing is fetched, the host then grows every file, and
/// the walk resumes after the timeout has passed.
#[test]
fn surplus_older_than_the_attr_ttl_is_refetched_not_served_stale() {
    let fixture = fixture("stale-surplus");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let client = session(&fixture, &runtime);
    let caller = Caller::default();

    // Files that are empty when the listing is fetched and are not when it is
    // walked. Several, because the first entry the walk delivers comes from the
    // fetch itself and only the rest are served from the held surplus.
    let grown: Vec<String> = (0..4).map(|index| format!("grows-{index}")).collect();
    for name in &grown {
        std::fs::write(fixture.host(&format!("tree/{name}")), b"").expect("writable");
    }
    let payload = vec![b'x'; 64 * 1024];

    let directories = Directories::default();
    let sizes = runtime.block_on(async {
        let root = client.root_node_id();
        let handle = client.open(caller, root, 0).await.expect("opendir");

        // One entry through, the rest of the batch held.
        let mut first = Collector::counting(1);
        read_directory(
            &directories,
            &client,
            caller,
            at(root, handle, 0),
            BRIEF,
            Privileged::Present,
            &mut first,
        )
        .await
        .expect("the first call");
        for node_id in &first.accepted {
            client.forget(caller, *node_id, 1).await;
        }

        // The world moves on, and the held surplus ages out of the timeout.
        for name in &grown {
            std::fs::write(fixture.host(&format!("tree/{name}")), &payload).expect("writable");
        }
        tokio::time::sleep(BRIEF + Duration::from_millis(100)).await;

        // The rest of the walk, one entry at a time.
        let mut sizes: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut cookie = first.resume;
        loop {
            let mut sink = SizeCollector::new(1);
            read_directory(
                &directories,
                &client,
                caller,
                at(root, handle, cookie),
                BRIEF,
                Privileged::Present,
                &mut sink,
            )
            .await
            .expect("the resumed walk");
            if sink.sizes.is_empty() {
                break;
            }
            cookie = sink.resume;
            sizes.extend(sink.sizes);
            for node_id in sink.accepted {
                client.forget(caller, node_id, 1).await;
            }
        }
        release_directory(&directories, &client, caller, handle).await;
        client
            .release(caller, root, handle, 0, None, false)
            .await
            .expect("releasable");
        sizes
    });

    let mut checked = 0;
    for (name, size) in &sizes {
        let name = String::from_utf8_lossy(name).into_owned();
        if !grown.contains(&name) {
            continue;
        }
        assert_eq!(
            *size,
            payload.len() as u64,
            "{name} was served from surplus fetched before it was written"
        );
        checked += 1;
    }
    assert!(
        checked >= grown.len() - 1,
        "only {checked} of the grown files were reached by the resumed walk"
    );

    assert!(
        eventually(PATIENCE, || nodes(&fixture) == 1),
        "the expired surplus was not given back: {} nodes held",
        nodes(&fixture)
    );
}

/// Inside the timeout, the surplus is what answers — no wire round trip.
///
/// The proof is the server's own directory handle: it is released after the
/// batch is fetched, so anything that reached for the wire would be answered
/// with an error. A call that succeeds could only have been served from what
/// the mount already held. The second half of the test is the same call after
/// the timeout, which does reach for the wire, and fails.
#[test]
fn surplus_within_the_attr_ttl_is_served_without_a_wire_fetch() {
    let fixture = fixture("held-surplus");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let client = session(&fixture, &runtime);
    let caller = Caller::default();

    let directories = Directories::default();
    let served = runtime.block_on(async {
        let root = client.root_node_id();

        // Fresh surplus, and no handle left to refetch through.
        let handle = client.open(caller, root, 0).await.expect("opendir");
        let mut first = Collector::counting(1);
        read_directory(
            &directories,
            &client,
            caller,
            at(root, handle, 0),
            HELD,
            Privileged::Present,
            &mut first,
        )
        .await
        .expect("the first call");
        client
            .release(caller, root, handle, 0, None, false)
            .await
            .expect("releasable");

        let mut second = Collector::counting(1);
        read_directory(
            &directories,
            &client,
            caller,
            at(root, handle, first.resume),
            HELD,
            Privileged::Present,
            &mut second,
        )
        .await
        .expect("held surplus needs no wire fetch");
        let served = second.names.len();

        for node_id in first.accepted.iter().chain(&second.accepted) {
            client.forget(caller, *node_id, 1).await;
        }
        release_directory(&directories, &client, caller, handle).await;

        // The same shape again, with the surplus allowed to expire: now the
        // call does reach for the wire, and the released handle refuses it.
        let handle = client.open(caller, root, 0).await.expect("opendir");
        let mut first = Collector::counting(1);
        read_directory(
            &directories,
            &client,
            caller,
            at(root, handle, 0),
            BRIEF,
            Privileged::Present,
            &mut first,
        )
        .await
        .expect("the first call");
        client
            .release(caller, root, handle, 0, None, false)
            .await
            .expect("releasable");
        tokio::time::sleep(BRIEF + Duration::from_millis(100)).await;

        let mut third = Collector::counting(1);
        assert!(
            read_directory(
                &directories,
                &client,
                caller,
                at(root, handle, first.resume),
                BRIEF,
                Privileged::Present,
                &mut third,
            )
            .await
            .is_err(),
            "expired surplus was served instead of being refetched"
        );
        for node_id in &first.accepted {
            client.forget(caller, *node_id, 1).await;
        }
        release_directory(&directories, &client, caller, handle).await;
        served
    });
    assert!(served > 0, "the held surplus delivered nothing");

    assert!(
        eventually(PATIENCE, || nodes(&fixture) == 1),
        "the surplus was not given back: {} nodes held",
        nodes(&fixture)
    );
}

/// A sink that records the size each entry reply carries.
struct SizeCollector {
    sizes: Vec<(Vec<u8>, u64)>,
    accepted: Vec<u64>,
    resume: u64,
    capacity: usize,
}

impl SizeCollector {
    fn new(capacity: usize) -> Self {
        Self {
            sizes: Vec::new(),
            accepted: Vec::new(),
            resume: 0,
            capacity,
        }
    }
}

impl DirectorySink for SizeCollector {
    fn offer(&mut self, entry: &DirectoryEntry<'_>) -> bool {
        if self.sizes.len() >= self.capacity {
            return true;
        }
        self.sizes.push((entry.name.to_vec(), entry.attr.size));
        self.accepted.push(entry.node_id);
        self.resume = entry.offset;
        false
    }

    fn counts_lookups(&self) -> bool {
        true
    }
}
