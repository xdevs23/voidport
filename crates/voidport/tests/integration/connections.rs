use voidport_test_client as support;

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustix::io::Errno;
use support::daemon::{Ground, reconnected_after, runtime};
use support::relay::{Cut, Latch, Relay};
use voidport::client::{
    Caller, Client, Connections, Data, EntrySink, Interrupt, Listed, Lock, LockKind, MountState,
    Placement,
};
use voidport::subscribe::{ShareEvent, Subscription};
use voidport_control::{
    NamespaceName, Reply, Request, Response, Rule, SessionSummary, ShareMode, Timeouts,
};
use voidport_proto::opcode::Opcode;
use voidport_test_support::create_directory;

const STALL: Duration = Duration::from_secs(30);

const O_RDWR: u32 = 2;

struct Rig {
    ground: Ground,
    relay: Relay,
    runtime: tokio::runtime::Runtime,
    client: Arc<Client>,
    tree: u64,
}

fn rig(label: &str) -> Rig {
    rig_with(label, |_| {})
}

fn rig_with(label: &str, prepare: impl FnOnce(&std::path::Path)) -> Rig {
    let ground = Ground::start(label);
    prepare(&ground.tree);
    let relay = Relay::start(ground.server.data_socket());
    let runtime = runtime();
    let client = ground.connect_to(&runtime, &relay.endpoint(), STALL);
    let tree = runtime
        .block_on(client.lookup(Caller::default(), client.root_node_id(), b"tree"))
        .expect("the graft resolves")
        .node_id;
    Rig {
        ground,
        relay,
        runtime,
        client,
        tree,
    }
}

impl Rig {
    fn session(&self) -> SessionSummary {
        let mut sessions = sessions_of(&self.ground);
        assert_eq!(sessions.len(), 1, "{sessions:?}");
        sessions.remove(0)
    }

    fn widen(&self) {
        let latch = Latch::default();
        let held = self
            .relay
            .arm(Opcode::Getattr, Cut::HoldReply(latch.clone()));
        let client = Arc::clone(&self.client);
        let root = client.root_node_id();
        let first = self
            .runtime
            .spawn(async move { client.getattr(Caller::default(), root, None).await });
        held.recv().expect("the first reply is held");
        self.runtime
            .block_on(self.client.getattr(Caller::default(), root, None))
            .expect("the second request takes a connection of its own");
        latch.release();
        self.runtime
            .block_on(first)
            .expect("joined")
            .expect("the held request is answered");
        let pool = self.client.connections().expect("a session").pooled;
        assert!(pool >= 2, "the pool holds {pool} connections");
    }

    fn lookup(&self, name: &[u8]) -> u64 {
        self.runtime
            .block_on(self.client.lookup(Caller::default(), self.tree, name))
            .expect("the name resolves")
            .node_id
    }

    fn open(&self, name: &[u8], flags: u32) -> (u64, u64) {
        let node = self.lookup(name);
        let handle = self
            .runtime
            .block_on(self.client.open(Caller::default(), node, flags))
            .expect("the file opens");
        (node, handle)
    }

    fn write(&self, (node, handle): (u64, u64), offset: u64, data: &[u8]) -> Result<u32, Errno> {
        self.runtime.block_on(self.client.write(
            Caller::default(),
            &Interrupt::none(),
            Placement {
                node_id: node,
                handle,
                offset,
            },
            data,
            false,
        ))
    }

    /// A forget applied later than this call is still applied, and one never
    /// applied ends the test only when the server ends.
    fn nodes_become(&self, nodes: usize) {
        self.ground.server.until(|| self.session().nodes == nodes);
    }

    /// Waits until every connection of the pool is idle, and makes the server
    /// read everything the client wrote on them so far.
    fn fence(&self) {
        self.relay.fence(&self.runtime, &self.client);
    }
}

/// The control client waits for the answer with no bound, as every control
/// request of these tests does: the result must not depend on how long the
/// server takes to answer.
fn sessions_of(ground: &Ground) -> Vec<SessionSummary> {
    let mut control = voidport_control::Client::connect_with(
        ground.server.control_socket(),
        Timeouts::unbounded(),
    )
    .expect("the control socket accepts connections");
    let answer = control
        .call(&Request::SessionList {})
        .expect("the server answers");
    match answer.response {
        Response::Ok {
            result: Reply::SessionList { sessions },
        } => sessions,
        other => panic!("session-list answered {other:?}"),
    }
}

fn block(rig: &Rig) -> usize {
    fs::metadata(&rig.ground.tree).expect("stat").blksize() as usize
}

#[test]
fn a_long_read_does_not_delay_a_lookup_a_small_read_or_a_write_in_parallel() {
    let rig = rig("connections-parallel");
    let long = rig.open(b"data.bin", O_RDWR);
    let small = rig.open(b"alpha", O_RDWR);
    let target = rig.open(b"beta", O_RDWR);

    let latch = Latch::default();
    let hold = |opcode| rig.relay.arm(opcode, Cut::HoldReply(latch.clone()));

    let long_held = hold(Opcode::Read);
    let client = Arc::clone(&rig.client);
    let buffer = rig.runtime.block_on(rig.client.buffer(64));
    let reading = rig.runtime.spawn(async move {
        let (data, outcome) = client
            .read(
                Caller::default(),
                &Interrupt::none(),
                long.0,
                long.1,
                0,
                Data::new(buffer),
            )
            .await;
        outcome.map(|_| data.filled().to_vec())
    });
    let mut carriers = vec![long_held.recv().expect("the long read's reply is held")];

    let others = [
        hold(Opcode::Lookup),
        hold(Opcode::Read),
        hold(Opcode::Write),
    ];
    let client = Arc::clone(&rig.client);
    let tree = rig.tree;
    let looking = rig.runtime.spawn(async move {
        client
            .lookup(Caller::default(), tree, b"alpha")
            .await
            .map(|entry| entry.node_id)
    });
    let client = Arc::clone(&rig.client);
    let buffer = rig.runtime.block_on(rig.client.buffer(64));
    let small_reading = rig.runtime.spawn(async move {
        let (data, outcome) = client
            .read(
                Caller::default(),
                &Interrupt::none(),
                small.0,
                small.1,
                0,
                Data::new(buffer),
            )
            .await;
        outcome.map(|_| data.filled().to_vec())
    });
    let client = Arc::clone(&rig.client);
    let writing = rig.runtime.spawn(async move {
        client
            .write(
                Caller::default(),
                &Interrupt::none(),
                Placement {
                    node_id: target.0,
                    handle: target.1,
                    offset: 0,
                },
                b"BETA",
                false,
            )
            .await
    });
    for held in others {
        carriers.push(held.recv().expect("the reply is held"));
    }

    let finished = [
        reading.is_finished(),
        looking.is_finished(),
        small_reading.is_finished(),
        writing.is_finished(),
    ];
    assert_eq!(finished, [false; 4], "every reply is still held");
    let mut distinct = carriers.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        4,
        "the long read, the lookup, the small read and the write were carried by \
         connections {carriers:?}"
    );

    latch.release();
    assert_eq!(
        rig.runtime.block_on(reading).expect("joined"),
        Ok(support::daemon::CONTENTS.to_vec())
    );
    assert_eq!(rig.runtime.block_on(looking).expect("joined"), Ok(small.0));
    assert_eq!(
        rig.runtime.block_on(small_reading).expect("joined"),
        Ok(b"alpha".to_vec())
    );
    assert_eq!(rig.runtime.block_on(writing).expect("joined"), Ok(4));
    assert_eq!(
        fs::read(rig.ground.tree.join("beta")).expect("host"),
        b"BETA-beta"
    );
}

#[test]
fn a_write_the_server_finished_is_answered_from_the_kept_reply() {
    let rig = rig("connections-write-finished");
    rig.widen();
    let file = rig.open(b"beta", O_RDWR);
    let lost = rig.relay.arm(Opcode::Write, Cut::DiscardReply);
    assert_eq!(rig.write(file, 0, b"ONCE"), Ok(4));
    lost.recv().expect("the reply was lost");
    assert_eq!(
        rig.relay.carried(Opcode::Write),
        1,
        "the write was not sent again"
    );
    assert_eq!(rig.relay.carried(Opcode::Outcome), 1);
    assert_eq!(
        fs::read(rig.ground.tree.join("beta")).expect("host"),
        b"ONCE-beta"
    );
    assert_eq!(rig.client.state(), MountState::Connected);
}

#[test]
fn a_write_cut_off_mid_data_is_a_short_write_and_the_rest_is_sent_again() {
    let rig = rig("connections-write-short");
    rig.widen();
    let piece = block(&rig);
    let file = rig.open(b"beta", O_RDWR);
    let data = vec![b'c'; 4 * piece];
    rig.relay.arm(
        Opcode::Write,
        Cut::Request {
            data: piece + piece / 2,
        },
    );
    // The outcome request closes the lost connection on the server, and one
    // that arrived before the first piece reached the file would find the
    // write never started. It is held until the piece is there.
    let latch = Latch::default();
    let asked = rig
        .relay
        .arm(Opcode::Outcome, Cut::HoldRequest(latch.clone()));
    let client = Arc::clone(&rig.client);
    let whole = data.clone();
    let writing = rig.runtime.spawn(async move {
        client
            .write(
                Caller::default(),
                &Interrupt::none(),
                Placement {
                    node_id: file.0,
                    handle: file.1,
                    offset: 0,
                },
                &whole,
                false,
            )
            .await
    });
    asked.recv().expect("the outcome request is held");
    let host = rig.ground.tree.join("beta");
    rig.ground
        .server
        .until(|| fs::read(&host).expect("host").get(..piece) == Some(&data[..piece]));
    latch.release();
    let written = rig
        .runtime
        .block_on(writing)
        .expect("joined")
        .expect("settled") as usize;
    assert_eq!(written, piece, "the server wrote one piece before the cut");
    // As after any short write: the rest, from where it stopped.
    assert_eq!(
        rig.write(file, written as u64, &data[written..]),
        Ok((data.len() - written) as u32)
    );
    assert_eq!(fs::read(rig.ground.tree.join("beta")).expect("host"), data);
}

#[test]
fn a_write_cut_off_before_any_byte_or_never_read_is_sent_again_once() {
    let rig = rig("connections-write-again");
    rig.widen();
    let file = rig.open(b"beta", O_RDWR);
    rig.relay.arm(Opcode::Write, Cut::Request { data: 0 });
    assert_eq!(rig.write(file, 0, b"ABCD"), Ok(4));
    rig.widen();
    rig.relay.arm(Opcode::Write, Cut::DropRequest);
    assert_eq!(rig.write(file, 4, b"EFGH"), Ok(4));
    assert_eq!(
        rig.relay.carried(Opcode::Write),
        2,
        "each was carried whole once"
    );
    assert_eq!(
        fs::read(rig.ground.tree.join("beta")).expect("host"),
        b"ABCDEFGHa"
    );
}

#[test]
fn a_write_lost_where_the_server_read_nothing_is_sent_again_once() {
    let rig = rig("connections-write-stale");
    let file = rig.open(b"beta", O_RDWR);
    // The session's one connection carries a request whose reply waits at
    // the relay, so the write joins a connection of its own, and the relay
    // drops the write before the server reads it.
    let latch = Latch::default();
    let held = rig
        .relay
        .arm(Opcode::Getattr, Cut::HoldReply(latch.clone()));
    let client = Arc::clone(&rig.client);
    let root = rig.client.root_node_id();
    let first = rig
        .runtime
        .spawn(async move { client.getattr(Caller::default(), root, None).await });
    held.recv().expect("the first reply is held");
    rig.relay.arm(Opcode::Write, Cut::DropRequest);
    assert_eq!(rig.write(file, 0, b"ONCE"), Ok(4));
    latch.release();
    rig.runtime
        .block_on(first)
        .expect("joined")
        .expect("the held request is answered");
    assert_eq!(rig.relay.carried(Opcode::Outcome), 1, "asked once");
    assert_eq!(rig.relay.carried(Opcode::Write), 1, "carried whole once");
    assert_eq!(
        fs::read(rig.ground.tree.join("beta")).expect("host"),
        b"ONCE-beta"
    );
    assert_eq!(rig.client.state(), MountState::Connected);
}

#[test]
fn interleaved_writes_of_different_bytes_each_land_once() {
    let rig = rig("connections-write-interleaved");
    rig.widen();
    let file = rig.open(b"data.bin", O_RDWR);
    let lost = rig.relay.arm(Opcode::Write, Cut::DiscardReply);
    let latch = Latch::default();
    let asked = rig
        .relay
        .arm(Opcode::Outcome, Cut::HoldReply(latch.clone()));
    let client = Arc::clone(&rig.client);
    let first = rig.runtime.spawn(async move {
        client
            .write(
                Caller::default(),
                &Interrupt::none(),
                Placement {
                    node_id: file.0,
                    handle: file.1,
                    offset: 0,
                },
                b"aaaaaaaa",
                false,
            )
            .await
    });
    lost.recv().expect("the first write's reply was lost");
    asked.recv().expect("its outcome is held");
    assert_eq!(
        rig.write(file, 0, b"bbbb"),
        Ok(4),
        "the second write runs meanwhile"
    );
    latch.release();
    assert_eq!(rig.runtime.block_on(first).expect("joined"), Ok(8));
    assert_eq!(rig.relay.carried(Opcode::Write), 2);
    assert_eq!(
        fs::read(rig.ground.tree.join("data.bin")).expect("host"),
        b"bbbbaaaa89"
    );
}

#[test]
fn appends_lost_at_every_point_end_in_the_file_once() {
    let rig = rig("connections-append");
    rig.widen();
    fs::write(rig.ground.tree.join("beta"), b"").expect("an empty file");
    let appending = O_RDWR | rustix::fs::OFlags::APPEND.bits();
    let file = rig.open(b"beta", appending);

    // Each loss takes a connection of the pool; the pool is widened before
    // each, so none of them is the session's last.
    rig.relay.arm(Opcode::Write, Cut::DiscardReply);
    assert_eq!(rig.write(file, 0, b"one;"), Ok(4));
    rig.widen();
    rig.relay.arm(Opcode::Write, Cut::Request { data: 2 });
    assert_eq!(rig.write(file, 0, b"two;"), Ok(4));
    rig.widen();
    rig.relay.arm(Opcode::Write, Cut::DropRequest);
    assert_eq!(rig.write(file, 0, b"three;"), Ok(6));
    assert_eq!(
        fs::read(rig.ground.tree.join("beta")).expect("host"),
        b"one;two;three;"
    );
}

#[test]
fn losing_the_last_connection_during_a_write_takes_the_reconnect_path() {
    let rig = rig("connections-write-last");
    let file = rig.open(b"beta", O_RDWR);
    assert_eq!(
        rig.client.connections(),
        Some(Connections {
            pooled: 1,
            subscribed: false
        })
    );
    reconnected_after(&rig.client, || {
        rig.relay.arm(Opcode::Write, Cut::DiscardReply);
        assert_eq!(rig.write(file, 0, b"LAST"), Err(Errno::IO));
    });
    assert_eq!(rig.relay.carried(Opcode::Outcome), 0, "nothing was asked");
    assert_eq!(
        fs::read(rig.ground.tree.join("beta")).expect("host"),
        b"LAST-beta"
    );
}

#[test]
fn a_lost_lookup_and_open_leave_the_counts_as_the_client_knows_them() {
    let rig = rig("connections-lookup-open");
    rig.widen();
    let before = rig.session();

    rig.relay.arm(Opcode::Lookup, Cut::DiscardReply);
    let node = rig.lookup(b"alpha");
    assert_eq!(
        rig.relay.carried(Opcode::Lookup),
        2,
        "the tree and alpha, once each"
    );
    assert_eq!(rig.session().nodes, before.nodes + 1);

    rig.widen();
    rig.relay.arm(Opcode::Open, Cut::DiscardReply);
    let handle = rig
        .runtime
        .block_on(rig.client.open(Caller::default(), node, O_RDWR))
        .expect("settled from the kept reply");
    assert_eq!(rig.session().handles, before.handles + 1);

    // One release and one forget balance them: had either been applied twice,
    // a count would be left over.
    rig.runtime
        .block_on(
            rig.client
                .release(Caller::default(), node, handle, 0, None, false),
        )
        .expect("released");
    assert_eq!(rig.session().handles, before.handles);
    rig.runtime
        .block_on(rig.client.forget(Caller::default(), node, 1));
    rig.nodes_become(before.nodes);
}

#[test]
fn a_lost_release_is_settled_and_not_moot() {
    let rig = rig("connections-release");
    rig.widen();
    let before = rig.session();
    let (node, handle) = rig.open(b"alpha", O_RDWR);
    assert_eq!(rig.session().handles, before.handles + 1);
    rig.relay.arm(Opcode::Release, Cut::DiscardReply);
    rig.runtime
        .block_on(
            rig.client
                .release(Caller::default(), node, handle, 0, None, false),
        )
        .expect("settled from the kept reply");
    assert_eq!(rig.relay.carried(Opcode::Release), 1);
    assert_eq!(rig.session().handles, before.handles);
}

/// Each case looks the node up twice before it writes a forget of one lookup,
/// so a forget applied twice removes the node. Each case waits until every
/// connection of the pool is idle and the server read everything sent on it,
/// and asserts that the server still has the node. One more forget of one
/// lookup must then remove it, which proves the lost forget was applied at all.
#[test]
fn a_forget_lost_with_its_connection_is_applied_once() {
    let rig = rig("connections-forget");
    let base = rig.session().nodes;
    let held_twice = || {
        rig.widen();
        let node = rig.lookup(b"alpha");
        assert_eq!(rig.lookup(b"alpha"), node);
        node
    };
    let forget = |node| {
        rig.runtime
            .block_on(rig.client.forget(Caller::default(), node, 1));
    };
    let recovered = |retired: &std::sync::mpsc::Receiver<usize>, node| {
        retired
            .recv()
            .expect("the server answered the retire of the lost connection");
        rig.fence();
        assert_eq!(rig.session().nodes, base + 1, "not applied twice");
        forget(node);
        rig.fence();
        assert_eq!(rig.session().nodes, base, "applied once");
    };

    // Read, and the connection lost right after: the relay passed the forget on
    // whole, and nothing after it.
    let node = held_twice();
    let latch = Latch::default();
    let read = rig
        .relay
        .arm(Opcode::Forget, Cut::AfterRequestUntil(latch.clone()));
    forget(node);
    read.recv().expect("the forget reached the server");
    let retired = rig
        .relay
        .arm(Opcode::Retire, Cut::HoldReply(Latch::released()));
    latch.release();
    recovered(&retired, node);

    // Read, followed by a request on the same connection that was answered,
    // and then lost while it is sending the next request. The answer proves the
    // server applied the forget, which it read first.
    let node = held_twice();
    let written = rig
        .relay
        .arm(Opcode::Forget, Cut::HoldRequest(Latch::released()));
    forget(node);
    let carrier = written.recv().expect("the relay took the forget");
    let answered = rig
        .relay
        .arm(Opcode::Getattr, Cut::HoldReply(Latch::released()));
    rig.runtime
        .block_on(rig.client.getattr(Caller::default(), rig.tree, None))
        .expect("answered");
    assert_eq!(
        answered.recv().expect("the reply went through"),
        carrier,
        "the later request went on the forget's connection"
    );
    let retired = rig
        .relay
        .arm(Opcode::Retire, Cut::HoldReply(Latch::released()));
    let cut = rig.relay.arm(Opcode::Getattr, Cut::AfterRequest);
    rig.runtime
        .block_on(rig.client.getattr(Caller::default(), rig.tree, None))
        .expect("sent again on another connection");
    assert_eq!(
        cut.recv().expect("the connection was lost"),
        carrier,
        "the forget's connection was lost"
    );
    recovered(&retired, node);

    // Never read: the relay dropped it before the server could read it, and
    // it is sent again.
    let node = held_twice();
    let retired = rig
        .relay
        .arm(Opcode::Retire, Cut::HoldReply(Latch::released()));
    let dropped = rig.relay.arm(Opcode::Forget, Cut::DropRequest);
    forget(node);
    dropped
        .recv()
        .expect("the relay dropped the forget before the server read it");
    recovered(&retired, node);
}

/// The only connection of the session waits for a reply that the relay
/// withholds, and the relay closes every new connection, so the first forget
/// waits for a connection of the session and the second one is queued behind
/// it. The relay then ends that connection, which ends the session, and sends
/// new connections to another server.
#[test]
fn a_queued_forget_of_an_ended_session_never_reaches_the_newer_one() {
    let rig = rig("connections-queued-forget");
    let other = Ground::start("connections-queued-forget-other");
    let (caller, root) = (Caller::default(), rig.client.root_node_id());
    let forgets = rig.relay.carried(Opcode::Forget);
    let latch = Latch::default();
    let held = rig
        .relay
        .arm(Opcode::Getattr, Cut::HoldReply(latch.clone()));
    let client = Arc::clone(&rig.client);
    let first = rig
        .runtime
        .spawn(async move { client.getattr(caller, root, None).await });
    held.recv().expect("the reply is withheld");

    rig.relay.refuse_new(true);
    let refused = rig.relay.refused();
    rig.client.queue_forget(caller, rig.tree, 1);
    rig.ground.server.until(|| rig.relay.refused() > refused);
    rig.client.queue_forget(caller, rig.tree, 1);
    reconnected_after(&rig.client, || {
        rig.relay.redirect(other.server.data_socket());
        rig.relay.refuse_new(false);
        rig.relay.end_carriers(Opcode::Getattr);
    });
    latch.release();
    rig.runtime
        .block_on(first)
        .expect("joined")
        .expect("sent again in the new session");

    let tree = rig
        .runtime
        .block_on(rig.client.lookup(caller, root, b"tree"))
        .expect("the graft resolves in the new session")
        .node_id;
    let looked_up = sessions_of(&other)[0].nodes;
    rig.client.queue_forget(caller, tree, 1);
    other
        .server
        .until(|| sessions_of(&other)[0].nodes < looked_up);
    rig.fence();
    assert_eq!(
        rig.relay.carried(Opcode::Forget),
        forgets + 1,
        "a forget of the ended session reached the newer one"
    );
}

#[derive(Default)]
struct Recording(Arc<Mutex<Vec<Vec<u8>>>>);

impl EntrySink for Recording {
    fn offer(&mut self, entry: &Listed<'_>) -> bool {
        self.0.lock().expect("unpoisoned").push(entry.name.to_vec());
        false
    }

    fn take_back(&mut self, count: usize) {
        let mut names = self.0.lock().expect("unpoisoned");
        let kept = names.len().saturating_sub(count);
        names.truncate(kept);
    }
}

#[test]
fn a_listing_cut_off_part_way_is_answered_whole_from_the_kept_reply() {
    const ENTRIES: usize = 40;
    let rig = rig_with("connections-listing", |tree| {
        let many = tree.join("many");
        create_directory(&many);
        for index in 0..ENTRIES {
            fs::write(many.join(format!("f{index:02}")), b"x").expect("a file");
        }
    });
    rig.widen();
    let (node, handle) = rig.open(
        b"many",
        rustix::fs::OFlags::DIRECTORY.bits() | rustix::fs::OFlags::RDONLY.bits(),
    );
    let base = rig.session().nodes;
    rig.relay.arm(Opcode::Readdirplus, Cut::Reply { pieces: 5 });
    let names = Arc::new(Mutex::new(Vec::new()));
    let listing = rig.runtime.block_on(rig.client.readdirplus(
        Caller::default(),
        node,
        handle,
        0,
        65536,
        Box::new(Recording(Arc::clone(&names))),
    ));
    assert_eq!(listing.outcome, Ok(true), "the listing is whole");
    let mut names = names.lock().expect("unpoisoned").clone();
    let offered = names.len();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), offered, "no entry was delivered twice");
    assert_eq!(names.len(), ENTRIES);
    assert_eq!(listing.accepted.len(), ENTRIES);
    assert_eq!(
        rig.relay.carried(Opcode::Readdirplus),
        1,
        "not listed again"
    );
    assert_eq!(
        rig.session().nodes,
        base + ENTRIES,
        "one lookup counted per entry the client holds"
    );
}

#[test]
fn a_listing_cut_off_with_its_session_is_answered_by_the_next_session() {
    let rig = rig_with("connections-listing-ended", |tree| {
        let many = tree.join("many");
        create_directory(&many);
        for index in 0..8 {
            fs::write(many.join(format!("f{index}")), b"x").expect("a file");
        }
    });
    let (node, handle) = rig.open(
        b"many",
        rustix::fs::OFlags::DIRECTORY.bits() | rustix::fs::OFlags::RDONLY.bits(),
    );
    assert_eq!(
        rig.client.connections(),
        Some(Connections {
            pooled: 1,
            subscribed: false
        }),
        "the listing takes the last connection of the session"
    );
    rig.relay.arm(Opcode::Readdirplus, Cut::Reply { pieces: 5 });
    let names = Arc::new(Mutex::new(Vec::new()));
    let listing = rig.runtime.block_on(rig.client.readdirplus(
        Caller::default(),
        node,
        handle,
        0,
        65536,
        Box::new(Recording(Arc::clone(&names))),
    ));
    assert_eq!(listing.outcome, Err(Errno::STALE));
    assert!(
        names.lock().expect("unpoisoned").is_empty(),
        "the entries of the ended session were taken back"
    );
    assert!(listing.accepted.is_empty());
    assert_eq!(
        rig.relay.carried(Opcode::Readdirplus),
        2,
        "listed again in the next session"
    );
}

#[test]
fn a_waiting_lock_whose_connection_closes_is_sent_again() {
    let rig = rig("connections-lock");
    rig.widen();
    let (node, handle) = rig.open(b"alpha", O_RDWR);
    let lock = |owner, kind| Lock {
        start: 0,
        end: u64::MAX,
        owner,
        pid: 1,
        kind,
    };
    rig.runtime
        .block_on(rig.client.setlk(
            Caller::default(),
            &Interrupt::none(),
            node,
            handle,
            lock(1, LockKind::Write),
            false,
        ))
        .expect("the first lock holder acquires the lock");
    let cut = rig.relay.arm(Opcode::Setlk, Cut::AfterRequest);
    let client = Arc::clone(&rig.client);
    let waiting = rig.runtime.spawn(async move {
        client
            .setlk(
                Caller::default(),
                &Interrupt::none(),
                node,
                handle,
                lock(2, LockKind::Write),
                true,
            )
            .await
    });
    cut.recv()
        .expect("the waiting request's connection was lost");
    // Sent again once never started: the first holder's, the lost one, and the
    // one sent again.
    rig.ground
        .server
        .until(|| rig.relay.carried(Opcode::Setlk) >= 3);
    assert!(!waiting.is_finished(), "it waits again");
    rig.runtime
        .block_on(rig.client.setlk(
            Caller::default(),
            &Interrupt::none(),
            node,
            handle,
            lock(1, LockKind::Unlock),
            false,
        ))
        .expect("the first lock holder lets go");
    assert_eq!(rig.runtime.block_on(waiting).expect("joined"), Ok(()));
}

fn whole_file(owner: u64, kind: LockKind) -> Lock {
    Lock {
        start: 0,
        end: u64::MAX,
        owner,
        pid: 1,
        kind,
    }
}

#[test]
fn an_interrupted_lock_wait_ends_with_eintr_and_takes_nothing() {
    let rig = rig("connections-interrupted-lock");
    let (node, handle) = rig.open(b"alpha", O_RDWR);
    let setlk = |owner, kind| {
        rig.runtime.block_on(rig.client.setlk(
            Caller::default(),
            &Interrupt::none(),
            node,
            handle,
            whole_file(owner, kind),
            false,
        ))
    };
    setlk(1, LockKind::Write).expect("the first lock holder acquires the lock");
    let pool = rig.client.connections();
    let reaching = rig
        .relay
        .arm(Opcode::Setlk, Cut::HoldRequest(Latch::released()));
    let (raise, interrupt) = Interrupt::new();
    let client = Arc::clone(&rig.client);
    let waiting = rig.runtime.spawn(async move {
        let lock = whole_file(2, LockKind::Write);
        client
            .setlk(Caller::default(), &interrupt, node, handle, lock, true)
            .await
    });
    reaching
        .recv()
        .expect("the waiting request is on its way to the server");
    raise.raise();
    assert_eq!(
        rig.runtime.block_on(waiting).expect("joined"),
        Err(Errno::INTR)
    );
    assert_eq!(
        rig.client.connections(),
        pool,
        "no connection closed for it"
    );
    setlk(1, LockKind::Unlock).expect("the first lock holder lets go");
    setlk(3, LockKind::Write).expect("the interrupted request placed no lock");
}

#[test]
fn a_raised_interrupt_ends_a_lock_request_and_never_an_unlock() {
    let rig = rig("connections-interrupted-unlock");
    let (node, handle) = rig.open(b"alpha", O_RDWR);
    let (raise, raised) = Interrupt::new();
    raise.raise();
    let setlk = |interrupt: &Interrupt, owner, kind| {
        rig.runtime.block_on(rig.client.setlk(
            Caller::default(),
            interrupt,
            node,
            handle,
            whole_file(owner, kind),
            false,
        ))
    };
    setlk(&Interrupt::none(), 1, LockKind::Write).expect("the first lock holder acquires it");
    assert_eq!(setlk(&raised, 2, LockKind::Write), Err(Errno::INTR));
    setlk(&raised, 1, LockKind::Unlock).expect("the unlock is applied");
    setlk(&Interrupt::none(), 2, LockKind::Write).expect("the lock is free");
}

#[test]
fn a_request_cancelled_before_its_connection_is_lost_is_retired_once() {
    let rig = rig("connections-cancel-before-loss");
    rig.widen();
    let before = rig.session();
    let root = rig.client.root_node_id();
    let latch = Latch::default();
    let held = rig.relay.arm(Opcode::Statfs, Cut::HoldReply(latch.clone()));
    let client = Arc::clone(&rig.client);
    let cancelled = rig
        .runtime
        .spawn(async move { client.statfs(Caller::default(), root).await });
    let carrier = held.recv().expect("the reply is held");
    cancelled.abort();
    assert!(
        rig.runtime
            .block_on(cancelled)
            .expect_err("the request was cancelled")
            .is_cancelled()
    );

    let other = rig
        .relay
        .arm(Opcode::Getattr, Cut::HoldReply(Latch::released()));
    rig.runtime
        .block_on(rig.client.getattr(Caller::default(), root, None))
        .expect("answered");
    assert_ne!(
        other.recv().expect("the reply went through"),
        carrier,
        "not on the connection whose reply is owed"
    );

    let retired = rig
        .relay
        .arm(Opcode::Retire, Cut::HoldReply(Latch::released()));
    rig.relay.end_carriers(Opcode::Statfs);
    assert_ne!(
        retired.recv().expect("the server answered the retire"),
        carrier
    );
    assert_eq!(
        rig.client.connections(),
        Some(Connections {
            pooled: 1,
            subscribed: false
        }),
        "the lost connection left the pool"
    );
    latch.release();
    rig.fence();
    assert_eq!(rig.relay.carried(Opcode::Retire), 1, "retired once");
    assert_eq!(rig.session().id, before.id, "the session lives on");
    assert_eq!(rig.client.state(), MountState::Connected);
}

#[test]
fn a_request_cancelled_while_its_outcome_answer_is_held_is_retired_once() {
    let rig = rig("connections-cancel-outcome");
    rig.widen();
    let file = rig.open(b"beta", O_RDWR);
    let before = rig.session();
    let lost = rig.relay.arm(Opcode::Write, Cut::DiscardReply);
    let latch = Latch::default();
    let asked = rig
        .relay
        .arm(Opcode::Outcome, Cut::HoldReply(latch.clone()));
    let retired = rig
        .relay
        .arm(Opcode::Retire, Cut::HoldReply(Latch::released()));
    let client = Arc::clone(&rig.client);
    let writing = rig.runtime.spawn(async move {
        client
            .write(
                Caller::default(),
                &Interrupt::none(),
                Placement {
                    node_id: file.0,
                    handle: file.1,
                    offset: 0,
                },
                b"ONCE",
                false,
            )
            .await
    });
    lost.recv().expect("the write's reply was lost");
    let question = asked.recv().expect("the answer about the write is held");
    writing.abort();
    assert!(
        rig.runtime
            .block_on(writing)
            .expect_err("the write was cancelled")
            .is_cancelled()
    );

    assert_ne!(
        retired
            .recv()
            .expect("the server answered the retire of the lost connection"),
        question,
        "not on the connection whose answer is owed"
    );
    assert_eq!(rig.relay.carried(Opcode::Retire), 1, "retired once");
    latch.release();
    assert_eq!(rig.relay.carried(Opcode::Write), 1, "not sent again");
    assert_eq!(
        fs::read(rig.ground.tree.join("beta")).expect("host"),
        b"ONCE-beta"
    );
    assert_eq!(rig.session().id, before.id, "the session lives on");
    assert_eq!(rig.client.state(), MountState::Connected);
}

/// The server answers only after it has synced its state file to the disk, so
/// the control client waits for the answer with no bound.
fn add_rule(rig: &Rig, path: &str) {
    let mut control = voidport_control::Client::connect_with(
        rig.ground.server.control_socket(),
        Timeouts::unbounded(),
    )
    .expect("the control socket accepts connections");
    let answer = control
        .call(&Request::RuleAdd {
            namespace: NamespaceName::new("work").expect("a valid name"),
            rule: Rule::new(path, ShareMode::Ro),
        })
        .expect("the server answers");
    assert!(
        matches!(answer.response, Response::Ok { .. }),
        "{:?}",
        answer.response
    );
}

fn next(rig: &Rig, subscription: &mut Subscription) -> ShareEvent {
    rig.runtime
        .block_on(subscription.next())
        .expect("the stream goes on")
}

#[test]
fn a_subscription_owns_its_connection() {
    let rig = rig("connections-subscription");
    let mut subscription = rig
        .runtime
        .block_on(Subscription::open(Arc::clone(&rig.client)))
        .expect("subscribed");
    assert!(matches!(
        next(&rig, &mut subscription),
        ShareEvent::Snapshot { .. }
    ));

    // A pool connection lost: the request is sent again, and the stream goes
    // on without a break.
    rig.relay.arm(Opcode::Getattr, Cut::DiscardReply);
    rig.runtime
        .block_on(rig.client.getattr(Caller::default(), rig.tree, None))
        .expect("sent again");
    add_rule(&rig, "/tree/docs");
    assert!(
        matches!(next(&rig, &mut subscription), ShareEvent::Added(_)),
        "the stream survived the loss of a connection that is not its own"
    );
    let beside = rig.relay.carried_beside(Opcode::Subscribe);
    let subscribed = beside
        .iter()
        .position(|opcode| *opcode == Opcode::Subscribe)
        .expect("a subscribe was carried");
    assert!(
        beside[subscribed + 1..].is_empty(),
        "the subscribed connection carries no request after its subscribe: {beside:?}"
    );

    // Its own connection lost: taken up again on another.
    rig.relay.end_carriers(Opcode::Subscribe);
    assert_eq!(next(&rig, &mut subscription), ShareEvent::Disconnected);
    assert_eq!(next(&rig, &mut subscription), ShareEvent::Resumed);
    assert!(matches!(
        next(&rig, &mut subscription),
        ShareEvent::Snapshot { .. }
    ));
    assert_eq!(rig.client.state(), MountState::Connected);
}

#[test]
fn losing_the_last_pool_connection_while_dials_fail_keeps_the_session() {
    let rig = rig("connections-last-pool");
    let mut subscription = rig
        .runtime
        .block_on(Subscription::open(Arc::clone(&rig.client)))
        .expect("subscribed");
    assert!(matches!(
        next(&rig, &mut subscription),
        ShareEvent::Snapshot { .. }
    ));
    let file = rig.open(b"beta", O_RDWR);
    assert_eq!(
        rig.client.connections(),
        Some(Connections {
            pooled: 1,
            subscribed: true
        })
    );
    let before = rig.session();
    assert_eq!(before.connections, 2);

    rig.relay.refuse_new(true);
    rig.relay.arm(Opcode::Getattr, Cut::DiscardReply);
    let refused = rig.relay.refused();
    let client = Arc::clone(&rig.client);
    let tree = rig.tree;
    let pending = rig
        .runtime
        .spawn(async move { client.getattr(Caller::default(), tree, None).await });
    rig.ground
        .server
        .until(|| rig.relay.refused() >= refused + 3);
    assert_eq!(rig.client.state(), MountState::Connected);
    // The server sees the lost connection close in its own time, and then
    // holds only the subscribed connection.
    rig.ground.server.until(|| rig.session().connections == 1);
    assert_eq!(
        rig.session().id,
        before.id,
        "the session lives on, on its subscribed connection"
    );
    assert!(!pending.is_finished(), "the request waits for a connection");

    rig.relay.refuse_new(false);
    rig.runtime
        .block_on(pending)
        .expect("joined")
        .expect("the request runs on the connection that joined");
    assert_eq!(rig.session().id, before.id, "in the same session");
    assert_eq!(
        rig.write(file, 0, b"kept"),
        Ok(4),
        "the handle opened before is still valid"
    );
    assert_eq!(rig.client.state(), MountState::Connected);
    add_rule(&rig, "/tree/docs");
    assert!(
        matches!(next(&rig, &mut subscription), ShareEvent::Added(_)),
        "the stream went on without a break"
    );
}

#[test]
fn a_refused_join_ends_the_session_and_the_mount_reconnects() {
    let rig = rig("connections-refused-join");
    // Another server behind the same endpoint, which never saw the session:
    // a connection that joins there is refused.
    let other = Ground::start("connections-refused-join-other");
    rig.relay.redirect(other.server.data_socket());
    let hellos = rig.relay.carried(Opcode::Hello);
    let root = rig.client.root_node_id();

    reconnected_after(&rig.client, || {
        // One request holds the session's one connection, so the next one joins
        // another, and is refused.
        let latch = Latch::default();
        let held = rig
            .relay
            .arm(Opcode::Getattr, Cut::HoldReply(latch.clone()));
        let client = Arc::clone(&rig.client);
        let first = rig
            .runtime
            .spawn(async move { client.getattr(Caller::default(), root, None).await });
        held.recv().expect("the first reply is held");
        rig.runtime
            .block_on(rig.client.getattr(Caller::default(), root, None))
            .expect("served in the new session");
        latch.release();
        rig.runtime
            .block_on(first)
            .expect("joined")
            .expect("sent again in the new session");
    });
    assert!(
        rig.relay.carried(Opcode::Hello) >= hellos + 2,
        "a refused join and the hello of a new session"
    );
    rig.ground
        .server
        .until(|| sessions_of(&rig.ground).is_empty());
    rig.runtime
        .block_on(rig.client.lookup(Caller::default(), root, b"tree"))
        .expect("the new session serves");
}
