//! The share subscription, driven over a real socket against a real server.
//!
//! Everything here is wire-level on purpose: the criteria are about what a
//! subscribed session *receives*, in what order, and about what it must never
//! receive. A test that went through the FUSE client would be asserting on the
//! client's aggregation instead of on the server's stream.
//!
//! The control plane is driven through the real control socket, so every delta
//! is produced by the same validate → persist → swap sequence an operator's
//! command runs.

mod support;

use std::time::Duration;

use support::fixture::Fixture;
use support::wire::{ShareLine, ShareNotification, status};
use support::{Dial, wire::WireClient};
use voidport_control::{Reply, Request, Rule, ShareMode};

/// How long a test waits before calling the server silent.
///
/// Long enough that a loaded machine is not mistaken for a server that said
/// nothing, short enough that a suite asserting silence a few times still
/// finishes quickly.
const SILENCE: Duration = Duration::from_millis(400);

fn name(raw: &str) -> voidport_control::NamespaceName {
    voidport_control::NamespaceName::new(raw).expect("a valid namespace name")
}

/// Adds a rule through the control plane, as an operator would.
fn add_rule(fixture: &Fixture, namespace: &str, rule: Rule) {
    let mut control = fixture.server.connect();
    assert_eq!(
        control.expect_ok(&Request::RuleAdd {
            namespace: name(namespace),
            rule,
        }),
        Reply::Done {}
    );
}

/// Removes a rule through the control plane.
fn remove_rule(fixture: &Fixture, namespace: &str, path: &str) {
    let mut control = fixture.server.connect();
    assert_eq!(
        control.expect_ok(&Request::RuleRemove {
            namespace: name(namespace),
            path: path.to_owned(),
            r#match: None,
        }),
        Reply::Done {}
    );
}

/// Removes a pattern rule, which is keyed by its path and its match together.
fn remove_pattern(fixture: &Fixture, namespace: &str, path: &str, matches: &str) {
    let mut control = fixture.server.connect();
    assert_eq!(
        control.expect_ok(&Request::RuleRemove {
            namespace: name(namespace),
            path: path.to_owned(),
            r#match: Some(matches.to_owned()),
        }),
        Reply::Done {}
    );
}

/// The `subscribed` flag the control plane reports for a session.
fn subscribed_flags(fixture: &Fixture) -> Vec<bool> {
    let mut control = fixture.server.connect();
    let Reply::SessionList { sessions } = control.expect_ok(&Request::SessionList {}) else {
        panic!("session list answers a session list");
    };
    sessions.iter().map(|session| session.subscribed).collect()
}

/// Criterion 1: every subscribe answers a begin/parts/end snapshot listing
/// exactly the literal non-hidden rules the session's scope admits, with modes
/// and kinds — and a second subscribe is the resync path, answering another.
#[test]
fn a_subscription_opens_with_the_sessions_whole_share_set() {
    let fixture = Fixture::start("subscribe-snapshot");
    let mut client = fixture.server.mount("project", "");
    client
        .subscribe()
        .expect("the server accepts a subscription");

    let entries = client.share_snapshot();
    assert_eq!(
        entries,
        vec![
            // The graft itself: a stated target, so its kind was recorded when
            // it was pinned.
            ShareLine::new("/project", "rw", "directory"),
            // Deeper literal rules with derived targets: never pinned, never
            // checked, so their kind is unknown by contract.
            ShareLine::new("/project/bar", "ro", "unknown"),
            ShareLine::new("/project/file.txt", "rw", "unknown"),
            ShareLine::new("/project/foo", "rw", "unknown"),
            // An admitted name that does not exist on the host is still a rule,
            // and therefore still an entry: the set is a pure function of the
            // table, not of the host.
            ShareLine::new("/project/new", "rw", "unknown"),
            // A re-targeted rule states its own target, so its kind is known.
            ShareLine::new("/project/vendor", "ro", "directory"),
        ],
        "the wildcard rule is a policy default, not a share, and the hidden \
         rules never appear"
    );

    // Subscribing again is legal and is the consumer's resync: a fresh
    // snapshot on the same stream.
    client.subscribe().expect("a resubscribe is legal");
    assert_eq!(client.share_snapshot(), entries);
}

/// Criterion 1, the chunked half: a snapshot larger than one frame arrives as
/// several parts bracketed by one begin and one end.
#[test]
fn a_snapshot_too_large_for_one_frame_arrives_in_parts() {
    let fixture = Fixture::start("subscribe-parts");
    // Long rule paths, close to the 4096-byte cap, so a few hundred of them
    // cannot fit one 1 MiB frame.
    let long = "d".repeat(3000);
    for index in 0..500 {
        add_rule(
            &fixture,
            "plain",
            Rule::new(format!("/tree/{index:04}{long}"), ShareMode::Ro),
        );
    }

    let mut client = fixture.server.mount("plain", "");
    client.subscribe().expect("subscribed");

    let ShareNotification::SnapshotBegin { entries } = client.share_event() else {
        panic!("a snapshot starts with its begin marker");
    };
    let mut parts = 0;
    let mut carried = 0;
    loop {
        match client.share_event() {
            ShareNotification::SnapshotPart(part) => {
                parts += 1;
                carried += part.len();
            }
            ShareNotification::SnapshotEnd => break,
            other => panic!("only parts until the end, not {other:?}"),
        }
    }
    assert!(parts > 1, "a snapshot this size needs several parts");
    assert_eq!(carried, entries as usize);
    // 500 added rules plus the two the fixture's `plain` namespace grafts.
    assert_eq!(carried, 502);
}

/// Criterion 2: control-plane edits reach a subscribed guest as the
/// corresponding deltas, and an unsubscribed session receives nothing.
#[test]
fn rule_edits_reach_a_subscriber_as_deltas() {
    let fixture = Fixture::start("subscribe-deltas");
    let mut listener = fixture.server.mount("plain", "");
    let mut silent = fixture.server.mount("plain", "");
    listener.subscribe().expect("subscribed");
    assert_eq!(
        listener.share_snapshot(),
        vec![
            ShareLine::new("/readonly", "ro", "directory"),
            ShareLine::new("/tree", "rw", "directory"),
        ]
    );

    add_rule(&fixture, "plain", Rule::new("/tree/sub", ShareMode::Ro));
    assert_eq!(
        listener.share_event(),
        ShareNotification::Added(ShareLine::new("/tree/sub", "ro", "unknown"))
    );

    // There is no modify operation: an operator's re-mode is a remove followed
    // by an add, and it arrives as the two publishes it was.
    remove_rule(&fixture, "plain", "/tree/sub");
    assert_eq!(
        listener.share_event(),
        ShareNotification::Removed("/tree/sub".to_owned())
    );
    add_rule(&fixture, "plain", Rule::new("/tree/sub", ShareMode::Rw));
    assert_eq!(
        listener.share_event(),
        ShareNotification::Added(ShareLine::new("/tree/sub", "rw", "unknown"))
    );

    // A session that never subscribed receives nothing at all, through all of
    // that churn.
    assert_eq!(
        silent.try_share_event(SILENCE),
        None,
        "a session that never subscribed never receives a notification"
    );
    // And it is still a working session.
    assert!(silent.lookup(support::wire::ROOT, "tree").is_ok());
}

/// Criterion 2's `changed` arm: a single publish that re-modes an entry arrives
/// as one `changed`.
///
/// The control plane's rule edits are one-per-publish, so the single-publish
/// re-mode a session actually observes is an *ancestor* edit that changes the
/// effective mode of the session's own root — one publish, one entry, one
/// changed event.
#[test]
fn a_single_publish_re_mode_arrives_as_changed() {
    let fixture = Fixture::start("subscribe-changed");
    // Mounted inside the share: the session's root is the `/tree` rule.
    let mut client = fixture.server.mount("plain", "/tree/sub");
    client.subscribe().expect("subscribed");
    assert_eq!(
        client.share_snapshot(),
        vec![ShareLine::new("/", "rw", "directory")],
        "a session mounted inside a share reports that share as `/`"
    );

    // One publish adds a literal rule on the mount root itself, which overrides
    // the enclosing graft: the session's `/` changes mode without appearing or
    // disappearing.
    add_rule(&fixture, "plain", Rule::new("/tree/sub", ShareMode::Ro));
    assert_eq!(
        client.share_event(),
        // `directory` whatever rule decides the mode: the mount root was stat'ed
        // at handshake time and a session over anything else was refused, so the
        // kind of `/` is known without asking the host again.
        ShareNotification::Changed(ShareLine::new("/", "ro", "directory")),
        "the mount root's own resolution decides its effective mode"
    );
}

/// Criterion 4's effective-mode half: the `/` entry carries what the data plane
/// *resolves* for the mount root, which a wildcard can decide.
///
/// A wildcard is never an entry — it is a per-directory default, not a share —
/// but it governs the mount root's own component, and resolution gives it the
/// last word over the graft it sits in. So the mode of `/` follows it, and the
/// event fires exactly when that effective mode changes, though no literal rule
/// anywhere names the mount root.
#[test]
fn a_wildcard_over_the_mount_root_decides_the_root_entrys_mode() {
    let fixture = Fixture::start("subscribe-wildcard-root");
    // Mounted inside the `/tree` graft, on a component no literal rule names.
    let mut client = fixture.server.mount("plain", "/tree/sub");
    client.subscribe().expect("subscribed");
    assert_eq!(
        client.share_snapshot(),
        vec![ShareLine::new("/", "rw", "directory")],
        "the enclosing graft is what resolves the mount root, for now"
    );

    // One publish, and it is a *wildcard*: `/tree/*` is the default for the
    // graft's children, so the mount root resolves read-only from here on.
    add_rule(&fixture, "plain", Rule::new("/tree/*", ShareMode::Ro));
    assert_eq!(
        client.share_event(),
        ShareNotification::Changed(ShareLine::new("/", "ro", "directory")),
        "the mount root's effective mode changed, so `/` changed"
    );
    // The wildcard itself is not an entry, so that is the whole of it.
    assert_eq!(client.try_share_event(SILENCE), None);

    // And back: removing it restores the graft's own mode.
    remove_rule(&fixture, "plain", "/tree/*");
    assert_eq!(
        client.share_event(),
        ShareNotification::Changed(ShareLine::new("/", "rw", "directory"))
    );

    // A session mounted *at* the graft is untouched by all of it: the wildcard
    // governs the graft's children, not the graft.
    let mut root = fixture.server.mount("plain", "/tree");
    root.subscribe().expect("subscribed");
    assert_eq!(
        root.share_snapshot(),
        vec![ShareLine::new("/", "rw", "directory")]
    );
    add_rule(&fixture, "plain", Rule::new("/tree/*", ShareMode::Ro));
    assert_eq!(
        root.try_share_event(SILENCE),
        None,
        "a wildcard below the mount root changes nothing the session can see"
    );
}

/// The pattern-rules criterion, asserted with two live subscribers side by
/// side: pattern churn produces no entries and no events for the subscriber
/// mounted at the enclosing share, while the subscriber mounted *inside* a
/// pattern-governed name sees its `/` entry follow the subscription contract's
/// own publish shapes.
///
/// Pattern rules are not entries — the enclosing literal rule's entry covers
/// the subtree — so everything the inner session hears is the `/` rule of the
/// subscription contract, firing exactly when the mount root's effective mode
/// changes.
#[test]
fn pattern_churn_is_silent_at_the_share_and_moves_only_the_inner_root_entry() {
    let fixture = Fixture::start("subscribe-patterns");
    // The motivating composition, established before anything mounts: the
    // graft's children hidden by a bare `*`, one family un-hidden by a match.
    add_rule(&fixture, "plain", Rule::new("/tree/*", ShareMode::Hidden));
    add_rule(
        &fixture,
        "plain",
        Rule::new("/tree", ShareMode::Rw).with_match("sub*"),
    );

    let mut enclosing = fixture.server.mount("plain", "/tree");
    enclosing.subscribe().expect("subscribed");
    assert_eq!(
        enclosing.share_snapshot(),
        vec![ShareLine::new("/", "rw", "directory")],
        "the pattern is not an entry: the enclosing share covers the subtree"
    );

    let mut inside = fixture.server.mount("plain", "/tree/sub");
    inside.subscribe().expect("subscribed");
    assert_eq!(
        inside.share_snapshot(),
        vec![ShareLine::new("/", "rw", "directory")],
        "a session mounted inside a pattern-governed name reports its own root"
    );

    // A two-operation re-mode over the hidden composition: the only legal path
    // is remove then add, and over a hidden default that is `removed` then
    // `added` — the removal is also, by itself, a removal that hides the mount
    // root.
    remove_pattern(&fixture, "plain", "/tree", "sub*");
    assert_eq!(
        inside.share_event(),
        ShareNotification::Removed("/".to_owned()),
        "with the pattern gone the hidden `*` decides the mount root"
    );
    add_rule(
        &fixture,
        "plain",
        Rule::new("/tree", ShareMode::Ro).with_match("sub*"),
    );
    assert_eq!(
        inside.share_event(),
        ShareNotification::Added(ShareLine::new("/", "ro", "directory"))
    );

    // Swap the hidden default for a visible one. The pattern decides the mount
    // root either way, so neither publish changes anything the inner session
    // can see.
    remove_rule(&fixture, "plain", "/tree/*");
    add_rule(&fixture, "plain", Rule::new("/tree/*", ShareMode::Ro));
    assert_eq!(inside.try_share_event(SILENCE), None);

    // Over a non-hidden wildcard, one publish that changes the root's
    // effective mode arrives as one `changed` — in both directions.
    remove_pattern(&fixture, "plain", "/tree", "sub*");
    assert_eq!(
        inside.try_share_event(SILENCE),
        None,
        "the wildcard's mode is the pattern's, so nothing the session sees moved"
    );
    add_rule(
        &fixture,
        "plain",
        Rule::new("/tree", ShareMode::Rw).with_match("sub*"),
    );
    assert_eq!(
        inside.share_event(),
        ShareNotification::Changed(ShareLine::new("/", "rw", "directory"))
    );
    remove_pattern(&fixture, "plain", "/tree", "sub*");
    assert_eq!(
        inside.share_event(),
        ShareNotification::Changed(ShareLine::new("/", "ro", "directory")),
        "a single-publish pattern removal over a non-hidden wildcard is one \
         changed"
    );

    // Through all of it, the subscriber at the enclosing share heard nothing:
    // no entry, no event, for add, re-mode or remove.
    assert_eq!(enclosing.try_share_event(SILENCE), None);
    enclosing.subscribe().expect("a resubscribe is legal");
    assert_eq!(
        enclosing.share_snapshot(),
        vec![ShareLine::new("/", "rw", "directory")],
        "and its entry set is what it always was"
    );
}

/// Criterion 3: hidden never leaks — hidden-rule churn produces no event at
/// all, and the hidden entries are absent from the resolution too.
#[test]
fn hidden_rules_produce_neither_entries_nor_events() {
    let fixture = Fixture::start("subscribe-hidden");
    let mut client = fixture.server.mount("project", "");
    client.subscribe().expect("subscribed");
    let before = client.share_snapshot();
    assert!(
        !before.iter().any(|entry| entry.path.contains("secret")),
        "a hidden rule is not an entry: {before:?}"
    );

    for index in 0..8 {
        add_rule(
            &fixture,
            "project",
            Rule::new(format!("/project/hidden{index}"), ShareMode::Hidden),
        );
    }
    assert_eq!(
        client.try_share_event(SILENCE),
        None,
        "hidden churn is silent on the stream"
    );
    // And what the stream withheld, the resolution withholds too: the probe
    // asserts against resolution itself, not against the stream's word.
    let project = client
        .lookup(support::wire::ROOT, "project")
        .expect("the graft resolves");
    assert_eq!(
        client
            .lookup(project.node_id, "hidden0")
            .expect_err("hidden"),
        status::NOENT
    );
    assert_eq!(
        client
            .lookup(project.node_id, "secret")
            .expect_err("hidden"),
        status::NOENT
    );

    // Removing them again is equally silent.
    for index in 0..8 {
        remove_rule(&fixture, "project", &format!("/project/hidden{index}"));
    }
    assert_eq!(client.try_share_event(SILENCE), None);
}

/// Criterion 4: subpath scoping — a session below the namespace root hears only
/// its own subtree, relative to its mount root, and hears nothing outside it.
#[test]
fn a_subpath_mount_hears_only_its_own_subtree() {
    let fixture = Fixture::start("subscribe-scope");
    let mut client = fixture.server.mount("plain", "/tree");
    client.subscribe().expect("subscribed");
    assert_eq!(
        client.share_snapshot(),
        vec![ShareLine::new("/", "rw", "directory")],
        "the mount root is `/`, and the sibling graft is out of scope"
    );

    // Inside the subtree: reported, relative to the mount root.
    add_rule(&fixture, "plain", Rule::new("/tree/sub", ShareMode::Ro));
    assert_eq!(
        client.share_event(),
        ShareNotification::Added(ShareLine::new("/sub", "ro", "unknown"))
    );

    // Strictly outside it: silent.
    add_rule(&fixture, "plain", Rule::new("/readonly/sub", ShareMode::Rw));
    assert_eq!(
        client.try_share_event(SILENCE),
        None,
        "a rule outside the session's subtree is not its business"
    );
}

/// Criterion 10, the lifecycle half: deleting the namespace ends the stream
/// with `ended` while the tombstoned session keeps serving, and a `Subscribe`
/// against the tombstoned session is refused.
#[test]
fn deleting_the_namespace_ends_the_stream_and_the_session_serves_on() {
    let fixture = Fixture::start("subscribe-lifecycle");
    let mut client = fixture.server.mount("plain", "");
    client.subscribe().expect("subscribed");
    let _ = client.share_snapshot();
    // A node named before the deletion, to prove the tombstone still serves.
    let tree = client
        .lookup(support::wire::ROOT, "tree")
        .expect("the graft resolves");

    let mut control = fixture.server.connect();
    assert_eq!(
        control.expect_ok(&Request::NamespaceDelete {
            name: name("plain")
        }),
        Reply::Done {}
    );

    assert_eq!(
        client.share_event(),
        ShareNotification::Ended(1),
        "a deleted namespace ends the stream, reason: namespace removed"
    );
    assert_eq!(
        client.try_share_event(SILENCE),
        None,
        "and nothing follows an ended stream"
    );

    // The session keeps serving on its tombstone, exactly as the lifecycle
    // rules say.
    assert!(client.getattr(tree.node_id).is_ok());
    assert!(client.lookup(support::wire::ROOT, "tree").is_ok());

    // A subscribe against the tombstoned session is refused.
    assert_eq!(
        client.subscribe().expect_err("a tombstone cannot change"),
        status::NOENT
    );
}

/// Criterion 6's operator half, plus the `Unsubscribe` no-op: the session list
/// reports the flag, and unsubscribing a session that has no subscription is a
/// plain success.
#[test]
fn the_session_list_reports_the_subscription_and_unsubscribe_is_idempotent() {
    let fixture = Fixture::start("subscribe-flag");
    let mut client = fixture.server.mount("plain", "");
    assert_eq!(subscribed_flags(&fixture), vec![false]);

    client.subscribe().expect("subscribed");
    let _ = client.share_snapshot();
    assert_eq!(subscribed_flags(&fixture), vec![true]);

    // Unsubscribing ends the stream without costing the connection.
    client.unsubscribe().expect("unsubscribed");
    assert_eq!(subscribed_flags(&fixture), vec![false]);
    add_rule(&fixture, "plain", Rule::new("/tree/sub", ShareMode::Ro));
    assert_eq!(
        client.try_share_event(SILENCE),
        None,
        "an unsubscribed session receives nothing"
    );

    // A second unsubscribe is a plain success — that is what makes it
    // idempotent, replay across a reconnect included.
    client.unsubscribe().expect("a no-op is a success");
    client.unsubscribe().expect("and stays one");
    // The session is still perfectly usable.
    assert!(client.lookup(support::wire::ROOT, "tree").is_ok());

    // And it can subscribe again, from scratch.
    client.subscribe().expect("resubscribed");
    assert!(
        client
            .share_snapshot()
            .iter()
            .any(|entry| entry.path == "/tree/sub")
    );
}

/// Criterion 9: a client that never subscribes is byte-compatible, and the
/// unknown-opcode path is what a probe against an older server would meet.
#[test]
fn an_unsubscribed_session_is_byte_identical_and_unknown_opcodes_stay_semantic() {
    use voidport_proto::frame::{FrameWriter, MAX_HELLO_FRAME_LEN};
    use voidport_proto::message::RequestHead;
    use voidport_proto::ops::node::GetattrRequest;
    use zerocopy::byteorder::little_endian::{U32, U64};

    let fixture = Fixture::start("subscribe-abi");
    let mut client: WireClient = fixture.server.mount("plain", "");

    // A whole ordinary exchange, with the subscription present in the build and
    // absent from the session: nothing extra arrives, ever.
    for _ in 0..8 {
        assert!(client.lookup(support::wire::ROOT, "tree").is_ok());
    }
    assert_eq!(client.try_share_event(SILENCE), None);

    // The discovery mechanism a client probing a *newer* op against an older
    // server meets: a well-framed request with an unknown opcode is answered
    // ENOSYS and the connection lives on.
    let head = RequestHead::new(support::wire::ROOT, 0, 0, 0);
    let body = GetattrRequest {
        handle: U64::ZERO,
        flags: U32::ZERO,
        reserved: U32::ZERO,
    };
    let mut buffer = [0u8; 128];
    let frame = FrameWriter::request(&mut buffer, MAX_HELLO_FRAME_LEN, 9999, &head, &body)
        .and_then(FrameWriter::finish)
        .expect("encodable");
    let mut bytes = frame.to_vec();
    // Re-stamp the opcode as one no build assigns, leaving the rest untouched.
    bytes[4..6].copy_from_slice(&0x7FFEu16.to_le_bytes());
    client.send_bytes(&bytes);
    let reply = client.receive().expect("a semantic error, not a close");
    let parsed = voidport_proto::frame::Frame::parse(&reply, client.max_frame_len())
        .expect("a well-framed reply");
    assert_eq!(
        parsed.raw_opcode(),
        0x7FFE,
        "an error response echoes the opcode"
    );
    assert_eq!(parsed.request_id(), 9999);
    // And the connection lives.
    assert!(client.lookup(support::wire::ROOT, "tree").is_ok());
}

/// Criterion 5: linearization. A subscriber that registers while the control
/// plane mutates concurrently misses no delta relative to its snapshot and
/// receives none that predates it.
///
/// The reconstruction is what proves it: the snapshot plus every delta must
/// equal the set the server would report *now*, whatever instant the
/// registration landed in relative to the publishes.
#[test]
fn registration_linearizes_against_publication() {
    let fixture = Fixture::start("subscribe-linearization");
    const ROUNDS: usize = 24;

    for round in 0..ROUNDS {
        let path = format!("/tree/churn{round}");
        let churn = {
            let path = path.clone();
            let socket = fixture.server.socket().to_path_buf();
            std::thread::spawn(move || {
                let mut control = voidportd::testing::ControlClient::connect(&socket)
                    .expect("the control socket accepts connections");
                control.expect_ok(&Request::RuleAdd {
                    namespace: voidport_control::NamespaceName::new("plain").expect("valid"),
                    rule: Rule::new(path, ShareMode::Ro),
                });
            })
        };

        let mut client = fixture.server.mount("plain", "");
        client.subscribe().expect("subscribed");
        let mut reconstructed: Vec<ShareLine> = client.share_snapshot();
        churn.join().expect("the mutation finishes");

        // Drain whatever deltas the registration did not already include, then
        // reconcile: the two together must name the same set either way.
        while let Some(event) = client.try_share_event(SILENCE) {
            match event {
                ShareNotification::Added(entry) => reconstructed.push(entry),
                ShareNotification::Removed(path) => {
                    reconstructed.retain(|entry| entry.path != path);
                }
                ShareNotification::Changed(entry) => {
                    reconstructed.retain(|held| held.path != entry.path);
                    reconstructed.push(entry);
                }
                other => panic!("a settled stream carries only deltas, not {other:?}"),
            }
        }
        reconstructed.sort_by(|left, right| left.path.cmp(&right.path));

        // What a fresh subscriber sees now is the truth to compare against.
        let mut fresh = fixture.server.mount("plain", "");
        fresh.subscribe().expect("subscribed");
        let mut truth = fresh.share_snapshot();
        truth.sort_by(|left, right| left.path.cmp(&right.path));

        assert_eq!(
            reconstructed, truth,
            "round {round}: the snapshot plus its deltas must reconstruct the \
             published set exactly — no delta missed, none from before the \
             snapshot"
        );
    }
}

/// Criterion 6: a consumer that lets its queue fill lapses instead of stalling
/// anything else.
///
/// The consumer here is deliberately the worst case the contract isolates: it
/// stops reading its socket, so the server's writer blocks and the notification
/// queue behind it is what fills. What must keep working through that is
/// everything *else* — the operator's control plane, and another session's file
/// I/O — and the laggard must be handed an unsolicited fresh snapshot, not
/// a stalled or poisoned connection.
#[test]
fn a_consumer_that_lets_its_queue_fill_lapses_and_costs_nobody_else() {
    let fixture = Fixture::start("subscribe-lapse");
    // Over the unix listener deliberately: its socket buffer is a fixed kernel
    // default, not an autotuning tcp window, so what the socket in front
    // of the queue can absorb is bounded by a number that does not move between
    // machines. That is what makes "the queue is what fills" a property of this
    // test, not a hope.
    let mut laggard =
        WireClient::unix(fixture.server.data_unix()).expect("the unix data listener accepts");
    laggard.hello("plain", "").expect("mounted");
    laggard.subscribe().expect("subscribed");
    let opening = laggard.share_snapshot();
    assert_eq!(opening.len(), 2, "the fixture's two grafts");

    // A second session, mounted and reading normally: this is what must not be
    // disturbed by the laggard's burst.
    let mut working = fixture.server.mount("plain", "");
    let tree = working
        .lookup(support::wire::ROOT, "tree")
        .expect("the graft resolves");

    // Paths long enough that each delta is a kilobyte, so the queue's depth is
    // reached before the socket has swallowed the whole burst.
    let long = "p".repeat(4000);
    const BURST: usize = 600;
    for index in 0..BURST {
        add_rule(
            &fixture,
            "plain",
            Rule::new(format!("/tree/{index:04}{long}"), ShareMode::Ro),
        );
        // Every tenth mutation, prove the two things the contract promises
        // cannot be hurt by a stalled subscriber.
        if index % 100 == 0 {
            assert!(
                working.getattr(tree.node_id).is_ok(),
                "another session's file I/O proceeds while a subscriber stalls"
            );
            assert_eq!(
                subscribed_flags(&fixture)
                    .iter()
                    .filter(|subscribed| **subscribed)
                    .count(),
                1,
                "the operator sees the session as subscribed throughout"
            );
        }
    }

    // Now the laggard reads. It gets whatever the socket held, and then — since
    // its queue was dropped — an *unsolicited* snapshot, which is the lapse
    // signal: there is no lapse message on the wire.
    let mut lapsed = false;
    let mut entries = Vec::new();
    for _ in 0..(BURST * 4) {
        match laggard
            .try_share_event(Duration::from_secs(10))
            .expect("the laggard's connection is alive")
        {
            ShareNotification::SnapshotBegin { .. } => {
                lapsed = true;
                entries.clear();
            }
            ShareNotification::SnapshotPart(part) if lapsed => entries.extend(part),
            ShareNotification::SnapshotEnd if lapsed => break,
            // Deltas the socket had already taken before the queue filled.
            ShareNotification::Added(_)
            | ShareNotification::Changed(_)
            | ShareNotification::Removed(_) => {}
            other => panic!("unexpected {other:?} before the lapse"),
        }
    }
    assert!(
        lapsed,
        "a queue that filled is dropped, and the resnapshot is how the consumer \
         learns it"
    );
    assert_eq!(
        entries.len(),
        BURST + 2,
        "the unsolicited snapshot is the whole, current set"
    );

    // The connection was never poisoned: the session still serves.
    assert!(laggard.lookup(support::wire::ROOT, "tree").is_ok());
    assert_eq!(subscribed_flags(&fixture).iter().filter(|s| **s).count(), 1);
}

/// Criterion 11: a rule path over the cap is refused at add time with a clear
/// error, and a hand-written state file carrying one refuses startup naming the
/// rule.
///
/// The cap is what makes "one entry always fits one notification frame" true by
/// construction, not by inspection, which is why it belongs to this
/// increment.
#[test]
fn rule_paths_are_capped_at_add_time_and_at_load() {
    use voidport_control::ErrorCode;

    let fixture = Fixture::start("subscribe-path-cap");
    let over = format!("/{}", "a".repeat(voidportd::rules::MAX_RULE_PATH_LEN));
    assert_eq!(over.len(), voidportd::rules::MAX_RULE_PATH_LEN + 1);

    let mut control = fixture.server.connect();
    let error = control.expect_error(&Request::RuleAdd {
        namespace: name("plain"),
        rule: Rule::new(over.clone(), ShareMode::Hidden),
    });
    assert_eq!(error.code, ErrorCode::InvalidConfiguration);
    assert!(
        error.message.contains("4096"),
        "the error names the cap: {}",
        error.message
    );

    // The cap itself is legal, so nothing an operator could reasonably write is
    // refused with it.
    assert_eq!(
        control.expect_ok(&Request::RuleAdd {
            namespace: name("plain"),
            rule: Rule::new(
                &over[..voidportd::rules::MAX_RULE_PATH_LEN],
                ShareMode::Hidden
            ),
        }),
        Reply::Done {}
    );

    // A hand-written state file — nothing the control plane can produce, but a
    // file an operator can write — refuses startup, naming the rule.
    let directory = support::TempDir::new("subscribe-path-cap-load");
    let graft = directory.directory("tree");
    let state = format!(
        r#"
[[namespaces]]
name = "handwritten"

[[namespaces.rules]]
path = "{graft}"
mode = "rw"
target = "{graft}"

[[namespaces.rules]]
path = "{over}"
mode = "hidden"
"#,
        graft = graft.display(),
    );
    let state_file = directory.write("state.toml", &state);
    let config =
        voidportd::testing::daemon_config(&state_file, support::environment(directory.path()));
    let error = support::RunningServer::start(&config)
        .expect_err("a state file with an oversized rule path refuses startup");
    let rendered = voidportd::error::render(&error);
    assert!(
        rendered.contains("4096"),
        "startup names the cap: {rendered}"
    );
}

/// Criterion 10's I/O half: a session that is both subscribed and serving files
/// is not disturbed by an event storm, as long as its consumer drains.
///
/// The consumer here is the ordinary one the contract isolates for: it reads
/// its socket. Its own `getattr` latency is measured *through* the storm — the
/// replies and the notifications share one stream — and must stay in the
/// millisecond range the same session shows when nothing is happening.
#[test]
fn a_subscribed_session_serving_files_is_undisturbed_by_an_event_storm() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Instant;

    let fixture = Fixture::start("subscribe-latency");
    let mut client = fixture.server.mount("plain", "");
    let tree = client
        .lookup(support::wire::ROOT, "tree")
        .expect("the graft resolves");

    // The quiet baseline, before anything is subscribed or storming.
    let mut quiet = Duration::ZERO;
    for _ in 0..50 {
        let (elapsed, drained) = client.timed_getattr(tree.node_id);
        assert_eq!(drained, 0, "nothing is subscribed yet");
        quiet = quiet.max(elapsed);
    }

    client.subscribe().expect("subscribed");
    let _ = client.share_snapshot();

    let storming = std::sync::Arc::new(AtomicBool::new(true));
    let published = std::sync::Arc::new(AtomicUsize::new(0));
    let storm = {
        let storming = std::sync::Arc::clone(&storming);
        let published = std::sync::Arc::clone(&published);
        let socket = fixture.server.socket().to_path_buf();
        std::thread::spawn(move || {
            let mut control = voidportd::testing::ControlClient::connect(&socket)
                .expect("the control socket accepts connections");
            let mut index = 0;
            while storming.load(Ordering::Relaxed) {
                control.expect_ok(&Request::RuleAdd {
                    namespace: voidport_control::NamespaceName::new("plain").expect("valid"),
                    rule: Rule::new(format!("/tree/storm{index}"), ShareMode::Ro),
                });
                index += 1;
                published.store(index, Ordering::Relaxed);
            }
            index
        })
    };

    // Nothing is measured until the storm is actually storming: the thread has
    // a control socket to connect and a first rule to publish, and on a machine
    // that schedules it late — a build sandbox with few cores, say — a
    // measurement loop could otherwise run to completion against a quiet server
    // and stop the storm before its first publish.
    let waiting = Instant::now();
    while published.load(Ordering::Relaxed) == 0 {
        assert!(
            waiting.elapsed() < Duration::from_secs(30),
            "the storm never got going"
        );
        std::thread::yield_now();
    }

    let mut stormed = Duration::ZERO;
    let mut drained_total = 0;
    for _ in 0..200 {
        let (elapsed, drained) = client.timed_getattr(tree.node_id);
        stormed = stormed.max(elapsed);
        drained_total += drained;
    }
    storming.store(false, Ordering::Relaxed);
    let published = storm.join().expect("the storm finishes");

    assert!(published > 0, "the storm published something");
    assert!(
        drained_total > 0,
        "the session really was draining notifications while it worked"
    );
    // The bound is generous on purpose — this is a shared machine and the
    // subject is "no *disturbance*", not a benchmark. What it catches is the
    // failure mode that matters: a publish that made the request path wait on
    // a subscriber would show up here as tens or hundreds of milliseconds.
    assert!(
        stormed < Duration::from_millis(250),
        "file I/O on a subscribed session stalled during an event storm: \
         {stormed:?} against a quiet {quiet:?}"
    );
}
