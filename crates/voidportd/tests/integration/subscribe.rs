#![forbid(unsafe_code)]

use voidport_test_server as support;

use support::Dial;
use support::fixture::Fixture;
use support::wire::{ShareLine, ShareNotification, WireClient, status};
use voidport_control::{Reply, Request, Rule, ShareMode};

fn name(raw: &str) -> voidport_control::NamespaceName {
    voidport_control::NamespaceName::new(raw).expect("a valid namespace name")
}

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

fn assert_silent(
    fixture: &Fixture,
    namespace: &str,
    parent: &str,
    clients: &mut [&mut WireClient],
    why: &str,
) {
    let heard = fixture.share_events_before(namespace, parent, clients);
    assert!(heard.iter().all(Vec::is_empty), "{why}: {heard:?}");
}

fn assert_unsubscribed_and_silent(client: &mut WireClient, why: &str) {
    assert_eq!(client.getattr_draining(support::wire::ROOT), 0, "{why}");
}

fn subscribed_flags(fixture: &Fixture) -> Vec<bool> {
    let mut control = fixture.server.connect();
    let Reply::SessionList { sessions } = control.expect_ok(&Request::SessionList {}) else {
        panic!("session list answers a session list");
    };
    sessions.iter().map(|session| session.subscribed).collect()
}

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
            // The graft sets a target, so its kind was recorded when it was
            // opened.
            ShareLine::new("/project", "rw", "directory"),
            // Deeper literal rules with derived targets are never opened, so
            // their kind is unknown.
            ShareLine::new("/project/bar", "ro", "unknown"),
            ShareLine::new("/project/file.txt", "rw", "unknown"),
            ShareLine::new("/project/foo", "rw", "unknown"),
            // An admitted name that does not exist on the host is still a rule, and the
            // set is a function of the table, not of the host.
            ShareLine::new("/project/new", "rw", "unknown"),
            ShareLine::new("/project/vendor", "ro", "directory"),
        ],
        "the wildcard rule is a policy default, not a share, and the hidden \
         rules never appear"
    );

    client.subscribe().expect("a resubscribe is legal");
    assert_eq!(client.share_snapshot(), entries);
}

#[test]
fn a_large_snapshot_arrives_as_one_streamed_part() {
    let fixture = Fixture::start("subscribe-parts");
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
    assert_eq!(parts, 1, "the whole snapshot streams as one part");
    assert_eq!(carried, entries as usize);
    // 500 added rules plus the two that the `plain` namespace of the fixture grafts.
    assert_eq!(carried, 502);
}

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

    // There is no modify operation: a re-mode is a remove followed by an add.
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

    assert_eq!(subscribed_flags(&fixture), vec![true, false]);
    assert_unsubscribed_and_silent(
        &mut silent,
        "a session that never subscribed never receives a notification",
    );
    assert!(silent.lookup(support::wire::ROOT, "tree").is_ok());
}

/// The rule edits of the control plane are one per publish, so the single-publish
/// re-mode that a session observes is an ancestor edit that changes the
/// effective mode of its root.
#[test]
fn a_single_publish_re_mode_arrives_as_changed() {
    let fixture = Fixture::start("subscribe-changed");
    let mut client = fixture.server.mount("plain", "/tree/sub");
    client.subscribe().expect("subscribed");
    assert_eq!(
        client.share_snapshot(),
        vec![ShareLine::new("/", "rw", "directory")],
        "a session mounted inside a share reports that share as `/`"
    );

    add_rule(&fixture, "plain", Rule::new("/tree/sub", ShareMode::Ro));
    assert_eq!(
        client.share_event(),
        // The mount root was stat'ed at handshake time and a session over anything else
        // was refused, so the kind of `/` is known without asking the host again.
        ShareNotification::Changed(ShareLine::new("/", "ro", "directory")),
        "the mount root's own resolution decides its effective mode"
    );
}

/// A wildcard is never an entry, but it sets the mode of the mount root over the
/// mode of the graft, so the event fires exactly when that
/// effective mode changes.
#[test]
fn a_wildcard_over_the_mount_root_decides_the_root_entrys_mode() {
    let fixture = Fixture::start("subscribe-wildcard-root");
    let mut client = fixture.server.mount("plain", "/tree/sub");
    client.subscribe().expect("subscribed");
    assert_eq!(
        client.share_snapshot(),
        vec![ShareLine::new("/", "rw", "directory")],
        "the enclosing graft is what resolves the mount root, for now"
    );

    add_rule(&fixture, "plain", Rule::new("/tree/*", ShareMode::Ro));
    assert_eq!(
        client.share_event(),
        ShareNotification::Changed(ShareLine::new("/", "ro", "directory")),
        "the mount root's effective mode changed, so `/` changed"
    );
    assert_silent(
        &fixture,
        "plain",
        "/tree/sub",
        &mut [&mut client],
        "the wildcard is not an entry",
    );

    remove_rule(&fixture, "plain", "/tree/*");
    assert_eq!(
        client.share_event(),
        ShareNotification::Changed(ShareLine::new("/", "rw", "directory"))
    );

    let mut root = fixture.server.mount("plain", "/tree");
    root.subscribe().expect("subscribed");
    assert_eq!(
        root.share_snapshot(),
        vec![ShareLine::new("/", "rw", "directory")]
    );
    add_rule(&fixture, "plain", Rule::new("/tree/*", ShareMode::Ro));
    assert_silent(
        &fixture,
        "plain",
        "/tree",
        &mut [&mut root],
        "a wildcard below the mount root changes nothing the session can see",
    );
}

#[test]
fn pattern_churn_is_silent_at_the_share_and_moves_only_the_inner_root_entry() {
    let fixture = Fixture::start("subscribe-patterns");
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

    // Over a hidden default a re-mode is `removed` then `added`, and the removal by
    // itself hides the mount root.
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

    // The pattern decides the mount root either way, so neither publish changes
    // anything the inner session can see.
    remove_rule(&fixture, "plain", "/tree/*");
    add_rule(&fixture, "plain", Rule::new("/tree/*", ShareMode::Ro));
    assert_silent(
        &fixture,
        "plain",
        "/tree/sub",
        &mut [&mut inside, &mut enclosing],
        "swapping the default changes nothing the sessions see",
    );

    remove_pattern(&fixture, "plain", "/tree", "sub*");
    assert_silent(
        &fixture,
        "plain",
        "/tree/sub",
        &mut [&mut inside, &mut enclosing],
        "the wildcard's mode is the pattern's, so nothing the sessions see moved",
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

    assert_silent(
        &fixture,
        "plain",
        "/tree",
        &mut [&mut enclosing],
        "pattern churn is silent at the enclosing share",
    );
    enclosing.subscribe().expect("a resubscribe is legal");
    assert_eq!(
        enclosing.share_snapshot(),
        vec![ShareLine::new("/", "rw", "directory")],
        "and its entry set is what it always was"
    );
}

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
    assert_silent(
        &fixture,
        "project",
        "/project",
        &mut [&mut client],
        "hidden churn is silent on the stream",
    );
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

    for index in 0..8 {
        remove_rule(&fixture, "project", &format!("/project/hidden{index}"));
    }
    assert_silent(
        &fixture,
        "project",
        "/project",
        &mut [&mut client],
        "removing hidden rules is silent too",
    );
}

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

    add_rule(&fixture, "plain", Rule::new("/tree/sub", ShareMode::Ro));
    assert_eq!(
        client.share_event(),
        ShareNotification::Added(ShareLine::new("/sub", "ro", "unknown"))
    );

    add_rule(&fixture, "plain", Rule::new("/readonly/sub", ShareMode::Rw));
    assert_silent(
        &fixture,
        "plain",
        "/tree",
        &mut [&mut client],
        "a rule outside the session's subtree is not its business",
    );
}

/// The stream diffs the entry set scoped to the session, not the rule table, and
/// here the two disagree: the wildcard re-modes every name in the directory
/// except the one claimed by a literal rule, the root of this session. Fanning
/// rule-table changes out would send a spurious `changed`.
#[test]
fn an_ancestor_default_the_mount_roots_own_rule_overrides_is_silent() {
    let fixture = Fixture::start("subscribe-override");
    add_rule(&fixture, "plain", Rule::new("/tree/sub", ShareMode::Rw));

    let mut client = fixture.server.mount("plain", "/tree/sub");
    client.subscribe().expect("subscribed");
    assert_eq!(
        client.share_snapshot(),
        vec![ShareLine::new("/", "rw", "directory")],
        "the session's own rule is what resolves its mount root"
    );

    add_rule(&fixture, "plain", Rule::new("/tree/*", ShareMode::Ro));
    assert_silent(
        &fixture,
        "plain",
        "/tree/sub",
        &mut [&mut client],
        "a default the mount root's own rule overrides is not a change to it",
    );

    // The silence was the diff and not a dead stream: without the overriding rule
    // the same wildcard decides the root, which the session does hear.
    remove_rule(&fixture, "plain", "/tree/sub");
    assert_eq!(
        client.share_event(),
        ShareNotification::Changed(ShareLine::new("/", "ro", "directory")),
        "with nothing overriding it, the default is what `/` resolves to"
    );
}

#[test]
fn deleting_the_namespace_ends_the_stream_and_the_session_serves_on() {
    let fixture = Fixture::start("subscribe-lifecycle");
    let mut client = fixture.server.mount("plain", "");
    client.subscribe().expect("subscribed");
    let _ = client.share_snapshot();
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
        subscribed_flags(&fixture),
        vec![false],
        "and nothing follows an ended stream: the session holds no subscription"
    );

    assert!(client.getattr(tree.node_id).is_ok());
    assert!(client.lookup(support::wire::ROOT, "tree").is_ok());

    assert_eq!(
        client.subscribe().expect_err("a tombstone cannot change"),
        status::NOENT
    );
}

/// A subscription is registered before its confirm is written. The test repeats
/// because a registration made after the confirm shows only when the list is
/// read late enough.
#[test]
fn a_subscribe_whose_confirm_has_arrived_is_already_in_the_session_list() {
    let fixture = Fixture::start("subscribe-confirm-listed");
    let mut client = fixture.server.mount("plain", "");
    for _ in 0..8 {
        client.subscribe().expect("the confirm arrives first");
        assert_eq!(subscribed_flags(&fixture), vec![true]);
        let _ = client.share_snapshot();
        client.unsubscribe().expect("unsubscribed");
        assert_eq!(subscribed_flags(&fixture), vec![false]);
    }
}

#[test]
fn the_session_list_reports_the_subscription_and_unsubscribe_is_idempotent() {
    let fixture = Fixture::start("subscribe-flag");
    let mut client = fixture.server.mount("plain", "");
    assert_eq!(subscribed_flags(&fixture), vec![false]);

    client.subscribe().expect("subscribed");
    let _ = client.share_snapshot();
    assert_eq!(subscribed_flags(&fixture), vec![true]);

    client.unsubscribe().expect("unsubscribed");
    assert_eq!(subscribed_flags(&fixture), vec![false]);
    add_rule(&fixture, "plain", Rule::new("/tree/sub", ShareMode::Ro));
    assert_unsubscribed_and_silent(&mut client, "an unsubscribed session receives nothing");

    client.unsubscribe().expect("a no-op is a success");
    client.unsubscribe().expect("and stays one");
    assert!(client.lookup(support::wire::ROOT, "tree").is_ok());

    client.subscribe().expect("resubscribed");
    assert!(
        client
            .share_snapshot()
            .iter()
            .any(|entry| entry.path == "/tree/sub")
    );
}

#[test]
fn an_unsubscribed_session_receives_nothing_extra() {
    let fixture = Fixture::start("subscribe-abi");
    let mut client: WireClient = fixture.server.mount("plain", "");
    for _ in 0..8 {
        assert!(client.lookup(support::wire::ROOT, "tree").is_ok());
    }
    assert_eq!(subscribed_flags(&fixture), vec![false]);
    assert_unsubscribed_and_silent(&mut client, "nothing extra arrives");
}

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
                let mut control = voidport_test_support::ControlClient::connect(&socket)
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

        let deltas = fixture
            .share_events_before("plain", "/tree", &mut [&mut client])
            .pop()
            .expect("the list of the client");
        for event in deltas {
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

/// The consumer stops reading its socket, so the notification task of the
/// server blocks and the queue behind it fills. The control plane and the file
/// I/O of another session must keep working, and the slow consumer is handed an
/// unsolicited fresh snapshot, not a stalled or poisoned connection.
#[test]
fn a_consumer_that_lets_its_queue_fill_lapses_and_costs_nobody_else() {
    let fixture = Fixture::start("subscribe-lapse");
    let mut laggard = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    laggard.hello("plain", "").expect("mounted");
    laggard.subscribe().expect("subscribed");
    let opening = laggard.share_snapshot();
    assert_eq!(opening.len(), 2, "the fixture's two grafts");

    let mut working = fixture.server.mount("plain", "");
    let tree = working
        .lookup(support::wire::ROOT, "tree")
        .expect("the graft resolves");

    let long = "p".repeat(4000);
    // The server writes into its end of the unix socket until the send buffer
    // of that end is full, and that buffer starts at the size of the buffer of
    // this end. Every notification is longer than the path it contains, so this
    // many fill the socket, one more waits in the blocked writer, and the rest
    // fill the queue one past its depth.
    let in_socket = laggard.send_buffer_size() / format!("/tree/0000{long}").len() + 1;
    let burst = in_socket + 1 + voidportd::data::subscribe::NOTIFICATION_QUEUE_DEPTH + 1;
    for index in 0..burst {
        add_rule(
            &fixture,
            "plain",
            Rule::new(format!("/tree/{index:04}{long}"), ShareMode::Ro),
        );
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

    let mut lapsed = false;
    let mut entries = Vec::new();
    for _ in 0..(burst * 4) {
        match laggard.share_event() {
            ShareNotification::SnapshotBegin { .. } => {
                lapsed = true;
                entries.clear();
            }
            ShareNotification::SnapshotPart(part) if lapsed => entries.extend(part),
            ShareNotification::SnapshotEnd if lapsed => break,
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
        burst + 2,
        "the unsolicited snapshot is the whole, current set"
    );

    assert!(laggard.lookup(support::wire::ROOT, "tree").is_ok());
    assert_eq!(subscribed_flags(&fixture).iter().filter(|s| **s).count(), 1);
}

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
    let config = voidport_test_support::daemon_config(&state_file);
    let error = support::RunningServer::start(&config)
        .expect_err("a state file with an oversized rule path refuses startup");
    let rendered = voidportd::error::render(&error);
    assert!(
        rendered.contains("4096"),
        "startup names the cap: {rendered}"
    );
}

#[test]
fn a_subscribed_session_serving_files_receives_every_event_of_a_storm() {
    const EVENTS: usize = 200;

    let fixture = Fixture::start("subscribe-dispatch");
    let mut client = fixture.server.mount("plain", "");
    let tree = client
        .lookup(support::wire::ROOT, "tree")
        .expect("the graft resolves");
    client.subscribe().expect("subscribed");
    let opening = client.share_snapshot();

    let mut drained = 0;
    for index in 0..EVENTS {
        add_rule(
            &fixture,
            "plain",
            Rule::new(format!("/tree/storm{index}"), ShareMode::Ro),
        );
        if index % 20 == 0 {
            drained += client.getattr_draining(tree.node_id);
        }
    }
    let rest = fixture
        .share_events_before("plain", "/tree", &mut [&mut client])
        .pop()
        .expect("the list of the client");
    assert!(
        rest.iter()
            .all(|event| matches!(event, ShareNotification::Added(_))),
        "the burst contains only additions: {rest:?}"
    );
    assert_eq!(opening.len() + drained + rest.len(), EVENTS + 2);
    assert!(client.getattr(tree.node_id).is_ok());
}
