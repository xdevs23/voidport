#![forbid(unsafe_code)]

mod support;

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixListener;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use voidport_control::client::Timeouts;
use voidport_control::{Listener, OwnershipSpec, Request};
use voidport_tui::client::{Backoff, Session};
use voidport_tui::event::Event;
use voidport_tui::model::{Connection, Dialog, Screen, Tone};

use support::{Harness, STATE, fixture, patience};

fn press(harness: &mut Harness, code: KeyCode) {
    harness.feed(Event::Key(KeyEvent::new(code, KeyModifiers::NONE)));
}

fn type_text(harness: &mut Harness, text: &str) {
    for character in text.chars() {
        press(harness, KeyCode::Char(character));
    }
}

#[test]
fn attaching_reads_every_screen_and_quitting_leaves_the_server_serving() {
    let (directory, server) = fixture("attach");
    let mut harness = Harness::attach(server.socket()).expect("the control socket accepts");

    // The fixture configures port 0, so the bound endpoint can only come from
    // the server.
    assert!(
        harness.until(patience(), |model| model.server.ready().is_some()),
        "the overview never arrived: {:?}",
        harness.model.status
    );
    let facts = harness.model.server.ready().expect("read").clone();
    assert_eq!(facts.control_socket, server.socket().display().to_string());
    let tcp = facts
        .listeners
        .iter()
        .find(|listener| listener.transport == "tcp")
        .expect("the fixture binds a tcp listener");
    assert_eq!(tcp.endpoint, server.data_tcp().to_string());
    assert!(
        facts
            .listeners
            .iter()
            .any(|listener| listener.transport == "unix"),
        "{:?}",
        facts.listeners
    );

    press(&mut harness, KeyCode::Char('2'));
    assert!(harness.until(patience(), |model| model.namespaces.ready().is_some()));
    assert_eq!(harness.model.namespace_keys(), vec!["project"]);

    for (key, screen) in [
        (KeyCode::Char('3'), Screen::Rules),
        (KeyCode::Char('4'), Screen::Ownership),
        (KeyCode::Char('5'), Screen::Modes),
    ] {
        press(&mut harness, key);
        assert_eq!(harness.model.screen, screen);
        assert!(
            harness.until(patience(), |model| model.namespace_spec().is_some()),
            "{screen:?} never read its namespace"
        );
    }
    press(&mut harness, KeyCode::Char('6'));
    assert!(harness.until(patience(), |model| model.sessions.ready().is_some()));
    press(&mut harness, KeyCode::Char('1'));
    assert_eq!(harness.model.screen, Screen::Overview);

    press(&mut harness, KeyCode::Char('q'));
    assert!(harness.model.finished);
    harness.stop();

    let mut client = server.connect();
    client.expect_ok(&Request::ServerInfo {});
    drop(directory);
}

#[test]
fn the_overview_follows_a_listener_added_and_removed_while_it_watches() {
    let (directory, server) = fixture("listeners");
    let mut harness = Harness::attach(server.socket()).expect("the control socket accepts");
    assert!(
        harness.until(patience(), |model| model.server.ready().is_some()),
        "the overview never arrived: {:?}",
        harness.model.status
    );

    let path = directory.join("added.sock");
    let mut client = server.connect();
    client.expect_ok(&Request::ListenerAdd {
        listener: Listener::Unix { path: path.clone() },
    });

    let endpoint = path.display().to_string();
    let shows = |model: &voidport_tui::Model, endpoint: &str| {
        model.server.ready().is_some_and(|facts| {
            facts
                .listeners
                .iter()
                .any(|listener| listener.endpoint == endpoint)
        })
    };
    assert!(
        harness.until(patience(), |model| shows(model, &endpoint)),
        "the added listener never appeared: {:?}",
        harness
            .model
            .server
            .ready()
            .map(|facts| facts.listeners.clone())
    );

    client.expect_ok(&Request::ListenerRemove {
        endpoint: endpoint.clone(),
    });
    assert!(
        harness.until(patience(), |model| !shows(model, &endpoint)),
        "the removed listener never went away: {:?}",
        harness
            .model
            .server
            .ready()
            .map(|facts| facts.listeners.clone())
    );

    harness.stop();
    drop(directory);
}

#[test]
fn namespace_create_and_delete_round_trip_behind_a_confirmation() {
    let (_directory, server) = fixture("namespaces");
    let mut harness = Harness::attach(server.socket()).expect("the control socket accepts");
    press(&mut harness, KeyCode::Char('2'));
    assert!(harness.until(patience(), |model| model.namespaces.ready().is_some()));

    press(&mut harness, KeyCode::Char('n'));
    type_text(&mut harness, "fresh");
    press(&mut harness, KeyCode::Enter);
    assert!(
        harness.until(patience(), |model| model
            .namespace_keys()
            .iter()
            .any(|key| key == "fresh")),
        "the created namespace never appeared: {:?}",
        harness.model.status
    );
    assert_eq!(harness.model.status.tone, Tone::Success);

    let mut client = server.connect();
    let listed = client.expect_ok(&Request::NamespaceList {});
    assert!(format!("{listed:?}").contains("fresh"), "{listed:?}");

    harness.model.namespace_selection.select("fresh");
    press(&mut harness, KeyCode::Char('d'));
    assert!(
        matches!(harness.model.dialog, Some(Dialog::Confirm(_))),
        "delete must ask first"
    );
    press(&mut harness, KeyCode::Char('y'));
    assert!(
        harness.until(patience(), |model| !model
            .namespace_keys()
            .iter()
            .any(|key| key == "fresh")),
        "the deleted namespace never went away"
    );
}

#[test]
fn a_rejected_creation_renders_the_servers_error_and_changes_nothing() {
    let (_directory, server) = fixture("rejected");
    let mut harness = Harness::attach(server.socket()).expect("the control socket accepts");
    press(&mut harness, KeyCode::Char('2'));
    assert!(harness.until(patience(), |model| model.namespaces.ready().is_some()));
    let before = harness.model.namespace_keys();

    press(&mut harness, KeyCode::Char('n'));
    type_text(&mut harness, "project");
    press(&mut harness, KeyCode::Enter);
    assert!(
        harness.until(patience(), |model| model.status.tone == Tone::Failure),
        "the duplicate was not refused"
    );
    assert!(
        harness.model.status.message.contains("already-exists"),
        "{:?}",
        harness.model.status
    );
    assert_eq!(harness.model.namespace_keys(), before);
}

#[test]
fn rule_add_and_remove_round_trip() {
    let (_directory, server) = fixture("rules");
    let mut harness = Harness::attach(server.socket()).expect("the control socket accepts");
    press(&mut harness, KeyCode::Char('3'));
    assert!(harness.until(patience(), |model| model.namespace_spec().is_some()));
    assert_eq!(harness.model.rule_keys(), vec!["/project"]);

    press(&mut harness, KeyCode::Char('a'));
    type_text(&mut harness, "added");
    press(&mut harness, KeyCode::Tab);
    press(&mut harness, KeyCode::Tab);
    type_text(&mut harness, "data");
    press(&mut harness, KeyCode::Enter);
    assert!(
        harness.until(patience(), |model| model
            .rule_keys()
            .iter()
            .any(|key| key == "/added")),
        "the added rule never appeared: {:?}",
        harness.model.status
    );

    harness.model.rule_selection.select("/added");
    press(&mut harness, KeyCode::Char('d'));
    press(&mut harness, KeyCode::Char('y'));
    assert!(
        harness.until(patience(), |model| !model
            .rule_keys()
            .iter()
            .any(|key| key == "/added")),
        "the removed rule never went away"
    );
}

#[test]
fn the_ownership_editor_round_trips_the_whole_policy_including_sentinels() {
    let (_directory, server) = fixture("ownership");
    let mut harness = Harness::attach(server.socket()).expect("the control socket accepts");
    press(&mut harness, KeyCode::Char('4'));
    assert!(harness.until(patience(), |model| model.namespace_spec().is_some()));

    press(&mut harness, KeyCode::Char('e'));
    let Some(Dialog::Form(form)) = &mut harness.model.dialog else {
        panic!("no ownership form");
    };
    form.fields[0].value = "map".to_owned();
    form.fields[1].value = "hide".to_owned();
    form.fields[4].value = "uid->0, 1001->1000".to_owned();
    form.fields[5].value = "gid->0".to_owned();
    press(&mut harness, KeyCode::Enter);

    assert!(
        harness.until(patience(), |model| matches!(
            model.namespace_spec().map(|spec| &spec.ownership),
            Some(OwnershipSpec::Map { .. })
        )),
        "the policy never landed: {:?}",
        harness.model.status
    );
    let spec = harness.model.namespace_spec().expect("read").clone();
    let OwnershipSpec::Map {
        unmapped,
        uid_map,
        gid_map,
        ..
    } = &spec.ownership
    else {
        panic!("expected a map policy");
    };
    assert_eq!(unmapped.to_string(), "hide");
    assert_eq!(uid_map.len(), 2);
    assert_eq!(
        uid_map[0].host,
        voidport_control::HostId::Sentinel(voidport_control::IdSentinel::Uid),
        "the sentinel survived the round trip unresolved"
    );
    assert_eq!(gid_map.len(), 1);

    press(&mut harness, KeyCode::Char('e'));
    let Some(Dialog::Form(form)) = &mut harness.model.dialog else {
        panic!("no ownership form");
    };
    form.fields[4].value = "1001->1000, 1002->1000".to_owned();
    press(&mut harness, KeyCode::Enter);
    assert!(
        harness.until(patience(), |model| model.status.tone == Tone::Failure),
        "a non-injective map was accepted"
    );
    assert!(
        harness
            .model
            .status
            .message
            .contains("invalid-configuration"),
        "{:?}",
        harness.model.status
    );
    let after = harness.model.namespace_spec().expect("read").clone();
    assert_eq!(
        after.ownership, spec.ownership,
        "a rejection leaves the view exactly as it was"
    );
}

#[test]
fn the_permission_and_auth_setters_round_trip() {
    let (_directory, server) = fixture("modes");
    let mut harness = Harness::attach(server.socket()).expect("the control socket accepts");
    press(&mut harness, KeyCode::Char('5'));
    assert!(harness.until(patience(), |model| model.namespace_spec().is_some()));

    press(&mut harness, KeyCode::Enter);
    assert!(
        harness.until(patience(), |model| model.status.tone == Tone::Success
            && model.status.message.contains("permission")),
        "the permission setter was not answered: {:?}",
        harness.model.status
    );

    press(&mut harness, KeyCode::Char('j'));
    press(&mut harness, KeyCode::Enter);
    assert!(
        harness.until(patience(), |model| model.status.tone == Tone::Success
            && model.status.message.contains("auth")),
        "the auth setter was not answered: {:?}",
        harness.model.status
    );

    let mut client = server.connect();
    let shown = client.expect_ok(&Request::NamespaceShow {
        name: voidport_control::NamespaceName::new("project").expect("valid"),
    });
    let rendered = format!("{shown:?}");
    assert!(rendered.contains("Passthrough"), "{rendered}");
    assert!(rendered.contains("None"), "{rendered}");
}

#[test]
fn a_restarted_server_is_reconnected_to_and_every_view_is_re_read() {
    let (directory, mut server) = fixture("reconnect");
    let state_file = directory.join("state.toml");
    let mut harness = Harness::attach(server.socket()).expect("the control socket accepts");
    press(&mut harness, KeyCode::Char('2'));
    assert!(harness.until(patience(), |model| model.namespaces.ready().is_some()));

    server.stop();
    drop(server);
    assert!(
        harness.until(patience(), |model| !model.connection.is_connected()),
        "the loss was never noticed"
    );
    assert!(
        harness.model.status.tone == Tone::Failure,
        "{:?}",
        harness.model.status
    );

    let restarted = support::start(&state_file);
    {
        let mut client = restarted.connect();
        client.expect_ok(&Request::NamespaceCreate {
            namespace: voidport_control::NamespaceSpec::new(
                voidport_control::NamespaceName::new("after-restart").expect("valid"),
            ),
        });
    }
    assert!(
        harness.until(Duration::from_secs(20), |model| model
            .connection
            .is_connected()
            && model
                .namespace_keys()
                .iter()
                .any(|key| key == "after-restart")),
        "the interface never caught up with the restarted server: {:?}",
        harness.model.status
    );
    drop(directory);
}

#[test]
fn quitting_stays_instant_while_a_reconnection_is_pending() {
    let (directory, mut server) = fixture("quit-while-retrying");
    let mut harness = Harness::attach(server.socket()).expect("the control socket accepts");
    assert!(harness.until(patience(), |model| model.server.ready().is_some()));
    server.stop();
    drop(server);
    assert!(harness.until(patience(), |model| !model.connection.is_connected()));

    // The worker sleeps between attempts; quitting must not wait for that.
    press(&mut harness, KeyCode::Char('q'));
    assert!(harness.model.finished);
    let started = Instant::now();
    harness.stop();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "quitting waited {:?} for the retry",
        started.elapsed()
    );
    drop(directory);
}

#[test]
fn a_wedged_server_is_detected_by_the_clients_timeouts() {
    let directory = support::TempDir::new("wedged");
    let socket = directory.join("control.sock");
    let listener = UnixListener::bind(&socket).expect("a bindable socket path");
    // Accept and never answer: the wedged server the timeouts exist for.
    let wedged = std::thread::spawn(move || {
        let held = listener.accept().expect("a connection");
        std::thread::sleep(Duration::from_secs(3));
        drop(held);
    });

    let mut harness = Harness::with(
        &socket,
        Timeouts {
            read: Some(Duration::from_millis(200)),
            ..Timeouts::default()
        },
        Backoff {
            initial: Duration::from_millis(50),
            max: Duration::from_millis(100),
        },
    )
    .expect("the control socket accepts");
    assert!(
        harness.until(patience(), |model| matches!(
            model.connection,
            Connection::Lost { .. }
        )),
        "a server that never answers was never detected"
    );
    assert!(
        harness.model.status.message.contains("longer than"),
        "the timeout is not what was reported: {:?}",
        harness.model.status
    );
    harness.stop();
    let _ = wedged.join();
}

/// A reply this client cannot read is a fault of that one exchange, not of
/// the socket: the view reports it and the connection stays up.
#[test]
fn a_reply_the_client_cannot_read_is_reported_without_dropping_the_connection() {
    let directory = support::TempDir::new("skewed");
    let socket = directory.join("control.sock");
    let listener = UnixListener::bind(&socket).expect("a bindable socket path");
    let skewed = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("a connection");
        let reader = BufReader::new(stream.try_clone().expect("clone"));
        for line in reader.lines() {
            if line.is_err() {
                return;
            }
            if stream.write_all(b"{\"status\":\"maybe\"}\n").is_err() {
                return;
            }
        }
    });

    let mut harness = Harness::attach(&socket).expect("the control socket accepts");
    assert!(
        harness.until(patience(), |model| model.server.failure().is_some()),
        "the unreadable answer was never reported: {:?}",
        harness.model.status
    );
    assert!(
        harness.model.connection.is_connected(),
        "one unreadable answer took the connection down: {:?}",
        harness.model.connection
    );
    harness.stop();
    let _ = skewed.join();
}

#[test]
fn a_missing_socket_fails_before_anything_is_taken_over() {
    let directory = support::TempDir::new("missing");
    let error =
        Session::connect(&directory.join("nothing.sock")).expect_err("nothing is listening there");
    assert!(error.to_string().contains("cannot connect"), "{error}");
}

#[test]
fn attaching_tails_the_log_file_the_server_names() {
    let scratch = support::TempDir::new("log-path");
    let log = scratch.join("voidportd.log");
    std::fs::write(
        &log,
        "2026-08-16T10:11:12.345678Z  INFO voidportd: started\n",
    )
    .expect("a writable log file");
    let (_directory, server) = support::logging_fixture("logs", &log);
    let mut harness = Harness::attach(server.socket()).expect("the control socket accepts");

    press(&mut harness, KeyCode::Char('7'));
    assert_eq!(harness.model.screen, Screen::Logs);
    assert!(
        harness.until(patience(), |model| model
            .logs
            .lines()
            .any(|line| line.text.contains("started"))),
        "the log file was never tailed: {:?} {:?}",
        harness.model.log_file(),
        harness.model.logs.trouble
    );
    assert_eq!(
        harness.model.log_file(),
        Some(log.display().to_string().as_str()),
        "the path did not come from server-info"
    );

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .expect("the log file reopens");
    file.write_all(b"2026-08-16T10:11:13.000000Z  WARN voidportd: something to say\n")
        .expect("the log file writes");
    drop(file);
    assert!(
        harness.until(patience(), |model| model
            .logs
            .lines()
            .any(|line| line.text.contains("something to say"))),
        "the tail did not follow the file"
    );
    assert!(harness.model.logs.following());
    assert_eq!(harness.model.logs.trouble, None);
    harness.stop();
}

#[test]
fn an_unreadable_log_file_is_named_and_the_interface_keeps_working() {
    let scratch = support::TempDir::new("log-elsewhere");
    let log = scratch.join("not-on-this-machine/voidportd.log");
    let (_directory, server) = support::logging_fixture("logs-elsewhere", &log);
    let mut harness = Harness::attach(server.socket()).expect("the control socket accepts");

    press(&mut harness, KeyCode::Char('7'));
    assert!(
        harness.until(patience(), |model| model.logs.trouble.is_some()),
        "an unreadable log file said nothing"
    );
    assert_eq!(
        harness.model.log_file(),
        Some(log.display().to_string().as_str()),
        "the placeholder cannot name a path it was not given"
    );
    assert!(harness.model.logs.lines().len() == 0);

    press(&mut harness, KeyCode::Char('2'));
    assert!(
        harness.until(patience(), |model| model.namespaces.ready().is_some()),
        "an unreadable log file took the interface down with it"
    );
    assert_eq!(harness.model.namespace_keys(), vec!["project"]);
    harness.stop();
}

/// The other tests assert against the state file of the fixture, so a change
/// to it would silently weaken them.
#[test]
fn the_fixture_serves_what_the_tests_assume() {
    assert!(STATE.contains("transport = \"tcp\""));
    assert!(STATE.contains("transport = \"unix\""));
    assert!(STATE.contains("name = \"project\""));
}
