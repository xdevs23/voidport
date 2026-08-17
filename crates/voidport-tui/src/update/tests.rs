//! Reducer tests: every behaviour rule, and every binding Help lists.
//!
//! The reducer is pure, so each test is the same shape — build a model, feed
//! events, assert the model and the effects. No server, no terminal, no clock.

use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use voidport_control::{
    AuthMode, ControlError, ErrorCode, HostDirectIo, IdMapping, IdSentinel, ListenerInfo,
    NamespaceName, NamespaceSpec, NamespaceSummary, OwnershipMode, OwnershipSpec, PermissionMode,
    Request, Rule, SessionSummary, ShareMode, UnmappedPolicy,
};

use std::path::PathBuf;

use crate::event::{Correlation, Effect, Event, Failure, Fetch};
use crate::keys::{self, ACTIONS, Action, BINDINGS, Context};
use crate::model::logs::Level;
use crate::model::{Dialog, Mode, Model, SCREENS, Screen, Tone};
use crate::tail::LogRead;

fn name(raw: &str) -> NamespaceName {
    NamespaceName::new(raw).expect("valid namespace name")
}

fn model() -> Model {
    Model::new(Mode::Attach, "/run/voidport/control.sock", None)
}

fn press(model: &mut Model, code: KeyCode) -> Vec<Effect> {
    update(model, Event::Key(KeyEvent::new(code, KeyModifiers::NONE)))
}

/// A key held with control.
fn chord(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::CONTROL)
}

fn type_text(model: &mut Model, text: &str) {
    for character in text.chars() {
        press(model, KeyCode::Char(character));
    }
}

fn summary(name_: &str, rules: usize) -> NamespaceSummary {
    NamespaceSummary {
        name: name(name_),
        ownership: OwnershipMode::Passthrough,
        permission: PermissionMode::Passthrough,
        direct_io: HostDirectIo::Cached,
        auth: AuthMode::None,
        rules,
    }
}

fn spec(name_: &str) -> NamespaceSpec {
    NamespaceSpec {
        rules: vec![
            Rule::new("/project", ShareMode::Rw).with_target("/srv/project"),
            Rule::new("/project/*", ShareMode::Hidden),
            // A pattern rule on the same directory the literal rule above
            // covers: the two are different rules, and the rule list has to
            // keep them apart.
            Rule::new("/project", ShareMode::Ro).with_match("docs-*"),
        ],
        ..NamespaceSpec::new(name(name_))
    }
}

fn session(id: u64) -> SessionSummary {
    SessionSummary {
        id,
        namespace: name("project"),
        subpath: "/project".to_owned(),
        transport: "tcp".to_owned(),
        peer: "127.0.0.1:40404".to_owned(),
        nodes: 3,
        handles: 1,
        subscribed: false,
    }
}

/// Feeds the answers a screen's fetches expect, so a test can start from a
/// model that has actually read the server.
fn loaded(model: &mut Model) {
    update(
        model,
        Event::Fetched {
            fetch: Fetch::Namespaces,
            result: Ok(Reply::NamespaceList {
                namespaces: vec![summary("alpha", 1), summary("project", 2)],
            }),
        },
    );
    let selected = model
        .selected_namespace()
        .expect("the list selected something");
    update(
        model,
        Event::Fetched {
            fetch: Fetch::Namespace(selected.clone()),
            result: Ok(Reply::Namespace {
                namespace: spec(selected.as_str()),
            }),
        },
    );
}

/// The log file the fixture server names.
const LOG_FILE: &str = "/srv/voidport/voidportd.log";

/// Answers `server-info`, which is where the Logs screen learns the path.
fn informed(model: &mut Model, log_file: Option<&str>) {
    update(
        model,
        Event::Fetched {
            fetch: Fetch::ServerInfo,
            result: Ok(Reply::ServerInfo {
                version: "0.1.0".to_owned(),
                state_file: "/srv/voidport/state.toml".to_owned(),
                control_socket: "/srv/voidport/control.sock".to_owned(),
                namespaces: 1,
                listeners: Vec::new(),
                node_descriptors: 0,
                node_descriptor_budget: 4096,
                log_file: log_file.map(std::borrow::ToOwned::to_owned),
            }),
        },
    );
}

/// One tracing record, in the shape the subscriber writes them.
fn record(level: &str, message: &str) -> String {
    format!("2026-08-16T10:11:12.345678Z {level} voidportd: {message}")
}

/// `count` info records, oldest first.
fn records(count: usize) -> Vec<String> {
    (1..=count)
        .map(|n| record("INFO", &n.to_string()))
        .collect()
}

/// The read the edge would have posted after reading `path`.
fn tailed(model: &mut Model, path: &str, lines: &[String]) {
    update(
        model,
        Event::LogRead(LogRead {
            path: PathBuf::from(path),
            lines: lines.to_vec(),
            trouble: None,
        }),
    );
}

/// The effect that reads one log file.
fn read_log(path: &str) -> Effect {
    Effect::ReadLog {
        path: PathBuf::from(path),
    }
}

/// The bottom line of the log view.
fn newest(model: &Model) -> String {
    model
        .logs
        .window(1)
        .first()
        .map(|line| line.text.clone())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Freshness: the tick and focus entry
// ---------------------------------------------------------------------------

#[test]
fn the_tick_re_reads_every_visible_view() {
    let mut model = model();
    assert_eq!(
        update(&mut model, Event::Tick),
        vec![
            Effect::Fetch(Fetch::ServerInfo),
            Effect::Fetch(Fetch::Sessions)
        ],
        "the overview shows the server and a session count"
    );

    model.screen = Screen::Sessions;
    assert_eq!(
        update(&mut model, Event::Tick),
        vec![Effect::Fetch(Fetch::Sessions)]
    );
}

#[test]
fn focusing_a_screen_re_reads_it_at_once() {
    let mut model = model();
    let effects = press(&mut model, KeyCode::Char('2'));
    assert_eq!(model.screen, Screen::Namespaces);
    assert_eq!(effects, vec![Effect::Fetch(Fetch::Namespaces)]);

    loaded(&mut model);
    let effects = press(&mut model, KeyCode::Tab);
    assert_eq!(model.screen, Screen::Rules);
    assert_eq!(
        effects,
        vec![
            Effect::Fetch(Fetch::Namespaces),
            Effect::Fetch(Fetch::Namespace(name("alpha")))
        ],
        "a per-namespace screen reads the list and the namespace"
    );
}

#[test]
fn an_external_mutation_is_visible_within_one_tick() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);
    assert_eq!(model.namespace_keys(), vec!["alpha", "project"]);

    // Another operator creates one through `voidport-ctl`; the next tick reads
    // it, and the model has it.
    assert_eq!(
        update(&mut model, Event::Tick),
        vec![Effect::Fetch(Fetch::Namespaces)]
    );
    update(
        &mut model,
        Event::Fetched {
            fetch: Fetch::Namespaces,
            result: Ok(Reply::NamespaceList {
                namespaces: vec![
                    summary("alpha", 1),
                    summary("new", 0),
                    summary("project", 2),
                ],
            }),
        },
    );
    assert_eq!(model.namespace_keys(), vec!["alpha", "new", "project"]);
    assert_eq!(
        model.namespace_selection.selected(),
        Some("alpha"),
        "a selection survives a refresh by key"
    );
}

#[test]
fn an_item_deleted_elsewhere_clears_the_selection_with_a_note() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);
    model.namespace_selection.select("project");

    update(
        &mut model,
        Event::Fetched {
            fetch: Fetch::Namespaces,
            result: Ok(Reply::NamespaceList {
                namespaces: vec![summary("alpha", 1)],
            }),
        },
    );
    assert_eq!(
        model.namespace_selection.selected(),
        None,
        "the deleted item's neighbour is not a selection the operator made"
    );
    assert!(
        model.status.message.contains("project"),
        "{:?}",
        model.status
    );
    assert_eq!(model.namespace.ready(), None, "its views went with it");

    // And the next tick's answer does not quietly adopt a row either.
    update(
        &mut model,
        Event::Fetched {
            fetch: Fetch::Namespaces,
            result: Ok(Reply::NamespaceList {
                namespaces: vec![summary("alpha", 1)],
            }),
        },
    );
    assert_eq!(model.namespace_selection.selected(), None);
}

#[test]
fn a_failed_re_read_renders_as_a_failure_and_never_as_stale_data() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);
    assert!(model.namespaces.ready().is_some());

    update(
        &mut model,
        Event::Fetched {
            fetch: Fetch::Namespaces,
            result: Err(Failure::Transport("the socket died".to_owned())),
        },
    );
    assert_eq!(model.namespaces.ready(), None);
    assert_eq!(model.namespaces.failure(), Some("the socket died"));
}

#[test]
fn a_reply_of_the_wrong_shape_is_a_failure_too() {
    let mut model = model();
    update(
        &mut model,
        Event::Fetched {
            fetch: Fetch::ServerInfo,
            result: Ok(Reply::Done {}),
        },
    );
    assert!(model.server.failure().is_some());
}

// ---------------------------------------------------------------------------
// Mutation correlation
// ---------------------------------------------------------------------------

#[test]
fn a_mutation_is_pending_until_it_is_answered_then_re_reads() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);
    model.namespace_selection.select("project");

    press(&mut model, KeyCode::Char('d'));
    let effects = press(&mut model, KeyCode::Char('y'));
    let Some(Effect::Mutate {
        correlation,
        request,
    }) = effects.first().cloned()
    else {
        panic!("expected a mutation, got {effects:?}");
    };
    assert_eq!(
        request,
        Request::NamespaceDelete {
            name: name("project")
        }
    );
    assert_eq!(
        model.pending.as_ref().map(|p| p.correlation),
        Some(correlation)
    );
    assert_eq!(model.status.tone, Tone::Pending);

    let effects = update(
        &mut model,
        Event::Answered {
            correlation,
            result: Ok(Reply::Done {}),
        },
    );
    assert!(model.pending.is_none());
    assert_eq!(model.status.tone, Tone::Success);
    assert_eq!(
        effects,
        vec![Effect::Fetch(Fetch::Namespaces)],
        "success re-reads the view that issued it"
    );
}

#[test]
fn a_rejection_renders_the_servers_error_and_changes_nothing_else() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);
    let before = model.namespaces.ready().cloned();

    press(&mut model, KeyCode::Char('d'));
    let effects = press(&mut model, KeyCode::Enter);
    let Some(Effect::Mutate { correlation, .. }) = effects.first().cloned() else {
        panic!("expected a mutation");
    };

    let effects = update(
        &mut model,
        Event::Answered {
            correlation,
            result: Err(Failure::Rejected(ControlError::new(
                ErrorCode::NotFound,
                "no namespace \"alpha\"",
            ))),
        },
    );
    assert!(effects.is_empty(), "a rejection re-reads nothing");
    assert!(model.pending.is_none());
    assert_eq!(model.status.tone, Tone::Failure);
    assert!(
        model.status.message.contains("no namespace \"alpha\""),
        "{:?}",
        model.status
    );
    assert_eq!(
        model.namespaces.ready().cloned(),
        before,
        "the view is exactly as it was"
    );
    assert!(model.dialog.is_none());
}

#[test]
fn an_answer_to_something_else_is_ignored() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);
    press(&mut model, KeyCode::Char('d'));
    let effects = press(&mut model, KeyCode::Char('y'));
    let Some(Effect::Mutate { correlation, .. }) = effects.first().cloned() else {
        panic!("expected a mutation");
    };

    let stale = Correlation(correlation.0 + 41);
    let effects = update(
        &mut model,
        Event::Answered {
            correlation: stale,
            result: Ok(Reply::Done {}),
        },
    );
    assert!(effects.is_empty());
    assert!(
        model.pending.is_some(),
        "the real mutation is still outstanding"
    );
}

#[test]
fn only_one_mutation_is_in_flight_at_a_time() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);
    press(&mut model, KeyCode::Char('d'));
    press(&mut model, KeyCode::Char('y'));

    press(&mut model, KeyCode::Char('d'));
    let effects = press(&mut model, KeyCode::Char('y'));
    assert!(effects.is_empty(), "the second is refused, not queued");
    assert_eq!(model.status.tone, Tone::Failure);
}

// ---------------------------------------------------------------------------
// Connection loss and reconnection
// ---------------------------------------------------------------------------

#[test]
fn losing_the_connection_banners_and_reconnecting_re_reads_everything() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);

    update(
        &mut model,
        Event::Disconnected {
            reason: "the socket died".to_owned(),
            attempt: 2,
        },
    );
    assert!(!model.connection.is_connected());
    assert_eq!(model.status.tone, Tone::Failure);

    let effects = update(&mut model, Event::Connected);
    assert!(model.connection.is_connected());
    assert_eq!(
        model.namespaces.ready(),
        None,
        "a reconnect may be a different server; nothing read before it is evidence"
    );
    // Every view, not only the focused screen's: an invalidated view left
    // unread until its screen is next entered is a hole in the picture.
    assert_eq!(
        effects,
        vec![
            Effect::Fetch(Fetch::ServerInfo),
            Effect::Fetch(Fetch::Namespaces),
            Effect::Fetch(Fetch::Sessions),
            Effect::Fetch(Fetch::Namespace(name("alpha"))),
        ]
    );
    assert_eq!(model.server.ready(), None);
    assert_eq!(model.sessions.ready(), None);
    assert_eq!(model.namespace.ready(), None);
}

#[test]
fn a_form_in_progress_survives_a_reconnect() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);
    press(&mut model, KeyCode::Char('n'));
    type_text(&mut model, "keepme");

    update(
        &mut model,
        Event::Disconnected {
            reason: "gone".to_owned(),
            attempt: 1,
        },
    );
    update(&mut model, Event::Connected);
    let Some(Dialog::Form(form)) = &model.dialog else {
        panic!("the form was thrown away");
    };
    assert_eq!(form.fields[0].value, "keepme");
}

// ---------------------------------------------------------------------------
// Every binding Help lists
// ---------------------------------------------------------------------------

#[test]
fn quitting_asks_the_edge_to_leave() {
    let mut quitting = model();
    assert_eq!(press(&mut quitting, KeyCode::Char('q')), vec![Effect::Quit]);
    assert!(quitting.finished);

    let mut model = model();
    let control_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    assert_eq!(
        update(&mut model, Event::Key(control_c)),
        vec![Effect::Quit]
    );
    assert!(model.finished, "Ctrl-C is a key in raw mode, and it quits");
}

#[test]
fn an_outside_stop_quits_the_same_way() {
    let mut model = model();
    assert_eq!(update(&mut model, Event::Stop), vec![Effect::Quit]);
    assert!(model.finished);
}

#[test]
fn help_opens_scrolls_and_closes() {
    let mut model = model();
    press(&mut model, KeyCode::Char('?'));
    assert!(model.help);
    assert_eq!(model.help_scroll, 0, "it opens at its first line");
    // The overlay swallows the rest of the keyboard.
    let effects = press(&mut model, KeyCode::Char('q'));
    assert!(effects.is_empty());
    assert!(!model.finished);

    // The list is longer than any terminal it is read in, so it scrolls — and
    // the last line is reachable, which is what makes it the canonical list
    // not a list of the first screenful.
    let last = crate::keys::help_rows() - 1;
    press(&mut model, KeyCode::Char('j'));
    assert_eq!(model.help_scroll, 1);
    press(&mut model, KeyCode::Char('k'));
    assert_eq!(model.help_scroll, 0);
    press(&mut model, KeyCode::Char('k'));
    assert_eq!(model.help_scroll, 0, "it does not scroll above its top");
    press(&mut model, KeyCode::PageDown);
    assert_eq!(
        model.help_scroll,
        usize::try_from(super::input::PAGE).expect("a page is forwards")
    );
    press(&mut model, KeyCode::PageUp);
    assert_eq!(model.help_scroll, 0);
    press(&mut model, KeyCode::Char('G'));
    assert_eq!(model.help_scroll, last);
    press(&mut model, KeyCode::Char('j'));
    assert_eq!(model.help_scroll, last, "it does not scroll past its end");
    press(&mut model, KeyCode::Char('g'));
    assert_eq!(model.help_scroll, 0);

    press(&mut model, KeyCode::Char('G'));
    press(&mut model, KeyCode::Esc);
    assert!(!model.help);
    press(&mut model, KeyCode::Char('?'));
    assert_eq!(model.help_scroll, 0, "reopening starts at the top again");
}

/// Ctrl-C and Ctrl-Z are listed under "Anywhere", so they have to work
/// anywhere: an operator in a create form with no way out and no signal to
/// raise has nothing left to try.
#[test]
fn quit_and_suspend_win_inside_every_modal_state() {
    for open in [
        |model: &mut Model| {
            press(model, KeyCode::Char('?'));
        },
        |model: &mut Model| {
            model.screen = Screen::Namespaces;
            loaded(model);
            press(model, KeyCode::Char('n'));
        },
        |model: &mut Model| {
            model.screen = Screen::Namespaces;
            loaded(model);
            press(model, KeyCode::Char('d'));
        },
        |model: &mut Model| {
            model.screen = Screen::Namespaces;
            loaded(model);
            press(model, KeyCode::Char('/'));
        },
    ] {
        let mut suspending = model();
        open(&mut suspending);
        assert_eq!(
            update(&mut suspending, Event::Key(chord(KeyCode::Char('z')))),
            vec![Effect::Suspend],
            "Ctrl-Z did nothing"
        );

        let mut quitting = model();
        open(&mut quitting);
        assert_eq!(
            update(&mut quitting, Event::Key(chord(KeyCode::Char('c')))),
            vec![Effect::Quit],
            "Ctrl-C did nothing"
        );
        assert!(quitting.finished);
    }
}

/// The other half of the same rule: a plain character still belongs to whatever
/// is being typed into.
#[test]
fn a_plain_screen_binding_does_not_reach_into_a_form() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);
    press(&mut model, KeyCode::Char('n'));
    press(&mut model, KeyCode::Char('q'));
    assert!(!model.finished, "`q` was being typed into the name field");
    let Some(Dialog::Form(form)) = &model.dialog else {
        panic!("the form went away");
    };
    assert_eq!(form.fields[0].value, "q");
}

#[test]
fn every_screen_is_reachable_by_keyboard() {
    let mut model = model();
    for (index, screen) in SCREENS.iter().enumerate() {
        let digit = char::from_digit(u32::try_from(index).expect("small") + 1, 10).expect("digit");
        press(&mut model, KeyCode::Char(digit));
        assert_eq!(model.screen, *screen);
    }
    press(&mut model, KeyCode::BackTab);
    assert_eq!(model.screen, Screen::Sessions);
    press(&mut model, KeyCode::Tab);
    assert_eq!(model.screen, Screen::Logs);
}

#[test]
fn refreshing_re_reads_now() {
    let mut model = model();
    model.screen = Screen::Sessions;
    assert_eq!(
        press(&mut model, KeyCode::Char('r')),
        vec![Effect::Fetch(Fetch::Sessions)]
    );
}

#[test]
fn suspending_asks_the_edge_to_suspend() {
    let mut model = model();
    let control_z = KeyEvent::new(KeyCode::Char('z'), KeyModifiers::CONTROL);
    assert_eq!(
        update(&mut model, Event::Key(control_z)),
        vec![Effect::Suspend]
    );
}

#[test]
fn the_list_bindings_move_the_selection() {
    let mut model = model();
    model.screen = Screen::Sessions;
    update(
        &mut model,
        Event::Fetched {
            fetch: Fetch::Sessions,
            result: Ok(Reply::SessionList {
                sessions: (1..=30).map(session).collect(),
            }),
        },
    );
    assert_eq!(model.session_selection.selected(), Some("1"));
    press(&mut model, KeyCode::Char('j'));
    assert_eq!(model.session_selection.selected(), Some("2"));
    press(&mut model, KeyCode::Down);
    assert_eq!(model.session_selection.selected(), Some("3"));
    press(&mut model, KeyCode::Char('k'));
    assert_eq!(model.session_selection.selected(), Some("2"));
    press(&mut model, KeyCode::Up);
    assert_eq!(model.session_selection.selected(), Some("1"));
    press(&mut model, KeyCode::PageDown);
    assert_eq!(model.session_selection.selected(), Some("11"));
    press(&mut model, KeyCode::PageUp);
    assert_eq!(model.session_selection.selected(), Some("1"));
    press(&mut model, KeyCode::Char('G'));
    assert_eq!(model.session_selection.selected(), Some("30"));
    press(&mut model, KeyCode::End);
    assert_eq!(model.session_selection.selected(), Some("30"));
    press(&mut model, KeyCode::Char('g'));
    assert_eq!(model.session_selection.selected(), Some("1"));
    press(&mut model, KeyCode::Home);
    assert_eq!(model.session_selection.selected(), Some("1"));
}

#[test]
fn filtering_narrows_a_list_incrementally() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);

    press(&mut model, KeyCode::Char('/'));
    assert!(model.namespace_selection.is_filtering());
    type_text(&mut model, "proj");
    assert_eq!(model.namespace_selection.filter(), Some("proj"));
    assert_eq!(model.namespace_selection.selected(), Some("project"));
    press(&mut model, KeyCode::Backspace);
    assert_eq!(model.namespace_selection.filter(), Some("pro"));
    press(&mut model, KeyCode::Enter);
    assert!(
        !model.namespace_selection.is_filtering(),
        "Enter accepts the pattern and gives the keys back to the list"
    );
    assert_eq!(model.namespace_selection.filter(), Some("pro"));
    press(&mut model, KeyCode::Esc);
    assert_eq!(model.namespace_selection.filter(), None);
}

#[test]
fn a_filter_started_over_is_cancelled_with_escape() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);
    press(&mut model, KeyCode::Char('/'));
    type_text(&mut model, "zzz");
    press(&mut model, KeyCode::Esc);
    assert_eq!(model.namespace_selection.filter(), None);
    assert!(!model.namespace_selection.is_filtering());
}

#[test]
fn opening_a_namespace_shows_its_rules() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);
    let effects = press(&mut model, KeyCode::Enter);
    assert_eq!(model.screen, Screen::Rules);
    assert!(effects.contains(&Effect::Fetch(Fetch::Namespace(name("alpha")))));
}

#[test]
fn moving_the_namespace_selection_re_reads_the_per_namespace_views() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);
    assert!(model.namespace_spec().is_some());

    let effects = press(&mut model, KeyCode::Char('j'));
    assert_eq!(model.namespace_selection.selected(), Some("project"));
    assert_eq!(
        effects,
        vec![Effect::Fetch(Fetch::Namespace(name("project")))]
    );
    assert!(
        model.namespace_spec().is_none(),
        "what was read belonged to the other namespace"
    );
}

#[test]
fn creating_a_namespace_goes_through_a_form() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);

    press(&mut model, KeyCode::Char('n'));
    assert!(matches!(model.dialog, Some(Dialog::Form(_))));
    type_text(&mut model, "fresh");
    let effects = press(&mut model, KeyCode::Enter);
    assert_eq!(
        effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::Mutate { request, .. } => Some(request.clone()),
                Effect::Fetch(_) | Effect::ReadLog { .. } | Effect::Quit | Effect::Suspend => None,
            })
            .collect::<Vec<_>>(),
        vec![Request::NamespaceCreate {
            namespace: NamespaceSpec::new(name("fresh"))
        }]
    );
    assert!(model.dialog.is_none(), "a submitted form closes");
}

#[test]
fn a_form_refused_locally_stays_open_and_sends_nothing() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);
    press(&mut model, KeyCode::Char('n'));
    type_text(&mut model, "a/b");
    let effects = press(&mut model, KeyCode::Enter);
    assert!(effects.is_empty());
    assert!(matches!(model.dialog, Some(Dialog::Form(_))));
    assert_eq!(model.status.tone, Tone::Failure);
}

#[test]
fn a_form_moves_between_fields_and_cycles_choices() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);
    press(&mut model, KeyCode::Char('n'));

    press(&mut model, KeyCode::Tab);
    let Some(Dialog::Form(form)) = &model.dialog else {
        panic!("no form");
    };
    assert_eq!(form.focus, 1);
    press(&mut model, KeyCode::BackTab);
    press(&mut model, KeyCode::Down);
    press(&mut model, KeyCode::Down);
    press(&mut model, KeyCode::Down);
    press(&mut model, KeyCode::Right);
    let Some(Dialog::Form(form)) = &model.dialog else {
        panic!("no form");
    };
    assert_eq!(form.fields[3].label, "ownership");
    assert_eq!(form.fields[3].value, "map", "Right cycles the closed set");

    press(&mut model, KeyCode::Up);
    press(&mut model, KeyCode::Esc);
    assert!(model.dialog.is_none(), "Esc cancels");
}

#[test]
fn deleting_a_namespace_asks_first_and_can_be_refused() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    loaded(&mut model);

    press(&mut model, KeyCode::Char('d'));
    let Some(Dialog::Confirm(confirm)) = &model.dialog else {
        panic!("no confirmation");
    };
    assert!(confirm.prompt.contains("alpha"), "{}", confirm.prompt);
    let effects = press(&mut model, KeyCode::Char('n'));
    assert!(effects.is_empty(), "answering no sends nothing");
    assert!(model.dialog.is_none());
    assert!(model.pending.is_none());
}

#[test]
fn rules_are_added_and_removed_from_the_rules_screen() {
    let mut model = model();
    model.screen = Screen::Rules;
    loaded(&mut model);

    press(&mut model, KeyCode::Char('a'));
    type_text(&mut model, "added");
    let effects = press(&mut model, KeyCode::Enter);
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::Mutate {
            request: Request::RuleAdd { rule, .. },
            ..
        } if rule.path == "/added"
    )));

    let correlation = model.pending.as_ref().expect("pending").correlation;
    update(
        &mut model,
        Event::Answered {
            correlation,
            result: Ok(Reply::Done {}),
        },
    );
    model.rule_selection.select("/project/*");
    press(&mut model, KeyCode::Char('d'));
    let effects = press(&mut model, KeyCode::Char('y'));
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::Mutate {
            request: Request::RuleRemove { path, .. },
            ..
        } if path == "/project/*"
    )));
}

#[test]
fn a_pattern_rule_is_its_own_row_and_is_removed_by_its_own_key() {
    let mut model = model();
    model.screen = Screen::Rules;
    loaded(&mut model);

    // Three rules, three keys: the pattern rule is keyed by its path *and* its
    // match, spelled the way `rule remove` takes the pair.
    assert_eq!(
        model.rule_keys(),
        vec![
            "/project".to_owned(),
            "/project/*".to_owned(),
            "/project --match 'docs-*'".to_owned(),
        ]
    );

    model.rule_selection.select("/project --match 'docs-*'");
    press(&mut model, KeyCode::Char('d'));
    let Some(Dialog::Confirm(confirm)) = &model.dialog else {
        panic!("no confirmation");
    };
    assert!(
        confirm.prompt.contains("/project --match 'docs-*'"),
        "{}",
        confirm.prompt
    );
    let effects = press(&mut model, KeyCode::Char('y'));
    assert!(
        effects.iter().any(|effect| matches!(
            effect,
            Effect::Mutate {
                request: Request::RuleRemove { path, r#match, .. },
                ..
            } if path == "/project" && r#match.as_deref() == Some("docs-*")
        )),
        "the removal names the pair that keys the selected rule: {effects:?}"
    );

    let correlation = model.pending.as_ref().expect("pending").correlation;
    update(
        &mut model,
        Event::Answered {
            correlation,
            result: Ok(Reply::Done {}),
        },
    );

    // The literal rule at that same path is the other rule, and removing it
    // sends no match — which is what makes the two removals different.
    model.rule_selection.select("/project");
    press(&mut model, KeyCode::Char('d'));
    let effects = press(&mut model, KeyCode::Char('y'));
    assert!(
        effects.iter().any(|effect| matches!(
            effect,
            Effect::Mutate {
                request: Request::RuleRemove { path, r#match, .. },
                ..
            } if path == "/project" && r#match.is_none()
        )),
        "{effects:?}"
    );
}

#[test]
fn a_rule_row_the_server_no_longer_has_clears_the_selection() {
    let mut model = model();
    model.screen = Screen::Rules;
    loaded(&mut model);
    model.rule_selection.select("/project --match 'docs-*'");

    let selected = model.selected_namespace().expect("a selection");
    let mut without_pattern = spec(selected.as_str());
    without_pattern.rules.retain(|rule| rule.r#match.is_none());
    update(
        &mut model,
        Event::Fetched {
            fetch: Fetch::Namespace(selected),
            result: Ok(Reply::Namespace {
                namespace: without_pattern,
            }),
        },
    );
    assert_eq!(model.rule_selection.selected(), None);
    assert!(
        model.status.message.contains("--match 'docs-*'"),
        "{}",
        model.status.message
    );
    assert!(model.selected_rule().is_none());
}

#[test]
fn the_ownership_editor_opens_pre_filled_and_submits_the_whole_policy() {
    let mut model = model();
    model.screen = Screen::Ownership;
    loaded(&mut model);
    let selected = model.selected_namespace().expect("a selection");
    update(
        &mut model,
        Event::Fetched {
            fetch: Fetch::Namespace(selected.clone()),
            result: Ok(Reply::Namespace {
                namespace: NamespaceSpec {
                    ownership: OwnershipSpec::Map {
                        unmapped: UnmappedPolicy::Hide,
                        squash_uid: 65534,
                        squash_gid: 65534,
                        uid_map: vec![IdMapping::new(IdSentinel::Uid, 0)],
                        gid_map: Vec::new(),
                    },
                    ..spec(selected.as_str())
                },
            }),
        },
    );

    press(&mut model, KeyCode::Char('e'));
    let Some(Dialog::Form(form)) = &model.dialog else {
        panic!("no form");
    };
    assert_eq!(form.fields[0].value, "map");
    assert_eq!(
        form.fields[4].value, "uid->0",
        "the sentinel stays a sentinel"
    );

    let effects = press(&mut model, KeyCode::Enter);
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::Mutate {
            request: Request::OwnershipSet { ownership, .. },
            ..
        } if matches!(ownership, OwnershipSpec::Map { unmapped: UnmappedPolicy::Hide, .. })
    )));
}

#[test]
fn the_mode_setters_move_cycle_and_apply() {
    let mut model = model();
    model.screen = Screen::Modes;
    loaded(&mut model);
    assert_eq!(model.modes.row, 0);
    assert_eq!(model.modes.permission, "passthrough");

    press(&mut model, KeyCode::Char(' '));
    assert_eq!(
        model.modes.permission, "passthrough",
        "v1 defines exactly one permission mode, so cycling returns to it"
    );
    let effects = press(&mut model, KeyCode::Enter);
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::Mutate {
            request: Request::PermissionSet { .. },
            ..
        }
    )));
    let correlation = model.pending.as_ref().expect("pending").correlation;
    update(
        &mut model,
        Event::Answered {
            correlation,
            result: Ok(Reply::Done {}),
        },
    );

    press(&mut model, KeyCode::Char('j'));
    assert_eq!(model.modes.row, 1);
    press(&mut model, KeyCode::Right);
    assert_eq!(model.modes.auth, "none");
    let effects = press(&mut model, KeyCode::Enter);
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::Mutate {
            request: Request::AuthSet { .. },
            ..
        }
    )));
    press(&mut model, KeyCode::Char('k'));
    assert_eq!(model.modes.row, 0);
}

/// The apply buffer follows the server until the operator touches it, and is
/// theirs afterwards.
///
/// Without the distinction the screen shows "TO APPLY" values nobody chose:
/// another operator's `permission-set` refreshes the server column while the
/// buffer keeps whatever it had, and Enter then applies that.
#[test]
fn an_untouched_mode_buffer_follows_the_server_and_a_touched_one_does_not() {
    let mut model = model();
    model.screen = Screen::Modes;
    loaded(&mut model);
    let selected = model.selected_namespace().expect("a selection");
    assert_eq!(model.modes.permission, "passthrough");
    assert!(!model.modes.edited);

    // Another operator changes the mode: an untouched buffer takes it.
    let changed = |permission: &str| Reply::Namespace {
        namespace: NamespaceSpec {
            permission: permission.parse().expect("a mode the protocol defines"),
            ..spec(selected.as_str())
        },
    };
    update(
        &mut model,
        Event::Fetched {
            fetch: Fetch::Namespace(selected.clone()),
            result: Ok(changed("passthrough")),
        },
    );
    assert_eq!(model.modes.permission, "passthrough");

    // Once the operator has cycled it, the refresh leaves their value alone.
    press(&mut model, KeyCode::Char(' '));
    assert!(model.modes.edited, "cycling is an edit");
    model.modes.permission = "the operator's own".to_owned();
    update(
        &mut model,
        Event::Fetched {
            fetch: Fetch::Namespace(selected.clone()),
            result: Ok(changed("passthrough")),
        },
    );
    assert_eq!(model.modes.permission, "the operator's own");

    // Applying gives it back to the server.
    model.modes.permission = "passthrough".to_owned();
    let effects = press(&mut model, KeyCode::Enter);
    let Some(Effect::Mutate { correlation, .. }) = effects.first().cloned() else {
        panic!("expected a mutation, got {effects:?}");
    };
    update(
        &mut model,
        Event::Answered {
            correlation,
            result: Ok(Reply::Done {}),
        },
    );
    assert!(
        !model.modes.edited,
        "an applied buffer is the server's again"
    );
}

#[test]
fn an_operation_needing_a_selection_says_so_instead_of_guessing() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    assert!(press(&mut model, KeyCode::Char('d')).is_empty());
    assert_eq!(model.status.tone, Tone::Failure);

    model.screen = Screen::Rules;
    assert!(press(&mut model, KeyCode::Char('a')).is_empty());
    assert!(press(&mut model, KeyCode::Char('d')).is_empty());
    model.screen = Screen::Ownership;
    assert!(press(&mut model, KeyCode::Char('e')).is_empty());
    model.screen = Screen::Modes;
    assert!(press(&mut model, KeyCode::Enter).is_empty());
}

/// Every action Help lists is driven through the reducer, by every chord the
/// table binds it to, and its effect on the model is asserted.
///
/// There is no checklist here to keep: [`exercise`] is an **exhaustive match**
/// over [`Action`], so an action added to the table without an exercise does
/// not fail an assertion — it fails to compile. A hand-written list is a list
/// somebody has to remember to add to, which is exactly the discipline the
/// design says Help completeness must not rest on.
#[test]
fn every_help_listed_binding_is_driven_through_the_reducer() {
    for binding in BINDINGS {
        assert!(
            ACTIONS.contains(&binding.action),
            "{:?} is bound but missing from ACTIONS, so Help could not list it",
            binding.action
        );
        if binding.keys.is_empty() {
            // Text entry: no chord of its own, every printable character.
            exercise(binding.context, KeyEvent::new(KeyCode::Char('x'), NONE));
            continue;
        }
        for chord in binding.keys {
            exercise(binding.context, KeyEvent::new(chord.code, chord.modifiers));
        }
    }
}

/// No modifier.
const NONE: KeyModifiers = KeyModifiers::NONE;

/// Puts the model in `context` and feeds `key` to the reducer, asserting what
/// the action bound there is supposed to do.
///
/// The match is exhaustive over [`Action`] on purpose: the compiler is the
/// checklist.
fn exercise(context: Context, key: KeyEvent) {
    let action = keys::action(context, key)
        .or_else(|| {
            (context == Context::Form || context == Context::Filter).then_some(Action::TypeText)
        })
        .unwrap_or_else(|| panic!("{key:?} resolves to nothing in {context:?}"));
    let mut model = model();
    let effects = match context {
        Context::Anywhere | Context::Global => {
            model.screen = Screen::Namespaces;
            loaded(&mut model);
            update(&mut model, Event::Key(key))
        }
        Context::List | Context::Sessions => {
            model.screen = Screen::Sessions;
            sessions(&mut model);
            update(&mut model, Event::Key(key))
        }
        Context::Logs => {
            model.screen = Screen::Logs;
            tailed(&mut model, LOG_FILE, &records(30));
            // Scrolled back, so both directions have somewhere to go.
            model.logs.scroll(5);
            update(&mut model, Event::Key(key))
        }
        Context::Namespaces => {
            model.screen = Screen::Namespaces;
            loaded(&mut model);
            update(&mut model, Event::Key(key))
        }
        Context::Rules => {
            model.screen = Screen::Rules;
            loaded(&mut model);
            model.rule_selection.select("/project");
            update(&mut model, Event::Key(key))
        }
        Context::Ownership => {
            model.screen = Screen::Ownership;
            loaded(&mut model);
            update(&mut model, Event::Key(key))
        }
        Context::Modes => {
            model.screen = Screen::Modes;
            loaded(&mut model);
            update(&mut model, Event::Key(key))
        }
        Context::Form => {
            model.screen = Screen::Namespaces;
            loaded(&mut model);
            press(&mut model, KeyCode::Char('n'));
            type_text(&mut model, "fresh");
            update(&mut model, Event::Key(key))
        }
        Context::Confirm => {
            model.screen = Screen::Namespaces;
            loaded(&mut model);
            press(&mut model, KeyCode::Char('d'));
            update(&mut model, Event::Key(key))
        }
        Context::Filter => {
            model.screen = Screen::Namespaces;
            loaded(&mut model);
            press(&mut model, KeyCode::Char('/'));
            type_text(&mut model, "pro");
            update(&mut model, Event::Key(key))
        }
        Context::Help => {
            press(&mut model, KeyCode::Char('?'));
            model.help_scroll = 3;
            update(&mut model, Event::Key(key))
        }
    };
    let what = format!("{action:?} through {key:?} in {context:?}");
    match action {
        Action::Quit => {
            assert!(model.finished, "{what} did not finish");
            assert_eq!(effects, vec![Effect::Quit], "{what}");
        }
        Action::ToggleHelp => assert!(model.help, "{what}"),
        Action::NextScreen => assert_eq!(model.screen, Screen::Namespaces.step(true), "{what}"),
        Action::PreviousScreen => {
            assert_eq!(model.screen, Screen::Namespaces.step(false), "{what}");
        }
        Action::Focus(screen) => assert_eq!(model.screen, screen, "{what}"),
        Action::Refresh => assert!(!effects.is_empty(), "{what} read nothing"),
        Action::Suspend => assert_eq!(effects, vec![Effect::Suspend], "{what}"),
        Action::SelectNext if context == Context::Help => {
            assert_eq!(model.help_scroll, 4, "{what}");
        }
        Action::SelectPrevious if context == Context::Help => {
            assert_eq!(model.help_scroll, 2, "{what}");
        }
        Action::PageDown if context == Context::Help => {
            assert!(model.help_scroll > 3, "{what}");
        }
        Action::PageUp if context == Context::Help => {
            assert_eq!(model.help_scroll, 0, "{what}");
        }
        Action::SelectFirst if context == Context::Help => {
            assert_eq!(model.help_scroll, 0, "{what}");
        }
        Action::SelectLast if context == Context::Help => {
            assert_eq!(model.help_scroll, crate::keys::help_rows() - 1, "{what}");
        }
        Action::SelectNext if context == Context::Logs => {
            assert_eq!(
                model.logs.offset(),
                4,
                "{what} did not move towards the newest"
            );
        }
        Action::SelectPrevious if context == Context::Logs => {
            assert_eq!(
                model.logs.offset(),
                6,
                "{what} did not move towards the oldest"
            );
        }
        Action::PageDown if context == Context::Logs => {
            assert!(model.logs.following(), "{what}");
        }
        Action::PageUp if context == Context::Logs => {
            assert_eq!(model.logs.offset(), 15, "{what}");
        }
        Action::SelectFirst if context == Context::Logs => {
            assert_eq!(
                model.logs.offset(),
                29,
                "{what} did not reach the oldest line"
            );
        }
        Action::SelectLast if context == Context::Logs => {
            assert!(
                model.logs.following(),
                "{what} did not return to the newest"
            );
        }
        Action::Follow => assert!(model.logs.following(), "{what}"),
        Action::CycleLevel => assert_eq!(model.logs.level(), Level::Debug, "{what}"),
        Action::SelectNext | Action::PageDown if context == Context::Modes => {
            assert_eq!(model.modes.row, 1, "{what}");
        }
        Action::SelectPrevious | Action::PageUp if context == Context::Modes => {
            assert_eq!(model.modes.row, 0, "{what}");
        }
        Action::SelectNext => assert_eq!(model.session_selection.selected(), Some("2"), "{what}"),
        Action::SelectPrevious => {
            assert_eq!(model.session_selection.selected(), Some("1"), "{what}");
        }
        Action::SelectFirst => {
            assert_eq!(model.session_selection.selected(), Some("1"), "{what}");
        }
        Action::SelectLast => {
            assert_eq!(model.session_selection.selected(), Some("30"), "{what}");
        }
        Action::PageDown => {
            assert_eq!(model.session_selection.selected(), Some("11"), "{what}");
        }
        Action::PageUp => {
            assert_eq!(model.session_selection.selected(), Some("1"), "{what}");
        }
        Action::StartFilter => assert!(
            model
                .selection()
                .is_some_and(crate::model::Selection::is_filtering),
            "{what}"
        ),
        Action::OpenNamespace => assert_eq!(model.screen, Screen::Rules, "{what}"),
        Action::CreateNamespace | Action::AddRule | Action::EditOwnership => assert!(
            matches!(model.dialog, Some(Dialog::Form(_))),
            "{what} opened no form"
        ),
        Action::DeleteNamespace | Action::RemoveRule => assert!(
            matches!(model.dialog, Some(Dialog::Confirm(_))),
            "{what} asked nothing"
        ),
        Action::CycleValue if context == Context::Modes => {
            assert!(model.modes.edited, "{what} did not touch the buffer");
        }
        Action::CycleValue => {
            let Some(Dialog::Form(form)) = &model.dialog else {
                panic!("{what} lost the form");
            };
            assert!(!form.fields[form.focus].value.is_empty(), "{what}");
        }
        Action::ApplyMode => assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, Effect::Mutate { .. })),
            "{what} issued nothing"
        ),
        Action::Confirm if context == Context::Confirm => assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, Effect::Mutate { .. })),
            "{what} issued nothing"
        ),
        Action::Confirm => assert!(
            model
                .namespace_selection
                .filter()
                .is_some_and(|filter| filter == "pro")
                && !model.namespace_selection.is_filtering(),
            "{what} did not accept the pattern"
        ),
        Action::Cancel if context == Context::Help => assert!(!model.help, "{what}"),
        Action::Cancel if context == Context::Filter => {
            assert_eq!(model.namespace_selection.filter(), None, "{what}");
        }
        Action::Cancel if context == Context::List => {
            assert_eq!(model.session_selection.filter(), None, "{what}");
        }
        Action::Cancel => assert!(model.dialog.is_none(), "{what} dismissed nothing"),
        Action::NextField | Action::PreviousField => {
            let Some(Dialog::Form(form)) = &model.dialog else {
                panic!("{what} lost the form");
            };
            assert_ne!(form.focus, 0, "{what} did not move the cursor");
        }
        Action::Submit => assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, Effect::Mutate { .. })),
            "{what} submitted nothing"
        ),
        Action::Backspace if context == Context::Filter => {
            assert_eq!(model.namespace_selection.filter(), Some("pr"), "{what}");
        }
        Action::Backspace => {
            let Some(Dialog::Form(form)) = &model.dialog else {
                panic!("{what} lost the form");
            };
            assert_eq!(form.fields[0].value, "fres", "{what}");
        }
        Action::TypeText if context == Context::Filter => {
            assert_eq!(model.namespace_selection.filter(), Some("prox"), "{what}");
        }
        Action::TypeText => {
            let Some(Dialog::Form(form)) = &model.dialog else {
                panic!("{what} lost the form");
            };
            assert_eq!(form.fields[0].value, "freshx", "{what}");
        }
    }
}

/// A session list long enough for the paging bindings to have somewhere to go.
fn sessions(model: &mut Model) {
    update(
        model,
        Event::Fetched {
            fetch: Fetch::Sessions,
            result: Ok(Reply::SessionList {
                sessions: (1..=30).map(session).collect(),
            }),
        },
    );
}

// ---------------------------------------------------------------------------
// Serve-and-present supervision, and the terminal size
// ---------------------------------------------------------------------------

#[test]
fn a_presented_server_stopping_ends_the_interface() {
    let mut model = Model::new(Mode::Serving, "/srv/control.sock", None);
    update(
        &mut model,
        Event::ServerStopped {
            reason: Some("a listener died".to_owned()),
        },
    );
    assert!(model.finished);
    assert_eq!(model.status.tone, Tone::Failure);
    assert!(model.status.message.contains("a listener died"));
}

#[test]
fn a_resize_is_remembered_so_the_placeholder_can_be_decided() {
    let mut model = model();
    assert!(
        update(
            &mut model,
            Event::Resize {
                width: 20,
                height: 5
            }
        )
        .is_empty()
    );
    assert_eq!(model.size, (20, 5));
    assert!(!model.fits());
}

#[test]
fn the_overview_reports_what_the_server_said_including_its_endpoints() {
    let mut model = model();
    update(
        &mut model,
        Event::Fetched {
            fetch: Fetch::ServerInfo,
            result: Ok(Reply::ServerInfo {
                version: "0.1.0".to_owned(),
                state_file: "/srv/state.toml".to_owned(),
                control_socket: "/srv/control.sock".to_owned(),
                namespaces: 2,
                listeners: vec![ListenerInfo::new("tcp", "127.0.0.1:9000")],
                node_descriptors: 0,
                node_descriptor_budget: 4096,
                log_file: Some("/srv/voidportd.log".to_owned()),
            }),
        },
    );
    let facts = model.server.ready().expect("read");
    assert_eq!(facts.listeners.len(), 1);
    assert_eq!(model.version.as_deref(), Some("0.1.0"));
    assert_eq!(model.log_file(), Some("/srv/voidportd.log"));
}

// ---------------------------------------------------------------------------
// The Logs screen
// ---------------------------------------------------------------------------

#[test]
fn the_logs_screen_tails_the_file_the_server_named() {
    let mut model = model();
    informed(&mut model, Some(LOG_FILE));

    // Focusing it re-reads where the file is and reads the file itself.
    let effects = press(&mut model, KeyCode::Char('7'));
    assert_eq!(model.screen, Screen::Logs);
    assert_eq!(
        effects,
        vec![Effect::Fetch(Fetch::ServerInfo), read_log(LOG_FILE)]
    );
    // And it rides the ordinary tick from then on.
    assert_eq!(
        update(&mut model, Event::Tick),
        vec![Effect::Fetch(Fetch::ServerInfo), read_log(LOG_FILE)]
    );

    tailed(&mut model, LOG_FILE, &records(3));
    assert!(model.logs.following());
    assert_eq!(newest(&model), record("INFO", "3"));

    // What the server just logged appears at the bottom, and the view stays
    // there.
    tailed(
        &mut model,
        LOG_FILE,
        &[record("WARN", "a listener went away")],
    );
    assert_eq!(newest(&model), record("WARN", "a listener went away"));
    assert_eq!(model.logs.lines().len(), 4);
}

#[test]
fn a_log_screen_nobody_is_looking_at_reads_no_file() {
    let mut model = model();
    informed(&mut model, Some(LOG_FILE));
    for screen in SCREENS.iter().filter(|screen| **screen != Screen::Logs) {
        model.screen = *screen;
        assert!(
            !update(&mut model, Event::Tick).contains(&read_log(LOG_FILE)),
            "{screen:?} read the log file"
        );
    }
}

#[test]
fn scrolling_back_leaves_follow_and_a_binding_returns_to_it() {
    let mut model = model();
    informed(&mut model, Some(LOG_FILE));
    model.screen = Screen::Logs;
    tailed(&mut model, LOG_FILE, &records(20));

    press(&mut model, KeyCode::Up);
    press(&mut model, KeyCode::Up);
    assert!(!model.logs.following());
    assert_eq!(newest(&model), record("INFO", "18"));

    // Lines arriving under a scrolled-back view do not drag it along.
    tailed(&mut model, LOG_FILE, &records(2));
    assert_eq!(newest(&model), record("INFO", "18"));

    press(&mut model, KeyCode::Char('f'));
    assert!(model.logs.following());
    assert_eq!(newest(&model), record("INFO", "2"));

    // The oldest line the ring holds is reachable, and so is the newest.
    press(&mut model, KeyCode::Char('g'));
    assert_eq!(newest(&model), record("INFO", "1"));
    press(&mut model, KeyCode::Char('G'));
    assert!(model.logs.following());
}

#[test]
fn the_level_filter_cycles_through_the_tracing_levels() {
    let mut model = model();
    informed(&mut model, Some(LOG_FILE));
    model.screen = Screen::Logs;
    tailed(
        &mut model,
        LOG_FILE,
        &[
            record("TRACE", "t"),
            record("DEBUG", "d"),
            record("INFO", "i"),
            record("WARN", "w"),
            record("ERROR", "e"),
        ],
    );
    assert_eq!(model.logs.level(), Level::Trace);
    assert_eq!(model.logs.shown().count(), 5);

    for (level, shown) in [
        (Level::Debug, 4),
        (Level::Info, 3),
        (Level::Warn, 2),
        (Level::Error, 1),
        (Level::Trace, 5),
    ] {
        press(&mut model, KeyCode::Char('l'));
        assert_eq!(model.logs.level(), level);
        assert_eq!(model.logs.shown().count(), shown, "at {}", level.label());
    }
}

/// The attach-mode placeholder: a path this process cannot read is *named*,
/// and nothing else about the interface changes.
#[test]
fn a_log_file_that_cannot_be_read_is_named_and_the_interface_stays_healthy() {
    let mut model = model();
    informed(&mut model, Some("/elsewhere/voidportd.log"));
    model.screen = Screen::Logs;
    update(
        &mut model,
        Event::LogRead(LogRead {
            path: PathBuf::from("/elsewhere/voidportd.log"),
            lines: Vec::new(),
            trouble: Some("No such file or directory (os error 2)".to_owned()),
        }),
    );

    assert_eq!(model.log_file(), Some("/elsewhere/voidportd.log"));
    assert_eq!(
        model.logs.trouble.as_deref(),
        Some("No such file or directory (os error 2)")
    );
    assert!(!model.finished, "an unreadable log file ended the session");
    assert!(model.server.ready().is_some(), "the other views suffered");
    // And it keeps asking: a log file that appears later is picked up.
    assert!(
        update(&mut model, Event::Tick).contains(&read_log("/elsewhere/voidportd.log")),
        "the tail gave up on the file"
    );
    tailed(&mut model, "/elsewhere/voidportd.log", &records(1));
    assert_eq!(model.logs.trouble, None);
    assert_eq!(newest(&model), record("INFO", "1"));
}

#[test]
fn a_server_that_names_no_log_file_is_not_tailed() {
    let mut model = model();
    informed(&mut model, None);
    model.screen = Screen::Logs;
    assert_eq!(model.log_file(), None);
    assert_eq!(
        update(&mut model, Event::Tick),
        vec![Effect::Fetch(Fetch::ServerInfo)],
        "there is no file to read"
    );
}

#[test]
fn a_different_log_file_is_not_a_continuation_of_the_old_one() {
    let mut model = model();
    informed(&mut model, Some(LOG_FILE));
    model.screen = Screen::Logs;
    tailed(&mut model, LOG_FILE, &records(3));
    assert_eq!(model.logs.lines().len(), 3);

    // A reconnect to a restarted server, logging somewhere else: what the ring
    // holds described the old file and describes nothing now.
    informed(&mut model, Some("/srv/voidport/other.log"));
    tailed(
        &mut model,
        "/srv/voidport/other.log",
        &[record("INFO", "new")],
    );
    assert_eq!(model.logs.lines().len(), 1);
    assert_eq!(newest(&model), record("INFO", "new"));
    assert_eq!(
        model.logs.source.as_deref(),
        Some("/srv/voidport/other.log")
    );
}
