//! Every screen, drawn into a `TestBackend` buffer and asserted on.
//!
//! No terminal is involved anywhere here: `TestBackend` is a plain in-memory
//! buffer, so the suite runs with no controlling terminal at all. What is
//! asserted is what an operator would read — the interface is a report, and a
//! report that says the wrong thing is a defect no reducer test would catch.

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use voidport_control::{
    AuthMode, HostDirectIo, IdMapping, IdSentinel, ListenerInfo, NamespaceName, NamespaceSpec,
    NamespaceSummary, OwnershipMode, OwnershipSpec, PermissionMode, Rule, SessionSummary,
    ShareMode, UnmappedPolicy,
};
use voidport_tui::model::form::Form;
use voidport_tui::model::view::View;
use voidport_tui::model::{
    Confirm, Connection, Dialog, LaunchNotes, MIN_HEIGHT, MIN_WIDTH, Mode, Model, Screen,
    ServerFacts, Status,
};
use voidport_tui::render;

/// Draws one frame and returns it as text, one line per row.
fn frame(model: &Model, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("a test backend");
    terminal
        .draw(|frame| render::draw(frame, model))
        .expect("the frame draws");
    let buffer = terminal.backend().buffer().clone();
    let area = buffer.area;
    (0..area.height)
        .map(|y| {
            (0..area.width)
                .map(|x| buffer[(x, y)].symbol().to_owned())
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A frame at a comfortable size.
fn drawn(model: &Model) -> String {
    frame(model, 110, 30)
}

fn name(raw: &str) -> NamespaceName {
    NamespaceName::new(raw).expect("valid namespace name")
}

fn model() -> Model {
    let mut model = Model::new(Mode::Attach, "/run/voidport/control.sock", None);
    model.connection = Connection::Connected;
    model.version = Some("0.1.0".to_owned());
    model.size = (110, 30);
    model
}

fn with_server(model: &mut Model) {
    model.server = View::Ready(ServerFacts {
        version: "0.1.0".to_owned(),
        state_file: "/srv/voidport/state.toml".to_owned(),
        control_socket: "/srv/voidport/control.sock".to_owned(),
        namespaces: 2,
        listeners: vec![
            ListenerInfo::new("tcp", "127.0.0.1:40404"),
            ListenerInfo::new("unix", "/srv/voidport/data.sock"),
        ],
        log_file: Some("/srv/voidport/voidportd.log".to_owned()),
    });
    model.sessions = View::Ready(vec![session(7)]);
}

fn session(id: u64) -> SessionSummary {
    SessionSummary {
        id,
        namespace: name("project"),
        subpath: "/project".to_owned(),
        transport: "tcp".to_owned(),
        peer: "127.0.0.1:52020".to_owned(),
        nodes: 12,
        handles: 2,
        subscribed: true,
    }
}

fn namespaces(model: &mut Model) {
    model.namespaces = View::Ready(vec![
        NamespaceSummary {
            name: name("alpha"),
            ownership: OwnershipMode::Passthrough,
            permission: PermissionMode::Passthrough,
            direct_io: HostDirectIo::Cached,
            auth: AuthMode::None,
            rules: 1,
        },
        NamespaceSummary {
            name: name("project"),
            ownership: OwnershipMode::Map,
            permission: PermissionMode::Passthrough,
            direct_io: HostDirectIo::Cached,
            auth: AuthMode::None,
            rules: 3,
        },
    ]);
    model.namespace_selection.select("project");
}

fn namespace(model: &mut Model) {
    namespaces(model);
    model.namespace = View::Ready(NamespaceSpec {
        ownership: OwnershipSpec::Map {
            unmapped: UnmappedPolicy::Hide,
            squash_uid: 65534,
            squash_gid: 65533,
            uid_map: vec![IdMapping::new(IdSentinel::Uid, 0)],
            gid_map: Vec::new(),
        },
        rules: vec![
            Rule::new("/project", ShareMode::Rw).with_target("/srv/project"),
            Rule::new("/project/secret", ShareMode::Hidden),
            // A pattern rule on the directory the first rule covers: a row of
            // its own, shown by the pair that keys it.
            Rule::new("/project", ShareMode::Ro).with_match("docs-*"),
        ],
        ..NamespaceSpec::new(name("project"))
    });
    model.modes.permission = "passthrough".to_owned();
    model.modes.auth = "none".to_owned();
    model.rule_selection.select("/project");
}

#[test]
fn the_overview_shows_the_server_its_endpoints_and_its_sessions() {
    let mut model = model();
    with_server(&mut model);
    let rendered = drawn(&model);
    assert!(rendered.contains("Overview"), "{rendered}");
    assert!(rendered.contains("0.1.0"), "{rendered}");
    assert!(rendered.contains("/srv/voidport/state.toml"), "{rendered}");
    assert!(
        rendered.contains("/srv/voidport/control.sock"),
        "{rendered}"
    );
    // `ListenerInfo`'s own `Display`, the same rendering `voidport-ctl` prints.
    assert!(rendered.contains("tcp 127.0.0.1:40404"), "{rendered}");
    assert!(
        rendered.contains("unix /srv/voidport/data.sock"),
        "{rendered}"
    );
    for listener in &model.server.ready().expect("read").listeners {
        assert!(rendered.contains(&listener.to_string()), "{rendered}");
    }
    assert!(rendered.contains("sessions        1"), "{rendered}");
    assert!(
        rendered.contains("quitting leaves this server serving"),
        "{rendered}"
    );
}

#[test]
fn the_overview_shows_a_seeded_launchs_mount_commands_and_auth_note() {
    let mut model = Model::new(
        Mode::Serving,
        "/srv/voidport/control.sock",
        Some(LaunchNotes {
            namespace: "share".to_owned(),
            mounts: vec![
                "voidport mount voidport://127.0.0.1:40404/@share /mnt/share".to_owned(),
                "voidport mount voidport+unix://%2Fsrv%2Fdata.sock/@share /mnt/share".to_owned(),
            ],
            control_command: "voidport-ctl --socket /srv/voidport/control.sock info".to_owned(),
            auth_note: Some("Note: auth is \"none\" — see docs/THREAT-MODEL.md.".to_owned()),
        }),
    );
    model.connection = Connection::Connected;
    with_server(&mut model);
    let rendered = drawn(&model);
    assert!(
        rendered.contains("voidport mount voidport://127.0.0.1:40404/@share /mnt/share"),
        "{rendered}"
    );
    assert!(
        rendered.contains("voidport+unix://%2Fsrv%2Fdata.sock"),
        "{rendered}"
    );
    assert!(
        rendered.contains("voidport-ctl --socket /srv/voidport/control.sock info"),
        "{rendered}"
    );
    assert!(rendered.contains("THREAT-MODEL.md"), "{rendered}");
    assert!(
        rendered.contains("quitting shuts this server down"),
        "{rendered}"
    );
}

#[test]
fn the_namespace_list_shows_every_column_and_marks_the_selection() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    namespaces(&mut model);
    let rendered = drawn(&model);
    assert!(rendered.contains("NAME"), "{rendered}");
    assert!(rendered.contains("OWNERSHIP"), "{rendered}");
    assert!(rendered.contains("PERMISSION"), "{rendered}");
    assert!(rendered.contains("AUTH"), "{rendered}");
    assert!(rendered.contains("RULES"), "{rendered}");
    assert!(rendered.contains("alpha"), "{rendered}");
    assert!(rendered.contains("project"), "{rendered}");
    assert!(rendered.contains("map"), "{rendered}");
    assert!(rendered.contains("n: create, d: delete"), "{rendered}");
}

#[test]
fn an_empty_or_unread_list_says_which_it_is() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    model.namespaces = View::Ready(Vec::new());
    assert!(drawn(&model).contains("no namespaces"));

    model.namespaces = View::Failed("the socket died".to_owned());
    let rendered = drawn(&model);
    assert!(rendered.contains("cannot read this view"), "{rendered}");
    assert!(rendered.contains("the socket died"), "{rendered}");

    model.namespaces = View::Loading;
    assert!(drawn(&model).contains("reading…"));
}

#[test]
fn the_rule_list_shows_modes_keys_and_targets() {
    let mut model = model();
    model.screen = Screen::Rules;
    namespace(&mut model);
    let rendered = drawn(&model);
    assert!(rendered.contains("namespace \"project\""), "{rendered}");
    assert!(rendered.contains("MODE"), "{rendered}");
    assert!(rendered.contains("rw"), "{rendered}");
    assert!(rendered.contains("/srv/project"), "{rendered}");
    assert!(rendered.contains("hidden"), "{rendered}");
    assert!(rendered.contains("/project/secret"), "{rendered}");
    // A pattern rule is its own row, shown as the pair `rule remove` takes —
    // the same spelling `voidport-ctl` lists it with.
    assert!(rendered.contains("/project --match 'docs-*'"), "{rendered}");
    assert!(rendered.contains("a: add, d: remove"), "{rendered}");
}

#[test]
fn the_ownership_screen_shows_the_whole_policy_with_sentinels_intact() {
    let mut model = model();
    model.screen = Screen::Ownership;
    namespace(&mut model);
    let rendered = drawn(&model);
    assert!(rendered.contains("mode        map"), "{rendered}");
    assert!(rendered.contains("unmapped    hide"), "{rendered}");
    assert!(
        rendered.contains("squash      uid 65534, gid 65533"),
        "{rendered}"
    );
    assert!(rendered.contains("uid map     uid->0"), "{rendered}");
    assert!(rendered.contains("gid map     empty"), "{rendered}");

    model.namespace = View::Ready(NamespaceSpec {
        ownership: OwnershipSpec::Static { uid: 1, gid: 2 },
        ..NamespaceSpec::new(name("project"))
    });
    assert!(drawn(&model).contains("static      uid 1, gid 2"));
}

#[test]
fn the_mode_screen_shows_the_server_value_beside_the_one_to_apply() {
    let mut model = model();
    model.screen = Screen::Modes;
    namespace(&mut model);
    let rendered = drawn(&model);
    assert!(rendered.contains("SETTING"), "{rendered}");
    assert!(rendered.contains("SERVER"), "{rendered}");
    assert!(rendered.contains("TO APPLY"), "{rendered}");
    assert!(rendered.contains("permission"), "{rendered}");
    assert!(rendered.contains("passthrough"), "{rendered}");
    assert!(rendered.contains("auth"), "{rendered}");
    assert!(rendered.contains("none"), "{rendered}");
    assert!(
        rendered.contains("Space: change, Enter: apply"),
        "{rendered}"
    );
}

#[test]
fn the_session_list_shows_one_row_per_mount() {
    let mut model = model();
    model.screen = Screen::Sessions;
    model.sessions = View::Ready(vec![session(7), session(8)]);
    model.session_selection.select("8");
    let rendered = drawn(&model);
    assert!(rendered.contains("NAMESPACE"), "{rendered}");
    assert!(rendered.contains("HANDLES"), "{rendered}");
    assert!(rendered.contains("127.0.0.1:52020"), "{rendered}");
    assert!(rendered.contains("/project"), "{rendered}");

    model.sessions = View::Ready(Vec::new());
    assert!(drawn(&model).contains("no sessions"));
}

#[test]
fn a_long_list_scrolls_so_the_selection_stays_visible() {
    let mut model = model();
    model.screen = Screen::Sessions;
    model.sessions = View::Ready((1..=60).map(session).collect());
    model.session_selection.select("60");
    let rendered = drawn(&model);
    assert!(rendered.contains("│60     project"), "{rendered}");
    assert!(
        !rendered.contains("│1      project"),
        "the window moved past the first row:\n{rendered}"
    );
}

/// The log tail: what it is showing, where it is showing it from, and where
/// the view sits in the file.
#[test]
fn the_logs_screen_shows_the_tail_it_holds_and_names_the_file() {
    let mut model = model();
    with_server(&mut model);
    model.screen = Screen::Logs;
    model.logs.append(vec![
        "2026-08-16T10:11:12.345678Z  INFO voidportd: voidportd started".to_owned(),
        "2026-08-16T10:11:13.000000Z  WARN voidportd: a listener went away".to_owned(),
    ]);

    let rendered = drawn(&model);
    assert!(rendered.contains("Logs"), "{rendered}");
    assert!(
        rendered.contains("tailing /srv/voidport/voidportd.log"),
        "{rendered}"
    );
    assert!(rendered.contains("following"), "{rendered}");
    assert!(rendered.contains("level >= trace"), "{rendered}");
    assert!(rendered.contains("voidportd started"), "{rendered}");
    assert!(rendered.contains("a listener went away"), "{rendered}");

    // Scrolled back, the screen says how far and how to get back.
    model.logs.append(vec![
        "2026-08-16T10:11:14.000000Z  INFO voidportd: and then this".to_owned(),
    ]);
    model.logs.scroll(1);
    let rendered = drawn(&model);
    assert!(rendered.contains("1 lines back (f: follow)"), "{rendered}");
    assert!(!rendered.contains("and then this"), "{rendered}");
}

/// The honest placeholder: a log file this process cannot read is *named*.
#[test]
fn a_log_file_that_cannot_be_read_is_named_rather_than_worked_around() {
    let mut model = model();
    with_server(&mut model);
    model.screen = Screen::Logs;
    model.logs.trouble = Some("No such file or directory (os error 2)".to_owned());

    let rendered = drawn(&model);
    assert!(
        rendered.contains("cannot read /srv/voidport/voidportd.log"),
        "{rendered}"
    );
    assert!(rendered.contains("os error 2"), "{rendered}");
}

#[test]
fn a_server_that_names_no_log_file_says_so() {
    let mut model = model();
    with_server(&mut model);
    model.screen = Screen::Logs;
    let mut facts = model.server.ready().expect("read").clone();
    facts.log_file = None;
    model.server = View::Ready(facts);

    let rendered = drawn(&model);
    assert!(rendered.contains("names no log file"), "{rendered}");
    assert!(rendered.contains("stderr"), "{rendered}");
}

#[test]
fn a_filter_is_shown_while_it_is_in_force() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    namespaces(&mut model);
    model.namespace_selection.start_filter();
    for character in "pro".chars() {
        model.namespace_selection.push_filter(character);
    }
    let rendered = drawn(&model);
    assert!(rendered.contains("/pro_"), "{rendered}");
    assert!(rendered.contains("project"), "{rendered}");
    assert!(!rendered.contains("alpha"), "{rendered}");
}

#[test]
fn the_help_overlay_lists_every_binding() {
    let mut model = model();
    model.help = true;
    // Tall enough for the whole table, derived from the table: a binding added
    // to it must not silently fall off the bottom of this assertion. The
    // overlay takes 90% of the frame less its borders, so the frame is sized
    // with room to spare.
    let height =
        u16::try_from(voidport_tui::keys::help_rows() * 2 + 10).expect("a drawable height");
    let rendered = frame(&model, 110, height);
    for binding in voidport_tui::keys::BINDINGS {
        assert!(
            rendered.contains(binding.action.label()),
            "Help does not mention {:?}:\n{rendered}",
            binding.action
        );
    }
    assert!(rendered.contains("Ctrl-C"), "{rendered}");
    assert!(rendered.contains("any character"), "{rendered}");
}

/// The list is canonical only if it can be *read*, and the size it has to be
/// readable at is the smallest one the interface claims to support.
///
/// Drawn at a comfortable 110x60 the overlay happens to fit, which is exactly
/// why that size proves nothing about it. At the contractual minimum it shows
/// about a fifth of itself, so the assertion is that every row is reachable by
/// scrolling — the first one at the top, the last one at the bottom, and
/// nothing beyond it.
#[test]
fn the_help_overlay_scrolls_so_every_binding_is_reachable_at_the_minimum_size() {
    let mut model = model();
    model.size = (MIN_WIDTH, MIN_HEIGHT);
    model.help = true;

    let rows = voidport_tui::keys::help_rows();
    let mut seen = String::new();
    for scroll in 0..rows {
        model.help_scroll = scroll;
        seen.push_str(&frame(&model, MIN_WIDTH, MIN_HEIGHT));
        seen.push('\n');
    }
    for binding in voidport_tui::keys::BINDINGS {
        assert!(
            seen.contains(binding.action.label()),
            "{:?} cannot be read at {MIN_WIDTH}x{MIN_HEIGHT} at any scroll position",
            binding.action
        );
    }

    // The table's own first and last rows, derived, not quoted: a
    // binding added to either end moves these with it.
    let order = voidport_tui::keys::HELP_ORDER;
    let first = *order.first().expect("Help lists something");
    let last = voidport_tui::keys::bindings(*order.last().expect("Help lists something"))
        .last()
        .expect("the last context has bindings")
        .action
        .label();

    model.help_scroll = 0;
    let top = frame(&model, MIN_WIDTH, MIN_HEIGHT);
    assert!(top.contains("line 1 of"), "{top}");
    assert!(top.contains(first.title()), "{top}");
    assert!(
        !top.contains(last),
        "the whole list fitted, so this size proves nothing about scrolling:\n{top}"
    );

    // And the last position still draws the last row, not an empty box.
    model.help_scroll = rows - 1;
    let bottom = frame(&model, MIN_WIDTH, MIN_HEIGHT);
    assert!(bottom.contains(last), "{bottom}");
}

#[test]
fn a_form_shows_its_fields_its_hint_and_its_error() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    namespaces(&mut model);
    let mut form = Form::rule_add(name("project"));
    form.error = Some("a rule needs a path".to_owned());
    model.dialog = Some(Dialog::Form(form));
    let rendered = drawn(&model);
    assert!(rendered.contains("Add rule to \"project\""), "{rendered}");
    assert!(rendered.contains("path"), "{rendered}");
    assert!(rendered.contains("mode"), "{rendered}");
    assert!(rendered.contains("target"), "{rendered}");
    assert!(rendered.contains("a rule needs a path"), "{rendered}");
    assert!(rendered.contains("Enter: submit"), "{rendered}");
}

#[test]
fn a_confirmation_asks_in_words() {
    let mut model = model();
    model.screen = Screen::Namespaces;
    namespaces(&mut model);
    model.dialog = Some(Dialog::Confirm(Confirm {
        prompt: "Delete namespace \"project\"?".to_owned(),
        description: "delete namespace \"project\"".to_owned(),
        request: voidport_control::Request::NamespaceDelete {
            name: name("project"),
        },
    }));
    let rendered = drawn(&model);
    assert!(rendered.contains("Delete namespace"), "{rendered}");
    assert!(rendered.contains("y: yes"), "{rendered}");
}

#[test]
fn the_status_line_carries_the_socket_the_version_and_the_last_outcome() {
    let mut model = model();
    model.status = Status::failure("not-found: no namespace \"gone\"");
    let rendered = drawn(&model);
    assert!(
        rendered.contains("/run/voidport/control.sock"),
        "{rendered}"
    );
    assert!(rendered.contains("voidportd 0.1.0"), "{rendered}");
    assert!(rendered.contains("no namespace"), "{rendered}");
}

#[test]
fn a_lost_connection_banners_above_the_body() {
    let mut model = model();
    model.connection = Connection::Lost {
        reason: "the socket died".to_owned(),
        attempt: 3,
    };
    let rendered = drawn(&model);
    assert!(
        rendered.contains("disconnected: the socket died"),
        "{rendered}"
    );
    assert!(rendered.contains("attempt 3"), "{rendered}");
}

#[test]
fn a_terminal_below_the_minimum_gets_the_placeholder_and_nothing_else() {
    let mut model = model();
    with_server(&mut model);
    model.size = (MIN_WIDTH - 1, MIN_HEIGHT - 1);
    let rendered = frame(&model, MIN_WIDTH - 1, MIN_HEIGHT - 1);
    assert!(rendered.contains("terminal too small"), "{rendered}");
    assert!(
        rendered.contains(&format!("at least {MIN_WIDTH}x{MIN_HEIGHT}")),
        "{rendered}"
    );
    assert!(
        !rendered.contains("Overview"),
        "a degraded layout was drawn:\n{rendered}"
    );

    // One row taller and one column wider is enough for the real interface.
    model.size = (MIN_WIDTH, MIN_HEIGHT);
    let rendered = frame(&model, MIN_WIDTH, MIN_HEIGHT);
    assert!(rendered.contains("Overview"), "{rendered}");
    assert!(!rendered.contains("terminal too small"), "{rendered}");
}
