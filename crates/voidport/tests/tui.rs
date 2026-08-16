//! The operator interface against a real mount.
//!
//! Two things about the TUI can only be shown with a guest actually mounted,
//! and both are here, not with the interface's own suite, because this
//! is where a real FUSE mount lives:
//!
//! * a rule changed through the interface's **client layer** — the same
//!   `Session` its worker drives, issuing the same typed operations its reducer
//!   composes — binds for a mounted guest at its next lookup;
//! * the Sessions view shows a new mount within one refresh interval, and
//!   drops it after the unmount.
//!
//! The interface is driven through `voidport_tui::harness`, the one headless
//! driver, so this suite and the interface's own suite are proving the same
//! plumbing.

mod support;

use std::fs;
use std::time::Duration;

use support::{Fixture, eventually};
use voidport_control::client::Timeouts;
use voidport_control::{NamespaceName, Request, Rule, ShareMode};
use voidport_tui::client::Session;
use voidport_tui::event::Event;
use voidport_tui::harness::Harness;
use voidport_tui::model::Screen;

/// How long a test waits for the server, the guest or the interface.
const PATIENCE: Duration = Duration::from_secs(10);

/// The namespace name, validated the way every operator surface validates it.
fn name(raw: &str) -> NamespaceName {
    NamespaceName::new(raw).expect("valid namespace name")
}

// ---------------------------------------------------------------------------
// Criterion 4 — a rule changed through the interface binds for a mounted guest
// ---------------------------------------------------------------------------

#[test]
fn a_rule_changed_through_the_interface_binds_at_the_guests_next_lookup() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("tui-rules");
    let guest = fixture.mount("tui-rules", "plain", "");
    assert!(fs::metadata(guest.path("tree")).expect("stat").is_dir());
    assert!(
        fs::metadata(guest.path("added")).is_err(),
        "nothing is grafted there yet"
    );

    // The interface's own client layer, issuing the operation its rule form
    // composes.
    let mut session = Session::connect_with(fixture.server.socket(), Timeouts::default())
        .expect("the control socket accepts");
    session
        .call(&Request::RuleAdd {
            namespace: name("plain"),
            rule: Rule::new("/added", ShareMode::Rw).with_target("added"),
        })
        .expect("the server answers")
        .expect("the server accepts the rule");

    assert!(
        eventually(PATIENCE, || fs::metadata(guest.path("added")).is_ok()),
        "the rule the interface added never reached the guest"
    );
    assert_eq!(
        fs::read(guest.path("added/inside")).expect("readable"),
        b"added"
    );

    // And removing it the same way takes it away again.
    session
        .call(&Request::RuleRemove {
            namespace: name("plain"),
            path: "/added".to_owned(),
            r#match: None,
        })
        .expect("the server answers")
        .expect("the server accepts the removal");
    assert!(
        eventually(PATIENCE, || fs::metadata(guest.path("added")).is_err()),
        "the removed rule stayed visible to the guest"
    );
}

// ---------------------------------------------------------------------------
// Criterion 7 — the Sessions view follows a real mount
// ---------------------------------------------------------------------------

#[test]
fn the_sessions_view_shows_a_mount_and_drops_it_after_the_unmount() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("tui-sessions");
    let mut interface =
        Harness::attach(fixture.server.socket()).expect("the control socket accepts");
    interface.model.screen = Screen::Sessions;
    interface.feed(Event::Tick);
    assert!(
        interface.settle(|model| model.sessions.ready().is_some_and(Vec::is_empty)),
        "the interface never read an empty session list"
    );

    let mut guest = fixture.mount("tui-sessions", "plain", "/tree");
    assert!(
        fs::metadata(guest.path("data.bin")).is_ok(),
        "the mount serves"
    );
    assert!(
        interface.settle(|model| model
            .sessions
            .ready()
            .is_some_and(|sessions| sessions.len() == 1)),
        "the new mount never appeared in the sessions view"
    );
    let session = interface
        .model
        .sessions
        .ready()
        .expect("read")
        .first()
        .expect("one session")
        .clone();
    assert_eq!(session.namespace.as_str(), "plain");
    assert_eq!(session.subpath, "/tree");
    assert_eq!(
        interface.model.session_selection.selected(),
        Some(session.id.to_string().as_str()),
        "the list selects the mount it just learned about"
    );

    guest.unmount_patiently().expect("the mount unmounts");
    drop(guest);
    assert!(
        interface.settle(|model| model.sessions.ready().is_some_and(Vec::is_empty)),
        "the ended session never left the view"
    );
    assert!(
        interface
            .model
            .status
            .message
            .contains(&session.id.to_string()),
        "the interface said nothing about the session that ended: {:?}",
        interface.model.status
    );
}
