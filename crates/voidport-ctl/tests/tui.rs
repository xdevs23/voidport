//! What one operator does through the CLI, another sees in the TUI.
//!
//! The two surfaces share a control protocol, a client and a server, and the
//! design's freshness rule says the second must notice the first within one
//! tick. This drives the real `voidport-ctl` binary against a real server while
//! the interface's own model holds a view of it — the only place in the
//! workspace where both operator surfaces run at once.
//!
//! The interface is driven through `voidport_tui::harness`, the one headless
//! driver: a copy of that plumbing here could quietly stop dispatching a fetch
//! and this test would then pass without ever having read the server.

mod support;

use support::{Ctl as _, TempDir, server};
use voidport_tui::harness::Harness;
use voidport_tui::model::Screen;

/// The same state file the CLI suite drives.
const STATE: &str = r#"
[[namespaces]]
name = "project"

[[namespaces.rules]]
path = "/project"
mode = "rw"
target = "project"
"#;

#[test]
fn a_mutation_made_through_the_cli_reaches_a_watching_interface() {
    let directory = TempDir::new("tui-and-ctl");
    directory.directory("project");
    directory.directory("extra");
    let server = server(&directory, STATE);
    let mut interface = Harness::attach(server.socket()).expect("the control socket accepts");

    // The namespace list, as the interface holds it.
    interface.focus(Screen::Namespaces);
    assert!(
        interface.settle(|model| model.namespace_keys() == ["project"]),
        "the interface never read the namespace list"
    );

    // Another operator, at another terminal.
    server.expect_ok(&["namespace", "create", "from-the-cli"]);
    assert!(
        interface.settle(|model| model
            .namespace_keys()
            .iter()
            .any(|key| key == "from-the-cli")),
        "the CLI's namespace never reached the interface"
    );

    // A rule added through the CLI reaches the per-namespace view the same way.
    interface.model.namespace_selection.select("project");
    interface.focus(Screen::Rules);
    assert!(
        interface.settle(|model| model.rule_keys() == ["/project"]),
        "the interface never read the rule list"
    );
    server.expect_ok(&[
        "rule", "add", "project", "/extra", "--mode", "ro", "--target", "extra",
    ]);
    assert!(
        interface.settle(|model| model.rule_keys().iter().any(|key| key == "/extra")),
        "the CLI's rule never reached the interface"
    );

    // And a deletion clears the selection that named it, with a note.
    interface.focus(Screen::Namespaces);
    interface.model.namespace_selection.select("from-the-cli");
    server.expect_ok(&["namespace", "delete", "from-the-cli"]);
    assert!(
        interface.settle(|model| model.namespace_selection.selected().is_none()),
        "the deleted namespace kept the selection"
    );
    assert!(
        interface.model.status.message.contains("from-the-cli"),
        "{:?}",
        interface.model.status
    );
}
