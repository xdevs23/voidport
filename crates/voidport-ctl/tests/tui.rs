//! What one operator does through the CLI, another sees in the TUI. The
//! interface runs headless through `voidport_test_support::tui`, so this test
//! cannot pass without having read the server.

#![forbid(unsafe_code)]

mod support;

use support::{Ctl as _, TempDir, server};
use voidport_test_support::tui::Harness;
use voidport_tui::model::Screen;

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

    interface.focus(Screen::Namespaces);
    assert!(
        interface.settle(|model| model.namespace_keys() == ["project"]),
        "the interface never read the namespace list"
    );

    server.expect_ok(&["namespace", "create", "from-the-cli"]);
    assert!(
        interface.settle(|model| model
            .namespace_keys()
            .iter()
            .any(|key| key == "from-the-cli")),
        "the CLI's namespace never reached the interface"
    );

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
