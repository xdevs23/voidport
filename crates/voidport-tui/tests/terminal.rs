//! Terminal lifecycle, proven in a pty the test itself creates.
//!
//! Each case runs the real interface in a real terminal and asserts on what an
//! operator would be left with: raw mode while it runs, an ordinary cooked
//! terminal afterwards, and the alternate screen given back — on a quit, on a
//! panic, and around a suspend. A pre-takeover failure is proven the other way
//! round: the terminal is never touched at all.
//!
//! The child of every case is this binary itself, re-executed on
//! [`pty::CHILD_TEST`]; the product has no test hook of any kind.

mod support;

use std::path::PathBuf;
use std::time::Duration;

use support::pty::{SCENARIO, SOCKET, STATE_FILE, spawn, unique};
use voidport_pty::{CTRL_Z, ENTER_ALTERNATE, LEAVE_ALTERNATE, Pty};
use voidport_tui::model::{Mode, Model};
use voidport_tui::terminal::Terminal;
use voidport_tui::{Options, Presentation};
use voidportd::testing::{RunningServer, daemon_config, pinned_environment};

/// What the child prints when the interface returned cleanly.
const CLEAN: &str = "CHILD-CLEAN";

/// What it prints when the interface refused before taking anything over.
const REFUSED: &str = "CHILD-REFUSED";

/// The panic message the panic scenario raises.
const DELIBERATE: &str = "a deliberate panic inside the interface";

/// The failure the serve-and-present scenario injects.
const INJECTED: &str = "an injected daemon failure";

// ---------------------------------------------------------------------------
// The scenarios, run in the child process
// ---------------------------------------------------------------------------

/// The child every pty case runs.
///
/// Does nothing at all unless the scenario variable is set, so an ordinary
/// `cargo test` run simply skips it.
#[test]
fn pty_child() {
    let Ok(scenario) = std::env::var(SCENARIO) else {
        return;
    };
    match scenario.as_str() {
        "attach" | "suspend" => attach_child(),
        "panic" => panic_child(),
        "missing-socket" => missing_socket_child(),
        "takeover-failure" => takeover_failure_child(),
        "serving-failure" => serving_failure_child(),
        "real-serving-failure" => real_serving_failure_child(),
        other => panic!("unknown pty scenario {other:?}"),
    }
}

/// Runs the real interface against the server the parent started.
fn attach_child() {
    let socket = std::env::var(SOCKET).expect("the parent names a control socket");
    let options = Options::new(socket);
    match voidport_tui::run(&options, Presentation::Attach, |_| {}) {
        Ok(()) => {
            println!("{CLEAN}");
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!("{REFUSED}: {error}");
            std::process::exit(3);
        }
    }
}

/// Presents a server that dies on its own shortly after takeover.
///
/// The daemon itself belongs to the `voidportd` binary; what is proven here is
/// the supervisor path this crate owns — the terminal comes back, the failure
/// is reported plainly, and the exit is nonzero.
fn serving_failure_child() {
    let socket = std::env::var(SOCKET).expect("the parent names a control socket");
    let (report, stopped) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        let _ = report.send(Err(INJECTED.to_owned()));
    });
    let serving = Presentation::Serving(voidport_tui::Serving {
        notes: None,
        shutdown: Box::new(|| {}),
        stopped,
    });
    let error = voidport_tui::run(&Options::new(socket), serving, |_| {})
        .expect_err("the presented server died");
    eprintln!("{REFUSED}: {error}");
    std::process::exit(5);
}

/// Presents a **real** server, and really stops it while the interface has the
/// terminal.
///
/// The other serving scenario proves the supervisor against a `Serving` whose
/// three capabilities are the test's own. This one proves it against the thing
/// itself: a real `voidportd` daemon, its real control socket, the interface
/// attached to it and drawing — and then the daemon stops. Its `serve` is what
/// reports, so nothing about the failure is manufactured; a presented server
/// that stops while the interface is running is a failure of the launch
/// whether or not it stopped cleanly, and the operator has to be told on a
/// terminal they can read.
fn real_serving_failure_child() {
    let state_file =
        PathBuf::from(std::env::var(STATE_FILE).expect("the parent names a state file"));
    let directory = state_file.parent().expect("a state file has a parent");
    let mut server =
        RunningServer::start(&daemon_config(&state_file, pinned_environment(directory)))
            .expect("the server starts");
    let socket = server.socket().to_path_buf();

    let (report, stopped) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // Long enough for the takeover and the first frame; the case asserts on
        // raw mode before it waits for the exit either way.
        std::thread::sleep(Duration::from_millis(400));
        server.stop();
        // What `Daemon::serve` returned: it stopped, and it stopped cleanly.
        let _ = report.send(Ok(()));
    });

    let serving = Presentation::Serving(voidport_tui::Serving {
        notes: None,
        // Never called: the daemon is gone before the interface asks for it.
        shutdown: Box::new(|| {}),
        stopped,
    });
    let error = voidport_tui::run(&Options::new(socket), serving, |_| {})
        .expect_err("the presented server stopped under the interface");
    eprintln!("{REFUSED}: {error}");
    std::process::exit(7);
}

/// Takes the terminal over, draws, and panics with it still taken.
fn panic_child() {
    let mut terminal = Terminal::acquire().expect("a pty is a terminal");
    let model = Model::new(Mode::Attach, "/run/voidport/control.sock", None);
    terminal.draw(&model).expect("the frame draws");
    println!("{ENTER_ALTERNATE}");
    std::thread::sleep(Duration::from_millis(300));
    panic!("{DELIBERATE}");
}

/// Points stdout at a descriptor whose every write fails, then asks for the
/// terminal.
///
/// Raw mode goes through the tty on stdin and succeeds; the alternate screen is
/// written to stdout, which is now `/dev/full` — writable, and `ENOSPC` on
/// every byte. That is a takeover failing *after* it changed the terminal: the
/// one path where the rollback is all that stands between the operator and a
/// raw terminal with no interface in it, there being no `Terminal` to drop yet.
fn takeover_failure_child() {
    let sink = rustix::fs::open(
        "/dev/full",
        rustix::fs::OFlags::WRONLY,
        rustix::fs::Mode::empty(),
    )
    .expect("/dev/full opens");
    rustix::stdio::dup2_stdout(&sink).expect("stdout is replaceable");
    let error = Terminal::acquire().expect_err("stdout cannot be written to");
    eprintln!("{REFUSED}: {error}");
    std::process::exit(6);
}

/// Asks for a socket that is not there.
fn missing_socket_child() {
    let options = Options::new(
        voidportd::testing::scratch_root().join(format!("{}.sock", unique("voidport-tui-absent"))),
    );
    let error = voidport_tui::run(&options, Presentation::Attach, |_| {})
        .expect_err("nothing is listening there");
    eprintln!("{REFUSED}: {error}");
    std::process::exit(4);
}

// ---------------------------------------------------------------------------
// The cases, run in the parent
// ---------------------------------------------------------------------------

/// A server for a child to attach to, and a pty running that child.
fn attached(scenario: &str, label: &str) -> (support::TempDir, RunningServer, Pty) {
    let (directory, server) = support::fixture(label);
    let socket = server.socket().display().to_string();
    let pty = spawn(scenario, &[(SOCKET, socket.as_str())]);
    (directory, server, pty)
}

#[test]
fn quitting_gives_the_terminal_back() {
    let (_directory, _server, mut pty) = attached("attach", "pty-quit");
    assert!(
        pty.wait_for(ENTER_ALTERNATE),
        "the interface never took the terminal over:\n{}",
        pty.output()
    );
    assert!(
        pty.wait_until(Pty::is_raw),
        "the terminal was never put into raw mode"
    );
    assert!(pty.wait_for("Overview"), "{}", pty.output());

    pty.send(b"q");
    let status = pty.wait();
    assert!(status.success(), "the interface exited with {status:?}");
    assert!(pty.wait_for(CLEAN), "{}", pty.output());
    assert!(
        pty.output().contains(LEAVE_ALTERNATE),
        "the alternate screen was never given back:\n{:?}",
        pty.output()
    );
    assert!(
        pty.wait_until(Pty::is_cooked),
        "the terminal was left in raw mode"
    );
}

#[test]
fn a_panic_gives_the_terminal_back_before_it_prints() {
    let mut pty = spawn("panic", &[]);
    assert!(
        pty.wait_until(Pty::is_raw),
        "the terminal was never put into raw mode:\n{}",
        pty.output()
    );

    let status = pty.wait();
    assert!(!status.success(), "a panic must not exit successfully");
    assert!(
        pty.wait_for(DELIBERATE),
        "the panic message never reached the terminal:\n{:?}",
        pty.output()
    );
    let output = pty.output();
    let left = output
        .find(LEAVE_ALTERNATE)
        .expect("the alternate screen was never given back");
    let printed = output.find(DELIBERATE).expect("checked above");
    assert!(
        left < printed,
        "the panic printed into the alternate screen, where nobody could read it"
    );
    assert!(
        pty.wait_until(Pty::is_cooked),
        "a panic left the terminal in raw mode"
    );
}

#[test]
fn suspending_gives_the_terminal_back_and_resuming_redraws() {
    let (_directory, _server, mut pty) = attached("suspend", "pty-suspend");
    assert!(pty.wait_for("Overview"), "{}", pty.output());
    let before = pty.output().matches(ENTER_ALTERNATE).count();

    // In raw mode Ctrl-Z is a byte, not a signal: the interface reads it,
    // hands the terminal back, raises SIGTSTP on itself, and comes back.
    //
    // The child is a session leader here — a pty child always is — so its
    // process group is orphaned and the kernel discards the job-control stop
    // instead of leaving a process nothing could resume. What that leaves
    // observable is exactly the part this process controls: the terminal is
    // given back, then taken again, and the interface is redrawn.
    pty.send(&[CTRL_Z]);
    assert!(
        pty.wait_until(|pty| pty.output().matches(ENTER_ALTERNATE).count() > before),
        "the interface never came back from a suspend:\n{:?}",
        pty.output()
    );
    assert!(
        pty.output().contains(LEAVE_ALTERNATE),
        "the terminal was never handed back:\n{:?}",
        pty.output()
    );
    assert!(pty.is_raw(), "the resumed interface is not in raw mode");
    assert!(
        pty.wait_until(|pty| pty.output().matches("Overview").count() > 1),
        "the resumed interface never redrew:\n{:?}",
        pty.output()
    );

    pty.send(b"q");
    let status = pty.wait();
    assert!(
        status.success(),
        "the interface exited with {status:?}:\n{:?}",
        pty.output()
    );
    assert!(pty.wait_until(Pty::is_cooked));
}

#[test]
fn a_daemon_failure_after_takeover_restores_prints_and_exits_nonzero() {
    let (_directory, _server, mut pty) = attached("serving-failure", "pty-serving-failure");
    assert!(
        pty.wait_until(Pty::is_raw),
        "the interface never took the terminal over:\n{}",
        pty.output()
    );

    let status = pty.wait();
    assert!(!status.success(), "a dead daemon must exit nonzero");
    assert!(pty.wait_for(INJECTED), "{:?}", pty.output());
    let output = pty.output();
    let left = output
        .find(LEAVE_ALTERNATE)
        .expect("the alternate screen was never given back");
    let printed = output.find(INJECTED).expect("checked above");
    assert!(
        left < printed,
        "the failure printed into the alternate screen, where nobody could read it"
    );
    assert!(
        pty.wait_until(Pty::is_cooked),
        "a daemon failure left the terminal in raw mode"
    );
}

/// The same supervisor path, with a real daemon on the other end of it.
///
/// The case above injects the report; this one lets a real `voidportd` produce
/// it. The child starts a real daemon on a real control socket, presents it,
/// and stops it while the interface is drawing — so the whole path runs against
/// the thing itself: the terminal comes back, the failure is printed where the
/// operator can read it, and the exit is nonzero.
#[test]
fn a_real_daemon_stopping_under_the_interface_restores_and_exits_nonzero() {
    let (directory, server) = support::fixture("pty-real-serving");
    // The child serves the same state file, on a socket of its own; this
    // server's only job was to write one the child can serve.
    drop(server);
    let state_file = directory.join("state.toml").display().to_string();
    let mut pty = spawn("real-serving-failure", &[(STATE_FILE, state_file.as_str())]);

    assert!(
        pty.wait_until(Pty::is_raw),
        "the interface never took the terminal over:\n{}",
        pty.output()
    );
    assert!(pty.wait_for("Overview"), "{}", pty.output());

    let status = pty.wait();
    assert!(!status.success(), "a stopped daemon must exit nonzero");
    // The wording of the *report*, not of the status line: the interface says
    // "the server stopped" on its own status line too, and that one is drawn
    // inside the alternate screen.
    let stopped = "while the interface was running";
    assert!(pty.wait_for(stopped), "{:?}", pty.output());
    let output = pty.output();
    let left = output
        .find(LEAVE_ALTERNATE)
        .expect("the alternate screen was never given back");
    let printed = output.find(stopped).expect("checked above");
    assert!(
        left < printed,
        "the failure printed into the alternate screen, where nobody could read it"
    );
    assert!(
        pty.wait_until(Pty::is_cooked),
        "a stopped daemon left the terminal in raw mode"
    );
}

#[test]
fn a_pre_takeover_failure_prints_plainly_and_exits_nonzero() {
    let mut pty = spawn("missing-socket", &[]);
    let status = pty.wait();
    assert!(!status.success(), "a refused launch must exit nonzero");
    assert!(pty.wait_for(REFUSED), "{}", pty.output());
    let output = pty.output();
    assert!(output.contains("cannot connect"), "{output:?}");
    assert!(
        !output.contains(ENTER_ALTERNATE),
        "the terminal was taken over before the failure:\n{output:?}"
    );
    assert!(
        pty.is_cooked(),
        "a failure before takeover must leave the terminal alone"
    );
}

#[test]
fn a_takeover_that_fails_after_raw_mode_gives_the_terminal_back() {
    let mut pty = spawn("takeover-failure", &[]);
    let status = pty.wait();
    assert!(!status.success(), "a refused takeover must exit nonzero");
    assert!(pty.wait_for(REFUSED), "{}", pty.output());
    // `ENOSPC`, printed by the OS-error `Display`: the takeover got as far as
    // writing the alternate screen, which is to say raw mode was already on.
    assert!(
        pty.output().contains("os error 28"),
        "the takeover failed somewhere else than the step under test:\n{:?}",
        pty.output()
    );
    assert!(
        pty.wait_until(Pty::is_cooked),
        "a half-finished takeover left the terminal in raw mode:\n{:?}",
        pty.output()
    );
}

/// The child test is inert outside a pty run, so an ordinary `cargo test`
/// executes it as a no-op instead of hanging on a terminal it has not got.
#[test]
fn the_child_is_inert_without_a_scenario() {
    assert!(
        std::env::var(SCENARIO).is_err(),
        "the parent process must not carry a scenario"
    );
}
