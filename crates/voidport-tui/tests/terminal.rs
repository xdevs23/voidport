#![forbid(unsafe_code)]

#[path = "support/pty.rs"]
mod pty;
mod support;

use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use pty::{
    ACKNOWLEDGEMENT, SCENARIO, SOCKET, STATE_FILE, acknowledge, await_observation, spawn, unique,
};
use voidport_pty::{CTRL_Z, ENTER_ALTERNATE, LEAVE_ALTERNATE, Pty};
use voidport_test_support::{RunningServer, daemon_config};
use voidport_tui::model::{Mode, Model};
use voidport_tui::terminal::Terminal;
use voidport_tui::{Options, Presentation};

const CLEAN: &str = "CHILD-CLEAN";

const REFUSED: &str = "CHILD-REFUSED";

const DELIBERATE: &str = "a deliberate panic inside the interface";

const INJECTED: &str = "an injected daemon failure";

/// Does nothing unless the scenario variable is set, so an ordinary
/// `cargo test` run skips it.
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

fn serving_failure_child() {
    let socket = std::env::var(SOCKET).expect("the parent names a control socket");
    let (report, stopped) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        await_observation();
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

/// Presents a real server and stops it while the interface has the terminal.
/// A presented server that stops while the interface runs is a failure of the
/// launch whether or not it stopped cleanly.
fn real_serving_failure_child() {
    let state_file =
        PathBuf::from(std::env::var(STATE_FILE).expect("the parent names a state file"));
    let mut server = RunningServer::start(&daemon_config(&state_file)).expect("the server starts");
    let socket = server.socket().to_path_buf();

    let (report, stopped) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        await_observation();
        server.stop();
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

fn panic_child() {
    let mut terminal = Terminal::acquire().expect("a pty is a terminal");
    let model = Model::new(Mode::Attach, "/run/voidport/control.sock", None);
    terminal.draw(&model).expect("the frame draws");
    println!("{ENTER_ALTERNATE}");
    await_observation();
    panic!("{DELIBERATE}");
}

/// Raw mode goes through the tty on stdin and succeeds. The alternate screen
/// is written to stdout, which is `/dev/full` and fails with `ENOSPC` on every
/// byte. The takeover fails after it changed the terminal, so only the
/// rollback restores the terminal.
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

fn missing_socket_child() {
    let options = Options::new(
        voidport_test_support::scratch_root()
            .join(format!("{}.sock", unique("voidport-tui-absent"))),
    );
    let error = voidport_tui::run(&options, Presentation::Attach, |_| {})
        .expect_err("nothing is listening there");
    eprintln!("{REFUSED}: {error}");
    std::process::exit(4);
}

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
    let directory = support::TempDir::new("panic-ack");
    let path = directory.join("ack.sock");
    let listener = UnixListener::bind(&path).expect("an acknowledgement listener");
    let mut pty = spawn("panic", &[(ACKNOWLEDGEMENT, path.to_str().unwrap())]);
    assert!(
        pty.wait_until(Pty::is_raw),
        "the terminal was never put into raw mode:\n{}",
        pty.output()
    );

    assert!(pty.wait_for("Overview"), "{}", pty.output());
    acknowledge(&listener, &pty);

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

    // The child is a session leader, so its process group is orphaned and the
    // kernel discards the job-control stop. What stays observable is that the
    // terminal is given back and taken again, and that the interface is redrawn.
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
    let (directory, server) = support::fixture("pty-serving-failure");
    let path = directory.join("ack.sock");
    let listener = UnixListener::bind(&path).expect("an acknowledgement listener");
    let mut pty = spawn(
        "serving-failure",
        &[
            (SOCKET, server.socket().to_str().unwrap()),
            (ACKNOWLEDGEMENT, path.to_str().unwrap()),
        ],
    );
    assert!(
        pty.wait_until(Pty::is_raw),
        "the interface never took the terminal over:\n{}",
        pty.output()
    );

    assert!(pty.wait_for("Overview"), "{}", pty.output());
    acknowledge(&listener, &pty);

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

#[test]
fn a_real_daemon_stopping_under_the_interface_restores_and_exits_nonzero() {
    let (directory, server) = support::fixture("pty-real-serving");
    drop(server);
    let state_file = directory.join("state.toml").display().to_string();
    let path = directory.join("ack.sock");
    let listener = UnixListener::bind(&path).expect("an acknowledgement listener");
    let mut pty = spawn(
        "real-serving-failure",
        &[
            (STATE_FILE, state_file.as_str()),
            (ACKNOWLEDGEMENT, path.to_str().unwrap()),
        ],
    );

    assert!(
        pty.wait_until(Pty::is_raw),
        "the interface never took the terminal over:\n{}",
        pty.output()
    );
    assert!(pty.wait_for("Overview"), "{}", pty.output());

    acknowledge(&listener, &pty);

    let status = pty.wait();
    assert!(!status.success(), "a stopped daemon must exit nonzero");
    // The wording of the report, not of the status line, which shows "the
    // server stopped" too inside the alternate screen.
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

#[test]
fn the_child_is_inert_without_a_scenario() {
    assert!(
        std::env::var(SCENARIO).is_err(),
        "the parent process must not carry a scenario"
    );
}
