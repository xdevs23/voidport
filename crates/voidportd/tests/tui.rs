//! `voidportd --tui`: the real binary, in a pty the test creates.
//!
//! Both launches are exercised as an operator would run them — attaching to a
//! server somebody else started, and serving one in the foreground — together
//! with the terminal's whole lifecycle around them: raw mode while it runs, an
//! ordinary terminal afterwards, a SIGTERM that restores before it exits, and a
//! failure before takeover that never touches the terminal at all.

mod support;

use std::fs;
use std::time::Duration;

use rustix::process::{Pid, Signal};
use support::{ControlClient, RunningServer, TempDir, daemon_config, wait_for_removal};
use voidport_control::Request;
use voidport_pty::{ENTER_ALTERNATE, LEAVE_ALTERNATE, Pty, Spawn};

/// How long a test waits for the daemon.
const PATIENCE: Duration = Duration::from_secs(10);

/// Runs the real `voidportd` binary in a fresh pty.
///
/// The working directory is the case's own temporary directory: named, so that
/// nothing the daemon or the harness resolves relatively lands in the source
/// tree, and so that the spawn never falls back to a `$HOME` a build sandbox
/// points at a directory that does not exist.
fn voidportd(directory: &TempDir, arguments: &[&str]) -> Pty {
    Pty::spawn(&Spawn::new(env!("CARGO_BIN_EXE_voidportd"), directory.path()).args(arguments))
}

/// A state file with one namespace and a tcp listener on an ephemeral port.
fn state(directory: &TempDir) -> String {
    format!(
        r#"
[[server.listeners]]
transport = "tcp"
addr = "127.0.0.1:0"

[[namespaces]]
name = "project"

[[namespaces.rules]]
path = "/project"
mode = "rw"
target = "{target}"
"#,
        target = directory.directory("project").display()
    )
}

/// Sends a signal to the process under the pty.
fn signal(pty: &Pty, signal: Signal) {
    let pid =
        Pid::from_raw(i32::try_from(pty.pid()).expect("a plausible pid")).expect("a live pid");
    rustix::process::kill_process(pid, signal).expect("the signal is delivered");
}

// ---------------------------------------------------------------------------
// Attach mode
// ---------------------------------------------------------------------------

#[test]
fn attaching_presents_a_running_server_and_leaves_it_serving() {
    let directory = TempDir::new("tui-attach");
    let state_file = directory.write("state.toml", &state(&directory));
    let server = RunningServer::start(&daemon_config(
        &state_file,
        support::environment(directory.path()),
    ))
    .expect("the server starts");

    let socket = server.socket().display().to_string();
    let mut pty = voidportd(&directory, &["--tui", "--control-socket", &socket]);
    assert!(
        pty.wait_for(ENTER_ALTERNATE),
        "the interface never took the terminal over:\n{}",
        pty.output()
    );
    assert!(pty.wait_until(Pty::is_raw), "raw mode was never entered");
    assert!(pty.wait_for("Overview"), "{}", pty.output());
    // The bound endpoint comes from the extended server-info reply: the state
    // file says port 0, so only the server can know this.
    let endpoint = server.data_tcp().to_string();
    assert!(pty.wait_for(&endpoint), "{}", pty.output());

    // Every screen, by keyboard alone.
    for (key, title) in [
        (b'2', "Namespaces"),
        (b'3', "Rules"),
        (b'4', "Ownership"),
        (b'5', "Permission"),
        (b'6', "Sessions"),
    ] {
        pty.send(&[key]);
        assert!(
            pty.wait_for(title),
            "{title} never appeared:\n{}",
            pty.output()
        );
    }
    pty.send(b"?");
    assert!(
        pty.wait_for_text("Ctrl-C quit"),
        "the help overlay never listed a binding:\n{}",
        pty.text()
    );
    // Closed with `?`, not Esc: a lone Esc immediately followed by `q`
    // is `Alt-q` to any terminal's parser, and this test types faster than a
    // person can.
    pty.send(b"?");
    pty.send(b"q");
    let status = pty.wait();
    assert!(status.success(), "the interface exited with {status:?}");
    assert!(
        pty.output().contains(LEAVE_ALTERNATE),
        "the alternate screen was never given back"
    );
    assert!(pty.wait_until(Pty::is_cooked), "the terminal was left raw");

    // Attach mode leaves the server exactly where it was.
    let mut client = ControlClient::connect(server.socket()).expect("the server still serves");
    client.expect_ok(&Request::ServerInfo {});
}

#[test]
fn a_sigterm_restores_the_terminal_and_stops_cleanly() {
    let directory = TempDir::new("tui-sigterm");
    let state_file = directory.write("state.toml", &state(&directory));
    let server = RunningServer::start(&daemon_config(
        &state_file,
        support::environment(directory.path()),
    ))
    .expect("the server starts");

    let socket = server.socket().display().to_string();
    let mut pty = voidportd(&directory, &["--tui", "--control-socket", &socket]);
    assert!(pty.wait_for("Overview"), "{}", pty.output());
    assert!(pty.wait_until(Pty::is_raw));

    signal(&pty, Signal::TERM);
    let status = pty.wait();
    assert!(
        status.success(),
        "a SIGTERM is a clean stop, not a failure: {status:?}"
    );
    assert!(
        pty.output().contains(LEAVE_ALTERNATE),
        "SIGTERM left the alternate screen up"
    );
    assert!(
        pty.wait_until(Pty::is_cooked),
        "SIGTERM left the terminal in raw mode"
    );
}

/// Attach mode with no `--control-socket` finds the per-user socket, which is
/// the same lookup `voidport-ctl` performs — one shared function, so an operator
/// who reaches their local instance with one surface reaches it with the other.
#[test]
fn attaching_with_no_flags_finds_the_per_user_socket() {
    let directory = TempDir::new("tui-lookup");
    // The state file goes where a flagless `voidportd share` would put it, so
    // the control socket beside it is exactly the path the lookup tries first.
    let state_directory = directory.directory("voidport");
    let state_file = state_directory.join("state.toml");
    fs::write(&state_file, state(&directory)).expect("a writable state file");
    let server = RunningServer::start(&daemon_config(
        &state_file,
        support::environment(&state_directory),
    ))
    .expect("the server starts");
    assert_eq!(
        server.socket(),
        state_directory.join("control.sock"),
        "the case has to bind the path the lookup looks for"
    );

    // `HOME` is pinned with `XDG_STATE_HOME` so the case cannot reach the
    // socket of whoever runs the suite through the `~/.local/state` fallback.
    let state_home = directory.path().display().to_string();
    let mut pty = Pty::spawn(
        &Spawn::new(env!("CARGO_BIN_EXE_voidportd"), directory.path())
            .args(&["--tui"])
            .env("XDG_STATE_HOME", &state_home)
            .env("HOME", &state_home),
    );
    assert!(pty.wait_for("Overview"), "{}", pty.output());
    // The bound endpoint is known only to the server, so seeing it proves the
    // interface reached *this* server and not merely a screen.
    let endpoint = server.data_tcp().to_string();
    assert!(pty.wait_for(&endpoint), "{}", pty.output());

    pty.send(b"q");
    let status = pty.wait();
    assert!(status.success(), "the interface exited with {status:?}");
    assert!(pty.wait_until(Pty::is_cooked), "the terminal was left raw");
}

/// With nothing to attach to, the failure names both paths the lookup tried and
/// the terminal is never touched.
#[test]
fn attaching_with_no_flags_and_no_server_names_every_path_tried() {
    let directory = TempDir::new("tui-lookup-none");
    let state_home = directory.path().display().to_string();
    let mut pty = Pty::spawn(
        &Spawn::new(env!("CARGO_BIN_EXE_voidportd"), directory.path())
            .args(&["--tui"])
            .env("XDG_STATE_HOME", &state_home)
            .env("HOME", &state_home),
    );
    // Waited for, not read after the exit: the child's last write and
    // this side's read of it are two different events, and a busy machine
    // orders them the other way round often enough to matter.
    let per_user = directory
        .join("voidport/control.sock")
        .display()
        .to_string();
    assert!(
        pty.wait_for(&per_user),
        "the per-user path is missing from:\n{:?}",
        pty.output()
    );
    let status = pty.wait();
    assert!(!status.success(), "a refused launch must exit nonzero");
    let output = pty.output();
    assert!(
        output.contains("/run/voidport/control.sock"),
        "the system path is missing from:\n{output:?}"
    );
    assert!(output.contains("--control-socket"), "{output:?}");
    assert!(
        !output.contains(ENTER_ALTERNATE),
        "the terminal was taken over before the failure:\n{output:?}"
    );
    assert!(pty.is_cooked(), "the terminal was not left alone");
}

#[test]
fn a_socket_that_is_not_there_prints_plainly_and_never_takes_the_terminal() {
    let directory = TempDir::new("tui-missing");
    let absent = directory.join("absent.sock").display().to_string();
    let mut pty = voidportd(&directory, &["--tui", "--control-socket", &absent]);
    // Waited for, not read after the exit: the child's last write and
    // this side's read of it are two different events, and a busy machine
    // orders them the other way round often enough to matter.
    assert!(pty.wait_for("cannot connect"), "{:?}", pty.output());
    let status = pty.wait();
    assert!(!status.success(), "a refused launch must exit nonzero");
    let output = pty.output();
    assert!(
        !output.contains(ENTER_ALTERNATE),
        "the terminal was taken over before the failure:\n{output:?}"
    );
    assert!(pty.is_cooked(), "the terminal was not left alone");
}

// ---------------------------------------------------------------------------
// Serve-and-present
// ---------------------------------------------------------------------------

#[test]
fn serving_and_presenting_a_state_file_shuts_it_down_on_quit() {
    let directory = TempDir::new("tui-serve");
    let state_file = directory.write("state.toml", &state(&directory));
    let socket = directory.join("control.sock");

    let mut pty = voidportd(
        &directory,
        &[
            "--tui",
            "--state",
            &state_file.display().to_string(),
            "--control-socket",
            &socket.display().to_string(),
        ],
    );
    assert!(pty.wait_for("Overview"), "{}", pty.output());
    assert!(
        pty.wait_for_text("Serving: quitting shuts this server down"),
        "{}",
        pty.text()
    );
    assert!(pty.wait_until(Pty::is_raw));
    // The daemon's own diagnostics go to a file beside the state file, never
    // over the frame.
    // Waited for by content, not by existence: the destination is opened when
    // the launch is worked out and written to as records are emitted, so a file
    // that is merely there proves nothing yet.
    let log = directory.join("voidportd.log");
    assert!(
        pty.wait_until(
            |_| fs::read_to_string(&log).is_ok_and(|written| written.contains("voidportd started"))
        ),
        "the daemon's tracing never reached its file: {:?}",
        fs::read_to_string(&log)
    );
    assert!(
        !pty.output().contains("voidportd started"),
        "a log line was drawn over the interface"
    );

    pty.send(b"q");
    let status = pty.wait();
    assert!(status.success(), "the interface exited with {status:?}");
    assert!(
        wait_for_removal(&socket, PATIENCE),
        "quitting must shut the server down, socket and all"
    );
    assert!(pty.wait_until(Pty::is_cooked));
}

#[test]
fn a_seeded_launch_presents_its_mount_commands_in_the_overview() {
    let directory = TempDir::new("tui-share");
    let shared = directory.directory("shared");
    let state_file = directory.join("state.toml");
    let socket = directory.join("control.sock");

    let mut pty = voidportd(
        &directory,
        &[
            "--tui",
            "--state",
            &state_file.display().to_string(),
            "--control-socket",
            &socket.display().to_string(),
            "share",
            &shared.display().to_string(),
            "--addr",
            "127.0.0.1:0",
        ],
    );
    assert!(pty.wait_for("Overview"), "{}", pty.output());
    // The copy-paste block the plain launch prints to stdout is rendered here
    // instead, with the port the listener actually bound.
    assert!(
        pty.wait_for_text("voidport mount voidport://127.0.0.1:"),
        "the mount command never appeared:\n{}",
        pty.text()
    );
    assert!(
        pty.wait_for_text("voidport-ctl --socket"),
        "the control-socket hint never appeared:\n{}",
        pty.text()
    );
    assert!(
        pty.wait_for_text("THREAT-MODEL.md"),
        "the auth-none note never appeared for a tcp listener:\n{}",
        pty.text()
    );

    pty.send(b"q");
    let status = pty.wait();
    assert!(status.success(), "the interface exited with {status:?}");
    assert!(
        wait_for_removal(&socket, PATIENCE),
        "quitting must shut the seeded server down"
    );

    // The seed is ordinary configuration afterwards, exactly as a plain seeded
    // launch leaves it.
    let persisted = fs::read_to_string(&state_file).expect("the state file was written");
    assert!(persisted.contains("[[namespaces]]"), "{persisted}");
    assert!(persisted.contains("shared"), "{persisted}");
}

#[test]
fn the_log_file_can_be_placed_by_hand() {
    let directory = TempDir::new("tui-logfile");
    let state_file = directory.write("state.toml", &state(&directory));
    let socket = directory.join("control.sock");
    let log = directory.join("elsewhere.log");

    let mut pty = voidportd(
        &directory,
        &[
            "--tui",
            "--state",
            &state_file.display().to_string(),
            "--control-socket",
            &socket.display().to_string(),
            "--log-file",
            &log.display().to_string(),
        ],
    );
    assert!(pty.wait_for("Overview"), "{}", pty.output());
    assert!(
        pty.wait_until(
            |_| fs::read_to_string(&log).is_ok_and(|written| written.contains("voidportd started"))
        ),
        "--log-file was not honoured: {:?}",
        fs::read_to_string(&log)
    );
    assert!(
        !directory.join("voidportd.log").exists(),
        "the default log file was written as well"
    );

    pty.send(b"q");
    assert!(pty.wait().success());
}

/// An empty `RUST_LOG` means "nobody asked for a filter", not "log nothing".
///
/// `EnvFilter::try_from_default_env` parses an empty value into a filter with
/// no directives, which enables nothing — so a daemon launched from an
/// environment that exports `RUST_LOG=` writes an empty log file and says
/// nothing about why. Build sandboxes export exactly that, which is where this
/// was found.
#[test]
fn an_empty_rust_log_does_not_silence_the_daemon() {
    let directory = TempDir::new("tui-empty-rust-log");
    let state_file = directory.write("state.toml", &state(&directory));
    let socket = directory.join("control.sock");
    let log = directory.join("elsewhere.log");

    let mut pty = Pty::spawn(
        &Spawn::new(env!("CARGO_BIN_EXE_voidportd"), directory.path())
            .args(&[
                "--tui",
                "--state",
                &state_file.display().to_string(),
                "--control-socket",
                &socket.display().to_string(),
                "--log-file",
                &log.display().to_string(),
            ])
            .env("RUST_LOG", ""),
    );
    assert!(pty.wait_for("Overview"), "{}", pty.output());
    assert!(
        pty.wait_until(
            |_| fs::read_to_string(&log).is_ok_and(|written| written.contains("voidportd started"))
        ),
        "an empty RUST_LOG silenced the daemon: {:?}",
        fs::read_to_string(&log)
    );

    pty.send(b"q");
    assert!(pty.wait().success());
}
