#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::fs;

use rustix::process::{Pid, Signal};
use support::{ControlClient, RunningServer, TempDir, daemon_config};
use voidport_control::Request;
use voidport_pty::{ENTER_ALTERNATE, LEAVE_ALTERNATE, Pty, Spawn};

/// The working directory is the temporary directory of the case, so nothing
/// resolved relatively ends up in the source tree.
fn voidportd(directory: &TempDir, arguments: &[&str]) -> Pty {
    Pty::spawn(&Spawn::new(env!("CARGO_BIN_EXE_voidportd"), directory.path()).args(arguments))
}

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

fn signal(pty: &Pty, signal: Signal) {
    let pid =
        Pid::from_raw(i32::try_from(pty.pid()).expect("a plausible pid")).expect("a live pid");
    rustix::process::kill_process(pid, signal).expect("the signal is delivered");
}

#[test]
fn attaching_presents_a_running_server_and_leaves_it_serving() {
    let directory = TempDir::new("tui-attach");
    let state_file = directory.write("state.toml", &state(&directory));
    let server = RunningServer::start(&daemon_config(&state_file)).expect("the server starts");

    let socket = server.socket().display().to_string();
    let mut pty = voidportd(&directory, &["--tui", "--control-socket", &socket]);
    assert!(
        pty.wait_for(ENTER_ALTERNATE),
        "the interface never took the terminal over:\n{}",
        pty.output()
    );
    assert!(pty.wait_until(Pty::is_raw), "raw mode was never entered");
    assert!(pty.wait_for("Overview"), "{}", pty.output());
    // The state file has port 0, so only the server knows the bound endpoint.
    let endpoint = server.data_tcp().to_string();
    assert!(pty.wait_for(&endpoint), "{}", pty.output());

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
    // Closed with `?`, not Esc: a lone Esc immediately followed by `q` is `Alt-q`
    // to any terminal parser, and this test types faster than a person can.
    pty.send(b"?");
    pty.send(b"q");
    let status = pty.wait();
    assert!(status.success(), "the interface exited with {status:?}");
    assert!(
        pty.output().contains(LEAVE_ALTERNATE),
        "the alternate screen was never given back"
    );
    assert!(pty.wait_until(Pty::is_cooked), "the terminal was left raw");

    let mut client = ControlClient::connect(server.socket()).expect("the server still serves");
    client.expect_ok(&Request::ServerInfo {});
}

#[test]
fn a_sigterm_restores_the_terminal_and_stops_cleanly() {
    let directory = TempDir::new("tui-sigterm");
    let state_file = directory.write("state.toml", &state(&directory));
    let server = RunningServer::start(&daemon_config(&state_file)).expect("the server starts");

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

#[test]
fn attaching_with_no_flags_finds_the_per_user_socket() {
    let directory = TempDir::new("tui-lookup");
    // The control socket beside the state file is the first path the lookup tries.
    let state_directory = directory.directory("voidport");
    let state_file = state_directory.join("state.toml");
    fs::write(&state_file, state(&directory)).expect("a writable state file");
    let server = RunningServer::start(&daemon_config(&state_file)).expect("the server starts");
    assert_eq!(
        server.socket(),
        state_directory.join("control.sock"),
        "the case has to bind the path the lookup looks for"
    );

    // `HOME` is set with `XDG_STATE_HOME` so the case cannot reach the socket
    // of the user running the suite through the `~/.local/state` fallback.
    let state_home = directory.path().display().to_string();
    let mut pty = Pty::spawn(
        &Spawn::new(env!("CARGO_BIN_EXE_voidportd"), directory.path())
            .args(&["--tui"])
            .env("XDG_STATE_HOME", &state_home)
            .env("HOME", &state_home),
    );
    assert!(pty.wait_for("Overview"), "{}", pty.output());
    // Only the server knows the bound endpoint, so seeing it proves the interface
    // reached this server.
    let endpoint = server.data_tcp().to_string();
    assert!(pty.wait_for(&endpoint), "{}", pty.output());

    pty.send(b"q");
    let status = pty.wait();
    assert!(status.success(), "the interface exited with {status:?}");
    assert!(pty.wait_until(Pty::is_cooked), "the terminal was left raw");
}

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
    // Waited for, not read after the exit: the last write of the child and this
    // read are two events that a busy machine orders either way.
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
    // Waited for, not read after the exit: the last write of the child and this
    // read are two events that a busy machine orders either way.
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
    // Startup logging is synchronous and precedes presentation, so the first frame
    // shows the startup record is written.
    let log = directory.join("voidportd.log");
    assert!(
        fs::read_to_string(&log).is_ok_and(|written| written.contains("voidportd started")),
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
        !socket.exists(),
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
        pty.wait_for_text("README.md"),
        "the auth-none note never appeared for a tcp listener:\n{}",
        pty.text()
    );

    pty.send(b"q");
    let status = pty.wait();
    assert!(status.success(), "the interface exited with {status:?}");
    assert!(
        !socket.exists(),
        "quitting must shut the seeded server down"
    );

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
        fs::read_to_string(&log).is_ok_and(|written| written.contains("voidportd started")),
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

/// `EnvFilter::try_from_default_env` parses an empty `RUST_LOG` into a filter
/// that enables nothing, and build sandboxes export exactly that.
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
        fs::read_to_string(&log).is_ok_and(|written| written.contains("voidportd started")),
        "an empty RUST_LOG silenced the daemon: {:?}",
        fs::read_to_string(&log)
    );

    pty.send(b"q");
    assert!(pty.wait().success());
}
