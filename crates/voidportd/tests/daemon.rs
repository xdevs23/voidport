#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::fs;
use std::io::Read;
use std::process::{Child, Command, Stdio};

use rustix::process::{Pid, Signal};
use support::{ControlClient, TempDir};
use voidport_control::{NamespaceName, NamespaceSpec, Reply, Request};
use voidport_test_support::{ReadinessSocket, Startup};

fn ready(child: &Child, readiness: &ReadinessSocket) -> bool {
    readiness.wait_for(child) == Startup::Ready
}

/// Graft targets are opened when a namespace is built, so the target is created
/// inside the temporary directory of the test before the daemon starts.
fn state(directory: &TempDir) -> String {
    format!(
        r#"
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

fn spawn(
    state_file: &std::path::Path,
    socket: &std::path::Path,
    readiness: &ReadinessSocket,
) -> Child {
    Command::new(env!("CARGO_BIN_EXE_voidportd"))
        .arg("--state")
        .arg(state_file)
        .arg("--control-socket")
        .arg(socket)
        .env("NOTIFY_SOCKET", readiness.path())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the daemon binary runs")
}

fn stderr_of(child: &mut Child) -> String {
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    stderr
}

fn refused(mut child: Child, readiness: &ReadinessSocket) -> String {
    if ready(&child, readiness) {
        let _ = child.kill();
        let _ = child.wait();
        panic!("the daemon must refuse to start, but it is serving");
    }
    let status = child.wait().expect("the daemon exits");
    let stderr = stderr_of(&mut child);
    assert!(
        !status.success(),
        "the daemon must refuse to start: {stderr}"
    );
    stderr
}

#[test]
fn the_daemon_serves_a_state_file_and_stops_cleanly_on_each_signal() {
    for signal in [Signal::INT, Signal::TERM] {
        let directory = TempDir::new("daemon-signal");
        let state_file = directory.write("state.toml", &state(&directory));
        let socket = directory.join("control.sock");
        let readiness = ReadinessSocket::bind(directory.join("notify.sock"));

        let mut child = spawn(&state_file, &socket, &readiness);
        assert!(
            ready(&child, &readiness),
            "the daemon must serve the control socket"
        );

        let mut client = ControlClient::connect(&socket).expect("connects");
        let Reply::ServerInfo { namespaces, .. } = client.expect_ok(&Request::ServerInfo {}) else {
            panic!("expected server info");
        };
        assert_eq!(namespaces, 1);
        drop(client);

        let pid =
            Pid::from_raw(i32::try_from(child.id()).expect("a plausible pid")).expect("a live pid");
        rustix::process::kill_process(pid, signal).expect("the signal is delivered");

        let status = child.wait().expect("the daemon exits");
        assert!(
            status.success(),
            "{signal:?} must be a clean shutdown, got {status:?}: {}",
            stderr_of(&mut child)
        );
        assert!(
            !socket.exists(),
            "a clean shutdown must unlink the control socket"
        );
    }
}

#[test]
fn a_daemon_that_cannot_report_readiness_exits_with_an_error_and_unlinks_its_socket() {
    let directory = TempDir::new("daemon-notify-unreachable");
    let state_file = directory.write("state.toml", &state(&directory));
    let socket = directory.join("control.sock");

    let mut child = Command::new(env!("CARGO_BIN_EXE_voidportd"))
        .arg("--state")
        .arg(&state_file)
        .arg("--control-socket")
        .arg(&socket)
        .env("NOTIFY_SOCKET", directory.join("nobody.notify"))
        .stderr(Stdio::piped())
        .spawn()
        .expect("the daemon binary runs");
    let status = child.wait().expect("the daemon exits");

    assert!(
        !status.success(),
        "the daemon must exit with an error: {}",
        stderr_of(&mut child)
    );
    assert!(!socket.exists(), "the exit must unlink the control socket");
}

#[test]
fn a_control_socket_from_the_state_file_uses_its_configured_spelling() {
    let directory = TempDir::new("daemon-relative-socket");
    let state_file = directory.write(
        "state.toml",
        &format!(
            "[server]\ncontrol_socket = \"control.sock\"\n{}",
            state(&directory)
        ),
    );
    let elsewhere = TempDir::new("daemon-relative-cwd");
    let readiness = ReadinessSocket::bind(directory.join("notify.sock"));

    // The control socket is not a host target, so the process interprets its
    // relative spelling where the daemon was started.
    let mut child = Command::new(env!("CARGO_BIN_EXE_voidportd"))
        .arg("--state")
        .arg(&state_file)
        .current_dir(elsewhere.path())
        .env("NOTIFY_SOCKET", readiness.path())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the daemon binary runs");

    let socket = elsewhere.join("control.sock");
    assert!(
        ready(&child, &readiness),
        "the socket must use its process-relative configured spelling"
    );
    assert!(
        !directory.join("control.sock").exists(),
        "the control socket must not be resolved as a host target"
    );

    let mut client = ControlClient::connect(&socket).expect("connects");
    let Reply::ServerInfo { control_socket, .. } = client.expect_ok(&Request::ServerInfo {}) else {
        panic!("expected server info");
    };
    assert_eq!(control_socket, "control.sock");
    drop(client);

    let pid =
        Pid::from_raw(i32::try_from(child.id()).expect("a plausible pid")).expect("a live pid");
    rustix::process::kill_process(pid, Signal::TERM).expect("the signal is delivered");
    let status = child.wait().expect("the daemon exits");
    assert!(status.success(), "{}", stderr_of(&mut child));
}

#[test]
fn a_second_daemon_process_on_the_same_state_file_is_refused() {
    let directory = TempDir::new("daemon-lock");
    let state_file = directory.write("state.toml", &state(&directory));
    let socket = directory.join("control.sock");
    // Every daemon of this test reports to one socket: the first reports once,
    // and the refused ones exit without a report.
    let readiness = ReadinessSocket::bind(directory.join("notify.sock"));

    let mut first = spawn(&state_file, &socket, &readiness);
    assert!(ready(&first, &readiness), "the first daemon starts");

    let stderr = refused(
        spawn(&state_file, &directory.join("second.sock"), &readiness),
        &readiness,
    );
    assert!(stderr.contains("already owns"), "{stderr}");
    assert!(
        !directory.join("second.sock").exists(),
        "a refused startup must not leave a socket behind"
    );

    // The link follows the state file through the rename, so the claim has to be
    // about the file and not about the spelling.
    let mut client = ControlClient::connect(&socket).expect("connects");
    client.expect_ok(&Request::NamespaceCreate {
        namespace: NamespaceSpec::new(NamespaceName::new("mutated").expect("a valid name")),
    });
    drop(client);

    let alias = directory.join("alias.toml");
    std::os::unix::fs::symlink(&state_file, &alias).expect("a link to the state file");
    let stderr = refused(
        spawn(&alias, &directory.join("third.sock"), &readiness),
        &readiness,
    );
    assert!(
        stderr.contains("already owns"),
        "a daemon reaching the same state file through a link must refuse: {stderr}"
    );
    assert!(
        !directory.join("third.sock").exists(),
        "a refused startup must not leave a socket behind"
    );

    let pid =
        Pid::from_raw(i32::try_from(first.id()).expect("a plausible pid")).expect("a live pid");
    rustix::process::kill_process(pid, Signal::TERM).expect("the signal is delivered");
    assert!(first.wait().expect("the daemon exits").success());
}

#[test]
fn an_invalid_state_file_refuses_startup_and_says_why() {
    let directory = TempDir::new("daemon-invalid");
    let state_file = directory.write(
        "state.toml",
        r#"
        [[namespaces]]
        name = "project"
        [[namespaces.rules]]
        path = "/a"
        mode = "rw"
        target = "/srv/a"
        [[namespaces.rules]]
        path = "/a/secret"
        mode = "hidden"
        [[namespaces.rules]]
        path = "/a/secret/key"
        mode = "ro"
        "#,
    );
    let socket = directory.join("control.sock");

    let output = Command::new(env!("CARGO_BIN_EXE_voidportd"))
        .arg("--state")
        .arg(&state_file)
        .arg("--control-socket")
        .arg(&socket)
        .output()
        .expect("the daemon binary runs");
    assert!(
        !output.status.success(),
        "a dead configuration must not start"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("project"), "{stderr}");
    assert!(stderr.contains("/a/secret/key"), "{stderr}");
    assert!(!socket.exists(), "nothing was bound");
}

#[test]
fn a_missing_state_file_is_created_and_served() {
    let directory = TempDir::new("daemon-missing");
    let state_file = directory.join("absent.toml");
    let socket = directory.join("control.sock");
    let readiness = ReadinessSocket::bind(directory.join("notify.sock"));

    let mut child = spawn(&state_file, &socket, &readiness);
    assert!(
        ready(&child, &readiness),
        "the daemon must serve the control socket: {}",
        stderr_of(&mut child)
    );
    assert_eq!(
        fs::read_to_string(&state_file).expect("the state file was created"),
        "[server]\n"
    );

    let mut client = ControlClient::connect(&socket).expect("connects");
    let Reply::ServerInfo { namespaces, .. } = client.expect_ok(&Request::ServerInfo {}) else {
        panic!("expected server info");
    };
    assert_eq!(namespaces, 0);
    drop(client);

    let pid =
        Pid::from_raw(i32::try_from(child.id()).expect("a plausible pid")).expect("a live pid");
    rustix::process::kill_process(pid, Signal::TERM).expect("the signal is delivered");
    let status = child.wait().expect("the daemon exits");
    assert!(status.success(), "{}", stderr_of(&mut child));
}
