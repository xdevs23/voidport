//! The real `voidportd` binary: startup from a state file, clean shutdown on
//! SIGINT and SIGTERM, and the failures that must refuse startup outright.

mod support;

use std::fs;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal};
use support::{ControlClient, TempDir, wait_for_removal, wait_for_socket};
use voidport_control::{NamespaceName, NamespaceSpec, Reply, Request};

/// How long a test waits for the daemon to come up or go down.
const PATIENCE: Duration = Duration::from_secs(10);

/// A state file with one namespace, grafting a directory the test owns.
///
/// Graft targets are pinned when a namespace is built, so the target has to
/// exist before the daemon starts; it is created inside the test's own
/// temporary directory, not pointed at a shared system one, which no
/// test should be sharing read-write.
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

/// Spawns the real daemon with stderr captured.
fn spawn(state_file: &std::path::Path, socket: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_voidportd"))
        .arg("--state")
        .arg(state_file)
        .arg("--control-socket")
        .arg(socket)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the daemon binary runs")
}

/// Reads whatever the child wrote to stderr.
fn stderr_of(child: &mut Child) -> String {
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    stderr
}

/// Waits for a daemon that must refuse to start, and returns what it said.
///
/// The wait is bounded and kills a survivor, because the failure this guards
/// against is a daemon that *does* start: waiting for that one to exit would
/// hang the suite instead of failing it.
fn refused(mut child: Child) -> String {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("the daemon is waitable") {
            let stderr = stderr_of(&mut child);
            assert!(
                !status.success(),
                "the daemon must refuse to start: {stderr}"
            );
            return stderr;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("the daemon must refuse to start, but it is serving");
}

#[test]
fn the_daemon_serves_a_state_file_and_stops_cleanly_on_each_signal() {
    for signal in [Signal::INT, Signal::TERM] {
        let directory = TempDir::new("daemon-signal");
        let state_file = directory.write("state.toml", &state(&directory));
        let socket = directory.join("control.sock");

        let mut child = spawn(&state_file, &socket);
        assert!(
            wait_for_socket(&socket, PATIENCE),
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
            wait_for_removal(&socket, PATIENCE),
            "a clean shutdown must unlink the control socket"
        );
    }
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

    // Started from a different working directory on purpose: the control
    // socket is not a host target, so its relative spelling is interpreted by
    // the process exactly where the daemon was started.
    let mut child = Command::new(env!("CARGO_BIN_EXE_voidportd"))
        .arg("--state")
        .arg(&state_file)
        .current_dir(elsewhere.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the daemon binary runs");

    let socket = elsewhere.join("control.sock");
    assert!(
        wait_for_socket(&socket, PATIENCE),
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

    let mut first = spawn(&state_file, &socket);
    assert!(
        wait_for_socket(&socket, PATIENCE),
        "the first daemon starts"
    );

    let stderr = refused(spawn(&state_file, &directory.join("second.sock")));
    assert!(stderr.contains("already owns"), "{stderr}");
    assert!(
        !directory.join("second.sock").exists(),
        "a refused startup must not leave a socket behind"
    );

    // The same file spelled as a symbolic link, after a mutation has renamed a
    // new inode over it: the link follows the state file through that rename,
    // so the claim has to be about the file and not about the spelling.
    let mut client = ControlClient::connect(&socket).expect("connects");
    client.expect_ok(&Request::NamespaceCreate {
        namespace: NamespaceSpec::new(NamespaceName::new("mutated").expect("a valid name")),
    });
    drop(client);

    let alias = directory.join("alias.toml");
    std::os::unix::fs::symlink(&state_file, &alias).expect("a link to the state file");
    let stderr = refused(spawn(&alias, &directory.join("third.sock")));
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
    // The required startup contract: only the *cleanly missing* file is created,
    // as the empty document — a server with nothing configured. The malformed
    // file above is the other half of that decision, and still refuses.
    let directory = TempDir::new("daemon-missing");
    let state_file = directory.join("absent.toml");
    let socket = directory.join("control.sock");

    let mut child = spawn(&state_file, &socket);
    assert!(
        wait_for_socket(&socket, PATIENCE),
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
