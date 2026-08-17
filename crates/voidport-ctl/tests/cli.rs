//! The real CLI against a real server: every operation, both output modes, and
//! the exit status a script branches on.

mod support;

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;

use support::{Ctl as _, RunningServer, TempDir, server};
use voidport_control::{OwnershipSpec, Reply, Response};
use voidportd::testing::{create_directory, daemon_config, pinned_environment};

/// A state file with one namespace to inspect and mutate, and a data listener
/// on an ephemeral port so a session can be mounted and then listed.
const STATE: &str = r#"
[[server.listeners]]
transport = "tcp"
addr = "127.0.0.1:0"

[[namespaces]]
name = "project"

[[namespaces.rules]]
path = "/project"
mode = "rw"
target = "project"
"#;

/// A temporary directory holding the graft targets `STATE` names.
///
/// Graft targets are pinned at build time, so they must exist before the
/// server starts.
fn directory(label: &str) -> TempDir {
    let directory = TempDir::new(label);
    directory.directory("project");
    directory.directory("data");
    directory
}

/// Parses a `--json` line as the response envelope it must be.
fn envelope(line: &str) -> Response {
    serde_json::from_str(line.trim_end())
        .unwrap_or_else(|error| panic!("not a response envelope: {line}: {error}"))
}

#[test]
fn every_operation_is_reachable_from_the_command_line() {
    let directory = directory("operations");
    let server = server(&directory, STATE);

    let info = server.expect_ok(&["info"]);
    assert!(info.contains("version:"), "{info}");
    assert!(info.contains("state file:"), "{info}");
    assert!(
        info.contains(&server.socket().display().to_string()),
        "{info}"
    );

    server.expect_ok(&["namespace", "create", "scratch"]);
    let list = server.expect_ok(&["namespace", "list"]);
    assert!(list.contains("project"), "{list}");
    assert!(list.contains("scratch"), "{list}");

    server.expect_ok(&[
        "rule", "add", "scratch", "/data", "--mode", "ro", "--target", "data",
    ]);
    server.expect_ok(&["rule", "add", "scratch", "/data/*", "--mode", "hidden"]);
    server.expect_ok(&[
        "ownership",
        "set",
        "scratch",
        "--ownership",
        "map",
        "--uid-map",
        "uid:0",
        "--gid-map",
        "gid:0",
        "--unmapped",
        "hide",
    ]);
    server.expect_ok(&["permission", "set", "scratch", "--mode", "passthrough"]);
    server.expect_ok(&["auth", "set", "scratch", "--mode", "none"]);

    let shown = server.expect_ok(&["namespace", "show", "scratch"]);
    assert!(shown.contains("namespace:  scratch"), "{shown}");
    assert!(shown.contains("ownership:  map"), "{shown}");
    assert!(shown.contains("unmapped: hide"), "{shown}");
    // The sentinel is shown as configured, not as a resolved id.
    assert!(shown.contains("uid -> 0"), "{shown}");
    assert!(!shown.contains("4242"), "{shown}");
    assert!(shown.contains("ro     /data"), "{shown}");
    assert!(shown.contains("-> data"), "{shown}");

    server.expect_ok(&["rule", "remove", "scratch", "/data/*"]);
    server.expect_ok(&["namespace", "delete", "scratch"]);
    let list = server.expect_ok(&["namespace", "list"]);
    assert!(!list.contains("scratch"), "{list}");
}

#[test]
fn session_list_shows_the_mounts_the_data_plane_is_serving() {
    let directory = directory("sessions");
    let server = server(&directory, STATE);

    let empty = server.expect_ok(&["session", "list"]);
    assert_eq!(empty.trim(), "no sessions");

    // One real mount, handshaken over the real data listener.
    let _session = mount(&server, "project", "/project");

    let listed = server.expect_ok(&["session", "list"]);
    let lines: Vec<&str> = listed.lines().collect();
    assert!(lines[0].starts_with("ID"), "{listed}");
    assert!(lines[1].contains("project"), "{listed}");
    assert!(lines[1].contains("/project"), "{listed}");
    assert!(lines[1].contains("tcp"), "{listed}");

    let line = server.expect_ok(&["--json", "session", "list"]);
    let Response::Ok {
        result: Reply::SessionList { sessions },
    } = envelope(&line)
    else {
        panic!("expected a session list: {line}");
    };
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].namespace.as_str(), "project");
    assert_eq!(sessions[0].subpath, "/project");
    assert_eq!(sessions[0].nodes, 1, "the mount root");
}

/// The three listener operations, round-tripped through the real CLI: one
/// binds, `list` shows it, and `remove` takes it away again — with the state
/// file agreeing at every step, because that is what a restart would serve.
#[test]
fn listener_add_list_and_remove_round_trip_through_the_cli() {
    let directory = directory("listeners");
    let state_file = directory.join("state.toml");
    let server = server(&directory, STATE);
    let socket = directory.join("added.sock");
    let path = socket.display().to_string();

    // The startup listener, and nothing else.
    let listed = server.expect_ok(&["listener", "list"]);
    assert_eq!(listed.lines().count(), 1, "{listed}");
    assert!(listed.starts_with("tcp 127.0.0.1:"), "{listed}");

    let added = server.expect_ok(&["listener", "add", "--unix", &path]);
    assert_eq!(added.trim(), format!("listening on unix {path}"));
    assert!(socket.exists(), "the CLI's listener is really bound");

    let listed = server.expect_ok(&["listener", "list"]);
    assert!(listed.contains(&format!("unix {path}")), "{listed}");
    assert_eq!(listed.lines().count(), 2, "{listed}");
    // `info` shows the same set, from the same field.
    assert!(
        server
            .expect_ok(&["info"])
            .contains(&format!("unix {path}")),
        "the two readings of one field disagree"
    );
    assert!(
        fs::read_to_string(&state_file)
            .expect("readable")
            .contains(&path),
        "a listener the CLI added is in the file a restart reads"
    );

    // The JSON envelope is the script interface, for this operation too. The
    // address differs from the configured one because a listener is identified
    // by the source form it was asked for: a second `127.0.0.1:0` would be
    // refused as the duplicate it is.
    let line = server.expect_ok(&["--json", "listener", "add", "--addr", "127.0.0.2:0"]);
    let Response::Ok {
        result: Reply::Listener { listener },
    } = envelope(&line)
    else {
        panic!("expected a listener reply: {line}");
    };
    assert_eq!(listener.transport, "tcp");
    assert_ne!(
        listener.endpoint, "127.0.0.2:0",
        "the reply names the port the kernel gave, not the one asked for"
    );

    server.expect_ok(&["listener", "remove", &path]);
    assert!(!socket.exists(), "removal unlinked the socket");
    let listed = server.expect_ok(&["listener", "list"]);
    assert!(!listed.contains(&path), "{listed}");
    assert!(
        !fs::read_to_string(&state_file)
            .expect("readable")
            .contains(&path),
        "a removed listener is out of the file too"
    );

    // A refusal is a normal outcome: it prints the structured error and exits
    // nonzero, which is what a script branches on.
    let refused = server.expect_failure(&["listener", "remove", &path]);
    assert!(refused.starts_with("error [not-found]:"), "{refused}");
    assert!(refused.contains(&path), "{refused}");

    // Exactly one transport per invocation, and clap says so before any round
    // trip happens.
    let output = server.ctl(&["listener", "add", "--addr", "127.0.0.1:0", "--unix", &path]);
    assert!(!output.status.success());
}

/// Mounts a namespace over the data listener, returning the live connection.
///
/// Only the handshake is needed here — the data plane's own tests exercise the
/// operations — so it is written against `voidport-proto` directly instead of
/// pulling in the server suite's client.
fn mount(server: &RunningServer, namespace: &str, subpath: &str) -> TcpStream {
    use voidport_proto::frame::{FRAME_HEADER_LEN, Frame, FrameWriter};
    use voidport_proto::message::{RequestHead, ResponseOutcome};
    use voidport_proto::ops::handshake::{HelloReply, HelloRequest};
    use zerocopy::byteorder::little_endian::U32;

    let mut stream = TcpStream::connect(server.data_tcp()).expect("the data listener accepts");
    let body = HelloRequest {
        protocol_version: U32::new(voidport_proto::PROTOCOL_VERSION),
        flags: U32::ZERO,
        namespace_len: U32::new(namespace.len() as u32),
        subpath_len: U32::new(subpath.len() as u32),
        auth_len: U32::ZERO,
    };
    let mut buffer = [0u8; 256];
    let head = RequestHead::new(0, 0, 0, 0);
    let frame = {
        let mut writer =
            FrameWriter::request(&mut buffer, 4096, 1, &head, &body).expect("encodable");
        writer.payload(namespace.as_bytes()).expect("the name fits");
        writer
            .payload(subpath.as_bytes())
            .expect("the subpath fits");
        writer.finish().expect("a complete frame").to_vec()
    };
    stream.write_all(&frame).expect("the socket accepts");
    stream.flush().expect("the socket accepts");

    let mut header = [0u8; FRAME_HEADER_LEN];
    stream.read_exact(&mut header).expect("the server answers");
    let len = Frame::peek_len(&header, 4096)
        .expect("a declared length")
        .expect("a whole header") as usize;
    let mut reply = vec![0u8; len];
    reply[..FRAME_HEADER_LEN].copy_from_slice(&header);
    stream
        .read_exact(&mut reply[FRAME_HEADER_LEN..])
        .expect("the server answers");
    let parsed = Frame::parse(&reply, 4096).expect("a well-framed reply");
    match parsed.response::<HelloReply>().expect("a valid reply") {
        ResponseOutcome::Success(_) => stream,
        ResponseOutcome::Error(status) => panic!("the mount was refused: {status}"),
    }
}

#[test]
fn json_output_is_the_response_envelope_verbatim() {
    let directory = directory("json");
    let server = server(&directory, STATE);

    let line = server.expect_ok(&["--json", "namespace", "show", "project"]);
    assert!(line.starts_with(r#"{"status":"ok","result":"#), "{line}");
    let Response::Ok {
        result: Reply::Namespace { namespace },
    } = envelope(&line)
    else {
        panic!("expected a namespace reply: {line}");
    };
    assert_eq!(namespace.name.as_str(), "project");
    assert_eq!(namespace.rules.len(), 1);
    assert_eq!(namespace.ownership, OwnershipSpec::default());
    // Exactly one line: the envelope and nothing else.
    assert_eq!(line.lines().count(), 1, "{line}");

    let mutation = server.expect_ok(&["--json", "namespace", "create", "second"]);
    assert_eq!(
        envelope(&mutation),
        Response::Ok {
            result: Reply::Done {}
        }
    );

    let list = server.expect_ok(&["--json", "namespace", "list"]);
    let Response::Ok {
        result: Reply::NamespaceList { namespaces },
    } = envelope(&list)
    else {
        panic!("expected a namespace list: {list}");
    };
    assert_eq!(namespaces.len(), 2);

    let info = server.expect_ok(&["--json", "info"]);
    assert!(matches!(
        envelope(&info),
        Response::Ok {
            result: Reply::ServerInfo { .. }
        }
    ));
}

/// A pattern rule round-trips through the operator surface: `rule add
/// --match` writes it, `namespace show` displays it as the pair that keys it,
/// and `rule remove --match` removes exactly it.
#[test]
fn pattern_rules_round_trip_through_the_command_line() {
    let directory = directory("patterns");
    let server = server(&directory, STATE);

    server.expect_ok(&["rule", "add", "project", "/project/*", "--mode", "hidden"]);
    server.expect_ok(&[
        "rule",
        "add",
        "project",
        "/project",
        "--mode",
        "rw",
        "--match",
        "project-*",
    ]);
    server.expect_ok(&[
        "rule", "add", "project", "/project", "--mode", "ro", "--match", "docs-*",
    ]);

    let shown = server.expect_ok(&["namespace", "show", "project"]);
    assert!(
        shown.contains("rw     /project --match 'project-*'"),
        "{shown}"
    );
    assert!(
        shown.contains("ro     /project --match 'docs-*'"),
        "{shown}"
    );

    // The JSON surface carries the field verbatim, which is the scripting
    // contract.
    let line = server.expect_ok(&["--json", "namespace", "show", "project"]);
    assert!(line.contains(r#""match":"project-*""#), "{line}");

    // Overlap is refused, naming both rules.
    let overlap = server.expect_failure(&[
        "rule",
        "add",
        "project",
        "/project",
        "--mode",
        "ro",
        "--match",
        "project-a*",
    ]);
    assert!(
        overlap.contains("error [invalid-configuration]"),
        "{overlap}"
    );
    assert!(overlap.contains("project-*"), "{overlap}");
    assert!(overlap.contains("project-a*"), "{overlap}");

    // Removal names both fields, and takes exactly the rule they key.
    server.expect_ok(&[
        "rule",
        "remove",
        "project",
        "/project",
        "--match",
        "project-*",
    ]);
    let left = server.expect_ok(&["namespace", "show", "project"]);
    assert!(!left.contains("project-*"), "{left}");
    assert!(left.contains("--match 'docs-*'"), "{left}");
    // The literal rule at the same path is a different rule, and it stayed.
    assert!(left.contains("rw     /project  "), "{left}");
}

#[test]
fn a_rejected_operation_exits_nonzero_in_both_modes() {
    let directory = directory("rejection");
    let server = server(&directory, STATE);

    let human = server.expect_failure(&["namespace", "show", "absent"]);
    assert!(human.contains("error [not-found]"), "{human}");

    let json = server.expect_failure(&["--json", "namespace", "show", "absent"]);
    let response = envelope(&json);
    assert_eq!(
        response.as_error().map(|error| error.code),
        Some(voidport_control::ErrorCode::NotFound)
    );

    // An invalid configuration is rejected by the server, named, and changes
    // nothing.
    server.expect_ok(&[
        "rule",
        "add",
        "project",
        "/project/secret",
        "--mode",
        "hidden",
    ]);
    let dead = server.expect_failure(&[
        "rule",
        "add",
        "project",
        "/project/secret/key",
        "--mode",
        "ro",
    ]);
    assert!(dead.contains("error [invalid-configuration]"), "{dead}");
    assert!(dead.contains("/project/secret/key"), "{dead}");

    let shown = server.expect_ok(&["namespace", "show", "project"]);
    assert!(!shown.contains("/project/secret/key"), "{shown}");
}

#[test]
fn a_command_line_the_cli_can_reject_never_reaches_the_server() {
    let directory = directory("local-rejection");
    let server = server(&directory, STATE);

    for arguments in [
        vec!["namespace", "show", "a/b"],
        vec!["ownership", "set", "project"],
        vec!["ownership", "set", "project", "--ownership", "static"],
        vec![
            "ownership",
            "set",
            "project",
            "--ownership",
            "passthrough",
            "--unmapped",
            "hide",
        ],
    ] {
        let output = server.ctl(&arguments);
        assert!(
            !output.status.success(),
            "{arguments:?} should have been refused locally"
        );
        assert!(
            output.stdout.is_empty(),
            "a locally refused command must print nothing to stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).starts_with("voidport-ctl:"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn a_missing_server_is_reported_not_hung() {
    let directory = TempDir::new("no-server");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_voidport-ctl"))
        .arg("--socket")
        .arg(directory.join("absent.sock"))
        .arg("info")
        .output()
        .expect("the CLI binary runs");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot connect"), "{stderr}");
}

// ---------------------------------------------------------------------------
// Finding a server without `--socket`
// ---------------------------------------------------------------------------

/// The system socket the lookup falls back to, and the second path its failure
/// has to name.
const SYSTEM_SOCKET: &str = "/run/voidport/control.sock";

/// Runs the CLI with no `--socket`, in an environment whose per-user state
/// directory is `state_home`.
///
/// `HOME` is pinned alongside `XDG_STATE_HOME` so the case cannot reach the
/// socket of whoever is running the suite: the lookup falls back to
/// `$HOME/.local/state` and a developer's own `voidportd share` must not be what
/// a test connects to.
fn ctl_without_socket(state_home: &std::path::Path, arguments: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_voidport-ctl"))
        .env("XDG_STATE_HOME", state_home)
        .env("HOME", state_home)
        .args(arguments)
        .output()
        .expect("the CLI binary runs")
}

/// A server whose control socket is exactly the per-user path the lookup tries
/// first: `<state home>/voidport/control.sock`, which is where a `voidportd
/// share` launch seeds one.
fn per_user_server(directory: &TempDir) -> RunningServer {
    let state_directory = directory.directory("voidport");
    // The graft target is relative to the state file's own directory.
    create_directory(&state_directory.join("project"));
    let state_file = state_directory.join("state.toml");
    std::fs::write(&state_file, STATE).expect("a writable state file");
    let config = daemon_config(&state_file, pinned_environment(&state_directory));
    RunningServer::start(&config).expect("the server starts")
}

#[test]
fn the_per_user_socket_is_found_with_no_flags_at_all() {
    let directory = TempDir::new("lookup-user");
    let server = per_user_server(&directory);

    let output = ctl_without_socket(directory.path(), &["info"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The server it reached is the per-user one, which is the whole point: a
    // locally seeded instance is controllable by typing nothing but the command.
    assert!(
        stdout.contains(&server.socket().display().to_string()),
        "{stdout}"
    );
    assert!(
        server.socket().ends_with("voidport/control.sock"),
        "{}",
        server.socket().display()
    );
}

#[test]
fn a_named_socket_wins_over_the_lookup() {
    let directory = TempDir::new("lookup-flag");
    let _server = per_user_server(&directory);
    let absent = directory.join("named.sock");

    // A running server sits on the path the lookup would find. `--socket` is
    // absolute precedence, so the CLI must fail against the path it was given
    // instead of quietly talking to the other one.
    let output = ctl_without_socket(
        directory.path(),
        &["--socket", absent.to_str().expect("a utf-8 path"), "info"],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&absent.display().to_string()), "{stderr}");
}

#[test]
fn when_nothing_answers_the_error_names_every_path_tried() {
    // A state home with no socket in it, and no server anywhere: both
    // candidates fail, and the operator is owed both paths.
    let directory = TempDir::new("lookup-none");
    let output = ctl_without_socket(directory.path(), &["info"]);
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let per_user = directory.join("voidport/control.sock");
    assert!(
        stderr.contains(&per_user.display().to_string()),
        "the per-user path is missing from: {stderr}"
    );
    assert!(
        stderr.contains(SYSTEM_SOCKET),
        "the system path is missing from: {stderr}"
    );
    assert!(stderr.contains("--socket"), "{stderr}");
}
