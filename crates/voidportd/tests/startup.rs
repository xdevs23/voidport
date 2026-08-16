//! The startup contract: what a state file that is not there means, what a
//! server with no listeners is, and what `voidportd share` seeds before serving.
//!
//! These drive the library's own startup path against a real filesystem — the
//! real binary's version of the same journey is the client crate's quickstart
//! suite, which mounts what comes out of it.

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use support::{RunningServer, TempDir, daemon_config};
use voidport_control::{NamespaceName, Request, ShareMode};
use voidportd::daemon::{Daemon, DaemonConfig, SEEDED_CONTROL_SOCKET, StartupError};
use voidportd::error::render;
use voidportd::seed::{DEFAULT_NAMESPACE, Seed, SeedError};
use voidportd::state::{LimitsError, Listener, LoadError, StateDocument, load_document};
use voidportd::testing::pinned_environment;

fn name(raw: &str) -> NamespaceName {
    NamespaceName::new(raw).expect("valid namespace name")
}

/// A configuration for a state file inside `directory`, socket beside it.
fn config(directory: &TempDir, state_file: &std::path::Path) -> DaemonConfig {
    daemon_config(state_file, pinned_environment(directory.path()))
}

/// The same, for a launch that names no control socket: what an operator who
/// typed nothing but `voidportd share <DIR> --addr …` runs.
fn config_without_socket(directory: &TempDir, state_file: &std::path::Path) -> DaemonConfig {
    DaemonConfig::new(state_file).with_environment(pinned_environment(directory.path()))
}

/// The seed a `voidportd share <DIR> --addr 127.0.0.1:0` launch describes.
fn seed(directory: &TempDir, shared: &str, mode: ShareMode) -> Seed {
    Seed::new(
        directory.directory(shared),
        name(DEFAULT_NAMESPACE),
        mode,
        vec![Listener::Tcp {
            addr: "127.0.0.1:0".parse().expect("valid address"),
        }],
    )
    .expect("a valid seed")
}

/// The seed a `voidportd share <DIR> --vsock PORT` launch describes.
fn vsock_seed(directory: &TempDir, shared: &str, port: u32) -> Seed {
    Seed::new(
        directory.directory(shared),
        name(DEFAULT_NAMESPACE),
        ShareMode::Rw,
        vec![Listener::vsock(port)],
    )
    .expect("a valid seed")
}

#[test]
fn a_cleanly_missing_state_file_is_created_and_served() {
    let directory = TempDir::new("startup-missing");
    let state_file = directory.join("state.toml");
    assert!(!state_file.exists());

    let server = RunningServer::start(&config(&directory, &state_file)).expect("the server starts");
    assert_eq!(
        load_document(&state_file).expect("the created file loads"),
        StateDocument::default(),
        "a created state file is the empty document"
    );
    assert_eq!(
        fs::metadata(&state_file)
            .expect("readable")
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    // It is a running server, not a started-and-stalled one: the control plane
    // answers, with nothing configured.
    server.connect().expect_ok(&Request::NamespaceList {});
}

#[test]
fn a_state_file_that_exists_and_does_not_parse_still_refuses_startup() {
    let directory = TempDir::new("startup-malformed");
    let state_file = directory.write("state.toml", "this is not toml");
    let error = RunningServer::start(&config(&directory, &state_file))
        .expect_err("a malformed file is not replaced");
    assert!(matches!(error, StartupError::Load(_)), "{error}");
    assert_eq!(
        fs::read_to_string(&state_file).expect("readable"),
        "this is not toml",
        "the file the operator wrote is never overwritten"
    );
}

#[test]
fn a_server_with_no_listeners_serves_its_control_socket() {
    // Legal, and the state a created state file starts in: everything else is
    // added through the control plane.
    let directory = TempDir::new("startup-no-listeners");
    let state_file = directory.write("state.toml", "");
    let server = RunningServer::start(&config(&directory, &state_file)).expect("the server starts");
    server.connect().expect_ok(&Request::NamespaceList {});
}

#[test]
fn a_seeded_launch_writes_the_share_and_prints_its_mount_command() {
    let directory = TempDir::new("startup-seed");
    let state_file = directory.join("state.toml");
    let seed = seed(&directory, "project", ShareMode::Rw);
    let daemon = Daemon::start(&config(&directory, &state_file).with_seed(seed.clone()))
        .expect("the seeded server starts");

    // The seed went through the file, not around it: a plain `--state` launch
    // would reproduce exactly this server.
    let document = load_document(&state_file).expect("the seeded file loads");
    assert_eq!(document.server.listeners.len(), 1);
    let namespace = document.namespace(&name("share")).expect("seeded");
    assert_eq!(namespace.rules, vec![seed.rule()]);
    // The rule path is the directory's own absolute host path, replicated: the
    // guest sees the hierarchy it has here, not a flattened basename.
    let shared = directory.join("project");
    assert_eq!(
        namespace.rules[0].path,
        shared.to_str().expect("a text path")
    );
    assert_eq!(
        namespace.rules[0].target.as_deref(),
        shared.to_str(),
        "the graft target is the same directory"
    );
    assert_eq!(namespace.rules[0].mode, ShareMode::Rw);

    // The summary is derived from the listener as it bound, so the ephemeral
    // port is a real one.
    let summary = daemon.launch_summary().expect("a seeded launch reports");
    assert_eq!(summary.namespace, name("share"));
    assert_eq!(summary.mounts.len(), 1);
    assert!(summary.plaintext_tcp);
    let port = daemon.data_listeners().endpoints()[0]
        .tcp_address()
        .expect("a tcp listener")
        .port();
    assert_ne!(port, 0);
    assert_eq!(
        summary.mounts[0].url,
        format!("voidport://127.0.0.1:{port}/@share")
    );
    assert!(
        summary.to_string().contains("docs/THREAT-MODEL.md"),
        "{summary}"
    );
}

/// `share --vsock PORT` seeds a vsock listener exactly as `--addr` seeds a tcp
/// one: it goes through the state file, it binds, and the operator is handed
/// the line a guest mounts it with.
///
/// The skip rule is the vsock suite's — a machine that claims support cannot
/// skip, and one without the loopback transport says so out loud.
#[test]
fn a_seeded_vsock_launch_writes_the_listener_and_prints_the_cid_a_guest_dials() {
    if !voidportd::testing::vsock::preflight() {
        return;
    }
    let directory = TempDir::new("startup-seed-vsock");
    let state_file = directory.join("state.toml");
    let port = voidportd::testing::vsock::free_port().expect("a free vsock port");
    let seed = vsock_seed(&directory, "project", port);
    let daemon = Daemon::start(&config(&directory, &state_file).with_seed(seed.clone()))
        .expect("the seeded server starts");

    // The listener round-trips through the file: the port asked for, on the
    // wildcard cid a command line that names none means.
    let document = load_document(&state_file).expect("the seeded file loads");
    assert_eq!(
        document.server.listeners,
        vec![Listener::Vsock {
            cid: vsock::VMADDR_CID_ANY,
            port
        }]
    );
    assert_eq!(document.server.listeners, vec![Listener::vsock(port)]);
    assert_eq!(
        document.namespace(&name("share")).expect("seeded").rules,
        vec![seed.rule()]
    );

    // And the banner renders it: the cid printed is the one a *guest* dials
    // its host at, because a wildcard bind has no address of its own.
    let summary = daemon.launch_summary().expect("a seeded launch reports");
    assert_eq!(summary.mounts.len(), 1);
    assert_eq!(
        summary.mounts[0].url,
        format!("voidport+vsock://{}:{port}/@share", vsock::VMADDR_CID_HOST)
    );
    let rendered = summary.to_string();
    assert!(
        rendered.contains(&summary.mounts[0].to_string()),
        "{rendered}"
    );
    assert!(
        !summary.plaintext_tcp && !rendered.contains("docs/THREAT-MODEL.md"),
        "a vsock listener is not reachable off the machine: {rendered}"
    );
    drop(daemon);
}

#[test]
fn relaunching_the_same_share_leaves_the_state_file_byte_identical() {
    let directory = TempDir::new("startup-idempotent");
    let state_file = directory.join("state.toml");
    let seed = seed(&directory, "project", ShareMode::Rw);

    let daemon = Daemon::start(&config(&directory, &state_file).with_seed(seed.clone()))
        .expect("the seeded server starts");
    let first = fs::read_to_string(&state_file).expect("readable");
    drop(daemon);

    let daemon = Daemon::start(&config(&directory, &state_file).with_seed(seed))
        .expect("the same share starts again");
    assert_eq!(
        fs::read_to_string(&state_file).expect("readable"),
        first,
        "an identical relaunch must not rewrite the file"
    );
    let document = load_document(&state_file).expect("loads");
    assert_eq!(document.server.listeners.len(), 1, "no duplicate listener");
    assert_eq!(
        document
            .namespace(&name("share"))
            .expect("seeded")
            .rules
            .len(),
        1,
        "no duplicate rule"
    );
    drop(daemon);
}

#[test]
fn relaunching_the_same_vsock_share_leaves_the_state_file_byte_identical() {
    if !voidportd::testing::vsock::preflight() {
        return;
    }
    let directory = TempDir::new("startup-idempotent-vsock");
    let state_file = directory.join("state.toml");
    let port = voidportd::testing::vsock::free_port().expect("a free vsock port");
    let seed = vsock_seed(&directory, "project", port);

    let daemon = Daemon::start(&config(&directory, &state_file).with_seed(seed.clone()))
        .expect("the seeded server starts");
    let first = fs::read_to_string(&state_file).expect("readable");
    drop(daemon);

    let daemon = Daemon::start(&config(&directory, &state_file).with_seed(seed))
        .expect("the same share starts again");
    assert_eq!(
        fs::read_to_string(&state_file).expect("readable"),
        first,
        "an identical relaunch must not rewrite the file"
    );
    assert_eq!(
        load_document(&state_file)
            .expect("loads")
            .server
            .listeners
            .len(),
        1,
        "no duplicate listener"
    );
    drop(daemon);
}

/// A seeded vsock port is validated exactly like a configured one: the
/// `1..=65535` rule lives in the state document, and the launch that would
/// write a port outside it is refused before anything is persisted or bound.
#[test]
fn a_share_on_a_vsock_port_no_mount_url_could_name_refuses_startup() {
    let directory = TempDir::new("startup-vsock-port");
    // Both edges of the range: zero is not an address a guest can dial, and
    // above 65535 is a port no mount URL can spell.
    for (label, port) in [("zero", 0), ("too-wide", u32::from(u16::MAX) + 1)] {
        let state_file = directory.join(&format!("{label}.toml"));
        let error = Daemon::start(
            &config(&directory, &state_file).with_seed(vsock_seed(&directory, "project", port)),
        )
        .expect_err("the port is outside the range a mount URL can name");
        assert!(
            matches!(
                error,
                StartupError::Load(LoadError::ServerSettings {
                    source: LimitsError::VsockPort { port: refused, .. }
                }) if refused == port
            ),
            "{error}"
        );
        let rendered = render(&error);
        assert!(rendered.contains("1..=65535"), "{rendered}");
        // The state file was created by the launch and left empty: a refusal
        // never half-applies.
        assert_eq!(
            load_document(&state_file).expect("the created file loads"),
            StateDocument::default()
        );
    }
}

#[test]
fn a_second_share_composes_beside_the_first_instead_of_flattening() {
    // Two host directories with the same final component. Under host-path
    // replication they are two rules that cannot collide, and the namespace
    // reproduces the hierarchy they have on the host.
    let directory = TempDir::new("startup-compose");
    let state_file = directory.join("state.toml");
    let first = seed(&directory, "left/example-project", ShareMode::Rw);
    let second = seed(&directory, "right/example-project", ShareMode::Ro);

    let daemon = Daemon::start(&config(&directory, &state_file).with_seed(first.clone()))
        .expect("the first share starts");
    drop(daemon);
    let daemon = Daemon::start(&config(&directory, &state_file).with_seed(second.clone()))
        .expect("the second share starts beside it");
    drop(daemon);

    let document = load_document(&state_file).expect("the seeded file loads");
    let namespace = document.namespace(&name("share")).expect("seeded");
    assert_eq!(namespace.rules, vec![first.rule(), second.rule()]);
    assert_ne!(first.rule_path(), second.rule_path());
    assert!(
        first.rule_path().ends_with("/left/example-project"),
        "{}",
        first.rule_path()
    );
    assert!(
        second.rule_path().ends_with("/right/example-project"),
        "{}",
        second.rule_path()
    );
}

#[test]
fn a_share_that_names_no_control_socket_binds_one_beside_the_state_file() {
    // The compiled default lives under `/run/voidport`, which a non-root
    // operator cannot bind, so the two-command flow seeds its own socket.
    let directory = TempDir::new("startup-seeded-socket");
    let state_file = directory.join("state.toml");
    let beside = directory.join(SEEDED_CONTROL_SOCKET);
    let share = seed(&directory, "project", ShareMode::Rw);

    let daemon =
        Daemon::start(&config_without_socket(&directory, &state_file).with_seed(share.clone()))
            .expect("the seeded server starts");
    assert_eq!(daemon.control_socket(), beside);
    assert!(beside.exists(), "the seeded socket is the one bound");

    // It went into the document, so a plain `--state` launch reproduces it.
    let document = load_document(&state_file).expect("the seeded file loads");
    assert_eq!(document.server.control_socket, Some(beside.clone()));
    assert!(beside.is_absolute());

    // And the operator is told the line that reaches it.
    let summary = daemon.launch_summary().expect("a seeded launch reports");
    assert_eq!(summary.control_socket, beside);
    assert_eq!(
        summary.control_command(),
        format!("voidport-ctl --socket {} info", beside.display())
    );
    assert!(
        summary.to_string().contains(&summary.control_command()),
        "{summary}"
    );

    // Idempotent like the rest of the seed: the relaunch rewrites nothing and
    // binds the same socket.
    let seeded = fs::read_to_string(&state_file).expect("readable");
    drop(daemon);
    let daemon = Daemon::start(&config_without_socket(&directory, &state_file).with_seed(share))
        .expect("the same share starts again");
    assert_eq!(daemon.control_socket(), beside);
    assert_eq!(
        fs::read_to_string(&state_file).expect("readable"),
        seeded,
        "an identical relaunch must not rewrite the file"
    );
    drop(daemon);
}

#[test]
fn a_share_seeds_no_control_socket_when_the_launch_or_the_document_names_one() {
    let directory = TempDir::new("startup-socket-precedence");
    let state_file = directory.join("state.toml");
    let flag = directory.join("flag.sock");

    // The command line named one: nothing is seeded, because the document must
    // not name a path this server does not bind.
    let daemon = Daemon::start(
        &config_without_socket(&directory, &state_file)
            .with_control_socket(&flag)
            .with_seed(seed(&directory, "project", ShareMode::Rw)),
    )
    .expect("the seeded server starts");
    assert_eq!(daemon.control_socket(), flag);
    assert_eq!(
        load_document(&state_file)
            .expect("the seeded file loads")
            .server
            .control_socket,
        None
    );
    assert!(!directory.join(SEEDED_CONTROL_SOCKET).exists());
    drop(daemon);

    // The document names one: it is the operator's own value, so it wins and is
    // left exactly as written — a collision this is not.
    let directory = TempDir::new("startup-socket-configured");
    let configured = directory.join("configured.sock");
    let state_file = directory.write(
        "state.toml",
        &format!("[server]\ncontrol_socket = {:?}\n", configured.display()),
    );
    let daemon = Daemon::start(
        &config_without_socket(&directory, &state_file).with_seed(seed(
            &directory,
            "project",
            ShareMode::Rw,
        )),
    )
    .expect("the seeded server starts");
    assert_eq!(daemon.control_socket(), configured);
    assert_eq!(
        load_document(&state_file)
            .expect("the seeded file loads")
            .server
            .control_socket,
        Some(configured.clone())
    );
    assert!(!directory.join(SEEDED_CONTROL_SOCKET).exists());
    drop(daemon);

    // And a flag beside that document still wins the precedence.
    let flag = directory.join("flag.sock");
    let daemon = Daemon::start(
        &config_without_socket(&directory, &state_file)
            .with_control_socket(&flag)
            .with_seed(seed(&directory, "project", ShareMode::Rw)),
    )
    .expect("the seeded server starts");
    assert_eq!(daemon.control_socket(), flag);
    assert_eq!(
        load_document(&state_file)
            .expect("the seeded file loads")
            .server
            .control_socket,
        Some(configured),
        "the flag binds elsewhere without rewriting what the operator configured"
    );
    drop(daemon);
}

#[test]
fn a_share_that_collides_with_the_state_file_refuses_startup() {
    let directory = TempDir::new("startup-collision");
    let state_file = directory.join("state.toml");
    let daemon = Daemon::start(&config(&directory, &state_file).with_seed(seed(
        &directory,
        "project",
        ShareMode::Rw,
    )))
    .expect("the seeded server starts");
    let seeded = fs::read_to_string(&state_file).expect("readable");
    drop(daemon);

    // Same directory, other mode: one host path cannot mean both.
    let error = Daemon::start(&config(&directory, &state_file).with_seed(seed(
        &directory,
        "project",
        ShareMode::Ro,
    )))
    .expect_err("the rule collides");
    assert!(
        matches!(error, StartupError::Seed(SeedError::RuleConflict { .. })),
        "{error}"
    );
    let rendered = render(&error);
    let shared = directory.join("project");
    assert!(
        rendered.contains(shared.to_str().expect("a text path")),
        "{rendered}"
    );
    assert_eq!(
        fs::read_to_string(&state_file).expect("readable"),
        seeded,
        "a refused launch changes nothing"
    );
}
