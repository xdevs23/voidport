#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;

use support::{RunningServer, TempDir, daemon_config};
use voidport_control::{NamespaceName, Request, ShareMode, VsockPort};
use voidportd::daemon::{Daemon, DaemonConfig, SEEDED_CONTROL_SOCKET, StartupError};
use voidportd::data::Transport;
use voidportd::error::render;
use voidportd::seed::{DEFAULT_NAMESPACE, Seed, SeedError};
use voidportd::state::{Listener, LoadError, ServerSettingsError, StateDocument, load_document};

fn name(raw: &str) -> NamespaceName {
    NamespaceName::new(raw).expect("valid namespace name")
}

fn config(state_file: &std::path::Path) -> DaemonConfig {
    daemon_config(state_file)
}

fn config_without_socket(state_file: &std::path::Path) -> DaemonConfig {
    DaemonConfig::new(state_file)
}

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

    let server = RunningServer::start(&config(&state_file)).expect("the server starts");
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
    server.connect().expect_ok(&Request::NamespaceList {});
}

#[test]
fn a_state_file_that_exists_and_does_not_parse_still_refuses_startup() {
    let directory = TempDir::new("startup-malformed");
    let state_file = directory.write("state.toml", "this is not toml");
    let error =
        RunningServer::start(&config(&state_file)).expect_err("a malformed file is not replaced");
    assert!(matches!(error, StartupError::Load(_)), "{error}");
    assert_eq!(
        fs::read_to_string(&state_file).expect("readable"),
        "this is not toml",
        "the file the operator wrote is never overwritten"
    );
}

#[test]
fn a_server_with_no_listeners_serves_its_control_socket() {
    let directory = TempDir::new("startup-no-listeners");
    let state_file = directory.write("state.toml", "");
    let server = RunningServer::start(&config(&state_file)).expect("the server starts");
    server.connect().expect_ok(&Request::NamespaceList {});
}

#[test]
fn a_seeded_launch_writes_the_share_and_prints_its_mount_command() {
    let directory = TempDir::new("startup-seed");
    let state_file = directory.join("state.toml");
    let seed = seed(&directory, "project", ShareMode::Rw);
    let daemon = Daemon::start(&config(&state_file).with_seed(seed.clone()))
        .expect("the seeded server starts");

    let document = load_document(&state_file).expect("the seeded file loads");
    assert_eq!(document.server.listeners.len(), 1);
    let namespace = document.namespace(&name("share")).expect("seeded");
    assert_eq!(namespace.rules, vec![seed.rule()]);
    // The rule path is the absolute host path of the directory, replicated, so the
    // guest sees the hierarchy it has here.
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

    // The summary is derived from the listener as it bound, so the port is real.
    let summary = daemon.launch_summary().expect("a seeded launch reports");
    assert_eq!(summary.namespace, name("share"));
    assert_eq!(summary.mounts.len(), 1);
    assert!(summary.plaintext_tcp);
    let listeners = daemon.service().listeners();
    assert_eq!(listeners[0].transport, Transport::Tcp.as_str());
    let address: SocketAddr = listeners[0]
        .endpoint
        .parse()
        .expect("a tcp listener reports a socket address");
    assert_ne!(address.port(), 0);
    assert_eq!(
        summary.mounts[0].url,
        format!("voidport://127.0.0.1:{}/@share", address.port())
    );
    let note = summary.auth_note().expect("a tcp listener has a note");
    assert!(summary.to_string().contains(&note), "{summary}");
}

#[test]
fn a_seeded_launch_on_a_link_shares_the_link() {
    use voidportd::seed::shared_path::{SharedKind, SharedPath};

    for (label, target) in [
        ("startup-seed-link", "project"),
        ("startup-seed-dangling", "nowhere"),
    ] {
        let directory = TempDir::new(label);
        directory.directory("project");
        std::os::unix::fs::symlink(target, directory.join("link")).expect("writable");
        let shared = SharedPath::from_typed(std::path::Path::new("link"), directory.path())
            .expect("a link is shareable");
        assert_eq!(shared.kind(), SharedKind::Link);
        let seed = Seed::new(
            shared.path(),
            name(DEFAULT_NAMESPACE),
            ShareMode::Rw,
            vec![Listener::Tcp {
                addr: "127.0.0.1:0".parse().expect("valid address"),
            }],
        )
        .expect("a valid seed");

        let state_file = directory.join("state.toml");
        let _daemon =
            Daemon::start(&config(&state_file).with_seed(seed)).expect("the seeded server starts");
        let document = load_document(&state_file).expect("the seeded file loads");
        let rules = &document.namespace(&name("share")).expect("seeded").rules;
        let link = directory.join("link");
        assert_eq!(rules[0].path, link.to_str().expect("a text path"));
        assert_eq!(rules[0].target.as_deref(), link.to_str());
    }
}

#[test]
fn a_seeded_vsock_launch_writes_the_listener_and_prints_the_cid_a_guest_dials() {
    if !voidport_test_support::vsock::preflight() {
        return;
    }
    let directory = TempDir::new("startup-seed-vsock");
    let state_file = directory.join("state.toml");
    let seed = vsock_seed(&directory, "project", 0);
    let daemon = Daemon::start(&config(&state_file).with_seed(seed.clone()))
        .expect("the seeded server starts");

    // Port 0 on the wildcard cid that a command line without a cid gets. A restart
    // picks a port again.
    let document = load_document(&state_file).expect("the seeded file loads");
    assert_eq!(
        document.server.listeners,
        vec![Listener::Vsock {
            cid: vsock::VMADDR_CID_ANY,
            port: VsockPort::Any
        }]
    );
    assert_eq!(document.server.listeners, vec![Listener::vsock(0)]);
    assert_eq!(
        document.namespace(&name("share")).expect("seeded").rules,
        vec![seed.rule()]
    );

    let port = voidport_test_support::bound_vsock_port(&daemon.service().listeners());

    // The cid printed is the one a guest dials its host at, because a wildcard bind
    // has no address of its own.
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
        !summary.plaintext_tcp && summary.auth_note().is_none(),
        "a vsock listener is not reachable off the machine: {rendered}"
    );
    drop(daemon);
}

#[test]
fn relaunching_the_same_share_leaves_the_state_file_byte_identical() {
    let directory = TempDir::new("startup-idempotent");
    let state_file = directory.join("state.toml");
    let seed = seed(&directory, "project", ShareMode::Rw);

    let daemon = Daemon::start(&config(&state_file).with_seed(seed.clone()))
        .expect("the seeded server starts");
    let first = fs::read_to_string(&state_file).expect("readable");
    drop(daemon);

    let daemon =
        Daemon::start(&config(&state_file).with_seed(seed)).expect("the same share starts again");
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
    if !voidport_test_support::vsock::preflight() {
        return;
    }
    let directory = TempDir::new("startup-idempotent-vsock");
    let state_file = directory.join("state.toml");
    let seed = vsock_seed(&directory, "project", 0);

    let daemon = Daemon::start(&config(&state_file).with_seed(seed.clone()))
        .expect("the seeded server starts");
    let first = fs::read_to_string(&state_file).expect("readable");
    drop(daemon);

    let daemon =
        Daemon::start(&config(&state_file).with_seed(seed)).expect("the same share starts again");
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

#[test]
fn a_share_on_a_vsock_port_no_mount_url_could_name_refuses_startup() {
    let directory = TempDir::new("startup-vsock-port");
    let state_file = directory.join("state.toml");
    let port = u32::from(u16::MAX) + 1;
    let error =
        Daemon::start(&config(&state_file).with_seed(vsock_seed(&directory, "project", port)))
            .expect_err("the port is outside the range that a mount URL accepts");
    assert!(
        matches!(
            error,
            StartupError::Load(LoadError::ServerSettings {
                source: ServerSettingsError::VsockPort { port: refused, .. }
            }) if refused == port
        ),
        "{error}"
    );
    let rendered = render(&error);
    assert!(rendered.contains("1..=65535"), "{rendered}");
    assert_eq!(
        load_document(&state_file).expect("the created file loads"),
        StateDocument::default()
    );
}

#[test]
fn a_second_share_composes_beside_the_first_instead_of_flattening() {
    let directory = TempDir::new("startup-compose");
    let state_file = directory.join("state.toml");
    let first = seed(&directory, "left/example-project", ShareMode::Rw);
    let second = seed(&directory, "right/example-project", ShareMode::Ro);

    let daemon = Daemon::start(&config(&state_file).with_seed(first.clone()))
        .expect("the first share starts");
    drop(daemon);
    let daemon = Daemon::start(&config(&state_file).with_seed(second.clone()))
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
    // The compiled default is under `/run/voidport`, which a non-root user cannot
    // bind, so the two-command flow seeds its own socket.
    let directory = TempDir::new("startup-seeded-socket");
    let state_file = directory.join("state.toml");
    let beside = directory.join(SEEDED_CONTROL_SOCKET);
    let share = seed(&directory, "project", ShareMode::Rw);

    let daemon = Daemon::start(&config_without_socket(&state_file).with_seed(share.clone()))
        .expect("the seeded server starts");
    assert_eq!(daemon.control_socket(), beside);
    assert!(beside.exists(), "the seeded socket is the one bound");

    let document = load_document(&state_file).expect("the seeded file loads");
    assert_eq!(document.server.control_socket, Some(beside.clone()));
    assert!(beside.is_absolute());

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

    let seeded = fs::read_to_string(&state_file).expect("readable");
    drop(daemon);
    let daemon = Daemon::start(&config_without_socket(&state_file).with_seed(share))
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

    // The command line named one: nothing is seeded, because the document must not
    // name a path this server does not bind.
    let daemon = Daemon::start(
        &config_without_socket(&state_file)
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

    // The document names one, so it wins and is left exactly as written.
    let directory = TempDir::new("startup-socket-configured");
    let configured = directory.join("configured.sock");
    let state_file = directory.write(
        "state.toml",
        &format!("[server]\ncontrol_socket = {:?}\n", configured.display()),
    );
    let daemon = Daemon::start(&config_without_socket(&state_file).with_seed(seed(
        &directory,
        "project",
        ShareMode::Rw,
    )))
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

    let flag = directory.join("flag.sock");
    let daemon = Daemon::start(
        &config_without_socket(&state_file)
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
    let daemon =
        Daemon::start(&config(&state_file).with_seed(seed(&directory, "project", ShareMode::Rw)))
            .expect("the seeded server starts");
    let seeded = fs::read_to_string(&state_file).expect("readable");
    drop(daemon);

    let error =
        Daemon::start(&config(&state_file).with_seed(seed(&directory, "project", ShareMode::Ro)))
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
