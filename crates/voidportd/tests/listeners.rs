#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::path::{Path, PathBuf};

use support::wire::{ROOT, WireClient};
use support::{ControlClient, RunningServer, TempDir};
use voidport_control::{ErrorCode, Listener, ListenerInfo, Reply, Request};
use voidport_test_support::daemon_config;
use voidportd::state::{StateDocument, load_document};

const TCP_LISTENER: &str = "[[server.listeners]]\ntransport = \"tcp\"\naddr = \"127.0.0.1:0\"\n";

fn tcp_listener() -> Listener {
    Listener::Tcp {
        addr: "127.0.0.1:0".parse().expect("valid address"),
    }
}

fn state(listeners: &str, target: &Path) -> String {
    format!(
        r#"
[server]
{listeners}

[[namespaces]]
name = "plain"

[[namespaces.rules]]
path = "/tree"
mode = "rw"
target = "{target}"
"#,
        target = target.display()
    )
}

/// The server is declared first so that it is dropped first: it stops while the
/// directory with its sockets and its state file is still there.
struct Case {
    server: RunningServer,
    state_file: PathBuf,
    directory: TempDir,
}

impl Case {
    fn start(label: &str, listeners: impl FnOnce(&Path) -> String) -> Self {
        let directory = TempDir::new(label);
        let target = directory.directory("tree");
        std::fs::write(target.join("data.bin"), b"0123456789").expect("writable");
        let state_file =
            directory.write("state.toml", &state(&listeners(directory.path()), &target));
        let server = RunningServer::start(&daemon_config(&state_file)).expect("the server starts");
        Self {
            server,
            state_file,
            directory,
        }
    }

    fn tcp(label: &str) -> Self {
        Self::start(label, |_| TCP_LISTENER.to_owned())
    }

    fn document(&self) -> StateDocument {
        load_document(&self.state_file).expect("the state file loads")
    }

    fn persisted(&self) -> Vec<Listener> {
        self.document().server.listeners
    }

    fn restart(&mut self) {
        self.server.stop();
        self.server = RunningServer::start(&daemon_config(&self.state_file))
            .expect("the server restarts from its own state file");
    }

    fn control(&self) -> ControlClient {
        self.server.connect()
    }

    fn endpoints(&self) -> Vec<String> {
        let Reply::ServerInfo { listeners, .. } = self.control().expect_ok(&Request::ServerInfo {})
        else {
            panic!("server-info answers server info");
        };
        listeners
            .into_iter()
            .map(|listener| listener.endpoint)
            .collect()
    }
}

fn add(client: &mut ControlClient, listener: Listener) -> String {
    added(client, listener).endpoint
}

fn added(client: &mut ControlClient, listener: Listener) -> ListenerInfo {
    let Reply::Listener { listener } = client.expect_ok(&Request::ListenerAdd { listener }) else {
        panic!("listener-add returns the listener it bound");
    };
    listener
}

fn mounts(mut client: WireClient) {
    client.hello("plain", "/tree").expect("the mount resolves");
    client
        .lookup(ROOT, "data.bin")
        .expect("the graft is reachable through the new listener");
}

#[test]
fn a_runtime_tcp_listener_accepts_a_mount_immediately() {
    // A unix listener at startup, so the tcp one below is added to a server
    // that is already serving something else.
    let case = Case::start("listener-add-tcp", |directory| {
        format!(
            "[[server.listeners]]\ntransport = \"unix\"\npath = \"{}\"\n",
            directory.join("startup.sock").display()
        )
    });
    let started_with = case.endpoints();

    let endpoint = add(&mut case.control(), tcp_listener());
    let address: std::net::SocketAddr = endpoint.parse().expect("a bound address");
    assert_ne!(address.port(), 0);
    mounts(WireClient::tcp(address).expect("the new listener accepts connections"));

    let endpoints = case.endpoints();
    assert!(endpoints.contains(&endpoint), "{endpoints:?}");
    for existing in &started_with {
        assert!(endpoints.contains(existing), "{endpoints:?}");
    }
    mounts(WireClient::unix(case.server.data_unix()).expect("the startup listener still serves"));

    assert_eq!(
        case.persisted(),
        vec![
            Listener::Unix {
                path: case.directory.join("startup.sock")
            },
            tcp_listener(),
        ]
    );
}

#[test]
fn a_runtime_unix_listener_serves_and_a_restart_serves_it_again() {
    let mut case = Case::tcp("listener-add-unix");
    let path = case.directory.join("added.sock");

    let endpoint = add(&mut case.control(), Listener::Unix { path: path.clone() });
    assert_eq!(endpoint, path.display().to_string());
    assert!(path.exists(), "the socket is on the filesystem");
    mounts(WireClient::unix(&path).expect("the new listener accepts connections"));

    assert_eq!(
        case.persisted(),
        vec![tcp_listener(), Listener::Unix { path: path.clone() }]
    );

    case.restart();
    assert!(
        case.endpoints().contains(&endpoint),
        "a restarted server serves what the file says: {:?}",
        case.endpoints()
    );
    mounts(WireClient::unix(&path).expect("the restarted server accepts on it"));
}

/// A machine with no loopback transport prints a skip for this test.
#[test]
fn a_runtime_vsock_listener_accepts_a_mount_immediately() {
    if !voidport_test_support::vsock::preflight() {
        return;
    }
    let case = Case::tcp("listener-add-vsock");

    let reported = added(&mut case.control(), Listener::vsock(0));
    let port = voidport_test_support::vsock_port(&reported);
    assert_ne!(port, 0, "the port that was bound is reported");
    assert_eq!(reported.endpoint, format!("any:{port}"));
    mounts(WireClient::vsock(port).expect("the new vsock listener accepts connections"));
    assert_eq!(case.persisted()[1], Listener::vsock(0));
}

#[test]
fn a_bind_failure_answers_the_os_error_and_changes_nothing() {
    let case = Case::tcp("listener-bind-failure");
    let before = case.persisted();
    let mut client = case.control();

    let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    let taken = occupied.local_addr().expect("a bound address");
    let error = client.expect_error(&Request::ListenerAdd {
        listener: Listener::Tcp { addr: taken },
    });
    assert_eq!(error.code, ErrorCode::BindFailed);
    assert!(error.message.contains(&taken.to_string()), "{error}");
    assert!(error.message.contains("in use"), "{error}");

    let nowhere = case.directory.join("nowhere").join("data.sock");
    let error = client.expect_error(&Request::ListenerAdd {
        listener: Listener::Unix {
            path: nowhere.clone(),
        },
    });
    assert_eq!(error.code, ErrorCode::BindFailed);
    assert!(
        error.message.contains(&nowhere.display().to_string()),
        "{error}"
    );
    assert!(!nowhere.exists(), "a failed bind creates nothing");

    assert_eq!(case.persisted(), before);
    mounts(WireClient::tcp(case.server.data_tcp()).expect("the original listener still serves"));
}

#[test]
fn removing_a_listener_stops_new_connections_and_leaves_its_sessions_serving() {
    let case = Case::tcp("listener-remove");
    let mut client = case.control();
    let path = case.directory.join("doomed.sock");
    let endpoint = add(&mut client, Listener::Unix { path: path.clone() });

    let mut mounted = WireClient::unix(&path).expect("the listener accepts");
    mounted.hello("plain", "/tree").expect("the mount resolves");

    client.expect_ok(&Request::ListenerRemove {
        endpoint: endpoint.clone(),
    });

    assert!(!path.exists(), "the removed listener unlinked its socket");
    assert!(
        WireClient::unix(&path).is_err(),
        "a removed listener accepts nothing"
    );

    mounted
        .lookup(ROOT, "data.bin")
        .expect("an already-accepted session is untouched by removal");
    let Reply::SessionList { sessions } = client.expect_ok(&Request::SessionList {}) else {
        panic!("session-list answers sessions");
    };
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    assert_eq!(sessions[0].transport, "unix");

    assert_eq!(case.persisted(), vec![tcp_listener()]);
    assert!(
        !case.endpoints().contains(&endpoint),
        "{:?}",
        case.endpoints()
    );
}

/// A tcp listener leaves no path to look at, so the refused connection shows it
/// was closed. A listener is identified by the source form it was added with, so
/// removal must give that spelling back, or `:0` could be added once per server
/// lifetime.
#[test]
fn a_removed_tcp_listener_stops_accepting_and_gives_its_source_form_back() {
    // A unix listener at startup, so the tcp entry under test is one this test
    // added and can add again.
    let case = Case::start("listener-remove-tcp", |directory| {
        format!(
            "[[server.listeners]]\ntransport = \"unix\"\npath = \"{}\"\n",
            directory.join("startup.sock").display()
        )
    });
    let mut client = case.control();
    let endpoint = add(&mut client, tcp_listener());
    let address: std::net::SocketAddr = endpoint.parse().expect("a bound address");

    let mut mounted = WireClient::tcp(address).expect("the listener accepts");
    mounted.hello("plain", "/tree").expect("the mount resolves");

    client.expect_ok(&Request::ListenerRemove {
        endpoint: endpoint.clone(),
    });

    assert!(
        WireClient::tcp(address).is_err(),
        "a removed tcp listener accepts nothing, and the operation answered only once it did not"
    );
    mounted
        .lookup(ROOT, "data.bin")
        .expect("an already-accepted session is untouched by removal");

    let again = add(&mut client, tcp_listener());
    mounts(WireClient::tcp(again.parse().expect("a bound address")).expect("the new one accepts"));
    assert_eq!(
        case.persisted(),
        vec![
            Listener::Unix {
                path: case.directory.join("startup.sock")
            },
            tcp_listener(),
        ],
        "the removed entry left the file, so the re-add did not double it"
    );
}

#[test]
fn removing_the_last_listener_leaves_a_control_socket_only_server() {
    let mut case = Case::tcp("listener-remove-last");
    let endpoint = case.endpoints().pop().expect("one listener at startup");
    let mut client = case.control();
    client.expect_ok(&Request::ListenerRemove {
        endpoint: endpoint.clone(),
    });

    assert!(case.endpoints().is_empty());
    assert!(case.persisted().is_empty());
    client.expect_ok(&Request::NamespaceList {});

    case.restart();
    assert!(case.endpoints().is_empty());
    let endpoint = add(&mut case.control(), tcp_listener());
    mounts(WireClient::tcp(endpoint.parse().expect("a bound address")).expect("it accepts"));
}

#[test]
fn a_duplicate_add_is_refused_as_a_duplicate_not_as_a_bind_failure() {
    let case = Case::tcp("listener-duplicate");
    let mut client = case.control();
    let path = case.directory.join("once.sock");
    let endpoint = add(&mut client, Listener::Unix { path: path.clone() });

    let error = client.expect_error(&Request::ListenerAdd {
        listener: Listener::Unix { path: path.clone() },
    });
    assert_eq!(error.code, ErrorCode::AlreadyExists);
    assert!(error.message.contains(&endpoint), "{error}");
    assert!(path.exists());
    mounts(WireClient::unix(&path).expect("the first listener still serves"));
    assert_eq!(case.persisted().len(), 2, "nothing was written twice");

    // A listener is identified by the source form that was written, the only thing
    // to compare before a bind, so a second `:0` is a duplicate too. Two identical
    // entries would be one endpoint that cannot be named.
    let error = client.expect_error(&Request::ListenerAdd {
        listener: tcp_listener(),
    });
    assert_eq!(error.code, ErrorCode::AlreadyExists);
    assert!(error.message.contains("tcp 127.0.0.1:0"), "{error}");
    assert!(
        error.message.contains(&case.server.data_tcp().to_string()),
        "the refusal names where the held listener actually bound: {error}"
    );
}

#[test]
fn removing_an_endpoint_the_server_does_not_serve_is_a_typed_error() {
    let case = Case::tcp("listener-remove-unknown");
    let mut client = case.control();
    let before = case.persisted();

    for endpoint in ["127.0.0.1:1", "/nowhere/data.sock", "any:1024", ""] {
        let error = client.expect_error(&Request::ListenerRemove {
            endpoint: endpoint.to_owned(),
        });
        assert_eq!(error.code, ErrorCode::NotFound, "{endpoint:?}");
        assert!(error.message.contains(endpoint), "{error}");
    }
    assert_eq!(case.persisted(), before);
}

/// The vsock port range is validated by the settings check that a state file
/// takes at load, so nothing is bound and no vsock transport is needed.
#[test]
fn a_runtime_vsock_port_is_validated_exactly_as_a_configured_one() {
    let case = Case::tcp("listener-vsock-port");
    let mut client = case.control();
    let before = case.persisted();

    let port = 70_000;
    let error = client.expect_error(&Request::ListenerAdd {
        listener: Listener::vsock(port),
    });
    assert_eq!(error.code, ErrorCode::InvalidConfiguration, "{port}");
    assert!(error.message.contains(&format!("port {port}")), "{error}");
    assert!(error.message.contains("1..=65535"), "{error}");
    assert_eq!(case.persisted(), before);
}
