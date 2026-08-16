//! Runtime listener operations: `listener-add`, `listener-remove`, and what
//! the state file, a restart and the sessions already mounted make of them.
//!
//! The listener-ops acceptance criteria 1–4 live here; criterion 5's operator
//! surfaces are in the `voidport-ctl` and `voidport-tui` suites, which drive the
//! real CLI and the real TUI client against this same server.
//!
//! Every case goes through the real control socket with the real typed client:
//! a listener is added by asking the running server for it, and then *used* —
//! a mount over the endpoint it answered with is the only proof that the
//! listener is serving, not merely recorded.

mod support;

use std::path::{Path, PathBuf};

use support::wire::{ROOT, WireClient};
use support::{ControlClient, RunningServer, TempDir};
use voidport_control::{ErrorCode, Listener, Reply, Request};
use voidportd::state::{StateDocument, load_document};
use voidportd::testing::{daemon_config, pinned_environment};

/// The startup listener most cases use: tcp on an ephemeral port.
const TCP_LISTENER: &str = "[[server.listeners]]\ntransport = \"tcp\"\naddr = \"127.0.0.1:0\"\n";

/// That same listener in source form, which is what the state file holds.
fn tcp_listener() -> Listener {
    Listener::Tcp {
        addr: "127.0.0.1:0".parse().expect("valid address"),
    }
}

/// A state file with the given listeners and one namespace grafting `tree`.
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

/// A running server whose state file the test can read and restart from.
///
/// The server is declared first so that it is dropped first: it stops while
/// the directory holding its sockets and its state file is still there.
struct Case {
    server: RunningServer,
    state_file: PathBuf,
    directory: TempDir,
}

impl Case {
    /// Starts a server on a fresh state file holding the listeners `listeners`
    /// spells for the case's own directory.
    fn start(label: &str, listeners: impl FnOnce(&Path) -> String) -> Self {
        let directory = TempDir::new(label);
        let target = directory.directory("tree");
        std::fs::write(target.join("data.bin"), b"0123456789").expect("writable");
        let state_file =
            directory.write("state.toml", &state(&listeners(directory.path()), &target));
        let server = RunningServer::start(&daemon_config(
            &state_file,
            pinned_environment(directory.path()),
        ))
        .expect("the server starts");
        Self {
            server,
            state_file,
            directory,
        }
    }

    /// A server with one tcp listener on an ephemeral port.
    fn tcp(label: &str) -> Self {
        Self::start(label, |_| TCP_LISTENER.to_owned())
    }

    /// The state file as it stands, which is what a restart would serve.
    fn document(&self) -> StateDocument {
        load_document(&self.state_file).expect("the state file loads")
    }

    /// The listeners the state file holds.
    fn persisted(&self) -> Vec<Listener> {
        self.document().server.listeners
    }

    /// Stops the server and starts a new one on the same state file, which is
    /// the whole of "a restart serves what the file says".
    fn restart(&mut self) {
        self.server.stop();
        self.server = RunningServer::start(&daemon_config(
            &self.state_file,
            pinned_environment(self.directory.path()),
        ))
        .expect("the server restarts from its own state file");
    }

    /// A control-plane connection.
    fn control(&self) -> ControlClient {
        self.server.connect()
    }

    /// The endpoints the server is serving on right now, as `server-info`
    /// reports them.
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

/// Adds a listener and returns the endpoint it bound.
fn add(client: &mut ControlClient, listener: Listener) -> String {
    let Reply::Listener { listener } = client.expect_ok(&Request::ListenerAdd { listener }) else {
        panic!("listener-add answers the listener it bound");
    };
    listener.endpoint
}

/// Mounts `plain` at `/tree` and reads one name through it, which is the proof
/// that a listener is serving, not merely bound.
fn mounts(mut client: WireClient) {
    client.hello("plain", "/tree").expect("the mount resolves");
    client
        .lookup(ROOT, "data.bin")
        .expect("the graft is reachable through the new listener");
}

// ---------------------------------------------------------------------------
// Criterion 1 — a listener added at runtime accepts a mount immediately, on
// all three transports, and the state file carries it across a restart
// ---------------------------------------------------------------------------

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
    // The answer is the port the kernel gave, not the `:0` that was asked for.
    let address: std::net::SocketAddr = endpoint.parse().expect("a bound address");
    assert_ne!(address.port(), 0);
    mounts(WireClient::tcp(address).expect("the new listener accepts connections"));

    // It is live everywhere the operator can look, and the ones already
    // serving are untouched.
    let endpoints = case.endpoints();
    assert!(endpoints.contains(&endpoint), "{endpoints:?}");
    for existing in &started_with {
        assert!(endpoints.contains(existing), "{endpoints:?}");
    }
    mounts(WireClient::unix(case.server.data_unix()).expect("the startup listener still serves"));

    // The file holds the source form, `:0` and all: what persists is what the
    // operator asked for, and a restart resolves it afresh.
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

    // The whole point of persisting: the next server serves it without anyone
    // asking again.
    case.restart();
    assert!(
        case.endpoints().contains(&endpoint),
        "a restarted server serves what the file says: {:?}",
        case.endpoints()
    );
    mounts(WireClient::unix(&path).expect("the restarted server accepts on it"));
}

/// The vsock side. A machine with no loopback transport skips it loudly; a
/// machine that claims support has no way to skip, which is the suite's rule.
#[test]
fn a_runtime_vsock_listener_accepts_a_mount_immediately() {
    if !voidportd::testing::vsock::preflight() {
        return;
    }
    let case = Case::tcp("listener-add-vsock");
    let port = voidportd::testing::vsock::free_port().expect("a free vsock port");

    let endpoint = add(&mut case.control(), Listener::vsock(port));
    // The wildcard cid is spelled `any`, as everywhere an operator reads it.
    assert_eq!(endpoint, format!("any:{port}"));
    mounts(WireClient::vsock(port).expect("the new vsock listener accepts connections"));
    assert_eq!(case.persisted()[1], Listener::vsock(port));
}

// ---------------------------------------------------------------------------
// Criterion 2 — a bind failure is the operation's error, persists nothing, and
// leaves every existing listener serving
// ---------------------------------------------------------------------------

#[test]
fn a_bind_failure_answers_the_os_error_and_changes_nothing() {
    let case = Case::tcp("listener-bind-failure");
    let before = case.persisted();
    let mut client = case.control();

    // An occupied port: somebody else holds it, so the OS refuses.
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    let taken = occupied.local_addr().expect("a bound address");
    let error = client.expect_error(&Request::ListenerAdd {
        listener: Listener::Tcp { addr: taken },
    });
    assert_eq!(error.code, ErrorCode::BindFailed);
    assert!(error.message.contains(&taken.to_string()), "{error}");
    // The operating system's own answer, not a paraphrase of it.
    assert!(error.message.contains("in use"), "{error}");

    // A unix path in a directory that does not exist.
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

    // Nothing was written, and the server still serves what it did before.
    assert_eq!(case.persisted(), before);
    mounts(WireClient::tcp(case.server.data_tcp()).expect("the original listener still serves"));
}

// ---------------------------------------------------------------------------
// Criterion 3 — removal stops new connections, leaves existing sessions
// serving, and may leave a control-socket-only server
// ---------------------------------------------------------------------------

#[test]
fn removing_a_listener_stops_new_connections_and_leaves_its_sessions_serving() {
    let case = Case::tcp("listener-remove");
    let mut client = case.control();
    let path = case.directory.join("doomed.sock");
    let endpoint = add(&mut client, Listener::Unix { path: path.clone() });

    // A session mounted through the listener that is about to go away.
    let mut mounted = WireClient::unix(&path).expect("the listener accepts");
    mounted.hello("plain", "/tree").expect("the mount resolves");

    client.expect_ok(&Request::ListenerRemove {
        endpoint: endpoint.clone(),
    });

    // No new connection lands: the socket is closed by the time the operation
    // answers, and a unix listener unlinks the path it created.
    assert!(!path.exists(), "the removed listener unlinked its socket");
    assert!(
        WireClient::unix(&path).is_err(),
        "a removed listener accepts nothing"
    );

    // Removal is not an eviction: the session accepted before it keeps
    // serving, and the operator still sees it.
    mounted
        .lookup(ROOT, "data.bin")
        .expect("an already-accepted session is untouched by removal");
    let Reply::SessionList { sessions } = client.expect_ok(&Request::SessionList {}) else {
        panic!("session-list answers sessions");
    };
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    assert_eq!(sessions[0].transport, "unix");

    // And the file no longer carries it.
    assert_eq!(case.persisted(), vec![tcp_listener()]);
    assert!(
        !case.endpoints().contains(&endpoint),
        "{:?}",
        case.endpoints()
    );
}

/// Removal on the transport that leaves nothing behind to look at, and what it
/// gives back.
///
/// The unix case above can read the answer off the filesystem — the path is
/// unlinked — but a tcp listener's only evidence is the socket itself, so the
/// refused connection is what says it was closed and not merely forgotten. The
/// second half is the churn an operator actually performs: a listener is
/// identified by the source form it was added with, so removing one must give
/// that spelling back. Otherwise `:0` could be added exactly once per server
/// lifetime, and the state file would grow an entry nobody could remove.
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

    // Mounted through it, so the removal has a session to leave alone.
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

    // The source form is free again: while the listener was held, adding
    // `127.0.0.1:0` a second time was a duplicate.
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
    // Legal, and still a server: the control plane answers exactly as before.
    client.expect_ok(&Request::NamespaceList {});

    // A restart of a listener-less server is a listener-less server, and it
    // can be given one again.
    case.restart();
    assert!(case.endpoints().is_empty());
    let endpoint = add(&mut case.control(), tcp_listener());
    mounts(WireClient::tcp(endpoint.parse().expect("a bound address")).expect("it accepts"));
}

// ---------------------------------------------------------------------------
// Criterion 4 — typed errors naming the endpoint, and validation parity with
// startup
// ---------------------------------------------------------------------------

#[test]
fn a_duplicate_add_is_refused_as_a_duplicate_rather_than_as_a_bind_failure() {
    let case = Case::tcp("listener-duplicate");
    let mut client = case.control();
    let path = case.directory.join("once.sock");
    let endpoint = add(&mut client, Listener::Unix { path: path.clone() });

    let error = client.expect_error(&Request::ListenerAdd {
        listener: Listener::Unix { path: path.clone() },
    });
    assert_eq!(error.code, ErrorCode::AlreadyExists);
    assert!(error.message.contains(&endpoint), "{error}");
    // The refusal came before the bind, so the live listener is untouched.
    assert!(path.exists());
    mounts(WireClient::unix(&path).expect("the first listener still serves"));
    assert_eq!(case.persisted().len(), 2, "nothing was written twice");

    // A listener is identified by the source form the operator wrote, which is
    // the only thing there is to compare before a bind. So a second `:0` is a
    // duplicate too — and that is what keeps every entry in the state file
    // reachable: two identical entries would be one endpoint an operator could
    // name and one they could not.
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

/// The vsock port range is the settings validation, and `listener-add` runs
/// it — the same check, the same message, on the same code path a state file
/// takes at load. Nothing is bound, so this needs no vsock transport.
#[test]
fn a_runtime_vsock_port_is_validated_exactly_as_a_configured_one() {
    let case = Case::tcp("listener-vsock-port");
    let mut client = case.control();
    let before = case.persisted();

    for port in [0, 70_000] {
        let error = client.expect_error(&Request::ListenerAdd {
            listener: Listener::vsock(port),
        });
        assert_eq!(error.code, ErrorCode::InvalidConfiguration, "{port}");
        // The startup message, word for word: one check, one wording.
        assert!(error.message.contains(&format!("port {port}")), "{error}");
        assert!(error.message.contains("1..=65535"), "{error}");
    }
    assert_eq!(case.persisted(), before);
}
