//! A real server, running on its own thread.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::control::service::Service;
use crate::daemon::{Daemon, DaemonConfig, StartupError};
use crate::data::DataListeners;
use crate::state::Environment;
use crate::testing::ControlClient;

/// A server running on its own thread, with its own runtime.
///
/// Running it on a thread instead of in the test's runtime keeps the tests
/// synchronous and makes them look like what they are: a client talking to a
/// separate server over a socket. It also puts the server in the test's own
/// process, which is what lets a test read the server's descriptor table
/// through `/proc/self/fd` (see [`open_descriptors`]).
#[derive(Debug)]
pub struct RunningServer {
    socket: PathBuf,
    listeners: Arc<DataListeners>,
    data_tcp: Option<SocketAddr>,
    data_unix: Option<PathBuf>,
    service: Arc<Service>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl RunningServer {
    /// Starts a server, or reports why it would not start.
    ///
    /// # Errors
    ///
    /// Propagates the daemon's own startup failure, which is what the lock and
    /// bind-contract tests assert on.
    pub fn start(config: &DaemonConfig) -> Result<Self, StartupError> {
        let daemon = Daemon::start(config)?;
        let socket = daemon.control_socket().to_path_buf();
        let service = daemon.service();
        // The endpoints the data listeners actually bound: a configured port 0
        // is resolved by now, which is how a test reaches an ephemeral one.
        let listeners = Arc::clone(daemon.data_listeners());
        let data_tcp = listeners.tcp_address();
        let data_unix = listeners.unix_path();
        let (shutdown, shutdown_signal) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a tokio runtime");
            runtime.block_on(async move {
                daemon
                    .serve(async {
                        let _ = shutdown_signal.await;
                    })
                    .await
                    .expect("the control plane serves");
            });
        });
        Ok(Self {
            socket,
            listeners,
            data_tcp,
            data_unix,
            service,
            shutdown: Some(shutdown),
            thread: Some(thread),
        })
    }

    /// The control socket path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The service behind the socket, for asserting on published state
    /// directly.
    #[must_use]
    pub fn service(&self) -> &Arc<Service> {
        &self.service
    }

    /// The address the tcp data listener bound at startup.
    #[must_use]
    pub fn data_tcp(&self) -> SocketAddr {
        self.data_tcp.expect("a tcp data listener is configured")
    }

    /// The path the unix data listener bound at startup.
    #[must_use]
    pub fn data_unix(&self) -> &Path {
        self.data_unix
            .as_deref()
            .expect("a unix data listener is configured")
    }

    /// The live listener registry, for tests that watch it change: the two
    /// accessors above name what *startup* bound, and a listener added or
    /// removed through the control plane is only visible here.
    #[must_use]
    pub fn listeners(&self) -> &Arc<DataListeners> {
        &self.listeners
    }

    /// A fresh control-plane connection.
    ///
    /// # Panics
    ///
    /// If the socket refuses it: a server that is running owes its operator a
    /// control plane.
    #[must_use]
    pub fn connect(&self) -> ControlClient {
        ControlClient::connect(&self.socket).expect("the control socket accepts connections")
    }

    /// Asks the server to shut down without waiting for it, for tests that
    /// must observe what happens *while* it is shutting down.
    pub fn signal_stop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }

    /// Stops the server and waits for it to finish shutting down.
    pub fn stop(&mut self) {
        self.signal_stop();
        if let Some(thread) = self.thread.take() {
            thread.join().expect("the server thread exits cleanly");
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The configuration a test daemon runs under.
///
/// The control socket goes beside the state file, so one temporary directory
/// holds everything the server owns and removing it removes the server's whole
/// world.
#[must_use]
pub fn daemon_config(state_file: &Path, environment: Environment) -> DaemonConfig {
    let directory = state_file.parent().unwrap_or_else(|| Path::new("."));
    DaemonConfig::new(state_file)
        .with_control_socket(directory.join("control.sock"))
        .with_environment(environment)
}

/// A pinned identity, so sentinel resolution does not depend on who runs the
/// suite. This is what a test asserting on *what the state file says* wants.
#[must_use]
pub fn pinned_environment(state_dir: &Path) -> Environment {
    Environment::new(4242, 4243, state_dir)
}

/// The real invoking identity. This is what a test asserting on *what lands on
/// the host* wants: only the server's own identity can be applied without
/// `CAP_CHOWN`.
#[must_use]
pub fn invoking_environment(state_dir: &Path) -> Environment {
    Environment::new(
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
        state_dir,
    )
}

/// How many open descriptors of this process point at `path`.
///
/// The server runs in the test's own process, so `/proc/self/fd` is the
/// server's descriptor table: this is how a test observes that forgetting a
/// node, or tearing a session down, really closed its pins.
#[must_use]
pub fn open_descriptors(path: &Path) -> usize {
    let Ok(entries) = fs::read_dir("/proc/self/fd") else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| fs::read_link(entry.path()).is_ok_and(|target| target == path))
        .count()
}
