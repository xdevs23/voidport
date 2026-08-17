//! Data-plane listeners.
//!
//! Listeners are served from the persisted configuration, and startup is
//! **all-or-nothing**: every listener is bound before any of them is served, so
//! a server that comes up is a server reachable on every endpoint its operator
//! configured. A partially reachable server is the worse failure — the operator
//! sees "started" and one guest cannot mount.
//!
//! The framing is byte-stream-agnostic, so a transport only has to say how it
//! is addressed and how a peer is named:
//!
//! * `tcp` — bound eagerly, so a port already in use fails startup;
//! * `unix` — the same bind contract as the control socket (sidecar claim,
//!   stale reclaim, live refuse, non-socket refuse, `0600`, unlinked on
//!   shutdown), shared with it in [`crate::socket`];
//! * `vsock` — bound on a cid and a port, reachable from this machine's own
//!   guests and from nowhere else. The two crates it takes and why it is split
//!   by descriptor duplication are in [`super::vsock`].
//!
//! # The three values a listener has
//!
//! They are deliberately distinct types, because the control plane needs all
//! three at once:
//!
//! * [`Listener`] — the **source form**, what the operator wrote and what the
//!   state file holds. A tcp listener configured on port 0 says `:0` here for
//!   as long as it lives, and a restart resolves it afresh.
//! * [`Endpoint`] — the address it **actually bound**, which is what a guest
//!   dials, what `server-info` lists, and how `listener-remove` names it.
//! * [`BoundListener`] — the socket itself, bound and not yet serving. It is a
//!   transient: [`DataListeners`] takes it, spawns its accept loop, and from
//!   then on the listener is reachable only through the registry.
//!
//! # Runtime mutation
//!
//! [`DataListeners`] is the registry the control plane's `listener-add` and
//! `listener-remove` operate on, so it is shared and interior-mutable, not
//! consumed by serving. Each listener owns its own stop signal, which is
//! what makes removing one possible without touching the others, and each is
//! joined on the way out, which is what keeps clean shutdown structural:
//! nothing here is a detached task.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use voidport_control::{ANY_CID, Listener, ListenerInfo};

use super::conn;
use super::server::DataPlane;
use super::session::Peer;
use super::vsock;
use crate::socket::{BindError, UnixSocket};

/// A data-plane transport, as the state file and the wire spell it.
///
/// The set is closed and it is the same set [`Listener`] tags itself with, so
/// a session, a bound endpoint and a configured listener all name a transport
/// with one vocabulary and none of them can name one that does not exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transport {
    /// A TCP socket.
    Tcp,
    /// A unix socket.
    Unix,
    /// A vsock endpoint.
    Vsock,
}

impl Transport {
    /// The name, as everything that writes a transport down writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Unix => "unix",
            Self::Vsock => "vsock",
        }
    }
}

impl fmt::Display for Transport {
    /// Honors width and alignment, so transports can be tabulated.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// A listener's address as bound: what a guest dials.
///
/// Distinct from the [`Listener`] it came from because the two disagree
/// wherever the kernel chose something: a tcp listener configured on port 0
/// keeps saying `:0` in the state file and says its real port here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A TCP address, port 0 resolved.
    Tcp(SocketAddr),
    /// A unix socket path.
    Unix(PathBuf),
    /// A vsock cid and port.
    Vsock {
        /// The cid it bound, which is the wildcard unless the operator named
        /// one.
        cid: u32,
        /// The port it bound.
        port: u32,
    },
}

impl Endpoint {
    /// The transport a session records.
    #[must_use]
    pub fn transport(&self) -> Transport {
        match self {
            Self::Tcp(_) => Transport::Tcp,
            Self::Unix(_) => Transport::Unix,
            Self::Vsock { .. } => Transport::Vsock,
        }
    }

    /// How this endpoint is written wherever an operator reads or names it.
    ///
    /// A vsock endpoint is written as the mount grammar's authority — `cid:port`
    /// — with the wildcard cid spelled `any`, because the number behind it
    /// (`4294967295`) tells an operator nothing about what it means.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Tcp(address) => address.to_string(),
            Self::Unix(path) => path.display().to_string(),
            Self::Vsock { cid, port } if *cid == ANY_CID => format!("any:{port}"),
            Self::Vsock { cid, port } => format!("{cid}:{port}"),
        }
    }

    /// How this endpoint reports itself over the control plane.
    #[must_use]
    pub fn info(&self) -> ListenerInfo {
        ListenerInfo::new(self.transport().as_str(), self.render())
    }

    /// The address a TCP listener bound, port 0 resolved. Tests need it to
    /// connect to an ephemeral port.
    #[must_use]
    pub fn tcp_address(&self) -> Option<SocketAddr> {
        match self {
            Self::Tcp(address) => Some(*address),
            Self::Unix(_) | Self::Vsock { .. } => None,
        }
    }

    /// The path a unix listener bound.
    #[must_use]
    pub fn unix_path(&self) -> Option<&Path> {
        match self {
            Self::Unix(path) => Some(path),
            Self::Tcp(_) | Self::Vsock { .. } => None,
        }
    }

    /// The cid and port a vsock listener bound.
    #[must_use]
    pub fn vsock_address(&self) -> Option<(u32, u32)> {
        match self {
            Self::Vsock { cid, port } => Some((*cid, *port)),
            Self::Tcp(_) | Self::Unix(_) => None,
        }
    }
}

/// A listener that is bound but not yet serving.
///
/// Binding happens synchronously — at startup before any runtime exists, and on
/// the blocking pool for a runtime addition — which is what makes
/// all-or-nothing startup possible: [`Daemon::start`](crate::daemon::Daemon::start)
/// either returns with every endpoint bound or fails having served nothing. It
/// is also what lets `listener-add` bind *before* it persists and drop the
/// never-served socket if the persist fails.
#[derive(Debug)]
pub enum BoundListener {
    /// A TCP endpoint.
    Tcp {
        /// The bound listener, in its blocking form.
        listener: std::net::TcpListener,
        /// The address it actually bound, port 0 resolved.
        address: SocketAddr,
    },
    /// A unix endpoint, which unlinks its path when dropped.
    Unix {
        /// The bound socket.
        socket: UnixSocket,
    },
    /// A vsock endpoint, reachable from this machine's guests.
    Vsock {
        /// The bound listener, in its blocking form. It becomes asynchronous at
        /// serve time, when there is a runtime to register it with.
        listener: ::vsock::VsockListener,
        /// The cid it actually bound, which is the wildcard unless the operator
        /// named one.
        cid: u32,
        /// The port it actually bound.
        port: u32,
    },
}

impl BoundListener {
    /// Binds every configured listener, or none of them.
    ///
    /// # Errors
    ///
    /// Returns the first [`ListenerError`]; listeners bound before it are
    /// dropped, which closes them and unlinks any unix path they created.
    pub fn bind_all(listeners: &[Listener]) -> Result<Vec<Self>, ListenerError> {
        listeners.iter().map(Self::bind).collect()
    }

    /// Binds one configured listener.
    ///
    /// # Errors
    ///
    /// Returns the underlying failure for anything that cannot be bound.
    pub fn bind(listener: &Listener) -> Result<Self, ListenerError> {
        match listener {
            Listener::Tcp { addr } => {
                let listener =
                    std::net::TcpListener::bind(addr).map_err(|source| ListenerError::Tcp {
                        address: *addr,
                        source,
                    })?;
                listener
                    .set_nonblocking(true)
                    .map_err(|source| ListenerError::Tcp {
                        address: *addr,
                        source,
                    })?;
                let address = listener.local_addr().unwrap_or(*addr);
                Ok(Self::Tcp { listener, address })
            }
            Listener::Unix { path } => Ok(Self::Unix {
                socket: UnixSocket::bind(path)?,
            }),
            Listener::Vsock { cid, port } => {
                let listener = vsock::bind(*cid, *port).map_err(|source| ListenerError::Vsock {
                    cid: *cid,
                    port: *port,
                    source,
                })?;
                // What the kernel says it bound, not what was asked for: the
                // two agree here, and reporting the bound address is what the
                // tcp arm does for the same reason.
                let bound = listener
                    .local_addr()
                    .map_err(|source| ListenerError::Vsock {
                        cid: *cid,
                        port: *port,
                        source,
                    })?;
                Ok(Self::Vsock {
                    listener,
                    cid: bound.cid(),
                    port: bound.port(),
                })
            }
        }
    }

    /// The address this listener actually bound.
    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        match self {
            Self::Tcp { address, .. } => Endpoint::Tcp(*address),
            Self::Unix { socket } => Endpoint::Unix(socket.path().to_path_buf()),
            Self::Vsock { cid, port, .. } => Endpoint::Vsock {
                cid: *cid,
                port: *port,
            },
        }
    }

    /// Accepts connections until `stopped` says otherwise.
    ///
    /// A connection is spawned and forgotten: it owns its session, and the
    /// session's teardown is the connection task ending, whichever way it ends.
    /// That is also why removing a listener is not an eviction — the sessions
    /// it accepted have nothing left to do with it.
    async fn accept(self, plane: Arc<DataPlane>, mut stopped: watch::Receiver<bool>) {
        match self {
            Self::Tcp { listener, .. } => {
                let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
                    tracing::error!("a tcp data listener could not be served");
                    return;
                };
                loop {
                    tokio::select! {
                        biased;
                        _ = stopped.wait_for(|stopped| *stopped) => return,
                        accepted = listener.accept() => match accepted {
                            Ok((stream, address)) => {
                                // A filesystem protocol is a latency protocol:
                                // aggregating a reply with the next one costs a
                                // delayed-ACK round trip on every request.
                                if let Err(error) = stream.set_nodelay(true) {
                                    tracing::warn!(%error, "a data connection could not disable Nagle");
                                }
                                let peer = Peer::new(Transport::Tcp, address.to_string());
                                tokio::spawn(conn::serve(stream, Arc::clone(&plane), peer));
                            }
                            Err(error) => tracing::warn!(%error, "a data connection was not accepted"),
                        },
                    }
                }
            }
            Self::Unix { mut socket } => {
                let Some(bound) = socket.take() else {
                    return;
                };
                let Ok(listener) = tokio::net::UnixListener::from_std(bound) else {
                    tracing::error!("a unix data listener could not be served");
                    return;
                };
                loop {
                    tokio::select! {
                        biased;
                        _ = stopped.wait_for(|stopped| *stopped) => break,
                        accepted = listener.accept() => match accepted {
                            Ok((stream, _)) => {
                                let peer = Peer::new(Transport::Unix, socket.path().display().to_string());
                                tokio::spawn(conn::serve(stream, Arc::clone(&plane), peer));
                            }
                            Err(error) => tracing::warn!(%error, "a data connection was not accepted"),
                        },
                    }
                }
                // Dropping the socket here, not at the end of the
                // process, is what unlinks the path on a clean shutdown — and
                // on a `listener-remove`, which is the same path.
                drop(socket);
            }
            Self::Vsock {
                listener,
                cid,
                port,
            } => {
                // The bind happened before this runtime existed; this is where
                // that same descriptor joins its reactor.
                let acceptor = match vsock::Acceptor::new(listener) {
                    Ok(acceptor) => acceptor,
                    Err(error) => {
                        tracing::error!(%error, "a vsock data listener could not be served");
                        return;
                    }
                };
                loop {
                    tokio::select! {
                        biased;
                        _ = stopped.wait_for(|stopped| *stopped) => return,
                        accepted = acceptor.accept() => match accepted {
                            Ok((connection, address)) => {
                                let peer = Peer::new(
                                    Transport::Vsock,
                                    format!("{}:{}", address.cid(), address.port()),
                                );
                                tokio::spawn(conn::serve(connection, Arc::clone(&plane), peer));
                            }
                            Err(error) => tracing::warn!(
                                %error,
                                cid,
                                port,
                                "a data connection was not accepted",
                            ),
                        },
                    }
                }
            }
        }
    }
}

/// Every data listener the server currently holds, bound or serving.
///
/// Shared by startup, by the serving loop and by the control plane's listener
/// operations, which is why it is a registry behind a lock, not a value
/// serving consumes. The lock is only ever held for list manipulation — never
/// across an accept, and never across an await.
#[derive(Debug)]
pub struct DataListeners {
    plane: Arc<DataPlane>,
    /// The runtime the accept loops belong to, learned when serving starts.
    ///
    /// A listener added at runtime joins the *server's* runtime, not whichever
    /// runtime the control-plane handler happens to be reachable from.
    runtime: OnceLock<Handle>,
    live: Mutex<Vec<Live>>,
}

/// One listener the server holds: its source form, its bound address, and
/// whatever it takes to stop it.
#[derive(Debug)]
struct Live {
    /// The source form, which is what persists and what a restart re-binds.
    config: Listener,
    /// The address it bound, which is what names it.
    endpoint: Endpoint,
    state: State,
}

/// Whether a listener is merely bound or actually accepting.
#[derive(Debug)]
enum State {
    /// Bound, not yet serving: startup binds before there is a runtime.
    Bound(BoundListener),
    /// Serving, with everything it takes to stop it and know it stopped.
    Serving(Serving),
}

/// A running accept loop's handles.
#[derive(Debug)]
struct Serving {
    /// Set to stop this one listener, and only this one.
    stop: watch::Sender<bool>,
    /// Disconnected once the accept task has dropped its socket. The
    /// synchronous close path waits on it, which is what makes
    /// `listener-remove` mean "closed" by the time it answers, not
    /// "asked to close".
    closed: std::sync::mpsc::Receiver<()>,
    /// The accept task, joined by the asynchronous shutdown path.
    task: JoinHandle<()>,
}

impl Serving {
    /// Stops the listener and waits, **blocking the calling thread**, until its
    /// socket is closed.
    ///
    /// Only safe off the runtime's own threads — the control plane's handlers
    /// run on the blocking pool ([`crate::control::listener`]), which is where
    /// this is called from.
    fn close_blocking(self) {
        let _ = self.stop.send(true);
        // `Err` is the expected outcome: nothing is ever sent, and the channel
        // disconnects when the accept task drops its end.
        let _ = self.closed.recv();
        // The task has ended; the handle is dropped, not joined.
        drop(self.task);
    }
}

impl Live {
    /// Spawns this listener's accept loop, if it is not already serving.
    fn serve(self, plane: &Arc<DataPlane>, runtime: &Handle) -> Self {
        let Self {
            config,
            endpoint,
            state,
        } = self;
        let bound = match state {
            State::Bound(bound) => bound,
            serving @ State::Serving(_) => {
                return Self {
                    config,
                    endpoint,
                    state: serving,
                };
            }
        };
        tracing::info!(
            transport = %endpoint.transport(),
            endpoint = endpoint.render(),
            "serving a data listener"
        );
        let (stop, stopped) = watch::channel(false);
        let (open, closed) = std::sync::mpsc::channel();
        let plane = Arc::clone(plane);
        let task = runtime.spawn(async move {
            bound.accept(plane, stopped).await;
            // Dropped only here, after `accept` has returned and with it
            // dropped the socket: a thread waiting on `closed` is waiting for
            // exactly that.
            drop(open);
        });
        Self {
            config,
            endpoint,
            state: State::Serving(Serving { stop, closed, task }),
        }
    }
}

impl DataListeners {
    /// Binds every configured listener around a data plane.
    ///
    /// # Errors
    ///
    /// Returns the first [`ListenerError`]; nothing stays bound.
    pub fn bind(plane: Arc<DataPlane>, listeners: &[Listener]) -> Result<Arc<Self>, ListenerError> {
        let bound = BoundListener::bind_all(listeners)?;
        let live = listeners
            .iter()
            .cloned()
            .zip(bound)
            .map(|(config, bound)| Live {
                endpoint: bound.endpoint(),
                config,
                state: State::Bound(bound),
            })
            .collect();
        Ok(Arc::new(Self {
            plane,
            runtime: OnceLock::new(),
            live: Mutex::new(live),
        }))
    }

    /// The addresses every listener bound, in the order they were added.
    #[must_use]
    pub fn endpoints(&self) -> Vec<Endpoint> {
        self.lock()
            .iter()
            .map(|listener| listener.endpoint.clone())
            .collect()
    }

    /// How the bound endpoints report over the control plane.
    #[must_use]
    pub fn info(&self) -> Vec<ListenerInfo> {
        self.lock()
            .iter()
            .map(|listener| listener.endpoint.info())
            .collect()
    }

    /// Whether anything is bound at all. Zero listeners is a legal state: such
    /// a server serves only its control socket.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// The address the first tcp listener bound, for tests that need the port
    /// an ephemeral configuration resolved to.
    #[must_use]
    pub fn tcp_address(&self) -> Option<SocketAddr> {
        self.lock()
            .iter()
            .find_map(|listener| listener.endpoint.tcp_address())
    }

    /// The path the first unix listener bound.
    #[must_use]
    pub fn unix_path(&self) -> Option<PathBuf> {
        self.lock()
            .iter()
            .find_map(|listener| listener.endpoint.unix_path().map(Path::to_path_buf))
    }

    /// The listener already held with exactly this source form, if there is
    /// one.
    ///
    /// This is `listener-add`'s duplicate refusal, and it compares **source
    /// forms** for the same reason the seed does: what the operator asked for
    /// is what identifies the request, before anything is bound and therefore
    /// before there is a bound address to compare. It also means a duplicate is
    /// answered as a duplicate instead of as a confusing `EADDRINUSE` against
    /// the server's own socket. What it answers with is where the held one
    /// bound, because that is the endpoint the operator can act on.
    #[must_use]
    pub fn duplicate(&self, config: &Listener) -> Option<ListenerInfo> {
        self.lock()
            .iter()
            .find(|listener| &listener.config == config)
            .map(|listener| listener.endpoint.info())
    }

    /// The source form of the listener bound at `endpoint`, which is the
    /// document entry `listener-remove` has to take out of the state file.
    ///
    /// This mapping is the whole reason the registry keeps the source form:
    /// an operator names a listener by where it bound, and the file holds where
    /// it was asked to bind.
    #[must_use]
    pub fn configured(&self, endpoint: &str) -> Option<Listener> {
        self.lock()
            .iter()
            .find(|listener| listener.endpoint.render() == endpoint)
            .map(|listener| listener.config.clone())
    }

    /// The runtime the accept loops run on, once serving has started.
    ///
    /// `None` before that, which is also `listener-add`'s answer that there is
    /// nothing to add a listener to yet.
    #[must_use]
    pub fn runtime(&self) -> Option<Handle> {
        self.runtime.get().cloned()
    }

    /// Registers an already-bound listener and starts serving it.
    ///
    /// The last step of `listener-add`, and deliberately the last: the socket
    /// was bound before the persist and starts accepting only after it, so a
    /// listener a restart would not serve never served in the first place.
    pub fn publish(
        &self,
        runtime: &Handle,
        config: Listener,
        bound: BoundListener,
    ) -> ListenerInfo {
        let listener = Live {
            endpoint: bound.endpoint(),
            config,
            state: State::Bound(bound),
        }
        .serve(&self.plane, runtime);
        let info = listener.endpoint.info();
        self.lock().push(listener);
        info
    }

    /// Closes the listener bound at `endpoint` and forgets it, blocking until
    /// its socket is really gone.
    ///
    /// Returns whether there was one. This is `listener-remove`'s swap: when it
    /// returns, no further connection can land on that endpoint, while every
    /// session already accepted on it goes on serving — a session's connection
    /// has nothing to do with the listener that accepted it.
    ///
    /// It blocks the calling thread, so it belongs on the blocking pool, which
    /// is where every control-plane handler already runs.
    pub fn close_blocking(&self, endpoint: &str) -> bool {
        let listener = {
            let mut live = self.lock();
            let index = live
                .iter()
                .position(|listener| listener.endpoint.render() == endpoint);
            match index {
                Some(index) => live.remove(index),
                None => return false,
            }
        };
        tracing::info!(
            transport = %listener.endpoint.transport(),
            endpoint = listener.endpoint.render(),
            "closing a data listener"
        );
        match listener.state {
            // Never served: closing it is dropping it, which also unlinks a
            // unix path this server created.
            State::Bound(bound) => drop(bound),
            State::Serving(serving) => serving.close_blocking(),
        }
        true
    }

    /// Serves every listener until `shutdown` resolves, runtime additions
    /// included, then closes all of them and waits for their accept loops.
    ///
    /// Joining instead of detaching is what makes clean shutdown structural:
    /// when this returns, every socket the server bound is closed and every
    /// unix path it created is unlinked.
    pub async fn serve(self: Arc<Self>, shutdown: impl Future<Output = ()> + Send) {
        let runtime = Handle::current();
        // Ignored if serving somehow started twice: the first runtime wins, and
        // the accept loops of both belong to it.
        let _ = self.runtime.set(runtime.clone());
        {
            let mut live = self.lock();
            let listeners = std::mem::take(&mut *live);
            *live = listeners
                .into_iter()
                .map(|listener| listener.serve(&self.plane, &runtime))
                .collect();
        }
        shutdown.await;
        self.stop_all().await;
    }

    /// Stops every listener and waits for its accept loop to end.
    async fn stop_all(&self) {
        let listeners = std::mem::take(&mut *self.lock());
        let mut accepting = Vec::new();
        for listener in listeners {
            match listener.state {
                State::Bound(bound) => drop(bound),
                State::Serving(serving) => {
                    let _ = serving.stop.send(true);
                    // The task is awaited instead of the closed channel: this
                    // path runs *on* the runtime, where blocking would stop the
                    // very loops it is waiting for.
                    accepting.push(serving.task);
                }
            }
        }
        for task in accepting {
            let _ = task.await;
        }
    }

    /// Takes the registry lock, ignoring poisoning: a panicking holder leaves
    /// the list well-formed, and refusing to serve afterwards would be worse.
    fn lock(&self) -> MutexGuard<'_, Vec<Live>> {
        self.live
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// Why a data listener could not be bound.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ListenerError {
    /// A TCP endpoint could not be bound.
    #[error("cannot bind tcp data listener {address}")]
    Tcp {
        /// The configured address.
        address: SocketAddr,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// A unix endpoint could not be bound; the contract is the control
    /// socket's.
    #[error(transparent)]
    Unix(#[from] BindError),
    /// A vsock endpoint could not be bound — the port is taken on that cid, or
    /// this kernel has no vsock transport at all.
    #[error("cannot bind vsock data listener cid {cid} port {port}")]
    Vsock {
        /// The configured cid.
        cid: u32,
        /// The configured port.
        port: u32,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Scratch;

    /// A transport is spelled one way, and it is the way the configured
    /// listener tags itself: what a session reports and what a bound endpoint
    /// lists are the three names a state file is written with.
    #[test]
    fn a_transport_is_spelled_the_way_the_configured_listener_tags_itself() {
        let cases = [
            (
                Transport::Tcp,
                "tcp",
                Listener::Tcp {
                    addr: "127.0.0.1:9000".parse().expect("valid address"),
                },
            ),
            (
                Transport::Unix,
                "unix",
                Listener::Unix {
                    path: PathBuf::from("/run/voidport/data.sock"),
                },
            ),
            (Transport::Vsock, "vsock", Listener::vsock(1024)),
        ];
        for (transport, name, configured) in cases {
            assert_eq!(transport.as_str(), name);
            assert_eq!(transport.to_string(), name);
            assert_eq!(configured.transport(), name);
            assert_eq!(Peer::new(transport, "somewhere").transport, transport);
        }
    }

    /// A vsock listener binds like the other two, and reports the address it
    /// bound in the mount grammar's `cid:port` form.
    #[test]
    fn a_vsock_listener_binds_and_reports_its_endpoint() {
        if !crate::testing::vsock::preflight() {
            return;
        }
        let port = crate::testing::vsock::free_port().expect("a free vsock port");
        let bound = BoundListener::bind_all(&[Listener::Vsock { cid: ANY_CID, port }])
            .expect("the wildcard cid binds");

        let endpoint = bound[0].endpoint();
        assert_eq!(endpoint.transport(), Transport::Vsock);
        assert_eq!(endpoint.vsock_address(), Some((ANY_CID, port)));
        assert_eq!(endpoint.render(), format!("any:{port}"));
        assert!(endpoint.tcp_address().is_none());
        assert!(endpoint.unix_path().is_none());

        // The port is held: a second server cannot serve the same endpoint.
        let taken = BoundListener::bind(&Listener::Vsock { cid: ANY_CID, port })
            .expect_err("the port is in use");
        assert!(matches!(taken, ListenerError::Vsock { .. }), "{taken}");
        assert!(
            taken.to_string().contains(&format!("port {port}")),
            "{taken}"
        );
    }

    #[test]
    fn one_failing_listener_leaves_nothing_bound() {
        let scratch = Scratch::new("listeners");
        let path = scratch.join("data.sock");
        let error = BoundListener::bind_all(&[
            Listener::Unix { path: path.clone() },
            // A socket in a directory that does not exist: the second bind
            // fails, and the first must not survive it.
            Listener::Unix {
                path: scratch.join("nowhere").join("data.sock"),
            },
        ])
        .expect_err("the second entry fails startup");
        assert!(matches!(error, ListenerError::Unix(_)), "{error}");
        assert!(
            !path.exists(),
            "a listener bound before the failure must not survive it"
        );
    }

    #[test]
    fn tcp_and_unix_bind_and_report_their_endpoints() {
        let scratch = Scratch::new("listeners");
        let path = scratch.join("data.sock");
        let bound = BoundListener::bind_all(&[
            Listener::Tcp {
                addr: "127.0.0.1:0".parse().expect("valid address"),
            },
            Listener::Unix { path: path.clone() },
        ])
        .expect("both bind");

        let tcp = bound[0].endpoint();
        assert_eq!(tcp.transport(), Transport::Tcp);
        let address = tcp.tcp_address().expect("a tcp listener");
        assert_ne!(address.port(), 0, "the ephemeral port is resolved");
        assert!(tcp.unix_path().is_none());

        let unix = bound[1].endpoint();
        assert_eq!(unix.transport(), Transport::Unix);
        assert_eq!(unix.unix_path(), Some(path.as_path()));
        assert!(path.exists());
        assert_eq!(unix.render(), path.display().to_string());
        assert_eq!(
            unix.info(),
            ListenerInfo::new(Transport::Unix.as_str(), unix.render())
        );

        drop(bound);
        assert!(!path.exists(), "a dropped unix listener unlinks its path");
    }
}
