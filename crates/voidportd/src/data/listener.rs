//! Startup is all-or-nothing: every listener is bound before any of them is
//! served, so a server that comes up is reachable on every configured endpoint.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use voidport_control::{ANY_CID, Listener, ListenerInfo, VsockPort};

use super::conn;
use super::server::DataPlane;
use super::session::Peer;
use super::{virtio, vsock};
use crate::socket::{BindError, UnixSocket};

/// The same set [`Listener`] tags itself with, so a session, a bound endpoint
/// and a configured listener cannot name a transport that does not exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transport {
    Tcp,
    Unix,
    Vsock,
    VhostUser,
}

impl Transport {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Unix => "unix",
            Self::Vsock => "vsock",
            Self::VhostUser => "vhost-user",
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// Distinct from the [`Listener`] it came from because the two disagree wherever
/// the kernel chose something: a tcp listener configured on port 0 has `:0` in
/// the state file and its real port here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Tcp(SocketAddr),
    Unix(PathBuf),
    Vsock { cid: u32, port: u32 },
    VhostUser(PathBuf),
}

impl Endpoint {
    #[must_use]
    pub fn transport(&self) -> Transport {
        match self {
            Self::Tcp(_) => Transport::Tcp,
            Self::Unix(_) => Transport::Unix,
            Self::Vsock { .. } => Transport::Vsock,
            Self::VhostUser(_) => Transport::VhostUser,
        }
    }

    /// A vsock endpoint is written as `cid:port` with the wildcard cid spelled
    /// `any`, because the number behind it (`4294967295`) tells an operator
    /// nothing.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Tcp(address) => address.to_string(),
            Self::Unix(path) | Self::VhostUser(path) => path.display().to_string(),
            Self::Vsock { cid, port } if *cid == ANY_CID => format!("any:{port}"),
            Self::Vsock { cid, port } => format!("{cid}:{port}"),
        }
    }

    #[must_use]
    pub fn info(&self) -> ListenerInfo {
        ListenerInfo::new(self.transport().as_str(), self.render())
    }
}

/// Binding is synchronous, which makes all-or-nothing startup possible and lets
/// `listener-add` bind before it persists and drop the never-served socket if
/// the persist fails.
#[derive(Debug)]
pub enum BoundListener {
    Tcp {
        listener: std::net::TcpListener,
        address: SocketAddr,
    },
    Unix {
        socket: UnixSocket,
    },
    Vsock {
        /// In its blocking form. It becomes asynchronous at serve time, when
        /// there is a runtime to register it with.
        listener: ::vsock::VsockListener,
        cid: u32,
        port: u32,
    },
    VhostUser {
        socket: UnixSocket,
    },
}

impl BoundListener {
    pub fn bind_all(listeners: &[Listener]) -> Result<Vec<Self>, ListenerError> {
        listeners.iter().map(Self::bind).collect()
    }

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
            Listener::VhostUser { path } => Ok(Self::VhostUser {
                socket: UnixSocket::bind(path)?,
            }),
            Listener::Vsock { cid, port } => {
                let listener = vsock::bind(*cid, *port).map_err(|source| ListenerError::Vsock {
                    cid: *cid,
                    port: *port,
                    source,
                })?;
                // The port asked for and the port bound differ for
                // `VsockPort::Any`, so the bound address is reported, as the tcp
                // arm does for `:0`.
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

    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        match self {
            Self::Tcp { address, .. } => Endpoint::Tcp(*address),
            Self::Unix { socket } => Endpoint::Unix(socket.path().to_path_buf()),
            Self::VhostUser { socket } => Endpoint::VhostUser(socket.path().to_path_buf()),
            Self::Vsock { cid, port, .. } => Endpoint::Vsock {
                cid: *cid,
                port: *port,
            },
        }
    }

    /// A connection is spawned and forgotten: the session ends when the
    /// connection task ends.
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
                                // Nagle would hold back a small reply until the
                                // peer acknowledges earlier data, so a delayed
                                // acknowledgement would add a wait to every
                                // request.
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
            Self::Unix { socket } => {
                accept_unix(socket, Transport::Unix, stopped, |stream, peer| {
                    tokio::spawn(conn::serve(stream, Arc::clone(&plane), peer));
                })
                .await;
            }
            Self::VhostUser { socket } => {
                accept_unix(socket, Transport::VhostUser, stopped, |stream, peer| {
                    virtio::serve(stream, Arc::clone(&plane), peer);
                })
                .await;
            }
            Self::Vsock {
                listener,
                cid,
                port,
            } => {
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

async fn accept_unix(
    mut socket: UnixSocket,
    transport: Transport,
    mut stopped: watch::Receiver<bool>,
    serve: impl Fn(tokio::net::UnixStream, Peer),
) {
    let Some(bound) = socket.take() else {
        return;
    };
    let Ok(listener) = tokio::net::UnixListener::from_std(bound) else {
        tracing::error!(%transport, "a data listener could not be served");
        return;
    };
    loop {
        tokio::select! {
            biased;
            _ = stopped.wait_for(|stopped| *stopped) => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    serve(stream, Peer::new(transport, socket.path().display().to_string()));
                }
                Err(error) => tracing::warn!(%error, "a data connection was not accepted"),
            },
        }
    }
    // Dropping the socket here unlinks the path on a clean shutdown and on a
    // `listener-remove`.
    drop(socket);
}

/// Behind a lock held only for list manipulation, never across an accept and
/// never across an await.
#[derive(Debug)]
pub struct DataListeners {
    plane: Arc<DataPlane>,
    /// A listener added at runtime joins the runtime of the server, not
    /// whichever runtime the control-plane handler is reachable from.
    runtime: OnceLock<Handle>,
    live: Mutex<Vec<Live>>,
}

#[derive(Debug)]
struct Live {
    config: Listener,
    endpoint: Endpoint,
    state: State,
}

#[derive(Debug)]
enum State {
    Bound(BoundListener),
    Serving(Serving),
}

#[derive(Debug)]
struct Serving {
    stop: watch::Sender<bool>,
    /// Disconnected once the accept task has dropped its socket, so
    /// `listener-remove` means closed by the time it returns.
    closed: std::sync::mpsc::Receiver<()>,
    task: JoinHandle<()>,
}

impl Serving {
    /// Blocks the calling thread until its socket is closed. Only safe off the
    /// threads of the runtime: the control-plane handlers run on the blocking
    /// pool ([`crate::control::listener`]).
    fn close_blocking(self) {
        let _ = self.stop.send(true);
        // `Err` is the expected outcome: nothing is ever sent, and the channel
        // disconnects when the accept task drops its end.
        let _ = self.closed.recv();
        drop(self.task);
    }
}

impl Live {
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
            // Dropped only after `accept` has returned and with it dropped the
            // socket: a thread waiting on `closed` waits for exactly that.
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

    #[must_use]
    pub fn endpoints(&self) -> Vec<Endpoint> {
        self.lock()
            .iter()
            .map(|listener| listener.endpoint.clone())
            .collect()
    }

    #[must_use]
    pub fn info(&self) -> Vec<ListenerInfo> {
        self.lock()
            .iter()
            .map(|listener| listener.endpoint.info())
            .collect()
    }

    /// Zero listeners is a legal state: such a server serves only its control
    /// socket.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Compares source forms, because what the operator asked for identifies the
    /// request before anything is bound, and a duplicate is answered as a
    /// duplicate instead of as an `EADDRINUSE` against the socket of the server
    /// itself. It returns where the existing one bound, which is the endpoint the
    /// operator can act on.
    #[must_use]
    pub fn duplicate(&self, config: &Listener) -> Option<ListenerInfo> {
        self.lock()
            .iter()
            .find(|listener| &listener.config == config)
            .map(|listener| listener.endpoint.info())
    }

    /// An operator names a listener by where it bound, and the state file
    /// contains where it was asked to bind.
    #[must_use]
    pub fn configured(&self, endpoint: &str) -> Option<Listener> {
        self.lock()
            .iter()
            .find(|listener| listener.endpoint.render() == endpoint)
            .map(|listener| listener.config.clone())
    }

    /// `None` before serving starts, which `listener-add` reports as nothing to
    /// add a listener to yet.
    #[must_use]
    pub fn runtime(&self) -> Option<Handle> {
        self.runtime.get().cloned()
    }

    /// The socket was bound before the persist and starts accepting only after
    /// it, so a listener a restart would not serve never served.
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

    /// When it returns, no further connection can arrive at that endpoint, while
    /// every session already accepted on it goes on serving. It blocks the
    /// calling thread, so it belongs on the blocking pool.
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
            // Never served: closing it is dropping it, which also unlinks a unix
            // path this server created.
            State::Bound(bound) => drop(bound),
            State::Serving(serving) => serving.close_blocking(),
        }
        true
    }

    /// Joining instead of detaching makes clean shutdown structural: when this
    /// returns, every socket the server bound is closed and every unix path it
    /// created is unlinked.
    pub async fn serve(self: Arc<Self>, shutdown: impl Future<Output = ()> + Send) {
        let runtime = Handle::current();
        // Ignored if serving somehow started twice: the first runtime wins.
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

    async fn stop_all(&self) {
        let listeners = std::mem::take(&mut *self.lock());
        let mut accepting = Vec::new();
        for listener in listeners {
            match listener.state {
                State::Bound(bound) => drop(bound),
                State::Serving(serving) => {
                    let _ = serving.stop.send(true);
                    // The task is awaited instead of the closed channel: this
                    // path runs on the runtime, where blocking would stop the
                    // very loops it waits for.
                    accepting.push(serving.task);
                }
            }
        }
        for task in accepting {
            let _ = task.await;
        }
    }

    /// Ignores poisoning: a panicking holder leaves the list well-formed.
    fn lock(&self) -> MutexGuard<'_, Vec<Live>> {
        self.live
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ListenerError {
    #[error("cannot bind tcp data listener {address}")]
    Tcp {
        address: SocketAddr,
        #[source]
        source: io::Error,
    },
    /// The same bind contract as the control socket.
    #[error(transparent)]
    Unix(#[from] BindError),
    #[error("cannot bind vsock data listener cid {cid} port {port}")]
    Vsock {
        cid: u32,
        port: VsockPort,
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use voidport_test_host::Scratch;

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
            (
                Transport::VhostUser,
                "vhost-user",
                Listener::VhostUser {
                    path: PathBuf::from("/run/voidport/vhost-user.sock"),
                },
            ),
        ];
        for (transport, name, configured) in cases {
            assert_eq!(transport.as_str(), name);
            assert_eq!(transport.to_string(), name);
            assert_eq!(configured.transport(), name);
            assert_eq!(Peer::new(transport, "somewhere").transport, transport);
        }
    }

    #[test]
    fn a_vsock_listener_binds_and_reports_its_endpoint() {
        if !voidport_test_host::vsock::preflight() {
            return;
        }
        let bound = BoundListener::bind_all(&[Listener::vsock(0)]).expect("the wildcard cid binds");

        let endpoint = bound[0].endpoint();
        let Endpoint::Vsock { cid, port } = endpoint else {
            panic!("a vsock listener reports a vsock endpoint");
        };
        assert_eq!(cid, ANY_CID);
        assert_ne!(
            VsockPort::from(port),
            VsockPort::Any,
            "the port that was bound is reported"
        );
        assert_eq!(endpoint.transport(), Transport::Vsock);
        assert_eq!(endpoint.render(), format!("any:{port}"));

        let taken = BoundListener::bind(&Listener::vsock(port)).expect_err("the port is in use");
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
            // A socket in a directory that does not exist: the second bind fails,
            // and the first must not survive it.
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
        let Endpoint::Tcp(address) = tcp else {
            panic!("a tcp listener reports a tcp endpoint");
        };
        assert_ne!(address.port(), 0, "the ephemeral port is resolved");

        let unix = bound[1].endpoint();
        assert_eq!(unix, Endpoint::Unix(path.clone()));
        assert_eq!(unix.transport(), Transport::Unix);
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
