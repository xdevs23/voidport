//! A server that can be killed and brought back, as a real process.
//!
//! The resilience suites need something the in-process runner cannot give them:
//! a server that **dies without warning**. A `SIGKILL` on a child process is
//! the honest version of "the server breaks away" — no clean shutdown, no
//! unlinked socket, no chance to answer anything in flight — and bringing the
//! same state file back up on the same socket is the honest version of "the
//! server comes back".
//!
//! The listener's address has to **survive the restart**, or a client that
//! reconnected to it would be proving nothing about the mount it was serving. A
//! unix socket qualifies because its address is a path, and a vsock listener
//! because its port is written in the state file; a tcp listener bound to port
//! 0 would come back somewhere else, which is why neither is that. Unix is the
//! default and vsock is what the vsock suite asks for — see [`DataAddress`].
//!
//! The servers are started by a [`Launcher`], not by this process — see
//! that type for the kernel behaviour that forces it.

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::Shutdown;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use rustix::process::{Pid, Signal};
use voidport::client::{Client, Concurrency, MountState, Resilience};
use voidport::mount::{Mount, MountOptions};
use voidport::url::{Endpoint, MountUrl};

use super::{Guest, TempDir, daemon_binary};
// Re-exported so the poll-until-true the suites use has one name and one
// definition, reachable beside the servers they poll about.
pub use super::eventually;

/// How long a server is given to come up, or to go down.
pub const PATIENCE: Duration = Duration::from_secs(30);

/// Where a restartable server's data plane is reached.
///
/// One address, in the three forms every suite needs it in: the listener block
/// of a state file, the endpoint a client dials, and the URL a mount is written
/// as. They are together here so a suite cannot write a state file naming one
/// address and then dial another.
#[derive(Clone, Debug)]
pub enum DataAddress {
    /// A unix socket at a path.
    Unix(PathBuf),
    /// A vsock port, served on the wildcard cid and dialled on the loopback
    /// cid — the same machine talking to itself, which is what makes vsock
    /// testable without a VM.
    Vsock {
        /// The port, which the state file names and a restart therefore keeps.
        port: u32,
    },
}

impl DataAddress {
    /// The `[[server.listeners]]` block that serves this address.
    #[must_use]
    pub fn listener_block(&self) -> String {
        match self {
            Self::Unix(path) => format!(
                "[[server.listeners]]\ntransport = \"unix\"\npath = \"{}\"\n",
                path.display()
            ),
            Self::Vsock { port } => {
                format!("[[server.listeners]]\ntransport = \"vsock\"\nport = {port}\n")
            }
        }
    }

    /// The endpoint a client dials to reach it.
    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        match self {
            Self::Unix(path) => Endpoint::Unix { path: path.clone() },
            Self::Vsock { port } => Endpoint::Vsock {
                cid: LOOPBACK_CID,
                port: u16::try_from(*port).expect("a port a mount URL can name"),
            },
        }
    }

    /// The mount URL of a namespace subpath on it.
    #[must_use]
    pub fn url(&self, namespace: &str, subpath: &str) -> String {
        match self {
            Self::Unix(path) => {
                let socket = percent_encoding::percent_encode(
                    path.as_os_str().as_bytes(),
                    percent_encoding::NON_ALPHANUMERIC,
                );
                format!("voidport+unix://{socket}/@{namespace}{subpath}")
            }
            Self::Vsock { port } => {
                format!("voidport+vsock://{LOOPBACK_CID}:{port}/@{namespace}{subpath}")
            }
        }
    }

    /// Whether a server is accepting connections here right now.
    #[must_use]
    pub fn accepts(&self) -> bool {
        match self {
            Self::Unix(path) => accepts(path),
            Self::Vsock { port } => {
                match vsock::VsockStream::connect_with_cid_port(LOOPBACK_CID, *port) {
                    Ok(stream) => {
                        let _ = stream.shutdown(Shutdown::Both);
                        true
                    }
                    Err(_) => false,
                }
            }
        }
    }
}

/// The cid a machine reaches itself at, which is what the kernel's loopback
/// vsock transport provides. A guest would name its host's cid instead; the
/// suite has no guest, and a loopback connection exercises the same transport.
pub const LOOPBACK_CID: u32 = vsock::VMADDR_CID_LOCAL;

/// A `voidportd` process serving one state file over one data address.
#[derive(Debug)]
pub struct Restartable {
    state: PathBuf,
    control: PathBuf,
    data: DataAddress,
    /// Starts every server this handle runs, from outside this process.
    launcher: Launcher,
    /// The running server's pid; `None` while the server is down.
    running: Option<Pid>,
}

impl Restartable {
    /// Writes `state` into the directory and starts a server on it.
    ///
    /// The state text is written verbatim, so a test that means to change the
    /// configuration across a restart writes a different one and calls
    /// [`Self::rewrite_state`].
    ///
    /// The launcher is created here, which is *before* any test has a
    /// mountpoint: that ordering is the whole point of it.
    #[must_use]
    pub fn start(directory: &TempDir, state: &str) -> Self {
        Self::start_at(
            directory,
            state,
            DataAddress::Unix(directory.join("data.sock")),
        )
    }

    /// The same, for a state file that serves its data plane somewhere else.
    ///
    /// The address is passed, not derived, because the state text and the
    /// address must agree, and only the caller that wrote the text knows.
    #[must_use]
    pub fn start_at(directory: &TempDir, state: &str, data: DataAddress) -> Self {
        let state_file = directory.join("state.toml");
        let control = directory.join("control.sock");
        std::fs::write(&state_file, state).expect("a writable state file");
        let launcher = Launcher::start(&daemon_binary(), &state_file, &control);
        let mut server = Self {
            state: state_file,
            control,
            data,
            launcher,
            running: None,
        };
        server.start_again();
        server
    }

    /// The state file the server serves.
    #[must_use]
    pub fn state_file(&self) -> &Path {
        &self.state
    }

    /// The control socket.
    #[must_use]
    pub fn control_socket(&self) -> &Path {
        &self.control
    }

    /// The data address guests connect to — the same one across restarts.
    #[must_use]
    pub fn data(&self) -> &DataAddress {
        &self.data
    }

    /// The data socket guests connect to, for the suites that put a relay in
    /// front of it.
    ///
    /// # Panics
    ///
    /// If this server's data plane is not a unix socket: only a path can have a
    /// relay bound beside it.
    #[must_use]
    pub fn data_socket(&self) -> &Path {
        match &self.data {
            DataAddress::Unix(path) => path,
            DataAddress::Vsock { .. } => panic!("this server's data plane is a vsock port"),
        }
    }

    /// The endpoint a client dials.
    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        self.data.endpoint()
    }

    /// The mount URL of a namespace subpath.
    #[must_use]
    pub fn url(&self, namespace: &str, subpath: &str) -> String {
        self.data.url(namespace, subpath)
    }

    /// Replaces the state file, for a restart that serves a changed
    /// configuration.
    pub fn rewrite_state(&self, state: &str) {
        std::fs::write(&self.state, state).expect("a writable state file");
    }

    /// Whether a server is running under this handle.
    #[must_use]
    pub fn is_up(&self) -> bool {
        self.running.is_some()
    }

    /// Kills the server outright.
    ///
    /// `SIGKILL`: nothing is flushed, the socket file is left behind, and every
    /// session dies where it stood. That is the case the resilience contract is
    /// about. The launcher reaps the corpse.
    pub fn kill(&mut self) {
        self.signal(Signal::KILL);
    }

    /// Asks the server to shut down cleanly and waits for it.
    pub fn terminate(&mut self) {
        self.signal(Signal::TERM);
    }

    /// Signals the running server and waits until it is no longer serving.
    fn signal(&mut self, signal: Signal) {
        let Some(pid) = self.running.take() else {
            return;
        };
        let _ = rustix::process::kill_process(pid, signal);
        // A killed server leaves its socket file behind, so the file is
        // refusing connections, not absent; a terminated one unlinks it.
        // Either way this is what "the server is down" means, and waiting for
        // it is what stops a client from connecting to a server already gone.
        eventually(PATIENCE, || !self.data.accepts());
    }

    /// Starts a server on the current state file and waits until it serves.
    ///
    /// # Panics
    ///
    /// If the server does not accept a data connection within [`PATIENCE`]:
    /// there is nothing a resilience test can assert against a server that
    /// never came up.
    pub fn start_again(&mut self) {
        assert!(self.running.is_none(), "a server is already running");
        self.running = Some(self.launcher.launch());
        assert!(
            eventually(PATIENCE, || self.data.accepts()),
            "the server never accepted a connection on {:?}",
            self.data
        );
    }

    /// Kills the server and brings it straight back — the whole restart, as one
    /// step, for the tests whose subject is what the *client* did meanwhile.
    pub fn restart(&mut self) {
        self.kill();
        self.start_again();
    }
}

impl Drop for Restartable {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Starts server processes, from outside this process's descriptor table.
///
/// A restart cannot be a plain `Command::spawn` from the test process, and the
/// reason is the kernel's, not the harness's. The mount-level suites hold a
/// descriptor on a voidport mountpoint across the restart — that descriptor is
/// the criterion's own subject — and `execve` closes every inherited
/// close-on-exec descriptor in the forked child. Closing one on a FUSE mount
/// issues a synchronous `FLUSH`, and a mount whose server has just been killed
/// stalls it for the whole reconnect window. The child therefore sits inside
/// `exec` until the window it was supposed to land inside has already closed.
/// Measured on this VM with one descriptor held and the server killed:
/// `/bin/true` execs in 0.4 ms while the mount is serving, and in 4.0005 s
/// against a 4 s window while it is stalling.
///
/// The launcher is started **before** any mountpoint exists, so its descriptor
/// table holds nothing belonging to a mount and its `exec` is immediate — 0.6 ms
/// measured under exactly those conditions. Every server every suite starts goes
/// through it, so there is one way to start a server, not a fast one and
/// a correct one.
#[derive(Debug)]
struct Launcher {
    shell: Child,
    /// One line written here starts one server.
    commands: ChildStdin,
    /// One line read back is the pid it started.
    started: BufReader<ChildStdout>,
}

/// What the launcher runs: a server per line read, its pid reported back, and
/// the corpse reaped before the next line is taken.
///
/// The daemon binary and its two paths arrive as `$0`, `$1` and `$2` — as
/// arguments, never interpolated into the text — so no path is ever quoted into
/// a script.
const LAUNCH: &str = "while IFS= read -r _command; do \
     \"$0\" --state \"$1\" --control-socket \"$2\" </dev/null >/dev/null 2>&1 & \
     echo \"$!\"; \
     wait \"$!\"; \
     done";

impl Launcher {
    /// Starts a launcher for one server's command line.
    fn start(daemon: &Path, state: &Path, control: &Path) -> Self {
        let mut shell = Command::new("/bin/sh")
            .arg("-c")
            .arg(LAUNCH)
            .arg(daemon)
            .arg(state)
            .arg(control)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("a shell to start servers from");
        let commands = shell.stdin.take().expect("a piped stdin");
        let started = BufReader::new(shell.stdout.take().expect("a piped stdout"));
        Self {
            shell,
            commands,
            started,
        }
    }

    /// Starts one server and returns its pid.
    ///
    /// # Panics
    ///
    /// If the launcher cannot be reached or does not answer with a pid: a suite
    /// that cannot start a server has nothing left to assert.
    fn launch(&mut self) -> Pid {
        writeln!(self.commands, "start").expect("the launcher takes commands");
        self.commands.flush().expect("the launcher takes commands");
        let mut reported = String::new();
        self.started
            .read_line(&mut reported)
            .expect("the launcher reports the pid it started");
        let raw = reported
            .trim()
            .parse()
            .unwrap_or_else(|error| panic!("the launcher answered {reported:?}: {error}"));
        Pid::from_raw(raw).expect("a pid the launcher started")
    }
}

impl Drop for Launcher {
    /// The launcher never outlives the handle that made it. [`Restartable`]'s
    /// own drop has already killed the server, so nothing is orphaned here.
    fn drop(&mut self) {
        let _ = self.shell.kill();
        let _ = self.shell.wait();
    }
}

/// Whether a unix socket path currently accepts connections.
///
/// A path left behind by a killed server is still there and still a socket; it
/// simply refuses. That difference is exactly what "the server is up" means
/// here.
#[must_use]
pub fn accepts(path: &Path) -> bool {
    match UnixStream::connect(path) {
        Ok(stream) => {
            let _ = stream.shutdown(Shutdown::Both);
            true
        }
        Err(_) => false,
    }
}

/// A state file serving the `work` namespace on `socket`, with `rules` under
/// it.
///
/// Every configuration these suites restart a server onto differs only in that
/// block, so it is the only thing written out per case: a reader comparing two
/// of them sees the change and nothing else. An empty `rules` is the namespace
/// with no grafts at all.
///
/// Written out here instead of reusing the end-to-end fixture's because these
/// suites need a *fixed* unix listener path and a tree they may churn, and the
/// e2e fixture's assertions are written against its own exact listings.
#[must_use]
fn state_file_serving(socket: &Path, rules: &str) -> String {
    format!(
        r#"
[server]

[[server.listeners]]
transport = "unix"
path = "{socket}"

[[namespaces]]
name = "work"
{rules}"#,
        socket = socket.display(),
    )
}

/// The state file the resilience suites serve: one host tree, grafted
/// read-write, plus a read-only view of the same tree.
#[must_use]
pub fn state_file(tree: &Path, socket: &Path) -> String {
    state_file_serving(
        socket,
        &format!(
            r#"
[[namespaces.rules]]
path = "/tree"
mode = "rw"
target = "{tree}"

[[namespaces.rules]]
path = "/readonly"
mode = "ro"
target = "{tree}"
"#,
            tree = tree.display(),
        ),
    )
}

/// The same, with the read-write graft removed: what an operator's "cut them
/// off" looks like from the other side of a restart.
#[must_use]
pub fn state_file_without_the_tree(socket: &Path) -> String {
    state_file_serving(socket, "")
}

/// The same, with the namespace itself gone: the handshake has nothing to
/// resolve, so the mount stays degraded with its probe running.
#[must_use]
pub fn state_file_without_the_namespace(socket: &Path) -> String {
    format!(
        r#"
[server]

[[server.listeners]]
transport = "unix"
path = "{socket}"
"#,
        socket = socket.display(),
    )
}

/// The same, with everything below the graft hidden by a wildcard.
///
/// A name the namespace hides cannot be created — the guest would not see what
/// it made — which the server answers `EACCES`.
#[must_use]
pub fn state_file_hiding_children(tree: &Path, socket: &Path) -> String {
    state_file_serving(
        socket,
        &format!(
            r#"
[[namespaces.rules]]
path = "/tree"
mode = "rw"
target = "{tree}"

[[namespaces.rules]]
path = "/tree/*"
mode = "hidden"
"#,
            tree = tree.display(),
        ),
    )
}

/// The same, with the tree grafted read-only instead of read-write.
#[must_use]
pub fn state_file_read_only(tree: &Path, socket: &Path) -> String {
    state_file_serving(
        socket,
        &format!(
            r#"
[[namespaces.rules]]
path = "/tree"
mode = "ro"
target = "{tree}"
"#,
            tree = tree.display(),
        ),
    )
}

/// The same graft, re-targeted at a different host directory.
///
/// The arm of the configuration-change criterion that keeps the mount path
/// intact and moves what is *behind* it: `/tree` still resolves, and resolves
/// to somewhere else. A stale node id from the old session names nothing in the
/// new one, so what a fresh walk finds is the new target's contents.
#[must_use]
pub fn state_file_retargeted(elsewhere: &Path, socket: &Path) -> String {
    state_file_serving(
        socket,
        &format!(
            r#"
[[namespaces.rules]]
path = "/tree"
mode = "rw"
target = "{elsewhere}"
"#,
            elsewhere = elsewhere.display(),
        ),
    )
}

/// The contents of the fixture's `data.bin`, which is the file the resilience
/// suites read and write across a gap.
pub const CONTENTS: &[u8] = b"0123456789";

/// A host tree, and the restartable server that serves it.
///
/// One fixture for all four resilience suites. They asked the same three
/// questions of it — a tree to churn, a socket whose address survives a
/// restart, and a client or a mount pointed at it — and had four copies of the
/// answer; this is the answer, once. The files are a superset of what any one
/// suite needs, because a fixture that varies per suite is the duplication
/// coming back: `alpha` and `beta` differ in *length* so that an id which
/// aliased one for the other would show up as data, not as a number.
pub struct Ground {
    /// The scratch directory everything below lives in. Kept alive by being
    /// held; suites also hang mountpoints and second trees off it.
    pub directory: TempDir,
    /// The grafted host tree, for host-side assertions.
    pub tree: PathBuf,
    /// The server, to kill and bring back.
    pub server: Restartable,
}

impl Ground {
    /// Builds the tree, writes the state file, and starts the server.
    #[must_use]
    pub fn start(label: &str) -> Self {
        let directory = TempDir::new(label);
        let tree = directory.directory("tree");
        std::fs::write(tree.join("data.bin"), CONTENTS).expect("a writable tree");
        std::fs::write(tree.join("alpha"), b"alpha").expect("a writable tree");
        std::fs::write(tree.join("beta"), b"beta-beta").expect("a writable tree");
        let socket = directory.join("data.sock");
        let server = Restartable::start(&directory, &state_file(&tree, &socket));
        Self {
            directory,
            tree,
            server,
        }
    }

    /// The data socket, which keeps its address across restarts.
    #[must_use]
    pub fn socket(&self) -> PathBuf {
        self.server.data_socket().to_path_buf()
    }

    /// Connects a bare client to the server, with no FUSE mount in the way.
    #[must_use]
    pub fn connect(&self, runtime: &tokio::runtime::Runtime, stall: Duration) -> Arc<Client> {
        self.connect_to(runtime, &self.server.endpoint(), stall)
    }

    /// The same, through an endpoint of the caller's own — a relay in front of
    /// the server, for the suites whose subject is what crosses the wire.
    #[must_use]
    pub fn connect_to(
        &self,
        runtime: &tokio::runtime::Runtime,
        endpoint: &Endpoint,
        stall: Duration,
    ) -> Arc<Client> {
        runtime
            .block_on(Client::mount_with(
                endpoint,
                "work",
                b"",
                Resilience { stall },
                Concurrency::default(),
            ))
            .expect("the mount is established")
    }

    /// Mounts the namespace on a fresh mountpoint with the given stall window.
    #[must_use]
    pub fn mount(&self, label: &str, stall: Duration) -> Guest {
        self.mount_with(
            label,
            &MountOptions {
                reconnect_stall: stall,
                ..MountOptions::default()
            },
        )
    }

    /// The same, for a suite that needs more of the mount's options than the
    /// stall window — the data-caching mode and the readahead pool among them.
    #[must_use]
    pub fn mount_with(&self, label: &str, options: &MountOptions) -> Guest {
        let mountpoint = self.directory.directory(&format!("mnt-{label}"));
        let url = self.server.url("work", "");
        let parsed = MountUrl::parse(&url).unwrap_or_else(|error| panic!("{url}: {error}"));
        let mount = Mount::new(&parsed, &mountpoint, options)
            .unwrap_or_else(|error| panic!("mounting {url} failed: {error}"));
        Guest::adopt(mount, mountpoint)
    }
}

/// Waits until a client is serving again, so an assertion about *what* the
/// server answers is never accidentally an assertion about *when* it came back.
pub fn settle(client: &Client) {
    assert!(
        eventually(PATIENCE, || client.state() == MountState::Connected),
        "the client never reconnected (it is {:?})",
        client.state()
    );
}

/// A blocking runtime for the client-level suites.
///
/// The resilience tests are written as straight-line stories — connect, kill,
/// assert — so they drive the async client from one thread instead of
/// scattering `block_on` through every step.
#[must_use]
pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .expect("a tokio runtime")
}
