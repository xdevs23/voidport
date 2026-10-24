use std::io::{BufRead as _, BufReader, Write as _};
use std::net::Shutdown;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout};
use std::sync::Arc;
use std::time::Duration;

use rustix::process::{Pid, Signal};
use voidport::client::{Client, MountState, Resilience};
use voidport::mount::{Mount, MountOptions};
use voidport::url::{Endpoint, MountUrl};
use voidport_control::{Reply, Request};
use voidport_spawn::{Program, Stream};
use voidport_test_support::{
    ControlClient, ReadinessSocket, Startup, bound_vsock_port, readable, until,
};

pub use crate::eventually;
use crate::{Guest, TempDir, daemon_binary};

pub const PATIENCE: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub enum DataAddress {
    Unix(PathBuf),
    /// Served on the wildcard cid and dialled on the loopback cid, so vsock needs no VM.
    Vsock {
        /// Recorded in the state file, so a restart uses it again.
        port: u32,
    },
}

impl DataAddress {
    #[must_use]
    pub fn listener_block(&self) -> String {
        match self {
            Self::Unix(path) => format!(
                "[[server.listeners]]\ntransport = \"unix\"\npath = \"{}\"\n",
                path.display()
            ),
            Self::Vsock { port } => vsock_listener_block(*port),
        }
    }

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

    #[must_use]
    pub fn accepts(&self) -> bool {
        match self {
            Self::Unix(path) => accepts(path),
            Self::Vsock { port } => {
                match vsock::VsockStream::connect_with_cid_port(LOOPBACK_CID, *port) {
                    Ok(stream) => {
                        let _probe_needs_no_clean_close = stream.shutdown(Shutdown::Both);
                        true
                    }
                    Err(_) => false,
                }
            }
        }
    }
}

/// Port 0 asks the server for a free port.
fn vsock_listener_block(port: u32) -> String {
    format!("[[server.listeners]]\ntransport = \"vsock\"\nport = {port}\n")
}

fn reported_vsock_port(control: &Path) -> u32 {
    let Reply::ServerInfo { listeners, .. } = ControlClient::connect(control)
        .expect("the control socket accepts connections")
        .expect_ok(&Request::ServerInfo {})
    else {
        panic!("server-info returns server info");
    };
    bound_vsock_port(&listeners)
}

/// A guest would name the cid of its host instead. A loopback connection exercises the same transport.
pub const LOOPBACK_CID: u32 = vsock::VMADDR_CID_LOCAL;

#[derive(Debug)]
pub struct Restartable {
    state: PathBuf,
    control: PathBuf,
    data: DataAddress,
    launcher: Launcher,
    running: Option<Pid>,
}

impl Restartable {
    #[must_use]
    pub fn start(directory: &TempDir, state: &str) -> Self {
        Self::start_at(
            directory,
            state,
            DataAddress::Unix(directory.join("data.sock")),
        )
    }

    /// Only the caller that wrote the state text knows the address.
    #[must_use]
    pub fn start_at(directory: &TempDir, state: &str, data: DataAddress) -> Self {
        Self::start_with(directory, state, |_| data)
    }

    /// `state` builds the state text around a `[[server.listeners]]` block. Before
    /// this returns, the state file contains the port reported by the server. A
    /// change made through the control socket writes port 0 back, so a test that
    /// restarts after one calls [`Self::rewrite_state`] again.
    #[must_use]
    pub fn start_on_any_vsock_port(directory: &TempDir, state: impl Fn(&str) -> String) -> Self {
        let server = Self::start_with(directory, &state(&vsock_listener_block(0)), |control| {
            DataAddress::Vsock {
                port: reported_vsock_port(control),
            }
        });
        server.rewrite_state(&state(&server.data.listener_block()));
        server
    }

    /// `address` is called with the control socket once the server has reported
    /// readiness, so a server that chooses its port can be asked for it.
    fn start_with(
        directory: &TempDir,
        state: &str,
        address: impl FnOnce(&Path) -> DataAddress,
    ) -> Self {
        let state_file = directory.join("state.toml");
        let control = directory.join("control.sock");
        std::fs::write(&state_file, state).expect("a writable state file");
        let readiness = ReadinessSocket::bind(directory.join("notify.sock"));
        let mut launcher = Launcher::start(&daemon_binary(), &state_file, &control, readiness);
        let running = launcher.launch();
        let data = address(&control);
        let server = Self {
            state: state_file,
            control,
            data,
            launcher,
            running: Some(running),
        };
        assert!(
            server.data.accepts(),
            "the acknowledged listener accepts connections"
        );
        server
    }

    #[must_use]
    pub fn state_file(&self) -> &Path {
        &self.state
    }

    #[must_use]
    pub fn control_socket(&self) -> &Path {
        &self.control
    }

    #[must_use]
    pub fn data(&self) -> &DataAddress {
        &self.data
    }

    #[must_use]
    pub fn data_socket(&self) -> &Path {
        match &self.data {
            DataAddress::Unix(path) => path,
            DataAddress::Vsock { .. } => panic!("this server's data plane is a vsock port"),
        }
    }

    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        self.data.endpoint()
    }

    #[must_use]
    pub fn url(&self, namespace: &str, subpath: &str) -> String {
        self.data.url(namespace, subpath)
    }

    pub fn rewrite_state(&self, state: &str) {
        std::fs::write(&self.state, state).expect("a writable state file");
    }

    #[must_use]
    pub fn is_up(&self) -> bool {
        self.running.is_some()
    }

    #[must_use]
    pub fn pid(&self) -> Option<Pid> {
        self.running
    }

    pub fn until(&self, condition: impl FnMut() -> bool) {
        until(
            || self.running.is_none() || self.launcher.server_exited(),
            condition,
        );
    }

    /// The socket file is left behind.
    pub fn kill(&mut self) {
        self.signal(Signal::KILL);
    }

    pub fn terminate(&mut self) {
        self.signal(Signal::TERM);
    }

    fn signal(&mut self, signal: Signal) {
        let Some(pid) = self.running.take() else {
            return;
        };
        let _server_may_have_exited = rustix::process::kill_process(pid, signal);
        self.launcher.exited();
    }

    pub fn start_again(&mut self) {
        assert!(self.running.is_none(), "a server is already running");
        self.running = Some(self.launcher.launch());
        assert!(
            self.data.accepts(),
            "the acknowledged listener accepts connections"
        );
    }

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

/// A server is never started with `Command::spawn` from the test process. At
/// `execve`, the forked child closes the descriptors it inherited on a mountpoint,
/// and closing one on a FUSE mount whose server was just killed sends a `FLUSH`
/// that waits for the whole reconnect window. The shell started through
/// [`voidport_spawn`] has no descriptor of a mount of this process.
#[derive(Debug)]
struct Launcher {
    shell: Child,
    /// One line written here starts one server.
    commands: ChildStdin,
    /// One line read back is the pid it started, and the next one its exit.
    started: BufReader<ChildStdout>,
    readiness: ReadinessSocket,
}

/// The input ends once this process has ended, however it ends. The shell then
/// kills its process group, which contains every server it started.
///
/// The daemon binary and the paths arrive as `$0`, `$1` and `$2`, so no path is
/// interpolated into the script.
const LAUNCH: &str = "while IFS= read -r _command; do \
     { \"$0\" --state \"$1\" --control-socket \"$2\" </dev/null & \
     printf '{\"pid\":%s}\\n' \"$!\"; \
     wait \"$!\"; \
     printf '{\"exit\":%s}\\n' \"$?\"; } & \
     done; \
     kill -s KILL 0";

impl Launcher {
    fn start(daemon: &Path, state: &Path, control: &Path, readiness: ReadinessSocket) -> Self {
        let mut shell = Program::new("/bin/sh")
            .env("NOTIFY_SOCKET", readiness.path())
            .arg("-c")
            .arg(LAUNCH)
            .arg(daemon)
            .arg(state)
            .arg(control)
            .stdin(Stream::Piped)
            .stdout(Stream::Piped)
            .in_new_process_group()
            .spawn()
            .expect("a shell to start servers from");
        let commands = shell.stdin.take().expect("a piped stdin");
        let started = BufReader::new(shell.stdout.take().expect("a piped stdout"));
        Self {
            shell,
            commands,
            started,
            readiness,
        }
    }

    fn launch(&mut self) -> Pid {
        writeln!(self.commands, "start").expect("the launcher takes commands");
        self.commands.flush().expect("the launcher takes commands");
        let event = self.event();
        let raw = event
            .get("pid")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or_else(|| panic!("expected a started process, received {event}"));
        let pid = Pid::from_raw(i32::try_from(raw).expect("a process id")).expect("a valid pid");
        // The launcher writes nothing more until the server exits, so a line
        // already read into the buffer, or a pipe that becomes readable, is the
        // exit.
        if !self.started.buffer().is_empty()
            || self.readiness.wait(self.started.get_ref()) == Startup::Exited
        {
            let event = self.event();
            panic!("the server exited before it reported readiness: {event}");
        }
        pid
    }

    /// The launcher writes nothing after it reports the exit of the server.
    fn server_exited(&self) -> bool {
        !self.started.buffer().is_empty() || readable(self.started.get_ref())
    }

    fn event(&mut self) -> serde_json::Value {
        let mut line = String::new();
        assert_ne!(
            self.started.read_line(&mut line).expect("launcher output"),
            0,
            "the launcher exited before its expected acknowledgement"
        );
        serde_json::from_str(&line).expect("a structured launcher event")
    }

    fn exited(&mut self) {
        let event = self.event();
        assert!(
            event
                .get("exit")
                .and_then(serde_json::Value::as_u64)
                .is_some(),
            "expected a reaped process, received {event}"
        );
    }
}

impl Drop for Launcher {
    /// [`Restartable`] has already killed the server, so nothing is orphaned here.
    fn drop(&mut self) {
        let ended = self.shell.kill().and_then(|()| self.shell.wait());
        if let Err(error) = ended {
            eprintln!("the launcher shell is not ended: {error}");
        }
    }
}

/// A killed server leaves its socket file behind, and connecting to it fails.
#[must_use]
pub fn accepts(path: &Path) -> bool {
    match UnixStream::connect(path) {
        Ok(stream) => {
            let _probe_needs_no_clean_close = stream.shutdown(Shutdown::Both);
            true
        }
        Err(_) => false,
    }
}

/// The end-to-end fixture is not reused here, because these suites need a fixed
/// unix listener path and a tree they may change.
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

#[must_use]
pub fn state_file_without_the_tree(socket: &Path) -> String {
    state_file_serving(socket, "")
}

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

/// A name hidden by the namespace cannot be created, and the server returns
/// `EACCES`.
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

/// A node id from the old session matches no node in the new one.
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

pub const CONTENTS: &[u8] = b"0123456789";

/// `alpha` and `beta` differ in length, so an id that points at the wrong one of
/// the two shows up in the data read.
pub struct Ground {
    pub directory: TempDir,
    pub tree: PathBuf,
    pub server: Restartable,
}

impl Ground {
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

    #[must_use]
    pub fn socket(&self) -> PathBuf {
        self.server.data_socket().to_path_buf()
    }

    #[must_use]
    pub fn connect(&self, runtime: &tokio::runtime::Runtime, stall: Duration) -> Arc<Client> {
        self.connect_to(runtime, &self.server.endpoint(), stall)
    }

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
            ))
            .expect("the mount is established")
    }

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

    #[must_use]
    pub fn mount_with(&self, label: &str, options: &MountOptions) -> Guest {
        self.mount_with_url(label, &self.server.url("work", ""), options)
    }

    #[must_use]
    pub fn mount_with_url(&self, label: &str, url: &str, options: &MountOptions) -> Guest {
        let mountpoint = self.directory.directory(&format!("mnt-{label}"));
        let parsed = MountUrl::parse(url).unwrap_or_else(|error| panic!("{url}: {error}"));
        let mount = Mount::new(&parsed, &mountpoint, options, &crate::guardian())
            .unwrap_or_else(|error| panic!("mounting {url} failed: {error:?}"));
        Guest::adopt(mount, mountpoint)
    }
}

pub fn state_is(client: &Client, ready: impl Fn(MountState) -> bool) {
    wait_until(client, |client| ready(client.state()));
}

/// Runs `ending`, which ends the session the client is connected over, and waits
/// until the client is connected over a newer one. A client that has not yet
/// noticed the loss still reports `Connected` over the ended session, so waiting
/// for that state right after the loss can return before the session is replaced.
pub fn reconnected_after(client: &Client, ending: impl FnOnce()) {
    let ended = client
        .connected_generation()
        .expect("the client was connected when the session was ended");
    ending();
    wait_until(client, |client| {
        client
            .connected_generation()
            .is_some_and(|generation| generation > ended)
    });
}

fn wait_until(client: &Client, reached: impl Fn(&Client) -> bool) {
    let mut changes = client.changes();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a state waiter")
        .block_on(async {
            loop {
                if reached(client) {
                    return;
                }
                assert_ne!(
                    client.state(),
                    MountState::Closed,
                    "the client closed before the awaited state"
                );
                changes
                    .changed()
                    .await
                    .expect("the client state publisher remains live");
            }
        });
}

#[must_use]
pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .expect("a tokio runtime")
}
