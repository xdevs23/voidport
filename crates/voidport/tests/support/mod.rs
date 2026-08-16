//! Scaffolding for the end-to-end suite.
//!
//! Everything here exists to make one test drive the *whole* product: a real
//! `voidportd` (the library, started exactly as its binary starts it, on its own
//! thread), real listeners, the real FUSE client mounting through the real
//! kernel, and the real `voidport-ctl` binary for operator traffic. Nothing is
//! mocked — the properties under test only exist against a real kernel and a
//! real filesystem.
//!
//! The suite needs privileges: mounting and unmounting a FUSE filesystem, and
//! the host-side ownership assertions, are root's business. The development VM
//! runs it as root. The one thing it is allowed to give up on is a machine
//! where FUSE itself is unusable, which [`preflight`] decides once.
#![allow(dead_code, reason = "each test file uses part of this")]

pub mod daemon;
pub mod mapping;

use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use voidport::mount::{Mount, MountOptions};
use voidport::url::MountUrl;
use voidport_control::{Reply, Request, Response, SessionSummary};
// The server runner, the control client and the descriptor probe are the same
// machinery this crate's server uses in its own suite; only the host tree and
// the state file below are this suite's own.
use voidportd::testing::{
    RunningServer, create_directory, daemon_config, invoking_environment, open_descriptors,
    scratch_root,
};

/// The host uid the fixture's map translates to guest uid 1000, so the forward
/// direction of the map is visible in a `stat` and not just implied.
pub const MAPPED_HOST_ID: u32 = 1234;

/// The guest id [`MAPPED_HOST_ID`] presents as.
pub const MAPPED_GUEST_ID: u32 = 1000;

/// An unprivileged id used to prove the guest kernel's own permission check.
pub const NOBODY_ID: u32 = 65534;

/// Distinguishes temporary directories created within one process.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Whether FUSE is usable on this machine.
///
/// This is the single capability preflight the contract allows a skip for: if
/// `/dev/fuse` is missing or cannot be opened, nothing in this suite can run.
/// Everywhere else a skip is a failure.
#[must_use]
pub fn preflight() -> bool {
    match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")
    {
        Ok(_) => true,
        Err(error) => {
            eprintln!("skipping: /dev/fuse is unusable ({error})");
            false
        }
    }
}

/// Whether the vsock suite may run on this machine — and the rule that decides.
///
/// [`preflight`] above is a plain capability check, because a machine without
/// `/dev/fuse` can run nothing in this suite. Vsock's is the one the design
/// decided, and it is stricter: a machine whose kernel carries the loopback
/// transport module **claims support**, and on such a machine a probe that
/// fails is a test failure, not a skip — the suite may not go vacuously
/// green where the transport is there. Only a machine without the module skips,
/// and it says so loudly.
///
/// The implementation lives in the server library's scaffolding because the
/// server's own suite asks the same question of the same machine.
#[allow(unused_imports, reason = "each test file uses part of this")]
pub use voidportd::testing::vsock::{free_port as free_vsock_port, preflight as vsock_preflight};

/// A temporary directory that removes itself.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates a uniquely named directory under
    /// [`scratch_root`](voidportd::testing::scratch_root).
    ///
    /// That root is deliberately not `$TMPDIR`, for two reasons that meet
    /// here: the server's unix data listener is bound inside this directory
    /// and a socket path must fit `sun_path`, and a mountpoint has to be
    /// *traversable* — one case mounts with `allow_other` and reaches it as
    /// another user — where a shell-provided temporary directory is usually
    /// private to its owner. The mode is set explicitly for the second reason,
    /// so the suite does not depend on the umask it inherits.
    #[must_use]
    pub fn new(label: &str) -> Self {
        let nanos = SystemTime::UNIX_EPOCH
            .elapsed()
            .map_or(0, |elapsed| elapsed.as_nanos());
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = scratch_root().join(format!(
            "voidport-e2e-{label}-{}-{sequence}-{nanos}",
            std::process::id()
        ));
        create_directory(&path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("a settable mode");
        Self { path }
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A path inside the directory.
    #[must_use]
    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Creates a subdirectory and returns its path.
    pub fn directory(&self, name: &str) -> PathBuf {
        let path = self.join(name);
        create_directory(&path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("a settable mode");
        path
    }

    /// Writes a file inside the directory and returns its path.
    pub fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.join(name);
        if let Some(parent) = path.parent() {
            create_directory(parent);
        }
        fs::write(&path, contents).expect("a writable temporary file");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// The host tree, the state file, and the server the tests run against.
///
/// The namespaces are the design's own examples:
///
/// * `project` — the worked example, with mapped ownership: `foo` read-write,
///   `bar` read-only, `file.txt` read-write, everything else hidden by a
///   wildcard, plus an admitted name that does not exist yet (`new`), a
///   re-targeted graft (`vendor`) and a world-readable file (`public.txt`) for
///   the guest kernel's own permission check;
/// * `plain` — one host tree grafted twice, read-write at `/tree` and
///   read-only at `/readonly`, which is what makes read-only enforcement
///   testable beside the read-write path.
#[derive(Debug)]
pub struct Fixture {
    /// The temporary directory holding the state file, the host tree and the
    /// mountpoints.
    pub directory: TempDir,
    /// The running server.
    pub server: RunningServer,
}

impl Fixture {
    /// Builds the host tree, writes the state file, and starts the server.
    #[must_use]
    pub fn start(label: &str) -> Self {
        Self::start_with(label, "")
    }

    /// The same, with extra state-file text inserted under `[server]` — a
    /// scalar setting, or a `[server.limits]` table of caps.
    ///
    /// It goes *before* the listeners, so a bare key lands in `[server]` where
    /// an operator would write it, not inside the last listener's table.
    #[must_use]
    pub fn start_with(label: &str, extra: &str) -> Self {
        let directory = TempDir::new(label);
        build_tree(directory.path());
        let state = state_file(directory.path(), extra);
        let state_file = directory.write("state.toml", &state);

        // The real invoking identity, not a pinned one: the ownership
        // assertions are about what lands on the host, and only the server's
        // own identity can be applied without CAP_CHOWN.
        let config = daemon_config(&state_file, invoking_environment(directory.path()));
        Self {
            server: RunningServer::start(&config).expect("the server starts"),
            directory,
        }
    }

    /// A path in the host tree, as the server sees it.
    #[must_use]
    pub fn host(&self, relative: &str) -> PathBuf {
        self.directory.join(relative)
    }

    /// The tcp URL of a namespace subpath.
    #[must_use]
    pub fn tcp_url(&self, namespace: &str, subpath: &str) -> String {
        format!(
            "voidport://{}/@{namespace}{subpath}",
            self.server.data_tcp()
        )
    }

    /// The unix-socket URL of a namespace subpath.
    ///
    /// The socket path is the authority component, so it is percent-encoded
    /// with the crate that owns the encoding, not by hand.
    #[must_use]
    pub fn unix_url(&self, namespace: &str, subpath: &str) -> String {
        let socket = percent_encoding::percent_encode(
            self.server.data_unix().as_os_str().as_bytes(),
            percent_encoding::NON_ALPHANUMERIC,
        );
        format!("voidport+unix://{socket}/@{namespace}{subpath}")
    }

    /// Mounts a namespace subpath over tcp, on a fresh mountpoint.
    #[must_use]
    pub fn mount(&self, label: &str, namespace: &str, subpath: &str) -> Guest {
        self.mount_with(
            label,
            &self.tcp_url(namespace, subpath),
            &MountOptions::default(),
        )
    }

    /// Mounts a URL with the options given.
    #[must_use]
    pub fn mount_with(&self, label: &str, url: &str, options: &MountOptions) -> Guest {
        let mountpoint = self.directory.directory(&format!("mnt-{label}"));
        let parsed = MountUrl::parse(url).unwrap_or_else(|error| panic!("{url}: {error}"));
        let mount = Mount::new(&parsed, &mountpoint, options)
            .unwrap_or_else(|error| panic!("mounting {url} on {mountpoint:?} failed: {error}"));
        Guest { mount, mountpoint }
    }

    /// Runs the real operator CLI against this server.
    pub fn ctl(&self, arguments: &[&str]) -> Output {
        Command::new(ctl_binary())
            .arg("--socket")
            .arg(self.server.socket())
            .args(arguments)
            .output()
            .expect("the CLI binary runs")
    }

    /// Runs the CLI and requires success.
    pub fn expect_ctl(&self, arguments: &[&str]) -> String {
        let output = self.ctl(arguments);
        assert!(
            output.status.success(),
            "voidport-ctl {arguments:?} failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("utf-8 output")
    }

    /// The sessions the server is serving, as the control plane reports them.
    #[must_use]
    pub fn sessions(&self) -> Vec<SessionSummary> {
        let response = self.control(&Request::SessionList {});
        match response {
            Response::Ok {
                result: Reply::SessionList { sessions },
            } => sessions,
            other => panic!("session-list answered {other:?}"),
        }
    }

    /// Sends one control-plane request over the real socket.
    pub fn control(&self, request: &Request) -> Response {
        self.server.connect().call(request)
    }

    /// How many open descriptors of this process point at `path`.
    ///
    /// The server runs in the test's own process, so `/proc/self/fd` is the
    /// server's descriptor table: this is how a test observes that tearing a
    /// session down really closed its pins.
    #[must_use]
    pub fn open_descriptors(&self, path: &Path) -> usize {
        open_descriptors(path)
    }
}

/// A mounted namespace, unmounted when the test ends however it ends.
///
/// Dropping it unmounts: a panicking test must never leave a stale FUSE mount
/// behind, because a stale one breaks every later run and even an `ls` of the
/// mountpoint.
#[derive(Debug)]
pub struct Guest {
    mount: Mount,
    mountpoint: PathBuf,
}

impl Guest {
    /// Wraps a mount a test established itself in the suite's drop guard.
    ///
    /// The guard is the point: a panicking test must never leave a stale FUSE
    /// mountpoint behind, and a suite that builds its own mounts needs that
    /// protection just as much as one that goes through [`Fixture`].
    #[must_use]
    pub fn adopt(mount: Mount, mountpoint: PathBuf) -> Self {
        Self { mount, mountpoint }
    }

    /// The mount root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.mountpoint
    }

    /// A path inside the mount.
    #[must_use]
    pub fn path(&self, relative: &str) -> PathBuf {
        self.mountpoint.join(relative)
    }

    /// The session behind the mount.
    #[must_use]
    pub fn client(&self) -> std::sync::Arc<voidport::client::Client> {
        self.mount.client()
    }

    /// The mount's readahead engine, for asking what its pool is holding.
    #[must_use]
    pub fn readahead(&self) -> std::sync::Arc<voidport::client::Readahead> {
        self.mount.readahead()
    }

    /// Unmounts, reporting what the kernel said, with no allowance made.
    ///
    /// # Errors
    ///
    /// The kernel's error — `EBUSY` for a mountpoint still in use.
    pub fn unmount(&mut self) -> io::Result<()> {
        self.mount.unmount()
    }

    /// Unmounts, waiting out the closes the kernel has not finished yet.
    ///
    /// Closing a descriptor on a FUSE mount completes asynchronously — the
    /// kernel does not wait for the RELEASE reply — so an unmount issued the
    /// instant a test drops its last file can transiently report `EBUSY`. The
    /// product is right to surface that (v1 has no forced unmount); a test that
    /// means "unmount a quiet mountpoint" waits for it to actually be quiet.
    ///
    /// # Errors
    ///
    /// The kernel's error: anything but `EBUSY` at once, and `EBUSY` if the
    /// mountpoint is still busy when patience runs out. Only `EBUSY` is a
    /// reason to wait — every other error is the answer, and retrying it for
    /// twenty seconds would only bury it.
    pub fn unmount_patiently(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match self.mount.unmount() {
                Ok(()) => return Ok(()),
                Err(error)
                    if errno(&error) != rustix::io::Errno::BUSY.raw_os_error()
                        || Instant::now() >= deadline =>
                {
                    return Err(error);
                }
                Err(_) => std::thread::sleep(Duration::from_millis(25)),
            }
        }
    }
}

impl Drop for Guest {
    /// The drop guard the suite is required to have: however a test ends,
    /// panic included, the mount comes down. A stale FUSE mount would break
    /// every later run and even an `ls` of the mountpoint, so a guard that
    /// cannot manage it says so as loudly as it can.
    fn drop(&mut self) {
        if let Err(error) = self.unmount_patiently() {
            eprintln!(
                "!!! {} is still mounted: {error}",
                self.mountpoint.display()
            );
        }
    }
}

/// Where the operator CLI binary is.
pub fn ctl_binary() -> PathBuf {
    workspace_binary("voidport-ctl")
}

/// Where the server binary is.
pub fn daemon_binary() -> PathBuf {
    workspace_binary("voidportd")
}

/// Where another workspace package's binary is.
///
/// `CARGO_BIN_EXE_*` only names binaries of the package under test, so the
/// sibling target directory is where a workspace build leaves these. Running
/// the workspace suite (`./check`) builds them; a bare `cargo test -p voidport`
/// does not.
pub fn workspace_binary(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let mut directory = exe
        .parent()
        .expect("the test binary lives somewhere")
        .to_path_buf();
    if directory.ends_with("deps") {
        directory.pop();
    }
    let binary = directory.join(name);
    assert!(
        binary.exists(),
        "{} is missing: build the workspace (./check, or cargo test --workspace) so the \
         other crates' binaries exist",
        binary.display()
    );
    binary
}

/// Builds the host tree the state file grafts.
fn build_tree(root: &Path) {
    let project = root.join("project");
    create_directory(&project);
    // The worked example's own modes: `foo` rwx------, `bar` rwx------ on the
    // host and r-x------ through the read-only graft, `file.txt` rw-------.
    make(&project.join("foo"), Kind::Directory, 0o700);
    make(&project.join("bar"), Kind::Directory, 0o700);
    make(&project.join("secret"), Kind::Directory, 0o700);
    fs::write(project.join("secret/key"), b"secret").expect("writable");
    fs::write(project.join("bar/note.txt"), b"read only").expect("writable");
    make(&project.join("file.txt"), Kind::File, 0o600);
    fs::write(project.join("file.txt"), b"worked example").expect("writable");
    // World-readable, so an unprivileged guest caller can be shown reaching a
    // file it is allowed and being refused one it is not.
    make(&project.join("public.txt"), Kind::File, 0o644);
    fs::write(project.join("public.txt"), b"public").expect("writable");

    let external = root.join("external");
    create_directory(&external);
    fs::write(external.join("note"), b"re-targeted").expect("writable");

    let tree = root.join("tree");
    create_directory(&tree.join("sub"));
    fs::write(tree.join("data.bin"), b"0123456789").expect("writable");
    fs::write(tree.join("sub/inner"), b"inner").expect("writable");
    // A file whose host owner the map translates, so the forward direction of
    // ownership mapping is observable through the mount.
    fs::write(tree.join("mapped"), b"mapped").expect("writable");

    // Somewhere for a rule added at runtime to point at.
    create_directory(&root.join("added"));
    fs::write(root.join("added/inside"), b"added").expect("writable");
}

/// What [`make`] creates.
enum Kind {
    File,
    Directory,
}

/// Creates an entry with exactly the mode asked for, whatever the umask is.
fn make(path: &Path, kind: Kind, mode: u32) {
    match kind {
        Kind::File => {
            fs::write(path, b"").expect("writable");
        }
        Kind::Directory => create_directory(path),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("a settable mode");
}

/// The state file, with the fixture's absolute paths and listeners.
fn state_file(root: &Path, extra: &str) -> String {
    let socket = root.join("data.sock");
    format!(
        r#"
[server]
{extra}

[[server.listeners]]
transport = "tcp"
addr = "127.0.0.1:0"

[[server.listeners]]
transport = "unix"
path = "{socket}"

[[namespaces]]
name = "project"

[namespaces.ownership]
mode = "map"
unmapped = "squash"
uid_map = [{{ host = "uid", guest = 0 }}, {{ host = {MAPPED_HOST_ID}, guest = {MAPPED_GUEST_ID} }}]
gid_map = [{{ host = "gid", guest = 0 }}, {{ host = {MAPPED_HOST_ID}, guest = {MAPPED_GUEST_ID} }}]

[[namespaces.rules]]
path = "/project"
mode = "rw"
target = "project"

[[namespaces.rules]]
path = "/project/*"
mode = "hidden"

[[namespaces.rules]]
path = "/project/foo"
mode = "rw"

[[namespaces.rules]]
path = "/project/bar"
mode = "ro"

[[namespaces.rules]]
path = "/project/file.txt"
mode = "rw"

[[namespaces.rules]]
path = "/project/public.txt"
mode = "rw"

[[namespaces.rules]]
path = "/project/new"
mode = "rw"

[[namespaces.rules]]
path = "/project/vendor"
mode = "ro"
target = "external"

[[namespaces]]
name = "plain"

[[namespaces.rules]]
path = "/tree"
mode = "rw"
target = "tree"

[[namespaces.rules]]
path = "/readonly"
mode = "ro"
target = "tree"
"#,
        socket = socket.display(),
    )
}

/// The permission bits as `ls -l` renders them: `rwx------`.
#[must_use]
pub fn mode_string(mode: u32) -> String {
    let mut rendered = String::with_capacity(9);
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 0o7;
        rendered.push(if bits & 0o4 != 0 { 'r' } else { '-' });
        rendered.push(if bits & 0o2 != 0 { 'w' } else { '-' });
        rendered.push(if bits & 0o1 != 0 { 'x' } else { '-' });
    }
    rendered
}

/// The permission bits of a path, as the mount presents them.
#[must_use]
pub fn presented_mode(path: &Path) -> String {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("{} should exist: {error}", path.display()));
    mode_string(metadata.permissions().mode())
}

/// Waits until a condition holds, or gives up.
///
/// Coherence across mounts is bounded by the cache timeouts, not immediate, so
/// a test asserts "within the timeouts", not "at once". The resilience
/// suites poll the same way for a different reason — a server that has just
/// been restarted comes back when it comes back — so this is the one
/// poll-until-true in the suite and [`daemon`] uses it too.
///
/// The granularity is fine enough that a suite measuring against a stall
/// window is measuring the window, not this loop.
pub fn eventually(patience: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + patience;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The errno a failed operation carries.
#[must_use]
pub fn errno(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or_default()
}
