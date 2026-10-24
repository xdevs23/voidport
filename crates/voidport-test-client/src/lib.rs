pub mod daemon;
pub mod mapping;
pub mod namespace;
pub mod relay;
pub mod signal;

use std::fs;
use std::io::{self, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use rustix::process::Pid;
use voidport::guardian::Launch;
use voidport::mount::{Mount, MountOptions, TeardownError};
use voidport::url::MountUrl;
use voidport_control::{Reply, Request, Response, SessionSummary};
use voidport_spawn::{Program, Stream};
use voidport_test_support::{
    RunningServer, create_directory, daemon_config, open_descriptors, scratch_root,
};

/// Translates to guest uid 1000, so the forward direction of the map is visible
/// in a `stat`.
pub const MAPPED_HOST_ID: u32 = 1234;

pub const MAPPED_GUEST_ID: u32 = 1000;

pub const NOBODY_ID: u32 = 65534;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

const TEMP_DIR_PREFIX: &str = "voidport-e2e-";

pub fn preflight() {
    if let Err(error) = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")
    {
        panic!("/dev/fuse is unusable, so nothing can be mounted: {error}");
    }
}

pub use voidport_test_support::vsock::preflight as vsock_preflight;

/// The kernel sends a forget for every node of a mount whose dentry it drops.
/// The write evicts the unused inodes of every mount on the machine, also those
/// of tests running in parallel, so a test that counts the reads served from
/// cached pages has the file open across those reads.
pub fn drop_dentry_cache() {
    fs::write("/proc/sys/vm/drop_caches", b"2\n").expect("a prunable dentry cache (needs root)");
}

#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

/// Reads one directory per line until its input ends, which happens once this
/// process has ended, then detaches every mount below one of them.
const DETACH: &str = r#"while IFS= read -r directory; do set -- "$@" "$directory"; done
findmnt --list --noheadings --output TARGET | while IFS= read -r target; do
    for directory; do
        case "$target" in "$directory"/*) umount --lazy "$target" ;; esac
    done
done"#;

static DETACHER: OnceLock<Mutex<Child>> = OnceLock::new();

#[must_use]
pub fn detacher() -> Option<Pid> {
    DETACHER
        .get()
        .map(|detacher| Pid::from_child(&detacher.lock().unwrap_or_else(PoisonError::into_inner)))
}

fn detach_mounts_below(directory: &Path) {
    let detacher = DETACHER.get_or_init(|| {
        Mutex::new(
            Program::new("/bin/sh")
                .arg("-c")
                .arg(DETACH)
                .stdin(Stream::Piped)
                // A Ctrl-C sent to the process group of the test does not
                // end the detacher before it has detached anything.
                .in_new_process_group()
                .spawn()
                .expect("a shell that detaches the mounts of the test"),
        )
    });
    let mut line = directory.as_os_str().as_bytes().to_vec();
    line.push(b'\n');
    detacher
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .stdin
        .as_mut()
        .expect("a piped stdin")
        .write_all(&line)
        .expect("the detacher takes a directory");
}

impl TempDir {
    /// Not under `$TMPDIR`: a socket path must fit `sun_path`, and a mountpoint must
    /// be traversable, because one case mounts with `allow_other` and opens it as
    /// another user. The mode is set explicitly, so the suite does not depend on the
    /// inherited umask.
    #[must_use]
    pub fn new(label: &str) -> Self {
        let path = Self::unique_path(label);
        create_directory(&path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("a settable mode");
        detach_mounts_below(&path);
        Self { path }
    }

    fn unique_path(label: &str) -> PathBuf {
        let nanos = SystemTime::UNIX_EPOCH
            .elapsed()
            .map_or(0, |elapsed| elapsed.as_nanos());
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        scratch_root().join(format!(
            "{TEMP_DIR_PREFIX}{label}-{}-{sequence}-{nanos}",
            std::process::id()
        ))
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub fn directory(&self, name: &str) -> PathBuf {
        let path = self.join(name);
        create_directory(&path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("a settable mode");
        path
    }

    pub fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.join(name);
        if let Some(parent) = path.parent() {
            create_directory(parent);
        }
        fs::write(&path, contents).expect("a writable temporary file");
        path
    }

    pub fn executable(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.write(name, contents);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("a settable mode");
        path
    }
}

/// Whether `path` is a directory made by [`TempDir::new`] or lies below one.
fn is_in_temp_dir(path: &Path) -> bool {
    path.strip_prefix(scratch_root())
        .ok()
        .and_then(|inside| inside.components().next())
        .is_some_and(|directory| {
            directory
                .as_os_str()
                .as_bytes()
                .starts_with(TEMP_DIR_PREFIX.as_bytes())
        })
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path) {
            cleanup_failed(format_args!(
                "the temporary directory {} is not removed: {error}",
                self.path.display()
            ));
        }
    }
}

/// A panic in a drop that runs while the thread unwinds aborts the process,
/// so the failure is printed then and fails the test otherwise.
pub fn cleanup_failed(failure: impl std::fmt::Display) {
    if std::thread::panicking() {
        eprintln!("{failure}");
    } else {
        panic!("{failure}");
    }
}

pub fn kill_and_reap(child: &mut Child) {
    if let Err(error) = child.kill().and_then(|()| child.wait()) {
        cleanup_failed(format_args!(
            "the process {} is not ended: {error}",
            child.id()
        ));
    }
}

/// A program the test started, killed if the test ends before it exits, so
/// that no mount a test leaves behind remains busy.
#[derive(Debug)]
pub struct KilledOnDrop(pub Child);

impl Drop for KilledOnDrop {
    fn drop(&mut self) {
        kill_and_reap(&mut self.0);
    }
}

#[must_use]
pub fn tcp_url(address: impl std::fmt::Display, namespace: &str, subpath: &str) -> String {
    format!("voidport://{address}/@{namespace}{subpath}")
}

/// The server is dropped before the directory it writes into.
#[derive(Debug)]
pub struct Fixture {
    pub server: RunningServer,
    pub directory: TempDir,
}

impl Fixture {
    #[must_use]
    pub fn start(label: &str) -> Self {
        Self::start_with(label, "")
    }

    /// `extra` goes before the listeners, so a bare key belongs to `[server]`.
    #[must_use]
    pub fn start_with(label: &str, extra: &str) -> Self {
        Self::start_over(label, extra, None)
    }

    /// Adds the namespace `image`, which grafts `graft` at `/fs`, so that a suite can
    /// put a host filesystem of its choosing behind a mount.
    #[must_use]
    pub fn start_over(label: &str, extra: &str, graft: Option<&Path>) -> Self {
        let directory = TempDir::new(label);
        build_tree(directory.path());
        let state = state_file(directory.path(), extra, graft);
        let state_file = directory.write("state.toml", &state);

        // Only the identity of the server can be applied without CAP_CHOWN.
        let config = daemon_config(&state_file);
        Self {
            server: RunningServer::start(&config).expect("the server starts"),
            directory,
        }
    }

    #[must_use]
    pub fn host(&self, relative: &str) -> PathBuf {
        self.directory.join(relative)
    }

    #[must_use]
    pub fn tcp_url(&self, namespace: &str, subpath: &str) -> String {
        tcp_url(self.server.data_tcp(), namespace, subpath)
    }

    #[must_use]
    pub fn unix_url(&self, namespace: &str, subpath: &str) -> String {
        let socket = percent_encoding::percent_encode(
            self.server.data_unix().as_os_str().as_bytes(),
            percent_encoding::NON_ALPHANUMERIC,
        );
        format!("voidport+unix://{socket}/@{namespace}{subpath}")
    }

    #[must_use]
    pub fn mount(&self, label: &str, namespace: &str, subpath: &str) -> Guest {
        self.mount_with(
            label,
            &self.tcp_url(namespace, subpath),
            &MountOptions::default(),
        )
    }

    pub fn mount_fresh(&self, label: &str, namespace: &str, subpath: &str) -> Guest {
        self.mount_with(
            label,
            &self.tcp_url(namespace, subpath),
            &MountOptions {
                attr_timeout: Duration::ZERO,
                entry_timeout: Duration::ZERO,
                ..MountOptions::default()
            },
        )
    }

    #[must_use]
    pub fn mount_with(&self, label: &str, url: &str, options: &MountOptions) -> Guest {
        let mountpoint = self.directory.directory(&format!("mnt-{label}"));
        let parsed = MountUrl::parse(url).unwrap_or_else(|error| panic!("{url}: {error}"));
        let mount = Mount::new(&parsed, &mountpoint, options, &guardian())
            .unwrap_or_else(|error| panic!("mounting {url} on {mountpoint:?} failed: {error:?}"));
        Guest { mount, mountpoint }
    }

    pub fn ctl(&self, arguments: &[&str]) -> Output {
        Program::new(ctl_binary())
            .arg("--socket")
            .arg(self.server.socket())
            .args(arguments)
            .stdout(Stream::Piped)
            .stderr(Stream::Piped)
            .spawn()
            .expect("the CLI binary starts")
            .wait_with_output()
            .expect("the CLI binary runs")
    }

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

    pub fn control(&self, request: &Request) -> Response {
        self.server.connect().call(request)
    }

    #[must_use]
    pub fn open_descriptors(&self, path: &Path) -> usize {
        open_descriptors(path)
    }
}

#[derive(Debug)]
pub struct Guest {
    mount: Mount,
    mountpoint: PathBuf,
}

impl Guest {
    #[must_use]
    pub fn adopt(mount: Mount, mountpoint: PathBuf) -> Self {
        Self { mount, mountpoint }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.mountpoint
    }

    #[must_use]
    pub fn path(&self, relative: &str) -> PathBuf {
        self.mountpoint.join(relative)
    }

    #[must_use]
    pub fn client(&self) -> std::sync::Arc<voidport::client::Client> {
        self.mount.client()
    }

    #[must_use]
    pub fn guardian_id(&self) -> Option<u32> {
        self.mount.guardian_id()
    }

    pub fn unmount(&mut self) -> Result<(), TeardownError> {
        self.mount.unmount()
    }

    /// Closing a descriptor on a FUSE mount completes asynchronously, because the
    /// kernel does not wait for the RELEASE reply, so an unmount issued the instant a
    /// test drops its last file can transiently report `EBUSY`. Only `EBUSY` is waited
    /// out, because retrying another error would only bury it.
    pub fn unmount_patiently(&mut self) -> Result<(), TeardownError> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match self.mount.unmount() {
                Err(TeardownError::Unmount(error))
                    if errno(&error) == rustix::io::Errno::BUSY.raw_os_error()
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(25));
                }
                unmounted => return unmounted,
            }
        }
    }
}

impl Drop for Guest {
    /// A stale FUSE mount would break every later run, so a failure is reported
    /// loudly.
    fn drop(&mut self) {
        if let Err(error) = self.unmount_patiently() {
            eprintln!(
                "!!! {} is still mounted: {error}",
                self.mountpoint.display()
            );
        }
    }
}

#[must_use]
pub fn guardian() -> Launch {
    Launch {
        program: workspace_binary("voidport"),
        arguments: vec![voidport::guardian::COMMAND.into()],
    }
}

/// The FUSE client program. `voidport mount` mounts through the voidport
/// kernel module where this process can, so this panics there: these tests
/// exercise the FUSE client.
#[must_use]
pub fn fuse_client() -> Program<'static> {
    assert_ne!(
        voidport::kernel::availability().ok(),
        Some(voidport::kernel::Availability::Usable),
        "the voidport kernel module is loaded; these tests exercise the FUSE client"
    );
    let mut program = Program::new(workspace_binary("voidport"));
    program.stdout(Stream::Inherit).stderr(Stream::Inherit);
    program
}

#[must_use]
pub fn ctl_binary() -> PathBuf {
    workspace_binary("voidport-ctl")
}

#[must_use]
pub fn daemon_binary() -> PathBuf {
    workspace_binary("voidportd")
}

#[must_use]
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

fn build_tree(root: &Path) {
    let project = root.join("project");
    create_directory(&project);
    make(&project.join("foo"), Kind::Directory, 0o700);
    make(&project.join("bar"), Kind::Directory, 0o700);
    make(&project.join("secret"), Kind::Directory, 0o700);
    fs::write(project.join("secret/key"), b"secret").expect("writable");
    fs::write(project.join("bar/note.txt"), b"read only").expect("writable");
    make(&project.join("file.txt"), Kind::File, 0o600);
    fs::write(project.join("file.txt"), b"worked example").expect("writable");
    // World-readable, so a test can show an unprivileged guest caller reading a
    // file it is allowed and failing on one it is not.
    make(&project.join("public.txt"), Kind::File, 0o644);
    fs::write(project.join("public.txt"), b"public").expect("writable");

    let external = root.join("external");
    create_directory(&external);
    fs::write(external.join("note"), b"re-targeted").expect("writable");

    let tree = root.join("tree");
    create_directory(&tree.join("sub"));
    fs::write(tree.join("data.bin"), b"0123456789").expect("writable");
    fs::write(tree.join("sub/inner"), b"inner").expect("writable");
    // A file whose host uid the map translates, so the forward direction of
    // ownership mapping is observable through the mount.
    fs::write(tree.join("mapped"), b"mapped").expect("writable");

    // Somewhere for a rule added at runtime to point at.
    create_directory(&root.join("added"));
    fs::write(root.join("added/inside"), b"added").expect("writable");
}

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

fn state_file(root: &Path, extra: &str, graft: Option<&Path>) -> String {
    let socket = root.join("data.sock");
    let image = graft.map_or_else(String::new, |target| {
        format!(
            r#"
[[namespaces]]
name = "image"

[[namespaces.rules]]
path = "/fs"
mode = "rw"
target = "{target}"
"#,
            target = target.display(),
        )
    });
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

[[namespaces]]
name = "uncached"
direct_io = "always"

[[namespaces.rules]]
path = "/tree"
mode = "rw"
target = "tree"
{image}"#,
        socket = socket.display(),
    )
}

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

#[must_use]
pub fn presented_mode(path: &Path) -> String {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("{} should exist: {error}", path.display()));
    mode_string(metadata.permissions().mode())
}

/// The poll interval is short enough that a suite measuring a stall window
/// measures the window itself.
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

#[must_use]
pub fn errno(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or_default()
}

/// Returns the bytes that arrived, as the mount does for a read that failed after
/// some pieces. A read that received nothing returns the errno.
pub async fn read(
    client: &voidport::client::Client,
    caller: voidport::client::Caller,
    node_id: u64,
    handle: u64,
    offset: u64,
    size: u32,
) -> Result<Vec<u8>, rustix::io::Errno> {
    let data = voidport::client::Data::new(client.buffer(size as usize).await);
    let origin = voidport::client::Origin::detached(caller);
    let (data, outcome) = client
        .read(origin, node_id, handle, offset, data)
        .await
        .map_err(|voidport::client::Interrupted| rustix::io::Errno::INTR)?;
    match outcome {
        Ok(voidport::client::Streamed {
            failed: Some(errno),
            ..
        })
        | Err(errno)
            if data.filled().is_empty() =>
        {
            Err(errno)
        }
        _ => Ok(data.filled().to_vec()),
    }
}

pub fn read_message(from: &mut impl io::Read) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; voidport_proto::frame::FRAME_HEADER_LEN];
    from.read_exact(&mut bytes)?;
    let follows = loop {
        let needed = match voidport_proto::frame::Frame::parse_prefix(
            &bytes,
            &voidport_proto::limits::LIMITS,
        )
        .map_err(io::Error::other)?
        {
            voidport_proto::frame::Parsed::Frame(frame) => break frame.follows(),
            voidport_proto::frame::Parsed::Need(needed) => needed,
        };
        let have = bytes.len();
        bytes.resize(needed, 0);
        from.read_exact(&mut bytes[have..])?;
    };
    let mut take = |bytes: &mut Vec<u8>, len: usize| {
        let have = bytes.len();
        bytes.resize(have + len, 0);
        from.read_exact(&mut bytes[have..])
    };
    match follows {
        voidport_proto::message::Follows::Nothing => {}
        voidport_proto::message::Follows::Data(len) => take(&mut bytes, len as usize)?,
        voidport_proto::message::Follows::Pieces(_) => loop {
            take(&mut bytes, voidport_proto::piece::PIECE_LEN_LEN)?;
            let at = bytes.len() - voidport_proto::piece::PIECE_LEN_LEN;
            let len =
                voidport_proto::piece::read_length(bytes[at..].try_into().expect("a length word"));
            if len == 0 {
                take(&mut bytes, voidport_proto::piece::CLOSING_LEN)?;
                break;
            }
            take(&mut bytes, len as usize)?;
        },
    }
    Ok(bytes)
}
