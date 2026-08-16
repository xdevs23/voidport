//! The vsock transport, end to end.
//!
//! Vsock is what a VM guest reaches its host over when there is no network
//! between them: no interface, no route, no address anything off the machine
//! can name. The wire protocol above it is the same one tcp and unix carry, and
//! **that is exactly what this suite is for** — the contract is behaviour
//! parity, and parity is proven, not assumed.
//!
//! The four subjects, one per criterion of the vsock increment:
//!
//! 1. a real mount over vsock lists, reads, writes and unmounts;
//! 2. the URL grammar carries the scheme — in what the binary documents and in
//!    what it refuses (the parse itself is proven in `voidport::url`'s own
//!    tests, where the typed errors are);
//! 3. reconnect parity: a server killed and restarted under a live vsock mount
//!    behaves exactly as the reconnect contract rules over tcp and unix;
//! 4. the subscription stream works over vsock: subscribe, one delta, clean
//!    end.
//!
//! **The skip rule is the design's, and it is not a free pass.** A machine
//! whose kernel carries the vsock loopback module claims support, and on such a
//! machine a probe failure fails the suite instead of skipping it; a machine
//! without the module skips loudly. That decision is
//! [`vsock_preflight`](support::vsock_preflight), and every test here begins
//! with it.
//!
//! There is no VM here: the loopback cid is this machine talking to itself over
//! the same transport a guest would use, which is the kernel's own facility for
//! exactly this.

mod support;

use std::fs;
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use rustix::io::Errno;
use serde_json::Value;
use support::daemon::{DataAddress, LOOPBACK_CID, PATIENCE, Restartable, eventually, settle};
use support::{Guest, TempDir, errno, free_vsock_port, preflight, vsock_preflight};
use voidport::client::MountState;
use voidport::mount::{Mount, MountOptions};
use voidport::url::{Endpoint, MountUrl};
use voidport_control::{NamespaceName, Reply, Request, Rule, ShareMode};

/// The stall window the reconnect case runs with: long enough to cover a
/// restart, short enough not to dominate the suite.
const STALL: Duration = Duration::from_secs(5);

/// The contents of the file the mount reads and writes.
const CONTENTS: &[u8] = b"0123456789";

/// A host tree served over a vsock port, and the server serving it.
struct Ground {
    directory: TempDir,
    tree: PathBuf,
    server: Restartable,
}

impl Ground {
    /// Builds the tree, writes a state file with a vsock listener, and starts
    /// a server on it — or `None` where this machine may skip.
    ///
    /// Both preflights are asked here: the mount needs FUSE, and the transport
    /// needs the kernel's vsock loopback.
    fn start(label: &str) -> Option<Self> {
        if !preflight() || !vsock_preflight() {
            return None;
        }
        let directory = TempDir::new(label);
        let tree = directory.directory("tree");
        fs::write(tree.join("data.bin"), CONTENTS).expect("a writable tree");
        fs::write(tree.join("note.txt"), b"note").expect("a writable tree");
        let port = free_vsock_port().expect("a free vsock port");
        let address = DataAddress::Vsock { port };
        let server = Restartable::start_at(&directory, &state_file(&tree, &address), address);
        Some(Self {
            directory,
            tree,
            server,
        })
    }

    /// Mounts `work` on a fresh mountpoint, over vsock.
    fn mount(&self, label: &str, stall: Duration) -> Guest {
        let mountpoint = self.directory.directory(&format!("mnt-{label}"));
        let url = self.server.url("work", "");
        let parsed = MountUrl::parse(&url).unwrap_or_else(|error| panic!("{url}: {error}"));
        // The URL really is a vsock one: a suite that silently fell back to
        // another transport would prove nothing at all.
        assert!(
            matches!(parsed.endpoint, Endpoint::Vsock { cid, .. } if cid == LOOPBACK_CID),
            "the mount URL must name the loopback cid: {url}"
        );
        let options = MountOptions {
            reconnect_stall: stall,
            ..MountOptions::default()
        };
        let mount = Mount::new(&parsed, &mountpoint, &options)
            .unwrap_or_else(|error| panic!("mounting {url} failed: {error}"));
        Guest::adopt(mount, mountpoint)
    }
}

/// The state file: one namespace, one read-write graft, served on `address`.
fn state_file(tree: &Path, address: &DataAddress) -> String {
    format!(
        r#"
[server]

{listener}
[[namespaces]]
name = "work"

[[namespaces.rules]]
path = "/tree"
mode = "rw"
target = "{tree}"
"#,
        listener = address.listener_block(),
        tree = tree.display(),
    )
}

/// Criterion 1: a mount over vsock lists, reads, writes and unmounts.
#[test]
fn a_vsock_mount_lists_reads_writes_and_unmounts() {
    let Some(ground) = Ground::start("vsock-mount") else {
        return;
    };
    let mut guest = ground.mount("mount", STALL);

    // List.
    let mut listed: Vec<String> = fs::read_dir(guest.path("tree"))
        .expect("the mount lists")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    listed.sort();
    assert_eq!(listed, vec!["data.bin".to_owned(), "note.txt".to_owned()]);

    // Read.
    assert_eq!(
        fs::read(guest.path("tree/data.bin")).expect("the mount reads"),
        CONTENTS
    );

    // Write, and observe it on the host: the bytes really crossed the vsock.
    fs::write(guest.path("tree/written"), b"over vsock").expect("the mount writes");
    assert_eq!(
        fs::read(ground.tree.join("written")).expect("the host holds it"),
        b"over vsock"
    );

    // The session is a vsock one, as the server itself reports it.
    let sessions = match control(&ground.server, &Request::SessionList {}) {
        Reply::SessionList { sessions } => sessions,
        other => panic!("session-list answered {other:?}"),
    };
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    assert_eq!(sessions[0].transport, "vsock", "{sessions:?}");

    // Unmount.
    guest.unmount_patiently().expect("the mount comes down");
    assert!(
        fs::read_dir(guest.root())
            .expect("the mountpoint is a directory again")
            .next()
            .is_none(),
        "an unmounted mountpoint is the empty directory it was"
    );
}

/// Criterion 2: the scheme is in what the binary documents and in what it
/// refuses. It needs no vsock at all — a grammar is a grammar on every machine.
#[test]
fn the_binary_documents_and_refuses_vsock_urls() {
    let help = Command::new(env!("CARGO_BIN_EXE_voidport"))
        .args(["mount", "--help"])
        .output()
        .expect("the binary runs");
    let help = String::from_utf8(help.stdout).expect("utf-8 help");
    assert!(help.contains("voidport+vsock://cid:port"), "{help}");

    // The same page the manual is rendered from, so `man` cannot disagree.
    let subscribe = Command::new(env!("CARGO_BIN_EXE_voidport"))
        .args(["subscribe", "--help"])
        .output()
        .expect("the binary runs");
    let subscribe = String::from_utf8(subscribe.stdout).expect("utf-8 help");
    assert!(
        subscribe.contains("voidport+vsock://cid:port"),
        "{subscribe}"
    );

    // A cid that is not a number, and a port that is not there: each answers
    // its own typed error, and the command exits non-zero.
    for (url, message) in [
        ("voidport+vsock://host.example:1/@ns", "invalid cid"),
        ("voidport+vsock://2/@ns", "no port"),
        ("voidport+vsock:///@ns", "no cid"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_voidport"))
            .args(["mount", url, "/nonexistent-mountpoint"])
            .output()
            .expect("the binary runs");
        assert!(!output.status.success(), "{url} should be refused");
        let reported = String::from_utf8_lossy(&output.stderr);
        assert!(reported.contains("cannot mount"), "{url}: {reported}");
        assert!(reported.contains(message), "{url}: {reported}");
    }
}

/// Criterion 3: reconnect parity. A server killed and restarted under a live
/// vsock mount behaves exactly as the reconnect contract rules over the other
/// transports — path-based work heals with nothing surfaced, and identifiers
/// from the dead session answer their plain stale errno.
#[test]
fn a_vsock_mount_heals_paths_and_stales_descriptors_across_a_restart() {
    let Some(mut ground) = Ground::start("vsock-restart") else {
        return;
    };
    let guest = ground.mount("restart", STALL);

    let mut held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(guest.path("tree/data.bin"))
        .expect("opens before the restart");
    let mut before = Vec::new();
    held.read_to_end(&mut before).expect("reads before");
    assert_eq!(before, CONTENTS);

    ground.server.kill();
    let client = guest.client();
    assert!(
        eventually(PATIENCE, || client.state() != MountState::Connected),
        "the mount never noticed its server had gone"
    );
    ground.server.start_again();
    settle(&client);
    assert_eq!(client.state(), MountState::Connected);

    // Path-based work carries on with nothing surfaced: the walk from the mount
    // root is what the kernel's own `ESTALE` retry rebuilds.
    assert_eq!(
        fs::read(guest.path("tree/data.bin")).expect("a fresh walk works after the restart"),
        CONTENTS
    );
    fs::write(guest.path("tree/after"), b"after").expect("a create after the restart works");

    // The other half: the descriptor from the dead session names nothing, and
    // says so with a plain errno, not a framing fault.
    let refused = held
        .write_all(b"!")
        .expect_err("a descriptor cannot survive its session");
    assert!(
        stale(&refused),
        "a write through the dead session's handle should report the loss: {refused}"
    );
    assert!(
        eventually(PATIENCE, || {
            let mut after = Vec::new();
            held.seek(SeekFrom::Start(0)).is_ok()
                && held
                    .read_to_end(&mut after)
                    .is_err_and(|error| stale(&error))
        }),
        "a read through the dead session's handle never reported the loss"
    );
}

/// Criterion 4: the subscription stream works over vsock — subscribe, one
/// delta, clean end.
#[test]
fn a_subscription_streams_a_delta_and_ends_cleanly_over_vsock() {
    if !vsock_preflight() {
        return;
    }
    let directory = TempDir::new("vsock-subscribe");
    let tree = directory.directory("tree");
    let port = free_vsock_port().expect("a free vsock port");
    let address = DataAddress::Vsock { port };
    let server = Restartable::start_at(&directory, &state_file(&tree, &address), address);

    let mut stream = Subscription::open(&server.url("work", ""));
    let snapshot = stream.next_named("snapshot");
    assert_eq!(snapshot["v"], 1);
    assert_eq!(snapshot["entries"][0]["path"], "/tree");

    // One delta.
    control(
        &server,
        &Request::RuleAdd {
            namespace: namespace("work"),
            rule: Rule::new("/tree/docs", ShareMode::Ro),
        },
    );
    let added = stream.next_named("added");
    assert_eq!(added["path"], "/tree/docs");
    assert_eq!(added["mode"], "ro");

    // A clean end: the namespace goes, the stream says why, and the command
    // exits zero.
    control(
        &server,
        &Request::NamespaceDelete {
            name: namespace("work"),
        },
    );
    let ended = stream.next_named("ended");
    assert_eq!(ended["reason"], "namespace-removed");
    assert!(
        stream.wait().success(),
        "the command exits cleanly once the stream has ended"
    );
}

/// Whether an error is the plain stale errno an identifier from a dead session
/// is owed: `ESTALE` for a node, `EBADF` for a handle.
fn stale(error: &std::io::Error) -> bool {
    let code = errno(error);
    code == Errno::STALE.raw_os_error() || code == Errno::BADF.raw_os_error()
}

fn namespace(name: &str) -> NamespaceName {
    NamespaceName::new(name).expect("a valid namespace name")
}

/// Drives one control-plane request against the server, and expects it to
/// succeed.
fn control(server: &Restartable, request: &Request) -> Reply {
    let mut client = voidport_control::Client::connect(server.control_socket())
        .expect("the control socket accepts connections");
    let answer = client.call(request).expect("the server answers");
    match answer.response {
        voidport_control::Response::Ok { result } => result,
        voidport_control::Response::Error { error } => panic!("the server refused: {error}"),
    }
}

/// A running `voidport subscribe`, and its lines.
///
/// The lines are pumped off the pipe by a thread of its own, so a test waiting
/// for an event that never comes fails instead of hanging.
struct Subscription {
    child: Child,
    lines: mpsc::Receiver<String>,
}

impl Subscription {
    fn open(url: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_voidport"))
            .args(["subscribe", url])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the voidport binary runs");
        let stdout = child.stdout.take().expect("stdout is piped");
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if sender.send(line).is_err() {
                    return;
                }
            }
        });
        Self { child, lines }
    }

    /// Reads until an event of that name arrives, and returns it.
    fn next_named(&mut self, event: &str) -> Value {
        loop {
            let line = match self.lines.recv_timeout(PATIENCE) {
                Ok(line) => line,
                Err(error) => panic!(
                    "no {event} in time ({error:?}); child alive={:?}",
                    self.child.try_wait()
                ),
            };
            let parsed: Value = serde_json::from_str(&line)
                .unwrap_or_else(|error| panic!("every line is one JSON object: {error} in {line}"));
            if parsed["event"] == event {
                return parsed;
            }
        }
    }

    fn wait(mut self) -> std::process::ExitStatus {
        self.child.wait().expect("the command is waitable")
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
