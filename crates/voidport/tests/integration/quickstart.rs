//! The quickstart through the real binaries: `voidportd share` against a state
//! file that does not exist yet, then the `voidport mount` line printed by the
//! server, then reads and writes through the mount, an unmount, and a clean
//! shutdown. Nothing here builds a state file or a URL, so a wrong printed line
//! fails the mount.

use voidport_test_client as support;

use std::fs;
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal};
use support::daemon::LOOPBACK_CID;
use support::{TempDir, daemon_binary, fuse_client, preflight, vsock_preflight};
use voidport::url::{Endpoint, MountUrl};
use voidport_spawn::{Program, Stream};
use voidportd::launch::SECURITY_SECTION;

const PATIENCE: Duration = Duration::from_secs(20);

struct Shared {
    child: Child,
    mounts: Vec<String>,
    /// Kept alive so the reader thread below can keep draining the server's
    /// stdout: a pipe nobody reads would block the server on a full buffer.
    _printed: mpsc::Receiver<String>,
}

impl Shared {
    fn start(directory: &Path, state_file: &Path, socket: &Path, listener: &[&str]) -> Self {
        let mut child = Program::new(daemon_binary())
            .arg("share")
            .arg(directory)
            .args(listener)
            .arg("--state")
            .arg(state_file)
            .arg("--control-socket")
            .arg(socket)
            .stdout(Stream::Piped)
            .stderr(Stream::Inherit)
            .spawn()
            .expect("the daemon binary runs");

        // Read stdout on its own thread: a launch that fails must fail this
        // test by timing out, not by blocking it forever.
        let stdout = child.stdout.take().expect("stdout is piped");
        let (lines, printed) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if lines.send(line).is_err() {
                    return;
                }
            }
        });

        let mut mounts = Vec::new();
        let deadline = Instant::now() + PATIENCE;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("the server must print its mount commands");
            let line = printed
                .recv_timeout(remaining)
                .expect("the server must print its mount commands");
            let trimmed = line.trim();
            if let Some(command) = trimmed.strip_prefix("voidport mount ") {
                mounts.push(command.to_owned());
            }
            // The plain-transport note closes the block for a tcp launch.
            if trimmed.contains(SECURITY_SECTION) {
                assert!(
                    trimmed.contains("auth is \"none\""),
                    "the note must say what it is about: {trimmed}"
                );
                break;
            }
            // A launch with no tcp listener is not reachable off the machine
            // and prints no such note, so its block ends with the control line.
            if trimmed.starts_with("voidport-ctl --socket")
                && !mounts.iter().any(|mount| mount.starts_with("voidport://"))
            {
                break;
            }
        }
        assert_eq!(mounts.len(), 1, "one line per listener: {mounts:?}");
        Self {
            child,
            mounts,
            _printed: printed,
        }
    }

    fn url(&self) -> &str {
        self.mounts[0]
            .split_whitespace()
            .next()
            .expect("a mount command names a URL")
    }

    fn suggested_mountpoint(&self) -> &str {
        self.mounts[0]
            .split_whitespace()
            .nth(1)
            .expect("a mount command names a mountpoint")
    }

    fn stop(mut self) -> bool {
        let pid = Pid::from_raw(i32::try_from(self.child.id()).expect("a plausible pid"))
            .expect("a live pid");
        rustix::process::kill_process(pid, Signal::TERM).expect("the signal is delivered");
        self.child.wait().expect("the daemon exits").success()
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        let ended = self.child.kill().and_then(|()| self.child.wait());
        if let Err(error) = ended {
            eprintln!("the shared server is not ended: {error}");
        }
    }
}

struct Guest {
    child: Option<Child>,
    mountpoint: PathBuf,
}

impl Guest {
    fn mount(url: &str, mountpoint: &Path, probe: &Path) -> Self {
        let child = fuse_client()
            .args(["mount", url])
            .arg(mountpoint)
            .spawn()
            .expect("the client binary runs");
        let guest = Self {
            child: Some(child),
            mountpoint: mountpoint.to_path_buf(),
        };
        let deadline = Instant::now() + PATIENCE;
        while !probe.exists() {
            assert!(
                Instant::now() < deadline,
                "{} never came up",
                mountpoint.display()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        guest
    }

    fn unmount(&mut self) {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let umount = fuse_client()
                .arg("umount")
                .arg(&self.mountpoint)
                .output()
                .expect("the client binary runs");
            if umount.status.success() {
                break;
            }
            // Closing a descriptor on a FUSE mount completes asynchronously, so
            // an unmount right after a write can transiently report EBUSY.
            assert!(
                Instant::now() < deadline,
                "unmounting {} failed: {}",
                self.mountpoint.display(),
                String::from_utf8_lossy(&umount.stderr)
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut child = self.child.take().expect("the mount is still running");
        let deadline = Instant::now() + PATIENCE;
        while child.try_wait().expect("the child is waitable").is_none() {
            assert!(
                Instant::now() < deadline,
                "the mount process did not exit after the unmount"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            child.wait().expect("the child reports").success(),
            "the foreground mount must exit cleanly"
        );
    }
}

impl Drop for Guest {
    /// A mount the test failed to take down must not outlive it: a stale FUSE
    /// mountpoint breaks every later run.
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if let Err(error) = fuse_client().arg("umount").arg(&self.mountpoint).status() {
            eprintln!(
                "the mount at {} is not taken down: {error}",
                self.mountpoint.display()
            );
        }
        let ended = child.kill().and_then(|()| child.wait());
        if let Err(error) = ended {
            eprintln!("the mount process is not ended: {error}");
        }
    }
}

fn listing(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .expect("a readable directory")
        .map(|entry| {
            entry
                .expect("a readable entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

#[test]
fn the_quickstart_shares_a_directory_and_mounts_it() {
    preflight();
    let directory = TempDir::new("quickstart");
    let shared = directory.directory("shared");
    fs::write(shared.join("hello.txt"), "hello from the host").expect("writable");
    let state_file = directory.join("state.toml");
    let socket = directory.join("control.sock");
    assert!(
        !state_file.exists(),
        "the quickstart writes no file by hand"
    );

    let server = Shared::start(&shared, &state_file, &socket, &["--addr", "127.0.0.1:0"]);
    assert!(
        state_file.exists(),
        "a missing state file is created by the launch"
    );
    assert!(socket.exists(), "the control plane is up");
    assert_eq!(server.suggested_mountpoint(), "/mnt/share");

    // The URL names the namespace root, and the share is grafted at its own
    // absolute host path, so the host hierarchy is replicated below the
    // mountpoint: the guest reaches it at the same path, minus the leading `/`.
    let mountpoint = directory.directory("mnt");
    let graft = mountpoint.join(shared.strip_prefix("/").expect("an absolute host path"));
    let mut guest = Guest::mount(server.url(), &mountpoint, &graft.join("hello.txt"));

    // The engine synthesizes every intermediate directory of a deep rule, so
    // the walk down to the graft works one component at a time, starting with
    // the first component of the host path at the mount root.
    let first = shared
        .components()
        .nth(1)
        .expect("a host path below the root");
    assert_eq!(
        listing(&mountpoint),
        vec![first.as_os_str().to_string_lossy().into_owned()],
        "the mount root shows the first component of the shared host path"
    );
    let mut walked = mountpoint.clone();
    for component in shared.strip_prefix("/").expect("absolute").components() {
        walked.push(component);
        assert!(
            fs::metadata(&walked)
                .expect("every component resolves")
                .is_dir(),
            "{} is not a directory",
            walked.display()
        );
    }
    assert_eq!(walked, graft);

    assert_eq!(
        fs::read_to_string(graft.join("hello.txt")).expect("the mount serves"),
        "hello from the host"
    );
    fs::write(graft.join("written.txt"), "hello from the guest").expect("the share is read-write");
    assert_eq!(
        fs::read_to_string(shared.join("written.txt")).expect("the write reached the host"),
        "hello from the guest"
    );

    guest.unmount();
    assert!(server.stop(), "the server shuts down cleanly");
    assert!(
        !socket.exists(),
        "a clean shutdown unlinks the control socket"
    );
}

/// The cid in the printed line is the one a guest dials its host at. There is
/// no guest here, so the host talks to itself over the vsock loopback, which
/// reaches the same wildcard-bound listener at the loopback cid. That
/// substitution is the one thing this test does to the printed line.
#[test]
fn the_quickstart_shares_a_directory_over_vsock() {
    preflight();
    if !vsock_preflight() {
        return;
    }
    let directory = TempDir::new("quickstart-vsock");
    let shared = directory.directory("shared");
    fs::write(shared.join("hello.txt"), "hello from the host").expect("writable");
    let state_file = directory.join("state.toml");
    let socket = directory.join("control.sock");

    let server = Shared::start(&shared, &state_file, &socket, &["--vsock", "0"]);
    let printed = MountUrl::parse(server.url()).expect("the printed line is a mount URL");
    let Endpoint::Vsock { cid, port } = printed.endpoint else {
        panic!("the printed line is a vsock URL: {}", server.url());
    };
    assert_eq!(
        cid,
        vsock::VMADDR_CID_HOST,
        "the printed line names the cid a guest dials its host at"
    );
    assert_ne!(port, 0, "the port that was bound is printed");
    assert_eq!(server.suggested_mountpoint(), "/mnt/share");

    let mountpoint = directory.directory("mnt");
    let graft = mountpoint.join(shared.strip_prefix("/").expect("an absolute host path"));
    let dialled = format!("voidport+vsock://{LOOPBACK_CID}:{port}/@share");
    let mut guest = Guest::mount(&dialled, &mountpoint, &graft.join("hello.txt"));

    assert_eq!(
        fs::read_to_string(graft.join("hello.txt")).expect("the mount serves"),
        "hello from the host"
    );
    fs::write(graft.join("written.txt"), "hello from the guest").expect("the share is read-write");
    assert_eq!(
        fs::read_to_string(shared.join("written.txt")).expect("the write reached the host"),
        "hello from the guest"
    );

    guest.unmount();
    assert!(server.stop(), "the server shuts down cleanly");
}

#[test]
fn a_share_with_no_listener_is_refused() {
    // There is no default bind: the refusal says which flags would have fixed it.
    let directory = TempDir::new("quickstart-no-listener");
    let shared = directory.directory("shared");
    let output = Program::new(daemon_binary())
        .arg("share")
        .arg(&shared)
        .arg("--state")
        .arg(directory.join("state.toml"))
        .output()
        .expect("the daemon binary runs");
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("--addr"), "{message}");
    assert!(message.contains("--unix"), "{message}");
    assert!(message.contains("--vsock"), "{message}");
}
