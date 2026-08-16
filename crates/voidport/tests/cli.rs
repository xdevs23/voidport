//! The real `voidport` binary: argument parsing, exit codes, error rendering.
//!
//! Everything else in this suite drives the library. This file drives the
//! program an operator actually types, as a separate process: `voidport mount`
//! in the foreground until somebody unmounts it, `voidport umount` doing the
//! unmounting, and the two ways each of them is asked for the impossible. A
//! library that works and a binary that does not is still a product that does
//! not work.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use support::Fixture;

/// How long the binary is given to bring a mount up or take it down.
const PATIENCE: Duration = Duration::from_secs(20);

/// The binary under test.
fn voidport() -> Command {
    Command::new(env!("CARGO_BIN_EXE_voidport"))
}

/// A foreground `voidport mount`, taken down however the test ends.
struct Mounted {
    /// `None` once the process has been waited for by [`Mounted::finish`].
    child: Option<Child>,
    mountpoint: PathBuf,
}

impl Mounted {
    /// Starts the binary and waits until the mount is serving.
    fn start(url: &str, mountpoint: &Path, probe: &Path) -> Self {
        Self::start_with(url, mountpoint, probe, &[])
    }

    /// The same, with extra flags on the `mount` subcommand.
    fn start_with(url: &str, mountpoint: &Path, probe: &Path, flags: &[&str]) -> Self {
        let child = voidport()
            .args(["mount", url])
            .arg(mountpoint)
            .args(flags)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the binary runs");
        let mounted = Self {
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
        mounted
    }

    /// Waits for the process to exit once the mountpoint is unmounted.
    fn finish(mut self) -> Output {
        let mut child = self.child.take().expect("the mount is still running");
        let deadline = Instant::now() + PATIENCE;
        while child.try_wait().expect("the child is waitable").is_none() {
            assert!(
                Instant::now() < deadline,
                "the mount process did not exit after the unmount"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        child.wait_with_output().expect("the child reports")
    }
}

impl Drop for Mounted {
    /// A mount the test failed to take down must not outlive it: a stale FUSE
    /// mountpoint breaks every later run.
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let _ = voidport().arg("umount").arg(&self.mountpoint).status();
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn the_binary_mounts_and_unmounts() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("cli-mount");
    let mountpoint = fixture.directory.directory("mnt-cli");
    let url = fixture.tcp_url("project", "/project");

    let mounted = Mounted::start(&url, &mountpoint, &mountpoint.join("file.txt"));
    // The mount serves the real namespace, not just a mountpoint.
    assert_eq!(
        std::fs::read(mountpoint.join("file.txt")).expect("the mount serves"),
        b"worked example"
    );
    assert!(fixture.sessions().len() == 1, "{:?}", fixture.sessions());

    let umount = voidport()
        .arg("umount")
        .arg(&mountpoint)
        .output()
        .expect("the binary runs");
    assert!(
        umount.status.success(),
        "umount failed: {}",
        String::from_utf8_lossy(&umount.stderr)
    );

    // The foreground mount ends when the mountpoint does, and reports success.
    let output = mounted.finish();
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the mount process exited with {}: {said}",
        output.status,
    );
    // And it says nothing alarming on the way out. fuser unmounts a second time
    // from its own session handle as the session ends, on a mountpoint this
    // unmount has already taken down, so that attempt can only fail — a warning
    // there is an unmount that worked, reported as one that did not, in every
    // client log there is.
    assert!(
        !said.contains("WARN"),
        "an unmount that succeeded warned:\n{said}"
    );
}

/// `--direct-io` is reachable from the command line an operator types, not just
/// from the library — and a mount that takes it serves the namespace exactly as
/// one that does not.
///
/// The flag reaches the manual page by the same route: `src/cli.rs` is compiled
/// into this binary and into the build script that renders `voidport.1`, so a
/// flag `--help` accepts is a flag the page documents.
#[test]
fn the_binary_mounts_with_direct_io() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("cli-direct-io");
    let mountpoint = fixture.directory.directory("mnt-direct-io");
    let url = fixture.tcp_url("project", "/project");

    let mounted = Mounted::start_with(
        &url,
        &mountpoint,
        &mountpoint.join("file.txt"),
        &["--direct-io"],
    );
    assert_eq!(
        std::fs::read(mountpoint.join("file.txt")).expect("the mount serves"),
        b"worked example"
    );

    let umount = voidport()
        .arg("umount")
        .arg(&mountpoint)
        .output()
        .expect("the binary runs");
    assert!(
        umount.status.success(),
        "umount failed: {}",
        String::from_utf8_lossy(&umount.stderr)
    );
    let output = mounted.finish();
    assert!(
        output.status.success(),
        "the mount process exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_url_the_grammar_refuses_is_reported_and_exits_nonzero() {
    let output = voidport()
        .args(["mount", "voidport://host/@ns", "/nonexistent-mountpoint"])
        .output()
        .expect("the binary runs");
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("cannot mount"), "{message}");
    assert!(message.contains("no port"), "{message}");
}

#[test]
fn unmounting_something_that_is_not_a_mountpoint_is_reported_and_exits_nonzero() {
    let directory = support::TempDir::new("cli-umount");
    let output = voidport()
        .arg("umount")
        .arg(directory.path())
        .output()
        .expect("the binary runs");
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("cannot unmount"), "{message}");
}
