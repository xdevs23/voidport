#![forbid(unsafe_code)]

use voidport_test_client as support;

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Output};

use support::{Fixture, fuse_client};
use voidport_spawn::{Program, Stream};
use voidport_test_support::{ReadinessSocket, Startup};

/// This process never opens a file or directory inside a mount, so no
/// descriptor of it can make the mount busy when the test unmounts it.
fn read_in_child(path: &Path) -> Vec<u8> {
    let output = Program::new("cat").arg(path).output().expect("cat runs");
    assert!(
        output.status.success(),
        "cat {} failed: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

struct Mounted {
    child: Option<Child>,
    mountpoint: PathBuf,
}

impl Mounted {
    fn start(url: &str, mountpoint: &Path, probe: &Path) -> Self {
        let readiness = ReadinessSocket::bind(mountpoint.with_extension("notify"));
        let child = fuse_client()
            .env("NOTIFY_SOCKET", readiness.path())
            .args(["mount", url])
            .arg(mountpoint)
            .stdout(Stream::Piped)
            .stderr(Stream::Piped)
            .spawn()
            .expect("the binary runs");
        let mounted = Self {
            child: Some(child),
            mountpoint: mountpoint.to_path_buf(),
        };
        assert_eq!(
            readiness.wait_for(mounted.child.as_ref().expect("mount process")),
            Startup::Ready,
            "the mount process exited before it reported readiness"
        );
        assert!(
            probe.exists(),
            "the acknowledged mount serves its namespace"
        );
        mounted
    }

    fn finish(mut self) -> Output {
        self.child
            .take()
            .expect("the mount is still running")
            .wait_with_output()
            .expect("the child reports")
    }
}

impl Drop for Mounted {
    /// A mount the test failed to take down must not outlive it: a stale FUSE
    /// mountpoint breaks every later run.
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let _ = fuse_client().arg("umount").arg(&self.mountpoint).status();
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn the_binary_mounts_and_unmounts() {
    support::preflight();
    let fixture = Fixture::start("cli-mount");
    let mountpoint = fixture.directory.directory("mnt-cli");
    let url = fixture.tcp_url("project", "/project");

    let mounted = Mounted::start(&url, &mountpoint, &mountpoint.join("file.txt"));
    assert_eq!(
        read_in_child(&mountpoint.join("file.txt")),
        b"worked example"
    );
    assert!(fixture.sessions().len() == 1, "{:?}", fixture.sessions());

    let umount = fuse_client()
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
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the mount process exited with {}: {said}",
        output.status,
    );
    // A warning here would report a successful unmount as a failed one in every
    // client log.
    assert!(
        !said.contains("WARN"),
        "an unmount that succeeded warned:\n{said}"
    );
}

#[test]
fn a_mount_that_cannot_report_readiness_exits_with_an_error_and_unmounts() {
    support::preflight();
    let fixture = Fixture::start("cli-notify-unreachable");
    let mountpoint = fixture.directory.directory("mnt-notify");
    let url = fixture.tcp_url("project", "/project");

    let output = fuse_client()
        .env("NOTIFY_SOCKET", fixture.directory.join("nobody.notify"))
        .args(["mount", &url])
        .arg(&mountpoint)
        .output()
        .expect("the binary runs");

    assert!(
        !output.status.success(),
        "the mount must exit with an error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let beside = std::fs::metadata(fixture.directory.path()).expect("the directory");
    let here = std::fs::metadata(&mountpoint).expect("the mountpoint is a directory again");
    assert_eq!(here.dev(), beside.dev(), "nothing is left mounted there");
}

#[test]
fn a_url_the_grammar_refuses_is_reported_and_exits_nonzero() {
    let output = fuse_client()
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
    let output = fuse_client()
        .arg("umount")
        .arg(directory.path())
        .output()
        .expect("the binary runs");
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("cannot unmount"), "{message}");
}
