//! The fixture this suite drives the interface against.
//!
//! The driver itself is [`voidport_tui::harness::Harness`] — the app loop with
//! the terminal removed, shared with every other suite that needs one. What
//! lives here is only what is true of *this* suite: the state file it serves
//! and the temporary directory it serves out of.
#![allow(dead_code, reason = "each test file uses part of this")]

pub mod pty;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use voidportd::testing::{
    RunningServer, create_directory, daemon_config, pinned_environment, scratch_root,
};

#[allow(
    unused_imports,
    reason = "each integration test file uses part of this"
)]
pub use voidport_tui::harness::{Harness, PATIENCE};

/// How long a test waits for the server to answer before giving up.
#[must_use]
pub fn patience() -> Duration {
    PATIENCE
}

/// A state file with both transports and one namespace to mutate.
///
/// The unix listener's path is filled in per fixture: a listener path is not a
/// host target, so it resolves as the process sees it, and two suites running
/// side by side must not name the same socket.
pub const STATE: &str = r#"
[[server.listeners]]
transport = "tcp"
addr = "127.0.0.1:0"

[[server.listeners]]
transport = "unix"
path = "{data_socket}"

[[namespaces]]
name = "project"

[[namespaces.rules]]
path = "/project"
mode = "rw"
target = "project"
"#;

/// [`STATE`] with its socket path filled in.
#[must_use]
pub fn state(directory: &TempDir) -> String {
    STATE.replace(
        "{data_socket}",
        &directory.join("data.sock").display().to_string(),
    )
}

/// Distinguishes temporary directories created within one process.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A temporary directory that removes itself.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates a uniquely named directory under
    /// [`scratch_root`](voidportd::testing::scratch_root), whose depth is
    /// bounded by `sun_path`, not by `$TMPDIR`: the server's control
    /// socket is bound inside it.
    #[must_use]
    pub fn new(label: &str) -> Self {
        let path = scratch_root().join(format!(
            "voidport-tui-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        create_directory(&path);
        Self { path }
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A path inside it.
    #[must_use]
    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Creates a subdirectory. Graft targets are pinned when a namespace is
    /// built, so they have to exist before the server starts.
    pub fn directory(&self, name: &str) -> PathBuf {
        let path = self.join(name);
        create_directory(&path);
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A temporary directory holding [`STATE`], and a server serving it.
#[must_use]
pub fn fixture(label: &str) -> (TempDir, RunningServer) {
    let directory = TempDir::new(label);
    directory.directory("project");
    directory.directory("data");
    let state_file = directory.join("state.toml");
    fs::write(&state_file, state(&directory)).expect("a writable state file");
    let server = start(&state_file, directory.path());
    (directory, server)
}

/// Starts a server on an existing state file — used again to prove that the
/// interface reconnects to a *restarted* server.
#[must_use]
pub fn start(state_file: &Path, directory: &Path) -> RunningServer {
    let config = daemon_config(state_file, pinned_environment(directory));
    RunningServer::start(&config).expect("the server starts")
}

/// [`fixture`], with the server told where its tracing goes.
///
/// The path is only reported, never opened by the server: the process's
/// subscriber is the binary's business, and a suite has no subscriber of its
/// own. What this fixture proves is the path arriving over the control
/// protocol and the interface tailing whatever is at it.
#[must_use]
pub fn logging_fixture(label: &str, log_file: &Path) -> (TempDir, RunningServer) {
    let directory = TempDir::new(label);
    directory.directory("project");
    directory.directory("data");
    let state_file = directory.join("state.toml");
    fs::write(&state_file, state(&directory)).expect("a writable state file");
    let config =
        daemon_config(&state_file, pinned_environment(directory.path())).with_log_file(log_file);
    let server = RunningServer::start(&config).expect("the server starts");
    (directory, server)
}
