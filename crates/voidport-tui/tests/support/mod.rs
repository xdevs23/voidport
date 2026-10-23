#![allow(dead_code, reason = "each test file uses part of this")]

pub mod pty;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use voidport_test_support::{RunningServer, create_directory, daemon_config, scratch_root};

#[allow(
    unused_imports,
    reason = "each integration test file uses part of this"
)]
pub use voidport_test_support::tui::{Harness, PATIENCE};

#[must_use]
pub fn patience() -> Duration {
    PATIENCE
}

/// The path of the unix listener is filled in per fixture, because two
/// suites running side by side must not use the same socket.
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

#[must_use]
pub fn state(directory: &TempDir) -> String {
    STATE.replace(
        "{data_socket}",
        &directory.join("data.sock").display().to_string(),
    )
}

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// The depth is bounded by `sun_path`, not by `$TMPDIR`, because the control
    /// socket is bound inside the directory.
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

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// The server opens graft targets when a namespace is built, so they have
    /// to exist before the server starts.
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

#[must_use]
pub fn fixture(label: &str) -> (TempDir, RunningServer) {
    let directory = TempDir::new(label);
    directory.directory("project");
    directory.directory("data");
    let state_file = directory.join("state.toml");
    fs::write(&state_file, state(&directory)).expect("a writable state file");
    let server = start(&state_file);
    (directory, server)
}

#[must_use]
pub fn start(state_file: &Path) -> RunningServer {
    let config = daemon_config(state_file);
    RunningServer::start(&config).expect("the server starts")
}

/// The path is only reported to the server, never opened by it.
#[must_use]
pub fn logging_fixture(label: &str, log_file: &Path) -> (TempDir, RunningServer) {
    let directory = TempDir::new(label);
    directory.directory("project");
    directory.directory("data");
    let state_file = directory.join("state.toml");
    fs::write(&state_file, state(&directory)).expect("a writable state file");
    let config = daemon_config(&state_file).with_log_file(log_file);
    let server = RunningServer::start(&config).expect("the server starts");
    (directory, server)
}
