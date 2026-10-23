//! Runs the real CLI against a real server.
//!
//! The server is the real `voidportd` library, started exactly as the daemon
//! binary starts it and served on its own thread by the runner the workspace's
//! suites share; the CLI is the real compiled binary, run as a separate
//! process. Only the process boundary between them is simulated.
#![allow(dead_code, reason = "the test file uses part of this")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use voidport_test_support::{create_directory, daemon_config, scratch_root};

pub use voidport_test_support::RunningServer;

/// Distinguishes temporary directories created within one process.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A temporary directory that removes itself.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates a uniquely named directory under
    /// [`scratch_root`](voidport_test_support::scratch_root): the server's
    /// control socket is bound inside it, so its depth is bounded by
    /// `sun_path`, not by `$TMPDIR`.
    #[must_use]
    pub fn new(label: &str) -> Self {
        let nanos = SystemTime::UNIX_EPOCH
            .elapsed()
            .map_or(0, |elapsed| elapsed.as_nanos());
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = scratch_root().join(format!(
            "voidport-ctl-{label}-{}-{sequence}-{nanos}",
            std::process::id()
        ));
        create_directory(&path);
        Self { path }
    }

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
    ///
    /// Graft targets are resolved when a namespace is built, so a rule naming
    /// one needs it to exist before the server starts or the change is applied.
    pub fn directory(&self, name: &str) -> PathBuf {
        let path = self.join(name);
        create_directory(&path);
        path
    }

    /// Writes a file inside the directory and returns its path.
    pub fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.join(name);
        fs::write(&path, contents).expect("a writable temporary file");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Starts the server the CLI runs against.
#[must_use]
pub fn server(directory: &TempDir, state: &str) -> RunningServer {
    let state_file = directory.write("state.toml", state);
    // A fixed identity, so what the CLI shows does not depend on who runs the
    // suite.
    let config = daemon_config(&state_file);
    RunningServer::start(&config).expect("the server starts")
}

/// Running the real operator CLI against a running server.
pub trait Ctl {
    /// Runs the CLI, whatever it answers.
    fn ctl(&self, arguments: &[&str]) -> Output;

    /// Runs the CLI and requires success, returning its stdout.
    fn expect_ok(&self, arguments: &[&str]) -> String;

    /// Runs the CLI and requires a nonzero exit, returning its stdout.
    fn expect_failure(&self, arguments: &[&str]) -> String;
}

impl Ctl for RunningServer {
    fn ctl(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_voidport-ctl"))
            .arg("--socket")
            .arg(self.socket())
            .args(arguments)
            .output()
            .expect("the CLI binary runs")
    }

    fn expect_ok(&self, arguments: &[&str]) -> String {
        let output = self.ctl(arguments);
        assert!(
            output.status.success(),
            "voidport-ctl {arguments:?} failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("utf-8 output")
    }

    fn expect_failure(&self, arguments: &[&str]) -> String {
        let output = self.ctl(arguments);
        assert!(
            !output.status.success(),
            "voidport-ctl {arguments:?} unexpectedly succeeded: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        String::from_utf8(output.stdout).expect("utf-8 output")
    }
}
