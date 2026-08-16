//! Shared scaffolding for the server's integration tests.
//!
//! Everything here exists to make the tests talk to a *real* server: a real
//! temporary directory, a real state file, a real unix socket. Nothing is
//! mocked, because the properties under test — atomic persistence, the bind
//! contract, clean shutdown — only exist against a real filesystem.
#![allow(dead_code, reason = "each integration test file uses part of this")]

pub mod fixture;
pub mod wire;

use std::fs;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use voidportd::state::Environment;
use voidportd::testing::{create_directory, pinned_environment, scratch_root};

// Re-exported so the test files import their scaffolding from one place; each
// file uses part of it, as the allow at the top of this module already says.
#[allow(
    unused_imports,
    reason = "each integration test file uses part of this"
)]
pub use voidportd::testing::{ControlClient, RunningServer, daemon_config, open_descriptors};

/// Distinguishes temporary directories created within one process.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A temporary directory that removes itself.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates a uniquely named directory under
    /// [`scratch_root`](voidportd::testing::scratch_root) — the server's
    /// sockets are bound inside it, so its depth is bounded by `sun_path`
    /// and not by `$TMPDIR`.
    #[must_use]
    pub fn new(label: &str) -> Self {
        let nanos = SystemTime::UNIX_EPOCH
            .elapsed()
            .map_or(0, |elapsed| elapsed.as_nanos());
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = scratch_root().join(format!(
            "voidportd-{label}-{}-{sequence}-{nanos}",
            std::process::id()
        ));
        create_directory(&path);
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
    ///
    /// Graft targets are pinned when a namespace is built, so a state file or
    /// a mutation naming one needs it to exist first.
    pub fn directory(&self, name: &str) -> PathBuf {
        let path = self.join(name);
        create_directory(&path);
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

/// The hermetic environment the tests build state in: a pinned identity, so
/// sentinel resolution does not depend on who runs the suite.
#[must_use]
pub fn environment(state_dir: &Path) -> Environment {
    pinned_environment(state_dir)
}

/// Data-plane clients against a running server.
///
/// The runner itself is shared with the other suites and knows nothing about
/// the wire; the wire client is this suite's own. They meet here.
pub trait Dial {
    /// A data-plane client, connected but not handshaken.
    fn dial(&self) -> wire::WireClient;

    /// A data-plane client, connected and handshaken onto a namespace.
    fn mount(&self, namespace: &str, subpath: &str) -> wire::WireClient;
}

impl Dial for RunningServer {
    fn dial(&self) -> wire::WireClient {
        wire::WireClient::tcp(self.data_tcp()).expect("the data listener accepts connections")
    }

    /// Panics if the handshake is refused: the tests that expect a refusal do
    /// the handshake themselves.
    fn mount(&self, namespace: &str, subpath: &str) -> wire::WireClient {
        let mut client = self.dial();
        client
            .hello(namespace, subpath)
            .unwrap_or_else(|status| panic!("mounting {namespace}{subpath} failed: {status}"));
        client
    }
}

/// Waits until a control socket accepts a connection, or gives up.
///
/// Used only for servers started as a separate process, where readiness cannot
/// be observed directly.
pub fn wait_for_socket(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if UnixStream::connect(path).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// Waits until a path is gone, or gives up.
pub fn wait_for_removal(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    !path.exists()
}
