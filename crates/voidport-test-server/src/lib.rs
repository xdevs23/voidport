#![forbid(unsafe_code)]

pub mod fixture;
pub mod wire;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use voidport_test_support::{create_directory, scratch_root};
use voidportd::state::Environment;

pub use voidport_test_support::{
    ControlClient, RunningServer, daemon_config, descriptor_flags, open_descriptors,
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
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
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A fixed identity, so what the sentinels resolve to does not depend on who runs
/// the suite.
#[must_use]
pub fn environment(state_dir: &Path) -> Environment {
    Environment::new(4242, 4243, state_dir)
}

pub trait Dial {
    fn dial(&self) -> wire::WireClient;

    fn mount(&self, namespace: &str, subpath: &str) -> wire::WireClient;
}

impl Dial for RunningServer {
    fn dial(&self) -> wire::WireClient {
        wire::WireClient::tcp(self.data_tcp()).expect("the data listener accepts connections")
    }

    /// Panics if the handshake fails: the tests that expect it to fail do the
    /// handshake themselves.
    fn mount(&self, namespace: &str, subpath: &str) -> wire::WireClient {
        let mut client = self.dial();
        client
            .hello(namespace, subpath)
            .unwrap_or_else(|status| panic!("mounting {namespace}{subpath} failed: {status}"));
        client
    }
}
