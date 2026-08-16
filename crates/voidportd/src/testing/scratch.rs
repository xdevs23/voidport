//! Scratch space for unit tests that need a real filesystem.
//!
//! Most of this crate is pure logic and needs nothing here. The parts that are
//! not — graft pinning, contained descent, attributes, xattrs, locks — are only
//! meaningful against real inodes, so they get a real directory that removes
//! itself. Deliberately minimal: a test that needs a *server* wants
//! [`RunningServer`](super::RunningServer), and a suite's host tree and state
//! file stay with the suite.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Distinguishes scratch directories created within one process.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The mode every scratch directory ends up with, whatever the umask was.
const SCRATCH_MODE: u32 = 0o755;

/// The directory every scratch space in the workspace's suites is created
/// under.
///
/// Deliberately `/tmp` and **not** `std::env::temp_dir()`. A server's control
/// socket and its unix data listener live inside a scratch directory, and a
/// unix socket path must fit `sockaddr_un::sun_path` — 108 bytes including the
/// terminator, a limit the kernel enforces at `bind(2)` and nothing in a path
/// API hints at. `$TMPDIR` is not bounded: a nix shell sets one per shell and
/// nests them, so a suite run from two nested shells inherits a base long
/// enough to leave no room for the rest, and every socket-binding test in the
/// workspace fails on `path must be shorter than SUN_LEN` — a failure about
/// nothing the tests are about. `/tmp` is short, always present, and
/// traversable, which the client suite's `allow_other` case needs as well.
///
/// Scratch names are correspondingly kept short: label, pid and a counter, no
/// timestamp.
#[must_use]
pub fn scratch_root() -> &'static Path {
    Path::new("/tmp")
}

/// Creates a scratch directory, and its parents, with a mode no umask can take
/// away.
///
/// Every suite in the workspace creates its scratch space through this, and the
/// mode is restated for the same reason
/// [`crate::state::persist`](crate::state) restates the state file's: the
/// process umask filters what `mkdir` is given, and this process's umask is not
/// a constant. A server bound anywhere in it tightens the umask to `0o177`
/// around `bind(2)` — deliberately, so a socket is never momentarily
/// group-readable — and the umask is process-global, so a directory another
/// thread creates inside that window comes out `0o600`: no execute bit, and
/// therefore nothing can be created inside it afterwards.
///
/// The suites run servers in their own process, so the window is real and the
/// collision is a race. It is invisible to a run as root — root traverses a
/// directory whatever its bits say — and it fails as `EACCES` for every other
/// user, which is to say: green in a development shell, red in a build sandbox,
/// and in a different test each time. Restating the mode ends the whole class.
///
/// # Panics
///
/// If the directory cannot be created or its mode cannot be set. A suite that
/// has no scratch space has nothing to test.
pub fn create_directory(path: &Path) {
    // One component at a time, not `create_dir_all`, because **every**
    // directory this call creates needs the restatement — not only the last
    // one. `create_dir_all("…/tree/sub")` makes two, and a `tree` left at
    // `0o600` is a directory `sub` cannot then be created in.
    //
    // A component that already exists is left exactly as it is: the root of the
    // walk is `/` and then `/tmp`, and neither is this function's to re-mode.
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => {
                fs::set_permissions(&current, fs::Permissions::from_mode(SCRATCH_MODE))
                    .expect("a temporary directory whose mode is ours to state");
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!(
                "a writable temporary directory: {} could not be created: {error}",
                current.display()
            ),
        }
    }
}

/// A uniquely named temporary directory that removes itself when dropped.
#[derive(Debug)]
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// Creates a scratch directory labelled with its purpose, under
    /// [`scratch_root`].
    pub fn new(label: &str) -> Self {
        let path = scratch_root().join(format!(
            "voidportd-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        create_directory(&path);
        Self { path }
    }

    /// The directory itself.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A path inside the directory, whether or not anything is there.
    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// The directory's path as configuration would spell it.
    pub fn as_target(&self) -> String {
        self.path.display().to_string()
    }

    /// Creates a subdirectory and returns its path as configuration would
    /// spell it.
    pub fn directory(&self, name: &str) -> String {
        let path = self.join(name);
        create_directory(&path);
        path.display().to_string()
    }

    /// Writes a file inside the directory and returns its path.
    pub fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.join(name);
        if let Some(parent) = path.parent() {
            create_directory(parent);
        }
        fs::write(&path, contents).expect("a writable temporary file");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::net::UnixListener;

    /// The property [`scratch_root`] exists for. The label is longer than any
    /// suite's, and the socket name is the longest one the suites bind.
    #[test]
    fn a_socket_inside_a_scratch_directory_binds_whatever_tmpdir_says() {
        let scratch = Scratch::new("a-label-as-long-as-any-suite-would-choose");
        let path = scratch.join("control.sock");
        assert!(
            path.as_os_str().as_bytes().len() < 108,
            "{} does not fit sun_path",
            path.display()
        );
        UnixListener::bind(&path).expect("a scratch directory holds bindable socket paths");
    }

    /// A scratch directory created while a bind holds the umask tight is still
    /// a directory things can be created in.
    ///
    /// The umask is process-global and the suites bind sockets on other
    /// threads, so this window really does land on a `mkdir` now and then. As
    /// root the resulting `0o600` directory is still traversable, which is why
    /// the failure only ever showed up as one arbitrary test of the suite
    /// refusing to run in a build sandbox.
    #[test]
    fn a_scratch_directory_survives_a_concurrent_binds_umask() {
        let mode_of = |path: &Path| fs::metadata(path).expect("stat").permissions().mode() & 0o777;

        let tightened = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o177));
        let scratch = Scratch::new("umask-window");
        // Two levels in one call: the intermediate directory is created by the
        // same `mkdir` sequence and needs the same restatement, which is where
        // this went wrong the first time.
        create_directory(&scratch.join("tree").join("sub"));
        rustix::process::umask(tightened);

        for directory in [
            scratch.path().to_path_buf(),
            scratch.join("tree"),
            scratch.join("tree").join("sub"),
        ] {
            assert_eq!(
                mode_of(&directory),
                SCRATCH_MODE,
                "the umask of whatever else the process was doing decided the mode of {}",
                directory.display()
            );
        }
        fs::write(scratch.join("tree").join("sub").join("file"), b"reachable")
            .expect("a subdirectory of a scratch directory is usable");
    }
}
