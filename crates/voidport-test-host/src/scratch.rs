use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

const SCRATCH_MODE: u32 = 0o755;

/// Not `std::env::temp_dir()`: a unix socket path must fit `sun_path` (108 bytes),
/// and nested nix shells make `$TMPDIR` too long for it.
#[must_use]
pub fn scratch_root() -> &'static Path {
    Path::new("/tmp")
}

/// Sets the mode of every directory it creates. The umask is process-global, and
/// a `bind` on another thread tightens it to `0o177`, which would leave a
/// directory without an execute bit.
pub fn create_directory(path: &Path) {
    // One component at a time, because every directory created needs the mode,
    // also the ones above the last. Existing components are left as they are.
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

#[derive(Debug)]
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    pub fn new(label: &str) -> Self {
        let path = scratch_root().join(format!(
            "voidportd-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        create_directory(&path);
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub fn as_target(&self) -> String {
        self.path.display().to_string()
    }

    pub fn directory(&self, name: &str) -> String {
        let path = self.join(name);
        create_directory(&path);
        path.display().to_string()
    }

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

    #[test]
    fn a_scratch_directory_survives_a_concurrent_binds_umask() {
        let mode_of = |path: &Path| fs::metadata(path).expect("stat").permissions().mode() & 0o777;

        let tightened = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o177));
        let scratch = Scratch::new("umask-window");
        // Two levels: the intermediate directory needs the mode too.
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
