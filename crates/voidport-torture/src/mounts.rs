//! The mounts the load runs over.
//!
//! Every mount the harness makes is a real FUSE mount of a real server, made
//! through the product's own [`Mount`], not a helper, and every one of
//! them is wrapped in a drop guard. That guard is not politeness: a torture run
//! that panics or is interrupted with a mount still in place leaves a
//! mountpoint that breaks every later run and even an `ls` of the directory, so
//! the teardown has to survive the run failing.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use voidport::mount::{Mount, MountOptions};
use voidport::url::MountUrl;

/// How long an unmount waits out a mountpoint that is merely still settling.
///
/// Closing a descriptor on a FUSE mount completes asynchronously — the kernel
/// does not wait for the RELEASE reply — so an unmount issued the instant a
/// worker stops can transiently report `EBUSY`. Waiting it out is what makes
/// "still mounted at the end" mean a leak, not a race.
const UNMOUNT_PATIENCE: Duration = Duration::from_secs(30);

/// One mounted namespace, unmounted when it drops however it drops.
#[derive(Debug)]
pub struct TortureMount {
    mount: Option<Mount>,
    mountpoint: PathBuf,
}

impl TortureMount {
    /// The mount root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.mountpoint
    }

    /// Unmounts, waiting out a mountpoint that is still settling.
    ///
    /// # Errors
    ///
    /// The kernel's error: anything but `EBUSY` at once, and `EBUSY` if the
    /// mountpoint is still busy when the patience runs out.
    pub fn unmount(&mut self) -> io::Result<()> {
        let Some(mount) = self.mount.as_mut() else {
            return Ok(());
        };
        let deadline = Instant::now() + UNMOUNT_PATIENCE;
        loop {
            match mount.unmount() {
                Ok(()) => {
                    self.mount = None;
                    // The mountpoint is the harness's own directory, and an
                    // unmounted one is litter, not state.
                    let _ = std::fs::remove_dir(&self.mountpoint);
                    return Ok(());
                }
                Err(error)
                    if error.raw_os_error() != Some(rustix::io::Errno::BUSY.raw_os_error())
                        || Instant::now() >= deadline =>
                {
                    return Err(error);
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }
}

impl Drop for TortureMount {
    fn drop(&mut self) {
        if let Err(error) = self.unmount() {
            eprintln!(
                "!!! voidport-torture: {} is still mounted: {error}",
                self.mountpoint.display()
            );
        }
    }
}

/// Where new mounts come from.
#[derive(Debug)]
pub struct Fleet {
    url: MountUrl,
    root: PathBuf,
    sequence: AtomicU64,
}

impl Fleet {
    /// A fleet mounting `url` on fresh mountpoints under `root`.
    ///
    /// # Errors
    ///
    /// Returns the URL's own parse error.
    pub fn new(url: &str, root: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            url: MountUrl::parse(url)?,
            root: root.to_path_buf(),
            sequence: AtomicU64::new(0),
        })
    }

    /// The URL every mount of this fleet is made from.
    #[must_use]
    pub fn url(&self) -> &MountUrl {
        &self.url
    }

    /// Mounts on a fresh mountpoint.
    ///
    /// # Errors
    ///
    /// Returns the failure to create the mountpoint or to mount on it.
    pub fn mount(&self, label: &str) -> anyhow::Result<TortureMount> {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let mountpoint = self.root.join(format!("mnt-{label}-{sequence}"));
        std::fs::create_dir_all(&mountpoint)?;
        let mount = Mount::new(&self.url, &mountpoint, &MountOptions::default())?;
        Ok(TortureMount {
            mount: Some(mount),
            mountpoint,
        })
    }
}

/// Mountpoints under `root` that the kernel still knows about.
///
/// Read from the process's own mount table, which is the only place a leak
/// would be visible after the harness has dropped everything it holds.
#[must_use]
pub fn mounted_under(root: &Path) -> Vec<String> {
    let Ok(table) = std::fs::read_to_string("/proc/self/mounts") else {
        return Vec::new();
    };
    let root = root.to_string_lossy().into_owned();
    table
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter(|point| point.starts_with(&root))
        .map(str::to_owned)
        .collect()
}

/// Loop devices backed by a file under `root`.
///
/// The harness makes none, and that is exactly why this is checked: a run that
/// ends with one is a run that left something behind.
#[must_use]
pub fn loop_devices_under(root: &Path) -> Vec<(String, String)> {
    let Ok(entries) = std::fs::read_dir("/sys/block") else {
        return Vec::new();
    };
    let root = root.to_string_lossy().into_owned();
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let device = entry.file_name().to_string_lossy().into_owned();
            let backing = std::fs::read_to_string(entry.path().join("loop/backing_file")).ok()?;
            let backing = backing.trim().to_owned();
            backing.starts_with(&root).then_some((device, backing))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two leak probes answer honestly about a directory nothing has ever
    /// mounted anything under.
    #[test]
    fn an_untouched_directory_holds_no_mounts_and_no_loop_devices() {
        let quiet = Path::new("/proc/self/fd/nothing-is-mounted-here");
        assert!(mounted_under(quiet).is_empty());
        assert!(loop_devices_under(quiet).is_empty());
    }

    /// And the mount table probe really does read the table: the root
    /// filesystem is mounted, whatever else this machine is doing.
    #[test]
    fn the_mount_table_probe_finds_a_mount_that_is_there() {
        assert!(
            mounted_under(Path::new("/"))
                .iter()
                .any(|point| point == "/"),
            "the root filesystem is mounted"
        );
    }
}
