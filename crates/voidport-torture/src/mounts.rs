//! A torture run that panics or is interrupted with a mount still in place
//! leaves a mountpoint that breaks every later run, so every mount unmounts
//! itself on drop.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use voidport::guardian::Launch;
use voidport::mount::{Mount, MountOptions, TeardownError};
use voidport::url::MountUrl;

use crate::connections::{Connection, Connections, Registration};

pub const GUARDIAN: &str = "guardian";

/// Closing a descriptor on a FUSE mount completes asynchronously, because the
/// kernel does not wait for the RELEASE reply, so an unmount issued the
/// instant a worker stops can report `EBUSY`. Waiting it out makes "still
/// mounted at the end" mean a leak, not a race.
const UNMOUNT_PATIENCE: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct TortureMount {
    mount: Option<Mount>,
    mountpoint: PathBuf,
    url: MountUrl,
    listed: Option<Registration>,
}

impl TortureMount {
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.mountpoint
    }

    /// Stored with the mount, never recomputed: it is the one source for the
    /// namespace, the subpath and the endpoint that a worker derives from the
    /// mount.
    #[must_use]
    pub fn url(&self) -> &MountUrl {
        &self.url
    }

    #[cfg(test)]
    pub(crate) fn unmounted(mountpoint: PathBuf, url: MountUrl) -> Self {
        Self {
            mount: None,
            mountpoint,
            url,
            listed: None,
        }
    }

    pub fn unmount(&mut self) -> Result<(), TeardownError> {
        let Some(mount) = self.mount.as_mut() else {
            return Ok(());
        };
        let deadline = Instant::now() + UNMOUNT_PATIENCE;
        loop {
            match mount.unmount() {
                Ok(()) => {
                    self.mount = None;
                    self.listed = None;
                    // An unmounted mountpoint is litter, not state.
                    let _ = std::fs::remove_dir(&self.mountpoint);
                    return Ok(());
                }
                Err(TeardownError::Unmount(busy))
                    if busy.raw_os_error() == Some(rustix::io::Errno::BUSY.raw_os_error())
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => return Err(error),
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

/// A fleet contains every URL the run was given, because mounts are dealt out
/// over them in order: a two-URL run with two mounts puts one on each.
#[derive(Debug)]
pub struct Fleet {
    urls: Vec<MountUrl>,
    root: PathBuf,
    guardian: Launch,
    sequence: AtomicU64,
    connections: Arc<Connections>,
}

impl Fleet {
    pub fn new(
        urls: &[String],
        root: &Path,
        guardian: Launch,
        connections: Arc<Connections>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(!urls.is_empty(), "a run needs at least one URL to mount");
        Ok(Self {
            urls: urls
                .iter()
                .map(|url| MountUrl::parse(url))
                .collect::<Result<_, _>>()?,
            root: root.to_path_buf(),
            guardian,
            sequence: AtomicU64::new(0),
            connections,
        })
    }

    #[must_use]
    pub fn url(&self, index: u64) -> &MountUrl {
        &self.urls[index as usize % self.urls.len()]
    }

    #[must_use]
    pub fn urls(&self) -> &[MountUrl] {
        &self.urls
    }

    /// The caller passes the URL instead of an index into the fleet, so that
    /// the mount and everything a worker derives from that URL cannot come
    /// apart.
    pub fn mount(&self, label: &str, url: &MountUrl) -> anyhow::Result<TortureMount> {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let mountpoint = self.root.join(format!("mnt-{label}-{sequence}"));
        std::fs::create_dir_all(&mountpoint)?;
        let mount = Mount::new(url, &mountpoint, &MountOptions::default(), &self.guardian)?;
        let listed = self.connections.register(Connection::Kernel {
            mountpoint: mountpoint.clone(),
            abort: mount.abort_handle(),
        });
        Ok(TortureMount {
            mount: Some(mount),
            mountpoint,
            url: url.clone(),
            listed: Some(listed),
        })
    }
}

/// Mountpoints under `root` that the kernel still knows about, read from the
/// mount table of the process, the only place a leak is visible after the
/// harness dropped everything it holds.
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

/// Loop devices backed by a file under `root`. The harness makes none, so a run
/// that ends with one left something behind.
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
pub(crate) mod tests {
    use super::*;

    pub(crate) fn guardian() -> Launch {
        Launch {
            program: PathBuf::from("/proc/self/exe"),
            arguments: vec![GUARDIAN.into()],
        }
    }

    #[test]
    fn an_untouched_directory_holds_no_mounts_and_no_loop_devices() {
        let quiet = Path::new("/proc/self/fd/nothing-is-mounted-here");
        assert!(mounted_under(quiet).is_empty());
        assert!(loop_devices_under(quiet).is_empty());
    }

    #[test]
    fn a_fleet_deals_its_mounts_over_every_url_it_was_given() {
        let urls = [
            "voidport://127.0.0.1:9000/@work".to_owned(),
            "voidport+vsock://1:9001/@work".to_owned(),
        ];
        let fleet = Fleet::new(&urls, Path::new("/tmp"), guardian(), Arc::default())
            .expect("two parseable URLs");
        assert_eq!(fleet.urls().len(), 2);
        assert_eq!(fleet.url(0), &fleet.urls()[0]);
        assert_eq!(fleet.url(1), &fleet.urls()[1]);
        assert_eq!(fleet.url(2), &fleet.urls()[0]);

        assert!(Fleet::new(&[], Path::new("/tmp"), guardian(), Arc::default()).is_err());
    }

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
