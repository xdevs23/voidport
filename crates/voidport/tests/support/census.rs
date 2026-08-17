//! The wire census: how many requests a mount has in flight, counted by the
//! kernel that issued them.
//!
//! A test that claims writes *overlap* has to show the overlap somewhere, and
//! the honest place is not the client's own bookkeeping — a counter voidport
//! keeps could agree with voidport's intentions while the guest kernel
//! serialized everything upstream of it, which is exactly the failure mode
//! `FOPEN_PARALLEL_DIRECT_WRITES` is about. So the census asks the kernel:
//! `fusectl` publishes `waiting` per connection, which is `fc->num_waiting` —
//! the number of requests allocated for this connection and not yet freed, i.e.
//! sent to userspace or queued to be. One write in flight reads 1; eight
//! overlapping writes read up to 8.
//!
//! The connection is found the way the kernel names it: `fuse_ctl_add_conn`
//! creates the directory from `fc->dev`, which is the superblock's device
//! number, which is the `st_dev` of every file in the mount.
//!
//! There is no skip here. `fusectl` is standard on Linux and is mounted on the
//! machine this suite runs on; a missing one is a machine that cannot answer
//! the question, and the suite says so instead of passing vacuously.

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// Where `fusectl` publishes a connection's counters.
const CONNECTIONS: &str = "/sys/fs/fuse/connections";

/// How often the sampler looks. Fine enough that a burst of writes lasting
/// milliseconds is sampled hundreds of times, cheap enough that the sampler is
/// not what the machine is busy with — and it touches `sysfs` only, so it adds
/// no request to the connection it is counting.
const INTERVAL: Duration = Duration::from_micros(200);

/// The `waiting` file of one mount's FUSE connection.
#[derive(Debug)]
pub struct Census {
    waiting: PathBuf,
}

impl Census {
    /// Finds the connection behind a mounted path.
    ///
    /// # Panics
    ///
    /// If the path is not on a FUSE mount whose connection `fusectl` publishes.
    #[must_use]
    pub fn of(mounted: &Path) -> Self {
        let device = fs::metadata(mounted)
            .unwrap_or_else(|error| panic!("{} should stat: {error}", mounted.display()))
            .dev();
        let waiting = Path::new(CONNECTIONS)
            .join(device.to_string())
            .join("waiting");
        assert!(
            waiting.exists(),
            "no fuse connection {device} under {CONNECTIONS} for {}: the census cannot count \
             what it cannot find (is fusectl mounted?)",
            mounted.display()
        );
        Self { waiting }
    }

    /// How many requests are in flight right now.
    #[must_use]
    pub fn waiting(&self) -> usize {
        let text = fs::read_to_string(&self.waiting)
            .unwrap_or_else(|error| panic!("{} should read: {error}", self.waiting.display()));
        text.trim()
            .parse()
            .unwrap_or_else(|error| panic!("{} held {text:?}: {error}", self.waiting.display()))
    }

    /// Runs `work`, sampling throughout, and reports the most it ever saw in
    /// flight alongside whatever `work` returned.
    ///
    /// The sampling is the point: the count after the work is the count of an
    /// idle mount, and would prove nothing about a peak.
    pub fn peak_during<T>(&self, work: impl FnOnce() -> T) -> (T, usize) {
        let stop = Arc::new(AtomicBool::new(false));
        let sampler = {
            let waiting = self.waiting.clone();
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let census = Self { waiting };
                let mut peak = 0;
                while !stop.load(Ordering::Relaxed) {
                    peak = peak.max(census.waiting());
                    thread::sleep(INTERVAL);
                }
                peak
            })
        };
        let value = work();
        stop.store(true, Ordering::Relaxed);
        let peak = sampler.join().expect("the sampler finishes");
        (value, peak)
    }
}
