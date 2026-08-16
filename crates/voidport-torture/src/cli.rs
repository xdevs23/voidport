//! The command line.
//!
//! The defaults are sized for a development VM of this shape — tens of cores,
//! tens of gigabytes — and are meant to leave it usable: ten classes at two
//! workers each is twenty threads of filesystem load, which saturates the
//! server without taking the machine away from whoever is watching. `--duration`
//! and `--intensity` are the two knobs that turn a smoke run into an
//! hours-long soak.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use voidport_torture::metrics::Class;

/// The voidport torture harness.
#[derive(Debug, Parser)]
#[command(name = "voidport-torture", version, about)]
pub struct Cli {
    /// The voidport URL to mount, as `voidport mount` takes it.
    #[arg(long, value_name = "URL")]
    pub url: String,
    /// Where mountpoints and the run's own files live.
    #[arg(long, value_name = "PATH")]
    pub work_dir: PathBuf,
    /// How long to keep the load on, in seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 120)]
    pub duration: u64,
    /// Workers per class.
    #[arg(long, value_name = "N", default_value_t = 2)]
    pub intensity: u64,
    /// Mounts to hold open for the whole run. Two is what makes the
    /// contention class contend across mounts, not within one.
    #[arg(long, value_name = "N", default_value_t = 2)]
    pub mounts: u64,
    /// Which classes to drive, comma-separated. Every class by default.
    #[arg(long, value_name = "LIST", value_delimiter = ',')]
    pub classes: Vec<String>,
    /// The server's control socket, for its session, node and handle counts.
    #[arg(long, value_name = "PATH")]
    pub control_socket: Option<PathBuf>,
    /// The server process, for its descriptor, thread and memory counts.
    #[arg(long, value_name = "PID")]
    pub server_pid: Option<u32>,
    /// Append every sample and violation to this file, as JSON lines.
    #[arg(long, value_name = "PATH")]
    pub log: Option<PathBuf>,
    /// Print the report as JSON on stdout as well as the summary on stderr.
    #[arg(long)]
    pub json: bool,
}

impl Cli {
    /// The classes this invocation asked for.
    ///
    /// # Errors
    ///
    /// Names a class that does not exist, and lists the ones that do.
    pub fn classes(&self) -> anyhow::Result<Vec<Class>> {
        if self.classes.is_empty() {
            return Ok(Class::ALL.to_vec());
        }
        self.classes
            .iter()
            .map(|name| {
                Class::parse(name).map_err(|unknown| {
                    anyhow::anyhow!(
                        "unknown class {unknown:?}; the classes are {}",
                        Class::ALL
                            .iter()
                            .map(|class| class.name())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
            })
            .collect()
    }

    /// How long the load stays on.
    #[must_use]
    pub fn duration(&self) -> Duration {
        Duration::from_secs(self.duration)
    }
}
