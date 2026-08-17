//! The command line.
//!
//! The defaults are sized for a development VM of this shape — tens of cores,
//! tens of gigabytes — and are meant to leave it usable: the classes at two
//! workers each is a couple of dozen threads of filesystem load, which
//! saturates the server without taking the machine away from whoever is
//! watching. `--duration` and `--intensity` are the two knobs that turn a smoke
//! run into an hours-long soak.
//!
//! `--server-binary` is the third thing that changes what a run *is*: with it
//! the harness starts and owns the server, which is what the restart class
//! needs and what the rules and listener classes mutate.

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;

use voidport_torture::metrics::Class;

/// The voidport torture harness.
#[derive(Debug, Parser)]
#[command(name = "voidport-torture", version, about)]
pub struct Cli {
    /// The voidport URL to mount, as `voidport mount` takes it. Repeat it to
    /// put the run's mounts on more than one transport at once.
    #[arg(long = "url", value_name = "URL", required = true)]
    pub urls: Vec<String>,
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
    /// The server's control socket, for its session, node and handle counts,
    /// and for the classes that change its rules and its listeners.
    #[arg(long, value_name = "PATH")]
    pub control_socket: Option<PathBuf>,
    /// The server process, for its descriptor, thread and memory counts.
    ///
    /// Not needed with `--server-binary`: a server the harness starts is a
    /// server whose pid the harness already knows, and knows again after every
    /// restart.
    #[arg(long, value_name = "PID", conflicts_with = "server_binary")]
    pub server_pid: Option<u32>,
    /// Start and own a server, so the restart class has one to restart.
    ///
    /// Without it the harness attaches to a server somebody else runs, and the
    /// restart class is unavailable. The data address the URL names must be one
    /// that survives a restart — a unix path or a vsock port — because a tcp
    /// listener on port 0 comes back somewhere else.
    #[arg(long, value_name = "PATH", requires = "server_state")]
    pub server_binary: Option<PathBuf>,
    /// The state file that server serves.
    #[arg(long, value_name = "PATH", requires = "server_binary")]
    pub server_state: Option<PathBuf>,
    /// Where the server's own output goes, appended across restarts.
    #[arg(long, value_name = "PATH", default_value = "/dev/null")]
    pub server_log: PathBuf,
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

    /// The control socket this invocation talks to: the one it was given, or
    /// the one the server the harness starts was told to listen on.
    #[must_use]
    pub fn control_socket(&self) -> Option<PathBuf> {
        self.control_socket
            .clone()
            .or_else(|| self.server_state.as_deref().map(default_control_socket))
    }
}

/// Where a server the harness starts puts its control socket.
///
/// Beside the state file, so one directory holds everything the server owns —
/// the same arrangement the workspace's suites use.
#[must_use]
fn default_control_socket(state: &Path) -> PathBuf {
    state
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("control.sock")
}
