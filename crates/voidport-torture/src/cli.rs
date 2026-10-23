use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use voidport_torture::metrics::Class;
use voidport_torture::mounts::GUARDIAN;

/// The voidport torture harness.
#[derive(Debug, Parser)]
#[command(
    name = "voidport-torture",
    version,
    about,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
pub struct Cli {
    /// The command that runs the guardian of a mount, in place of a run.
    #[command(subcommand)]
    pub command: Option<Command>,
    /// The run.
    #[command(flatten)]
    pub run: Option<Run>,
}

/// What runs in place of a run.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Runs the guardian of a mount, which every mount of a run starts with
    /// its end of a socket pair as standard input.
    #[command(name = GUARDIAN, hide = true)]
    Guardian,
}

/// What a run does.
#[derive(Debug, Args)]
pub struct Run {
    /// The voidport URL to mount, as `voidport mount` takes it. Repeat it to
    /// put the run's mounts on more than one transport at once.
    #[arg(long = "url", value_name = "URL", required = true)]
    pub urls: Vec<String>,
    /// Where mountpoints and the files of the run live.
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
    /// Which classes to run, comma-separated. Every class by default.
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
    /// Start a server and manage it, so the restart class has one to restart.
    ///
    /// Without it the harness attaches to a server somebody else runs, and the
    /// restart class is unavailable. The data address in the URL must be one
    /// that survives a restart, a unix path or a vsock port, because a tcp
    /// listener on port 0 comes back on another port.
    #[arg(long, value_name = "PATH", requires = "server_state")]
    pub server_binary: Option<PathBuf>,
    /// The state file used by that server.
    #[arg(long, value_name = "PATH", requires = "server_binary")]
    pub server_state: Option<PathBuf>,
    /// Where the output of the server goes, appended across restarts.
    #[arg(long, value_name = "PATH", default_value = "/dev/null")]
    pub server_log: PathBuf,
    /// Append every sample and violation to this file, as JSON lines.
    #[arg(long, value_name = "PATH")]
    pub log: Option<PathBuf>,
    /// Print the report as JSON on stdout as well as the summary on stderr.
    #[arg(long)]
    pub json: bool,
}

impl Run {
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

    #[must_use]
    pub fn duration(&self) -> Duration {
        Duration::from_secs(self.duration)
    }

    #[must_use]
    pub fn control_socket(&self) -> Option<PathBuf> {
        self.control_socket
            .clone()
            .or_else(|| self.server_state.as_deref().map(default_control_socket))
    }
}

#[must_use]
fn default_control_socket(state: &Path) -> PathBuf {
    state
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("control.sock")
}
