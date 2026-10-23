use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context as _, Result};
use voidport_tui::{LaunchNotes, Options, Presentation, Serving};
use voidportd::daemon::Daemon;
use voidportd::launch::LaunchSummary;

pub const LOG_FILE: &str = "voidportd.log";

/// The subscriber is installed before the command line is parsed, but the
/// launch logs while it is worked out and the destination is only known
/// afterwards. So the destination moves, because `tracing` allows one
/// subscriber per process.
#[derive(Debug)]
enum Destination {
    Stderr,
    File(std::fs::File),
    Discard,
}

static DESTINATION: OnceLock<Mutex<Destination>> = OnceLock::new();

struct Diagnostics;

impl Write for Diagnostics {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut destination = destination().lock().unwrap_or_else(|poisoned| {
            // A panicking writer must not silence the log that would explain it.
            poisoned.into_inner()
        });
        match &mut *destination {
            Destination::Stderr => io::stderr().write(buffer),
            Destination::File(file) => file.write(buffer),
            Destination::Discard => Ok(buffer.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut destination = destination()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &mut *destination {
            Destination::Stderr => io::stderr().flush(),
            Destination::File(file) => file.flush(),
            Destination::Discard => Ok(()),
        }
    }
}

fn destination() -> &'static Mutex<Destination> {
    DESTINATION.get_or_init(|| Mutex::new(Destination::Stderr))
}

/// Colour is off because the same records may end up in a log file.
pub fn install() {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(|| Diagnostics)
        .with_env_filter(filter())
        .init();
}

/// An empty `RUST_LOG` counts as absent: `EnvFilter::try_from_default_env`
/// parses it into a filter that enables nothing. An unparseable value falls
/// back the same way.
fn filter() -> tracing_subscriber::EnvFilter {
    let default = || tracing_subscriber::EnvFilter::new("info");
    match std::env::var(tracing_subscriber::EnvFilter::DEFAULT_ENV) {
        Ok(directives) if !directives.trim().is_empty() => {
            tracing_subscriber::EnvFilter::try_new(directives).unwrap_or_else(|_| default())
        }
        _ => default(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Logging {
    Discard,
    File(PathBuf),
}

impl Logging {
    #[must_use]
    pub fn choose(log_file: Option<PathBuf>, state_file: Option<&Path>) -> Self {
        match (log_file, state_file) {
            (Some(path), _) => Self::File(path),
            (None, Some(state_file)) => Self::File(
                state_file
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(LOG_FILE),
            ),
            (None, None) => Self::Discard,
        }
    }

    /// Called before the interface takes over the terminal, so no log line
    /// corrupts the frame.
    ///
    /// # Errors
    ///
    /// Fails if the log file cannot be opened, leaving the destination as it
    /// was.
    pub fn redirect(&self) -> Result<()> {
        let next = match self {
            Self::Discard => Destination::Discard,
            Self::File(path) => Destination::File(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .with_context(|| format!("cannot open the log file {}", path.display()))?,
            ),
        };
        *destination()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = next;
        Ok(())
    }
}

#[must_use]
pub fn notes(summary: &LaunchSummary) -> LaunchNotes {
    LaunchNotes {
        namespace: summary.namespace.to_string(),
        mounts: summary
            .mounts
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        control_command: summary.control_command(),
        auth_note: summary.auth_note(),
    }
}

/// # Errors
///
/// Returns the failure of the interface: an unreachable socket or an unusable
/// terminal.
pub async fn attach(
    socket: PathBuf,
    terminated: impl Future<Output = ()> + Send + 'static,
) -> Result<(), voidport_tui::Error> {
    let options = Options::new(socket);
    present(options, Presentation::Attach, terminated).await
}

/// # Errors
///
/// Returns the failure of the interface, or of the daemon if it stopped on its
/// own.
pub async fn serve_and_present(
    daemon: Daemon,
    terminated: impl Future<Output = ()> + Send + 'static,
) -> Result<(), voidport_tui::Error> {
    let socket = daemon.control_socket().to_path_buf();
    let launch = daemon.launch_summary().map(|summary| notes(&summary));

    // The daemon runs on the runtime, the interface on a blocking thread.
    let (shutdown, shutdown_signal) = tokio::sync::oneshot::channel::<()>();
    let (report, stopped) = channel();
    tokio::spawn(async move {
        let result = daemon
            .serve(async {
                let _ = shutdown_signal.await;
            })
            .await;
        let _ = report.send(result.map_err(|error| error.to_string()));
    });

    let options = Options::new(socket);
    present(
        options,
        Presentation::Serving(Serving {
            notes: launch,
            shutdown: Box::new(move || {
                let _ = shutdown.send(());
            }),
            stopped,
        }),
        terminated,
    )
    .await
}

/// In raw mode Ctrl-C is a key, not a signal, so a SIGTERM or a SIGINT from
/// another terminal arrives here and is handed to the interface as a stop.
async fn present(
    options: Options,
    presentation: Presentation,
    terminated: impl Future<Output = ()> + Send + 'static,
) -> Result<(), voidport_tui::Error> {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        voidport_tui::run(&options, presentation, move |stopper| {
            handle.spawn(async move {
                terminated.await;
                stopper.stop();
            });
        })
    })
    .await
    .expect("the interface thread does not panic unobserved")
}
