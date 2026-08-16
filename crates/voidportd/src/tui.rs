//! Binary-only wiring for `voidportd --tui`.
//!
//! This module belongs to the `voidportd` **binary**, not to its library: the
//! design keeps the daemon library free of any user interface, and the
//! `voidport-tui` crate is a dependency of the binary alone. What lives here is
//! exactly the glue neither side may own —
//!
//! * turning a [`LaunchSummary`] into the value the Overview renders (the
//!   TUI crate cannot depend on this one, since the dependency runs the other
//!   way);
//! * giving the interface the three capabilities it needs to supervise a
//!   daemon it did not create: shut it down, learn that it stopped, and be
//!   told to stop from outside;
//! * sending the daemon's tracing to a file, because in a TUI the terminal
//!   belongs to the interface and a log line drawn over it would corrupt the
//!   frame.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context as _, Result};
use voidport_tui::{LaunchNotes, Options, Presentation, Serving};
use voidportd::daemon::Daemon;
use voidportd::launch::LaunchSummary;

/// The log file a serve-and-present launch writes beside its state file.
pub const LOG_FILE: &str = "voidportd.log";

/// Where every tracing record this process emits is written.
///
/// One subscriber is installed before the command line is even looked at, and
/// this is the writer behind it. It has to be switchable, not chosen at
/// install time because the two facts arrive in the wrong order: the launch
/// logs things while it is being *worked out* — most plainly the state file
/// `share` picked when nobody named one, which the contract says it "logs the
/// path it chose" — and where those records belong is only known once it *has*
/// been worked out. A subscriber installed after the decision drops every
/// record made during it, and `tracing` allows exactly one subscriber per
/// process, so the destination moves instead of the subscriber.
#[derive(Debug)]
enum Destination {
    /// The ordinary daemon destination: stderr, so stdout carries only what the
    /// operator is meant to act on.
    Stderr,
    /// A file, appended to, while a TUI owns the terminal.
    File(std::fs::File),
    /// Nowhere: attach mode with no `--log-file`.
    Discard,
}

/// The one destination, and the lock that lets it be replaced.
static DESTINATION: OnceLock<Mutex<Destination>> = OnceLock::new();

/// The writer the subscriber holds: a handle to whatever [`DESTINATION`] is
/// now.
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

/// The destination, defaulting to stderr.
fn destination() -> &'static Mutex<Destination> {
    DESTINATION.get_or_init(|| Mutex::new(Destination::Stderr))
}

/// Installs the process's one subscriber, writing to stderr.
///
/// Called before the command line is turned into a plan, so that everything the
/// planning itself has to say is recorded somewhere, not dropped.
/// Colour is off unconditionally: the same records may end up in a file the
/// moment [`Logging::redirect`] is called, and escape sequences in a log file
/// are noise nobody asked for.
pub fn install() {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(|| Diagnostics)
        .with_env_filter(filter())
        .init();
}

/// What `RUST_LOG` asks for, or `info`.
///
/// An **empty** `RUST_LOG` is treated as an absent one, which
/// `EnvFilter::try_from_default_env` does not do: an empty value parses
/// successfully into a filter with no directives, and a filter with no
/// directives enables nothing at all. A daemon that silently stops logging
/// because something in the environment exported `RUST_LOG=` — a build sandbox
/// does exactly that — is a diagnostic hole that only shows up when the
/// diagnostics are needed. A value that is set but unparseable falls back the
/// same way instead of taking the server down over a log filter.
fn filter() -> tracing_subscriber::EnvFilter {
    let default = || tracing_subscriber::EnvFilter::new("info");
    match std::env::var(tracing_subscriber::EnvFilter::DEFAULT_ENV) {
        Ok(directives) if !directives.trim().is_empty() => {
            tracing_subscriber::EnvFilter::try_new(directives).unwrap_or_else(|_| default())
        }
        _ => default(),
    }
}

/// Where the daemon's tracing goes while a TUI owns the terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Logging {
    /// Nowhere: attach mode with no `--log-file`. The interface presents a
    /// server whose own diagnostics are that server's business.
    Discard,
    /// A file, appended to.
    File(PathBuf),
}

impl Logging {
    /// Where a TUI launch logs: `--log-file` if given, else a file beside the
    /// state file for a serving launch, else nowhere.
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

    /// Sends everything from here on to this destination.
    ///
    /// The terminal belongs to the interface from the moment it is taken over,
    /// and a log line drawn over the frame would corrupt it — so this is called
    /// before the takeover, and after it nothing this process logs reaches the
    /// terminal.
    ///
    /// # Errors
    ///
    /// Fails if the log file cannot be opened, leaving the destination as it
    /// was so the failure itself is still reportable.
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

/// What the Overview shows for a seeded launch.
///
/// A straight translation: the daemon owns the wording of a mount command and
/// of the plain-transport note, and the interface owns how they are laid out.
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

/// Attaches to a running server's control socket.
///
/// # Errors
///
/// Returns the interface's own failure: a socket that cannot be reached (raised
/// before the terminal is touched) or a terminal that cannot be used.
pub async fn attach(socket: PathBuf) -> Result<(), voidport_tui::Error> {
    let options = Options::new(socket);
    present(options, Presentation::Attach).await
}

/// Serves and presents one daemon: the TUI is the foreground, and quitting it
/// shuts the server down.
///
/// # Errors
///
/// Returns the interface's failure, or the daemon's if it stopped on its own.
pub async fn serve_and_present(daemon: Daemon) -> Result<(), voidport_tui::Error> {
    let socket = daemon.control_socket().to_path_buf();
    let launch = daemon.launch_summary().map(|summary| notes(&summary));

    // The daemon runs on the runtime; the interface runs on a blocking thread.
    // The two meet through exactly three things: a shutdown signal, a "it has
    // stopped" report, and the socket they both name.
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
    )
    .await
}

/// Runs the interface on a blocking thread, with SIGINT/SIGTERM wired to it.
///
/// The interface is a blocking loop and the runtime has to keep turning under
/// it — the daemon it presents is running there. Signals are the runtime's job
/// too: in raw mode Ctrl-C is a key, not a signal, so a SIGTERM (or a
/// SIGINT from another terminal) arrives here and is handed to the interface
/// as an ordinary stop.
async fn present(options: Options, presentation: Presentation) -> Result<(), voidport_tui::Error> {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        voidport_tui::run(&options, presentation, move |stopper| {
            handle.spawn(async move {
                crate::terminated().await;
                stopper.stop();
            });
        })
    })
    .await
    .expect("the interface thread does not panic unobserved")
}
