//! The voidport server daemon.
//!
//! A thin shell: parse arguments, start the daemon, serve both planes until a
//! termination signal arrives, and report failures as a full error chain (the
//! loader's enrichment is only useful if the binary prints it).
//!
//! Two launches, one path. `voidportd --state PATH` serves what the state file
//! holds. `voidportd share <DIR>` serves the same way, having first seeded the
//! same state file with the listeners, namespace and rule the command line
//! described — quick sharing is not a separate mode, it is a state file the
//! operator did not have to write. Everything the seeded launch produces is
//! ordinary configuration afterwards: reconfigurable through `voidport-ctl`, and
//! reproduced by a plain `--state` launch on the next restart.

mod cli;
mod tui;

use std::io;
use std::process::ExitCode;

use anyhow::{Context as _, Result, anyhow, bail};
use clap::Parser as _;
use std::path::PathBuf;
use voidport_control::{NamespaceName, ShareMode, find_control_socket};
use voidportd::daemon::{Daemon, DaemonConfig};
use voidportd::error::render;
use voidportd::seed::Seed;
use voidportd::state::Listener;

use crate::cli::{Args, Command, ShareArgs};
use crate::tui::Logging;

#[tokio::main]
async fn main() -> ExitCode {
    // Before the command line is turned into anything: working the launch out
    // is itself logged — `share` with no `--state` chooses a state file
    // and the contract says it logs the path it chose — and a subscriber
    // installed after that decision would drop exactly those records. Where
    // they go is settled afterwards, by `Logging::redirect`.
    tui::install();
    let plan = match plan(Args::parse()) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("voidportd: {error:#}");
            return ExitCode::FAILURE;
        }
    };
    // Before anything is bound, written or taken over: every launch is stopped
    // by this one future, and it is registered while a failure is still only a
    // launch that does not happen. Every branch below is handed the same
    // already-listening streams.
    let terminated = match terminated() {
        Ok(terminated) => terminated,
        Err(error) => {
            eprintln!("voidportd: {error}");
            return ExitCode::FAILURE;
        }
    };
    match plan {
        Plan::Attach { socket, logging } => {
            let socket = match attach_socket(socket) {
                Ok(socket) => socket,
                Err(error) => {
                    eprintln!("voidportd: {error:#}");
                    return ExitCode::FAILURE;
                }
            };
            if let Err(error) = logging.redirect() {
                eprintln!("voidportd: {error:#}");
                return ExitCode::FAILURE;
            }
            match tui::attach(socket, terminated).await {
                Ok(()) => ExitCode::SUCCESS,
                // Every failure the interface reports is already restored-and-
                // plain by the time it reaches here: a socket that could not be
                // reached, a terminal that could not be used, a server that
                // stopped on its own.
                Err(error) => {
                    eprintln!("voidportd: {}", render(&error));
                    ExitCode::FAILURE
                }
            }
        }
        Plan::Serve { config, present } => serve(config, present, terminated).await,
    }
}

/// Starts a server and either serves it plainly or presents it.
///
/// `terminated` is the stop this launch already listens for: both ways of
/// running a server are ended by the same future.
async fn serve(
    config: DaemonConfig,
    present: Option<Logging>,
    terminated: impl Future<Output = ()> + Send + 'static,
) -> ExitCode {
    // A plain launch keeps the destination it started with — stderr, so stdout
    // carries only what the operator is meant to act on: a seeded launch prints
    // mount commands there, and a line an operator pipes into a shell must not
    // have a log record wrapped around it. A presented one moves it off the
    // terminal, which now belongs to the interface.
    if let Some(logging) = &present
        && let Err(error) = logging.redirect()
    {
        eprintln!("voidportd: {error:#}");
        return ExitCode::FAILURE;
    }

    let daemon = match Daemon::start(&config) {
        Ok(daemon) => daemon,
        Err(error) => {
            eprintln!("voidportd: {}", render(&error));
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        state_file = %config.state_file.display(),
        control_socket = %daemon.control_socket().display(),
        namespaces = daemon.service().snapshot().registry.len(),
        "voidportd started"
    );

    if present.is_some() {
        // The launch summary is rendered in the Overview instead of stdout.
        return match tui::serve_and_present(daemon, terminated).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("voidportd: {}", render(&error));
                ExitCode::FAILURE
            }
        };
    }

    // A seeded launch owes the operator the exact line to paste into the guest,
    // built from the listeners as they actually bound.
    if let Some(summary) = daemon.launch_summary() {
        println!("{summary}");
    }

    if let Err(error) = daemon.serve(terminated).await {
        eprintln!("voidportd: {}", render(&error));
        return ExitCode::FAILURE;
    }
    tracing::info!("voidportd stopped");
    ExitCode::SUCCESS
}

/// What this launch is.
#[derive(Debug)]
enum Plan {
    /// Serve a state file; `present` says whether the operator interface is the
    /// foreground, and where the server's diagnostics go if it is.
    Serve {
        /// What to start.
        config: DaemonConfig,
        /// Present it, logging there.
        present: Option<Logging>,
    },
    /// Attach the operator interface to a server somebody else launched.
    Attach {
        /// Its control socket, when `--control-socket` named one. `None` is
        /// resolved by [`attach_socket`] once the terminal is still untouched
        /// — the lookup connects, which is not a command-line decision.
        socket: Option<PathBuf>,
        /// Where this process's own diagnostics go.
        logging: Logging,
    },
}

/// Turns the command line into a plan.
///
/// Everything that can be decided without touching a socket is decided here, so
/// a mistyped launch fails before anything is bound or written.
fn plan(args: Args) -> Result<Plan> {
    let Args {
        state,
        control_socket,
        tui,
        log_file,
        command,
    } = args;
    // `--tui` alone is attach mode: no state file means no server of our own,
    // and the socket is the only thing we need to know.
    if tui && state.is_none() && command.is_none() {
        return Ok(Plan::Attach {
            socket: control_socket,
            logging: Logging::choose(log_file, None),
        });
    }
    let mut config = match command {
        None => {
            let state = state.context(
                "no state file: pass --state PATH, use `voidportd share <DIR>` to share a \
                 directory right away, or pass --tui alone to attach to a running server",
            )?;
            DaemonConfig::new(state)
        }
        Some(Command::Share(share)) => {
            let state = match state {
                Some(state) => state,
                None => default_state_file()?,
            };
            DaemonConfig::new(state).with_seed(seed(share)?)
        }
    };
    if let Some(path) = control_socket {
        config = config.with_control_socket(path);
    }
    let present = tui.then(|| Logging::choose(log_file, Some(&config.state_file)));
    // The server reports where this process's diagnostics land, so the Logs
    // screen can tail them through `server-info` in either mode instead of
    // through a second, mode-specific path only one of the two launches has.
    if let Some(Logging::File(path)) = &present {
        config = config.with_log_file(path.clone());
    }
    Ok(Plan::Serve { config, present })
}

/// Which control socket attach mode presents.
///
/// `--control-socket` has absolute precedence. Without it, the same lookup
/// `voidport-ctl` uses finds the first default socket a server answers on — one
/// shared function, so an operator who reaches a local instance with
/// `voidport-ctl info` reaches the same one with `voidportd --tui`.
///
/// It runs here, not in [`plan`], because it connects: planning decides
/// what can be decided from the command line alone, and this is a question only
/// the running system can answer.
fn attach_socket(socket: Option<PathBuf>) -> Result<PathBuf> {
    match socket {
        Some(socket) => Ok(socket),
        None => find_control_socket()
            .map_err(|error| anyhow!("{error}; pass --control-socket PATH to name one")),
    }
}

/// The seed a `share` launch describes.
fn seed(share: ShareArgs) -> Result<Seed> {
    // Canonical, so the graft target is absolute and the namespace path — which
    // is that same path, replicated — is the directory's real one:
    // `voidportd share .` shares the working directory at the path it has, not
    // at `.`.
    let directory = share
        .directory
        .canonicalize()
        .with_context(|| format!("cannot share {}", share.directory.display()))?;
    if !directory.is_dir() {
        bail!(
            "cannot share {}: it is not a directory",
            directory.display()
        );
    }
    let namespace = NamespaceName::new(share.name).context("invalid --name")?;
    let mode = if share.ro {
        ShareMode::Ro
    } else {
        ShareMode::Rw
    };
    // The vsock port is not range-checked here: a seeded listener is validated
    // exactly like a configured one, through the state document's own
    // `1..=65535` rule, before anything is written or bound.
    let listeners = share
        .addr
        .into_iter()
        .map(|addr| Listener::Tcp { addr })
        .chain(share.unix.into_iter().map(|path| Listener::Unix { path }))
        .chain(share.vsock.into_iter().map(Listener::vsock))
        .collect();
    Ok(Seed::new(directory, namespace, mode, listeners)?)
}

/// Where `share` seeds when `--state` is absent.
///
/// The XDG state directory, because a shared directory is exactly what that
/// directory is for: state the operator did not write by hand but wants back
/// after a restart. The directory is named by the shared rule the operator
/// surfaces search with — the seeded control socket lands beside this file, and
/// that is the socket a flagless `voidport-ctl` looks for first, so the two must
/// be the same directory by construction, not by coincidence.
///
/// The parents are created — the operator asked for this path by not naming one
/// — and the choice is logged, because a file nobody typed the name of has to
/// be findable.
fn default_state_file() -> Result<PathBuf> {
    let directory = voidport_control::user_state_directory().context(
        "neither XDG_STATE_HOME nor HOME is set: pass --state PATH to say where the \
         state file should live",
    )?;
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("cannot create {}", directory.display()))?;
    let state_file = directory.join("state.toml");
    tracing::info!(state_file = %state_file.display(), "sharing into the default state file");
    Ok(state_file)
}

/// Listens for the signals that ask this process to stop, and returns the
/// future that resolves when one of them arrives.
///
/// Both streams are registered here, not inside the future, so the future has
/// exactly one way to resolve: a signal. Everything downstream reads a resolved
/// future as an order to stop — [`Daemon::serve`] stops accepting on both
/// planes, the interface stops itself — so a registration failure that resolved
/// it instead of being raised would end a server nobody asked to stop, and log
/// the clean shutdown it is not.
///
/// # Errors
///
/// Returns the failure to listen for either signal, which refuses the launch.
/// The client refuses a mount the same way when its signals cannot be
/// registered.
fn terminated() -> io::Result<impl Future<Output = ()> + Send + 'static> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt =
        signal(SignalKind::interrupt()).map_err(|error| cannot_listen("SIGINT", &error))?;
    let mut terminate =
        signal(SignalKind::terminate()).map_err(|error| cannot_listen("SIGTERM", &error))?;
    Ok(async move {
        // Both signals mean the same thing here: finish the mutation in
        // flight, unlink the socket, exit.
        let signal = tokio::select! {
            _ = interrupt.recv() => "SIGINT",
            _ = terminate.recv() => "SIGTERM",
        };
        tracing::info!(signal, "shutting down");
    })
}

/// Names the signal a registration failure was for, keeping the kernel's own
/// reason and its kind.
fn cannot_listen(signal: &str, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("cannot listen for {signal}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_lines_default_namespace_is_the_seeds() {
        // The command line is compiled twice — into this binary and into the
        // build script that writes the manual page — so it cannot reach into
        // the library for this value. It can be checked against it here.
        assert_eq!(cli::DEFAULT_NAMESPACE, voidportd::seed::DEFAULT_NAMESPACE);
    }

    /// What the eager restructure guarantees: registration is over before the
    /// future exists, so the future carries no failure path of its own and the
    /// only thing that can resolve it is a signal. A caller may therefore treat
    /// a resolved future as an order to stop, which is exactly what
    /// `Daemon::serve` and the interface do.
    ///
    /// The kernel refusing SIGINT or SIGTERM to this process cannot be staged
    /// here, so the failure path is proven where it is observable — in the
    /// constructor's message, below — and this test proves the future's two
    /// halves: it does not resolve unasked, and it does resolve on a signal.
    #[tokio::test]
    async fn only_a_signal_resolves_the_termination_future() {
        use std::time::Duration;

        use rustix::process::{Signal, getpid, kill_process};

        let terminated = terminated().expect("SIGINT and SIGTERM can be listened for");
        tokio::pin!(terminated);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut terminated)
                .await
                .is_err(),
            "the shutdown future resolved without a signal"
        );
        // Both streams are registered, so the default disposition is already
        // replaced: this is delivered to the stream above, not to the kernel's
        // "terminate this process".
        kill_process(getpid(), Signal::INT).expect("a process can signal itself");
        tokio::time::timeout(Duration::from_secs(10), terminated)
            .await
            .expect("SIGINT resolves the shutdown future");
    }

    #[test]
    fn a_refused_registration_names_the_signal_and_keeps_the_reason() {
        // What the operator reads when a launch is refused: which signal could
        // not be listened for, and why.
        let error = cannot_listen("SIGTERM", &io::Error::from(io::ErrorKind::PermissionDenied));
        assert_eq!(
            error.to_string(),
            "cannot listen for SIGTERM: permission denied"
        );
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn the_command_line_is_a_valid_clap_definition() {
        use clap::CommandFactory as _;

        // What `build.rs` renders into `voidportd.1`; clap's own assertions
        // catch a malformed definition here, not in a build script.
        Args::command().debug_assert();
    }
}
