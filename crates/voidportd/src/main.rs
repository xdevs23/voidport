#![forbid(unsafe_code)]

mod cli;
mod tui;

use std::io;
use std::process::ExitCode;

use anyhow::{Context as _, Result, anyhow};
use clap::Parser as _;
use std::path::PathBuf;
use voidport_control::{NamespaceName, ShareMode, find_control_socket};
use voidportd::daemon::{Daemon, DaemonConfig};
use voidportd::error::render;
use voidportd::reclaim;
use voidportd::seed::Seed;
use voidportd::seed::shared_path::SharedPath;
use voidportd::state::Listener;

use crate::cli::{Args, Command, ShareArgs};
use crate::tui::Logging;

fn main() -> ExitCode {
    // Installed before the command line is parsed: working out the launch
    // logs, and a later subscriber would drop those records.
    tui::install();
    let plan = match plan(Args::parse()) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("voidportd: {error:#}");
            return ExitCode::FAILURE;
        }
    };
    // Before the runtime starts its worker threads, which `run` brings up.
    if matches!(plan, Plan::Serve { .. }) {
        reclaim::confine_arenas();
    }
    run(plan)
}

#[tokio::main]
async fn run(plan: Plan) -> ExitCode {
    // Registered before anything is bound or written, so a failure is only a
    // launch that does not happen.
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
                Err(error) => {
                    eprintln!("voidportd: {}", render(&error));
                    ExitCode::FAILURE
                }
            }
        }
        Plan::Serve { config, present } => serve(config, present, terminated).await,
    }
}

async fn serve(
    config: DaemonConfig,
    present: Option<Logging>,
    terminated: impl Future<Output = ()> + Send + 'static,
) -> ExitCode {
    // A plain launch logs to stderr, so stdout contains only the mount
    // commands. A presented launch moves the log off the terminal.
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

    if let Err(error) = sd_notify::notify(&[sd_notify::NotifyState::Ready]) {
        eprintln!(
            "voidportd: cannot report readiness to the socket named by NOTIFY_SOCKET: {error}; \
             start the server with NOTIFY_SOCKET unset, or naming a socket that receives \
             datagrams"
        );
        return ExitCode::FAILURE;
    }

    if present.is_some() {
        return match tui::serve_and_present(daemon, terminated).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("voidportd: {}", render(&error));
                ExitCode::FAILURE
            }
        };
    }

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

#[derive(Debug)]
enum Plan {
    Serve {
        config: DaemonConfig,
        present: Option<Logging>,
    },
    Attach {
        /// `None` is resolved in [`attach_socket`], because the lookup connects.
        socket: Option<PathBuf>,
        logging: Logging,
    },
}

fn plan(args: Args) -> Result<Plan> {
    let Args {
        state,
        control_socket,
        tui,
        log_file,
        command,
    } = args;
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
    // The Logs screen tails this file through `server-info` in either mode.
    if let Some(Logging::File(path)) = &present {
        config = config.with_log_file(path.clone());
    }
    Ok(Plan::Serve { config, present })
}

/// Runs after [`plan`], because the lookup connects.
fn attach_socket(socket: Option<PathBuf>) -> Result<PathBuf> {
    match socket {
        Some(socket) => Ok(socket),
        None => find_control_socket()
            .map_err(|error| anyhow!("{error}; pass --control-socket PATH to name one")),
    }
}

fn seed(share: ShareArgs) -> Result<Seed> {
    // `DIR` is taken as typed, so a link is shared as a link.
    let working_directory = std::env::current_dir().context("cannot read the working directory")?;
    let shared = SharedPath::from_typed(&share.directory, &working_directory)?;
    if let Some(notice) = shared.notice() {
        tracing::info!("{notice}");
    }
    let directory = shared.path().to_path_buf();
    let namespace = NamespaceName::new(share.name).context("invalid --name")?;
    let mode = if share.ro {
        ShareMode::Ro
    } else {
        ShareMode::Rw
    };
    // The vsock port is validated later through the port rule of the state
    // document, like a configured one.
    let listeners = share
        .addr
        .into_iter()
        .map(|addr| Listener::Tcp { addr })
        .chain(share.unix.into_iter().map(|path| Listener::Unix { path }))
        .chain(share.vsock.into_iter().map(Listener::vsock))
        .collect();
    Ok(Seed::new(directory, namespace, mode, listeners)?)
}

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

/// Both signal streams are registered before the future exists, so a
/// registration failure is raised. A resolved future means stop.
fn terminated() -> io::Result<impl Future<Output = ()> + Send + 'static> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt =
        signal(SignalKind::interrupt()).map_err(|error| cannot_listen("SIGINT", &error))?;
    let mut terminate =
        signal(SignalKind::terminate()).map_err(|error| cannot_listen("SIGTERM", &error))?;
    Ok(async move {
        let signal = tokio::select! {
            _ = interrupt.recv() => "SIGINT",
            _ = terminate.recv() => "SIGTERM",
        };
        tracing::info!(signal, "shutting down");
    })
}

fn cannot_listen(signal: &str, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("cannot listen for {signal}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_lines_default_namespace_is_the_seeds() {
        // The command line is also compiled into the build script.
        assert_eq!(cli::DEFAULT_NAMESPACE, voidportd::seed::DEFAULT_NAMESPACE);
    }

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
        kill_process(getpid(), Signal::INT).expect("a process can signal itself");
        tokio::time::timeout(Duration::from_secs(10), terminated)
            .await
            .expect("SIGINT resolves the shutdown future");
    }

    #[test]
    fn a_refused_registration_names_the_signal_and_keeps_the_reason() {
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

        Args::command().debug_assert();
    }
}
