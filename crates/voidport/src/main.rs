#![forbid(unsafe_code)]

mod cli;
mod diagnostics;
mod events;
mod helper;
mod report;

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::parser::ValueSource;
use clap::{ArgMatches, CommandFactory as _, FromArgMatches as _};
use voidport::client::{Client, Resilience};
use voidport::guardian::Launch;
use voidport::kernel::{self, Availability, KernelError, KernelMountOptions, PendingMount};
use voidport::mount::{Mount, MountOptions};
use voidport::subscribe::Subscription;
use voidport::url::MountUrl;

use crate::cli::{Cli, Command};

fn main() -> ExitCode {
    if helper::invoked(std::env::args_os().next().as_deref()) {
        return helper::main();
    }
    // A command line the parser refuses never reaches a log; clap reports it
    // itself.
    let matches = Cli::command().get_matches();
    let arguments = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    diagnostics::install();

    match run(arguments, &matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report::report("voidport", error.as_ref());
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Cli, matches: &ArgMatches) -> Result<()> {
    match arguments.command {
        Command::Mount {
            url,
            mountpoint,
            attr_timeout,
            entry_timeout,
            allow_other,
            read_only,
            dispatch_threads,
            reconnect_stall,
            no_auto_unmount,
            no_privileged_bits,
            direct_io,
        } => {
            let parsed = MountUrl::parse(&url).with_context(|| format!("cannot mount {url}"))?;
            let options = MountOptions {
                attr_timeout: seconds(attr_timeout)?,
                entry_timeout: seconds(entry_timeout)?,
                allow_other,
                read_only,
                dispatch_threads,
                reconnect_stall: seconds(reconnect_stall)?,
                auto_unmount: !no_auto_unmount,
                privileged_bits: !no_privileged_bits,
                direct_io,
            };
            // The module dials only TCP and unix sockets, and a process that
            // may not mount gets its mount from the FUSE client.
            if kernel::can_dial(&parsed.endpoint) {
                match kernel::availability().with_context(|| format!("cannot mount {url}"))? {
                    Availability::Usable => {
                        let dispatch_threads_given = given(matches, "dispatch_threads");
                        return mount_through_kernel(
                            &url,
                            &mountpoint,
                            &options,
                            dispatch_threads_given,
                        )
                        .with_context(|| format!("cannot mount {url}"));
                    }
                    unavailable => {
                        tracing::debug!(?unavailable, "the mount goes over FUSE");
                    }
                }
            }
            let guardian = Launch {
                program: PathBuf::from("/proc/self/exe"),
                arguments: vec![cli::GUARDIAN.into()],
            };
            let mount = Mount::new(&parsed, &mountpoint, &options, &guardian)
                .with_context(|| format!("cannot mount {url}"))?;
            // SIGINT and SIGTERM run the same ordered teardown as a clean
            // unmount, so a Ctrl-C leaves no mountpoint behind. They are caught
            // before readiness is reported, so a stop that follows the report
            // finds the handlers installed.
            let signals = mount
                .catch_signals()
                .context("the mount cannot catch SIGINT and SIGTERM")?;
            ready()?;
            mount
                .serve_until_signalled(signals)
                .context("the mount ended in error")
        }
        Command::Umount { mountpoint } => voidport::mount::unmount(&mountpoint)
            .with_context(|| format!("cannot unmount {}", mountpoint.display())),
        Command::Subscribe {
            url,
            reconnect_stall,
        } => {
            let parsed =
                MountUrl::parse(&url).with_context(|| format!("cannot subscribe to {url}"))?;
            let resilience = Resilience {
                stall: seconds(reconnect_stall)?,
            };
            subscribe(&parsed, resilience).with_context(|| format!("cannot subscribe to {url}"))
        }
        Command::Guardian => voidport::guardian::serve().context("the guardian of a mount failed"),
    }
}

fn subscribe(url: &MountUrl, resilience: Resilience) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("the subscription needs a runtime")?;
    runtime.block_on(async move {
        let client = Client::mount_with(
            &url.endpoint,
            url.namespace.as_str(),
            &url.subpath,
            resilience,
        )
        .await?;
        let mut shares = Subscription::open(client)
            .await
            .map_err(|errno| anyhow::anyhow!("the server refused the subscription: {errno}"))?;
        // Line-buffered by hand: a shell pipeline that mounts from this must
        // see each event as it happens, and not once a block fills.
        let mut out = std::io::stdout().lock();
        while let Some(event) = shares.next().await {
            writeln!(out, "{}", events::render(&event))?;
            out.flush()?;
        }
        Ok(())
    })
}

fn given(matches: &ArgMatches, id: &str) -> bool {
    matches
        .subcommand_matches("mount")
        .and_then(|mount| mount.value_source(id))
        == Some(ValueSource::CommandLine)
}

/// `--dispatch-threads` shapes only the FUSE client, so the mount fails when
/// `dispatch_threads_given` says it was given. `--allow-other` and
/// `--no-auto-unmount` match what a kernel mount does anyway. No readiness is
/// reported, because no process remains for a service manager to wait on.
fn mount_through_kernel(
    url: &str,
    mountpoint: &Path,
    options: &MountOptions,
    dispatch_threads_given: bool,
) -> Result<(), KernelMountError> {
    if dispatch_threads_given {
        return Err(KernelMountError::FuseOnly {
            flag: "--dispatch-threads",
        });
    }
    let options = KernelMountOptions::for_client(options);
    PendingMount::new(url, mountpoint, &options)?.make()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum KernelMountError {
    #[error(
        "{flag} shapes only the FUSE client, and this mount goes through the voidport kernel module"
    )]
    FuseOnly { flag: &'static str },
    #[error(transparent)]
    Kernel(#[from] KernelError),
}

fn ready() -> Result<(), ReadyError> {
    sd_notify::notify(&[sd_notify::NotifyState::Ready]).map_err(|source| ReadyError { source })
}

#[derive(Debug, thiserror::Error)]
#[error("cannot report readiness to the socket named by NOTIFY_SOCKET")]
struct ReadyError {
    source: io::Error,
}

fn seconds(value: f64) -> Result<Duration> {
    Duration::try_from_secs_f64(value)
        .with_context(|| format!("{value} is not a number of seconds a timeout can be"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_line_restates_the_values_of_the_library() {
        // The command line is compiled into this binary and into the build
        // script that writes the manual page, so it cannot use the library for
        // these values.
        assert_eq!(
            cli::DEFAULT_TIMEOUT_SECONDS,
            voidport::mount::DEFAULT_TIMEOUT.as_secs_f64()
        );
        assert_eq!(
            cli::DEFAULT_DISPATCH_THREADS,
            voidport::mount::DEFAULT_DISPATCH_THREADS
        );
        assert_eq!(
            cli::DEFAULT_RECONNECT_STALL_SECONDS,
            voidport::client::DEFAULT_RECONNECT_STALL.as_secs_f64()
        );
        assert_eq!(cli::GUARDIAN, voidport::guardian::COMMAND);
    }

    #[test]
    fn a_flag_counts_as_given_only_on_the_command_line() {
        use clap::CommandFactory as _;

        let matches = |arguments: &[&str]| Cli::command().get_matches_from(arguments);
        let mount = ["voidport", "mount", "voidport://h:1/@ns", "/mnt"];
        assert!(!given(&matches(&mount), "dispatch_threads"));
        let explicit = [&mount[..], &["--dispatch-threads", "1"]].concat();
        assert!(given(&matches(&explicit), "dispatch_threads"));
    }

    #[test]
    fn the_command_line_is_a_valid_clap_definition() {
        use clap::CommandFactory as _;

        Cli::command().debug_assert();
    }
}
