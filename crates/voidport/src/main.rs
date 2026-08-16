//! The voidport guest client.
//!
//! A thin shell around the library: parse a mount URL, mount it, and stay in
//! the foreground until the filesystem is unmounted. `voidport umount` is the
//! other half — a plain kernel unmount of a mountpoint this or another process
//! mounted.

mod cli;
mod diagnostics;
mod events;

use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use voidport::client::{Client, Resilience};
use voidport::mount::{Mount, MountOptions};
use voidport::subscribe::Subscription;
use voidport::url::MountUrl;

use crate::cli::{Cli, Command};

fn main() -> ExitCode {
    // Parsed before the diagnostics are installed, because where they go is one
    // thing and what they may not swallow is another: the mount's own teardown
    // is what tells fuser's spurious unmount warning from a real one, and the
    // command line is where the mountpoint comes from. A command line the
    // parser refuses never reaches a log; clap reports it itself.
    let arguments = Cli::parse();
    diagnostics::install(mountpoint(&arguments.command));

    match run(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("voidport: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// The mountpoint this invocation mounts on, where it mounts one.
///
/// Only a mount runs a FUSE session, and only a FUSE session has an unmount of
/// fuser's own behind it; the other two commands hand over nothing.
fn mountpoint(command: &Command) -> Option<&Path> {
    match command {
        Command::Mount { mountpoint, .. } => Some(mountpoint),
        Command::Umount { .. } | Command::Subscribe { .. } => None,
    }
}

/// Runs one command.
fn run(arguments: Cli) -> Result<()> {
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
            direct_io,
            readahead,
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
                direct_io,
                readahead: mebibytes(readahead),
            };
            let mount = Mount::new(&parsed, &mountpoint, &options)
                .with_context(|| format!("cannot mount {url}"))?;
            // SIGINT and SIGTERM run the same ordered teardown a clean unmount
            // does, unmount attempt included: a Ctrl-C must not leave a
            // mountpoint behind for the operator to clean up.
            mount
                .serve_until_signalled()
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
    }
}

/// Prints one JSON line per share event until the stream ends.
///
/// It opens an ordinary data-plane session — the same one a mount opens, on the
/// same protocol — and drives the library's subscription. Nothing here decides
/// anything about the stream; the reconnect brackets and the level-triggered
/// snapshots are the library's, which is what makes this command a test of the
/// API embedders use.
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
        // Line-buffered by hand: a shell pipeline driving mounts from this must
        // see each event as it happens, not when a block fills.
        let mut out = std::io::stdout().lock();
        while let Some(event) = shares.next().await {
            writeln!(out, "{}", events::render(&event))?;
            out.flush()?;
        }
        Ok(())
    })
}

/// A timeout in seconds, refusing what cannot be one.
fn seconds(value: f64) -> Result<Duration> {
    Duration::try_from_secs_f64(value)
        .with_context(|| format!("{value} is not a number of seconds a timeout can be"))
}

/// A count of mebibytes as a count of bytes, saturating, not wrapping:
/// a number too large for this machine's address space is that machine's
/// largest, and the pool is a ceiling nothing has to reach.
fn mebibytes(value: u64) -> usize {
    usize::try_from(value.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_lines_defaults_are_the_mounts() {
        // The command line is compiled twice — into this binary and into the
        // build script that writes the manual page — so it cannot reach into
        // the library for these values. It can be checked against it here.
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
        assert_eq!(
            mebibytes(cli::DEFAULT_READAHEAD_MIB),
            voidport::client::DEFAULT_POOL_BYTES
        );
    }

    #[test]
    fn the_command_line_is_a_valid_clap_definition() {
        use clap::CommandFactory as _;

        // What `build.rs` renders into `voidport.1`.
        Cli::command().debug_assert();
    }
}
