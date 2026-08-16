//! The voidport benchmark harness.
//!
//! One binary, one scenario per invocation, one JSON record per run on stdout
//! and a human summary on stderr. It knows nothing about voidport: it is handed
//! a directory and measures what that directory does, which is what makes the
//! same command comparable across a tmpfs, a voidport mount over a unix socket,
//! the same over tcp, and a 9p mount.
//!
//! The measurement discipline is uniform and lives in [`report`]: a warmup,
//! then repetitions, each optionally preceded by `sync(2)` and a page-cache
//! drop, with per-repetition throughput and — where a scenario samples them —
//! pooled per-operation latency percentiles.
//!
//! Results live in `docs/PERFORMANCE.md`; the driver that produced them and
//! the raw records are kept out of tree.

mod cli;
mod fsutil;
mod report;
mod scenario;

use std::process::ExitCode;

use clap::Parser as _;

use crate::cli::Cli;

fn main() -> ExitCode {
    let arguments = Cli::parse();
    let name = arguments.scenario.name();
    match scenario::run(&arguments.scenario, &arguments.common)
        .and_then(|run| run.emit(arguments.common.json.as_deref()))
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("voidport-bench: {name}: {error:#}");
            ExitCode::FAILURE
        }
    }
}
