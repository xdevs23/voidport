//! The torture harness binary.
//!
//! It mounts, it loads, it watches, it tears down, and it exits non-zero if any
//! invariant was violated — so a run of hours can be left alone and its exit
//! status believed.

mod cli;

use std::process::ExitCode;

use clap::Parser as _;

use voidport_torture::{Plan, Probe, Seed};

fn main() -> ExitCode {
    let arguments = cli::Cli::parse();
    match torture(&arguments) {
        Ok(passed) => {
            if passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("voidport-torture: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Runs one plan, reports it, and says whether it held.
fn torture(arguments: &cli::Cli) -> anyhow::Result<bool> {
    let plan = Plan {
        url: arguments.url.clone(),
        work_dir: arguments.work_dir.clone(),
        duration: arguments.duration(),
        intensity: arguments.intensity,
        classes: arguments.classes()?,
        mounts: arguments.mounts,
        probe: Probe {
            pid: arguments.server_pid,
            control_socket: arguments.control_socket.clone(),
        },
        log: arguments.log.clone(),
        seed: Seed::default(),
    };
    let report = voidport_torture::run(&plan)?;
    eprint!("{}", report.render());
    if arguments.json {
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(report.passed())
}
