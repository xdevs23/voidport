//! The torture harness binary.
//!
//! It mounts, it loads, it watches, it tears down, and it exits non-zero if any
//! invariant was violated — so a run of hours can be left alone and its exit
//! status believed.

mod cli;

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser as _;
use voidport::url::MountUrl;

use voidport_torture::{Plan, Probe, Seed, ServerPid, Supervisor};

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
///
/// A run that owns its server starts it **first**, before the plan is handed to
/// the engine and therefore before anything is mounted; that ordering is the
/// supervisor's, not this function's convenience, and it is why the server is
/// built here instead of inside the engine.
fn torture(arguments: &cli::Cli) -> anyhow::Result<bool> {
    let control_socket = arguments.control_socket();
    let server = match (&arguments.server_binary, &arguments.server_state) {
        (Some(binary), Some(state)) => {
            let control = control_socket
                .clone()
                .ok_or_else(|| anyhow::anyhow!("a server needs a control socket"))?;
            let ready = MountUrl::parse(
                arguments
                    .urls
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("a run needs a URL"))?,
            )?;
            Some(Arc::new(Supervisor::start(
                binary,
                state,
                &control,
                &ready,
                &arguments.server_log,
            )?))
        }
        _ => None,
    };

    let plan = Plan {
        urls: arguments.urls.clone(),
        work_dir: arguments.work_dir.clone(),
        duration: arguments.duration(),
        intensity: arguments.intensity,
        classes: arguments.classes()?,
        mounts: arguments.mounts,
        probe: Probe {
            pid: server
                .as_ref()
                .map(|server| server.pid())
                .or_else(|| arguments.server_pid.map(ServerPid::new)),
            control_socket,
        },
        log: arguments.log.clone(),
        seed: Seed::default(),
        server,
    };
    let report = voidport_torture::run(&plan)?;
    eprint!("{}", report.render());
    if arguments.json {
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(report.passed())
}
