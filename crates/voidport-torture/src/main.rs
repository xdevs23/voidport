#![forbid(unsafe_code)]

mod cli;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser as _;
use voidport::guardian::Launch;
use voidport::url::MountUrl;

use voidport_torture::mounts::GUARDIAN;
use voidport_torture::{Plan, Probe, Seed, ServerPid, Supervisor};

fn main() -> ExitCode {
    let arguments = cli::Cli::parse();
    let outcome = match (arguments.command, arguments.run) {
        (Some(cli::Command::Guardian), _) => voidport::guardian::serve()
            .map(|()| true)
            .map_err(|error| anyhow::Error::new(error).context("the guardian of a mount failed")),
        (None, Some(run)) => torture(&run),
        (None, None) => Err(anyhow::anyhow!("a run needs its arguments")),
    };
    match outcome {
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

/// The server is started first, before the plan is handed to the engine, so
/// before anything is mounted.
fn torture(arguments: &cli::Run) -> anyhow::Result<bool> {
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
        guardian: Launch {
            program: PathBuf::from("/proc/self/exe"),
            arguments: vec![GUARDIAN.into()],
        },
    };
    let report = voidport_torture::run(&plan)?;
    eprint!("{}", report.render());
    if arguments.json {
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(report.passed())
}
