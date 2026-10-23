#![forbid(unsafe_code)]

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
