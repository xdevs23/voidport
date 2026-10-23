//! The voidport operator CLI. `--json` prints the response line of the server
//! verbatim. A failed operation exits nonzero in both modes.
#![forbid(unsafe_code)]

mod cli;
mod render;
mod request;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::anyhow;
use clap::Parser;
use voidport_control::{Client, find_control_socket};

use crate::cli::{Cli, Command, ListenerCommand};

fn main() -> ExitCode {
    let arguments = Cli::parse();
    match run(&arguments) {
        Ok(success) => {
            if success {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("voidport-ctl: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Returns whether the server accepted the command. A rejected operation still
/// prints a structured answer, while an error here means the CLI could not talk
/// to the server at all.
fn run(arguments: &Cli) -> anyhow::Result<bool> {
    let request = arguments.command.to_request()?;
    let socket = socket(arguments)?;
    // The one shared control client: the same connection, the same finite
    // timeouts, the same parsing the operator TUI uses.
    let mut client = Client::connect(&socket)?;
    let answer = client.call(&request)?;

    if arguments.json {
        println!("{}", answer.line);
    } else {
        println!("{}", human(&arguments.command, &answer.response));
    }
    Ok(answer.as_error().is_none())
}

/// `listener list` reuses `server-info`, so its reply carries the whole server
/// block and only the endpoints were asked for.
fn human(command: &Command, response: &voidport_control::Response) -> String {
    match command {
        Command::Listener(ListenerCommand::List) => render::render_listener_list(response),
        _ => render::render(response),
    }
}

/// `--socket` has absolute precedence: a server that is not at an explicit path
/// is reported against that path, not replaced by another one. Without it, the
/// shared lookup is the one `voidportd --tui` uses to attach.
fn socket(arguments: &Cli) -> anyhow::Result<PathBuf> {
    match &arguments.socket {
        Some(socket) => Ok(socket.clone()),
        // The failure names the paths tried, and this adds the way out of it;
        // it is written as one sentence instead of as error context so the
        // operator reads the paths before the advice.
        None => find_control_socket()
            .map_err(|error| anyhow!("{error}; pass --socket PATH to name one")),
    }
}
