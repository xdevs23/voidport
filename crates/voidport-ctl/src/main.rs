//! The voidport operator CLI.
//!
//! One subcommand per control operation, human-readable output by default and
//! `--json` — the server's response line, verbatim — for scripts. A failed
//! operation exits nonzero in both modes, so a script can branch on the exit
//! status and still capture the structured error.

mod cli;
mod render;

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

/// Runs one command, returning whether the server accepted it.
///
/// The distinction matters: a rejected operation is a normal outcome that
/// still prints a structured answer, while an error here means the CLI could
/// not talk to the server at all.
fn run(arguments: &Cli) -> anyhow::Result<bool> {
    let request = arguments.command.to_request()?;
    let socket = socket(arguments)?;
    // The one shared control client: the same connection, the same finite
    // timeouts, the same parsing the operator TUI drives.
    let mut client = Client::connect(&socket)?;
    let answer = client.call(&request)?;

    if arguments.json {
        println!("{}", answer.line);
    } else {
        println!("{}", human(&arguments.command, &answer.response));
    }
    Ok(answer.as_error().is_none())
}

/// The human rendering of one answer.
///
/// One command needs to know which question it asked: `listener list` reuses
/// `server-info` instead of adding a read operation of its own, so the reply
/// carries the whole server block and only the endpoints were asked for. Every
/// other command is rendered from the reply alone.
fn human(command: &Command, response: &voidport_control::Response) -> String {
    match command {
        Command::Listener(ListenerCommand::List) => render::render_listener_list(response),
        _ => render::render(response),
    }
}

/// Which control socket to talk to.
///
/// `--socket` has absolute precedence: an explicit path is used exactly as
/// given, and a server that is not there is reported against that path, not
/// quietly replaced by another one. Without it, the shared lookup finds
/// the first default socket a server answers on — the same lookup
/// `voidportd --tui` uses to attach, so the two surfaces cannot disagree about
/// which local instance they mean.
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
