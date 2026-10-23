#![forbid(unsafe_code)]

mod census;

use std::error::Error as _;
use std::io::{self, Write as _};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::process::ExitCode;

use clap::Parser;
use serde::Serialize;

use crate::census::CensusError;

/// The voidport wire census.
#[derive(Debug, Parser)]
#[command(name = "voidport-wire-census", version, about)]
struct Cli {
    /// The address to listen on for the connections of the mount. Port 0
    /// lets the kernel choose a free port.
    listen: SocketAddr,
    /// The address of the server.
    server: SocketAddr,
}

#[derive(Serialize)]
struct Listening {
    host: IpAddr,
    port: u16,
}

fn run(arguments: &Cli) -> Result<(), CensusError> {
    let listener = TcpListener::bind(arguments.listen).map_err(CensusError::Listen)?;
    let bound = listener.local_addr().map_err(CensusError::Listen)?;
    print(&Listening {
        host: bound.ip(),
        port: bound.port(),
    })?;
    let totals = census::count(&listener, arguments.server, io::stdin())?;
    print(&totals)
}

fn print(value: &impl Serialize) -> Result<(), CensusError> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, value)
        .map_err(io::Error::from)
        .and_then(|()| writeln!(output))
        .and_then(|()| output.flush())
        .map_err(CensusError::Print)
}

fn main() -> ExitCode {
    match run(&Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprint!("voidport-wire-census: {error}");
            let mut cause = error.source();
            while let Some(error) = cause {
                eprint!(": {error}");
                cause = error.source();
            }
            eprintln!();
            ExitCode::FAILURE
        }
    }
}
