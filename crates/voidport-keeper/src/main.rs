#![forbid(unsafe_code)]

mod cli;

use std::fs;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context as _;
use clap::Parser as _;
use rustix::fs::Mode;

use self::cli::Args;

fn main() -> ExitCode {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(io::stderr)
        .init();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("voidport-keeper: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> anyhow::Result<()> {
    let socket =
        Socket::bind(&args.vm).with_context(|| format!("binding {}", args.vm.display()))?;
    // From here on QEMU can be started: its connection waits in the queue of
    // the socket until the keeper accepts it.
    tracing::info!(socket = %args.vm.display(), "waiting for QEMU");
    let (qemu, _) = socket
        .listener
        .accept()
        .with_context(|| format!("waiting for QEMU on {}", args.vm.display()))?;
    voidport_keeper::serve(qemu, &args.server)?;
    Ok(())
}

struct Socket {
    path: PathBuf,
    listener: UnixListener,
}

impl Socket {
    fn bind(path: &Path) -> io::Result<Self> {
        let listener = match bind_private(path) {
            Err(error) if error.kind() == io::ErrorKind::AddrInUse && abandoned(path) => {
                fs::remove_file(path)?;
                bind_private(path)
            }
            bound => bound,
        }?;
        Ok(Self {
            path: path.to_path_buf(),
            listener,
        })
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.path) {
            tracing::warn!(%error, path = %self.path.display(), "the socket QEMU connected to was not removed");
        }
    }
}

/// Binds `path` with a umask that lets only the account that runs the
/// process use the socket. The keeper has no other thread yet, so no other
/// thread sees the changed umask of the process.
fn bind_private(path: &Path) -> io::Result<UnixListener> {
    let previous = rustix::process::umask(Mode::from_bits_truncate(0o177));
    let bound = UnixListener::bind(path);
    rustix::process::umask(previous);
    bound
}

fn abandoned(path: &Path) -> bool {
    UnixStream::connect(path).is_err_and(|error| error.kind() == io::ErrorKind::ConnectionRefused)
}
