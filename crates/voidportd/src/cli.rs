//! `build.rs` compiles this file alone to render the manual page, so it cannot
//! use the library.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand};

/// Restated from `voidportd::seed::DEFAULT_NAMESPACE`, which `main.rs` tests it
/// against.
pub const DEFAULT_NAMESPACE: &str = "share";

/// The voidport server: serves policy-composed namespaces of the host
/// filesystem.
#[derive(Debug, Parser)]
#[command(name = "voidportd", version, about)]
pub struct Args {
    /// The state file to serve: persistent, server-owned configuration.
    ///
    /// The server owns this file from startup onwards. Every control-plane
    /// mutation is persisted back into it, and it is created if it does not
    /// exist, so what a server serves survives a restart without the command
    /// that set it up. `voidportd share` defaults to
    /// `$XDG_STATE_HOME/voidport/state.toml` (`~/.local/state/voidport/state.toml`
    /// when `XDG_STATE_HOME` is unset), creating the directories it needs and
    /// logging the path it chose. Every other launch requires this flag.
    #[arg(long, short = 's', value_name = "PATH", global = true)]
    pub state: Option<PathBuf>,
    /// The control socket to serve. Wins over the one the state file names;
    /// without either, `share` seeds one beside the state file and any other
    /// launch uses the compiled default `/run/voidport/control.sock`. With
    /// `--tui` alone it names the server to attach to, and without it attach
    /// mode looks for a running one: `$XDG_STATE_HOME/voidport/control.sock`
    /// (`~/.local/state/…` when the variable is unset) and then
    /// `/run/voidport/control.sock`, taking the first that answers.
    #[arg(long, short = 'c', value_name = "PATH", global = true)]
    pub control_socket: Option<PathBuf>,
    /// Manage the server through the full-screen operator interface. With
    /// `--state` or `share` the server is served in the foreground and
    /// quitting shuts it down; on its own it attaches to a running server's
    /// control socket and quitting leaves it serving.
    #[arg(long, global = true)]
    pub tui: bool,
    /// Where the server's own diagnostics go while the interface owns the
    /// terminal. Defaults to a file beside the state file when serving, and to
    /// nowhere when attaching.
    #[arg(long, value_name = "PATH", global = true)]
    pub log_file: Option<PathBuf>,
    /// What to serve. Without a subcommand the server serves `--state`.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// The launches that are more than "serve this state file".
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Share one host directory straight away: seed the state file with it and
    /// serve.
    ///
    /// Quick sharing is not a separate mode. The listeners, the namespace and
    /// the directory are written into the state file, which is persistent,
    /// server-owned configuration and lives at
    /// `$XDG_STATE_HOME/voidport/state.toml` unless `--state` names another
    /// path. That file is then served exactly as any other launch serves it:
    /// the share survives a restart without this command, and `voidport-ctl`
    /// reconfigures it while guests stay mounted.
    ///
    /// Nothing is ever overwritten. A piece that is already in the file with
    /// exactly this content is left alone, so repeating the command changes
    /// nothing; one that would give an existing namespace or rule different
    /// content refuses to start and names the collision.
    ///
    /// The directory is attached at its own absolute host path, so a guest
    /// mounting the namespace sees the hierarchy the directory has here, and
    /// sharing a second directory adds it at its own path instead of colliding
    /// on a name.
    Share(ShareArgs),
}

/// `voidportd share <DIR> …`
#[derive(Debug, ClapArgs)]
pub struct ShareArgs {
    /// The host directory to share. It is attached at its own absolute path.
    ///
    /// The path is taken as typed and no link in it is resolved, so a path
    /// that names a symbolic link shares the link. `DIR/.` or `DIR/` shares
    /// the directory the link points to. A path that is `.`, ends in `/.` or
    /// `/`, or has a `..` component is resolved on the host first.
    #[arg(value_name = "DIR")]
    pub directory: PathBuf,
    /// A tcp endpoint to serve on. Repeatable; at least one listener is
    /// required, because there is no default bind.
    #[arg(long, value_name = "HOST:PORT")]
    pub addr: Vec<SocketAddr>,
    /// A unix socket to serve on. Repeatable.
    #[arg(long, value_name = "PATH")]
    pub unix: Vec<PathBuf>,
    /// A vsock port to serve on, for guests of this machine's hypervisor.
    /// Repeatable.
    ///
    /// The listener binds the vsock wildcard, which on a host means every
    /// guest of it, and the printed mount command names the cid a guest dials
    /// its host at. The port is 1..=65535, because a mount URL's port is the
    /// URL standard's 16-bit one. Port 0 asks the server for a free one, and
    /// the printed mount command shows the port it got.
    #[arg(long, value_name = "PORT")]
    pub vsock: Vec<u32>,
    /// Share read-only.
    #[arg(long)]
    pub ro: bool,
    /// The namespace to share it in.
    #[arg(long, value_name = "NAME", default_value = DEFAULT_NAMESPACE)]
    pub name: String,
}
