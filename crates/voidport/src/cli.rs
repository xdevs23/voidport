//! Compiled by `build.rs` as well, so it cannot use the library. The defaults
//! restated here are checked against the library by a test in `main.rs`.

use std::num::NonZeroUsize;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// The same value as `voidport::mount::DEFAULT_TIMEOUT`.
pub const DEFAULT_TIMEOUT_SECONDS: f64 = 1.0;

/// The same value as `voidport::mount::DEFAULT_DISPATCH_THREADS`.
pub const DEFAULT_DISPATCH_THREADS: NonZeroUsize = NonZeroUsize::new(1).expect("1 is not zero");

/// The same value as `voidport::client::DEFAULT_RECONNECT_STALL`.
pub const DEFAULT_RECONNECT_STALL_SECONDS: f64 = 5.0;

/// The same value as `voidport::guardian::COMMAND`.
pub const GUARDIAN: &str = "guardian";

/// The voidport guest client: mounts a namespace through the voidport kernel
/// module or over FUSE.
#[derive(Debug, Parser)]
#[command(name = "voidport", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Mount a namespace.
    ///
    /// Where the kernel has the voidport kernel module and this process may
    /// mount, the mount goes through the module and the command returns once it
    /// is made. Otherwise, and for a vsock URL, since the module dials only TCP
    /// and unix sockets, the FUSE client mounts it and runs until the
    /// mountpoint is unmounted. `mount -t voidport URL DIR` and an fstab line of
    /// type voidport take the same URL, through the mount.voidport helper
    /// installed beside this command.
    Mount {
        /// `voidport://host:port/@namespace[/subpath]`,
        /// `voidport+unix://<percent-encoded socket path>/@namespace[/subpath]`,
        /// or `voidport+vsock://cid:port/@namespace[/subpath]` (a guest reaches
        /// its host at cid 2).
        url: String,
        /// Where to mount it.
        mountpoint: PathBuf,
        /// How long the kernel may cache attributes, in seconds.
        #[arg(long, value_name = "SECONDS", default_value_t = DEFAULT_TIMEOUT_SECONDS)]
        attr_timeout: f64,
        /// How long the kernel may cache name resolutions, in seconds.
        #[arg(long, value_name = "SECONDS", default_value_t = DEFAULT_TIMEOUT_SECONDS)]
        entry_timeout: f64,
        /// Let users other than the mounting one reach the mount. A mount
        /// through the kernel module is reachable by every user already.
        #[arg(long)]
        allow_other: bool,
        /// Have the kernel refuse write-class operations as well, in addition
        /// to the server's own share modes.
        #[arg(long)]
        read_only: bool,
        /// How many FUSE event loops read and dispatch kernel requests in
        /// parallel. Raise it for many concurrent guest processes; one client
        /// doing one thing at a time cannot use more than one. A mount through
        /// the kernel module fails with an error when this is given.
        #[arg(long, value_name = "COUNT", default_value_t = DEFAULT_DISPATCH_THREADS)]
        dispatch_threads: NonZeroUsize,
        /// How long requests wait, in seconds, when the server breaks away,
        /// before the mount starts failing them immediately. The mount keeps
        /// trying to reconnect either way and resumes as soon as the server is
        /// back. Zero fails requests the moment the connection dies.
        #[arg(long, value_name = "SECONDS", default_value_t = DEFAULT_RECONNECT_STALL_SECONDS)]
        reconnect_stall: f64,
        /// Do not ask the kernel to release this mountpoint if the client is
        /// killed. Auto-unmount is opportunistic anyway: it needs the
        /// fusermount helper and --allow-other, and the mount logs which way it
        /// went. A mount through the kernel module remains until it is
        /// unmounted, whichever way the command ends.
        #[arg(long)]
        no_auto_unmount: bool,
        /// Show no setuid or setgid bits on this mount, and refuse a chmod that
        /// would set one. Stronger than the classic nosuid, which honors
        /// nothing but still shows the bits: this masks them, so nothing on
        /// this mount can read that a file carries one. Recorded bits are
        /// untouched: other mounts of the same namespace still show them, and
        /// a chmod through this mount cannot clear them.
        #[arg(long)]
        no_privileged_bits: bool,
    },
    /// Unmount a voidport mountpoint, made through the kernel module or over
    /// FUSE. A busy mountpoint remains mounted.
    Umount {
        /// The mountpoint.
        mountpoint: PathBuf,
    },
    /// Print what the namespace shares, and keep printing as it changes.
    ///
    /// One JSON object per line on stdout, flushed as it is written, so a shell
    /// pipeline can mount and unmount from it. Diagnostics go to
    /// stderr. The stream starts with a full snapshot and follows it with
    /// changes, so a consumer reconciles instead of replaying; a reconnect
    /// brackets the outage and resumes with a fresh snapshot.
    Subscribe {
        /// `voidport://host:port/@namespace[/subpath]`,
        /// `voidport+unix://<percent-encoded socket path>/@namespace[/subpath]`,
        /// or `voidport+vsock://cid:port/@namespace[/subpath]` (a guest reaches
        /// its host at cid 2).
        url: String,
        /// How long to wait, in seconds, when the server breaks away, before
        /// reporting the outage. The stream keeps trying to reconnect either
        /// way and resumes with a fresh snapshot as soon as the server is back.
        #[arg(long, value_name = "SECONDS", default_value_t = DEFAULT_RECONNECT_STALL_SECONDS)]
        reconnect_stall: f64,
    },
    /// Runs the guardian of a mount, which `voidport mount` starts with its
    /// end of a socket pair as standard input.
    #[command(name = GUARDIAN, hide = true)]
    Guardian,
}
