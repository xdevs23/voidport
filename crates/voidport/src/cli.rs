//! The `voidport` command line.
//!
//! Its own module, and deliberately self-contained: the binary parses it, and
//! `build.rs` compiles this same file to generate `voidport.1`, so the manual
//! page and the `--help` output cannot drift apart. A build script cannot use
//! the crate it builds, which is why the two defaults that also live in
//! [`voidport::mount`](crate::mount) are restated here and checked against it by
//! a test in `main.rs`.

use std::num::NonZeroUsize;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// How long the kernel may cache attributes and name resolutions, in seconds.
///
/// The same value as `voidport::mount::DEFAULT_TIMEOUT`, restated for the reason
/// in the module docs.
pub const DEFAULT_TIMEOUT_SECONDS: f64 = 1.0;

/// How many FUSE event loops a mount runs by default.
///
/// The same value as `voidport::mount::DEFAULT_DISPATCH_THREADS`.
pub const DEFAULT_DISPATCH_THREADS: NonZeroUsize = NonZeroUsize::new(1).expect("1 is not zero");

/// How long a mount stalls when the server breaks away, in seconds.
///
/// The same value as `voidport::client::DEFAULT_RECONNECT_STALL`.
pub const DEFAULT_RECONNECT_STALL_SECONDS: f64 = 5.0;

/// How much memory a mount may hold for readahead, in MiB.
///
/// The same value as `voidport::client::DEFAULT_POOL_BYTES`, in the unit the
/// command line takes it in; restated for the reason in the module docs.
pub const DEFAULT_READAHEAD_MIB: u64 = 256;

/// The voidport guest client: mounts a namespace over FUSE.
#[derive(Debug, Parser)]
#[command(name = "voidport", version, about)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// What a guest does with a share.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Mount a namespace and serve it until the mountpoint is unmounted.
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
        /// Let users other than the mounting one reach the mount.
        #[arg(long)]
        allow_other: bool,
        /// Have the kernel refuse write-class operations as well, in addition
        /// to the server's own share modes.
        #[arg(long)]
        read_only: bool,
        /// How many FUSE event loops read and dispatch kernel requests in
        /// parallel. Raise it for many concurrent guest processes; one client
        /// doing one thing at a time cannot use more than one.
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
        /// went.
        #[arg(long)]
        no_auto_unmount: bool,
        /// Keep no copy of file data in this guest's page cache, so many guests
        /// reading one host file no longer each hold their own copy of it.
        /// Reads and writes go straight to the server, which costs re-read
        /// throughput; mmap keeps working, and metadata caching is unaffected.
        /// On a guest kernel older than 6.7 the mount logs a notice and keeps
        /// caching normally instead of giving up mmap.
        #[arg(long)]
        direct_io: bool,
        /// Show no setuid or setgid bits on this mount, and refuse a chmod that
        /// would set one. Stronger than the classic nosuid, which honors
        /// nothing but still shows the bits: this masks them, so nothing on
        /// this mount can read that a file carries one. Recorded bits are
        /// untouched — other mounts of the same namespace keep presenting
        /// them, and a chmod through this mount cannot clear them.
        #[arg(long)]
        no_privileged_bits: bool,
        /// How much memory, in MiB, this mount may hold for reading ahead of a
        /// sequential reader. A ceiling and not an allocation: an idle mount
        /// holds nothing. Zero turns the engine off and every read goes to the
        /// server as it is made. It applies only under --direct-io, where the
        /// guest keeps no page cache and therefore has no kernel readahead of
        /// its own; a page-cached mount is served by the kernel's and is
        /// untouched. Prefetched bytes are as fresh as --attr-timeout allows,
        /// never staler.
        #[arg(long, value_name = "MIB", default_value_t = DEFAULT_READAHEAD_MIB)]
        readahead: u64,
    },
    /// Unmount a voidport mountpoint. A busy mountpoint stays mounted.
    Umount {
        /// The mountpoint.
        mountpoint: PathBuf,
    },
    /// Print what the namespace shares, and keep printing as it changes.
    ///
    /// One JSON object per line on stdout, flushed as it is written, so a shell
    /// pipeline can drive mounts and unmounts from it. Diagnostics go to
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
}
