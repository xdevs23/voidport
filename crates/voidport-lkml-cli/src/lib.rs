#![forbid(unsafe_code)]
use clap::{Args, Parser, Subcommand};
use std::{num::NonZeroU64, path::PathBuf};

/// Preserve LKML responses and their available discussion context locally.
///
/// Header attribution is not authentication. Collection does not establish
/// historical completeness, redistribution rights or submission approval.
#[derive(Debug, Parser)]
#[command(name = "voidport-lkml", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Acquire explicit query units through lei, preserving exact delivered bytes.
    ///
    /// Use a corpus outside the source checkout. Queries pass unchanged to every
    /// configured archive source. Failed attempts retain mail and diagnostics;
    /// there is no automatic retry. Follow any server guidance in the retained
    /// stderr.
    Collect(Collect),
    /// Report committed progress and retained partial work without network access.
    Status {
        #[arg(long, value_name = "DIR")]
        output: PathBuf,
        /// Emit the versioned status record.
        #[arg(long)]
        json: bool,
    },
    /// Recompute hashes, interpretation and indexes offline without repairing files.
    Verify {
        #[arg(long, value_name = "DIR")]
        output: PathBuf,
    },
    /// Print the committed attempts, artifacts, observations and links as one JSON document.
    Export {
        #[arg(long, value_name = "DIR")]
        output: PathBuf,
    },
}

#[derive(Debug, Args)]
pub struct Collect {
    #[arg(long, value_name = "DIR")]
    pub output: PathBuf,
    /// Public-inbox archive URL, repeatable. Defaults to the LKML archive on
    /// lore for a new corpus only. Every query runs against every source.
    #[arg(long, value_name = "URL")]
    pub source: Vec<String>,
    /// Query, repeatable. Defaults to f:torvalds for a new corpus only.
    /// Prefer explicit smaller date ranges for historical acquisition.
    #[arg(long, value_name = "QUERY")]
    pub query: Vec<String>,
    /// Selected mailbox, repeatable. Replaces the default candidate addresses.
    /// Check public mail evidence before adding aliases; keep that evidence separately.
    /// Source, query and author configuration cannot change within an existing corpus.
    #[arg(long, value_name = "ADDRESS")]
    pub author: Vec<String>,
    /// Re-execute completed units, retaining all previous observations.
    #[arg(long)]
    pub refresh: bool,
    /// Per-query acquisition deadline, including client setup, in seconds.
    #[arg(long, default_value = "1800")]
    pub timeout_seconds: NonZeroU64,
    /// Minimum interval after the persisted previous attempt finish, in seconds.
    #[arg(long, default_value = "5")]
    pub delay_seconds: NonZeroU64,
}
