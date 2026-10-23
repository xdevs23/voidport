use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// The voidport benchmark harness.
#[derive(Debug, Parser)]
#[command(name = "voidport-bench", version, about)]
pub struct Cli {
    /// What every scenario needs.
    #[command(flatten)]
    pub common: Common,
    /// The workload to measure.
    #[command(subcommand)]
    pub scenario: Scenario,
}

/// The options every scenario takes.
#[derive(Debug, Clone, Args)]
pub struct Common {
    /// The directory to benchmark. The scenario works inside a subdirectory of
    /// it and removes that subdirectory's previous contents first.
    #[arg(long, value_name = "PATH")]
    pub dir: PathBuf,
    /// Names the backend in the emitted record.
    #[arg(long, value_name = "NAME", default_value = "unlabeled")]
    pub label: String,
    /// Unmeasured repetitions run before the measured ones.
    #[arg(long, value_name = "N", default_value_t = 1)]
    pub warmup: u32,
    /// Measured repetitions.
    #[arg(long, value_name = "N", default_value_t = 5)]
    pub reps: u32,
    /// sync(2) and drop the page, dentry and inode caches before every
    /// repetition. Needs root; required for an honest read measurement.
    #[arg(long)]
    pub drop_caches: bool,
    /// Append the JSON line to this file as well as writing it to stdout.
    #[arg(long, value_name = "PATH")]
    pub json: Option<PathBuf>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Scenario {
    /// Create a file, write it sequentially, fsync, close.
    #[command(name = "seq-write")]
    SeqWrite {
        /// The file size.
        #[arg(long, value_name = "MIB", default_value_t = 256)]
        size_mib: u64,
        /// The write size.
        #[arg(long, value_name = "KIB", default_value_t = 128)]
        chunk_kib: u64,
    },
    /// Read a prepared file sequentially from start to end.
    #[command(name = "seq-read")]
    SeqRead {
        /// The file size.
        #[arg(long, value_name = "MIB", default_value_t = 256)]
        size_mib: u64,
        /// The read size.
        #[arg(long, value_name = "KIB", default_value_t = 128)]
        chunk_kib: u64,
    },
    /// Read small blocks at pseudorandom offsets of one prepared file.
    #[command(name = "rand-read-4k")]
    RandRead4k {
        /// The file size.
        #[arg(long, value_name = "MIB", default_value_t = 256)]
        size_mib: u64,
        /// The block size.
        #[arg(long, value_name = "KIB", default_value_t = 4)]
        block_kib: u64,
        /// How many reads one repetition performs.
        #[arg(long, value_name = "N", default_value_t = 20000)]
        ops: u64,
    },
    /// Create, write, fsync and close many small files.
    #[command(name = "small-files")]
    SmallFiles {
        /// How many files one repetition creates.
        #[arg(long, value_name = "N", default_value_t = 1000)]
        count: u64,
        /// The size of each file.
        #[arg(long, value_name = "BYTES", default_value_t = 4096)]
        size_bytes: u64,
    },
    /// Create a directory tree of small files, read them back, remove the tree.
    #[command(name = "build-tree")]
    BuildTree {
        /// How many directories the tree has.
        #[arg(long, value_name = "N", default_value_t = 32)]
        dirs: u64,
        /// How many files each directory has.
        #[arg(long, value_name = "N", default_value_t = 64)]
        files_per_dir: u64,
        /// The size of each file.
        #[arg(long, value_name = "BYTES", default_value_t = 4096)]
        size_bytes: u64,
    },
    /// Stat files by path, round-robin over a prepared set.
    #[command(name = "stat-loop")]
    StatLoop {
        /// How many files the set holds.
        #[arg(long, value_name = "N", default_value_t = 512)]
        files: u64,
        /// How many stats one repetition performs.
        #[arg(long, value_name = "N", default_value_t = 20000)]
        ops: u64,
    },
    /// List a directory of many entries, repeatedly.
    #[command(name = "readdir-loop")]
    ReaddirLoop {
        /// How many entries the directory holds.
        #[arg(long, value_name = "N", default_value_t = 1000)]
        entries: u64,
        /// How many full listings one repetition performs.
        #[arg(long, value_name = "N", default_value_t = 200)]
        listings: u64,
    },
    /// Walk a whole directory tree, stat'ing every entry.
    #[command(name = "walk")]
    Walk {
        /// How many levels of directories the tree has below its root.
        #[arg(long, value_name = "N", default_value_t = 3)]
        depth: u32,
        /// How many subdirectories each level holds.
        #[arg(long, value_name = "N", default_value_t = 8)]
        fanout: u64,
        /// How many files each directory holds.
        #[arg(long, value_name = "N", default_value_t = 8)]
        files_per_dir: u64,
    },
    /// Open and immediately close files, round-robin over a prepared set.
    #[command(name = "open-close-loop")]
    OpenCloseLoop {
        /// How many files the set holds.
        #[arg(long, value_name = "N", default_value_t = 64)]
        files: u64,
        /// How many open/close pairs one repetition performs.
        #[arg(long, value_name = "N", default_value_t = 20000)]
        ops: u64,
    },
    /// One writer appending records while readers poll for them.
    #[command(name = "one-writer-many-readers")]
    OneWriterManyReaders {
        /// How many reader threads poll.
        #[arg(long, value_name = "N", default_value_t = 4)]
        readers: u64,
        /// How many records the writer appends.
        #[arg(long, value_name = "N", default_value_t = 40)]
        records: u64,
        /// The size of one record.
        #[arg(long, value_name = "BYTES", default_value_t = 4096)]
        record_bytes: u64,
        /// How long the writer waits between records. Pacing is what makes the
        /// visibility latency a visibility latency and not a queue depth.
        #[arg(long, value_name = "MS", default_value_t = 100)]
        interval_ms: u64,
        /// How long a reader polls for one record before giving up on it.
        #[arg(long, value_name = "MS", default_value_t = 5000)]
        timeout_ms: u64,
        /// How long a reader waits between polls.
        #[arg(long, value_name = "US", default_value_t = 200)]
        poll_us: u64,
    },
    /// Threads doing mixed reads and writes on their own files at once.
    #[command(name = "parallel-rw")]
    ParallelRw {
        /// How many threads.
        #[arg(long, value_name = "N", default_value_t = 8)]
        threads: u64,
        /// How many write+read pairs each thread performs.
        #[arg(long, value_name = "N", default_value_t = 500)]
        ops_per_thread: u64,
        /// The size of one read and of one write.
        #[arg(long, value_name = "KIB", default_value_t = 64)]
        block_kib: u64,
        /// The size of each thread's file.
        #[arg(long, value_name = "MIB", default_value_t = 32)]
        file_mib: u64,
    },
}

impl Scenario {
    pub fn name(&self) -> &'static str {
        match self {
            Self::SeqWrite { .. } => "seq-write",
            Self::SeqRead { .. } => "seq-read",
            Self::RandRead4k { .. } => "rand-read-4k",
            Self::SmallFiles { .. } => "small-files",
            Self::BuildTree { .. } => "build-tree",
            Self::StatLoop { .. } => "stat-loop",
            Self::ReaddirLoop { .. } => "readdir-loop",
            Self::Walk { .. } => "walk",
            Self::OpenCloseLoop { .. } => "open-close-loop",
            Self::OneWriterManyReaders { .. } => "one-writer-many-readers",
            Self::ParallelRw { .. } => "parallel-rw",
        }
    }
}
