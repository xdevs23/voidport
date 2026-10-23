mod concurrent;
mod file;
mod meta;

use std::time::Duration;

use anyhow::Result;

use crate::cli::{Common, Scenario};
use crate::report::Run;

pub fn run(scenario: &Scenario, common: &Common) -> Result<Run> {
    match *scenario {
        Scenario::SeqWrite {
            size_mib,
            chunk_kib,
        } => file::seq_write(common, size_mib, chunk_kib),
        Scenario::SeqRead {
            size_mib,
            chunk_kib,
        } => file::seq_read(common, size_mib, chunk_kib),
        Scenario::RandRead4k {
            size_mib,
            block_kib,
            ops,
        } => file::rand_read(common, size_mib, block_kib, ops),
        Scenario::SmallFiles { count, size_bytes } => meta::small_files(common, count, size_bytes),
        Scenario::BuildTree {
            dirs,
            files_per_dir,
            size_bytes,
        } => meta::build_tree(common, dirs, files_per_dir, size_bytes),
        Scenario::StatLoop { files, ops } => meta::stat_loop(common, files, ops),
        Scenario::ReaddirLoop { entries, listings } => {
            meta::readdir_loop(common, entries, listings)
        }
        Scenario::Walk {
            depth,
            fanout,
            files_per_dir,
        } => meta::walk(common, depth, fanout, files_per_dir),
        Scenario::OpenCloseLoop { files, ops } => meta::open_close_loop(common, files, ops),
        Scenario::OneWriterManyReaders {
            readers,
            records,
            record_bytes,
            interval_ms,
            timeout_ms,
            poll_us,
        } => concurrent::one_writer_many_readers(
            common,
            readers,
            records,
            record_bytes,
            Duration::from_millis(interval_ms),
            Duration::from_millis(timeout_ms),
            Duration::from_micros(poll_us),
        ),
        Scenario::ParallelRw {
            threads,
            ops_per_thread,
            block_kib,
            file_mib,
        } => concurrent::parallel_rw(common, threads, ops_per_thread, block_kib, file_mib),
    }
}
