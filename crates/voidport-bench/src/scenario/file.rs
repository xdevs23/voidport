use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::FileExt as _;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use serde_json::json;

use crate::cli::Common;
use crate::fsutil;
use crate::report::{self, Rep, Run};

const MIB: u64 = 1024 * 1024;

/// The fsync is inside the window on purpose: without it the measurement
/// covers the page cache of the guest on every backend that has one.
pub fn seq_write(common: &Common, size_mib: u64, chunk_kib: u64) -> Result<Run> {
    let directory = fsutil::work_directory(&common.dir, "seq-write")?;
    let size = size_mib * MIB;
    let chunk = (chunk_kib * 1024) as usize;
    anyhow::ensure!(size > 0 && chunk > 0, "the file and the chunk need a size");
    let buffer = fsutil::filler(chunk);
    let path = directory.join("stream.bin");
    let params = json!({ "size_mib": size_mib, "chunk_kib": chunk_kib, "fsync": true });

    report::drive("seq-write", common, params, |_| {
        if path.exists() {
            fs::remove_file(&path).context("cannot clear the previous file")?;
        }
        let started = Instant::now();
        let mut file = File::create(&path).context("cannot create the file")?;
        let mut written = 0u64;
        while written < size {
            let take = chunk.min((size - written) as usize);
            file.write_all(&buffer[..take]).context("cannot write")?;
            written += take as u64;
        }
        file.sync_all().context("cannot fsync")?;
        drop(file);
        Ok(Rep::new(
            started.elapsed(),
            size.div_ceil(chunk as u64),
            size,
        ))
    })
}

pub fn seq_read(common: &Common, size_mib: u64, chunk_kib: u64) -> Result<Run> {
    let directory = fsutil::work_directory(&common.dir, "seq-read")?;
    let size = size_mib * MIB;
    let chunk = (chunk_kib * 1024) as usize;
    anyhow::ensure!(size > 0 && chunk > 0, "the file and the chunk need a size");
    let path = directory.join("stream.bin");
    fsutil::write_file(&path, size, chunk)?;
    let params = json!({ "size_mib": size_mib, "chunk_kib": chunk_kib });

    let mut buffer = vec![0u8; chunk];
    report::drive("seq-read", common, params, |_| {
        let started = Instant::now();
        let mut file = File::open(&path).context("cannot open the file")?;
        let mut read = 0u64;
        let mut calls = 0u64;
        loop {
            let count = file.read(&mut buffer).context("cannot read")?;
            if count == 0 {
                break;
            }
            read += count as u64;
            calls += 1;
        }
        let elapsed = started.elapsed();
        anyhow::ensure!(read == size, "the file read back short: {read} of {size}");
        Ok(Rep::new(elapsed, calls, read))
    })
}

pub fn rand_read(common: &Common, size_mib: u64, block_kib: u64, ops: u64) -> Result<Run> {
    let directory = fsutil::work_directory(&common.dir, "rand-read-4k")?;
    let size = size_mib * MIB;
    let block = (block_kib * 1024) as usize;
    anyhow::ensure!(block > 0 && size >= block as u64, "the block must fit");
    anyhow::ensure!(ops > 0, "the scenario needs operations to perform");
    let path = directory.join("stream.bin");
    fsutil::write_file(&path, size, 1024 * 1024)?;
    let blocks = size / block as u64;
    let params = json!({ "size_mib": size_mib, "block_kib": block_kib, "ops": ops });

    let mut buffer = vec![0u8; block];
    report::drive("rand-read-4k", common, params, |_| {
        let file = File::open(&path).context("cannot open the file")?;
        let mut rng = fsutil::Rng::new(0x5EED_5EED);
        let mut latencies: Vec<Duration> = Vec::with_capacity(ops as usize);
        let started = Instant::now();
        for _ in 0..ops {
            let offset = rng.below(blocks) * block as u64;
            let at = Instant::now();
            file.read_exact_at(&mut buffer, offset)
                .with_context(|| format!("cannot read at {offset}"))?;
            latencies.push(at.elapsed());
        }
        let elapsed = started.elapsed();
        Ok(Rep::new(elapsed, ops, ops * block as u64).with_latencies(latencies))
    })
}
