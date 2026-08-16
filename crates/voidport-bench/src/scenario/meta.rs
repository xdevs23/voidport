//! Metadata workloads: many small files, stat, readdir, open/close.
//!
//! These are the per-operation classes — what a build tree, a `find`, or a
//! package manager does — and the ones a proxy filesystem is judged on.

use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use serde_json::json;

use crate::cli::Common;
use crate::fsutil;
use crate::report::{self, Rep, Run};

/// Create, write, fsync and close many small files.
///
/// One operation is a whole file's life, which is what the workload actually
/// costs: a lookup, a create, a write, an fsync and a release.
pub fn small_files(common: &Common, count: u64, size_bytes: u64) -> Result<Run> {
    anyhow::ensure!(count > 0, "the scenario needs files to create");
    let directory = fsutil::work_directory(&common.dir, "small-files")?;
    let buffer = fsutil::filler(size_bytes as usize);
    let params = json!({ "count": count, "size_bytes": size_bytes, "fsync": true });

    report::drive("small-files", common, params, move |_| {
        let batch = directory.join("batch");
        if batch.exists() {
            fs::remove_dir_all(&batch).context("cannot clear the previous batch")?;
        }
        fs::create_dir(&batch).context("cannot create the batch directory")?;

        let mut latencies: Vec<Duration> = Vec::with_capacity(count as usize);
        let started = Instant::now();
        for index in 0..count {
            let path = batch.join(format!("file-{index}"));
            let at = Instant::now();
            let mut file = File::create(&path).context("cannot create a file")?;
            file.write_all(&buffer).context("cannot write a file")?;
            file.sync_all().context("cannot fsync a file")?;
            drop(file);
            latencies.push(at.elapsed());
        }
        let elapsed = started.elapsed();
        Ok(Rep::new(elapsed, count, count * size_bytes).with_latencies(latencies))
    })
}

/// Stat files by path, round-robin over a prepared set.
///
/// The path is resolved every time, so one operation is a lookup plus a
/// getattr — on a caching client, whatever survives of them.
pub fn stat_loop(common: &Common, files: u64, ops: u64) -> Result<Run> {
    anyhow::ensure!(files > 0 && ops > 0, "the scenario needs files and ops");
    let directory = fsutil::work_directory(&common.dir, "stat-loop")?;
    let paths = fsutil::populate(&directory, files, 4096)?;
    let params = json!({ "files": files, "ops": ops });

    report::drive("stat-loop", common, params, |_| {
        let mut latencies: Vec<Duration> = Vec::with_capacity(ops as usize);
        let started = Instant::now();
        for index in 0..ops {
            let path = &paths[(index % files) as usize];
            let at = Instant::now();
            let metadata = fs::metadata(path).context("cannot stat")?;
            latencies.push(at.elapsed());
            anyhow::ensure!(metadata.len() == 4096, "a file changed size under the loop");
        }
        let elapsed = started.elapsed();
        Ok(Rep::new(elapsed, ops, 0).with_latencies(latencies))
    })
}

/// List a directory of many entries, repeatedly.
///
/// One operation is a full listing: opendir, every readdir call the directory
/// needs, closedir. Names only — no per-entry stat — so this measures the
/// listing path itself.
pub fn readdir_loop(common: &Common, entries: u64, listings: u64) -> Result<Run> {
    anyhow::ensure!(entries > 0 && listings > 0, "the scenario needs both");
    let directory = fsutil::work_directory(&common.dir, "readdir-loop")?;
    let listing = directory.join("entries");
    fs::create_dir(&listing).context("cannot create the listing directory")?;
    fsutil::populate(&listing, entries, 0)?;
    let params = json!({ "entries": entries, "listings": listings });

    report::drive("readdir-loop", common, params, |_| {
        let mut latencies: Vec<Duration> = Vec::with_capacity(listings as usize);
        let started = Instant::now();
        for _ in 0..listings {
            let at = Instant::now();
            let mut seen = 0u64;
            for entry in fs::read_dir(&listing).context("cannot open the directory")? {
                let _ = entry.context("cannot read a directory entry")?.file_name();
                seen += 1;
            }
            latencies.push(at.elapsed());
            anyhow::ensure!(seen == entries, "listing returned {seen} of {entries}");
        }
        let elapsed = started.elapsed();
        Ok(Rep::new(elapsed, listings, 0)
            .with_latencies(latencies)
            .with_extra(json!({
                "entries_per_second": entries as f64 * listings as f64 / elapsed.as_secs_f64(),
            })))
    })
}

/// Walk a whole directory tree, stat'ing every entry, repeatedly.
///
/// This is the shape a build's module finder has — and the shape that exhausted
/// the server's descriptor table in the field: one repetition resolves *every
/// name in the tree*, so the number of names a run touches grows with the tree,
/// not with a working set the guest revisits. One operation is one
/// entry: its listing plus the `lstat` that classifies it.
pub fn walk(common: &Common, depth: u32, fanout: u64, files_per_dir: u64) -> Result<Run> {
    anyhow::ensure!(fanout > 0, "the scenario needs a branching factor");
    let directory = fsutil::work_directory(&common.dir, "walk")?;
    let root = directory.join("tree");
    let entries = build_tree(&root, depth, fanout, files_per_dir)?;
    let params = json!({
        "depth": depth,
        "fanout": fanout,
        "files_per_dir": files_per_dir,
        "entries": entries,
    });

    report::drive("walk", common, params, move |_| {
        let started = Instant::now();
        let seen = walk_tree(&root)?;
        let elapsed = started.elapsed();
        anyhow::ensure!(
            seen == entries,
            "the walk saw {seen} entries of the {entries} the tree holds"
        );
        Ok(Rep::new(elapsed, seen, 0).with_extra(json!({
            "entries_per_second": seen as f64 / elapsed.as_secs_f64(),
        })))
    })
}

/// Creates a tree `depth` levels deep, `fanout` directories and
/// `files_per_dir` empty files per level, and reports how many entries it
/// holds below its root.
fn build_tree(root: &Path, depth: u32, fanout: u64, files_per_dir: u64) -> Result<u64> {
    fs::create_dir_all(root).with_context(|| format!("cannot create {}", root.display()))?;
    let mut entries = 0;
    for index in 0..files_per_dir {
        let path = root.join(format!("file-{index}"));
        File::create(&path).with_context(|| format!("cannot create {}", path.display()))?;
        entries += 1;
    }
    if depth > 0 {
        for index in 0..fanout {
            let child = root.join(format!("dir-{index}"));
            entries += 1 + build_tree(&child, depth - 1, fanout, files_per_dir)?;
        }
    }
    Ok(entries)
}

/// Lists a tree and stats every entry, exactly as a source-tree scan does, and
/// reports how many entries it saw.
fn walk_tree(root: &Path) -> Result<u64> {
    let mut seen = 0;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("cannot open {}", directory.display()))?
        {
            let entry = entry.context("cannot read a directory entry")?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("cannot stat {}", path.display()))?;
            seen += 1;
            if metadata.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(seen)
}

/// Open a file read-only and immediately close it, round-robin over a set.
///
/// Neither half is ever served from a guest cache: FUSE sends every open and
/// every release to the server. This is the cleanest per-operation round trip
/// the harness has.
pub fn open_close_loop(common: &Common, files: u64, ops: u64) -> Result<Run> {
    anyhow::ensure!(files > 0 && ops > 0, "the scenario needs files and ops");
    let directory = fsutil::work_directory(&common.dir, "open-close-loop")?;
    let paths = fsutil::populate(&directory, files, 4096)?;
    let params = json!({ "files": files, "ops": ops });

    report::drive("open-close-loop", common, params, |_| {
        let mut latencies: Vec<Duration> = Vec::with_capacity(ops as usize);
        let started = Instant::now();
        for index in 0..ops {
            let path = &paths[(index % files) as usize];
            let at = Instant::now();
            let file = File::open(path).context("cannot open")?;
            drop(file);
            latencies.push(at.elapsed());
        }
        let elapsed = started.elapsed();
        Ok(Rep::new(elapsed, ops, 0).with_latencies(latencies))
    })
}
