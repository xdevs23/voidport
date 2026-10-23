use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use serde_json::json;

use crate::cli::Common;
use crate::fsutil;
use crate::report::{self, Rep, Run};

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

pub fn build_tree(common: &Common, dirs: u64, files_per_dir: u64, size_bytes: u64) -> Result<Run> {
    anyhow::ensure!(
        dirs > 0 && files_per_dir > 0,
        "the scenario needs files to create"
    );
    let files = dirs
        .checked_mul(files_per_dir)
        .context("the number of files in the tree does not fit in 64 bits")?;
    let bytes = files
        .checked_mul(size_bytes)
        .and_then(|written| written.checked_mul(2))
        .context("the bytes written and read back do not fit in 64 bits")?;
    let content = fsutil::filler(
        usize::try_from(size_bytes).context("the file size does not fit in memory")?,
    );
    let directory = fsutil::work_directory(&common.dir, "build-tree")?;
    let root = directory.join("tree");
    let params = json!({
        "dirs": dirs,
        "files_per_dir": files_per_dir,
        "size_bytes": size_bytes,
        "fsync": false,
    });

    report::drive("build-tree", common, params, |_| {
        let started = Instant::now();
        let paths = write_tree(&root, dirs, files_per_dir, &content)?;
        let written = started.elapsed();
        let mut buffer = Vec::with_capacity(content.len());
        for path in &paths {
            buffer.clear();
            File::open(path)
                .and_then(|mut file| file.read_to_end(&mut buffer))
                .with_context(|| format!("cannot read {}", path.display()))?;
            anyhow::ensure!(
                buffer == content,
                "reading {} returned bytes that differ from the bytes written",
                path.display()
            );
        }
        let read = started.elapsed();
        fs::remove_dir_all(&root).context("cannot remove the tree")?;
        let elapsed = started.elapsed();
        Ok(Rep::new(elapsed, files, bytes).with_extra(json!({
            "write_seconds": written.as_secs_f64(),
            "read_seconds": (read - written).as_secs_f64(),
            "remove_seconds": (elapsed - read).as_secs_f64(),
        })))
    })
}

fn write_tree(root: &Path, dirs: u64, files_per_dir: u64, content: &[u8]) -> Result<Vec<PathBuf>> {
    fs::create_dir(root).with_context(|| format!("cannot create {}", root.display()))?;
    let mut paths = Vec::new();
    for index in 0..dirs {
        let directory = root.join(format!("dir-{index}"));
        fs::create_dir(&directory)
            .with_context(|| format!("cannot create {}", directory.display()))?;
        for file in 0..files_per_dir {
            let path = directory.join(format!("file-{file}.o"));
            fs::write(&path, content)
                .with_context(|| format!("cannot write {}", path.display()))?;
            paths.push(path);
        }
    }
    Ok(paths)
}

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

pub fn walk(common: &Common, depth: u32, fanout: u64, files_per_dir: u64) -> Result<Run> {
    anyhow::ensure!(fanout > 0, "the scenario needs a branching factor");
    let directory = fsutil::work_directory(&common.dir, "walk")?;
    let root = directory.join("tree");
    let entries = create_tree(&root, depth, fanout, files_per_dir)?;
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

fn create_tree(root: &Path, depth: u32, fanout: u64, files_per_dir: u64) -> Result<u64> {
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
            entries += 1 + create_tree(&child, depth - 1, fanout, files_per_dir)?;
        }
    }
    Ok(entries)
}

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

/// FUSE sends every open and every release to the server, so neither is
/// served from a cache of the guest.
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

#[cfg(test)]
mod tests {
    use voidport_test_host::Scratch;

    use super::*;

    fn common(scratch: &Scratch) -> Common {
        Common {
            dir: scratch.path().to_path_buf(),
            label: "test".to_owned(),
            warmup: 1,
            reps: 2,
            drop_caches: false,
            json: None,
        }
    }

    #[test]
    fn a_build_tree_counts_every_file_and_leaves_nothing_behind() {
        let scratch = Scratch::new("bench-build-tree");
        let run = build_tree(&common(&scratch), 3, 4, 100).expect("the scenario runs");
        assert_eq!(run.per_rep.len(), 2);
        for rep in &run.per_rep {
            assert_eq!(rep.ops, 12);
            assert_eq!(rep.bytes, 2 * 12 * 100);
        }
        let work = fsutil::work_path(scratch.path(), run.scenario);
        let left = fs::read_dir(&work)
            .expect("the work directory of the scenario")
            .count();
        assert_eq!(left, 0, "{} is not empty", work.display());
    }

    #[test]
    fn a_build_tree_too_large_to_count_fails_before_it_creates_anything() {
        let scratch = Scratch::new("bench-build-tree-overflow");
        build_tree(&common(&scratch), u64::MAX, 2, 1).expect_err("the number of files overflows");
        assert!(!fsutil::work_path(scratch.path(), "build-tree").exists());
    }
}
