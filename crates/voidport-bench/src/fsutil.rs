//! The small filesystem and randomness helpers every scenario shares.
//!
//! Nothing here is measured: it is the setup a scenario performs around the
//! window it times.

use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

/// The directory a scenario owns inside the benchmarked target.
///
/// Every scenario works in its own subdirectory of a shared `voidport-bench`
/// directory, so one backend's leftovers cannot be another's warm cache, and a
/// whole run is removable by deleting one name.
pub fn work_directory(base: &Path, scenario: &str) -> Result<PathBuf> {
    let path = base.join("voidport-bench").join(scenario);
    if path.exists() {
        fs::remove_dir_all(&path).with_context(|| format!("cannot clear {}", path.display()))?;
    }
    fs::create_dir_all(&path).with_context(|| format!("cannot create {}", path.display()))?;
    Ok(path)
}

/// `sync(2)` and then drop the page, dentry and inode caches.
///
/// Root-only, and deliberately loud when it fails: a read scenario that
/// silently kept its cache would report the wrong filesystem entirely. Note
/// that this does not evict tmpfs contents — tmpfs pages *are* the storage —
/// which is exactly why the tmpfs baseline is a memory baseline.
pub fn drop_caches() -> Result<()> {
    rustix::fs::sync();
    fs::write("/proc/sys/vm/drop_caches", b"3\n").context("cannot drop the page cache (needs root)")
}

/// Writes a file of `size` bytes, `chunk` bytes at a time, and fsyncs it.
pub fn write_file(path: &Path, size: u64, chunk: usize) -> Result<()> {
    let buffer = filler(chunk);
    let mut file =
        File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
    let mut written = 0u64;
    while written < size {
        let take = chunk.min((size - written) as usize);
        file.write_all(&buffer[..take])
            .with_context(|| format!("cannot write {}", path.display()))?;
        written += take as u64;
    }
    file.sync_all()
        .with_context(|| format!("cannot fsync {}", path.display()))?;
    Ok(())
}

/// Creates `count` files of `size` bytes each, named `file-<n>`, and returns
/// their paths in creation order.
pub fn populate(directory: &Path, count: u64, size: u64) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::with_capacity(count as usize);
    for index in 0..count {
        let path = directory.join(format!("file-{index}"));
        write_file(&path, size, 64 * 1024)?;
        paths.push(path);
    }
    Ok(paths)
}

/// A buffer of non-zero bytes, so nothing measured can be a hole.
pub fn filler(size: usize) -> Vec<u8> {
    (0..size).map(|index| (index % 251) as u8 | 1).collect()
}

/// A deterministic pseudorandom source (xorshift64\*).
///
/// Offsets have to be unpredictable to the readahead heuristics but repeatable
/// across backends: the same seed gives every backend the same access pattern.
#[derive(Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Seeds the generator; the seed is coerced away from the fixed point 0.
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed | 0x9E37_79B9_7F4A_7C15,
        }
    }

    /// The next value.
    pub fn next_u64(&mut self) -> u64 {
        let mut state = self.state;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        self.state = state;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A value below `bound` (which must be nonzero).
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generator_is_deterministic_and_bounded() {
        let first: Vec<u64> = (0..8)
            .scan(Rng::new(7), |rng, _| Some(rng.below(1024)))
            .collect();
        let second: Vec<u64> = (0..8)
            .scan(Rng::new(7), |rng, _| Some(rng.below(1024)))
            .collect();
        assert_eq!(first, second);
        assert!(first.iter().all(|value| *value < 1024));
        assert_ne!(first, vec![0; 8]);
    }

    #[test]
    fn filler_never_writes_a_zero_byte() {
        assert!(filler(1024).iter().all(|byte| *byte != 0));
    }
}
