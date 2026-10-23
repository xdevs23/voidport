use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const FILE_SIZE: usize = 4096;

/// It runs on the same machine and in the same process as the workers, so a
/// busy machine slows it as much as it slows them. It reaches no mount and no
/// server, so nothing the server does can stop it.
#[derive(Debug)]
pub(crate) struct Reference {
    file: PathBuf,
    completed: AtomicU64,
}

impl Reference {
    pub(crate) fn new(file: PathBuf) -> Self {
        Self {
            file,
            completed: AtomicU64::new(0),
        }
    }

    pub(crate) fn prepare(work_dir: &Path) -> io::Result<Self> {
        let file = work_dir.join("reference");
        fs::write(&file, [0u8; FILE_SIZE])?;
        Ok(Self::new(file))
    }

    /// A failed operation counts as one, as it does for the workers of the run.
    pub(crate) fn work_until(&self, stop: &AtomicBool) {
        let mut failed = false;
        while !stop.load(Ordering::Relaxed) {
            if let Err(error) = self.step()
                && !failed
            {
                failed = true;
                eprintln!(
                    "!!! voidport-torture: the reference work on {} failed: {error}",
                    self.file.display()
                );
            }
            self.record();
        }
    }

    fn step(&self) -> io::Result<()> {
        fs::read(&self.file).map(drop)
    }

    pub(crate) fn record(&self) {
        self.completed.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn completed(&self) -> u64 {
        self.completed.load(Ordering::SeqCst)
    }

    pub(crate) fn remove(&self) {
        let _ = fs::remove_file(&self.file);
    }
}
