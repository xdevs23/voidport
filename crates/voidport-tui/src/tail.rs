//! A log file is not a stream: `logrotate` renames it and the server writes to
//! a new inode, `truncate` empties it in place, and a restart replaces it.
//! Each read therefore checks the file it is about to continue and starts
//! over when it is not the file it was reading: the inode, the length against
//! the offset, and the first bytes. The first bytes catch
//! `logrotate --copytruncate`, where the file is emptied and refilled past
//! the old offset before the next tick, so neither the inode nor the length
//! changes.

use std::fs::{File, Metadata};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use crate::model::logs::RING;

/// A server that logs faster than this per tick is read at this rate and
/// catches up over the following ticks, because the ring evicts the surplus
/// anyway.
pub const CHUNK: u64 = 64 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogRead {
    pub path: PathBuf,
    pub lines: Vec<String>,
    pub trouble: Option<String>,
}

#[derive(Debug, Default)]
pub struct Tail {
    following: Option<Following>,
}

impl Tail {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Never fails: an unreadable file is a [`LogRead::trouble`] that the screen
    /// states.
    pub fn read(&mut self, path: &Path) -> LogRead {
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => return self.give_up(path, &error),
        };
        let carried = self.following.take().and_then(|mut following| {
            (following.path == path && following.continues(&metadata)).then_some(following)
        });
        let mut following = match carried {
            Some(following) => following,
            None => match Following::open(path, &metadata) {
                Ok(following) => following,
                Err(error) => return self.give_up(path, &error),
            },
        };
        match following.read() {
            Ok(mut lines) => {
                // The ring would evict everything beyond its bound anyway.
                if lines.len() > RING {
                    lines.drain(..lines.len() - RING);
                }
                self.following = Some(following);
                LogRead {
                    path: path.to_path_buf(),
                    lines,
                    trouble: None,
                }
            }
            Err(error) => self.give_up(path, &error),
        }
    }

    /// Forgets the file, so the next tick opens it again and a log file that
    /// appears later is picked up.
    fn give_up(&mut self, path: &Path, error: &std::io::Error) -> LogRead {
        self.following = None;
        LogRead {
            path: path.to_path_buf(),
            lines: Vec::new(),
            trouble: Some(error.to_string()),
        }
    }
}

#[derive(Debug)]
struct Following {
    path: PathBuf,
    file: File,
    inode: u64,
    offset: u64,
    /// Whether the offset is known to sit on a line boundary. It does not when a
    /// large file was entered near its end, and the partial line there is
    /// dropped.
    aligned: bool,
    partial: Vec<u8>,
    head: Vec<u8>,
}

/// A timestamped log line is longer than this, so these bytes identify the
/// file.
const HEAD: usize = 64;

impl Following {
    fn open(path: &Path, metadata: &Metadata) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let offset = metadata.len().saturating_sub(CHUNK);
        let head = head(&file)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            inode: metadata.ino(),
            offset,
            aligned: offset == 0,
            partial: Vec::new(),
            head,
        })
    }

    fn continues(&mut self, metadata: &Metadata) -> bool {
        if self.inode != metadata.ino() || metadata.len() < self.offset {
            return false;
        }
        match head(&self.file) {
            Ok(head) if head.starts_with(&self.head) => {
                self.head = head;
                true
            }
            _ => false,
        }
    }

    fn read(&mut self) -> std::io::Result<Vec<String>> {
        let mut buffer = vec![0_u8; usize::try_from(CHUNK).unwrap_or(usize::MAX)];
        self.file.seek(SeekFrom::Start(self.offset))?;
        let taken = self.file.read(&mut buffer)?;
        self.offset += taken as u64;
        self.partial.extend_from_slice(&buffer[..taken]);

        let mut lines = Vec::new();
        while let Some(end) = self.partial.iter().position(|byte| *byte == b'\n') {
            let line = self.partial.drain(..=end).collect::<Vec<u8>>();
            let text = String::from_utf8_lossy(&line[..end])
                .trim_end_matches('\r')
                .to_owned();
            lines.push(text);
        }
        if !self.aligned {
            self.aligned = true;
            if !lines.is_empty() {
                lines.remove(0);
            }
        }
        Ok(lines)
    }
}

/// Positional, so it never disturbs the offset the reader follows from.
fn head(file: &File) -> std::io::Result<Vec<u8>> {
    let mut buffer = [0_u8; HEAD];
    let mut filled = 0;
    while filled < HEAD {
        match file.read_at(&mut buffer[filled..], filled as u64)? {
            0 => break,
            taken => filled += taken,
        }
    }
    Ok(buffer[..filled].to_vec())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let path = voidport_test_host::scratch_root()
                .join(format!("voidport-tail-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            voidport_test_host::create_directory(&path);
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn append(path: &Path, text: &str) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("the log file opens");
        file.write_all(text.as_bytes())
            .expect("the log file writes");
    }

    #[test]
    fn a_tail_reads_only_what_appeared_since_the_last_read() {
        let scratch = Scratch::new("incremental");
        let path = scratch.join("voidportd.log");
        append(&path, "first\nsecond\n");

        let mut tail = Tail::new();
        let read = tail.read(&path);
        assert_eq!(read.lines, vec!["first", "second"]);
        assert_eq!(read.trouble, None);
        assert_eq!(read.path, path);

        assert_eq!(tail.read(&path).lines, Vec::<String>::new());

        append(&path, "third\n");
        assert_eq!(tail.read(&path).lines, vec!["third"]);
    }

    #[test]
    fn a_half_written_line_is_held_back_until_it_is_whole() {
        let scratch = Scratch::new("partial");
        let path = scratch.join("voidportd.log");
        append(&path, "whole\npart");

        let mut tail = Tail::new();
        assert_eq!(tail.read(&path).lines, vec!["whole"]);
        append(&path, "ial\n");
        assert_eq!(tail.read(&path).lines, vec!["partial"]);
    }

    #[test]
    fn truncation_and_rotation_reopen_instead_of_going_quiet() {
        let scratch = Scratch::new("rotation");
        let path = scratch.join("voidportd.log");
        append(&path, "before\n");
        let mut tail = Tail::new();
        assert_eq!(tail.read(&path).lines, vec!["before"]);

        // `logrotate --copytruncate`: the inode is the same and the file is longer
        // than the old offset.
        std::fs::write(&path, "after the truncation\n").expect("truncates");
        assert_eq!(tail.read(&path).lines, vec!["after the truncation"]);

        std::fs::write(&path, "").expect("empties");
        assert_eq!(tail.read(&path).lines, Vec::<String>::new());
        append(&path, "after the emptying\n");
        assert_eq!(tail.read(&path).lines, vec!["after the emptying"]);

        std::fs::rename(&path, scratch.join("voidportd.log.1")).expect("rotates");
        append(&path, "after the rotation\n");
        assert_eq!(tail.read(&path).lines, vec!["after the rotation"]);
    }

    #[test]
    fn a_file_that_cannot_be_read_is_reported_not_raised() {
        let scratch = Scratch::new("missing");
        let path = scratch.join("elsewhere.log");

        let mut tail = Tail::new();
        let read = tail.read(&path);
        assert!(read.lines.is_empty());
        assert!(read.trouble.is_some(), "a missing file said nothing");
        assert_eq!(read.path, path);

        append(&path, "here now\n");
        let read = tail.read(&path);
        assert_eq!(read.trouble, None);
        assert_eq!(read.lines, vec!["here now"]);
    }

    #[test]
    fn a_large_file_is_entered_near_its_end() {
        let scratch = Scratch::new("large");
        let path = scratch.join("voidportd.log");
        let filler = "x".repeat(99);
        for _ in 0..(CHUNK / 100 + 200) {
            append(&path, &format!("{filler}\n"));
        }
        append(&path, "the newest line\n");

        let mut tail = Tail::new();
        let read = tail.read(&path);
        let bytes: usize = read.lines.iter().map(|line| line.len() + 1).sum();
        assert!(
            u64::try_from(bytes).expect("small") <= CHUNK,
            "the whole file was loaded: {bytes} bytes"
        );
        assert_eq!(
            read.lines.last().map(String::as_str),
            Some("the newest line")
        );
        assert!(
            read.lines
                .iter()
                .all(|line| line == &filler || line == "the newest line"),
            "a partial line was shown as a record"
        );
    }
}
