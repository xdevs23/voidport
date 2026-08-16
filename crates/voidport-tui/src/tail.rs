//! Following the server's log file, at the edge.
//!
//! This is the only place in the interface that opens a file, and it lives out
//! here for the same reason the socket does: the reducer is pure, so reading is
//! an [`Effect`](crate::event::Effect) that comes back as an
//! [`Event`](crate::event::Event). The loop asks for a read on its ordinary
//! tick; nothing here has a clock or a thread of its own.
//!
//! What it must survive is a file that is not a stream: `logrotate` renames it
//! and the server keeps writing to a *new* inode, `truncate` empties it in
//! place, and a restart replaces it. A reader that only remembers a byte offset
//! answers all three the same way — silence — which is the one failure a log
//! viewer must not have. So each read asks three questions of the file it is
//! about to continue, and starts over when any of them says this is not the
//! file it was reading: is it the same inode, is it still at least as long as
//! the offset, and does it still begin with the bytes it began with. The third
//! is what catches `logrotate --copytruncate`, where the file is emptied in
//! place and refilled past the old offset before the next tick — neither the
//! inode nor the length shows that, and a log's first line is timestamped, so
//! its opening bytes do.
//!
//! It is bounded in both directions: at most [`CHUNK`] bytes are taken per
//! read, and a file opened for the first time is entered near its end. The
//! whole file is never loaded, however large it has grown.

use std::fs::{File, Metadata};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use crate::model::logs::RING;

/// The most bytes one read takes from the file.
///
/// A server that logs faster than this per tick is read at this rate and
/// catches up over the following ticks — the ring would evict the surplus
/// anyway.
pub const CHUNK: u64 = 64 * 1024;

/// What one read of the log file produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogRead {
    /// The file that was read, so the model can tell a change of file from a
    /// continuation of the same one.
    pub path: PathBuf,
    /// The complete lines that appeared since the last read, oldest first.
    pub lines: Vec<String>,
    /// Why nothing could be read, in the operating system's own words.
    pub trouble: Option<String>,
}

/// A log file being followed.
#[derive(Debug, Default)]
pub struct Tail {
    following: Option<Following>,
}

impl Tail {
    /// A reader that is following nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads whatever `path` has gained since the last read of it.
    ///
    /// Never fails: a file that cannot be read is a [`LogRead::trouble`] the
    /// screen states, because a remote or permission-restricted attach is an
    /// ordinary situation and not an interface failure.
    pub fn read(&mut self, path: &Path) -> LogRead {
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => return self.give_up(path, &error),
        };
        // The same file as last time, still the file it was: carry on from the
        // offset.
        let carried = self.following.take().and_then(|mut following| {
            (following.path == path && following.continues(&metadata)).then_some(following)
        });
        // Otherwise — a first read, another server's file, a rotated-away
        // inode, or a file emptied under the reader — the offset describes
        // nothing, and every one of those is answered by entering the file as
        // a fresh reader would.
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

    /// Reports a read that failed and forgets the file, so the next tick opens
    /// it again — a log file that appears later is then picked up.
    fn give_up(&mut self, path: &Path, error: &std::io::Error) -> LogRead {
        self.following = None;
        LogRead {
            path: path.to_path_buf(),
            lines: Vec::new(),
            trouble: Some(error.to_string()),
        }
    }
}

/// The file, and where in it the reader is.
#[derive(Debug)]
struct Following {
    path: PathBuf,
    file: File,
    /// Which file this is, so a rotation is noticed instead of followed into
    /// silence.
    inode: u64,
    /// The next byte to read.
    offset: u64,
    /// Whether the offset is known to sit on a line boundary. It does not when
    /// a large file was entered near its end, and the partial line that starts
    /// there is dropped, not shown as a line.
    aligned: bool,
    /// The bytes after the last newline of the previous read: a line the
    /// server had not finished writing, held back until it is whole.
    partial: Vec<u8>,
    /// The bytes the file began with when it was last looked at, which is what
    /// tells an in-place truncation from a plain append.
    head: Vec<u8>,
}

/// How many of a file's first bytes identify it.
///
/// One timestamped log line is far longer than this; a file that still starts
/// with these bytes is the file it was.
const HEAD: usize = 64;

impl Following {
    /// Opens a file and enters it near its end.
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

    /// Whether the file on disk is still the one this reader is part-way
    /// through, and remembers it as it now is.
    fn continues(&mut self, metadata: &Metadata) -> bool {
        if self.inode != metadata.ino() || metadata.len() < self.offset {
            return false;
        }
        match head(&self.file) {
            // A file that has only grown still starts the way it did; a file
            // emptied and refilled in place does not.
            Ok(head) if head.starts_with(&self.head) => {
                self.head = head;
                true
            }
            _ => false,
        }
    }

    /// Takes up to [`CHUNK`] bytes and returns the complete lines in them.
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
        // The first line after entering a file part-way through is whatever was
        // being written at that byte, not a record.
        if !self.aligned {
            self.aligned = true;
            if !lines.is_empty() {
                lines.remove(0);
            }
        }
        Ok(lines)
    }
}

/// The first [`HEAD`] bytes of a file, or fewer if it is shorter.
///
/// Positional, so it never disturbs the offset the reader is following from.
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

    /// A directory that removes itself, under the root every suite in the
    /// workspace scratches in.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let path = voidportd::testing::scratch_root()
                .join(format!("voidport-tail-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            voidportd::testing::create_directory(&path);
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

        // Nothing new is nothing read, and not the file over again.
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

        // Emptied in place and refilled past the old offset before the next
        // read, which is what `logrotate --copytruncate` does: the inode is
        // the same and the file is *longer*, so only its opening bytes say so.
        std::fs::write(&path, "after the truncation\n").expect("truncates");
        assert_eq!(tail.read(&path).lines, vec!["after the truncation"]);

        // Emptied and left empty: the shrink alone is enough.
        std::fs::write(&path, "").expect("empties");
        assert_eq!(tail.read(&path).lines, Vec::<String>::new());
        append(&path, "after the emptying\n");
        assert_eq!(tail.read(&path).lines, vec!["after the emptying"]);

        // Rotated away: the same path, a different inode.
        std::fs::rename(&path, scratch.join("voidportd.log.1")).expect("rotates");
        append(&path, "after the rotation\n");
        assert_eq!(tail.read(&path).lines, vec!["after the rotation"]);
    }

    #[test]
    fn a_file_that_cannot_be_read_is_reported_rather_than_raised() {
        let scratch = Scratch::new("missing");
        let path = scratch.join("elsewhere.log");

        let mut tail = Tail::new();
        let read = tail.read(&path);
        assert!(read.lines.is_empty());
        assert!(read.trouble.is_some(), "a missing file said nothing");
        assert_eq!(read.path, path);

        // And a file that appears later is picked up without a restart.
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
        // The partial line the entry point landed in the middle of is not shown.
        assert!(
            read.lines
                .iter()
                .all(|line| line == &filler || line == "the newest line"),
            "a partial line was shown as a record"
        );
    }
}
