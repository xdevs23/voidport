use std::fmt;
use std::io;
use std::os::fd::OwnedFd;

use rustix::io::Errno;

#[derive(Debug, Default)]
pub struct KernelLog(pub(super) Vec<Logged>);

#[derive(Debug)]
pub(super) enum Logged {
    Message { level: Level, text: String },
    Unreadable(io::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Level {
    Error,
    Warning,
    Info,
    Unmarked,
}

impl Logged {
    /// A record is a level letter, a space and the text, ended by a newline.
    pub(super) fn message(record: &str) -> Self {
        let record = record.trim_end();
        let (level, text) = match record.split_once(' ') {
            Some(("e", text)) => (Level::Error, text),
            Some(("w", text)) => (Level::Warning, text),
            Some(("i", text)) => (Level::Info, text),
            _ => (Level::Unmarked, record),
        };
        Self::Message {
            level,
            text: text.to_owned(),
        }
    }
}

impl KernelLog {
    /// A read of an empty log fails with `ENODATA`. A read into a buffer shorter
    /// than the next message fails with `EMSGSIZE` and leaves that message in
    /// the log (`fetch_message_locked` in `fs/fsopen.c`,
    /// <https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/fs/fsopen.c?h=v6.18.56>).
    pub(super) fn read(context: &OwnedFd) -> Self {
        let mut buffer = vec![0; rustix::param::page_size()];
        let mut logged = Vec::new();
        loop {
            match rustix::io::read(context, &mut buffer[..]) {
                Ok(len) => logged.push(Logged::message(&String::from_utf8_lossy(&buffer[..len]))),
                Err(Errno::NODATA) => break,
                Err(Errno::MSGSIZE) => buffer.resize(buffer.len() * 2, 0),
                Err(Errno::INTR) => {}
                Err(error) => {
                    logged.push(Logged::Unreadable(error.into()));
                    break;
                }
            }
        }
        Self(logged)
    }
}

impl fmt::Display for KernelLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for logged in &self.0 {
            match logged {
                Logged::Message {
                    level: Level::Error | Level::Unmarked,
                    text,
                } => write!(f, ": {text}")?,
                Logged::Message {
                    level: Level::Warning,
                    text,
                } => write!(f, ": warning: {text}")?,
                Logged::Message {
                    level: Level::Info,
                    text,
                } => write!(f, ": info: {text}")?,
                Logged::Unreadable(error) => {
                    write!(f, ": the kernel's messages could not be read: {error}")?;
                }
            }
        }
        Ok(())
    }
}
