//! A child starts with a copy of the descriptor table of the thread that starts
//! it. Its `execve` closes every copy that is close-on-exec, and closing a copy
//! of a file of a FUSE mount waits for the reply of the mount. The kernel lets
//! go of a closed copy only once `execve` has returned (`do_close_on_exec` in
//! `fs/file.c`, `__fput_deferred` in `fs/file_table.c`), so the mount is busy
//! until then, and a mount whose server is gone replies to the flush only once
//! its stall window has passed. A descriptor whose close-on-exec flag is
//! cleared in a shared table would be inherited for good by every other child
//! started meanwhile.
//!
//! [`Program::spawn`] therefore starts every child from one launcher thread
//! whose descriptor table is emptied. It copies the descriptors given to a
//! child with `pidfd_getfd`. Emptying the table first copies every descriptor
//! of the process below 64 (`sane_fdtable_size` in `fs/file.c`). A file closed
//! by another thread meanwhile is released only once the launcher has closed
//! the copy, and a `flock` lock on it lasts until then.

#![deny(
    unreachable_pub,
    unsafe_op_in_unsafe_fn,
    unused_results,
    clippy::all,
    clippy::pedantic,
    clippy::let_underscore_must_use
)]

mod launcher;

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus, Output};

use self::launcher::{Grouping, Launcher, Request, Source};

const STREAMS: [RawFd; 3] = [0, 1, 2];

const STDERR: RawFd = 2;

#[derive(Debug)]
pub struct Program<'fd> {
    executable: OsString,
    arguments: Vec<OsString>,
    working_directory: Option<PathBuf>,
    clear_environment: bool,
    environment: Vec<(OsString, Option<OsString>)>,
    grouping: Grouping,
    streams: [Stream<'fd>; 3],
    descriptors: BTreeMap<RawFd, BorrowedFd<'fd>>,
}

#[derive(Clone, Copy, Debug)]
pub enum Stream<'fd> {
    Null,
    /// The same stream of the calling thread, or `/dev/null` where it has none.
    Inherit,
    Piped,
    Descriptor(BorrowedFd<'fd>),
}

#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    #[error("the thread that starts the child processes could not be started")]
    Launcher(#[source] io::Error),
    #[error("the thread that starts the child processes has ended")]
    LauncherGone,
    #[error("descriptor {0} was given at the number of a standard stream")]
    StandardStream(RawFd),
    #[error("a pipe for a standard stream of the child could not be made")]
    Pipe(#[source] io::Error),
    #[error("a descriptor of the child could not be copied into the launcher")]
    Copy(#[source] io::Error),
    #[error("descriptor {0} of the child is taken in the table of the launcher")]
    Taken(RawFd),
    #[error("the program could not be started")]
    Program(#[source] io::Error),
    #[error("waiting for the program failed")]
    Wait(#[source] io::Error),
}

impl<'fd> Program<'fd> {
    #[must_use]
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            executable: program.as_ref().to_owned(),
            arguments: Vec::new(),
            working_directory: None,
            clear_environment: false,
            environment: Vec::new(),
            grouping: Grouping::Inherited,
            streams: [Stream::Null; 3],
            descriptors: BTreeMap::new(),
        }
    }

    pub fn arg(&mut self, argument: impl AsRef<OsStr>) -> &mut Self {
        self.arguments.push(argument.as_ref().to_owned());
        self
    }

    pub fn args<A: AsRef<OsStr>>(&mut self, arguments: impl IntoIterator<Item = A>) -> &mut Self {
        self.arguments.extend(
            arguments
                .into_iter()
                .map(|argument| argument.as_ref().to_owned()),
        );
        self
    }

    /// Starts `wrapper` with `arguments`, followed by the program and the
    /// arguments given so far.
    pub fn run_through<A: AsRef<OsStr>>(
        &mut self,
        wrapper: impl AsRef<OsStr>,
        arguments: impl IntoIterator<Item = A>,
    ) -> &mut Self {
        let program = std::mem::replace(&mut self.executable, wrapper.as_ref().to_owned());
        let program_arguments = std::mem::take(&mut self.arguments);
        self.args(arguments).arg(program).args(program_arguments)
    }

    pub fn env(&mut self, name: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Self {
        self.environment
            .push((name.as_ref().to_owned(), Some(value.as_ref().to_owned())));
        self
    }

    pub fn env_remove(&mut self, name: impl AsRef<OsStr>) -> &mut Self {
        self.environment.push((name.as_ref().to_owned(), None));
        self
    }

    /// Starts the child with only the variables set after this call.
    pub fn env_clear(&mut self) -> &mut Self {
        self.clear_environment = true;
        self.environment.clear();
        self
    }

    pub fn current_dir(&mut self, directory: impl AsRef<Path>) -> &mut Self {
        self.working_directory = Some(directory.as_ref().to_owned());
        self
    }

    pub fn in_new_process_group(&mut self) -> &mut Self {
        self.grouping = Grouping::NewProcessGroup;
        self
    }

    /// Starts the child as the leader of a new session whose controlling
    /// terminal is the standard input of the child. The start fails with
    /// [`SpawnError::Program`] when the standard input is not a terminal.
    pub fn in_new_session_on_terminal(&mut self) -> &mut Self {
        self.grouping = Grouping::NewSessionOnTerminal;
        self
    }

    pub fn stdin(&mut self, stream: Stream<'fd>) -> &mut Self {
        self.streams[0] = stream;
        self
    }

    pub fn stdout(&mut self, stream: Stream<'fd>) -> &mut Self {
        self.streams[1] = stream;
        self
    }

    pub fn stderr(&mut self, stream: Stream<'fd>) -> &mut Self {
        self.streams[2] = stream;
        self
    }

    /// A later call with the same `number` replaces the descriptor.
    pub fn descriptor(&mut self, number: RawFd, descriptor: BorrowedFd<'fd>) -> &mut Self {
        let _replaced = self.descriptors.insert(number, descriptor);
        self
    }

    /// # Errors
    ///
    /// [`SpawnError::StandardStream`] for a descriptor at the number of a
    /// standard stream, and the errors of the start of the launcher and of the
    /// program.
    pub fn spawn(&self) -> Result<Child, SpawnError> {
        if let Some(&number) = self.descriptors.keys().find(|&&number| number <= STDERR) {
            return Err(SpawnError::StandardStream(number));
        }
        let launcher = Launcher::of_process()?;
        let [stdin, stdout, stderr] =
            std::array::from_fn(|index| prepare(self.streams[index], STREAMS[index]));
        let (stdin, stdout, stderr) = (
            stdin.map_err(SpawnError::Pipe)?,
            stdout.map_err(SpawnError::Pipe)?,
            stderr.map_err(SpawnError::Pipe)?,
        );
        let mut child = launcher.spawn(Request {
            executable: self.executable.clone(),
            arguments: self.arguments.clone(),
            working_directory: self.working_directory.clone(),
            clear_environment: self.clear_environment,
            environment: self.environment.clone(),
            grouping: self.grouping,
            streams: [stdin.0, stdout.0, stderr.0],
            descriptors: self
                .descriptors
                .iter()
                .map(|(&number, descriptor)| (number, descriptor.as_raw_fd()))
                .collect(),
        })?;
        // The child has its copies, so the ends of the child are closed here.
        child.stdin = stdin.1.map(|pipe| ChildStdin::from(pipe.ours));
        child.stdout = stdout.1.map(|pipe| ChildStdout::from(pipe.ours));
        child.stderr = stderr.1.map(|pipe| ChildStderr::from(pipe.ours));
        Ok(child)
    }

    /// # Errors
    ///
    /// The errors of [`Program::spawn`], and [`SpawnError::Wait`].
    pub fn status(&self) -> Result<ExitStatus, SpawnError> {
        self.spawn()?.wait().map_err(SpawnError::Wait)
    }

    /// # Errors
    ///
    /// The errors of [`Program::spawn`], and [`SpawnError::Wait`].
    pub fn output(&mut self) -> Result<Output, SpawnError> {
        self.stdout(Stream::Piped)
            .stderr(Stream::Piped)
            .spawn()?
            .wait_with_output()
            .map_err(SpawnError::Wait)
    }
}

struct Pipe {
    /// The launcher copies this end.
    theirs: OwnedFd,
    ours: OwnedFd,
}

impl Pipe {
    fn new(number: RawFd) -> io::Result<Self> {
        let (reader, writer) = io::pipe()?;
        let (theirs, ours) = if number == STREAMS[0] {
            (OwnedFd::from(reader), OwnedFd::from(writer))
        } else {
            (OwnedFd::from(writer), OwnedFd::from(reader))
        };
        Ok(Self { theirs, ours })
    }
}

fn prepare(stream: Stream<'_>, number: RawFd) -> io::Result<(Source, Option<Pipe>)> {
    Ok(match stream {
        Stream::Null => (Source::Null, None),
        Stream::Inherit => (Source::CopyIfOpen(number), None),
        Stream::Descriptor(descriptor) => (Source::Copy(descriptor.as_raw_fd()), None),
        Stream::Piped => {
            let pipe = Pipe::new(number)?;
            (Source::Copy(pipe.theirs.as_raw_fd()), Some(pipe))
        }
    })
}

/// Emptying the descriptor table closes the copy of every file in it, and a
/// file closed by another thread meanwhile is released only afterwards. Call
/// this before the process opens a file of a FUSE mount, and before the first
/// `flock` lock that one thread can release and another can set again.
///
/// # Errors
///
/// [`SpawnError::Launcher`] or [`SpawnError::LauncherGone`].
pub fn start_launcher() -> Result<(), SpawnError> {
    Launcher::of_process().map(drop)
}

#[cfg(test)]
mod tests;
