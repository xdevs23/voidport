use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Mutex, PoisonError};

use rustix::io::{Errno, FdFlags, fcntl_dupfd_cloexec, fcntl_setfd};
use rustix::process::{Pid, PidfdFlags, PidfdGetfdFlags, pidfd_getfd, pidfd_open};
use rustix::thread::gettid;

use crate::{STDERR, SpawnError};

static PROCESS: Mutex<Option<Launcher>> = Mutex::new(None);

#[derive(Clone, Debug)]
pub(crate) struct Launcher {
    requests: SyncSender<Asked>,
}

/// The thread that asks has the descriptors open until the answer arrives.
#[derive(Debug)]
pub(crate) struct Request {
    pub(crate) executable: OsString,
    pub(crate) arguments: Vec<OsString>,
    pub(crate) working_directory: Option<PathBuf>,
    pub(crate) clear_environment: bool,
    pub(crate) environment: Vec<(OsString, Option<OsString>)>,
    pub(crate) grouping: Grouping,
    /// The standard input, output and error, in this order.
    pub(crate) streams: [Source; 3],
    /// Each descriptor above the standard streams, as its number in the
    /// child and its number in the table of the thread that asks.
    pub(crate) descriptors: Vec<(RawFd, RawFd)>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Grouping {
    Inherited,
    NewProcessGroup,
    NewSessionOnTerminal,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Source {
    Null,
    Copy(RawFd),
    CopyIfOpen(RawFd),
}

#[derive(Debug)]
struct Asked {
    request: Request,
    asker: Pid,
    started: SyncSender<Result<Child, SpawnError>>,
}

impl Launcher {
    pub(crate) fn of_process() -> Result<Self, SpawnError> {
        let mut process = PROCESS.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(launcher) = &*process {
            return Ok(launcher.clone());
        }
        let launcher = Self::start()?;
        *process = Some(launcher.clone());
        Ok(launcher)
    }

    fn start() -> Result<Self, SpawnError> {
        let (requests, received) = sync_channel(0);
        let (report, reported) = sync_channel(1);
        let _thread = std::thread::Builder::new()
            .name("voidport-launcher".to_owned())
            .spawn(move || match empty_table() {
                Ok(streams) => {
                    let _reported = report.send(Ok(()));
                    serve(&received);
                    drop(streams);
                }
                Err(error) => {
                    let _reported = report.send(Err(error));
                }
            })
            .map_err(SpawnError::Launcher)?;
        reported
            .recv()
            .map_err(|_| SpawnError::LauncherGone)?
            .map_err(SpawnError::Launcher)?;
        Ok(Self { requests })
    }

    pub(crate) fn spawn(&self, request: Request) -> Result<Child, SpawnError> {
        let (started, child) = sync_channel(1);
        self.requests
            .send(Asked {
                request,
                asker: gettid(),
                started,
            })
            .map_err(|_| SpawnError::LauncherGone)?;
        child.recv().map_err(|_| SpawnError::LauncherGone)?
    }
}

/// While the returned standard streams are open, every descriptor opened later
/// gets a number above them.
fn empty_table() -> io::Result<[File; 3]> {
    let unshare = libc::CLOSE_RANGE_UNSHARE.cast_signed();
    // SAFETY: Unavoidable: neither std nor rustix unshares a descriptor table
    // or closes descriptors by range. With `CLOSE_RANGE_UNSHARE`, the kernel
    // first gives this thread a copy of the table of the process, and closes
    // every descriptor in that copy only. The table of every other thread is
    // unchanged, so no descriptor owned elsewhere is closed. This thread owns
    // no descriptor yet, and from here on it uses only the descriptors it
    // opens itself or copies with `pidfd_getfd`. That the flag closes the copy
    // alone is what `close_range` in `fs/file.c` does for a shared table.
    let closed = unsafe { libc::close_range(0, libc::c_uint::MAX, unshare) };
    if closed != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok([
        File::open("/dev/null")?,
        File::open("/dev/null")?,
        File::open("/dev/null")?,
    ])
}

fn serve(requests: &Receiver<Asked>) {
    for asked in requests {
        let _answered = asked.started.send(start(&asked.request, asked.asker));
    }
}

/// Every copy is first made above the highest number that the child gets, so
/// each of those numbers is free once the descriptor of `asker` is closed.
/// Each copy is then put at its number without close-on-exec.
fn start(request: &Request, asker: Pid) -> Result<Child, SpawnError> {
    let above = request
        .descriptors
        .iter()
        .map(|&(number, _)| number)
        .max()
        .unwrap_or(STDERR)
        + 1;
    let asker = pidfd_open(asker, PidfdFlags::from_bits_retain(libc::PIDFD_THREAD))
        .map_err(|errno| SpawnError::Copy(errno.into()))?;
    let copy = |number| {
        pidfd_getfd(&asker, number, PidfdGetfdFlags::empty())
            .and_then(|copied| fcntl_dupfd_cloexec(&copied, above))
    };
    let stream = |source| match source {
        Source::Null => Ok(Stdio::null()),
        Source::Copy(number) => copy(number).map(Stdio::from),
        Source::CopyIfOpen(number) => match copy(number) {
            Err(Errno::BADF) => Ok(Stdio::null()),
            copied => copied.map(Stdio::from),
        },
    };
    let [stdin, stdout, stderr] = request.streams.map(stream);
    let mut command = Command::new(&request.executable);
    let _command = command
        .args(&request.arguments)
        .stdin(stdin.map_err(|errno| SpawnError::Copy(errno.into()))?)
        .stdout(stdout.map_err(|errno| SpawnError::Copy(errno.into()))?)
        .stderr(stderr.map_err(|errno| SpawnError::Copy(errno.into()))?);
    if request.clear_environment {
        let _command = command.env_clear();
    }
    for (name, value) in &request.environment {
        let _command = match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    if let Some(directory) = &request.working_directory {
        let _command = command.current_dir(directory);
    }
    match request.grouping {
        Grouping::Inherited => {}
        Grouping::NewProcessGroup => {
            let _command = command.process_group(0);
        }
        Grouping::NewSessionOnTerminal => {
            // SAFETY: Unavoidable: std makes a child the leader of a new
            // session only through `pre_exec`, since its `setsid` is
            // unstable. `pre_exec` requires a hook that is async-signal-safe,
            // since it runs in the forked child after the standard streams are
            // in place. The hook makes the two system calls directly through
            // the rustix functions for them, which allocate nothing and take
            // no lock, and an `Errno` becomes an `io::Error` without an
            // allocation.
            let _command = unsafe { command.pre_exec(lead_session_on_terminal) };
        }
    }
    let copies = request
        .descriptors
        .iter()
        .map(|&(number, source)| copy(source).map(|copied| (number, copied)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|errno| SpawnError::Copy(errno.into()))?;
    drop(asker);
    let placed = copies
        .iter()
        .map(|(number, copied)| place(copied, *number))
        .collect::<Result<Vec<_>, _>>()?;
    let child = command.spawn().map_err(SpawnError::Program);
    drop(placed);
    child
}

fn lead_session_on_terminal() -> io::Result<()> {
    let _session = rustix::process::setsid()?;
    rustix::process::ioctl_tiocsctty(rustix::stdio::stdin())?;
    Ok(())
}

/// A copy at `number` without close-on-exec, for a child. The table of the
/// launcher thread is not shared and between two starts contains only its
/// standard streams, so no other child can inherit the descriptor.
fn place(copied: &OwnedFd, number: RawFd) -> Result<OwnedFd, SpawnError> {
    let placed =
        fcntl_dupfd_cloexec(copied, number).map_err(|errno| SpawnError::Copy(errno.into()))?;
    if placed.as_raw_fd() != number {
        return Err(SpawnError::Taken(number));
    }
    fcntl_setfd(&placed, FdFlags::empty()).map_err(|errno| SpawnError::Copy(errno.into()))?;
    Ok(placed)
}
