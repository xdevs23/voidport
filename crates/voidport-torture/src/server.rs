//! The server the run owns, and the two ways it is taken away.
//!
//! Every other part of this harness treats the server as something that is
//! simply there. The restart class cannot: its whole subject is the server
//! going away and coming back, and a server that goes away has to be a real
//! process for the interesting half of that to be possible at all. An
//! in-process server can be asked to stop; it cannot be **killed**, and a clean
//! stop proves nothing about crash consistency.
//!
//! So the harness starts a `voidportd` of its own and holds it here, with the
//! two stops the contract distinguishes:
//!
//! * `SIGTERM` — the ordered shutdown, where everything in flight is finished
//!   and the state file is left as the last mutation wrote it;
//! * `SIGKILL` — nothing is flushed, nothing is unlinked, and whatever the
//!   state file holds is whatever the last `rename` published. That is the
//!   crash-consistency property, and it is only observable this way.
//!
//! # Two orderings that are not optional
//!
//! **The launcher is made before any mount exists.** A restart cannot be a
//! plain spawn from the harness process: `execve` closes every inherited
//! close-on-exec descriptor in the forked child, closing one on a voidport
//! mount issues a synchronous `FLUSH`, and a mount whose server has just been
//! killed stalls that `FLUSH` for the whole reconnect window — so the child
//! would sit inside `exec` until the window it was meant to land inside had
//! already closed. The harness's workers hold descriptors on the mounts by
//! design. The launcher is therefore started while the process holds none, and
//! every server the run starts comes from it. This is the same reason and the
//! same shape as the client's resilience suites.
//!
//! **The data address survives the restart.** A restart is only a restart if
//! the mounts can find the server again, which means the address is written in
//! the state file: a unix path, or a vsock port. A tcp listener on port 0
//! re-resolves to a different port when the server comes back, so a run that
//! restarts must not be pointed at one.

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal};
use voidport::url::MountUrl;

use crate::resource::ServerPid;
use crate::wire;

/// How long a server is given to stop, or to start serving.
///
/// Both take milliseconds when they work; this is the bound past which "the
/// server is slow" has become "the server is not coming". It is stated
/// alongside the healing patience for a reason the restart class's own
/// documentation gives: their sum is how long that class can go without
/// completing anything, and that has to stay inside the progress watchdog.
pub(crate) const PATIENCE: Duration = Duration::from_secs(30);

/// How long the readiness handshake waits for the server's answer.
const HANDSHAKE_PATIENCE: Duration = Duration::from_secs(10);

/// How often the stop and start waits look again.
const POLL: Duration = Duration::from_millis(20);

/// How a restart takes the server away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// `SIGTERM`: the ordered shutdown the operator's own `Ctrl-C` performs.
    Graceful,
    /// `SIGKILL`: the crash. Nothing is flushed and nothing is cleaned up.
    Hard,
}

impl Stop {
    /// The signal this stop sends.
    #[must_use]
    fn signal(self) -> Signal {
        match self {
            Self::Graceful => Signal::TERM,
            Self::Hard => Signal::KILL,
        }
    }

    /// The name a report spells it with.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Graceful => "graceful",
            Self::Hard => "hard",
        }
    }
}

/// A `voidportd` process the run starts, stops and starts again.
#[derive(Debug)]
pub struct Supervisor {
    state: PathBuf,
    control: PathBuf,
    /// What a data connection is proven against: dialling this and completing
    /// the handshake is the definition of "the server is serving".
    ready: MountUrl,
    /// The pid the sampler watches, kept current across every restart.
    pid: ServerPid,
    /// Starts every server this handle runs, from outside this process.
    launcher: Mutex<Launcher>,
    /// The running server's pid, or `None` while it is down. Held apart from
    /// the launcher so a stop and a start cannot interleave.
    running: Mutex<Option<Pid>>,
    /// Held shared by every worker performing a control-plane mutation, and
    /// exclusively by the restart arm while it takes the state file's picture
    /// and signals. What the exclusive side buys is a well-defined *last
    /// persisted mutation*: no other worker's persist can land in the window,
    /// so the bytes on disk after the signal are the bytes from before it or
    /// the ones the restart arm's own mutation published, and nothing else.
    quiet: RwLock<()>,
    /// Graceful stops performed, and hard ones. Counted here because this is
    /// what performs them, and reported because "the run restarted the server"
    /// is only a claim if the number is in the report.
    stops: [AtomicU64; 2],
    /// Hard stops whose signal fell between a control mutation's request and
    /// its reply — the interval the server's write-and-rename persist lives
    /// in. Counted for the same reason: a crash-consistency assertion that
    /// never met a persist has asserted nothing, and the number is what says
    /// which it was.
    inside_mutation: AtomicU64,
}

/// How many restarts of each kind a run performed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Restarts {
    /// Stops by `SIGTERM`, each followed by a start.
    pub graceful: u64,
    /// Stops by `SIGKILL`, each followed by a start.
    pub hard: u64,
    /// How many of the hard ones the server died inside a control mutation
    /// for: the request was on the wire and no reply ever came.
    pub inside_mutation: u64,
}

impl Supervisor {
    /// Starts a server and waits until it serves.
    ///
    /// Call this **before mounting anything** — see this module's header for
    /// the kernel behaviour that makes the ordering load-bearing.
    ///
    /// `log` is where the server's own output goes, appended across restarts;
    /// a run that wants none passes `/dev/null`.
    ///
    /// # Errors
    ///
    /// Returns the failure to start the launcher, or the server never serving
    /// within its patience.
    pub fn start(
        binary: &Path,
        state: &Path,
        control: &Path,
        ready: &MountUrl,
        log: &Path,
    ) -> anyhow::Result<Self> {
        let supervisor = Self {
            state: state.to_path_buf(),
            control: control.to_path_buf(),
            ready: ready.clone(),
            pid: ServerPid::default(),
            launcher: Mutex::new(Launcher::start(binary, state, control, log)?),
            running: Mutex::new(None),
            quiet: RwLock::new(()),
            stops: [AtomicU64::new(0), AtomicU64::new(0)],
            inside_mutation: AtomicU64::new(0),
        };
        supervisor.start_again()?;
        Ok(supervisor)
    }

    /// The state file the server serves.
    #[must_use]
    pub fn state_file(&self) -> &Path {
        &self.state
    }

    /// The control socket the server listens on.
    #[must_use]
    pub fn control_socket(&self) -> &Path {
        &self.control
    }

    /// The pid cell the resource sampler reads.
    #[must_use]
    pub fn pid(&self) -> ServerPid {
        self.pid.clone()
    }

    /// How many stops of each kind this supervisor has performed.
    ///
    /// The teardown's own stop is not among them: this is read while the run is
    /// still holding the supervisor.
    #[must_use]
    pub fn restarts(&self) -> Restarts {
        Restarts {
            graceful: self.stops[0].load(Ordering::Relaxed),
            hard: self.stops[1].load(Ordering::Relaxed),
            inside_mutation: self.inside_mutation.load(Ordering::Relaxed),
        }
    }

    /// Records that the hard stop just performed took the server away between
    /// a control mutation's request and its reply.
    ///
    /// Called by the caller that issued the mutation, because only it can see
    /// that the reply never arrived.
    pub fn note_stop_inside_mutation(&self) {
        self.inside_mutation.fetch_add(1, Ordering::Relaxed);
    }

    /// Takes the shared side of the quiet gate, for a control-plane mutation.
    ///
    /// # Panics
    ///
    /// Never: a poisoned gate is recovered, because a worker that panicked
    /// says nothing about whether the next mutation may proceed.
    pub fn mutating(&self) -> RwLockReadGuard<'_, ()> {
        self.quiet
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Takes the exclusive side, so no control mutation is in flight.
    ///
    /// # Panics
    ///
    /// Never, for the same reason as [`Self::mutating`].
    pub fn quiesce(&self) -> RwLockWriteGuard<'_, ()> {
        self.quiet
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Stops the running server and waits until the process is gone.
    ///
    /// Waiting for the *process*, not for a refused connection: a killed
    /// server leaves its unix socket file behind and a terminated one unlinks
    /// it, so only the process table answers the same question for both stops.
    /// The launcher reaps the corpse, which is what makes the answer arrive.
    ///
    /// A stop that did not take keeps the pid: the process is still there, and
    /// forgetting it would leave the next start racing a server that is still
    /// serving the same address.
    ///
    /// # Errors
    ///
    /// Returns the failure to signal, or the process still being there when
    /// the patience runs out.
    pub fn stop(&self, stop: Stop) -> anyhow::Result<()> {
        let mut running = self
            .running
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(pid) = *running else {
            return Ok(());
        };
        self.stops[usize::from(stop == Stop::Hard)].fetch_add(1, Ordering::Relaxed);
        self.pid.clear();
        rustix::process::kill_process(pid, stop.signal())?;
        let deadline = Instant::now() + PATIENCE;
        while alive(pid) {
            anyhow::ensure!(
                Instant::now() < deadline,
                "the server did not stop within {} s of a {} stop",
                PATIENCE.as_secs(),
                stop.name()
            );
            std::thread::sleep(POLL);
        }
        *running = None;
        self.launcher
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .forget(pid);
        Ok(())
    }

    /// Starts a server on the current state file and waits until it serves.
    ///
    /// "Serves" is a completed handshake on the run's own data URL, not a bound
    /// socket: a server that accepts and then refuses the hello is not one a
    /// mount can heal against, and it is exactly the shape the reconnect
    /// contract distinguishes.
    ///
    /// # Errors
    ///
    /// Returns the launcher's failure, or the server never completing a
    /// handshake within its patience.
    pub fn start_again(&self) -> anyhow::Result<()> {
        let mut running = self
            .running
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        anyhow::ensure!(running.is_none(), "a server is already running");
        let pid = self
            .launcher
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .launch()?;
        *running = Some(pid);
        self.pid.set(pid.as_raw_nonzero().get().unsigned_abs());

        let deadline = Instant::now() + PATIENCE;
        loop {
            if let Ok(session) = wire::Session::mount(&self.ready, HANDSHAKE_PATIENCE) {
                drop(session);
                return Ok(());
            }
            anyhow::ensure!(
                Instant::now() < deadline && alive(pid),
                "the server never completed a handshake within {} s of starting",
                PATIENCE.as_secs()
            );
            std::thread::sleep(POLL);
        }
    }
}

impl Drop for Supervisor {
    /// The teardown stops the server the way an operator does, and kills only
    /// what will not go.
    ///
    /// The distinction is the state file's: a `SIGTERM` leaves it as the last
    /// mutation wrote it, and a run whose every shutdown was a kill would be
    /// leaving the next run to start on whatever the last `rename` happened to
    /// publish. The kill stays as the fallback, because a server that ignores
    /// its shutdown must not outlive the run either.
    fn drop(&mut self) {
        if let Err(graceful) = self.stop(Stop::Graceful) {
            eprintln!("!!! voidport-torture: the server would not stop: {graceful}");
            if let Err(hard) = self.stop(Stop::Hard) {
                eprintln!("!!! voidport-torture: the server would not die either: {hard}");
            }
        }
    }
}

/// Whether a process the launcher started is still there.
///
/// The launcher reaps what it starts, so a pid that has left `/proc` is a
/// process that has both exited and been waited for.
fn alive(pid: Pid) -> bool {
    Path::new(&format!("/proc/{}", pid.as_raw_nonzero())).exists()
}

/// Starts server processes, from outside this process's descriptor table.
///
/// One shell, started before the run holds anything, reading one line per
/// server to start and reporting the pid it started. See this module's header
/// for why the harness may not spawn them itself.
#[derive(Debug)]
struct Launcher {
    shell: Child,
    /// One line written here starts one server.
    commands: ChildStdin,
    /// One line read back is the pid it started.
    started: BufReader<ChildStdout>,
    /// The server it started and has not been told is gone.
    ///
    /// A server is the shell's *background* job, so killing the shell leaves it
    /// running under init, holding the data address and the state file's lock;
    /// the launcher therefore has to name it to take it down. It is cleared as
    /// soon as a stop has seen the process leave the table, so what is killed
    /// here can only ever be a process this launcher started and nobody has
    /// waited for.
    last: Option<Pid>,
}

/// What the launcher runs: a server per line read, its pid reported back, and
/// the corpse reaped before the next line is taken.
///
/// The daemon binary and its three paths arrive as `$0` to `$3` — as arguments,
/// never interpolated into the text — so no path is ever quoted into a script.
const LAUNCH: &str = "while IFS= read -r _command; do \
     \"$0\" --state \"$1\" --control-socket \"$2\" </dev/null >>\"$3\" 2>&1 & \
     echo \"$!\"; \
     wait \"$!\"; \
     done";

impl Launcher {
    /// Starts a launcher for one server's command line.
    fn start(daemon: &Path, state: &Path, control: &Path, log: &Path) -> anyhow::Result<Self> {
        anyhow::ensure!(
            daemon.exists(),
            "{} is missing: build the workspace so the server binary exists",
            daemon.display()
        );
        let mut shell = Command::new("/bin/sh")
            .arg("-c")
            .arg(LAUNCH)
            .arg(daemon)
            .arg(state)
            .arg(control)
            .arg(log)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let commands = shell
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("the launcher has no stdin"))?;
        let started = BufReader::new(
            shell
                .stdout
                .take()
                .ok_or_else(|| anyhow::anyhow!("the launcher has no stdout"))?,
        );
        Ok(Self {
            shell,
            commands,
            started,
            last: None,
        })
    }

    /// Starts one server and returns its pid.
    fn launch(&mut self) -> anyhow::Result<Pid> {
        writeln!(self.commands, "start")?;
        self.commands.flush()?;
        let mut reported = String::new();
        self.started.read_line(&mut reported)?;
        let raw: i32 = reported
            .trim()
            .parse()
            .map_err(|error| anyhow::anyhow!("the launcher answered {reported:?}: {error}"))?;
        let pid =
            Pid::from_raw(raw).ok_or_else(|| anyhow::anyhow!("the launcher answered pid {raw}"))?;
        self.last = Some(pid);
        Ok(pid)
    }

    /// Forgets a server whose exit the caller has already seen.
    fn forget(&mut self, pid: Pid) {
        if self.last == Some(pid) {
            self.last = None;
        }
    }
}

impl Drop for Launcher {
    /// Whatever the supervisor's own stop could not take down goes here: the
    /// server first, because it is the process holding the address and the
    /// state file, and the shell after it.
    fn drop(&mut self) {
        if let Some(pid) = self.last.take() {
            let _ = rustix::process::kill_process(pid, Signal::KILL);
        }
        let _ = self.shell.kill();
        let _ = self.shell.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two stops are two signals and two names, and nothing about them is
    /// derived from the other.
    #[test]
    fn the_two_stops_are_the_two_signals() {
        assert_eq!(Stop::Graceful.signal(), Signal::TERM);
        assert_eq!(Stop::Hard.signal(), Signal::KILL);
        assert_eq!(Stop::Graceful.name(), "graceful");
        assert_eq!(Stop::Hard.name(), "hard");
    }

    /// This process is alive, and pid 1 exists on every Linux machine; a pid
    /// past the maximum exists nowhere.
    #[test]
    fn the_liveness_probe_reads_the_process_table() {
        let mine = Pid::from_raw(i32::try_from(std::process::id()).expect("a pid")).expect("a pid");
        assert!(alive(mine));
        assert!(!alive(Pid::from_raw(i32::MAX).expect("a pid")));
    }

    /// The launcher takes down the server it started and nobody collected —
    /// and only that one. A pid a stop has already seen leave the process
    /// table is forgotten, so a teardown can never signal a number the machine
    /// has since handed to somebody else.
    #[test]
    fn a_launcher_forgets_the_server_a_stop_already_collected() {
        let nothing = Path::new("/dev/null");
        let mut launcher = Launcher::start(Path::new("/bin/sh"), nothing, nothing, nothing)
            .expect("a launcher starts");
        assert_eq!(launcher.last, None, "nothing has been launched yet");

        let started = Pid::from_raw(424_242).expect("a pid");
        launcher.last = Some(started);
        launcher.forget(Pid::from_raw(1).expect("a pid"));
        assert_eq!(
            launcher.last,
            Some(started),
            "a different pid is not this one"
        );
        launcher.forget(started);
        assert_eq!(launcher.last, None);
    }

    /// A supervisor pointed at a binary that is not there says so instead of
    /// starting a shell that will never answer.
    #[test]
    fn a_missing_server_binary_is_reported_at_once() {
        let url = MountUrl::parse("voidport://127.0.0.1:1/@ns").expect("a url");
        let error = Supervisor::start(
            Path::new("/nonexistent/voidportd"),
            Path::new("/nonexistent/state.toml"),
            Path::new("/nonexistent/control.sock"),
            &url,
            Path::new("/dev/null"),
        )
        .expect_err("a server binary that is not there cannot be started");
        assert!(error.to_string().contains("is missing"), "{error:#}");
    }
}
