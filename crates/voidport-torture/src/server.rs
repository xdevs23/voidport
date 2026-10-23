//! The server is a real process, because an in-process server cannot be killed
//! and a clean stop proves nothing about crash consistency.
//!
//! The servers come from a launcher started through `voidport_spawn`, whose
//! descriptor table contains no descriptor on a mount. A plain spawn from the
//! harness process would sit inside `execve`: closing a close-on-exec
//! descriptor on a voidport mount issues a synchronous `FLUSH`, which stalls
//! for the whole reconnect window when the server of that mount was just
//! killed.
//!
//! The data address survives a restart: it is a unix path or a vsock port,
//! because a tcp listener on port 0 comes back on a different port.

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal};
use voidport::url::MountUrl;
use voidport_spawn::{Program, Stream};

use crate::resource::ServerPid;
use crate::wire;

pub(crate) const PATIENCE: Duration = Duration::from_secs(30);

const HANDSHAKE_PATIENCE: Duration = Duration::from_secs(10);

const POLL: Duration = Duration::from_millis(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    Graceful,
    Hard,
}

impl Stop {
    #[must_use]
    fn signal(self) -> Signal {
        match self {
            Self::Graceful => Signal::TERM,
            Self::Hard => Signal::KILL,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Graceful => "graceful",
            Self::Hard => "hard",
        }
    }
}

#[derive(Debug)]
pub struct Supervisor {
    state: PathBuf,
    control: PathBuf,
    ready: MountUrl,
    pid: ServerPid,
    launcher: Mutex<Launcher>,
    /// Held apart from the launcher so a stop and a start cannot interleave.
    running: Mutex<Option<Pid>>,
    /// Held shared by every worker performing a control-plane mutation, and
    /// exclusively by the restart arm while it takes the picture of the state
    /// file and signals. No other persist can happen in that window, so the
    /// bytes on disk after the signal are the bytes from before it or those
    /// published by the mutation of the restart arm.
    quiet: RwLock<()>,
    stops: [AtomicU64; 2],
    /// Hard stops whose signal fell between the request and the reply of a
    /// control mutation, the interval of the persist of the server. A
    /// crash-consistency assertion that never met a persist asserts nothing.
    inside_mutation: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Restarts {
    pub graceful: u64,
    pub hard: u64,
    pub inside_mutation: u64,
}

impl Supervisor {
    /// Call this before mounting anything: the launcher empties a copy of the
    /// descriptor table when it starts, so a launcher started after a mount is
    /// open closes its copies of the descriptors on that mount, and each close
    /// issues a `FLUSH` (see `voidport_spawn::start_launcher`).
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

    #[must_use]
    pub fn state_file(&self) -> &Path {
        &self.state
    }

    #[must_use]
    pub fn control_socket(&self) -> &Path {
        &self.control
    }

    #[must_use]
    pub fn pid(&self) -> ServerPid {
        self.pid.clone()
    }

    #[must_use]
    pub fn restarts(&self) -> Restarts {
        Restarts {
            graceful: self.stops[0].load(Ordering::Relaxed),
            hard: self.stops[1].load(Ordering::Relaxed),
            inside_mutation: self.inside_mutation.load(Ordering::Relaxed),
        }
    }

    pub fn note_stop_inside_mutation(&self) {
        self.inside_mutation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mutating(&self) -> RwLockReadGuard<'_, ()> {
        self.quiet
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn quiesce(&self) -> RwLockWriteGuard<'_, ()> {
        self.quiet
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Waits for the process, not for a refused connection: a killed server
    /// leaves its unix socket file behind and a terminated one unlinks it. A stop
    /// that did not take still has the pid, because forgetting it would leave the
    /// next start racing a server that still listens on the address.
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

    /// "Serves" is a completed handshake on the data URL, not a bound socket: a
    /// server that accepts and then rejects the hello is not one a mount can
    /// heal against.
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
    /// A `SIGTERM` leaves the state file as the last mutation wrote it, so the
    /// teardown stops the server that way and kills only what will not go.
    fn drop(&mut self) {
        if let Err(graceful) = self.stop(Stop::Graceful) {
            eprintln!("!!! voidport-torture: the server would not stop: {graceful}");
            if let Err(hard) = self.stop(Stop::Hard) {
                eprintln!("!!! voidport-torture: the server would not die either: {hard}");
            }
        }
    }
}

fn alive(pid: Pid) -> bool {
    Path::new(&format!("/proc/{}", pid.as_raw_nonzero())).exists()
}

#[derive(Debug)]
struct Launcher {
    shell: Child,
    commands: ChildStdin,
    started: BufReader<ChildStdout>,
    /// A server is a background job of the shell, so killing the shell leaves it
    /// running under init with the data address and the lock of the state file.
    /// The launcher therefore records its pid to take it down.
    last: Option<Pid>,
}

/// The daemon binary and its three paths arrive as `$0` to `$3`, never
/// interpolated into the text, so no path is quoted into a script.
const LAUNCH: &str = "while IFS= read -r _command; do \
     \"$0\" --state \"$1\" --control-socket \"$2\" </dev/null >>\"$3\" 2>&1 & \
     echo \"$!\"; \
     wait \"$!\"; \
     done";

impl Launcher {
    fn start(daemon: &Path, state: &Path, control: &Path, log: &Path) -> anyhow::Result<Self> {
        anyhow::ensure!(
            daemon.exists(),
            "{} is missing: build the workspace so the server binary exists",
            daemon.display()
        );
        let mut shell = Program::new("/bin/sh")
            .arg("-c")
            .arg(LAUNCH)
            .arg(daemon)
            .arg(state)
            .arg(control)
            .arg(log)
            .stdin(Stream::Piped)
            .stdout(Stream::Piped)
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

    fn forget(&mut self, pid: Pid) {
        if self.last == Some(pid) {
            self.last = None;
        }
    }
}

impl Drop for Launcher {
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

    #[test]
    fn the_two_stops_are_the_two_signals() {
        assert_eq!(Stop::Graceful.signal(), Signal::TERM);
        assert_eq!(Stop::Hard.signal(), Signal::KILL);
        assert_eq!(Stop::Graceful.name(), "graceful");
        assert_eq!(Stop::Hard.name(), "hard");
    }

    #[test]
    fn the_liveness_probe_reads_the_process_table() {
        let mine = Pid::from_raw(i32::try_from(std::process::id()).expect("a pid")).expect("a pid");
        assert!(alive(mine));
        assert!(!alive(Pid::from_raw(i32::MAX).expect("a pid")));
    }

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
