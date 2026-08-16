//! Teardown: signals, and the exit the client cannot intercept.
//!
//! Reconnect-increment criteria **9 and 10**. Both drive the real `voidport`
//! binary, because both are about what a *process* does when it is asked — or
//! not asked — to stop.
//!
//! * **Signals** are the primary mechanism. `SIGINT` and `SIGTERM` run the same
//!   ordered teardown a clean unmount does, unmount attempt included, from
//!   Connected, Reconnecting and Degraded alike; a mountpoint that is busy
//!   still refuses to come down, and the process exits anyway instead of
//!   hanging on to a mountpoint nobody can release.
//! * **Auto-unmount** is the `SIGKILL` story, and it is opportunistic by
//!   design: fuser 0.18 refuses the option under the owner-only ACL and needs
//!   the `fusermount3` helper, so the honest claim is a pair — the mountpoint
//!   is released where the platform allows it, and where it does not the dead
//!   endpoint is the documented state and `voidport umount` recovers it.

mod support;

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::io::Errno;
use rustix::process::{Pid, Signal};
use support::daemon::{Ground, PATIENCE, eventually, runtime};
use support::preflight;
use voidport::client::{Caller, MountState};
use voidport::mount::MountOptions;

/// The window the signalled mounts run with.
const STALL: Duration = Duration::from_secs(5);

/// The `voidport` binary under test.
fn voidport() -> Command {
    Command::new(env!("CARGO_BIN_EXE_voidport"))
}

/// What a mountpoint currently is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mountpoint {
    /// Nothing is mounted here.
    Unmounted,
    /// A filesystem is mounted and answering.
    Live,
    /// A filesystem is mounted and its server is gone — the "transport
    /// endpoint is not connected" state a killed client leaves behind.
    Dead,
}

/// Probes a mountpoint without disturbing it.
fn probe(mountpoint: &Path) -> Mountpoint {
    match fs::metadata(mountpoint) {
        Err(error) if error.raw_os_error() == Some(Errno::NOTCONN.raw_os_error()) => {
            Mountpoint::Dead
        }
        Err(_) => Mountpoint::Unmounted,
        Ok(here) => {
            let under = mountpoint
                .parent()
                .and_then(|parent| fs::metadata(parent).ok())
                .map(|parent| parent.dev());
            if under == Some(here.dev()) {
                Mountpoint::Unmounted
            } else {
                Mountpoint::Live
            }
        }
    }
}

/// A foreground `voidport mount` child process.
struct Foreground {
    child: Option<Child>,
    mountpoint: PathBuf,
    /// Where the child's own diagnostics go.
    ///
    /// A mount that exits with the wrong status has already said why — it logs
    /// the kernel's refusal — and an assertion that cannot show that is an
    /// assertion nobody can act on, least of all for a failure that only
    /// appears under load.
    log: PathBuf,
}

impl Foreground {
    /// Mounts and waits until the mountpoint is answering.
    fn start(ground: &Ground, label: &str, extra: &[&str]) -> Option<Self> {
        let mountpoint = ground.directory.directory(&format!("mnt-{label}"));
        let log = ground.directory.join(&format!("mnt-{label}.log"));
        let child = voidport()
            .args(["mount", &ground.server.url("work", "")])
            .arg(&mountpoint)
            .arg("--reconnect-stall")
            .arg(STALL.as_secs_f64().to_string())
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                fs::File::create(&log).expect("a writable log file"),
            ))
            .spawn()
            .expect("the client binary runs");
        let guest = Self {
            child: Some(child),
            mountpoint,
            log,
        };
        if eventually(PATIENCE, || probe(&guest.mountpoint) == Mountpoint::Live) {
            Some(guest)
        } else {
            None
        }
    }

    /// The mountpoint.
    fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// What the child said, for an assertion that has to explain itself.
    fn said(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_else(|error| format!("(no log: {error})"))
    }

    /// Sends a signal and waits for the process to exit, reporting whether it
    /// exited successfully and how long it took.
    fn signal(&mut self, signal: Signal) -> (bool, Duration) {
        let child = self.child.as_mut().expect("the mount is still running");
        let started = Instant::now();
        rustix::process::kill_process(Pid::from_child(child), signal)
            .expect("the signal is delivered");
        let status = child.wait().expect("the mount process is waitable");
        self.child = None;
        (status.success(), started.elapsed())
    }

    /// Kills the process outright, with no chance to tear anything down.
    fn kill(&mut self) {
        let mut child = self.child.take().expect("the mount is still running");
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Drop for Foreground {
    /// A mount a test failed to take down must not outlive it: a stale FUSE
    /// mountpoint breaks every later run.
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if probe(&self.mountpoint) != Mountpoint::Unmounted {
            let _ = voidport().arg("umount").arg(&self.mountpoint).status();
        }
    }
}

// ---------------------------------------------------------------------------
// Criterion 9 — the signalled teardown
// ---------------------------------------------------------------------------

/// From Connected: both signals run the ordered teardown, unmount included.
#[test]
fn a_signalled_mount_unmounts_itself() {
    if !preflight() {
        return;
    }
    let ground = Ground::start("signal");
    for (label, signal) in [("int", Signal::INT), ("term", Signal::TERM)] {
        let Some(mut guest) = Foreground::start(&ground, label, &[]) else {
            panic!("the mount never came up");
        };
        assert_eq!(
            fs::read(guest.mountpoint().join("tree/alpha")).expect("the mount serves"),
            b"alpha"
        );
        let (clean, took) = guest.signal(signal);
        assert!(
            clean,
            "{label}: a signalled mount should exit cleanly, and it said:\n{}",
            guest.said()
        );
        assert!(
            took < Duration::from_secs(20),
            "{label}: the teardown took {took:?}"
        );
        assert_eq!(
            probe(guest.mountpoint()),
            Mountpoint::Unmounted,
            "{label}: a signalled mount must unmount itself"
        );
        // And it says nothing alarming on the way out. fuser unmounts a second
        // time from its own session handle as the session ends, on a mountpoint
        // this teardown has already taken down, so that attempt can only fail —
        // a warning there is an unmount that worked, reported as one that did
        // not, in every client log there is.
        let said = guest.said();
        assert!(
            !said.contains("WARN"),
            "{label}: a teardown that unmounted cleanly warned:\n{said}"
        );
    }
}

/// From Reconnecting and from Degraded alike: the in-flight attempt is
/// cancelled first, so the teardown does not wait out the window it was in.
#[test]
fn a_signalled_mount_unmounts_itself_while_its_server_is_gone() {
    if !preflight() {
        return;
    }
    let mut ground = Ground::start("signal-gone");

    // Reconnecting: signalled while the window is still open.
    let Some(mut guest) = Foreground::start(&ground, "reconnecting", &[]) else {
        panic!("the mount never came up");
    };
    assert_eq!(
        fs::read(guest.mountpoint().join("tree/alpha")).expect("the mount serves"),
        b"alpha"
    );
    ground.server.kill();
    let (clean, took) = guest.signal(Signal::TERM);
    assert!(
        clean,
        "a reconnecting mount should still exit cleanly, and it said:\n{}",
        guest.said()
    );
    assert!(
        took < STALL,
        "the teardown waited {took:?}, which is waiting out the window it was told to cancel"
    );
    assert_eq!(probe(guest.mountpoint()), Mountpoint::Unmounted);
    drop(guest);

    // Degraded: signalled after the window has closed.
    ground.server.start_again();
    let Some(mut guest) = Foreground::start(&ground, "degraded", &[]) else {
        panic!("the mount never came up");
    };
    assert_eq!(
        fs::read(guest.mountpoint().join("tree/alpha")).expect("the mount serves"),
        b"alpha"
    );
    ground.server.kill();
    // Ride the window out, so the mount is genuinely degraded.
    let _ = fs::metadata(guest.mountpoint().join("tree/never-seen"));
    std::thread::sleep(STALL);
    let (clean, took) = guest.signal(Signal::TERM);
    assert!(
        clean,
        "a degraded mount should still exit cleanly, and it said:\n{}",
        guest.said()
    );
    assert!(took < Duration::from_secs(20), "the teardown took {took:?}");
    assert_eq!(probe(guest.mountpoint()), Mountpoint::Unmounted);
}

/// A busy mountpoint still refuses to come down — and the process exits
/// anyway, leaving a mountpoint `voidport umount` recovers once it is idle.
#[test]
fn a_signalled_mount_with_a_busy_mountpoint_still_exits() {
    if !preflight() {
        return;
    }
    let ground = Ground::start("busy");
    let Some(mut guest) = Foreground::start(&ground, "busy", &[]) else {
        panic!("the mount never came up");
    };
    // An open descriptor inside the mount is what makes it busy; v1 has no
    // forced unmount, so the kernel's EBUSY is the honest answer.
    let held = fs::File::open(guest.mountpoint().join("tree/alpha")).expect("opens");

    let (clean, took) = guest.signal(Signal::TERM);
    assert!(
        !clean,
        "a teardown that could not unmount must say so in its exit status, and it said:\n{}",
        guest.said()
    );
    assert!(
        took < Duration::from_secs(20),
        "the process must exit even when the mountpoint will not: took {took:?}"
    );

    // The mountpoint is still there, and recoverable.
    drop(held);
    assert!(
        eventually(PATIENCE, || voidport()
            .arg("umount")
            .arg(guest.mountpoint())
            .status()
            .is_ok_and(|status| status.success())),
        "`voidport umount` should recover the mountpoint once it is idle"
    );
    assert_eq!(probe(guest.mountpoint()), Mountpoint::Unmounted);
}

/// The teardown's first step is terminal from **Connected** as well, which is
/// the state the criterion's third case starts in.
///
/// `stop_reconnecting` cancels the attempt where there is one; from Connected
/// there is none to cancel, and the thing that still has to hold is that no new
/// one can start behind it. A server breaking away in the window between that
/// call and the kernel unmount must not open a stall window for callbacks the
/// teardown is about to fail anyway, and must not put a dialler behind a
/// teardown that never comes back. Driven at the client level because the
/// window it is about is a few syscalls wide and a signal cannot be aimed
/// inside it.
#[test]
fn a_death_after_the_teardown_began_opens_no_window_behind_it() {
    let mut ground = Ground::start("stop-connected");
    let runtime = runtime();
    let client = ground.connect(&runtime, STALL);
    let caller = Caller::default();
    let root = client.root_node_id();
    runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the mount serves");

    client.stop_reconnecting();
    assert_eq!(
        client.state(),
        MountState::Connected,
        "the connection is left in place for the ordered unmount to run against"
    );

    ground.server.kill();
    assert!(
        eventually(PATIENCE, || client.state() == MountState::Closed),
        "a death after the teardown began must end the mount instead of opening a \
         stall window (it is {:?})",
        client.state()
    );
    let started = Instant::now();
    assert_eq!(
        runtime
            .block_on(client.getattr(caller, root, None))
            .expect_err("the mount is ending"),
        Errno::IO
    );
    assert!(
        started.elapsed() < STALL,
        "a request behind the teardown waited {:?} of a window nobody will wait out",
        started.elapsed()
    );
}

// ---------------------------------------------------------------------------
// Criterion 10 — the exit the client cannot intercept
// ---------------------------------------------------------------------------

/// A `SIGKILL` leaves either no mountpoint at all or a recoverable one, and
/// which of the two is a property of the platform, not of the client.
///
/// Both arms are asserted, and the gate between them is the platform's own
/// answer, not the outcome observed. The second always runs: the
/// owner-only ACL is the default and fuser refuses `auto_unmount` under it, so
/// the documented dead endpoint is what a killed client leaves — and `voidport
/// umount` is the documented recovery. The first is *required* wherever
/// `MountOptions::auto_unmounts` says the option will be carried, which is the
/// same question the client asks before it offers the option at all.
#[test]
fn a_killed_client_leaves_no_mountpoint_or_a_recoverable_one() {
    if !preflight() {
        return;
    }
    let ground = Ground::start("killed");

    // The arm that always holds: no auto-unmount, so the endpoint is left dead
    // and `voidport umount` is what recovers it.
    let Some(mut guest) = Foreground::start(&ground, "dead-endpoint", &["--no-auto-unmount"])
    else {
        panic!("the mount never came up");
    };
    assert_eq!(
        fs::read(guest.mountpoint().join("tree/alpha")).expect("the mount serves"),
        b"alpha"
    );
    guest.kill();
    assert!(
        eventually(PATIENCE, || probe(guest.mountpoint()) == Mountpoint::Dead),
        "a killed client without auto-unmount leaves the documented dead endpoint"
    );
    assert!(
        voidport()
            .arg("umount")
            .arg(guest.mountpoint())
            .status()
            .expect("the client binary runs")
            .success(),
        "`voidport umount` recovers the mountpoint"
    );
    assert_eq!(probe(guest.mountpoint()), Mountpoint::Unmounted);
    drop(guest);

    // The arm the platform decides. Which of the two outcomes is owed is
    // settled *before* the mount, by the same predicate the client itself
    // consults — the `fusermount` helper plus the widened ACL — so that a
    // machine which can auto-unmount is held to it. Accepting either outcome
    // unconditionally would pass on a client that had silently stopped asking
    // for the option at all.
    let carries = MountOptions {
        allow_other: true,
        ..MountOptions::default()
    }
    .auto_unmounts();
    let Some(mut released) = Foreground::start(&ground, "auto", &["--allow-other"]) else {
        assert!(
            !carries,
            "this platform takes auto_unmount, so an --allow-other mount must come up"
        );
        eprintln!("auto-unmount arm skipped: this platform refuses an --allow-other mount");
        return;
    };
    assert_eq!(
        fs::read(released.mountpoint().join("tree/alpha")).expect("the mount serves"),
        b"alpha"
    );
    released.kill();
    let mountpoint = released.mountpoint().to_path_buf();
    let released_itself = eventually(Duration::from_secs(10), || {
        probe(&mountpoint) == Mountpoint::Unmounted
    });
    if carries {
        assert!(
            released_itself,
            "the helper and the wider ACL are both here, so the kernel must have \
             released the mountpoint on its own (it is {:?})",
            probe(&mountpoint)
        );
        return;
    }
    // No helper, so the option was never asked for: the documented fallback is
    // the dead endpoint, and the same recovery.
    assert_eq!(
        probe(&mountpoint),
        Mountpoint::Dead,
        "without the helper a killed client leaves the documented dead endpoint"
    );
    assert!(
        voidport()
            .arg("umount")
            .arg(&mountpoint)
            .status()
            .expect("the client binary runs")
            .success(),
        "`voidport umount` recovers the mountpoint"
    );
}
