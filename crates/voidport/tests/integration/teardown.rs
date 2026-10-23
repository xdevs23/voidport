use voidport_test_client as support;

use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::num::NonZeroUsize;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

use procfs::ProcError;
use procfs::process::{Process, Syscall};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::{Errno, retry_on_intr};
use rustix::process::{Pid, PidfdFlags, Resource, Rlimit, Signal, getrlimit, pidfd_open, prlimit};
use support::daemon::{Ground, PATIENCE, eventually, runtime};
use support::mapping::SharedMapping;
use support::namespace::{NamespaceCopy, in_copy};
use support::relay::{Cut, Latch, Relay};
use support::{fuse_client, preflight};
use voidport::client::{Caller, MountState};
use voidport::guardian::Launch;
use voidport::mount::{Mount, MountError, MountOptions};
use voidport::url::MountUrl;
use voidport_proto::opcode::Opcode;
use voidport_spawn::{Program, Stream};
use voidport_test_support::{ReadinessSocket, Startup, until};

const STALL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mountpoint {
    /// Nothing is mounted here.
    Unmounted,
    /// Also replying with `EIO`, as the guardian of a killed client does until
    /// it has ended the connection.
    Live,
    Dead,
}

fn probe(mountpoint: &Path) -> Mountpoint {
    match fs::metadata(mountpoint) {
        Err(error) if error.raw_os_error() == Some(Errno::NOTCONN.raw_os_error()) => {
            Mountpoint::Dead
        }
        Err(error) if error.raw_os_error() == Some(Errno::IO.raw_os_error()) => Mountpoint::Live,
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

/// Whether the connection of the mount on `mountpoint` has ended. A
/// `statfs`, which the kernel always sends to the server, fails with
/// `ENOTCONN` then, where [`probe`] can still be given the attributes the
/// kernel cached.
fn disconnected(mountpoint: &Path) -> bool {
    rustix::fs::statfs(mountpoint).err() == Some(Errno::NOTCONN)
}

struct Foreground {
    child: Option<Child>,
    mountpoint: PathBuf,
    log: PathBuf,
}

impl Foreground {
    /// Mounts and waits until the client reports readiness, which it does
    /// once it catches `SIGINT` and `SIGTERM`. A signal sent while the
    /// mountpoint already answers but before that report ends the client
    /// without a teardown, or is ignored where the test was started with
    /// `SIGINT` ignored.
    fn start(ground: &Ground, label: &str, extra: &[&str]) -> Option<Self> {
        let mountpoint = ground.directory.directory(&format!("mnt-{label}"));
        let log = ground.directory.join(&format!("mnt-{label}.log"));
        let log_file = fs::File::create(&log).expect("a writable log file");
        let readiness =
            ReadinessSocket::bind(ground.directory.join(&format!("mnt-{label}.notify")));
        let child = fuse_client()
            .env("NOTIFY_SOCKET", readiness.path())
            .args(["mount", &ground.server.url("work", "")])
            .arg(&mountpoint)
            .arg("--reconnect-stall")
            .arg(STALL.as_secs_f64().to_string())
            .args(extra)
            .stdout(Stream::Null)
            .stderr(Stream::Descriptor(log_file.as_fd()))
            .spawn()
            .expect("the client binary runs");
        let guest = Self {
            child: Some(child),
            mountpoint,
            log,
        };
        let started = readiness.wait_for(guest.child.as_ref().expect("the mount runs"));
        (started == Startup::Ready).then_some(guest)
    }

    fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    fn said(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_else(|error| format!("(no log: {error})"))
    }

    fn signal(&mut self, signal: Signal) -> (bool, Duration) {
        let child = self.child.as_mut().expect("the mount is still running");
        let started = Instant::now();
        rustix::process::kill_process(Pid::from_child(child), signal)
            .expect("the signal is delivered");
        let status = child.wait().expect("the mount process is waitable");
        self.child = None;
        (status.success(), started.elapsed())
    }

    fn guardian(&self) -> OwnedFd {
        guardian_of(self.child.as_ref().expect("the mount is still running"))
    }

    fn children(&self) -> Vec<OwnedFd> {
        children_of(self.child.as_ref().expect("the mount is still running"))
    }

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
            let _ = fuse_client().arg("umount").arg(&self.mountpoint).status();
        }
    }
}

fn guardian_of(client: &Child) -> OwnedFd {
    let children = children_of(client);
    let count = children.len();
    let Ok([guardian]) = <[OwnedFd; 1]>::try_from(children) else {
        panic!("the client runs one child, its guardian, and runs {count}");
    };
    guardian
}

/// A pidfd of each child of `client`, which the thread that starts the
/// children of the client started: the guardian of its mount, and the
/// `fusermount3` helper of a mount with auto-unmount, which lives as long as
/// the mount.
fn children_of(client: &Child) -> Vec<OwnedFd> {
    let tasks = fs::read_dir(format!("/proc/{}/task", client.id()))
        .expect("the threads of the client are listed");
    let mut children = Vec::new();
    for task in tasks {
        // A thread that ended meanwhile has no children left.
        let Ok(listed) = fs::read_to_string(task.expect("a thread").path().join("children")) else {
            continue;
        };
        children.extend(listed.split_whitespace().map(|child| {
            let child = child
                .parse()
                .ok()
                .and_then(Pid::from_raw)
                .expect("a process id");
            pidfd_open(child, PidfdFlags::empty()).expect("the child runs")
        }));
    }
    children
}

fn wait_for_exit(pidfd: &OwnedFd) {
    retry_on_intr(|| poll(&mut [PollFd::new(pidfd, PollFlags::IN)], None))
        .expect("the process can be waited for");
}

fn exits(pidfd: &OwnedFd, patience: Duration) -> bool {
    let patience = Timespec::try_from(patience).expect("a timeout");
    let mut exited = [PollFd::new(pidfd, PollFlags::IN)];
    poll(&mut exited, Some(&patience)).expect("the process can be waited for") > 0
}

fn program(name: &str) -> PathBuf {
    let path = std::env::var_os("PATH").expect("a PATH");
    std::env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("{name} is on PATH"))
}

/// A program the test started, killed if the test ends before it exits, so
/// that no mount a test leaves behind remains busy.
struct KilledOnDrop(Child);

impl Drop for KilledOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_signalled_mount_unmounts_itself() {
    preflight();
    let ground = Ground::start("signal");
    let mut cases: Vec<(&str, Signal, &[&str], usize)> =
        vec![("int", Signal::INT, &[], 1), ("term", Signal::TERM, &[], 1)];
    let carries = MountOptions {
        allow_other: true,
        ..MountOptions::default()
    }
    .auto_unmounts();
    if carries {
        cases.push(("auto", Signal::TERM, &["--allow-other"], 2));
    } else {
        eprintln!("auto-unmount case skipped: this platform has no auto-unmount for --allow-other");
    }
    for (label, signal, extra, count) in cases {
        let Some(mut guest) = Foreground::start(&ground, label, extra) else {
            panic!("the mount never came up");
        };
        assert_eq!(
            fs::read(guest.mountpoint().join("tree/alpha")).expect("the mount serves"),
            b"alpha"
        );
        let children = guest.children();
        assert_eq!(
            children.len(),
            count,
            "{label}: the client runs its guardian, and the helper of an auto-unmount"
        );
        let (clean, took) = guest.signal(signal);
        assert!(
            clean,
            "{label}: a signalled mount should exit cleanly, and it said:\n{}",
            guest.said()
        );
        assert!(
            children.iter().all(|child| exits(child, Duration::ZERO)),
            "{label}: the guardian and the helper of a signalled mount must have exited"
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
        // A warning on the way out would report a successful unmount as a
        // failed one. An error is checked too: a teardown that does not wait
        // for a callback the kernel was still owed when the signal arrived
        // drops it unanswered and logs that, and it still unmounts cleanly and
        // exits zero.
        let said = guest.said();
        for alarm in ["WARN", "ERROR"] {
            assert!(
                !said.contains(alarm),
                "{label}: a teardown that unmounted cleanly said {alarm}:\n{said}"
            );
        }
    }
}

#[test]
fn a_signalled_mount_unmounts_itself_while_its_server_is_gone() {
    preflight();
    let mut ground = Ground::start("signal-gone");

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

    ground.server.start_again();
    let Some(mut guest) = Foreground::start(&ground, "degraded", &[]) else {
        panic!("the mount never came up");
    };
    assert_eq!(
        fs::read(guest.mountpoint().join("tree/alpha")).expect("the mount serves"),
        b"alpha"
    );
    ground.server.kill();
    // Wait out the window, so the mount is degraded.
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

#[test]
fn a_signalled_mount_with_a_busy_mountpoint_still_exits() {
    preflight();
    let ground = Ground::start("busy");
    let Some(mut guest) = Foreground::start(&ground, "busy", &[]) else {
        panic!("the mount never came up");
    };
    // An open descriptor inside the mount makes it busy. There is no forced
    // unmount, so the answer is the `EBUSY` of the kernel.
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

    drop(held);
    assert!(
        eventually(PATIENCE, || fuse_client()
            .arg("umount")
            .arg(guest.mountpoint())
            .status()
            .is_ok_and(|status| status.success())),
        "`voidport umount` should recover the mountpoint once it is idle"
    );
    assert_eq!(probe(guest.mountpoint()), Mountpoint::Unmounted);
}

/// From Connected, `stop_reconnecting` has no attempt to cancel, and what still
/// has to hold is that no new one can start behind it. A server breaking away
/// between that call and the kernel unmount must not open a stall window for
/// callbacks the teardown is about to fail anyway, and must not put a dialler
/// behind a teardown that never comes back. Run at the client level because
/// that window is a few syscalls wide and a signal cannot be aimed inside it.
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

#[test]
fn a_killed_client_leaves_no_mountpoint_or_a_recoverable_one() {
    preflight();
    let ground = Ground::start("killed");

    // No auto-unmount: the endpoint is left dead and `voidport umount` recovers
    // it.
    let Some(mut guest) = Foreground::start(&ground, "dead-endpoint", &["--no-auto-unmount"])
    else {
        panic!("the mount never came up");
    };
    assert_eq!(
        fs::read(guest.mountpoint().join("tree/alpha")).expect("the mount serves"),
        b"alpha"
    );
    let guardian = guest.guardian();
    guest.kill();
    wait_for_exit(&guardian);
    assert!(
        disconnected(guest.mountpoint()),
        "a killed client without auto-unmount leaves the documented dead endpoint once \
         its guardian has exited (it is {:?})",
        probe(guest.mountpoint())
    );
    assert!(
        fuse_client()
            .arg("umount")
            .arg(guest.mountpoint())
            .status()
            .expect("the client binary runs")
            .success(),
        "`voidport umount` recovers the mountpoint"
    );
    assert_eq!(probe(guest.mountpoint()), Mountpoint::Unmounted);
    drop(guest);

    // Which outcome is owed is decided before the mount, by the same predicate
    // the client consults (the `fusermount` helper plus `--allow-other`), so
    // that a machine which can auto-unmount is held to it. Accepting either
    // outcome would pass on a client that silently stopped asking for the
    // option.
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
    // The guardian ends the connection and, where there is a helper,
    // unmounts the mountpoint through it before it exits. The helper exits
    // after the guardian, so the outcome is there once every child of the
    // client has exited.
    let children = released.children();
    released.kill();
    children.iter().for_each(wait_for_exit);
    let mountpoint = released.mountpoint().to_path_buf();
    if carries {
        assert_eq!(
            probe(&mountpoint),
            Mountpoint::Unmounted,
            "the helper and the wider ACL are both here, so the guardian unmounts once \
             it has ended the connection, and the mount said:\n{}",
            released.said()
        );
        return;
    }
    assert!(
        disconnected(&mountpoint),
        "without the helper a killed client leaves the documented dead endpoint (it is {:?})",
        probe(&mountpoint)
    );
    assert!(
        fuse_client()
            .arg("umount")
            .arg(&mountpoint)
            .status()
            .expect("the client binary runs")
            .success(),
        "`voidport umount` recovers the mountpoint"
    );
}

/// The file is a program the guest runs from the mount, because a running
/// program is a mapping of its file that faults again on a page that was
/// dropped. It waits for a line on its standard input between the two. The
/// client is killed only once it waits there: a program still running the code
/// after its last write call would fault on a dropped page before the test
/// writes the line, and that write call would fail with `EPIPE`.
#[test]
fn a_killed_client_leaves_no_page_of_a_leased_file_behind() {
    preflight();
    let ground = Ground::start("guardian");
    let host = ground.tree.join("cat");
    fs::copy(program("cat"), &host).expect("the program is copied into the tree");
    let Some(mut guest) = Foreground::start(
        &ground,
        "guarded",
        &[
            "--no-auto-unmount",
            "--attr-timeout",
            "3600",
            "--entry-timeout",
            "3600",
        ],
    ) else {
        panic!("the mount never came up");
    };
    let path = guest.mountpoint().join("tree/cat");
    let page = vec![0; 4096];
    let held = fs::File::open(&path).expect("the file opens");
    let mut read = page.clone();
    held.read_exact_at(&mut read, 0).expect("the file reads");
    let mut written = page.clone();
    fs::File::open(&host)
        .and_then(|file| file.read_exact_at(&mut written, 0))
        .expect("the host file reads");
    assert_eq!(read, written);
    let _mapping = SharedMapping::open_read_only(&path, page.len()).expect("a leased file maps");
    let mut running = KilledOnDrop(
        Program::new(&path)
            .stdin(Stream::Piped)
            .stdout(Stream::Piped)
            .stderr(Stream::Inherit)
            .spawn()
            .expect("the program runs from the mount"),
    );
    limit_core_dump_to_one_byte(&running.0);
    let mut input = running.0.stdin.take().expect("a piped stdin");
    let mut output = BufReader::new(running.0.stdout.take().expect("a piped stdout"));
    let mut echoed = String::new();
    writeln!(input, "mapped").expect("the program reads");
    output.read_line(&mut echoed).expect("the program writes");
    assert_eq!(echoed, "mapped\n", "the program runs, its pages mapped");
    wait_for_input(&running.0);

    let guardian = guest.guardian();
    guest.kill();
    assert!(
        exits(&guardian, PATIENCE),
        "the guardian exits once it dropped the pages, and the mount said:\n{}",
        guest.said()
    );
    assert!(
        held.read_exact_at(&mut read, 0).is_err(),
        "a read fails instead of returning the pages"
    );
    writeln!(input, "faulted").expect("the program reads");
    drop(input);
    let status = running.0.wait().expect("the program exits");
    assert_eq!(
        status.signal(),
        Some(Signal::BUS.as_raw()),
        "the program faults on a mapped page that is gone, and ends with {status}"
    );
}

/// Returns once `program` sleeps in `read` or `splice` on descriptor 0. A
/// program that is running does not count, and neither does one that sleeps
/// outside of a system call, such as in a page fault.
///
/// Fails once the program has exited, because nothing is left that could let it
/// continue.
fn wait_for_input(program: &Child) {
    let program = Process::new(Pid::from_child(program).as_raw_nonzero().get())
        .expect("the program is listed in /proc");
    until(
        || !program.is_alive(),
        || match program.syscall() {
            Ok(Syscall::Blocked {
                syscall_number: libc::SYS_read | libc::SYS_splice,
                argument_registers: [0, ..],
                ..
            }) => true,
            Ok(_) => false,
            // `procfs` fails on the short line that `/proc/<pid>/syscall`
            // shows for a program asleep outside of a system call.
            Err(ProcError::InternalError(_)) => false,
            Err(error) => panic!("the system call of the program cannot be listed: {error}"),
        },
    );
}

#[test]
fn the_wait_for_input_ends_once_a_program_waits_for_its_input() {
    let mut cat = KilledOnDrop(
        Program::new(program("cat"))
            .stdin(Stream::Piped)
            .stdout(Stream::Piped)
            .stderr(Stream::Inherit)
            .spawn()
            .expect("cat runs"),
    );
    let mut input = cat.0.stdin.take().expect("a piped stdin");
    let mut output = BufReader::new(cat.0.stdout.take().expect("a piped stdout"));
    let mut echoed = String::new();
    writeln!(input, "line").expect("cat reads");
    output.read_line(&mut echoed).expect("cat writes");
    wait_for_input(&cat.0);
}

#[test]
#[should_panic(expected = "ended before")]
fn the_wait_for_input_fails_once_the_program_has_exited() {
    let finished = KilledOnDrop(
        Program::new(program("true"))
            .stdin(Stream::Null)
            .stdout(Stream::Null)
            .stderr(Stream::Null)
            .spawn()
            .expect("true runs"),
    );
    wait_for_input(&finished.0);
}

/// Sets the soft core-dump limit of `program` to one byte, which stops the
/// kernel from starting the helper of a `core_pattern` pipe when `program` ends
/// with a signal that dumps core, such as `SIGBUS` (`coredump_pipe` in
/// `fs/coredump.c`). `systemd-coredump`, such a helper, copies every mount of
/// the machine into a namespace of its own, which makes an unmount of a mount
/// used by another test fail with `EBUSY` meanwhile.
///
/// The hard limit is left as it is. Where it is zero, the soft limit cannot
/// become one, and the test fails.
fn limit_core_dump_to_one_byte(program: &Child) {
    let maximum = getrlimit(Resource::Core).maximum;
    assert_ne!(
        maximum,
        Some(0),
        "the hard core-dump limit is zero, so a SIGBUS of the program would start the core helper"
    );
    prlimit(
        Some(Pid::from_child(program)),
        Resource::Core,
        Rlimit {
            current: Some(1),
            maximum,
        },
    )
    .expect("the core-dump limit of the program is set to one byte");
}

#[test]
fn a_mount_whose_guardian_fails_fails_and_leaves_no_mountpoint() {
    preflight();
    let ground = Ground::start("failed-guardian");
    let mountpoint = ground.directory.directory("mnt-failed-guardian");
    let url = MountUrl::parse(&ground.server.url("work", "")).expect("a mount URL");
    // Without the helper of an auto-unmount, the mount unmounts itself
    // before it returns.
    let options = MountOptions {
        auto_unmount: false,
        ..MountOptions::default()
    };
    let failing = Launch {
        program: PathBuf::from("/bin/sh"),
        arguments: vec!["-c".into(), "exit 1".into()],
    };

    let Err(error) = Mount::new(&url, &mountpoint, &options, &failing) else {
        panic!("a mount whose guardian failed serves");
    };
    assert!(
        matches!(error, MountError::Guardian(_)),
        "the mount fails with the error of its guardian, and fails with {error:?}"
    );
    assert_eq!(probe(&mountpoint), Mountpoint::Unmounted);
}

/// A thread of this process that waited on the mount for a reply would
/// otherwise leave the connection open, and the process could never exit.
#[test]
fn a_mount_dropped_with_a_busy_mountpoint_ends_the_kernel_connection() {
    preflight();
    let ground = Ground::start("dropped-busy");
    let mountpoint = ground.directory.directory("mnt-dropped-busy");
    let mount = mount_in_this_process(&ground.server.url("work", ""), &mountpoint, 1);
    let held = fs::File::open(mountpoint.join("tree/alpha")).expect("the file opens");

    drop(mount);
    let error = fs::metadata(mountpoint.join("tree/absent"))
        .expect_err("a request to a mount that ended fails");
    assert_eq!(
        error.raw_os_error(),
        Some(Errno::NOTCONN.raw_os_error()),
        "the kernel connection the mount uses has ended, and the request failed with {error}"
    );

    drop(held);
    voidport::mount::unmount(&mountpoint)
        .expect("the mountpoint unmounts once no open file is left on it");
}

/// The request is the truncate of an open, which a relay delays on its way to
/// the server for good.
#[test]
fn a_mount_dropped_while_a_thread_waits_on_it_lets_the_thread_return() {
    preflight();
    let ground = Ground::start("dropped-waiting");
    let relay = Relay::start(&ground.socket());
    let truncating = relay.arm(Opcode::Setattr, Cut::HoldRequest(Latch::default()));
    let mountpoint = ground.directory.directory("mnt-dropped-waiting");
    let mount = mount_in_this_process(&relay.url("work", ""), &mountpoint, 1);
    drop_a_mount_a_thread_waits_on(mount, &mountpoint, || {
        truncating
            .recv()
            .expect("the mount read the truncate and sent it to the server");
    });

    voidport::mount::unmount(&mountpoint)
        .expect("the mountpoint unmounts once no request is left in it");
}

const CLIENT_URL: &str = "VOIDPORT_TEST_CLIENT_URL";
const CLIENT_MOUNTPOINT: &str = "VOIDPORT_TEST_CLIENT_MOUNTPOINT";

const HOLDING: &str = "holding a file of its own mount";

fn client_of_its_own_mount() -> Option<(String, PathBuf)> {
    Some((
        std::env::var(CLIENT_URL).ok()?,
        std::env::var_os(CLIENT_MOUNTPOINT)?.into(),
    ))
}

#[derive(Clone, Copy, Debug)]
enum ClientNamespace {
    OfTheTest,
    Copy,
}

fn run_client_of_its_own_mount(
    test: &str,
    url: &str,
    mountpoint: &Path,
    namespace: ClientNamespace,
) -> KilledOnDrop {
    let binary = std::env::current_exe().expect("the test binary");
    let mut program = match namespace {
        ClientNamespace::OfTheTest => Program::new(binary),
        ClientNamespace::Copy => in_copy(binary),
    };
    KilledOnDrop(
        program
            .args(["--exact", test, "--nocapture"])
            .env(CLIENT_URL, url)
            .env(CLIENT_MOUNTPOINT, mountpoint)
            .stdin(Stream::Piped)
            .stdout(Stream::Piped)
            .stderr(Stream::Inherit)
            .spawn()
            .expect("the client runs"),
    )
}

fn mount_in_this_process(url: &str, mountpoint: &Path, dispatch_threads: usize) -> Mount {
    let parsed = MountUrl::parse(url).expect("a mount URL");
    let options = MountOptions {
        auto_unmount: false,
        dispatch_threads: NonZeroUsize::new(dispatch_threads).expect("a dispatch thread"),
        ..MountOptions::default()
    };
    Mount::new(&parsed, mountpoint, &options, &support::guardian()).expect("the client mounts")
}

fn kill_and_see_no_page_behind(mut client: KilledOnDrop, mountpoint: &Path) {
    let held = fs::File::open(mountpoint.join("tree/alpha")).expect("the file opens");
    let mut read = [0; 5];
    held.read_exact_at(&mut read, 0).expect("the file reads");
    assert_eq!(&read, b"alpha");

    let guardian = guardian_of(&client.0);
    client.0.kill().expect("the client is killed");
    let status = client.0.wait().expect("the client exits");
    assert_eq!(status.signal(), Some(Signal::KILL.as_raw()));
    wait_for_exit(&guardian);
    assert!(
        held.read_exact_at(&mut read, 0).is_err(),
        "a read fails instead of returning the pages"
    );
    drop(held);
    assert!(
        fuse_client()
            .arg("umount")
            .arg(mountpoint)
            .status()
            .expect("the client binary runs")
            .success(),
        "`voidport umount` recovers the mountpoint the client left"
    );
}

/// Closing that file at the exit sends a flush, which only the guardian can
/// answer once the client is killed.
#[test]
fn a_killed_client_with_a_file_open_on_its_own_mount_exits_and_leaves_no_page_behind() {
    if let Some((url, mountpoint)) = client_of_its_own_mount() {
        hold_a_file_of_its_own_mount(&url, &mountpoint);
        return;
    }
    preflight();
    let ground = Ground::start("own-file");
    let mountpoint = ground.directory.directory("mnt-own-file");
    let mut client = run_client_of_its_own_mount(
        "teardown::a_killed_client_with_a_file_open_on_its_own_mount_exits_and_leaves_no_page_behind",
        &ground.server.url("work", ""),
        &mountpoint,
        ClientNamespace::OfTheTest,
    );
    let mut output = BufReader::new(client.0.stdout.take().expect("a piped stdout"));
    assert!(
        (&mut output)
            .lines()
            .map_while(Result::ok)
            .any(|line| line == HOLDING),
        "the client has a file open on its own mount"
    );
    kill_and_see_no_page_behind(client, &mountpoint);
}

fn hold_a_file_of_its_own_mount(url: &str, mountpoint: &Path) {
    let _mount = mount_in_this_process(url, mountpoint, 1);
    let held = fs::File::open(mountpoint.join("tree/alpha")).expect("the file opens");
    let mut read = [0; 5];
    held.read_exact_at(&mut read, 0).expect("the file reads");
    println!("{HOLDING}");
    let _ = std::io::stdin().read_line(&mut String::new());
}

/// The request is the truncate of an open, which a relay delays on its way to
/// the server for good. The client runs two dispatch threads, so the guardian
/// takes over only once both have ended, and the request may have been read
/// through either descriptor.
#[test]
fn a_killed_client_waiting_for_a_request_it_read_exits_and_leaves_no_page_behind() {
    if let Some((url, mountpoint)) = client_of_its_own_mount() {
        truncate_a_file_of_its_own_mount(&url, &mountpoint);
        return;
    }
    preflight();
    let ground = Ground::start("own-request");
    let relay = Relay::start(&ground.socket());
    let truncating = relay.arm(Opcode::Setattr, Cut::HoldRequest(Latch::default()));
    let mountpoint = ground.directory.directory("mnt-own-request");
    let client = run_client_of_its_own_mount(
        "teardown::a_killed_client_waiting_for_a_request_it_read_exits_and_leaves_no_page_behind",
        &relay.url("work", ""),
        &mountpoint,
        ClientNamespace::OfTheTest,
    );
    truncating
        .recv()
        .expect("the client read the truncate and sent it to the server");
    kill_and_see_no_page_behind(client, &mountpoint);
}

fn truncate_a_file_of_its_own_mount(url: &str, mountpoint: &Path) {
    let _mount = mount_in_this_process(url, mountpoint, 2);
    let _ = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(mountpoint.join("tree/beta"));
}

const FUSECTL: &str = "/sys/fs/fuse/connections";

/// `fusectl` does not show the kernel connection of the mount, so the
/// connection cannot be aborted. The request is the truncate of an open, which
/// a relay delays on its way to the server for good. The client runs two
/// dispatch threads in a copy of the mount namespace where it unmounts
/// `fusectl` first.
#[test]
fn a_mount_dropped_without_fusectl_while_a_thread_waits_on_it_ends_and_its_process_exits() {
    if let Some((url, mountpoint)) = client_of_its_own_mount() {
        unmount_fusectl();
        let mount = mount_in_this_process(&url, &mountpoint, 2);
        drop_a_mount_a_thread_waits_on(mount, &mountpoint, || {
            std::io::stdin()
                .read_line(&mut String::new())
                .expect("the standard input reads");
        });
        return;
    }
    preflight();
    let ground = Ground::start("dropped-unaborted");
    let relay = Relay::start(&ground.socket());
    let truncating = relay.arm(Opcode::Setattr, Cut::HoldRequest(Latch::default()));
    let mountpoint = ground.directory.directory("mnt-dropped-unaborted");
    let mut client = run_client_of_its_own_mount(
        "teardown::a_mount_dropped_without_fusectl_while_a_thread_waits_on_it_ends_and_its_process_exits",
        &relay.url("work", ""),
        &mountpoint,
        ClientNamespace::Copy,
    );
    truncating
        .recv()
        .expect("the client read the truncate and sent it to the server");

    drop(client.0.stdin.take());
    let status = client.0.wait().expect("the client exits");
    assert!(
        status.success(),
        "the client drops its mount and exits successfully, and it exited with {status}"
    );
}

/// A `fusectl` that is not mounted there is reported by the kernel as `EINVAL`.
fn unmount_fusectl() {
    match voidport::mount::unmount(Path::new(FUSECTL)) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(Errno::INVAL.raw_os_error()) => {}
        Err(error) => panic!("fusectl could not be unmounted: {error}"),
    }
}

fn drop_a_mount_a_thread_waits_on(mount: Mount, mountpoint: &Path, truncate_waits: impl FnOnce()) {
    let guardian = mount
        .guardian_id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw)
        .expect("the mount has a guardian");
    let guardian = pidfd_open(guardian, PidfdFlags::empty()).expect("the guardian runs");
    let beta = mountpoint.join("tree/beta");
    let waiting =
        std::thread::spawn(move || fs::OpenOptions::new().write(true).truncate(true).open(beta));
    truncate_waits();

    drop(mount);
    let opened = waiting
        .join()
        .expect("the thread that waited on the mount returns");
    assert!(
        opened.is_err(),
        "the request of the thread fails once the mount has ended"
    );
    retry_on_intr(|| poll(&mut [PollFd::new(&guardian, PollFlags::IN)], None))
        .expect("the guardian exits");
    let error = fs::metadata(mountpoint.join("tree/absent"))
        .expect_err("a request to a mount that ended fails");
    assert_eq!(
        error.raw_os_error(),
        Some(Errno::NOTCONN.raw_os_error()),
        "the kernel connection the mount uses has ended, and the request failed with {error}"
    );
}

const KILLED_TEST: &str = "VOIDPORT_TEST_KILLED_TEST";

#[test]
fn a_killed_test_process_leaves_no_server_and_no_mount_behind() {
    if std::env::var_os(KILLED_TEST).is_some() {
        start_a_server_and_a_mount();
        return;
    }
    preflight();
    let mut test = KilledOnDrop(
        Program::new(std::env::current_exe().expect("the test binary"))
            .args([
                "--exact",
                "teardown::a_killed_test_process_leaves_no_server_and_no_mount_behind",
                "--nocapture",
            ])
            .env(KILLED_TEST, "1")
            .stdin(Stream::Piped)
            .stdout(Stream::Piped)
            .stderr(Stream::Inherit)
            .spawn()
            .expect("the test process runs"),
    );
    let mut output = BufReader::new(test.0.stdout.take().expect("a piped stdout")).lines();
    let mut reported = |prefix: &str| {
        (&mut output)
            .map_while(Result::ok)
            .find_map(|line| line.strip_prefix(prefix).map(str::to_owned))
            .unwrap_or_else(|| panic!("the test process reports its {prefix}"))
    };
    let mut process = |prefix: &str| {
        let pid = reported(prefix)
            .parse()
            .ok()
            .and_then(Pid::from_raw)
            .expect("a process id");
        pidfd_open(pid, PidfdFlags::empty()).expect("the process runs")
    };
    let server = process("server ");
    let detacher = process("detacher ");
    let mountpoint = PathBuf::from(reported("mountpoint "));

    test.0.kill().expect("the test process is killed");
    test.0.wait().expect("the test process exits");
    for exited in [server, detacher] {
        retry_on_intr(|| poll(&mut [PollFd::new(&exited, PollFlags::IN)], None))
            .expect("the process exits");
    }
    assert_eq!(probe(&mountpoint), Mountpoint::Unmounted);
    let directory = mountpoint
        .parent()
        .expect("the directory of the test process");
    fs::remove_dir_all(directory).expect("the directory of the test process is removed");
}

fn start_a_server_and_a_mount() {
    let ground = Ground::start("killed-test");
    let guest = ground.mount("killed-test", STALL);
    let server = ground.server.pid().expect("the server runs");
    let detacher = support::detacher().expect("the directory of the server started it");
    println!("server {}", server.as_raw_nonzero());
    println!("detacher {}", detacher.as_raw_nonzero());
    println!("mountpoint {}", guest.root().display());
    let _ = std::io::stdin().read_line(&mut String::new());
}

#[test]
fn an_unmount_returns_while_another_namespace_has_a_copy_of_the_mount() {
    preflight();
    let ground = Ground::start("copied");
    let mut guest = ground.mount("copied", STALL);
    assert_eq!(
        fs::read(guest.path("tree/alpha")).expect("the mount serves"),
        b"alpha"
    );

    let mut copy = NamespaceCopy::start();
    let unmounted = guest.unmount_patiently();
    let copy_exists = copy.exists();
    copy.release();
    unmounted.expect("the mountpoint comes down");
    assert!(
        copy_exists,
        "the unmount returned only after the copy of the mount was gone"
    );
}

#[test]
fn a_signalled_mount_exits_while_another_namespace_has_a_copy_of_the_mount() {
    preflight();
    let ground = Ground::start("signal-copied");
    let Some(mut guest) = Foreground::start(&ground, "copied", &[]) else {
        panic!("the mount never came up");
    };

    let mut copy = NamespaceCopy::start();
    let (clean, _) = guest.signal(Signal::TERM);
    let copy_exists = copy.exists();
    copy.release();
    assert!(
        clean,
        "a signalled mount should exit cleanly, and it said:\n{}",
        guest.said()
    );
    assert!(
        copy_exists,
        "the process exited only after the copy of the mount was gone"
    );
}
