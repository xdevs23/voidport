//! The torture harness as a regular test: every class, briefly, with the
//! invariants on.
//!
//! This is the same [`voidport_torture::run`] an hours-long soak uses, at the
//! smallest size that still exercises every class — one worker each, two
//! mounts, a couple of minutes. It is in the suite because the harness is only
//! useful if it works, and because the properties it asserts (nothing stalls,
//! nothing leaks, nothing wedges, the teardown is clean) are properties every
//! change to the server can break.
//!
//! It is deliberately **not** a performance test. The ceilings it runs under
//! are the generous ones the design set, the duration is short, and the
//! resource bounds are computed from the run's own working set — so a slow
//! machine makes this test slower, never redder.
//!
//! # Why the server is a child process here
//!
//! Every other suite in the workspace runs its server on a thread of the test
//! process, which is what lets a test read the server's own descriptor table.
//! This one cannot: the restart class's whole subject is a server that dies
//! **without warning**, and an in-process server cannot be killed. So the
//! harness starts a real `voidportd` and watches it through `/proc`, which is
//! the same deviation the client's resilience suites make and for the same
//! reason. The data plane is a unix socket and not an ephemeral tcp port
//! for the same reason again: a restart has to come back at the address the
//! mounts are already using, and a `:0` port comes back somewhere else.
//!
//! Two things make this test unrunnable instead of red, and both are stated
//! where they are met: a machine where FUSE is unusable, and a build that left
//! no sibling server binary to start. Neither is a property of the server, and
//! everything that is one fails here.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use voidport::url::{Endpoint, MountUrl};
use voidport_torture::metrics::Class;
use voidport_torture::{Plan, Probe, Seed, Supervisor};
use voidportd::testing::{create_directory, scratch_root};

/// How long the smoke run keeps the load on.
///
/// Two minutes is the design's bound and this sits under it: long enough for
/// the warmup to pass, several judged windows to close, and the restart arm to
/// take the server away and bring it back several times.
const SECONDS: u64 = 90;

/// Whether FUSE is usable on this machine.
///
/// The single capability preflight the contract allows a skip for, spelled as
/// the end-to-end suite spells it.
fn preflight() -> bool {
    match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")
    {
        Ok(_) => true,
        Err(error) => {
            eprintln!("skipping: /dev/fuse is unusable ({error})");
            false
        }
    }
}

/// A temporary directory that removes itself.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// A uniquely named, traversable directory under the suite's scratch root.
    ///
    /// The name is kept short because a unix socket lives inside it and
    /// `sun_path` is 108 bytes, terminator included.
    fn new(label: &str) -> Self {
        let nanos = SystemTime::UNIX_EPOCH
            .elapsed()
            .map_or(0, |elapsed| elapsed.as_nanos() % 1_000_000);
        let path =
            scratch_root().join(format!("vp-torture-{label}-{}-{nanos}", std::process::id()));
        create_directory(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Where the server binary is, when a build has left one there.
///
/// `CARGO_BIN_EXE_*` only names binaries of the package under test, and the
/// server belongs to another one, so this is the sibling target directory a
/// workspace build leaves it in. Whether it is there is a fact about the build
/// that was run and not about the server: `cargo test -p voidport-torture`
/// compiles this crate and its library dependencies, and a library dependency
/// does not drag the sibling's *binary* along. That is the second and last
/// thing this test skips for, and it says so as loudly as the first — the
/// workspace build every gate runs does leave the binary there, so a skip here
/// is only ever somebody testing this crate alone.
fn daemon_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let mut directory = exe
        .parent()
        .expect("the test binary lives somewhere")
        .to_path_buf();
    if directory.ends_with("deps") {
        directory.pop();
    }
    let binary = directory.join("voidportd");
    if !binary.exists() {
        eprintln!(
            "skipping: {} is not there; build the workspace (./check, or \
             cargo test --workspace) so the other crates' binaries exist",
            binary.display()
        );
        return None;
    }
    Some(binary)
}

/// The state file: one namespace over one host tree, on a unix data socket.
///
/// The graft target is relative, and a relative target resolves against the
/// state file's own directory — which is where the host tree is built.
///
/// The node descriptor budget is configured **tiny** — hundreds, against a run
/// that resolves far more names than that — so this one run is both halves of
/// what the descriptor-budget criteria ask for: the smoke stays green, and
/// every class passes under a cache that is evicting and re-pinning
/// continuously. Every other suite in the workspace runs the server at its
/// derived budget, so the unconstrained path is covered where it costs nothing.
fn state_file(socket: &Path) -> String {
    format!(
        r#"
[server]
node_descriptor_budget = 256

[[server.listeners]]
transport = "unix"
path = "{socket}"

[[namespaces]]
name = "torture"

[[namespaces.rules]]
path = "/tree"
mode = "rw"
target = "tree"
"#,
        socket = socket.display(),
    )
}

#[test]
fn every_class_runs_briefly_with_the_invariants_on() {
    if !preflight() {
        return;
    }
    let Some(daemon) = daemon_binary() else {
        return;
    };
    let directory = TempDir::new("smoke");
    create_directory(&directory.path().join("tree"));
    let socket = directory.path().join("data.sock");
    let state = directory.path().join("state.toml");
    fs::write(&state, state_file(&socket)).expect("a writable state file");

    let url = format!(
        "{}/@torture/tree",
        Endpoint::Unix {
            path: socket.clone()
        }
    );
    let parsed = MountUrl::parse(&url).unwrap_or_else(|error| panic!("{url}: {error}"));
    // Started before anything is mounted, which is the ordering the supervisor
    // exists to keep: see its module documentation.
    let server = Arc::new(
        Supervisor::start(
            &daemon,
            &state,
            &directory.path().join("control.sock"),
            &parsed,
            &directory.path().join("server.log"),
        )
        .expect("the server starts"),
    );

    let plan = Plan {
        urls: vec![url],
        work_dir: directory.path().join("run"),
        duration: Duration::from_secs(SECONDS),
        intensity: 1,
        classes: Class::ALL.to_vec(),
        mounts: 2,
        probe: Probe {
            pid: Some(server.pid()),
            control_socket: Some(server.control_socket().to_path_buf()),
        },
        log: None,
        seed: Seed {
            // Smaller than the default working set: this is a liveness check,
            // and a smaller tree means the warmup is over sooner.
            tree_dirs: 4,
            tree_files: 16,
            crowded: 128,
            contended: 4,
            open_set: 8,
        },
        server: Some(Arc::clone(&server)),
    };

    let report = voidport_torture::run(&plan).expect("the harness runs");
    eprint!("{}", report.render());

    assert!(
        report.passed(),
        "the torture run violated its invariants:\n{}",
        report
            .violations
            .iter()
            .map(|violation| format!("  {violation}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    for class in &report.classes {
        assert!(
            class.completed > 0,
            "{} completed nothing at all",
            class.class.name()
        );
    }
    // Both stops, in a run short enough to belong in the suite: the graceful
    // one and the one that gives the server no chance to write anything.
    assert!(
        report.restarts.graceful > 0 && report.restarts.hard > 0,
        "the restart class performed {} graceful and {} hard stops",
        report.restarts.graceful,
        report.restarts.hard
    );
    // The mounts came down with the run, and the work directory is a plain
    // directory again — which is the clean-shutdown invariant seen from
    // outside the harness that asserts it.
    assert!(
        voidport_torture::mounts::mounted_under(&plan.work_dir).is_empty(),
        "a mount outlived the run"
    );
}
