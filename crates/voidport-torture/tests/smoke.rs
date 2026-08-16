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
//! The one skip the contract allows is a machine where FUSE is unusable; every
//! other failure here is a failure.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use voidport_torture::metrics::Class;
use voidport_torture::{Plan, Probe, Seed};
use voidportd::testing::{
    RunningServer, create_directory, daemon_config, invoking_environment, scratch_root,
};

/// How long the smoke run keeps the load on.
///
/// Two minutes is the design's bound and this sits under it: long enough for
/// the warmup to pass and several judged windows to close, short enough to
/// belong in a suite that runs on every change.
const SECONDS: u64 = 75;

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
    fn new(label: &str) -> Self {
        let nanos = SystemTime::UNIX_EPOCH
            .elapsed()
            .map_or(0, |elapsed| elapsed.as_nanos());
        let path = scratch_root().join(format!(
            "voidport-torture-{label}-{}-{nanos}",
            std::process::id()
        ));
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

/// The state file: one namespace over one host tree, on an ephemeral tcp port.
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
const STATE_FILE: &str = r#"
[server]
node_descriptor_budget = 256

[[server.listeners]]
transport = "tcp"
addr = "127.0.0.1:0"

[[namespaces]]
name = "torture"

[[namespaces.rules]]
path = "/tree"
mode = "rw"
target = "tree"
"#;

#[test]
fn every_class_runs_briefly_with_the_invariants_on() {
    if !preflight() {
        return;
    }
    let directory = TempDir::new("smoke");
    create_directory(&directory.path().join("tree"));
    let state = directory.path().join("state.toml");
    fs::write(&state, STATE_FILE).expect("a writable state file");

    let config = daemon_config(&state, invoking_environment(directory.path()));
    let server = RunningServer::start(&config).expect("the server starts");

    let plan = Plan {
        url: format!("voidport://{}/@torture/tree", server.data_tcp()),
        work_dir: directory.path().join("run"),
        duration: Duration::from_secs(SECONDS),
        intensity: 1,
        classes: Class::ALL.to_vec(),
        mounts: 2,
        probe: Probe {
            // The server runs on a thread of this very process, so this
            // process's descriptor, thread and memory counts are the server's
            // — plus the harness's own, which only makes the bounds stricter.
            pid: Some(std::process::id()),
            control_socket: Some(server.socket().to_path_buf()),
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
    // The mounts came down with the run, and the work directory is a plain
    // directory again — which is the clean-shutdown invariant seen from
    // outside the harness that asserts it.
    assert!(
        voidport_torture::mounts::mounted_under(&plan.work_dir).is_empty(),
        "a mount outlived the run"
    );
}
