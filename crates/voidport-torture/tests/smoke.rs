#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use voidport::guardian::Launch;
use voidport::url::{Endpoint, MountUrl};
use voidport_test_support::{create_directory, scratch_root};
use voidport_torture::metrics::Class;
use voidport_torture::mounts::GUARDIAN;
use voidport_torture::{Plan, Probe, Seed, Supervisor};

/// Long enough for the warmup to pass, several judged windows to close, and the
/// restart arm to restart the server several times.
const SECONDS: u64 = 90;

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

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Short, because a unix socket lives inside it and `sun_path` is 108 bytes.
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

/// `CARGO_BIN_EXE_*` is set only for binaries of the package under test, so
/// this is the sibling target directory of a workspace build. `cargo test -p
/// voidport-torture` does not build the binary of a library dependency, so the
/// test is skipped there.
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

/// The node descriptor budget is tiny, hundreds against a run that resolves far
/// more names, so every class passes under a cache that evicts and opens
/// descriptors again continuously. The other suites run the server at its
/// derived budget.
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
            tree_dirs: 4,
            tree_files: 16,
            crowded: 128,
            contended: 4,
            open_set: 8,
        },
        server: Some(Arc::clone(&server)),
        guardian: Launch {
            program: PathBuf::from(env!("CARGO_BIN_EXE_voidport-torture")),
            arguments: vec![GUARDIAN.into()],
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
    assert!(
        report.restarts.graceful > 0 && report.restarts.hard > 0,
        "the restart class performed {} graceful and {} hard stops",
        report.restarts.graceful,
        report.restarts.hard
    );
    assert!(
        voidport_torture::mounts::mounted_under(&plan.work_dir).is_empty(),
        "a mount outlived the run"
    );
}
