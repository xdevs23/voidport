//! What this suite's pty cases need on top of the shared harness.
//!
//! The pty itself, the terminal parser and the child's lifetime are
//! [`voidport_pty`]'s — one harness for the whole workspace, so a fix to it is a
//! fix everywhere. What stays here is the part that is only true of *this*
//! suite: the child of every case is this very test binary, re-executed with
//! `--exact` on [`CHILD_TEST`] and a scenario named in the environment. That
//! keeps the proofs free of any hook in the product — nothing in `voidport-tui`
//! knows it is being tested.

use std::sync::atomic::{AtomicU64, Ordering};

use voidport_pty::{Pty, Spawn};
use voidportd::testing::scratch_root;

/// The environment variable naming which scenario a child should run.
pub const SCENARIO: &str = "VOIDPORT_TUI_PTY_SCENARIO";

/// The environment variable carrying the control socket a child attaches to.
pub const SOCKET: &str = "VOIDPORT_TUI_PTY_SOCKET";

/// The environment variable carrying the state file a child serves.
pub const STATE_FILE: &str = "VOIDPORT_TUI_PTY_STATE_FILE";

/// The name of the child test the scenarios run inside.
pub const CHILD_TEST: &str = "pty_child";

/// Distinguishes scratch files created within one process.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A unique name for a scratch file this suite creates.
#[must_use]
pub fn unique(label: &str) -> String {
    format!(
        "{label}-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

/// Re-executes this test binary in a fresh pty, running `scenario`.
///
/// The child runs in [`scratch_root`]: a directory that certainly exists,
/// which the pty harness requires and which also means that anything the child
/// resolves relatively lands in scratch space, not in the crate's own
/// source directory.
#[must_use]
pub fn spawn(scenario: &str, environment: &[(&str, &str)]) -> Pty {
    let program = std::env::current_exe().expect("the test binary");
    let mut spawn = Spawn::new(&program, scratch_root())
        .args(&["--exact", CHILD_TEST, "--nocapture"])
        .env(SCENARIO, scenario);
    for (key, value) in environment {
        spawn = spawn.env(key, value);
    }
    Pty::spawn(&spawn)
}
