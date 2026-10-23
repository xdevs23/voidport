use std::sync::atomic::{AtomicU64, Ordering};

use voidport_pty::{Pty, Spawn};
use voidport_test_support::scratch_root;

pub const SCENARIO: &str = "VOIDPORT_TUI_PTY_SCENARIO";

pub const SOCKET: &str = "VOIDPORT_TUI_PTY_SOCKET";

pub const STATE_FILE: &str = "VOIDPORT_TUI_PTY_STATE_FILE";

pub const ACKNOWLEDGEMENT: &str = "VOIDPORT_TUI_PTY_ACKNOWLEDGEMENT";

pub fn await_observation() {
    use std::io::Read as _;
    let path = std::env::var(ACKNOWLEDGEMENT).expect("the parent names its acknowledgement socket");
    let mut stream = std::os::unix::net::UnixStream::connect(path).expect("the parent listens");
    println!("CHILD-AWAITING-OBSERVATION");
    let mut byte = [0];
    stream
        .read_exact(&mut byte)
        .expect("the parent acknowledges observation");
    assert_eq!(byte, [1]);
}

pub fn acknowledge(listener: &std::os::unix::net::UnixListener, pty: &Pty) {
    use std::io::Write as _;
    assert!(
        pty.wait_for("CHILD-AWAITING-OBSERVATION"),
        "{}",
        pty.output()
    );
    listener
        .set_nonblocking(true)
        .expect("a nonblocking listener");
    let (mut stream, _) = listener.accept().expect("the child awaits observation");
    stream
        .write_all(&[1])
        .expect("the child accepts the acknowledgement");
}

pub const CHILD_TEST: &str = "pty_child";

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[must_use]
pub fn unique(label: &str) -> String {
    format!(
        "{label}-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

/// The child runs in [`scratch_root`], which the pty harness requires to
/// exist.
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
