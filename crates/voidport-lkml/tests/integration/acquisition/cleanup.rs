use crate::collector::*;
use rustix::process::{Pid, Signal, kill_process, pidfd_send_signal};
use std::path::Path;
use voidport_lkml::model::{Attempt, AttemptState};
use voidport_spawn::Stream;

fn collect_held_query(fixture: &Fixture) -> std::process::Child {
    let mut child = fixture
        .command("collect")
        .args(["--query", "wait"])
        .stdout(Stream::Null)
        .stderr(Stream::Null)
        .spawn()
        .unwrap();
    wait_file(&fixture.attempt(1).join("delivery-ready.json"), &mut child);
    child
}

fn interrupted_attempt(fixture: &Fixture, first_error: &str) -> Attempt {
    let state = fixture.state();
    assert_eq!(state.records.attempts.len(), 1);
    let attempt = state.records.attempts[0].clone();
    assert_eq!(attempt.state, AttemptState::Failed);
    assert_eq!(attempt.errors[0], first_error);
    assert_eq!(
        attempt
            .errors
            .iter()
            .filter(|error| *error == INTERRUPTION)
            .count(),
        1
    );
    assert_eq!(attempt.cleanup, "terminated");
    assert!(!Path::new(&attempt.runtime).exists());
    fixture.verify();
    attempt
}

#[test]
fn cleanup_kills_a_daemon_that_ignores_sigterm_and_leaves_no_fixture_process() {
    let fixture = Fixture::new();
    fixture.replace_in_client("ignore_terminate = False", "ignore_terminate = True");
    let mut child = collect_held_query(&fixture);
    let daemon = pidfd_of_record(&fixture.attempt(1).join("daemon.json"));
    let query = pidfd_of_record(&fixture.attempt(1).join("query.json"));
    kill_process(Pid::from_child(&child), Signal::INT).unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(1));
    let attempt = interrupted_attempt(&fixture, INTERRUPTION);
    assert_eq!(attempt.deliveries.len(), 2);
    assert!(has_exited(&daemon));
    assert!(has_exited(&query));
}

#[test]
fn cleanup_confirms_a_daemon_that_exited_before_it() {
    let fixture = Fixture::new();
    let mut child = collect_held_query(&fixture);
    let daemon = pidfd_of_record(&fixture.attempt(1).join("daemon.json"));
    pidfd_send_signal(&daemon, Signal::KILL).unwrap();
    wait_exit(&daemon);
    kill_process(Pid::from_child(&child), Signal::INT).unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(1));
    interrupted_attempt(&fixture, INTERRUPTION);
}

struct SetupEnd {
    replacement: &'static str,
    signalled: bool,
    error: &'static str,
}

#[test]
fn a_signal_during_cleanup_lets_the_cleanup_finish() {
    for setup in [
        SetupEnd {
            replacement: "hold_setup = True",
            signalled: true,
            error: INTERRUPTION,
        },
        SetupEnd {
            replacement: "sys.exit(25)",
            signalled: false,
            error: "lei daemon setup failed: exit status: 25",
        },
    ] {
        let fixture = Fixture::new();
        fixture.replace_in_client("hold_setup = False", setup.replacement);
        fixture.replace_in_client("hold_identify = False", "hold_identify = True");
        let mut child = fixture
            .command("collect")
            .args(["--query", "pair", "--query", "later"])
            .stdout(Stream::Null)
            .stderr(Stream::Null)
            .spawn()
            .unwrap();
        let attempt = fixture.attempt(1);
        if setup.signalled {
            wait_file(&attempt.join("daemon-ready.json"), &mut child);
            kill_process(Pid::from_child(&child), Signal::INT).unwrap();
        }
        wait_file(&attempt.join("identify-ready.json"), &mut child);
        let daemon = pidfd_of_record(&attempt.join("daemon.json"));
        let identify = pidfd_of_record(&attempt.join("identify-ready.json"));
        kill_process(Pid::from_child(&child), Signal::TERM).unwrap();
        release(&attempt.join("identify-release"));
        assert_eq!(child.wait().unwrap().code(), Some(1), "{}", setup.error);
        let recorded = interrupted_attempt(&fixture, setup.error);
        assert!(recorded.deliveries.is_empty());
        assert!(!attempt.join("query.json").exists());
        assert!(!fixture.attempt(2).exists());
        assert!(has_exited(&daemon));
        assert!(has_exited(&identify));
    }
}
