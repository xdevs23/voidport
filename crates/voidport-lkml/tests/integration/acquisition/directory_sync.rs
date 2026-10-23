use crate::{
    collector::*,
    corpus::*,
    faulty_filesystem::{FaultyFilesystem, wait_for_held_sync},
};
use rustix::process::{Pid, Signal, kill_process};
use std::{
    os::unix::process::ExitStatusExt,
    process::{Child, Output},
};
use voidport_lkml::{
    model::{AttemptState, CorpusState},
    storage::Writer,
};
use voidport_spawn::Stream;

const UNCERTAIN_CANCELLATION: &str = "Error: acquisition interrupted by signal; \
     cancellation publication not confirmed: uncertain manifest commit";

fn collect_with_delayed_reservation(
    act: impl FnOnce(&FaultyFilesystem, &mut Child),
) -> (Fixture, CorpusState, Output) {
    let mut fixture = Fixture::new();
    let backing = fixture.temp.path().join("backing");
    let filesystem = FaultyFilesystem::mount(&backing, &fixture.output);
    let mut corpus = Writer::open(&fixture.output, configuration(&["earlier", "pair"])).unwrap();
    let attempt = reserve(&mut corpus, 0);
    let _parent = ingest(&mut corpus, attempt, &raw(true));
    finish(&mut corpus, attempt);
    let earlier = corpus.state().clone();
    drop(corpus);
    let arrived = filesystem.hold_next_sync();
    let mut collector = fixture
        .command("collect")
        .args(["--delay-seconds", "1"])
        .stdout(Stream::Null)
        .stderr(Stream::Piped)
        .spawn()
        .unwrap();
    wait_for_held_sync(&arrived, &mut collector);
    act(&filesystem, &mut collector);
    filesystem.release_held_sync();
    let output = collector.wait_with_output().unwrap();
    filesystem.unmount();
    fixture.output = backing;
    (fixture, earlier, output)
}

fn terminate(collector: &Child) {
    kill_process(Pid::from_child(collector), Signal::TERM).unwrap();
}
fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn restart(fixture: &Fixture) -> CorpusState {
    success(&fixture.collect(&[], &[]));
    fixture.verify();
    fixture.state()
}
fn assert_retried(stopped: &CorpusState, restarted: &CorpusState) {
    assert_eq!(
        restarted.records.attempts.len(),
        stopped.records.attempts.len() + 1
    );
    assert_eq!(restarted.records.attempts[0], stopped.records.attempts[0]);
    let retry = restarted.records.attempts.last().unwrap();
    assert_eq!(retry.unit, stopped.records.attempts[1].unit);
    assert_eq!(retry.state, AttemptState::Complete);
}

#[test]
#[ignore = "needs /dev/fuse and runs under tests/filesystem-check"]
fn uncertain_terminal_publication_is_kept_and_not_run_again() {
    let (fixture, earlier, collector) =
        collect_with_delayed_reservation(|filesystem, _| filesystem.fail_next_sync());
    assert_eq!(collector.status.code(), Some(1));
    assert!(
        stderr(&collector).starts_with("Error: uncertain manifest commit"),
        "{}",
        stderr(&collector)
    );
    let stopped = fixture.state();
    assert_eq!(stopped.generation, earlier.generation + 2);
    assert_eq!(stopped.records.attempts[0], earlier.records.attempts[0]);
    assert_eq!(stopped.records.attempts[1].state, AttemptState::Complete);
    assert_eq!(stopped.records.attempts[1].deliveries.len(), 2);
    assert_eq!(restart(&fixture), stopped);
}

#[test]
#[ignore = "needs /dev/fuse and runs under tests/filesystem-check"]
fn kill_at_the_reservation_is_interrupted_and_retried() {
    let (fixture, earlier, collector) =
        collect_with_delayed_reservation(|_, collector| collector.kill().unwrap());
    assert_eq!(
        collector.status.signal(),
        Some(signal_hook::consts::SIGKILL)
    );
    let stopped = fixture.state();
    assert_eq!(stopped.generation, earlier.generation + 1);
    assert_eq!(stopped.records.attempts[0], earlier.records.attempts[0]);
    assert_eq!(stopped.records.attempts[1].state, AttemptState::Running);
    let restarted = restart(&fixture);
    assert_retried(&stopped, &restarted);
    assert_eq!(
        restarted.records.attempts[1].state,
        AttemptState::Interrupted
    );
    assert_eq!(
        restarted.records.attempts[1].errors,
        ["previous invocation ended before attempt completion"]
    );
}

#[test]
#[ignore = "needs /dev/fuse and runs under tests/filesystem-check"]
fn signal_at_the_reservation_with_an_uncertain_terminal_publication_is_retried() {
    // The collector handles the signal when the delayed sync returns, before it
    // starts the client.
    let (fixture, earlier, collector) =
        collect_with_delayed_reservation(|filesystem, collector| {
            filesystem.fail_next_sync();
            terminate(collector);
        });
    assert_eq!(collector.status.code(), Some(1));
    assert!(
        stderr(&collector).starts_with(UNCERTAIN_CANCELLATION),
        "{}",
        stderr(&collector)
    );
    let stopped = fixture.state();
    assert_eq!(stopped.generation, earlier.generation + 2);
    assert_eq!(stopped.records.attempts[1].state, AttemptState::Failed);
    assert_eq!(
        stopped.records.attempts[1].errors[0],
        "acquisition interrupted by signal"
    );
    let restarted = restart(&fixture);
    assert_retried(&stopped, &restarted);
    assert_eq!(restarted.records.attempts[1], stopped.records.attempts[1]);
}

#[test]
#[ignore = "needs /dev/fuse and runs under tests/filesystem-check"]
fn signal_at_the_terminal_publication_fails_the_complete_attempt_and_retries_it() {
    let (fixture, earlier, collector) =
        collect_with_delayed_reservation(|filesystem, collector| {
            let terminal = filesystem.hold_next_sync();
            filesystem.release_held_sync();
            wait_for_held_sync(&terminal, collector);
            filesystem.fail_next_sync();
            terminate(collector);
        });
    assert_eq!(collector.status.code(), Some(1));
    assert!(
        stderr(&collector).starts_with(UNCERTAIN_CANCELLATION),
        "{}",
        stderr(&collector)
    );
    let stopped = fixture.state();
    assert_eq!(stopped.generation, earlier.generation + 3);
    assert_eq!(stopped.records.attempts[1].state, AttemptState::Failed);
    assert_eq!(
        stopped.records.attempts[1].errors,
        ["acquisition interrupted by signal"]
    );
    assert_eq!(stopped.records.attempts[1].deliveries.len(), 2);
    let restarted = restart(&fixture);
    assert_retried(&stopped, &restarted);
    assert_eq!(restarted.records.attempts[1], stopped.records.attempts[1]);
}
