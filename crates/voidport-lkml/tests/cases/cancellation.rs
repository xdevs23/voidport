use crate::{collector::*, corpus::*};
use std::fs;
use voidport_lkml::{
    model::AttemptState,
    storage::{Writer, digest},
};
use voidport_spawn::Stream;

#[test]
fn terminal_publication_keeps_recorded_signal_identity() {
    for signal in [rustix::process::Signal::INT, rustix::process::Signal::TERM] {
        let fixture = Fixture::new();
        let mut corpus = Writer::open(
            &fixture.output,
            configuration(&["earlier", "wait", "later"]),
        )
        .unwrap();
        let attempt = reserve(&mut corpus, 0);
        let _parent = ingest(&mut corpus, attempt, &raw(true));
        finish(&mut corpus, attempt);
        let earlier = corpus.state().clone();
        drop(corpus);
        let mut child = fixture
            .command("collect")
            .args(["--delay-seconds", "1"])
            .stdout(Stream::Null)
            .stderr(Stream::Piped)
            .spawn()
            .unwrap();
        wait_file(&fixture.attempt(2).join("delivery-ready.json"), &mut child);
        let daemon = pidfd_of_record(&fixture.attempt(2).join("daemon.json"));
        let reserved = fixture.state();
        assert_eq!(reserved.records.attempts.len(), 2);
        assert_eq!(reserved.records.attempts[0], earlier.records.attempts[0]);
        assert_eq!(reserved.records.attempts[1].state, AttemptState::Running);
        // A directory in place of the staging file makes the terminal
        // publication fail before its rename.
        fs::create_dir(fixture.output.join(".manifest.tmp")).unwrap();
        rustix::process::kill_process(rustix::process::Pid::from_child(&child), signal).unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{signal:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains(
                "Error: acquisition interrupted by signal; cancellation publication not confirmed: expected an unlinked-from-other-paths regular file\n"
            ),
            "{stderr}"
        );
        assert_eq!(fixture.state(), reserved);
        assert!(!fixture.attempt(3).exists());
        assert!(has_exited(&daemon));
        assert!(!std::path::Path::new(&reserved.records.attempts[1].runtime).exists());
        for (name, parent) in [("new/anything", true), ("cur/unusual-name", false)] {
            assert_eq!(
                fs::read(fixture.attempt(2).join("maildir").join(name)).unwrap(),
                raw(parent)
            );
            assert_eq!(
                fs::read(fixture.output.join("raw").join(digest(&raw(parent)))).unwrap(),
                raw(parent)
            );
        }
        fs::remove_dir(fixture.output.join(".manifest.tmp")).unwrap();
        let bytes = fs::read(fixture.output.join("manifest.json")).unwrap();
        fs::remove_file(&fixture.client).unwrap();
        fixture.verify();
        assert_eq!(
            fs::read(fixture.output.join("manifest.json")).unwrap(),
            bytes
        );
        assert_eq!(fixture.status()["generation"], reserved.generation);
    }
}
