use crate::collector::*;
use std::fs;
use voidport_lkml::model::AttemptState;

#[test]
fn malformed_daemon_pid_names_retained_output_and_preserves_parser_errors() {
    for (literal, bytes, context, cause) in [
        (
            "b'\\xff\\n'",
            b"\xff\n".as_slice(),
            "decode lei daemon-pid result in setup.stdout",
            "invalid utf-8 sequence of 1 bytes from index 0",
        ),
        (
            "b'not-a-pid\\n'",
            b"not-a-pid\n".as_slice(),
            "parse lei daemon-pid result in setup.stdout",
            "invalid digit found in string",
        ),
    ] {
        let fixture = Fixture::new();
        let script = fs::read_to_string(&fixture.client).unwrap();
        let original =
            "    print(json.loads((ROOT / \"daemon.json\").read_text())[\"pid\"], flush=True)";
        assert_eq!(script.matches(original).count(), 1);
        fs::write(&fixture.client, script.replace(original, &format!(
            "    sys.stdout.buffer.write({literal})\n    sys.stdout.buffer.flush()\n    print('synthetic setup diagnostic', file=sys.stderr)"
        ))).unwrap();
        let output = fixture.collect(&["pair", "later-parent"], &[]);
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        let primary = format!("{context}: {cause}");
        let cleanup = "cleanup unconfirmed: daemon identity was not established; termination cannot be confirmed";
        let summary = stderr.find("attempt 1 incomplete:").unwrap();
        let contextual = stderr[summary..].find(&primary).unwrap();
        let unconfirmed = stderr[summary..].find(cleanup).unwrap();
        assert!(contextual < unconfirmed);
        let state = fixture.state();
        assert_eq!(state.records.attempts.len(), 1);
        let attempt = &state.records.attempts[0];
        assert_eq!(attempt.state, AttemptState::Failed);
        assert_eq!(attempt.errors[0], primary);
        assert_eq!(attempt.errors[1], cleanup);
        assert_eq!(attempt.cleanup, cleanup);
        assert_eq!(attempt.exit_code, None);
        assert!(attempt.deliveries.is_empty());
        assert!(state.records.artifacts.is_empty());
        assert_eq!(
            fs::read(fixture.attempt(1).join("setup.stdout")).unwrap(),
            bytes
        );
        assert_eq!(
            fs::read(fixture.attempt(1).join("setup.stderr")).unwrap(),
            b"synthetic setup diagnostic\n"
        );
        assert_eq!(
            fs::read(fixture.attempt(1).join("cleanup-identify.stdout")).unwrap(),
            bytes
        );
        assert!(!fixture.attempt(1).join("query.json").exists());
        assert!(
            is_gone(&fixture.attempt(1).join("daemon.json")),
            "the unidentified daemon is still running"
        );
        assert!(!fixture.attempt(2).exists());
        assert!(!std::path::Path::new(&attempt.runtime).exists());
        let before = fs::read(fixture.output.join("manifest.json")).unwrap();
        fs::remove_file(&fixture.client).unwrap();
        fixture.verify();
        assert_eq!(
            fs::read(fixture.output.join("manifest.json")).unwrap(),
            before
        );
    }
}
