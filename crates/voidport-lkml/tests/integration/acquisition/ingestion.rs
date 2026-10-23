use crate::{collector::*, corpus::*};
use std::fs;
use voidport_lkml::{
    model::{AttemptState, MaildirFolder},
    storage::digest,
};

#[test]
fn invalid_new_does_not_hide_cur_or_ingest_tmp() {
    let fixture = Fixture::new();
    let output = fixture.collect(&["file-new", "pair"], &[]);
    assert!(!output.status.success());
    let diagnostic = format!(
        "ingestion failed: missing or invalid new: {}",
        rustix::io::Errno::NOTDIR
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with(&format!(
            "ordinary progress\nError: attempt 1 incomplete: {diagnostic}\n"
        )),
        "{stderr}"
    );
    let state = fixture.state();
    assert_eq!(state.generation, 3);
    assert_eq!(state.records.attempts.len(), 1);
    let attempt = &state.records.attempts[0];
    assert_eq!(attempt.state, AttemptState::Failed);
    assert_eq!(attempt.errors, [diagnostic]);
    assert_eq!(attempt.exit_code, Some(0));
    assert_eq!(attempt.cleanup, "terminated");
    assert_eq!(attempt.deliveries.len(), 1);
    assert_eq!(attempt.deliveries[0].directory, MaildirFolder::Cur);
    assert_eq!(
        attempt.deliveries[0].filename_hex,
        hex::encode("unusual-name")
    );
    assert_eq!(attempt.deliveries[0].digest, digest(&raw(false)));
    assert_eq!(state.records.artifacts.len(), 1);
    assert_eq!(state.records.observations.len(), 1);
    assert_eq!(
        fs::read(fixture.output.join("raw").join(digest(&raw(false)))).unwrap(),
        raw(false)
    );
    assert!(!fixture.output.join("raw").join(digest(&raw(true))).exists());
    for (name, parent) in [("new", true), ("cur/unusual-name", false)] {
        assert_eq!(
            fs::read(fixture.attempt(1).join("maildir").join(name)).unwrap(),
            raw(parent)
        );
    }
    assert_eq!(
        fs::read(fixture.attempt(1).join("maildir/tmp/partial")).unwrap(),
        b"not delivered"
    );
    assert!(!fixture.attempt(2).exists());
    let bytes = fs::read(fixture.output.join("manifest.json")).unwrap();
    fs::remove_file(&fixture.client).unwrap();
    fixture.verify();
    assert_eq!(
        fs::read(fixture.output.join("manifest.json")).unwrap(),
        bytes
    );
}

#[test]
fn unexpected_top_level_entry_is_named_without_losing_delivered_bytes() {
    let fixture = Fixture::new();
    let script = fs::read_to_string(&fixture.client).unwrap();
    fs::write(&fixture.client, script.replace(
        "record(\"delivery-ready.json\",",
        "(ROOT / 'maildir' / 'unexpected-name').write_bytes(b'not mail')\n    record(\"delivery-ready.json\",",
    )).unwrap();
    let output = fixture.collect(&["pair", "later"], &[]);
    assert!(!output.status.success());
    let state = fixture.state();
    assert_eq!(state.generation, 3);
    assert_eq!(state.records.attempts.len(), 1);
    assert_eq!(state.records.attempts[0].state, AttemptState::Failed);
    assert_eq!(
        state.records.attempts[0].errors,
        ["ingestion failed: unexpected Maildir entry \"unexpected-name\""]
    );
    assert!(state.records.attempts[0].deliveries.is_empty());
    assert!(state.records.artifacts.is_empty());
    assert!(state.records.observations.is_empty());
    for (name, parent) in [("new/anything", true), ("cur/unusual-name", false)] {
        assert_eq!(
            fs::read(fixture.attempt(1).join("maildir").join(name)).unwrap(),
            raw(parent)
        );
    }
    assert_eq!(
        fs::read(fixture.attempt(1).join("maildir/unexpected-name")).unwrap(),
        b"not mail"
    );
    assert!(!fixture.attempt(2).exists());
    let bytes = fs::read(fixture.output.join("manifest.json")).unwrap();
    fs::remove_file(&fixture.client).unwrap();
    fixture.verify();
    assert_eq!(
        fs::read(fixture.output.join("manifest.json")).unwrap(),
        bytes
    );
}
