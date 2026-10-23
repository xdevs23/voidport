mod cancellation;
mod cleanup;
mod daemon_pid;
mod directory_sync;
mod ingestion;
mod inventory;
mod publication_writes;
mod status;
use crate::collector::*;
use crate::corpus::*;
use serde::Serialize;
use std::{collections::BTreeMap, fs, os::fd::AsFd as _, path::Path};
use voidport_lkml::{
    mail::{Basis, Class, Mailbox, Relationship, Thread},
    model::{
        Artifact, Attempt, AttemptState, CorpusState, FORMAT_VERSION, MaildirFolder, Observation,
        Root, Segment, Source,
    },
    storage::{Corpus, DataDirectory, FORMAT_VERSION_3, Writer, digest},
};
use voidport_spawn::{Program, Stream};
use voidport_test_host::test_name;

#[test]
fn query_receipts_exact_bytes_counts_and_offline_readers() {
    let fixture = Fixture::new();
    success(&fixture.collect(&["pair", "overlap"], &[]));
    let state = fixture.state();
    assert_eq!(state.configuration.queries, ["pair", "overlap"]);
    assert_eq!(state.records.artifacts.len(), 2);
    assert_eq!(state.records.observations.len(), 4);
    for parent in [true, false] {
        let bytes = raw(parent);
        let key = digest(&bytes);
        let artifact = &state.records.artifacts[&key];
        assert_eq!(artifact.length, bytes.len() as u64);
        assert_eq!(
            artifact.metadata.class,
            if parent {
                Class::Context
            } else {
                Class::Response
            },
            "{key}"
        );
        assert_eq!(
            fs::read(fixture.output.join(&artifact.path)).unwrap(),
            bytes
        );
        assert_eq!(
            state
                .records
                .observations
                .iter()
                .filter(|o| o.delivery.digest == key)
                .count(),
            2
        );
    }
    for observation in &state.records.observations {
        let expected = if observation.delivery.digest == digest(&raw(true)) {
            "https://lore.kernel.org/lkml/parent@example.invalid/"
        } else {
            "https://lore.kernel.org/lkml/child@example.invalid/"
        };
        assert_eq!(observation.archive_link.as_deref(), Some(expected));
    }
    let relation = &state.records.links.relationships[&digest(&raw(false))];
    assert_eq!(relation.candidate.basis, Basis::Direct);
    assert_eq!(relation.targets, [digest(&raw(true))]);
    for attempt in &state.records.attempts {
        assert_eq!(attempt.state, AttemptState::Complete);
        assert_eq!(attempt.tool.version, "fixture-1");
        assert_eq!(attempt.tool.version_provenance, "supplied_package_metadata");
        assert_eq!(attempt.cleanup, "terminated");
        assert!(!std::path::Path::new(&attempt.runtime).exists());
        let directory = fixture.attempt(attempt.id);
        let receipt = json(&directory.join("query.json"));
        assert_eq!(
            receipt["arguments"],
            serde_json::to_value(&attempt.arguments).unwrap()
        );
        let env = receipt["environment"].as_object().unwrap();
        assert!(!env.contains_key("UNRELATED_SECRET"));
        for name in [
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
            "XDG_STATE_HOME",
            "TMPDIR",
        ] {
            assert!(env[name].as_str().unwrap().contains("/fd/"));
        }
        assert_eq!(env["XDG_RUNTIME_DIR"], attempt.runtime);
        for descriptor in receipt["descriptors"].as_object().unwrap().values() {
            assert!(!descriptor.as_str().unwrap().ends_with("/.lock"));
        }
        assert_eq!(
            fs::read(directory.join("query.stderr")).unwrap(),
            b"ordinary progress\n"
        );
        assert!(directory.join("maildir/tmp/partial").exists());
    }
    let status = fixture.status();
    assert_eq!(
        status["status_version"],
        voidport_lkml::model::STATUS_VERSION
    );
    assert_eq!(
        status["counts"],
        serde_json::json!({
            "invalid":0,"ambiguous_from":0,"context":1,"unlinked_author":0,"ambiguous_reply":0,"response":1,
            "artifacts":2,"observations":4,"message_ids":2,"variant_ids":0,"missing_parents":0,
            "complete_units":2,"unfinished_units":0,"partial_files":0
        })
    );
    assert_eq!(
        status["retained_attempt_directories"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    fs::remove_file(&fixture.client).unwrap();
    fixture.verify();
    assert_eq!(fixture.status()["generation"], state.generation);
}

#[test]
fn every_query_runs_against_every_source_and_links_to_it() {
    let sources = [
        "https://lore.kernel.org/linux-fsdevel/",
        "https://lore.kernel.org/rust-for-linux/",
    ];
    let fixture = Fixture::new();
    success(&fixture.collect(
        &["pair", "child-only"],
        &["--source", sources[0], "--source", sources[1]],
    ));
    let state = fixture.state();
    let units: Vec<_> = state
        .records
        .attempts
        .iter()
        .map(|attempt| {
            let receipt = json(&fixture.attempt(attempt.id).join("query.json"));
            let arguments: Vec<String> =
                serde_json::from_value(receipt["arguments"].clone()).unwrap();
            let only = arguments
                .iter()
                .position(|argument| argument == "--only")
                .unwrap();
            (
                arguments[only + 1].clone(),
                state.configuration.queries[attempt.unit.query].clone(),
            )
        })
        .collect();
    assert_eq!(
        units,
        [
            (sources[0].into(), "pair".into()),
            (sources[0].into(), "child-only".into()),
            (sources[1].into(), "pair".into()),
            (sources[1].into(), "child-only".into()),
        ]
    );
    let child_links: std::collections::BTreeSet<_> = state
        .records
        .observations
        .iter()
        .filter(|observation| observation.delivery.digest == digest(&raw(false)))
        .map(|observation| observation.archive_link.clone().unwrap())
        .collect();
    assert_eq!(
        child_links,
        sources
            .iter()
            .map(|source| format!("{source}child@example.invalid/"))
            .collect()
    );
    let status = fixture.status();
    assert_eq!(status["sources"], serde_json::json!(sources));
    assert_eq!(status["counts"]["complete_units"], 4);
    assert_eq!(status["counts"]["unfinished_units"], 0);
    success(&fixture.collect(&[], &[]));
    assert_eq!(fixture.state(), state);
    let unslashed = sources[0].trim_end_matches('/');
    success(&fixture.collect(&[], &["--source", unslashed, "--source", sources[1]]));
    assert_eq!(fixture.state(), state);
    fixture.verify();

    let mut repeated = state.clone();
    repeated
        .configuration
        .sources
        .push(repeated.configuration.sources[0].clone());
    rewrite(&fixture.output, &repeated);
    assert!(Corpus::open(&fixture.output).is_err());

    let lkml = voidport_lkml::model::DEFAULT_SOURCE;
    for refused_sources in [
        &[lkml, lkml][..],
        &[lkml, lkml.trim_end_matches('/')],
        &["lore.kernel.org/lkml/"],
        &["mailto:lkml@example.invalid"],
    ] {
        let refused = Fixture::new();
        let args: Vec<_> = refused_sources
            .iter()
            .flat_map(|source| ["--source", source])
            .collect();
        let output = refused.collect(&["pair"], &args);
        assert!(!output.status.success(), "{refused_sources:?}");
        assert!(!refused.output.exists(), "{refused_sources:?}");
    }
}

#[test]
fn path_resolution_records_unknown_version_and_missing_tool_creates_nothing() {
    let fixture = Fixture::new();
    let bin = fixture.temp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    std::os::unix::fs::symlink(&fixture.client, bin.join("lei")).unwrap();
    let output = fixture
        .command("collect")
        .args(["--query", "pair"])
        .env_remove("VOIDPORT_LKML_LEI")
        .env_remove("VOIDPORT_LKML_LEI_VERSION")
        .env("PATH", &bin)
        .output()
        .unwrap();
    success(&output);
    let state = fixture.state();
    assert_eq!(
        state.records.attempts[0].tool.executable,
        fs::canonicalize(&fixture.client).unwrap().to_str().unwrap()
    );
    assert_eq!(state.records.attempts[0].tool.version, "unknown");
    assert_eq!(state.records.attempts[0].tool.version_provenance, "unknown");
    fixture.verify();

    let missing = Fixture::new();
    let empty_path = missing.temp.path().join("empty-bin");
    fs::create_dir(&empty_path).unwrap();
    let output = missing
        .command("collect")
        .env_remove("VOIDPORT_LKML_LEI")
        .env_remove("VOIDPORT_LKML_LEI_VERSION")
        .env("PATH", empty_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("lei executable is missing or not executable")
    );
    assert!(!missing.output.exists());
}

#[test]
fn non_utf8_runtime_is_rejected_before_client_spawn() {
    use std::os::unix::ffi::OsStrExt;
    let fixture = Fixture::new();
    let runtime = fixture
        .temp
        .path()
        .join(std::ffi::OsStr::from_bytes(b"runtime-\xff"));
    fs::create_dir(&runtime).unwrap();
    let output = fixture
        .command("collect")
        .args(["--query", "pair"])
        .env("TMPDIR", &runtime)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("non-UTF8 runtime path"));
    assert!(fixture.state().records.attempts.is_empty());
    assert!(fixture.attempt(1).is_dir());
    for receipt in ["setup.stdout", "daemon.json", "query.json"] {
        assert!(!fixture.attempt(1).join(receipt).exists());
    }
    assert_eq!(fs::read_dir(runtime).unwrap().count(), 0);
    assert_eq!(
        fixture.status()["retained_attempt_directories"],
        serde_json::json!(["attempts/00000000000000000001"])
    );
    fixture.verify();
}

#[test]
fn hardlinked_deliveries_are_copied_and_tmp_is_only_validated() {
    use std::os::unix::fs::MetadataExt;
    let fixture = Fixture::new();
    success(&fixture.collect(&["hardlinks"], &[]));
    let state = fixture.state();
    let bytes = raw(true);
    let key = digest(&bytes);
    assert_eq!(state.records.artifacts.len(), 1);
    let artifact = &state.records.artifacts[&key];
    assert_eq!(artifact.length, bytes.len() as u64);
    assert_eq!(artifact.metadata.class, Class::Context);
    assert_eq!(
        fs::read(fixture.output.join(&artifact.path)).unwrap(),
        bytes
    );
    let deliveries = &state.records.attempts[0].deliveries;
    assert_eq!(deliveries.len(), 2);
    for (delivery, directory, filename) in [
        (&deliveries[0], MaildirFolder::New, "anything"),
        (&deliveries[1], MaildirFolder::Cur, "alias"),
    ] {
        assert_eq!(delivery.directory, directory);
        assert_eq!(delivery.filename_hex, hex::encode(filename));
        assert_eq!(delivery.digest, key);
    }
    assert_eq!(state.records.observations.len(), 2);
    for observation in &state.records.observations {
        assert_eq!(
            observation.archive_link.as_deref(),
            Some("https://lore.kernel.org/lkml/parent@example.invalid/")
        );
    }
    let input = fs::metadata(fixture.attempt(1).join("maildir/new/anything")).unwrap();
    let stored = fs::metadata(fixture.output.join(&artifact.path)).unwrap();
    assert_eq!(input.nlink(), 2);
    assert_eq!(stored.nlink(), 1);
    assert_ne!(input.ino(), stored.ino());
    assert_eq!(
        fs::metadata(fixture.attempt(1).join("maildir/tmp/partial"))
            .unwrap()
            .nlink(),
        2
    );
    fixture.verify();
}

#[test]
fn large_tmp_is_not_read_or_ingested() {
    if std::env::var_os("LKML_LIMIT_TMP_READ").is_none() {
        let status = Program::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &test_name!(large_tmp_is_not_read_or_ingested),
                "--nocapture",
            ])
            .env("LKML_LIMIT_TMP_READ", "1")
            .stdout(Stream::Inherit)
            .stderr(Stream::Inherit)
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    // A full read of the sparse tmp payload cannot fit in this subprocess.
    rustix::process::setrlimit(
        rustix::process::Resource::As,
        rustix::process::Rlimit {
            current: Some(512 * 1024 * 1024),
            maximum: Some(512 * 1024 * 1024),
        },
    )
    .unwrap();
    let fixture = Fixture::new();
    success(&fixture.collect(&["large-tmp"], &[]));
    let state = fixture.state();
    assert_eq!(state.records.artifacts.len(), 1);
    assert_eq!(state.records.attempts[0].deliveries.len(), 1);
    assert_eq!(
        state.records.attempts[0].deliveries[0].digest,
        digest(&raw(true))
    );
    assert_eq!(
        fs::read(
            fixture
                .output
                .join(&state.records.artifacts[&digest(&raw(true))].path)
        )
        .unwrap(),
        raw(true)
    );
    assert_eq!(
        fs::metadata(fixture.attempt(1).join("maildir/tmp/partial"))
            .unwrap()
            .len(),
        16 * 1024 * 1024 * 1024
    );
    fixture.verify();
}

#[test]
fn sensitive_message_id_has_one_encoded_archive_path_segment() {
    let fixture = Fixture::new();
    success(&fixture.collect(&["sensitive-id"], &[]));
    let state = fixture.state();
    assert_eq!(state.records.observations.len(), 1);
    assert_eq!(
        state
            .records
            .artifacts
            .values()
            .next()
            .unwrap()
            .metadata
            .primary_id
            .as_deref(),
        Some("a/b?c#d%25@example.invalid")
    );
    assert_eq!(
        state.records.observations[0].archive_link.as_deref(),
        Some("https://lore.kernel.org/lkml/a%2Fb%3Fc%23d%2525@example.invalid/")
    );
    fixture.verify();
}

#[test]
fn inter_unit_signals_preserve_completed_attempt_and_restart_only_second() {
    for signal in [rustix::process::Signal::INT, rustix::process::Signal::TERM] {
        let fixture = Fixture::new();
        let mut child = fixture
            .command("collect")
            .args(["--query", "overlap", "--query", "pair"])
            .args(["--delay-seconds", "3600"])
            .stdout(Stream::Null)
            .stderr(Stream::Null)
            .spawn()
            .unwrap();
        // The runtime directory of an attempt is removed when the attempt ends,
        // after the collector checked for a signal at its completion. From then
        // on the collector waits out the delay before the next query.
        wait_until(
            &mut child,
            "the completion of the first attempt",
            &[&fixture.output],
            || {
                fixture.published().is_some_and(|state| {
                    state
                        .records
                        .attempts
                        .first()
                        .is_some_and(|attempt| attempt.state == AttemptState::Complete)
                })
            },
        );
        let runtime = std::path::PathBuf::from(&fixture.state().records.attempts[0].runtime);
        wait_until(
            &mut child,
            "the removal of the runtime directory",
            &[runtime.parent().unwrap()],
            || !runtime.exists(),
        );
        let before = fixture.state();
        assert_eq!(before.records.attempts.len(), 1);
        assert!(before.records.attempts[0].errors.is_empty());
        assert_eq!(before.records.attempts[0].deliveries.len(), 2);
        rustix::process::kill_process(rustix::process::Pid::from_child(&child), signal).unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(1));
        assert_eq!(fixture.state(), before);
        assert!(!fixture.attempt(2).exists());
        fixture.verify();
        success(&fixture.collect(&[], &[]));
        let after = fixture.state();
        assert_eq!(after.records.attempts.len(), 2);
        assert_eq!(after.records.attempts[0], before.records.attempts[0]);
        assert_eq!(after.records.attempts[1].unit.query, 1);
        assert_eq!(after.records.attempts[1].state, AttemptState::Complete);
        assert_eq!(
            json(&fixture.attempt(2).join("query.json"))["arguments"][11],
            "pair"
        );
        for parent in [true, false] {
            assert_eq!(
                fs::read(
                    fixture
                        .output
                        .join(&after.records.artifacts[&digest(&raw(parent))].path)
                )
                .unwrap(),
                raw(parent)
            );
        }
        fixture.verify();
    }
}

#[test]
fn fatal_store_failure_preserves_ordered_diagnostics_and_stops_ingestion() {
    let fixture = Fixture::new();
    let corpus = Writer::open(&fixture.output, configuration(&["fatal-store", "pair"])).unwrap();
    let _created = corpus.data_dir(DataDirectory::Raw).unwrap();
    drop(corpus);
    let planted = fixture.output.join("raw").join(digest(&raw(true)));
    fs::write(&planted, b"other bytes").unwrap();
    assert!(!fixture.collect(&[], &[]).status.success());
    let state = fixture.state();
    assert_eq!(state.generation, 3);
    assert_eq!(state.records.attempts.len(), 1);
    let attempt = &state.records.attempts[0];
    assert_eq!(attempt.state, AttemptState::Failed);
    assert_eq!(attempt.cleanup, "terminated");
    assert_eq!(attempt.exit_code, Some(0));
    assert_eq!(
        attempt.errors,
        [
            "ingestion failed: invalid Maildir entry \"a-invalid\": expected a regular Maildir input file; store Maildir input new/\"b-store\": existing blob differs from delivered bytes"
        ]
    );
    assert!(attempt.deliveries.is_empty());
    assert!(state.records.artifacts.is_empty());
    assert!(!fixture.attempt(2).exists());
    for (name, parent) in [
        ("new/b-store", true),
        ("new/c-later", false),
        ("cur/later", false),
    ] {
        assert_eq!(
            fs::read(fixture.attempt(1).join("maildir").join(name)).unwrap(),
            raw(parent)
        );
    }
    assert!(fixture.attempt(1).join("maildir/new/a-invalid").exists());
    assert_eq!(fs::read(&planted).unwrap(), b"other bytes");
    assert!(
        !fixture
            .output
            .join("raw")
            .join(digest(&raw(false)))
            .exists()
    );
    fixture.verify();
    assert_eq!(fixture.status()["counts"]["partial_files"], 1);
}

#[test]
fn signals_after_failed_publication_preserve_primary_and_replay_errors() {
    use std::io::{Read, Write};
    const PRIMARY: &str = "lei query failed: exit status: 24";
    const UNCONFIRMED: &str = "cancellation publication not confirmed: expected an unlinked-from-other-paths regular file";
    // The fake lei gives setup.stderr a second link, which the replay rejects.
    const REPLAY: &str =
        "replay setup.stderr failed: expected an unlinked-from-other-paths regular file";
    for (signal, reject_publication) in [
        (None, false),
        (Some(rustix::process::Signal::INT), false),
        (Some(rustix::process::Signal::INT), true),
        (Some(rustix::process::Signal::TERM), false),
        (Some(rustix::process::Signal::TERM), true),
    ] {
        let fixture = Fixture::new();
        // The collector writes to its standard error only when it replays the
        // logs of a failed attempt, after it published the attempt. A full pipe
        // blocks the collector in that replay until the test reads.
        let (mut reader, mut writer) = std::io::pipe().unwrap();
        rustix::fs::fcntl_setfl(&writer, rustix::fs::OFlags::NONBLOCK).unwrap();
        let mut filled = 0;
        loop {
            match writer.write(&[0; 4096]) {
                Ok(written) => filled += written,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("{error}"),
            }
        }
        rustix::fs::fcntl_setfl(&writer, rustix::fs::OFlags::empty()).unwrap();
        let mut child = fixture
            .command("collect")
            .args(["--query", "aliased-setup-log", "--query", "pair"])
            .stdout(Stream::Null)
            .stderr(Stream::Descriptor(writer.as_fd()))
            .spawn()
            .unwrap();
        drop(writer);
        wait_until(&mut child, "the failed attempt", &[&fixture.output], || {
            fixture.published().is_some_and(|state| {
                state
                    .records
                    .attempts
                    .first()
                    .is_some_and(|attempt| attempt.state == AttemptState::Failed)
            })
        });
        if reject_publication {
            fs::create_dir(fixture.output.join(".manifest.tmp")).unwrap();
        }
        if let Some(signal) = signal {
            rustix::process::kill_process(rustix::process::Pid::from_child(&child), signal)
                .unwrap();
        }
        let mut stderr = Vec::new();
        reader.read_to_end(&mut stderr).unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(1));
        assert!(stderr[..filled].iter().all(|byte| *byte == 0));
        let stderr = String::from_utf8(stderr.split_off(filled)).unwrap();
        let mut durable = vec![PRIMARY];
        let mut summary = vec![PRIMARY];
        if signal.is_some() {
            summary.push(INTERRUPTION);
            if reject_publication {
                summary.push(UNCONFIRMED);
            } else {
                durable.push(INTERRUPTION);
            }
        }
        summary.push(REPLAY);
        assert!(
            stderr.starts_with(&format!(
                "synthetic failure after delivery\nError: attempt 1 incomplete: {}\n",
                summary.join("; ")
            )),
            "{signal:?}/{reject_publication}: {stderr}"
        );
        assert_eq!(
            stderr.matches(INTERRUPTION).count(),
            usize::from(signal.is_some())
        );
        let manifest_bytes = fs::read(fixture.output.join("manifest.json")).unwrap();
        let state = fixture.state();
        assert_eq!(
            state.generation,
            3 + u64::from(signal.is_some() && !reject_publication)
        );
        assert_eq!(state.records.attempts.len(), 1);
        let attempt = &state.records.attempts[0];
        assert_eq!(attempt.state, AttemptState::Failed);
        assert_eq!(attempt.errors, durable);
        assert_eq!(attempt.exit_code, Some(24));
        assert_eq!(attempt.cleanup, "terminated");
        assert_eq!(attempt.deliveries.len(), 2);
        assert_eq!(state.records.artifacts.len(), 2);
        assert!(!fixture.attempt(2).exists());
        assert!(!std::path::Path::new(&attempt.runtime).exists());
        assert_eq!(
            fs::read(fixture.attempt(1).join("query.stderr")).unwrap(),
            b"synthetic failure after delivery\n"
        );
        assert_eq!(
            fs::read(fixture.attempt(1).join("setup.stderr")).unwrap(),
            fs::read(fixture.attempt(1).join("log-alias")).unwrap()
        );
        for (name, parent) in [("new/anything", true), ("cur/unusual-name", false)] {
            assert_eq!(
                fs::read(fixture.attempt(1).join("maildir").join(name)).unwrap(),
                raw(parent)
            );
        }
        if reject_publication {
            assert!(fixture.output.join(".manifest.tmp").is_dir());
            fs::remove_dir(fixture.output.join(".manifest.tmp")).unwrap();
        }
        fixture.verify();
        assert_eq!(fixture.status()["counts"]["unfinished_units"], 2);
        assert_eq!(
            fs::read(fixture.output.join("manifest.json")).unwrap(),
            manifest_bytes
        );
    }
}

#[test]
fn signal_filenames_do_not_control_cancellation_diagnostics() {
    const ENTRY: &str =
        "ingestion failed: invalid Maildir entry \"signal\": expected a regular Maildir input file";
    for (query, signals) in [
        ("filename-signal", vec![None]),
        (
            "wait-filename-signal",
            vec![
                Some(rustix::process::Signal::INT),
                Some(rustix::process::Signal::TERM),
            ],
        ),
    ] {
        for signal in signals {
            let fixture = Fixture::new();
            let mut child = fixture
                .command("collect")
                .args(["--query", query, "--query", "pair"])
                .stdout(Stream::Null)
                .stderr(Stream::Null)
                .spawn()
                .unwrap();
            if let Some(signal) = signal {
                wait_file(&fixture.attempt(1).join("delivery-ready.json"), &mut child);
                rustix::process::kill_process(rustix::process::Pid::from_child(&child), signal)
                    .unwrap();
            }
            assert!(!child.wait().unwrap().success());
            let state = fixture.state();
            assert_eq!(state.records.attempts.len(), 1);
            let attempt = &state.records.attempts[0];
            assert_eq!(attempt.state, AttemptState::Failed);
            assert_eq!(
                attempt
                    .errors
                    .iter()
                    .filter(|error| *error == INTERRUPTION)
                    .count(),
                usize::from(signal.is_some())
            );
            assert_eq!(
                attempt
                    .errors
                    .iter()
                    .filter(|error| *error == ENTRY)
                    .count(),
                1
            );
            assert_eq!(attempt.errors.len(), 1 + usize::from(signal.is_some()));
            assert_eq!(attempt.cleanup, "terminated");
            assert_eq!(attempt.deliveries.len(), 2);
            assert!(!std::path::Path::new(&attempt.runtime).exists());
            assert!(!fixture.attempt(2).exists());
            fixture.verify();
        }
    }
}

#[test]
fn retries_refresh_history_configuration_and_persisted_defaults() {
    let fixture = Fixture::new();
    success(&fixture.collect(&["pair"], &["--author", "torvalds@osdl.org"]));
    let original = fs::read(fixture.output.join("manifest.json")).unwrap();
    success(&fixture.collect(&[], &[]));
    assert_eq!(
        fs::read(fixture.output.join("manifest.json")).unwrap(),
        original
    );
    for args in [
        vec!["--source", "https://lore.kernel.org/linux-fsdevel/"],
        vec!["--query", "changed"],
        vec!["--author", "other@example.invalid"],
    ] {
        assert!(!fixture.collect(&[], &args).status.success());
        assert_eq!(
            fs::read(fixture.output.join("manifest.json")).unwrap(),
            original
        );
    }
    success(&fixture.collect(&[], &["--refresh"]));
    let refreshed = fixture.state();
    let previous_finish =
        voidport_lkml::model::timestamp(refreshed.records.attempts[0].finished.as_deref().unwrap())
            .unwrap();
    let next_start =
        voidport_lkml::model::timestamp(&refreshed.records.attempts[1].started).unwrap();
    assert!(
        next_start - previous_finish
            >= time::Duration::seconds(refreshed.records.attempts[1].delay_seconds as i64)
    );
    assert_eq!(fixture.state().records.observations.len(), 4);
    assert_eq!(fixture.state().records.artifacts.len(), 2);
    let script = fs::read_to_string(&fixture.client).unwrap();
    fs::write(
        &fixture.client,
        script.replace("case = args[-1]", "case = 'failed-delivery'"),
    )
    .unwrap();
    assert!(!fixture.collect(&[], &["--refresh"]).status.success());
    let failed = fixture.state();
    assert_eq!(failed.records.attempts.len(), 3);
    assert_eq!(failed.records.observations.len(), 6);
    assert!(!failed.complete(failed.units()[0]));
    fs::write(&fixture.client, script).unwrap();
    success(&fixture.collect(&[], &[]));
    assert_eq!(fixture.state().records.attempts.len(), 4);
    assert_eq!(fixture.state().records.observations.len(), 8);
    fixture.verify();
}

#[derive(Serialize)]
struct ManifestV3<'a> {
    format_version: u32,
    generation: u64,
    sources: &'a [Source],
    queries: &'a [String],
    authors: &'a [Mailbox],
    attempts: &'a [Attempt],
    artifacts: &'a BTreeMap<String, Artifact>,
    observations: &'a [Observation],
    links: LinksV3<'a>,
}
#[derive(Serialize)]
struct LinksV3<'a> {
    message_ids: &'a BTreeMap<String, Vec<String>>,
    relationships: &'a BTreeMap<String, Relationship>,
    threads: Vec<&'a Thread>,
}

fn corpus_with_child(output: &Path, queries: &[&str]) -> (CorpusState, String) {
    let mut corpus = Writer::open(output, configuration(queries)).unwrap();
    let attempt = reserve(&mut corpus, 0);
    let child = ingest(&mut corpus, attempt, &raw(false));
    finish(&mut corpus, attempt);
    (corpus.state().clone(), child)
}

fn write_version_3(output: &Path, state: &CorpusState, threads: Vec<&Thread>) {
    let configuration = &state.configuration;
    let records = &state.records;
    let manifest = ManifestV3 {
        format_version: FORMAT_VERSION_3,
        generation: state.generation,
        sources: &configuration.sources,
        queries: &configuration.queries,
        authors: &configuration.authors,
        attempts: &records.attempts,
        artifacts: &records.artifacts,
        observations: &records.observations,
        links: LinksV3 {
            message_ids: &records.links.message_ids,
            relationships: &records.links.relationships,
            threads,
        },
    };
    fs::write(
        output.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    fs::remove_dir_all(output.join(DataDirectory::Segments.name())).unwrap();
}

#[test]
fn collect_converts_a_corpus_of_version_3_and_readers_leave_it() {
    let fixture = Fixture::new();
    let (stored, child) = corpus_with_child(&fixture.output, &["child-only", "later-parent"]);
    let threads = stored.records.links.threads.values().collect();
    write_version_3(&fixture.output, &stored, threads);
    let version_3 = fs::read(fixture.output.join("manifest.json")).unwrap();
    for operation in ["status", "verify"] {
        let output = fixture.command(operation).output().unwrap();
        assert!(!output.status.success(), "{operation}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("run collect to convert the corpus to the current format")
                && stderr.contains("corpus format version 3"),
            "{operation}: {stderr}"
        );
        assert_eq!(
            fs::read(fixture.output.join("manifest.json")).unwrap(),
            version_3
        );
        assert!(!fixture.output.join("segments").exists());
    }
    success(&fixture.collect(&[], &[]));
    let root: Root =
        serde_json::from_slice(&fs::read(fixture.output.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(root.format_version, FORMAT_VERSION);
    let segments = fixture.output.join(DataDirectory::Segments.name());
    let mut name = root.head;
    let converted = loop {
        let segment: Segment =
            serde_json::from_slice(&fs::read(segments.join(&name)).unwrap()).unwrap();
        match segment.previous.clone() {
            Some(previous) => name = previous,
            None => break segment,
        }
    };
    assert_eq!(
        converted,
        Segment {
            generation: stored.generation + 1,
            previous: None,
            records: stored.records.clone(),
        }
    );
    let collected = fixture.state();
    assert_eq!(collected.generation, stored.generation + 3);
    assert_eq!(collected.records.attempts.len(), 2);
    assert_eq!(collected.records.attempts[0], stored.records.attempts[0]);
    assert!(!fixture.attempt(1).join("query.json").exists());
    assert_eq!(
        collected.records.links.relationships[&child].targets,
        [digest(&raw(true))]
    );
    fixture.verify();
}

#[test]
fn a_refused_collect_leaves_a_corpus_of_version_3_unchanged() {
    let without_members = Thread {
        roots: Default::default(),
        members: Default::default(),
    };
    for refusal in [
        "query configuration differs",
        "raw integrity mismatch",
        "thread without members",
        "listed twice",
    ] {
        let fixture = Fixture::new();
        let (stored, child) = corpus_with_child(&fixture.output, &["child-only"]);
        let thread = stored.records.links.threads.values().next().unwrap();
        let threads = match refusal {
            "thread without members" => vec![thread, &without_members],
            "listed twice" => vec![thread, thread],
            _ => vec![thread],
        };
        write_version_3(&fixture.output, &stored, threads);
        let version_3 = fs::read(fixture.output.join("manifest.json")).unwrap();
        if refusal == "raw integrity mismatch" {
            fs::write(fixture.output.join("raw").join(&child), b"other bytes").unwrap();
        }
        let arguments: &[&str] = if refusal == "query configuration differs" {
            &["--query", "changed"]
        } else {
            &[]
        };
        let output = fixture.collect(&[], arguments);
        assert!(!output.status.success(), "{refusal}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(refusal),
            "{refusal}: {output:?}"
        );
        assert_eq!(
            fs::read(fixture.output.join("manifest.json")).unwrap(),
            version_3,
            "{refusal}"
        );
        assert!(!fixture.output.join("segments").exists(), "{refusal}");
    }
}

#[test]
fn collect_reuses_or_replaces_a_leftover_converted_segment() {
    use std::os::unix::fs::MetadataExt;
    for leftover in ["complete", "staging"] {
        let fixture = Fixture::new();
        let (stored, _child) = corpus_with_child(&fixture.output, &["child-only"]);
        let threads = stored.records.links.threads.values().collect();
        write_version_3(&fixture.output, &stored, threads);
        let bytes = Segment {
            generation: stored.generation + 1,
            previous: None,
            records: stored.records.clone(),
        }
        .encode()
        .unwrap();
        let name = digest(&bytes);
        let segments = fixture.output.join(DataDirectory::Segments.name());
        fs::create_dir(&segments).unwrap();
        let converted = segments.join(&name);
        let left = if leftover == "complete" {
            fs::write(&converted, &bytes).unwrap();
            converted.clone()
        } else {
            let staging = segments.join(format!("{name}.partial"));
            fs::write(&staging, &bytes[..bytes.len() / 2]).unwrap();
            staging
        };
        let left_inode = fs::metadata(&left).unwrap().ino();
        success(&fixture.collect(&[], &[]));
        assert_eq!(fs::read(&converted).unwrap(), bytes, "{leftover}");
        if leftover == "complete" {
            assert_eq!(fs::metadata(&converted).unwrap().ino(), left_inode);
        } else {
            assert!(!left.exists());
        }
        assert_eq!(fixture.state().head, Some(name), "{leftover}");
        let (partial, _attempts) = Corpus::open(&fixture.output).unwrap().inventory().unwrap();
        assert_eq!(partial, Vec::<String>::new(), "{leftover}");
        fixture.verify();
    }
}

#[test]
fn historical_arguments_are_preserved_and_structural_corruption_is_rejected() {
    let fixture = Fixture::new();
    success(&fixture.collect(&["pair"], &[]));
    let mut historical = fixture.state();
    let arguments: Vec<String> = [
        "q",
        "--no-local",
        "--threads",
        "--remote",
        "--no-save",
        "--dedupe",
        "none",
        "--only",
        voidport_lkml::model::DEFAULT_SOURCE,
        "--output",
        "maildir:maildir",
        "--",
        "pair",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_ne!(
        arguments,
        voidport_lkml::acquire::query_arguments(&historical.configuration.sources[0], "pair")
    );
    historical.records.attempts[0].arguments = arguments.clone();
    let path = fixture.output.join("manifest.json");
    let bytes = rewrite(&fixture.output, &historical);
    assert_eq!(
        Corpus::open(&fixture.output)
            .unwrap()
            .state()
            .records
            .attempts[0]
            .arguments,
        arguments
    );
    assert_eq!(
        fixture.status()["attempts"][0]["arguments"],
        serde_json::to_value(&arguments).unwrap()
    );
    fixture.verify();
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let mut nul = arguments.clone();
    nul[1].push('\0');
    let mut wrong_query = arguments.clone();
    *wrong_query.last_mut().unwrap() = "other".into();
    let mut no_separator = arguments.clone();
    no_separator.remove(no_separator.len() - 2);
    let mut wrong_source = arguments.clone();
    let only = wrong_source
        .iter()
        .position(|argument| argument == "--only")
        .unwrap();
    wrong_source[only + 1] = "https://lore.kernel.org/linux-fsdevel/".into();
    for invalid in [
        vec![],
        vec!["q".into()],
        vec!["daemon-kill".into(), "--".into(), "pair".into()],
        nul,
        wrong_query,
        no_separator,
        wrong_source,
    ] {
        let mut corrupt = historical.clone();
        corrupt.records.attempts[0].arguments = invalid;
        let corrupt_bytes = rewrite(&fixture.output, &corrupt);
        assert!(Corpus::open(&fixture.output).is_err());
        assert!(!fixture.command("status").output().unwrap().status.success());
        assert!(!fixture.command("verify").output().unwrap().status.success());
        assert_eq!(fs::read(&path).unwrap(), corrupt_bytes);
    }
}

#[test]
fn variants_and_later_parent_recomputation() {
    let fixture = Fixture::new();
    success(&fixture.collect(&["child-only", "later-parent", "variants"], &[]));
    let state = fixture.state();
    let targets = &state.records.links.message_ids["parent@example.invalid"];
    assert_eq!(targets.len(), 2);
    for key in targets {
        assert_eq!(
            digest(&fs::read(fixture.output.join("raw").join(key)).unwrap()),
            *key
        );
    }
    assert_eq!(
        state.records.links.relationships[&digest(&raw(false))].targets,
        *targets
    );
    assert!(
        state.records.links.relationships[&digest(&raw(false))]
            .missing
            .is_empty()
    );
    assert_eq!(fixture.status()["counts"]["variant_ids"], 1);
    fixture.verify();
}

#[test]
fn observable_failures_never_become_empty_success_or_retry() {
    for (query, artifacts, invalid) in [
        ("refused", 0, 0),
        ("failed-delivery", 2, 0),
        ("bare-html", 1, 1),
        ("malformed", 1, 1),
        ("missing-cur", 0, 0),
        ("symlink", 1, 0),
        ("fifo", 1, 0),
        ("tmp-symlink", 1, 0),
        ("tmp-fifo", 1, 0),
    ] {
        let fixture = Fixture::new();
        let output = fixture.collect(&[query, "pair"], &[]);
        assert!(!output.status.success(), "{query}");
        let state = fixture.state();
        assert_eq!(state.records.attempts.len(), 1, "{query}");
        assert_eq!(
            state.records.attempts[0].state,
            AttemptState::Failed,
            "{query}"
        );
        assert_eq!(state.records.artifacts.len(), artifacts, "{query}");
        if ["symlink", "fifo", "tmp-symlink", "tmp-fifo"].contains(&query) {
            let key = digest(&raw(true));
            assert_eq!(state.records.artifacts[&key].metadata.class, Class::Context);
            assert_eq!(
                fs::read(fixture.output.join(&state.records.artifacts[&key].path)).unwrap(),
                raw(true)
            );
            assert_eq!(state.records.attempts[0].deliveries.len(), 1);
            assert_eq!(state.records.attempts[0].deliveries[0].digest, key);
            assert!(
                state.records.attempts[0]
                    .errors
                    .iter()
                    .any(|error| error.contains("invalid Maildir entry"))
            );
        }
        assert_eq!(fixture.status()["counts"]["invalid"], invalid, "{query}");
        assert!(!std::path::Path::new(&state.records.attempts[0].runtime).exists());
        fixture.verify();
    }
    for query in ["empty", "html-mail"] {
        let fixture = Fixture::new();
        success(&fixture.collect(&[query], &[]));
        let state = fixture.state();
        assert!(state.complete(state.units()[0]));
        assert_eq!(fixture.status()["counts"]["invalid"], 0);
        if query == "empty" {
            assert_eq!(state.records.attempts.len(), 1);
            assert_eq!(state.records.attempts[0].state, AttemptState::Complete);
            assert!(state.records.attempts[0].deliveries.is_empty());
            assert!(state.records.artifacts.is_empty());
            assert!(state.records.observations.is_empty());
            assert_eq!(
                fixture.status()["counts"],
                serde_json::json!({
                    "invalid":0,"ambiguous_from":0,"context":0,"unlinked_author":0,"ambiguous_reply":0,"response":0,
                    "artifacts":0,"observations":0,"message_ids":0,"variant_ids":0,"missing_parents":0,
                    "complete_units":1,"unfinished_units":0,"partial_files":0
                })
            );
        }
        assert!(
            fixture.status()["limitations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str().unwrap().contains("indistinguishable"))
        );
    }
}

fn failed_and_released(fixture: &Fixture) -> CorpusState {
    let state = fixture.state();
    assert_eq!(state.records.attempts.len(), 1);
    let attempt = &state.records.attempts[0];
    assert_eq!(attempt.state, AttemptState::Failed);
    assert_eq!(attempt.cleanup, "terminated");
    assert!(!Path::new(&attempt.runtime).exists());
    fixture.verify();
    state
}

#[test]
fn handled_signals_and_busy_readers_release_owned_state() {
    for signal in [rustix::process::Signal::INT, rustix::process::Signal::TERM] {
        let fixture = Fixture::new();
        let mut child = fixture
            .command("collect")
            .args(["--query", "wait"])
            .stdout(Stream::Null)
            .stderr(Stream::Null)
            .spawn()
            .unwrap();
        wait_file(&fixture.attempt(1).join("delivery-ready.json"), &mut child);
        assert!(child.try_wait().unwrap().is_none());
        assert_eq!(
            json(&fixture.attempt(1).join("delivery-ready.json"))["files"],
            serde_json::json!(["new/anything", "cur/unusual-name"])
        );
        let daemon = pidfd_of_record(&fixture.attempt(1).join("daemon.json"));
        let query = pidfd_of_record(&fixture.attempt(1).join("query.json"));
        let original = fs::read(fixture.output.join("manifest.json")).unwrap();
        // A lock call that waited for the collector could return only after the
        // collector released the lock. A refusal while the collector still runs
        // shows that the call did not wait for it, however long the contender
        // took to start. The case asserts no time, so a wait that ends by
        // itself is not caught.
        for operation in ["status", "verify", "collect"] {
            let contender = fixture
                .command(operation)
                .stdout(Stream::Piped)
                .stderr(Stream::Piped)
                .spawn()
                .unwrap();
            let output = contender.wait_with_output().unwrap();
            assert!(!output.status.success(), "{operation}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("corpus busy"),
                "{operation}: {output:?}"
            );
            assert!(
                child.try_wait().unwrap().is_none(),
                "{operation} returned after the collector released the lock"
            );
            assert_eq!(
                fs::read(fixture.output.join("manifest.json")).unwrap(),
                original
            );
        }
        rustix::process::kill_process(rustix::process::Pid::from_child(&child), signal).unwrap();
        assert!(!child.wait().unwrap().success());
        let state = failed_and_released(&fixture);
        assert!(has_exited(&daemon));
        assert!(has_exited(&query));
        assert_eq!(state.records.artifacts.len(), 2);
        for parent in [true, false] {
            let bytes = raw(parent);
            let artifact = &state.records.artifacts[&digest(&bytes)];
            assert_eq!(
                fs::read(fixture.output.join(&artifact.path)).unwrap(),
                bytes
            );
        }
    }
}

#[test]
fn query_timeout_releases_owned_state() {
    let fixture = Fixture::new();
    let output = fixture.collect(&["wait"], &["--timeout-seconds", "1"]);
    assert!(!output.status.success());
    let state = failed_and_released(&fixture);
    let attempt = &state.records.attempts[0];
    assert!(
        attempt
            .errors
            .iter()
            .any(|error| error.contains("acquisition timeout"))
    );
    assert_eq!(attempt.exit_code, None);
}

fn fixture_holding_setup() -> Fixture {
    let fixture = Fixture::new();
    fixture.replace_in_client("hold_setup = False", "hold_setup = True");
    fixture
}

#[test]
fn interrupted_setup_identifies_and_stops_the_owned_daemon() {
    for signal in [rustix::process::Signal::INT, rustix::process::Signal::TERM] {
        let fixture = fixture_holding_setup();
        let mut child = fixture
            .command("collect")
            .args(["--query", "pair"])
            .stdout(Stream::Null)
            .stderr(Stream::Null)
            .spawn()
            .unwrap();
        wait_file(&fixture.attempt(1).join("daemon-ready.json"), &mut child);
        let daemon = pidfd_of_record(&fixture.attempt(1).join("daemon.json"));
        let reserved = fixture.state();
        assert_eq!(reserved.records.attempts[0].state, AttemptState::Running);
        rustix::process::kill_process(rustix::process::Pid::from_child(&child), signal).unwrap();
        assert!(!child.wait().unwrap().success());
        let failed = failed_and_released(&fixture);
        assert!(has_exited(&daemon));
        assert_eq!(failed.generation, reserved.generation + 1);
        assert!(failed.records.artifacts.is_empty());
        assert!(!fixture.attempt(1).join("query.json").exists());
    }
}

#[test]
fn setup_timeout_identifies_and_stops_the_owned_daemon() {
    let fixture = fixture_holding_setup();
    let output = fixture.collect(&["pair"], &["--timeout-seconds", "1"]);
    assert!(!output.status.success());
    let failed = failed_and_released(&fixture);
    assert_eq!(failed.records.attempts[0].errors[0], "acquisition timeout");
    assert!(failed.records.artifacts.is_empty());
    assert!(!fixture.attempt(1).join("query.json").exists());
}

#[test]
fn hard_kill_recovery_uses_fresh_state_without_inherited_lock() {
    let fixture = Fixture::new();
    let mut child = fixture
        .command("collect")
        .args(["--query", "wait", "--delay-seconds", "1"])
        .stdout(Stream::Null)
        .stderr(Stream::Null)
        .spawn()
        .unwrap();
    wait_file(&fixture.attempt(1).join("delivery-ready.json"), &mut child);
    let owned = ["query.json", "daemon.json"]
        .map(|record| pidfd_of_record(&fixture.attempt(1).join(record)));
    let before = fixture.state();
    child.kill().unwrap();
    child.wait().unwrap();
    let reader = Corpus::open(&fixture.output).unwrap();
    assert_eq!(reader.state().generation, before.generation);
    assert_eq!(
        reader.state().records.attempts[0].state,
        AttemptState::Running
    );
    assert!(reader.state().records.artifacts.is_empty());
    drop(reader);
    let script = fs::read_to_string(&fixture.client).unwrap();
    fs::write(
        &fixture.client,
        script.replace("case = args[-1]", "case = 'pair'"),
    )
    .unwrap();
    success(&fixture.collect(&[], &[]));
    let after = fixture.state();
    assert_eq!(after.records.attempts[0].state, AttemptState::Interrupted);
    assert!(after.records.attempts[0].cleanup.contains("unknown"));
    assert_ne!(
        after.records.attempts[0].runtime,
        after.records.attempts[1].runtime
    );
    assert!(after.records.attempts[1].state == AttemptState::Complete);
    assert!(fixture.attempt(1).join("maildir/new/anything").exists());
    // These handles were opened while the fixture processes were observed
    // alive. Neither the killed collector nor the recovery stopped them.
    for process in owned {
        assert!(!has_exited(&process));
        rustix::process::pidfd_send_signal(&process, rustix::process::Signal::TERM).unwrap();
    }
    fs::remove_dir_all(&after.records.attempts[0].runtime).unwrap();
    fixture.verify();
}
