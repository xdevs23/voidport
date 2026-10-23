use crate::{collector::*, corpus::*};
use serde::Deserialize;
use std::fs;
use voidport_lkml::{model, storage::Writer};

#[test]
fn zero_and_one_missing_pair_counts_match_the_identity_list() {
    let fixture = Fixture::new();
    let mut corpus = Writer::open(&fixture.output, configuration(&["offline"])).unwrap();
    let attempt = reserve(&mut corpus, 0);
    for missing in [false, true] {
        let expected = if missing {
            let digest = ingest(&mut corpus, attempt, &raw(false));
            corpus.publish().unwrap();
            serde_json::json!([{"source_digest": digest, "target_message_id": "parent@example.invalid"}])
        } else {
            serde_json::json!([])
        };
        let status = serde_json::to_value(model::status(corpus.state(), vec![], vec![])).unwrap();
        assert_eq!(status["missing_context"], expected);
        assert_eq!(status["counts"]["missing_parents"], usize::from(missing));
        assert_eq!(
            status["counts"]["missing_parents"],
            status["missing_context"].as_array().unwrap().len()
        );
    }
}

#[test]
fn attempt_states_have_exact_stable_human_and_json_spellings() {
    let fixture = Fixture::new();
    let mut corpus = Writer::open(&fixture.output, configuration(&["offline"])).unwrap();
    for state in [
        model::AttemptState::Complete,
        model::AttemptState::Failed,
        model::AttemptState::Interrupted,
        model::AttemptState::Running,
    ] {
        let attempt = reserve(&mut corpus, 0);
        if state != model::AttemptState::Running {
            let outcome = model::Outcome {
                state,
                ..completion()
            };
            corpus.record_outcome(attempt, outcome).unwrap();
            corpus.publish().unwrap();
        }
    }
    let generation = corpus.state().generation;
    drop(corpus);
    fs::remove_file(&fixture.client).unwrap();
    let value = fixture.status();
    let source = model::DEFAULT_SOURCE;
    let mut expected = format!(
        "corpus generation {generation}\nsource: {source}\nunit: {source} offline: unfinished\n"
    );
    for (name, count) in value["counts"].as_object().unwrap() {
        expected.push_str(&format!("{name}: {count}\n"));
    }
    for (index, spelling) in ["complete", "failed", "interrupted", "running"]
        .into_iter()
        .enumerate()
    {
        assert_eq!(value["attempts"][index]["state"], spelling);
        let id = index + 1;
        let cleanup = if spelling == "running" {
            "not established"
        } else {
            "terminated"
        };
        expected.push_str(&format!(
            "attempt {id}: {spelling}; attempts/{id:020}; {cleanup}\n"
        ));
    }
    for limitation in model::LIMITATIONS {
        expected.push_str(limitation);
        expected.push('\n');
    }
    let output = fixture.command("status").output().unwrap();
    success(&output);
    assert_eq!(output.stdout, expected.as_bytes());
    fixture.verify();
}

#[derive(Deserialize)]
struct Versions {
    status_version: u32,
    format_version: u32,
}

#[test]
fn unresolved_identities_are_ordered_and_offline_in_both_presentations() {
    let fixture = Fixture::new();
    let mut corpus = Writer::open(&fixture.output, configuration(&["offline"])).unwrap();
    let attempt = reserve(&mut corpus, 0);
    let first = ingest(&mut corpus, attempt, &raw(false));
    let second = ingest(
        &mut corpus,
        attempt,
        b"From: torvalds@osdl.org\r\nIn-Reply-To: <another@example.invalid>\r\n\r\nbody\r\n",
    );
    finish(&mut corpus, attempt);
    let mut pairs = [
        (first, "parent@example.invalid"),
        (second, "another@example.invalid"),
    ];
    pairs.sort();
    let state = corpus.state().clone();
    drop(corpus);
    let before = fs::read(fixture.output.join("manifest.json")).unwrap();
    fs::remove_file(&fixture.client).unwrap();
    let expected = serde_json::json!(
        pairs
            .iter()
            .map(|(source, target)| {
                serde_json::json!({"source_digest": source, "target_message_id": target})
            })
            .collect::<Vec<_>>()
    );
    let json = fixture.command("status").arg("--json").output().unwrap();
    success(&json);
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value["missing_context"], expected);
    assert_eq!(value["counts"]["missing_parents"], 2);
    assert_eq!(
        value["counts"]["missing_parents"],
        value["missing_context"].as_array().unwrap().len()
    );
    let versions: Versions = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(versions.status_version, model::STATUS_VERSION);
    assert_eq!(versions.format_version, model::FORMAT_VERSION);
    assert_eq!(
        fixture
            .command("status")
            .arg("--json")
            .output()
            .unwrap()
            .stdout,
        json.stdout
    );
    let expected_record = serde_json::to_value(model::status(
        &state,
        vec![],
        vec!["attempts/00000000000000000001".into()],
    ))
    .unwrap();
    assert_eq!(value, expected_record);
    let source = model::DEFAULT_SOURCE;
    let mut human = format!(
        "corpus generation {}\nsource: {source}\nunit: {source} offline: complete\n",
        state.generation
    );
    for (name, count) in value["counts"].as_object().unwrap() {
        human.push_str(&format!("{name}: {count}\n"));
    }
    for (source, target) in &pairs {
        human.push_str(&format!("missing context: {source} -> {target}\n"));
    }
    human.push_str("attempt 1: complete; attempts/00000000000000000001; terminated\n");
    for limitation in model::LIMITATIONS {
        human.push_str(limitation);
        human.push('\n');
    }
    let output = fixture.command("status").output().unwrap();
    success(&output);
    assert_eq!(output.stdout, human.as_bytes());
    fixture.verify();
    assert_eq!(
        fs::read(fixture.output.join("manifest.json")).unwrap(),
        before
    );
}

#[test]
fn export_prints_the_records_of_the_published_generation() {
    let fixture = Fixture::new();
    success(&fixture.collect(&["pair", "later-parent"], &[]));
    let output = fixture.command("export").output().unwrap();
    success(&output);
    let exported: model::Records = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(exported, fixture.state().records);
    assert!(!exported.artifacts.is_empty());
}
