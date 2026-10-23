use std::{ffi::OsStr, fs, path::Path};
use voidport_lkml::{
    mail,
    model::{
        self, Attempt, AttemptState, Configuration, CorpusState, MaildirFolder, Outcome, Root,
        Segment, Tool, Unit,
    },
    staging::AttemptHandle,
    storage::{DataDirectory, Writer, attempt_name, digest},
};

pub fn temporary() -> tempfile::TempDir {
    match std::env::var_os("VOIDPORT_LKML_TEST_ROOT") {
        Some(root) => tempfile::tempdir_in(root).unwrap(),
        None => tempfile::tempdir().unwrap(),
    }
}
pub fn configuration(queries: &[&str]) -> Configuration {
    Configuration {
        sources: model::sources(&[model::DEFAULT_SOURCE.into()]).unwrap(),
        queries: queries.iter().map(|q| (*q).into()).collect(),
        authors: mail::authors(&["torvalds@osdl.org".into()]).unwrap(),
    }
}
pub fn reserve(corpus: &mut Writer, query: usize) -> AttemptHandle {
    let id = u64::try_from(corpus.state().records.attempts.len()).unwrap() + 1;
    corpus
        .data_dir(DataDirectory::Attempts)
        .unwrap()
        .create(&attempt_name(id))
        .unwrap();
    let configuration = &corpus.state().configuration;
    let arguments = voidport_lkml::acquire::query_arguments(
        &configuration.sources[0],
        &configuration.queries[query],
    );
    let attempt = corpus
        .add_attempt(Attempt {
            id,
            unit: Unit { source: 0, query },
            directory: DataDirectory::Attempts.path(&attempt_name(id)),
            runtime: String::new(),
            tool: Tool {
                executable: "fake".into(),
                version: "fixture".into(),
                version_provenance: "test".into(),
            },
            arguments,
            timeout_seconds: 10,
            delay_seconds: 1,
            started: model::now(),
            finished: None,
            state: AttemptState::Running,
            exit_code: None,
            cleanup: "not established".into(),
            errors: vec![],
            deliveries: vec![],
        })
        .unwrap();
    corpus.publish().unwrap();
    attempt
}
pub fn ingest(corpus: &mut Writer, attempt: AttemptHandle, raw: &[u8]) -> String {
    let artifact = corpus.store(raw).unwrap();
    let digest = artifact.digest.clone();
    let delivered = corpus.attempt(attempt).unwrap().deliveries.len();
    let filename = format!("mail-{delivered}");
    corpus
        .deliver(attempt, MaildirFolder::New, OsStr::new(&filename), artifact)
        .unwrap();
    digest
}
pub fn completion() -> Outcome {
    Outcome {
        state: AttemptState::Complete,
        exit_code: Some(0),
        finished: model::now(),
        cleanup: "terminated".into(),
        errors: vec![],
    }
}
pub fn finish(corpus: &mut Writer, attempt: AttemptHandle) {
    corpus.record_outcome(attempt, completion()).unwrap();
    corpus.publish().unwrap();
}
pub fn rewrite(output: &Path, state: &CorpusState) -> Vec<u8> {
    let segment = Segment {
        generation: state.generation,
        previous: None,
        records: state.records.clone(),
    }
    .encode()
    .unwrap();
    let name = digest(&segment);
    let segments = output.join(DataDirectory::Segments.name());
    fs::create_dir_all(&segments).unwrap();
    fs::write(segments.join(&name), &segment).unwrap();
    let root = Root {
        format_version: model::FORMAT_VERSION,
        generation: state.generation,
        configuration: state.configuration.clone(),
        head: name,
    }
    .encode()
    .unwrap();
    fs::write(output.join("manifest.json"), &root).unwrap();
    root
}
pub fn raw(parent: bool) -> Vec<u8> {
    if parent {
        b"From: other@example.invalid\r\nMessage-ID: <parent@example.invalid>\r\nSubject: synthetic\r\n\r\nbody\r\n".to_vec()
    } else {
        b"From: torvalds@osdl.org\r\nMessage-ID: <child@example.invalid>\r\nSubject: synthetic\r\nIn-Reply-To: <parent@example.invalid>\r\n\r\nFrom literal\r\n>From literal\r\n>>From literal\r\n".to_vec()
    }
}
