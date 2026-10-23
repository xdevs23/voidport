#![forbid(unsafe_code)]
#[path = "support/corpus.rs"]
mod corpus;
mod faulty_filesystem;
use corpus::*;
use faulty_filesystem::{FaultyFilesystem, wait_for_held_sync};
use rustix::process::{
    DumpableBehavior, Resource, Rlimit, getrlimit, set_dumpable_behavior, setrlimit,
};
use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, symlink},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process::Output,
    sync::Barrier,
};
use voidport_lkml::{
    error::error_text,
    mail::{Class, Links},
    model::{Records, Root, Segment, Source},
    staging::AttemptHandle,
    storage::{Corpus, DataDirectory, StorageError, Writer, digest},
};
use voidport_spawn::{Program, Stream};

fn rerun(test: &str) -> Program<'static> {
    let mut program = Program::new(std::env::current_exe().unwrap());
    program
        .args(["--exact", test, "--nocapture", "--include-ignored"])
        .stdout(Stream::Inherit)
        .stderr(Stream::Inherit);
    program
}
fn run_with_write_limit(test: &str, corpus: &Path, terminate: bool) -> Output {
    let mut command = rerun(test);
    command.env("LKML_LIMITED_CORPUS", corpus);
    if terminate {
        command.env("LKML_LIMIT_TERMINATES", "1");
    }
    // Pipes are not files, so the limit leaves the output of the copy alone.
    let output = command.output().unwrap();
    let ended = if terminate {
        output.status.signal() == Some(signal_hook::consts::SIGXFSZ)
    } else {
        output.status.success()
    };
    assert!(ended, "{test}: {output:?}");
    output
}
fn limited_corpus() -> Option<PathBuf> {
    std::env::var_os("LKML_LIMITED_CORPUS").map(PathBuf::from)
}
fn limit_writes() {
    // A write past the limit raises SIGXFSZ, which ends the process. When the
    // signal is handled, the write fails with EFBIG instead.
    if std::env::var_os("LKML_LIMIT_TERMINATES").is_none() {
        signal_hook::flag::register(signal_hook::consts::SIGXFSZ, Default::default()).unwrap();
    }
    // SIGXFSZ dumps core, and the kernel starts the helper of a
    // `core_pattern` pipe whatever the core-dump limit is, but not for a
    // process that is not dumpable (`coredump_skip` in `fs/coredump.c`,
    // Linux 7.2.10). `systemd-coredump`, such a helper, copies every mount
    // of the machine into a namespace of its own and makes them busy for a
    // while. An `execve` makes a process dumpable again, so this applies
    // only to the code that runs in this process.
    set_dumpable_behavior(DumpableBehavior::NotDumpable).unwrap();
    setrlimit(
        Resource::Fsize,
        Rlimit {
            current: Some(0),
            maximum: getrlimit(Resource::Fsize).maximum,
        },
    )
    .unwrap();
}

fn corpus_with_reserved_attempt(path: &Path) -> (Writer, AttemptHandle, String) {
    let mut corpus = Writer::open(path, configuration(&["first", "second"])).unwrap();
    let completed = reserve(&mut corpus, 0);
    let parent = ingest(&mut corpus, completed, &raw(true));
    finish(&mut corpus, completed);
    let reserved = reserve(&mut corpus, 1);
    (corpus, reserved, parent)
}

fn running(corpus: &Writer) -> AttemptHandle {
    let &[attempt] = corpus.running_attempts().as_slice() else {
        panic!("not exactly one running attempt");
    };
    attempt
}

fn partial_files(partial: Vec<String>) -> (Vec<String>, String) {
    let (segments, others): (Vec<_>, Vec<_>) = partial
        .into_iter()
        .partition(|path| path.starts_with("segments/"));
    let [segment] = <[String; 1]>::try_from(segments).unwrap();
    (others, segment)
}

#[test]
fn failed_publication_keeps_the_previous_generation() {
    if let Some(path) = limited_corpus() {
        let mut corpus = Writer::open(&path, configuration(&["first", "second"])).unwrap();
        let attempt = running(&corpus);
        let _child = ingest(&mut corpus, attempt, &raw(false));
        let generation = corpus.state().generation;
        limit_writes();
        let error = error_text(&corpus.publish().unwrap_err());
        assert!(!error.contains("uncertain"), "{error}");
        assert_eq!(corpus.state().generation, generation);
        return;
    }
    let child = digest(&raw(false));
    for failure in ["write error", "write termination", "rename error"] {
        let temp = temporary();
        let path = temp.path().join("corpus");
        let (mut corpus, attempt, parent) = corpus_with_reserved_attempt(&path);
        let old = corpus.state().clone();
        if failure == "rename error" {
            let _child = ingest(&mut corpus, attempt, &raw(false));
            let saved = temp.path().join("manifest.saved");
            fs::rename(path.join("manifest.json"), &saved).unwrap();
            fs::create_dir(path.join("manifest.json")).unwrap();
            let error = error_text(&corpus.publish().unwrap_err());
            assert!(!error.contains("uncertain"), "{error}");
            assert_eq!(corpus.state().generation, old.generation);
            drop(corpus);
            fs::remove_dir(path.join("manifest.json")).unwrap();
            fs::rename(saved, path.join("manifest.json")).unwrap();
        } else {
            drop(corpus);
            run_with_write_limit(
                "failed_publication_keeps_the_previous_generation",
                &path,
                failure == "write termination",
            );
        }
        let (expected, staging) = if failure == "rename error" {
            (
                vec![".manifest.tmp".to_owned(), format!("raw/{child}")],
                false,
            )
        } else {
            (vec![format!("raw/{child}")], true)
        };
        let reader = Corpus::open(&path).unwrap();
        assert_eq!(reader.state(), &old, "{failure}");
        assert!(reader.state().records.artifacts.contains_key(&parent));
        assert_eq!(fs::read(path.join("raw").join(&child)).unwrap(), raw(false));
        reader.verify().unwrap();
        let (partial, segment) = partial_files(reader.inventory().unwrap().0);
        assert_eq!(partial, expected, "{failure}");
        assert_eq!(segment.ends_with(".partial"), staging, "{failure}");
        drop(reader);
        let mut retry = Writer::open(&path, configuration(&["first", "second"])).unwrap();
        retry.publish().unwrap();
        assert_eq!(retry.state().generation, old.generation + 1);
        assert_eq!(retry.state().records, old.records);
        assert_eq!(
            partial_files(retry.inventory().unwrap().0),
            (vec![format!("raw/{child}")], segment)
        );
        retry.verify().unwrap();
    }
}

fn assert_published(path: &Path, previous: u64, parent: &str, child: &str) {
    let mut corpus = Writer::open(path, configuration(&["first", "second"])).unwrap();
    assert_eq!(corpus.state().generation, previous + 1);
    assert_eq!(corpus.state().records.artifacts.len(), 2);
    for (key, bytes) in [(parent, raw(true)), (child, raw(false))] {
        assert!(corpus.state().records.artifacts.contains_key(key), "{key}");
        assert_eq!(fs::read(path.join("raw").join(key)).unwrap(), bytes);
    }
    corpus.verify().unwrap();
    assert!(corpus.inventory().unwrap().0.is_empty());
    corpus.publish().unwrap();
    assert_eq!(corpus.state().generation, previous + 2);
    corpus.verify().unwrap();
}

#[test]
#[ignore = "needs /dev/fuse and runs under tests/filesystem-check"]
fn failed_directory_sync_after_the_rename_is_an_uncertain_commit() {
    let temp = temporary();
    let backing = temp.path().join("backing");
    let filesystem = FaultyFilesystem::mount(&backing, &temp.path().join("mountpoint"));
    let (mut corpus, attempt, parent) = corpus_with_reserved_attempt(&filesystem.mountpoint);
    let previous = corpus.state().generation;
    let child = ingest(&mut corpus, attempt, &raw(false));
    filesystem.fail_next_sync();
    let error = error_text(&corpus.publish().unwrap_err());
    assert!(error.contains("uncertain manifest commit"), "{error}");
    assert_eq!(corpus.state().generation, previous + 1);
    drop(corpus);
    filesystem.unmount();
    assert_published(&backing, previous, &parent, &child);
}

#[test]
#[ignore = "needs /dev/fuse and runs under tests/filesystem-check"]
fn a_publication_writes_each_file_with_one_request() {
    let temp = temporary();
    let backing = temp.path().join("backing");
    let filesystem = FaultyFilesystem::mount(&backing, &temp.path().join("mountpoint"));
    let (mut corpus, attempt, _parent) = corpus_with_reserved_attempt(&filesystem.mountpoint);
    let _child = ingest(&mut corpus, attempt, &raw(false));
    finish(&mut corpus, attempt);
    let generation = corpus.state().generation;
    drop(corpus);
    let published = filesystem.published_files();
    filesystem.unmount();
    let roots = published
        .iter()
        .filter(|(name, _)| name == "manifest.json")
        .count();
    assert_eq!(u64::try_from(roots).unwrap(), generation);
    assert_eq!(published.len(), 2 * roots + 2, "{published:?}");
    assert!(
        published.iter().all(|(_, requests)| *requests == 1),
        "{published:?}"
    );
}

#[test]
#[ignore = "needs /dev/fuse and runs under tests/filesystem-check"]
fn stop_after_the_rename_keeps_the_new_generation() {
    if let Some(path) = std::env::var_os("LKML_STOPPED_CORPUS") {
        let mut corpus =
            Writer::open(Path::new(&path), configuration(&["first", "second"])).unwrap();
        let attempt = running(&corpus);
        let _child = ingest(&mut corpus, attempt, &raw(false));
        corpus.publish().unwrap();
        panic!("the sync after the rename was not held");
    }
    let temp = temporary();
    let backing = temp.path().join("backing");
    let filesystem = FaultyFilesystem::mount(&backing, &temp.path().join("mountpoint"));
    let (corpus, _, parent) = corpus_with_reserved_attempt(&filesystem.mountpoint);
    let previous = corpus.state().generation;
    drop(corpus);
    let arrived = filesystem.hold_next_sync();
    let mut copy = rerun("stop_after_the_rename_keeps_the_new_generation")
        .env("LKML_STOPPED_CORPUS", &filesystem.mountpoint)
        .spawn()
        .unwrap();
    wait_for_held_sync(&arrived, &mut copy);
    copy.kill().unwrap();
    filesystem.release_held_sync();
    assert_eq!(
        copy.wait().unwrap().signal(),
        Some(signal_hook::consts::SIGKILL)
    );
    filesystem.unmount();
    assert_published(&backing, previous, &parent, &digest(&raw(false)));
}

#[test]
fn failed_raw_store_is_uncommitted_and_retryable() {
    if let Some(path) = limited_corpus() {
        let corpus = Writer::open(&path, configuration(&["q"])).unwrap();
        limit_writes();
        corpus.store(&raw(false)).unwrap_err();
        return;
    }
    let bytes = raw(false);
    let key = digest(&bytes);
    // A failed or ended write leaves an empty staging file. A stop after the
    // write leaves the whole staging file, and a stop after its rename leaves
    // an unreferenced blob.
    for (failure, leftover, content) in [
        ("write error", format!("raw/{key}.partial"), vec![]),
        ("write termination", format!("raw/{key}.partial"), vec![]),
        (
            "stop after the write",
            format!("raw/{key}.partial"),
            bytes.clone(),
        ),
        ("stop after the rename", format!("raw/{key}"), bytes.clone()),
    ] {
        let temp = temporary();
        let path = temp.path().join("corpus");
        let mut corpus = Writer::open(&path, configuration(&["q"])).unwrap();
        let attempt = reserve(&mut corpus, 0);
        let before = corpus.state().clone();
        let _created = corpus.data_dir(DataDirectory::Raw).unwrap();
        drop(corpus);
        match failure {
            "write error" | "write termination" => {
                run_with_write_limit(
                    "failed_raw_store_is_uncommitted_and_retryable",
                    &path,
                    failure == "write termination",
                );
            }
            _ => fs::write(path.join(&leftover), &content).unwrap(),
        }
        let reader = Corpus::open(&path).unwrap();
        assert_eq!(reader.state(), &before, "{failure}");
        reader.verify().unwrap();
        assert_eq!(
            reader.inventory().unwrap().0,
            std::slice::from_ref(&leftover),
            "{failure}"
        );
        assert_eq!(
            fs::read(path.join(&leftover)).unwrap(),
            content,
            "{failure}"
        );
        drop(reader);
        let mut retry = Writer::open(&path, configuration(&["q"])).unwrap();
        assert_eq!(ingest(&mut retry, attempt, &bytes), key);
        finish(&mut retry, attempt);
        assert_eq!(fs::read(path.join("raw").join(&key)).unwrap(), bytes);
        retry.verify().unwrap();
        assert!(retry.inventory().unwrap().0.is_empty(), "{failure}");
    }
}

#[test]
fn concurrent_initializers_and_shared_readers_keep_one_lock_inode() {
    let temp = temporary();
    let path = temp.path().join("corpus");
    for round in 0..16 {
        let racing_path = if round == 0 {
            path.clone()
        } else {
            temp.path().join(format!("race-{round}"))
        };
        const CONTENDERS: usize = 4;
        let start = Barrier::new(CONTENDERS);
        // Each contender retains the file it opened until all have returned, so a
        // second exclusive opener would have to succeed while the first still has
        // its lock.
        let returned = Barrier::new(CONTENDERS);
        let results: Vec<_> = std::thread::scope(|scope| {
            let contenders: Vec<_> = (0..CONTENDERS)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        let result = Writer::open(&racing_path, configuration(&["q"]));
                        returned.wait();
                        result.map(|_| ()).map_err(|error| error_text(&error))
                    })
                })
                .collect();
            contenders
                .into_iter()
                .map(|contender| contender.join().unwrap())
                .collect()
        });
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "{results:?}"
        );
        for error in results.iter().filter_map(|result| result.as_ref().err()) {
            assert!(error.contains("corpus busy"), "{error}");
        }
        let reader = Corpus::open(&racing_path).unwrap();
        assert_eq!(reader.state().generation, 1);
    }
    let inode = fs::metadata(path.join(".lock")).unwrap().ino();
    let first = Corpus::open(&path).unwrap();
    let second = Corpus::open(&path).unwrap();
    assert!(Writer::open(&path, configuration(&["q"])).is_err());
    drop((first, second));
    let writer = Writer::open(&path, configuration(&["q"])).unwrap();
    assert!(Corpus::open(&path).is_err());
    assert_eq!(fs::metadata(path.join(".lock")).unwrap().ino(), inode);
    drop(writer);
    assert!(Corpus::open(&path).is_ok());
}

#[test]
fn initialization_foreign_paths_symlinks_and_versions_are_safe() {
    let temp = temporary();
    let missing = temp.path().join("missing");
    assert!(Corpus::open(&missing).is_err());
    assert!(!missing.exists());
    fs::create_dir(&missing).unwrap();
    assert!(Corpus::open(&missing).is_err());
    assert_eq!(fs::read_dir(&missing).unwrap().count(), 0);
    fs::write(missing.join("foreign"), b"do not change").unwrap();
    assert!(Writer::open(&missing, configuration(&["q"])).is_err());
    assert_eq!(fs::read(missing.join("foreign")).unwrap(), b"do not change");
    assert!(!missing.join(".lock").exists());
    let path = temp.path().join("corpus");
    drop(Writer::open(&path, configuration(&["q"])).unwrap());
    let alias = temp.path().join("alias");
    symlink(&path, &alias).unwrap();
    assert!(Corpus::open(&alias).is_err());
    let parent_alias = temp.path().join("parent-alias");
    symlink(temp.path(), &parent_alias).unwrap();
    assert!(Corpus::open(&parent_alias.join("corpus")).is_ok());
    let original = fs::read(path.join("manifest.json")).unwrap();
    let mut root: Root = serde_json::from_slice(&original).unwrap();
    root.format_version = 999;
    let unknown = root.encode().unwrap();
    fs::write(path.join("manifest.json"), &unknown).unwrap();
    let error = Writer::open(&path, configuration(&["q"]))
        .err()
        .expect("a manifest of an unknown version was read");
    assert!(
        matches!(error, StorageError::UnsupportedVersion { version: 999 }),
        "{error}"
    );
    assert_eq!(fs::read(path.join("manifest.json")).unwrap(), unknown);
    let recovery = temp.path().join("recovery");
    fs::create_dir(&recovery).unwrap();
    fs::write(recovery.join(".lock"), b"").unwrap();
    fs::write(
        recovery.join(".manifest.tmp"),
        b"interrupted initialization",
    )
    .unwrap();
    let first = Segment {
        generation: 1,
        previous: None,
        records: Records::default(),
    }
    .encode()
    .unwrap();
    let first_name = digest(&first);
    fs::create_dir(recovery.join("segments")).unwrap();
    fs::write(recovery.join("segments").join(&first_name), &first).unwrap();
    let inode = fs::metadata(recovery.join(".lock")).unwrap().ino();
    assert!(Corpus::open(&recovery).is_err());
    let corpus = Writer::open(&recovery, configuration(&["q"])).unwrap();
    assert_eq!(corpus.state().generation, 1);
    assert_eq!(corpus.state().head, Some(first_name));
    assert_eq!(fs::metadata(recovery.join(".lock")).unwrap().ino(), inode);
}

#[test]
fn directory_exists_requires_one_normal_component() {
    let temp = temporary();
    let path = temp.path().join("directory");
    fs::create_dir(&path).unwrap();
    let outside = temp.path().join("outside");
    fs::write(&outside, b"outside bytes").unwrap();
    fs::write(path.join("present"), b"inside bytes").unwrap();
    fs::create_dir(path.join("a")).unwrap();
    fs::write(path.join("a/b"), b"nested bytes").unwrap();
    symlink(&outside, path.join("link")).unwrap();
    symlink(temp.path().join("missing"), path.join("dangling")).unwrap();
    let directory = voidport_lkml::storage::Directory::open(&path).unwrap();
    for name in [
        "..",
        "../outside",
        "a/b",
        outside.to_str().unwrap(),
        "",
        ".",
        "./present",
        "a/..",
        "/",
    ] {
        assert_eq!(
            directory.exists(name).unwrap_err().to_string(),
            "invalid path component",
            "{name:?}"
        );
    }
    for name in ["present", "a", "link", "dangling"] {
        assert!(directory.exists(name).unwrap(), "{name}");
    }
    assert!(!directory.exists("absent").unwrap());
    assert_eq!(fs::read(&outside).unwrap(), b"outside bytes");
    assert_eq!(fs::read(path.join("present")).unwrap(), b"inside bytes");
    assert_eq!(fs::read(path.join("a/b")).unwrap(), b"nested bytes");
    assert_eq!(fs::read_link(path.join("link")).unwrap(), outside);
    assert_eq!(
        fs::read_link(path.join("dangling")).unwrap(),
        temp.path().join("missing")
    );
    assert!(!temp.path().join("missing").exists());
}

#[test]
fn authoritative_files_with_other_hardlinks_remain_refused() {
    for name in [".lock", "manifest.json", ".manifest.tmp", "raw", "segments"] {
        let temp = temporary();
        let path = temp.path().join("corpus");
        let mut corpus = Writer::open(&path, configuration(&["q"])).unwrap();
        let attempt = reserve(&mut corpus, 0);
        let key = ingest(&mut corpus, attempt, &raw(true));
        finish(&mut corpus, attempt);
        let segment = corpus.state().head.clone().unwrap();
        drop(corpus);
        let file = match name {
            "raw" => path.join("raw").join(key),
            "segments" => path.join("segments").join(segment),
            _ => path.join(name),
        };
        if name == ".manifest.tmp" {
            fs::write(&file, b"retained staging bytes").unwrap();
        }
        let before = fs::read(&file).unwrap();
        let alias = temp.path().join("alias");
        fs::hard_link(&file, &alias).unwrap();
        let result = match name {
            ".lock" | "manifest.json" | "segments" => {
                Writer::open(&path, configuration(&["q"])).map(|_| ())
            }
            ".manifest.tmp" => Writer::open(&path, configuration(&["q"]))
                .unwrap()
                .publish(),
            "raw" => Corpus::open(&path).unwrap().verify(),
            _ => unreachable!(),
        };
        assert!(result.is_err(), "{name}");
        assert_eq!(fs::read(&alias).unwrap(), before);
        assert_eq!(fs::read(&file).unwrap(), before);
    }
    let temp = temporary();
    let directory = voidport_lkml::storage::Directory::open(temp.path()).unwrap();
    fs::write(temp.path().join("query.stdout"), b"do not overwrite").unwrap();
    fs::hard_link(temp.path().join("query.stdout"), temp.path().join("alias")).unwrap();
    assert!(
        directory
            .file("query.stdout", rustix::fs::OFlags::WRONLY)
            .is_err()
    );
    assert_eq!(
        fs::read(temp.path().join("alias")).unwrap(),
        b"do not overwrite"
    );
}

#[test]
fn verify_recomputes_every_derivative_and_never_repairs() {
    let temp = temporary();
    let path = temp.path().join("corpus");
    let mut corpus = Writer::open(&path, configuration(&["q"])).unwrap();
    let attempt = reserve(&mut corpus, 0);
    let parent = ingest(&mut corpus, attempt, &raw(true));
    let child = ingest(&mut corpus, attempt, &raw(false));
    finish(&mut corpus, attempt);
    let original = corpus.state().clone();
    drop(corpus);
    for mutation in 0..9 {
        let mut changed = original.clone();
        let records = &mut changed.records;
        match mutation {
            0 => records.artifacts.get_mut(&child).unwrap().metadata.class = Class::Context,
            1 => records.links.message_ids.clear(),
            2 => records
                .links
                .relationships
                .get_mut(&child)
                .unwrap()
                .targets
                .clear(),
            3 => {
                records.observations[0].source =
                    Source::try_from("https://lore.kernel.org/linux-fsdevel/".to_owned()).unwrap();
            }
            4 => records.artifacts.get_mut(&child).unwrap().path = "../outside".into(),
            5 => records
                .artifacts
                .get_mut(&child)
                .unwrap()
                .metadata
                .text
                .clear(),
            6 => records.attempts[0].deliveries[0].filename_hex = hex::encode("../escape"),
            7 => {
                records.observations[0].archive_link =
                    Some("https://lore.kernel.org/lkml//parent@example.invalid/".into())
            }
            8 => {
                let thread = records.links.threads.values_mut().next().unwrap();
                thread.roots.clear();
            }
            _ => unreachable!(),
        }
        let bytes = rewrite(&path, &changed);
        let verified = Corpus::open(&path).and_then(|c| c.verify());
        assert!(verified.is_err(), "mutation {mutation}");
        assert_eq!(fs::read(path.join("manifest.json")).unwrap(), bytes);
    }
    rewrite(&path, &original);
    for replacement in [Some(b"modified".as_slice()), None] {
        let blob = path.join("raw").join(&parent);
        if let Some(bytes) = replacement {
            fs::write(&blob, bytes).unwrap();
        } else {
            fs::remove_file(&blob).unwrap();
        }
        assert!(Corpus::open(&path).unwrap().verify().is_err());
        if replacement.is_none() {
            assert!(!blob.exists());
        }
    }
    fs::write(path.join("raw").join(&parent), raw(true)).unwrap();
    let blob = path.join("raw").join(&child);
    fs::remove_file(&blob).unwrap();
    let outside = temp.path().join("outside");
    fs::write(&outside, raw(false)).unwrap();
    symlink(&outside, &blob).unwrap();
    assert!(Corpus::open(&path).unwrap().verify().is_err());
    assert_eq!(fs::read(outside).unwrap(), raw(false));
}

fn segment(path: &Path, name: &str) -> Segment {
    serde_json::from_slice(&fs::read(path.join("segments").join(name)).unwrap()).unwrap()
}
fn chain(path: &Path) -> Vec<Segment> {
    let root: Root =
        serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
    let mut segments = Vec::new();
    let mut next = Some(root.head);
    while let Some(name) = next {
        let segment = segment(path, &name);
        next = segment.previous.clone();
        segments.push(segment);
    }
    segments.reverse();
    segments
}

#[test]
fn each_publication_writes_only_the_records_it_adds() {
    let temp = temporary();
    let path = temp.path().join("corpus");
    let mut corpus = Writer::open(&path, configuration(&["first", "second"])).unwrap();
    let first = reserve(&mut corpus, 0);
    let child = ingest(&mut corpus, first, &raw(false));
    finish(&mut corpus, first);
    let second = reserve(&mut corpus, 1);
    let parent = ingest(&mut corpus, second, &raw(true));
    finish(&mut corpus, second);
    let state = corpus.state().clone();
    drop(corpus);
    let segments = chain(&path);
    let generations: Vec<_> = segments.iter().map(|segment| segment.generation).collect();
    assert_eq!(generations, [1, 2, 3, 4, 5]);
    assert_eq!(segments[0].records, Records::default());
    for (index, published) in segments[1..].iter().enumerate() {
        let ids: Vec<_> = published
            .records
            .attempts
            .iter()
            .map(|attempt| attempt.id)
            .collect();
        assert_eq!(ids, [u64::try_from(index / 2 + 1).unwrap()]);
    }
    assert_eq!(segments[4].records.attempts[0], state.records.attempts[1]);
    for reservation in [&segments[1], &segments[3]] {
        assert!(reservation.records.artifacts.is_empty());
        assert!(reservation.records.observations.is_empty());
        assert_eq!(reservation.records.links, Links::default());
    }
    for (finished, digest) in [(&segments[2], &child), (&segments[4], &parent)] {
        assert_eq!(
            finished.records.artifacts.keys().collect::<Vec<_>>(),
            [digest]
        );
        assert_eq!(finished.records.observations.len(), 1);
    }
    let links = &segments[4].records.links;
    assert_eq!(
        links.message_ids.keys().collect::<Vec<_>>(),
        ["parent@example.invalid"]
    );
    assert_eq!(links.relationships.keys().collect::<Vec<_>>(), [&child]);
    assert_eq!(
        links.relationships[&child].targets,
        std::slice::from_ref(&parent)
    );
    let threads: Vec<_> = links.threads.values().collect();
    assert_eq!(threads.len(), 1);
    assert_eq!(
        threads[0].members,
        [child.clone(), parent.clone()].into_iter().collect()
    );
    let reader = Corpus::open(&path).unwrap();
    assert_eq!(reader.state(), &state);
    reader.verify().unwrap();
}

#[test]
fn segments_must_match_their_names_and_unlisted_ones_are_partial() {
    let temp = temporary();
    let path = temp.path().join("corpus");
    let mut corpus = Writer::open(&path, configuration(&["q"])).unwrap();
    let attempt = reserve(&mut corpus, 0);
    let _parent = ingest(&mut corpus, attempt, &raw(true));
    finish(&mut corpus, attempt);
    let head = corpus.state().head.clone().unwrap();
    let listed = path.join("segments").join(&head);
    drop(corpus);
    let unlisted = digest(b"unlisted");
    fs::write(path.join("segments").join(&unlisted), b"unlisted").unwrap();
    let reader = Corpus::open(&path).unwrap();
    assert_eq!(
        reader.inventory().unwrap().0,
        [format!("segments/{unlisted}")]
    );
    reader.verify().unwrap();
    drop(reader);
    let root_path = path.join("manifest.json");
    let published_root = fs::read(&root_path).unwrap();
    let root: Root = serde_json::from_slice(&published_root).unwrap();
    let earlier = segment(&path, &head).previous.unwrap();
    let refused = |changed_head: String| {
        let changed = Root {
            head: changed_head,
            ..root.clone()
        }
        .encode()
        .unwrap();
        fs::write(&root_path, &changed).unwrap();
        let error = Corpus::open(&path)
            .err()
            .expect("a root naming another segment was read");
        assert_eq!(fs::read(&root_path).unwrap(), changed);
        error
    };
    let error = refused(earlier);
    assert!(
        matches!(error, StorageError::SegmentOrder { .. }),
        "{error}"
    );
    let error = refused("not-a-digest".into());
    assert!(matches!(error, StorageError::SegmentName { .. }), "{error}");
    fs::write(&root_path, &published_root).unwrap();
    let mut changed = fs::read(&listed).unwrap();
    changed.push(b' ');
    fs::write(&listed, &changed).unwrap();
    for writable in [false, true] {
        let error = if writable {
            Writer::open(&path, configuration(&["q"])).err()
        } else {
            Corpus::open(&path).err()
        }
        .expect("a changed segment was read");
        assert!(
            matches!(error, StorageError::SegmentIntegrity { .. }),
            "{error}"
        );
        assert_eq!(fs::read(&listed).unwrap(), changed);
    }
    fs::remove_file(&listed).unwrap();
    let error = Corpus::open(&path)
        .err()
        .expect("a corpus without its head segment was read");
    assert!(matches!(error, StorageError::SegmentRead { .. }), "{error}");
    assert!(!listed.exists());
}
