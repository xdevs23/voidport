use crate::{collector::*, faulty_filesystem::FaultyFilesystem};

#[test]
#[ignore = "needs /dev/fuse and runs under tests/filesystem-check"]
fn a_collector_run_writes_each_published_file_with_one_request() {
    let mut fixture = Fixture::new();
    let backing = fixture.temp.path().join("backing");
    let filesystem = FaultyFilesystem::mount(&backing, &fixture.output);
    success(&fixture.collect(&["pair"], &[]));
    let published = filesystem.published_files();
    filesystem.unmount();
    fixture.output = backing;
    let state = fixture.state();
    let roots = published
        .iter()
        .filter(|(name, _)| name == "manifest.json")
        .count();
    assert_eq!(u64::try_from(roots).unwrap(), state.generation);
    assert_eq!(
        published.len(),
        2 * roots + state.records.artifacts.len(),
        "{published:?}"
    );
    assert!(
        published.iter().all(|(_, requests)| *requests == 1),
        "{published:?}"
    );
}
