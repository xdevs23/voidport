#![forbid(unsafe_code)]

use voidport_test_client as support;

use std::fs;
use std::path::Path;

use support::{Fixture, preflight};

const BUDGET: usize = 64;

const DEPTH: u32 = 3;
const FANOUT: usize = 4;
const FILES_PER_DIR: usize = 8;

#[test]
fn a_source_tree_walk_far_past_the_budget_never_exhausts_the_server() {
    preflight();
    let fixture = Fixture::start_with(
        "walk-budget",
        &format!("node_descriptor_budget = {BUDGET}\n"),
    );
    let expected = build_tree(&fixture.host("tree/src"), DEPTH);
    assert!(
        expected > BUDGET * 10,
        "the tree must be big enough to walk: {expected} entries against a budget of {BUDGET}"
    );

    let guest = fixture.mount("walk", "plain", "/tree");

    let seen = walk_tree(&guest.path("src")).expect("the walk completes");
    assert_eq!(seen, expected, "the walk saw a different tree than exists");

    // What the server says it is holding, through the operator CLI: the one
    // view that can tell a node's cache slot from a handle's descriptor.
    let info = fixture.expect_ctl(&["info"]);
    let cache = info
        .lines()
        .find_map(|line| line.strip_prefix("node fd cache:"))
        .expect("server info reports the descriptor cache");
    let (resident, budget) = cache.split_once('/').expect("a count and a bound");
    let resident: usize = resident.trim().parse().expect("a count");
    let budget: usize = budget.trim().parse().expect("a bound");
    assert_eq!(budget, BUDGET);
    assert!(
        resident <= budget,
        "{resident} cache-resident descriptors past a budget of {budget}"
    );

    let second = walk_tree(&guest.path("src")).expect("the walk repeats");
    assert_eq!(second, expected);
    let sample = guest.path("src/file-0");
    assert_eq!(fs::read(&sample).expect("readable"), b"x".to_vec());
    fs::write(&sample, b"y").expect("writable");
    assert_eq!(fs::read(&sample).expect("readable"), b"y".to_vec());
}

fn build_tree(root: &Path, depth: u32) -> usize {
    fs::create_dir_all(root).expect("a creatable directory");
    let mut entries = 0;
    for index in 0..FILES_PER_DIR {
        fs::write(root.join(format!("file-{index}")), b"x").expect("a writable file");
        entries += 1;
    }
    if depth > 0 {
        for index in 0..FANOUT {
            entries += 1 + build_tree(&root.join(format!("dir-{index}")), depth - 1);
        }
    }
    entries
}

fn walk_tree(root: &Path) -> std::io::Result<usize> {
    let mut seen = 0;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            seen += 1;
            if metadata.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(seen)
}
