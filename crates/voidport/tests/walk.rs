//! The build-shaped workload, end to end: a real FUSE mount, a real tree walk,
//! and a server whose node descriptor cache is far too small to hold it.
//!
//! Descriptor-budget criterion **10**. The field failure this proves gone was
//! an AOSP build over voidport mounts: soong's module finder walked the source
//! tree, every name it resolved cost the server one `O_PATH` descriptor for as
//! long as the guest kernel remembered it, and the walk ended in thousands of
//! `readdirent: too many open files` and `open ...: too many open files`. The
//! same walk on the host, or through a bind mount, costs nothing — a dentry
//! cache is not a process's descriptor table.
//!
//! So this walks a tree of far more names than the server may hold descriptors
//! for, through the kernel, and requires every single operation to succeed. The
//! budget is configured tiny instead of the tree made huge, because the ratio
//! is what matters and a suite has to stay fast.

mod support;

use std::fs;
use std::path::Path;

use support::{Fixture, preflight};

/// The cache-resident descriptor bound the server runs under here.
const BUDGET: usize = 64;

/// The tree's shape. It holds 764 entries — nearly twelve times the budget —
/// and every one of them is a name the walk resolves.
const DEPTH: u32 = 3;
const FANOUT: usize = 4;
const FILES_PER_DIR: usize = 8;

/// A walk that resolves twelve times the budget in names finishes with no
/// errors at all, and the server's cache stays inside its bound throughout.
#[test]
fn a_source_tree_walk_far_past_the_budget_never_exhausts_the_server() {
    if !preflight() {
        return;
    }
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

    // The walk itself. `walk_tree` propagates the first error it meets, and
    // `EMFILE` is what it used to meet.
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

    // And the mount is still fully usable afterwards — an exhausted descriptor
    // table would have taken the next open down with it.
    let second = walk_tree(&guest.path("src")).expect("the walk repeats");
    assert_eq!(second, expected);
    let sample = guest.path("src/file-0");
    assert_eq!(fs::read(&sample).expect("readable"), b"x".to_vec());
    fs::write(&sample, b"y").expect("writable");
    assert_eq!(fs::read(&sample).expect("readable"), b"y".to_vec());
}

/// Builds a tree `depth` levels deep and reports how many entries it holds
/// below `root`, `root` itself excluded.
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

/// Lists a tree and stats every entry, exactly as a source-tree scan does.
///
/// Every error is propagated, not counted: the criterion is *zero*
/// errors, so the first one is the answer.
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
