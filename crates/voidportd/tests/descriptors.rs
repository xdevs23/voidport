//! The node descriptor budget: eviction, identity-verified re-pinning, and what
//! a guest sees while both happen underneath it.
//!
//! The failure this suite exists for was a field failure: a node pinned one
//! `O_PATH` descriptor for its whole life, a guest kernel under no memory
//! pressure never forgot a node, and an AOSP-scale walk exhausted the server's
//! descriptor table — after which every host open answered `EMFILE`. The budget
//! makes the descriptor a cache slot, and these are the acceptance criteria of
//! that change, driven over a real socket against a real server.
//!
//! The budget is set absurdly small here (`node_descriptor_budget = 32`, just
//! above the floor) so that a suite that has to stay fast still crosses it many
//! times over: what matters is the *ratio* between names resolved and slots
//! available, not the absolute numbers.

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use support::Dial as _;
use support::TempDir;
use support::fixture::Fixture;
use support::wire::{ROOT, WireClient, status};
use voidport_control::{NamespaceName, NamespaceSpec, Reply, Request, Rule, ShareMode};
use voidport_proto::ops::dir::rename_flags::EXCHANGE as RENAME_EXCHANGE;
use voidportd::testing::create_directory;

/// The budget every test here runs the server under.
const BUDGET: usize = 32;

/// The `[server]` setting that configures it.
const BUDGET_SETTING: &str = "node_descriptor_budget = 32\n";

/// `O_RDWR`, as the guest sends it.
const O_RDWR: u32 = 2;

/// A fixture whose server holds at most [`BUDGET`] node descriptors.
fn budgeted(label: &str) -> Fixture {
    Fixture::start_with(label, BUDGET_SETTING)
}

/// The server's own view of its descriptor cache: what it holds, and its bound.
///
/// Read through the control plane, which is the only view that can attribute a
/// descriptor to the node cache, not to a handle or a graft.
fn cache(fixture: &Fixture) -> (usize, usize) {
    let Reply::ServerInfo {
        node_descriptors,
        node_descriptor_budget,
        ..
    } = fixture.server.connect().expect_ok(&Request::ServerInfo {})
    else {
        panic!("expected server info");
    };
    (node_descriptors, node_descriptor_budget)
}

/// How many of this process's descriptors point anywhere inside `root`.
///
/// The server runs in the test's own process, so `/proc/self/fd` **is** the
/// server's descriptor table. This is the cross-check the criterion asks for:
/// the kernel's count of descriptors into the shared tree, against the count
/// the server publishes.
fn descriptors_into(root: &Path) -> usize {
    let Ok(entries) = fs::read_dir("/proc/self/fd") else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| fs::read_link(entry.path()).is_ok_and(|target| target.starts_with(root)))
        .count()
}

/// Builds `count` files under `directory`, named `entry-<n>`.
fn populate(directory: &Path, count: usize) -> Vec<String> {
    create_directory(directory);
    (0..count)
        .map(|index| {
            let name = format!("entry-{index:04}");
            fs::write(directory.join(&name), format!("{index}").as_bytes()).expect("writable");
            name
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Criteria 1, 2 and 10 — a walk far past the budget
// ---------------------------------------------------------------------------

/// A walk resolving ten times the budget in names completes with **zero**
/// errors, the cache never exceeds its bound while it runs, and the node table
/// grows past the bound freely.
///
/// This is the build-shaped workload that used to end in `EMFILE`: every name
/// is resolved, nothing is forgotten, and the guest keeps every node. What has
/// changed is that the descriptors behind those nodes are a cache now, so the
/// walk finishes instead of exhausting the table (criteria 1, 2 and 10).
#[test]
fn a_walk_ten_times_the_budget_in_names_completes_without_a_single_error() {
    let fixture = budgeted("walk-budget");
    let names = populate(&fixture.tree("walk"), BUDGET * 10);
    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client.hello("plain", "/tree").expect("the mount resolves");
    let directory = client.lookup(ROOT, "walk").expect("the directory resolves");

    let mut resolved = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let entry = client
            .lookup(directory.node_id, name)
            .unwrap_or_else(|status| panic!("{name} failed with {status}"));
        // A getattr through the node id, which is the operation that used to
        // need a descriptor the process no longer had.
        client
            .getattr(entry.node_id)
            .unwrap_or_else(|status| panic!("{name} attributes failed with {status}"));
        resolved.push(entry.node_id);

        // Sampled as the walk runs, not only at the end: the bound is
        // continuous.
        if index % 25 == 0 {
            let (resident, budget) = cache(&fixture);
            assert_eq!(budget, BUDGET);
            assert!(
                resident <= budget,
                "{resident} resident descriptors past a budget of {budget}"
            );
        }
    }

    let (resident, budget) = cache(&fixture);
    assert!(resident <= budget, "{resident} > {budget}");

    // Table entries are *not* bounded by it: `max_nodes` is unconfigured, so
    // the session holds a node per name it ever resolved.
    let Reply::SessionList { sessions } =
        fixture.server.connect().expect_ok(&Request::SessionList {})
    else {
        panic!("expected a session list");
    };
    let nodes = sessions.iter().map(|session| session.nodes).sum::<usize>();
    assert!(
        nodes > BUDGET * 5,
        "the node table should hold every name walked, not {nodes}"
    );

    // The one-time cross-check: what the kernel says this process holds into
    // the shared tree cannot exceed what the cache admits plus the handful of
    // graft pins and in-flight descriptors around it.
    let into_tree = descriptors_into(fixture.graft_root());
    assert!(
        into_tree <= BUDGET + 64,
        "{into_tree} descriptors into the tree against a budget of {BUDGET}"
    );

    // And every node the walk resolved still answers, in the order it was
    // resolved — which is the order the cache evicted them in.
    for node in &resolved {
        assert!(client.getattr(*node).is_ok(), "node {node} stopped working");
    }
}

// ---------------------------------------------------------------------------
// Criterion 3 — an evicted node answers exactly as a resident one
// ---------------------------------------------------------------------------

/// Attribute correctness across an evict-and-re-pin cycle.
#[test]
fn an_evicted_node_answers_metadata_identically_to_a_resident_one() {
    let fixture = budgeted("evict-attr");
    fs::write(fixture.tree("subject"), b"0123456789").expect("writable");
    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client.hello("plain", "/tree").expect("the mount resolves");

    let subject = client.lookup(ROOT, "subject").expect("resolves");
    let before = client.getattr(subject.node_id).expect("resident");

    // Push it out of the cache by resolving many other names.
    let names = populate(&fixture.tree("filler"), BUDGET * 3);
    let filler = client.lookup(ROOT, "filler").expect("resolves");
    for name in &names {
        client.lookup(filler.node_id, name).expect("resolves");
    }

    let after = client
        .getattr(subject.node_id)
        .expect("re-pins and answers");
    assert_eq!(
        after, before,
        "an evicted node must present exactly what a resident one did"
    );
    assert_eq!(after.size.get(), 10);
}

// ---------------------------------------------------------------------------
// Criterion 4 — identity, for files and for directories
// ---------------------------------------------------------------------------

/// After eviction, an external unlink-and-recreate at the same path answers
/// `ESTALE` to the old node id — for a file **and** for a directory — and the
/// new file's content is never served through the old id, while the *path*
/// heals.
///
/// The two halves are one rule: the node holding a key whose entry was replaced
/// is retired, so its id stays honestly stale and its key is free for the node
/// the next resolution mints. Without the retirement the dead node holds the
/// key and a fresh lookup answers `ESTALE` forever — the path-addressed retry
/// the design promises could never succeed.
///
/// The tmpfs arm. The ext4 arm, where `(dev, ino)` reuse is immediate, is
/// [`an_ext4_recreate_never_serves_the_impostor`].
#[test]
fn an_externally_recreated_entry_answers_stale_to_the_old_node_id() {
    let fixture = budgeted("identity");
    fs::write(fixture.tree("victim"), b"original").expect("writable");
    create_directory(&fixture.tree("victim-dir"));
    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client.hello("plain", "/tree").expect("the mount resolves");

    let file = client.lookup(ROOT, "victim").expect("resolves");
    let directory = client.lookup(ROOT, "victim-dir").expect("resolves");
    evict_everything(&fixture, &mut client, ROOT);

    // The host replaces both, behind the server's back.
    fs::remove_file(fixture.tree("victim")).expect("removable");
    fs::write(fixture.tree("victim"), b"impostor!").expect("writable");
    fs::remove_dir(fixture.tree("victim-dir")).expect("removable");
    create_directory(&fixture.tree("victim-dir"));

    assert_eq!(
        client.getattr(file.node_id).expect_err("a different file"),
        status::STALE
    );
    assert_eq!(
        client
            .getattr(directory.node_id)
            .expect_err("a different directory"),
        status::STALE,
        "directories record an identity too"
    );
    // Not one byte of the impostor is reachable through the old id.
    assert_eq!(
        client.open(file.node_id, O_RDWR).expect_err("stale"),
        status::STALE
    );
    // A fresh lookup of the same name resolves the new file, as it must.
    let fresh = client.lookup(ROOT, "victim").expect("the name resolves");
    assert_ne!(fresh.node_id, file.node_id);
    let handle = client.open(fresh.node_id, O_RDWR).expect("opens");
    assert_eq!(
        client.read(handle, 0, 64).expect("reads"),
        b"impostor!".to_vec()
    );

    // And the directory heals the same way, which is the harder half: a
    // directory is keyed by its namespace path, so the replacement lands on the
    // very key the stale node holds.
    let fresh_directory = client
        .lookup(ROOT, "victim-dir")
        .expect("the directory's name resolves");
    assert_ne!(fresh_directory.node_id, directory.node_id);
    assert!(client.getattr(fresh_directory.node_id).is_ok());
    assert_eq!(
        client
            .getattr(directory.node_id)
            .expect_err("the retired node names nothing"),
        status::STALE
    );
}

/// The same, on an **ext4** filesystem — where the probe measured `(dev, ino)`
/// coming straight back on the first recreate, 20000 of 20000 times.
///
/// Only the recorded birth time stands between the old node id and the
/// impostor's bytes here, so this is the arm that proves the identity record is
/// more than `(dev, ino, kind)`.
#[test]
fn an_ext4_recreate_never_serves_the_impostor() {
    let Some(image) = Ext4Image::create("ext4-identity", 64) else {
        return;
    };
    let fixture = Fixture::start_with_graft("ext4-identity", BUDGET_SETTING, image.mounted());
    fs::write(image.mounted().join("victim"), b"original").expect("writable");
    create_directory(&image.mounted().join("victim-dir"));

    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client.hello("plain", "/tree").expect("the mount resolves");
    let file = client.lookup(ROOT, "victim").expect("resolves");
    let directory = client.lookup(ROOT, "victim-dir").expect("resolves");
    let recorded = client.getattr(file.node_id).expect("resident");

    evict_everything(&fixture, &mut client, ROOT);

    let host_before = fs::metadata(image.mounted().join("victim")).expect("stattable");
    fs::remove_file(image.mounted().join("victim")).expect("removable");
    fs::write(image.mounted().join("victim"), b"impostor!").expect("writable");
    fs::remove_dir(image.mounted().join("victim-dir")).expect("removable");
    create_directory(&image.mounted().join("victim-dir"));
    let host_after = fs::metadata(image.mounted().join("victim")).expect("stattable");

    // The premise of the whole check, asserted, not assumed.
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(
        (host_before.dev(), host_before.ino()),
        (host_after.dev(), host_after.ino()),
        "ext4 was expected to reuse the inode immediately; without that this \
         test proves nothing"
    );

    assert_eq!(
        client.getattr(file.node_id).expect_err("a different file"),
        status::STALE,
        "the old node id served the impostor: identity is (dev, ino) only"
    );
    assert_eq!(
        client
            .getattr(directory.node_id)
            .expect_err("a different directory"),
        status::STALE
    );
    assert_eq!(
        client.open(file.node_id, O_RDWR).expect_err("stale"),
        status::STALE
    );
    assert_eq!(recorded.size.get(), 8, "the original was eight bytes");

    // The path heals, on the filesystem where healing is hardest: the recreated
    // file carries the *same* `(dev, ino)` as the node that was stale a moment
    // ago, so its key is occupied and only retiring that node can free it.
    let fresh = client.lookup(ROOT, "victim").expect("the name resolves");
    assert_ne!(fresh.node_id, file.node_id);
    let handle = client.open(fresh.node_id, O_RDWR).expect("opens");
    assert_eq!(
        client.read(handle, 0, 64).expect("reads"),
        b"impostor!".to_vec()
    );
    let fresh_directory = client
        .lookup(ROOT, "victim-dir")
        .expect("the directory's name resolves");
    assert_ne!(fresh_directory.node_id, directory.node_id);
    assert!(client.getattr(fresh_directory.node_id).is_ok());

    // And the retired ids stay honest afterwards.
    assert_eq!(
        client.getattr(file.node_id).expect_err("retired"),
        status::STALE
    );
    assert_eq!(
        client.getattr(directory.node_id).expect_err("retired"),
        status::STALE
    );
}

// ---------------------------------------------------------------------------
// Criterion 5 — open handles are untouched by budget pressure
// ---------------------------------------------------------------------------

/// A file opened, its node evicted, then read and written through its handle
/// behaves exactly as before: the handle retains the node's pin, which is the
/// accounting's handle-retained term.
#[test]
fn an_open_handle_survives_its_nodes_eviction() {
    let fixture = budgeted("handle-survives");
    fs::write(fixture.tree("open-me"), b"0123456789").expect("writable");
    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client.hello("plain", "/tree").expect("the mount resolves");

    let node = client.lookup(ROOT, "open-me").expect("resolves");
    let handle = client.open(node.node_id, O_RDWR).expect("opens");
    evict_everything(&fixture, &mut client, ROOT);

    assert_eq!(
        client.read(handle, 0, 5).expect("reads through the handle"),
        b"01234".to_vec()
    );
    assert_eq!(client.write(handle, 0, b"ABCDE").expect("writes"), 5);
    assert_eq!(
        client.read(handle, 0, 10).expect("reads"),
        b"ABCDE56789".to_vec()
    );
    // Even after the host removes the name — the handle holds the inode.
    fs::remove_file(fixture.tree("open-me")).expect("removable");
    assert_eq!(
        client.read(handle, 0, 5).expect("still reads"),
        b"ABCDE".to_vec()
    );
    client.release(handle).expect("releases");
}

// ---------------------------------------------------------------------------
// Criterion 6 — live reconfiguration
// ---------------------------------------------------------------------------

/// A rule removed at the control plane drops its graft pin, so an evicted node
/// beneath it answers `ESTALE` on its next node-addressed use.
///
/// The namespace is built for this test, not taken from the fixture, and
/// that is the point, not convenience: the fixture's `plain` namespace
/// grafts one host directory under *two* rules, so removing one of them leaves
/// the graft pinned by the other — and a graft still pinned is a node that
/// still re-pins, correctly. What this criterion is about is the graft going
/// away, which needs a rule that is the only one holding it.
#[test]
fn a_removed_rule_stales_the_evicted_nodes_beneath_it() {
    let fixture = budgeted("rule-removed");
    let target = fixture.tree("solo");
    populate(&target, 1);
    let namespace = NamespaceName::new("solo").expect("valid");
    let mut control = fixture.server.connect();
    control.expect_ok(&Request::NamespaceCreate {
        namespace: NamespaceSpec::new(namespace.clone()),
    });
    control.expect_ok(&Request::RuleAdd {
        namespace: namespace.clone(),
        rule: Rule::new("/solo", ShareMode::Rw)
            .with_target(target.to_str().expect("a utf-8 path").to_owned()),
    });

    let mut client = fixture.server.mount("solo", "/solo");
    let node = client.lookup(ROOT, "entry-0000").expect("resolves");
    assert!(client.getattr(node.node_id).is_ok());

    // Evicted through another session entirely: the budget is server-global, so
    // one mount's churn is what takes the other's slots.
    let mut churn = fixture.server.mount("plain", "/tree");
    evict_everything(&fixture, &mut churn, ROOT);

    control.expect_ok(&Request::RuleRemove {
        namespace,
        path: "/solo".to_owned(),
        r#match: None,
    });

    assert_eq!(
        client
            .getattr(node.node_id)
            .expect_err("the graft it lived under is gone"),
        status::STALE
    );
}

// ---------------------------------------------------------------------------
// Criterion 7 — the server never stales what it moved itself
// ---------------------------------------------------------------------------

/// Files and a populated directory renamed *through the mount*, then evicted,
/// then used again — without one spurious `ESTALE`, descendants included.
#[test]
fn a_rename_through_the_mount_never_stales_what_it_moved() {
    let fixture = budgeted("rename-rebind");
    let inside = fixture.tree("movable");
    let names = populate(&inside, 8);
    fs::write(fixture.tree("loose"), b"loose").expect("writable");

    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client.hello("plain", "/tree").expect("the mount resolves");

    // Resolve the directory, its children, and a loose file.
    let directory = client.lookup(ROOT, "movable").expect("resolves");
    let children: Vec<u64> = names
        .iter()
        .map(|name| {
            client
                .lookup(directory.node_id, name)
                .expect("resolves")
                .node_id
        })
        .collect();
    let loose = client.lookup(ROOT, "loose").expect("resolves");

    // The guest moves both, through the mount.
    client
        .rename(ROOT, "movable", ROOT, "moved")
        .expect("the directory renames");
    client
        .rename(ROOT, "loose", ROOT, "relocated")
        .expect("the file renames");

    evict_everything(&fixture, &mut client, ROOT);

    // Every node the rename moved still answers, the renamed directory's
    // descendants above all: the rename rewrote the host path each of them
    // records, which ran through the name that changed.
    assert!(
        client.getattr(directory.node_id).is_ok(),
        "the renamed directory staled"
    );
    assert!(
        client.getattr(loose.node_id).is_ok(),
        "the renamed file staled"
    );
    for (name, child) in names.iter().zip(&children) {
        assert!(
            client.getattr(*child).is_ok(),
            "{name}, a descendant of the renamed directory, staled"
        );
    }
    // And the host really did move them.
    assert!(fixture.tree("moved").is_dir());
    assert!(fixture.tree("relocated").is_file());
}

/// An entry created *inside* a directory the mount has already renamed records
/// where the host really has it, not where the namespace still says it is.
///
/// The guest keeps using the node id it holds, and that node still carries the
/// namespace path it was resolved at — the server does not rename its own
/// nodes. So the namespace describes the new entry under the directory's old
/// name, and only the directory's own recorded path knows where the entry
/// actually landed. The eviction is what makes the difference visible: a
/// resident pin answers from its descriptor whatever it recorded.
#[test]
fn an_entry_created_under_a_renamed_directory_records_where_it_landed() {
    let fixture = budgeted("create-under-renamed");
    create_directory(&fixture.tree("holder"));
    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client.hello("plain", "/tree").expect("the mount resolves");
    let directory = client.lookup(ROOT, "holder").expect("resolves");

    client
        .rename(ROOT, "holder", ROOT, "holder-moved")
        .expect("the directory renames");
    // Through the node id the guest still holds, whose namespace path is the
    // name that is gone.
    let made = client
        .mkdir(directory.node_id, "made", 0o755)
        .expect("creates under the renamed directory");
    let (created, handle) = client
        .create(directory.node_id, "file", O_RDWR, 0o644)
        .expect("creates a file under it too");
    client.release(handle).expect("releases");
    assert!(fixture.tree("holder-moved").join("made").is_dir());

    evict_everything(&fixture, &mut client, ROOT);
    assert!(
        client.getattr(made.node_id).is_ok(),
        "the created directory recorded the name the namespace shows, not the host's"
    );
    assert!(client.getattr(created.node_id).is_ok());
}

/// "The affected nodes" is **every session's**: a rename through one mount must
/// not stale another mount's nodes for the entry it moved.
///
/// Two mounts of the same namespace, one renaming and one merely holding. The
/// watcher never learns of the move — it has no reason to look the names up
/// again — so what keeps it working is the rename reaching into its table.
#[test]
fn a_rename_through_one_mount_never_stales_another_mounts_nodes() {
    let fixture = budgeted("rename-cross-session");
    let names = populate(&fixture.tree("shared-dir"), 4);
    fs::write(fixture.tree("shared-file"), b"shared").expect("writable");

    let mut mover = fixture.server.mount("plain", "/tree");
    let mut watcher = fixture.server.mount("plain", "/tree");

    // The watcher resolves everything first: these are the nodes at stake.
    let directory = watcher.lookup(ROOT, "shared-dir").expect("resolves");
    let child = watcher
        .lookup(directory.node_id, &names[0])
        .expect("resolves");
    let file = watcher.lookup(ROOT, "shared-file").expect("resolves");

    // The other mount moves both.
    mover
        .rename(ROOT, "shared-dir", ROOT, "moved-dir")
        .expect("the directory renames");
    mover
        .rename(ROOT, "shared-file", ROOT, "moved-file")
        .expect("the file renames");

    evict_everything(&fixture, &mut mover, ROOT);

    assert!(
        watcher.getattr(file.node_id).is_ok(),
        "another mount's node for the renamed file staled"
    );
    assert!(
        watcher.getattr(directory.node_id).is_ok(),
        "another mount's node for the renamed directory staled"
    );
    assert!(
        watcher.getattr(child.node_id).is_ok(),
        "a descendant held by another mount staled"
    );
}

/// One host directory grafted at two namespace paths is two nodes, and a rename
/// through one of them moves both.
///
/// The `plain` namespace grafts the fixture's tree twice — read-write at `/tree`
/// and read-only at `/readonly` — so a mount of the whole namespace holds two
/// nodes for every directory in it. The rename goes through the writable name;
/// the read-only alias must follow it, and must stay read-only.
#[test]
fn a_rename_moves_every_namespace_alias_of_the_entry() {
    let fixture = budgeted("rename-alias");
    let names = populate(&fixture.tree("aliased"), 4);
    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client
        .hello("plain", "/")
        .expect("the whole namespace mounts");

    let writable_tree = client.lookup(ROOT, "tree").expect("resolves");
    let readonly_tree = client.lookup(ROOT, "readonly").expect("resolves");
    let writable = client
        .lookup(writable_tree.node_id, "aliased")
        .expect("resolves");
    let readonly = client
        .lookup(readonly_tree.node_id, "aliased")
        .expect("resolves");
    assert_ne!(
        writable.node_id, readonly.node_id,
        "two namespace paths onto one host directory are two nodes"
    );
    let under_alias = client
        .lookup(readonly.node_id, &names[0])
        .expect("resolves");

    client
        .rename(
            writable_tree.node_id,
            "aliased",
            writable_tree.node_id,
            "renamed",
        )
        .expect("the directory renames");
    evict_everything(&fixture, &mut client, writable_tree.node_id);

    assert!(
        client.getattr(writable.node_id).is_ok(),
        "the node the rename went through staled"
    );
    assert!(
        client.getattr(readonly.node_id).is_ok(),
        "the read-only alias of the renamed directory staled"
    );
    assert!(
        client.getattr(under_alias.node_id).is_ok(),
        "a descendant reached through the alias staled"
    );
    // The alias moved, not its policy: a rebind re-points where a node looks,
    // never what may be done through it.
    assert_eq!(
        client
            .mkdir(readonly.node_id, "forbidden", 0o755)
            .expect_err("a read-only alias stays read-only"),
        status::ROFS
    );
}

/// A `RENAME_EXCHANGE` of two populated directories moves both subtrees, and
/// carries neither of them back over the other.
///
/// The two swaps are one rewrite: a node records its whole host path, so
/// applying the first swap's prefix and then the second's in turn would take
/// the entries that had just moved out of the first directory and put them
/// straight back into it. Every child here is resolved *before* the exchange
/// and used after it, so a node that came back with the wrong path answers for
/// the other directory's file — which the contents assert against.
#[test]
fn an_exchange_moves_both_subtrees_and_carries_neither_back() {
    let fixture = budgeted("rename-exchange");
    let left = fixture.tree("left");
    let right = fixture.tree("right");
    create_directory(&left);
    create_directory(&right);
    fs::write(left.join("child"), b"left-child").expect("writable");
    fs::write(right.join("child"), b"right-child").expect("writable");

    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client.hello("plain", "/tree").expect("the mount resolves");
    let left_node = client.lookup(ROOT, "left").expect("resolves");
    let right_node = client.lookup(ROOT, "right").expect("resolves");
    let left_child = client.lookup(left_node.node_id, "child").expect("resolves");
    let right_child = client
        .lookup(right_node.node_id, "child")
        .expect("resolves");

    client
        .rename_with(ROOT, "left", ROOT, "right", RENAME_EXCHANGE)
        .expect("the directories exchange");
    evict_everything(&fixture, &mut client, ROOT);

    // Both directories still answer, and so do both children — each still on
    // the bytes it was resolved on, wherever the exchange put its directory.
    assert!(client.getattr(left_node.node_id).is_ok());
    assert!(client.getattr(right_node.node_id).is_ok());
    for (child, contents) in [
        (left_child, b"left-child".as_slice()),
        (right_child, b"right-child".as_slice()),
    ] {
        let handle = client.open(child.node_id, O_RDWR).expect("opens");
        assert_eq!(
            client.read(handle, 0, 64).expect("reads"),
            contents.to_vec(),
            "an exchanged directory's child came back on the other one's file"
        );
        client.release(handle).expect("releases");
    }
    // And the host really did exchange them.
    assert_eq!(
        fs::read(fixture.tree("left").join("child")).expect("readable"),
        b"right-child".to_vec()
    );
}

/// A recipe is one way back, not the only one: after a link and an unlink, the
/// node re-pins by whichever name survived.
///
/// One recipe cannot represent two live names of an inode, and the namespace
/// path is the name the guest is actually holding — so the fallback is what
/// makes this honest in *both* directions, and the last unlink still stales.
#[test]
fn a_link_and_an_unlink_leave_the_node_re_pinnable_either_way() {
    let fixture = budgeted("link-unlink");
    fs::write(fixture.tree("subject"), b"subject").expect("writable");
    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client.hello("plain", "/tree").expect("the mount resolves");
    let node = client.lookup(ROOT, "subject").expect("resolves");

    // The name the node's recipe adopted is the one that goes: only the
    // namespace path is left to find the file by.
    client.link(ROOT, node.node_id, "copy").expect("links");
    client.unlink(ROOT, "copy").expect("unlinks");
    evict_everything(&fixture, &mut client, ROOT);
    assert_eq!(
        client
            .getattr(node.node_id)
            .expect("the original name still names the file")
            .size
            .get(),
        7
    );

    // And the other direction: the original name goes, the linked one stays.
    client.link(ROOT, node.node_id, "second").expect("links");
    client.unlink(ROOT, "subject").expect("unlinks");
    evict_everything(&fixture, &mut client, ROOT);
    assert!(
        client.getattr(node.node_id).is_ok(),
        "the name the guest linked it under is still there"
    );

    // When the last name goes there is nothing to find, and the node says so.
    client.unlink(ROOT, "second").expect("unlinks");
    evict_everything(&fixture, &mut client, ROOT);
    assert_eq!(
        client
            .getattr(node.node_id)
            .expect_err("no name is left to re-pin by"),
        status::STALE
    );
}

/// Resolves enough fresh names to push everything the session held out of the
/// cache, and asserts that it worked.
///
/// The names come from a directory of this helper's own, created fresh per
/// call, so a test can evict more than once. `under` is the node of the grafted
/// host tree the churn directory is made in — the mount root for a mount of
/// `/tree`, and the node of `tree` itself for a mount of the whole namespace.
fn evict_everything(fixture: &Fixture, client: &mut WireClient, under: u64) {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let round = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let label = format!("evict-{round}");
    let names = populate(&fixture.tree(&label), BUDGET * 3);
    let directory = client.lookup(under, &label).expect("resolves");
    for name in &names {
        client.lookup(directory.node_id, name).expect("resolves");
    }
    let (resident, budget) = cache(fixture);
    assert!(resident <= budget, "{resident} > {budget}");
}

// ---------------------------------------------------------------------------
// The ext4 loop image
// ---------------------------------------------------------------------------

/// A real ext4 filesystem in a file, mounted for the length of one test.
///
/// ext4 is not incidental here: it is the filesystem the identity probe found
/// handing back the same `(dev, ino)` on the first recreate, which is what makes
/// the birth-time half of the identity record load-bearing. tmpfs and btrfs
/// happen to be kinder; a guarantee that only holds on the kind filesystems is
/// not a guarantee.
struct Ext4Image {
    /// Removed after the unmount: it holds the image and the mountpoint.
    #[allow(dead_code, reason = "held for its Drop, which removes the image")]
    directory: TempDir,
    mountpoint: PathBuf,
    mounted: bool,
}

impl Ext4Image {
    /// Creates, formats and mounts an image of `mib` mebibytes.
    ///
    /// `None` where the kernel offers no loop devices, which is the one
    /// preflight this is allowed — the same one the e2e suite's loop-image test
    /// makes, and for the same reason: without `/dev/loop-control` there is no
    /// way to put a block device in front of a file. Missing *tools* are not
    /// skipped, because the development shell provides them; and once the
    /// device opens, every step below is required to succeed, so an environment
    /// that claims to offer loop devices cannot skip its way past a failure.
    ///
    /// A skip says out loud **what was not proven**, because the thing not
    /// proven here is a whole acceptance criterion: nothing else in this suite
    /// runs on a filesystem that reuses inode numbers immediately.
    fn create(label: &str, mib: u64) -> Option<Self> {
        if let Err(error) = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/loop-control")
        {
            eprintln!(
                "skipping {label}: /dev/loop-control is unusable ({error}); NOT PROVEN by this \
                 run: identity and retire-and-remint on a filesystem that reuses (dev, ino) \
                 immediately, which is the half of criterion 4 the birth-time check exists for"
            );
            return None;
        }
        let directory = TempDir::new(label);
        let image = directory.join("ext4.img");
        let file = fs::File::create(&image).expect("the image is creatable");
        file.set_len(mib * 1024 * 1024)
            .expect("the image is sizable");
        drop(file);
        run("mkfs.ext4", &["-q", "-F", &image.display().to_string()]);

        let mountpoint = directory.join("mnt");
        create_directory(&mountpoint);
        run(
            "mount",
            &[
                "-o",
                "loop",
                &image.display().to_string(),
                &mountpoint.display().to_string(),
            ],
        );
        Some(Self {
            directory,
            mountpoint,
            mounted: true,
        })
    }

    /// The mounted filesystem's root.
    fn mounted(&self) -> &Path {
        &self.mountpoint
    }
}

impl Drop for Ext4Image {
    /// A leaked mount outlives the test process and keeps the loop device and
    /// the scratch directory pinned, so this is as loud as it can be if it
    /// fails.
    fn drop(&mut self) {
        if !self.mounted {
            return;
        }
        let status = Command::new("umount").arg(&self.mountpoint).status();
        match status {
            Ok(status) if status.success() => {}
            other => eprintln!(
                "!!! {} is still mounted: {other:?}",
                self.mountpoint.display()
            ),
        }
        // `directory` is declared first, so it is removed *after* this body has
        // unmounted what lives inside it.
    }
}

/// Runs a command and requires it to succeed.
fn run(program: &str, arguments: &[&str]) {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "{program} could not be run ({error}); the development shell \
                 (`./check`, or `nix develop`) provides the tools this test needs"
            )
        });
    assert!(
        output.status.success(),
        "{program} {arguments:?} failed ({}):\n{}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
