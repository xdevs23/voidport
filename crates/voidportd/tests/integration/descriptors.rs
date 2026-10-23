#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::fs;
use std::path::{Path, PathBuf};

use rustix::fs::OFlags;
use support::Dial as _;
use support::TempDir;
use support::fixture::Fixture;
use support::wire::{ROOT, WireClient, status};
use voidport_control::{NamespaceName, NamespaceSpec, Reply, Request, Rule, ShareMode};
use voidport_proto::ops::dir::rename_flags::EXCHANGE as RENAME_EXCHANGE;
use voidport_spawn::{Program, Stream};
use voidport_test_support::create_directory;

const BUDGET: usize = 32;

const BUDGET_SETTING: &str = "node_descriptor_budget = 32\n";

fn budgeted(label: &str) -> Fixture {
    Fixture::start_with(label, BUDGET_SETTING)
}

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

/// The server runs in the process of the test, so `/proc/self/fd` is the
/// descriptor table of the server.
fn descriptors_into(root: &Path) -> usize {
    let Ok(entries) = fs::read_dir("/proc/self/fd") else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| fs::read_link(entry.path()).is_ok_and(|target| target.starts_with(root)))
        .count()
}

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
        client
            .getattr(entry.node_id)
            .unwrap_or_else(|status| panic!("{name} attributes failed with {status}"));
        resolved.push(entry.node_id);

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

    let nodes = nodes_held(&fixture);
    assert!(
        nodes > BUDGET * 5,
        "the node table should hold every name walked, not {nodes}"
    );

    let into_tree = descriptors_into(fixture.graft_root());
    assert!(
        into_tree <= BUDGET + 64,
        "{into_tree} descriptors into the tree against a budget of {BUDGET}"
    );

    for node in &resolved {
        assert!(client.getattr(*node).is_ok(), "node {node} stopped working");
    }
}

#[test]
fn an_evicted_node_answers_metadata_identically_to_a_resident_one() {
    let fixture = budgeted("evict-attr");
    fs::write(fixture.tree("subject"), b"0123456789").expect("writable");
    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client.hello("plain", "/tree").expect("the mount resolves");

    let subject = client.lookup(ROOT, "subject").expect("resolves");
    let before = client.getattr(subject.node_id).expect("resident");

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

/// The node with a key whose entry was replaced is retired, so its id is
/// stale and its key is free for the node that the next resolution mints.
/// Otherwise a fresh lookup fails with `ESTALE` forever.
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
    assert_eq!(
        client.open(file.node_id, OFlags::RDWR).expect_err("stale"),
        status::STALE
    );
    let fresh = client.lookup(ROOT, "victim").expect("the name resolves");
    assert_ne!(fresh.node_id, file.node_id);
    let handle = client.open(fresh.node_id, OFlags::RDWR).expect("opens");
    assert_eq!(
        client.read(handle, 0, 64).expect("reads"),
        b"impostor!".to_vec()
    );

    // A directory is keyed by its namespace path, so the replacement gets the
    // very key of the stale node.
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

/// On ext4, `(dev, ino)` comes straight back on the first recreate, so only the
/// recorded birth time stands between the old node id and the bytes of the
/// impostor.
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
        client.open(file.node_id, OFlags::RDWR).expect_err("stale"),
        status::STALE
    );
    assert_eq!(recorded.size.get(), 8, "the original was eight bytes");

    // The recreated file has the same `(dev, ino)` as the stale node, so its key is
    // occupied and only retiring that node can free it.
    let fresh = client.lookup(ROOT, "victim").expect("the name resolves");
    assert_ne!(fresh.node_id, file.node_id);
    let handle = client.open(fresh.node_id, OFlags::RDWR).expect("opens");
    assert_eq!(
        client.read(handle, 0, 64).expect("reads"),
        b"impostor!".to_vec()
    );
    let fresh_directory = client
        .lookup(ROOT, "victim-dir")
        .expect("the directory's name resolves");
    assert_ne!(fresh_directory.node_id, directory.node_id);
    assert!(client.getattr(fresh_directory.node_id).is_ok());

    assert_eq!(
        client.getattr(file.node_id).expect_err("retired"),
        status::STALE
    );
    assert_eq!(
        client.getattr(directory.node_id).expect_err("retired"),
        status::STALE
    );
}

#[test]
fn an_open_handle_survives_its_nodes_eviction() {
    let fixture = budgeted("handle-survives");
    fs::write(fixture.tree("open-me"), b"0123456789").expect("writable");
    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client.hello("plain", "/tree").expect("the mount resolves");

    let node = client.lookup(ROOT, "open-me").expect("resolves");
    let handle = client.open(node.node_id, OFlags::RDWR).expect("opens");
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
    fs::remove_file(fixture.tree("open-me")).expect("removable");
    assert_eq!(
        client.read(handle, 0, 5).expect("still reads"),
        b"ABCDE".to_vec()
    );
    client.release(handle).expect("releases");
}

/// The namespace is built for this test: the `plain` namespace of the fixture
/// grafts one host directory under two rules, so removing one of them leaves
/// the graft open through the other.
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
    // the churn of one mount takes the slots of the other.
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

#[test]
fn a_rename_through_the_mount_never_stales_what_it_moved() {
    let fixture = budgeted("rename-rebind");
    let inside = fixture.tree("movable");
    let names = populate(&inside, 8);
    fs::write(fixture.tree("loose"), b"loose").expect("writable");

    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client.hello("plain", "/tree").expect("the mount resolves");

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

    client
        .rename(ROOT, "movable", ROOT, "moved")
        .expect("the directory renames");
    client
        .rename(ROOT, "loose", ROOT, "relocated")
        .expect("the file renames");

    evict_everything(&fixture, &mut client, ROOT);

    // The rename rewrote the host path of every descendant, which ran through the
    // name that changed.
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
    assert!(fixture.tree("moved").is_dir());
    assert!(fixture.tree("relocated").is_file());
}

/// The node still has the namespace path it was resolved at, so the
/// namespace describes the new entry under the old name of the directory, and
/// only the recorded path of the directory has where the entry ended up.
/// Eviction makes the difference visible: a resident slot uses its descriptor.
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
    let made = client
        .mkdir(directory.node_id, "made", 0o755)
        .expect("creates under the renamed directory");
    let (created, handle) = client
        .create(directory.node_id, "file", OFlags::RDWR, 0o644)
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

/// The watcher never learns of the move, so what keeps it working is the rename
/// reaching into its table.
#[test]
fn a_rename_through_one_mount_never_stales_another_mounts_nodes() {
    let fixture = budgeted("rename-cross-session");
    let names = populate(&fixture.tree("shared-dir"), 4);
    fs::write(fixture.tree("shared-file"), b"shared").expect("writable");

    let mut mover = fixture.server.mount("plain", "/tree");
    let mut watcher = fixture.server.mount("plain", "/tree");

    let directory = watcher.lookup(ROOT, "shared-dir").expect("resolves");
    let child = watcher
        .lookup(directory.node_id, &names[0])
        .expect("resolves");
    let file = watcher.lookup(ROOT, "shared-file").expect("resolves");

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

/// The `plain` namespace grafts the tree twice, read-write at `/tree` and
/// read-only at `/readonly`, so a mount of the whole namespace has two nodes
/// for every directory. The alias must follow the rename and stay read-only.
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
    assert_eq!(
        client
            .mkdir(readonly.node_id, "forbidden", 0o755)
            .expect_err("a read-only alias stays read-only"),
        status::ROFS
    );
}

/// The two swaps are one rewrite: a node records its whole host path, so
/// applying the prefix of the first swap and then that of the second would put
/// the entries that just moved straight back.
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

    assert!(client.getattr(left_node.node_id).is_ok());
    assert!(client.getattr(right_node.node_id).is_ok());
    for (child, contents) in [
        (left_child, b"left-child".as_slice()),
        (right_child, b"right-child".as_slice()),
    ] {
        let handle = client.open(child.node_id, OFlags::RDWR).expect("opens");
        assert_eq!(
            client.read(handle, 0, 64).expect("reads"),
            contents.to_vec(),
            "an exchanged directory's child came back on the other one's file"
        );
        client.release(handle).expect("releases");
    }
    assert_eq!(
        fs::read(fixture.tree("left").join("child")).expect("readable"),
        b"right-child".to_vec()
    );
}

/// One recipe cannot represent two live names of an inode, and the namespace
/// path is the name used by the guest, so the fallback reopens by whichever
/// name survived.
#[test]
fn a_link_and_an_unlink_leave_the_node_re_pinnable_either_way() {
    let fixture = budgeted("link-unlink");
    fs::write(fixture.tree("subject"), b"subject").expect("writable");
    let mut client = WireClient::unix(fixture.server.data_unix()).expect("unix accepts");
    client.hello("plain", "/tree").expect("the mount resolves");
    let node = client.lookup(ROOT, "subject").expect("resolves");

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

    client.link(ROOT, node.node_id, "second").expect("links");
    client.unlink(ROOT, "subject").expect("unlinks");
    evict_everything(&fixture, &mut client, ROOT);
    assert!(
        client.getattr(node.node_id).is_ok(),
        "the name the guest linked it under is still there"
    );

    client.unlink(ROOT, "second").expect("unlinks");
    evict_everything(&fixture, &mut client, ROOT);
    assert_eq!(
        client
            .getattr(node.node_id)
            .expect_err("no name is left to re-pin by"),
        status::STALE
    );
}

/// Every entry a listing streams counts a lookup, and a reply that ends in an
/// errno gives back every entry it carried. The failure comes from the host:
/// between two reads of one handle, every descriptor opened by the first is
/// evicted and one listed file is removed, so the second read fails with
/// `ESTALE` after it counted the entries in front of that node again.
#[test]
fn a_listing_that_fails_midway_keeps_no_node() {
    let fixture = budgeted("listing-fails");
    let names = populate(&fixture.tree("listed"), 8);
    // A `forget` gets no reply, so the client waits until the server has read the
    // earlier requests of the connection before it reads what the server stored.
    let mut client = fixture.server.mount("plain", "/tree");
    let directory = client.lookup(ROOT, "listed").expect("resolves");
    let handle = client
        .open(directory.node_id, OFlags::RDONLY)
        .expect("opens");

    let listed = client
        .readdirplus(directory.node_id, handle, 0, 64 * 1024)
        .expect("the first read lists everything");
    assert_eq!(listed.len(), names.len());
    evict_everything(&fixture, &mut client, ROOT);
    let held = nodes_held(&fixture);

    let removed = &listed[listed.len() / 2];
    fs::remove_file(fixture.tree("listed").join(removed.name())).expect("removable");
    assert_eq!(
        client
            .readdirplus(directory.node_id, handle, 0, 64 * 1024)
            .expect_err("the removed file's node cannot be re-pinned"),
        status::STALE,
        "a short listing with no error would look like a directory that lost a file"
    );

    // Each listed node has the one lookup that the first read reported, so one
    // `forget` per entry reply empties them out of the table.
    for entry in &listed {
        client.forget(entry.entry.node_id, 1);
    }
    client.fence();
    assert_eq!(
        nodes_held(&fixture),
        held - listed.len(),
        "a failed listing keeps no node"
    );
}

fn nodes_held(fixture: &Fixture) -> usize {
    let Reply::SessionList { sessions } =
        fixture.server.connect().expect_ok(&Request::SessionList {})
    else {
        panic!("expected a session list");
    };
    sessions.iter().map(|session| session.nodes).sum()
}

/// The names come from a directory created fresh per call, so a test can evict
/// more than once. `under` is the node of the grafted host tree: the mount root
/// for a mount of `/tree`, the node of `tree` for the whole namespace.
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

/// ext4 hands back the same `(dev, ino)` on the first recreate, which is what
/// makes the birth-time half of the identity record needed.
struct Ext4Image {
    /// Removed after the unmount by its `Drop`, because it contains the image and
    /// the mountpoint.
    _directory: TempDir,
    mountpoint: PathBuf,
    mounted: bool,
}

impl Ext4Image {
    /// `None` where the kernel offers no loop devices. Missing tools are not
    /// skipped, and once the device opens every step must succeed. A skip shows
    /// what was not proven: nothing else in this suite runs on a filesystem
    /// that reuses inode numbers immediately.
    fn create(label: &str, mib: u64) -> Option<Self> {
        if let Err(error) = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/loop-control")
        {
            eprintln!(
                "skipping {label}: /dev/loop-control is unusable ({error}); NOT PROVEN by this \
                 run: identity and retire-and-remint on a filesystem that reuses (dev, ino) \
                 immediately"
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
            _directory: directory,
            mountpoint,
            mounted: true,
        })
    }

    fn mounted(&self) -> &Path {
        &self.mountpoint
    }
}

impl Drop for Ext4Image {
    /// A leaked mount outlives the test process, and the loop device is still
    /// in use.
    fn drop(&mut self) {
        if !self.mounted {
            return;
        }
        let status = Program::new("umount")
            .arg(&self.mountpoint)
            .stderr(Stream::Inherit)
            .status();
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

fn run(program: &str, arguments: &[&str]) {
    let output = Program::new(program)
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
