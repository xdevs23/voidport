//! Privileged mode bits over the real protocol.
//!
//! The first instance of the recorded-metadata pattern, driven the way every
//! other data-plane suite is driven: a real server, a real socket, and the
//! wire client in `support::wire`. What is pinned here is the whole contract —
//! that a guest sees setuid and setgid work while the host backing never gains
//! a bit the server's own user set, that they present through every
//! attribute-bearing reply and every name of a hard link, that they strip by
//! the kernel's own predicate, that they survive a restart, and that both
//! switches mask without destroying what was recorded.

mod support;

use std::fs;
use std::os::unix::fs::MetadataExt as _;

use support::Dial as _;
use support::TempDir;
use support::fixture::Fixture;
use support::wire::{ROOT, WireClient};
use voidport_control::{NamespaceName, Request};
use voidport_proto::ops::dir::rename_flags::EXCHANGE as RENAME_EXCHANGE;
use voidport_proto::ops::file::write_flags;
use voidport_proto::ops::node::{SetattrRequest, setattr_valid};
use voidportd::testing::{RunningServer, daemon_config, invoking_environment};
use zerocopy::byteorder::little_endian::{U32, U64};

/// `O_RDONLY` and `O_WRONLY`, as the guest sends them.
const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;

/// The permission bits of a presented mode.
const PERMISSIONS: u32 = 0o7777;

/// A chmod of exactly `mode`.
fn chmod(mode: u32) -> SetattrRequest {
    SetattrRequest {
        valid: U32::new(setattr_valid::MODE),
        reserved: U32::ZERO,
        handle: U64::ZERO,
        size: U64::ZERO,
        mode: U32::new(mode),
        uid: U32::ZERO,
        gid: U32::ZERO,
        reserved2: U32::ZERO,
        atime: voidport_proto::attr::Timespec::new(0, 0),
        mtime: voidport_proto::attr::Timespec::new(0, 0),
        ctime: voidport_proto::attr::Timespec::new(0, 0),
    }
}

/// The permission bits one name presents right now, through a fresh lookup.
fn presented(client: &mut WireClient, name: &str) -> u32 {
    presented_in(client, ROOT, name)
}

/// The same, for a name inside a directory other than the namespace root.
fn presented_in(client: &mut WireClient, parent: u64, name: &str) -> u32 {
    client
        .lookup(parent, name)
        .expect("the entry resolves")
        .attr
        .mode
        .get()
        & PERMISSIONS
}

/// Stops the server, starts a fresh one on the same state file, and mounts
/// `plain` at `/tree` — which is where a stale locator shows, since every row
/// is revalidated against the path it names.
fn restarted(fixture: Fixture) -> (TempDir, RunningServer) {
    let state_file = fixture.join("state.toml");
    let Fixture {
        directory,
        mut server,
        ..
    } = fixture;
    server.stop();
    drop(server);
    let config = daemon_config(&state_file, invoking_environment(directory.path()));
    let server = RunningServer::start(&config).expect("the server starts again");
    (directory, server)
}

/// The host file's own permission bits.
fn host_mode(fixture: &Fixture, name: &str) -> u32 {
    fs::metadata(fixture.tree(name))
        .expect("the host entry exists")
        .mode()
        & PERMISSIONS
}

/// Writes one byte to a file, with the mark the guest kernel sets when the
/// writer does not hold the file-mode privilege.
fn marked_write(client: &mut WireClient, node: u64, name: &str) {
    let handle = client.open(node, O_WRONLY).expect("the file opens");
    client
        .write_marked(node, handle, 0, b"x", write_flags::PRIVILEGED_STRIP)
        .unwrap_or_else(|error| panic!("the write of {name} failed: {error}"));
    client.release(handle).expect("the handle releases");
}

/// A guest chmod that sets setuid works, presents through every
/// attribute-bearing reply, and never reaches the host file's own mode.
#[test]
fn a_chmod_records_the_bits_and_the_host_mode_never_gains_them() {
    let fixture = Fixture::start("privbits-chmod");
    let mut client = fixture.server.mount("plain", "/tree");
    let entry = client.lookup(ROOT, "data.bin").expect("resolves");

    let settled = client
        .setattr(entry.node_id, chmod(0o6755))
        .expect("a chmod that sets both bits succeeds");
    assert_eq!(
        settled.mode.get() & PERMISSIONS,
        0o6755,
        "the setattr reply presents what the guest asked for"
    );
    assert_eq!(
        client.getattr(entry.node_id).expect("stats").mode.get() & PERMISSIONS,
        0o6755,
        "getattr presents the record"
    );
    assert_eq!(presented(&mut client, "data.bin"), 0o6755, "so does lookup");
    let listed = client
        .list(ROOT)
        .expect("the root lists")
        .into_iter()
        .find(|entry| entry.name() == "data.bin")
        .expect("the entry is listed");
    assert_eq!(
        listed.entry.attr.mode.get() & PERMISSIONS,
        0o6755,
        "and so does the readdirplus entry"
    );

    // The whole point: the host file never carries a privileged bit this
    // server's own user set.
    assert_eq!(host_mode(&fixture, "data.bin"), 0o0755);

    // A second mount of the same namespace presents the same record: it is the
    // namespace's, not the session's.
    let mut other = fixture.server.mount("plain", "/tree");
    assert_eq!(presented(&mut other, "data.bin"), 0o6755);
}

/// A create carrying a privileged mode masks the host file and presents the
/// record in the very reply that made the entry — on every kind that creates.
#[test]
fn a_create_masks_the_host_mode_and_presents_the_record() {
    let fixture = Fixture::start("privbits-create");
    let mut client = fixture.server.mount("plain", "/tree");

    let (entry, handle) = client
        .create(ROOT, "made.bin", O_RDONLY, 0o6755)
        .expect("the create lands");
    client.release(handle).expect("the handle releases");
    assert_eq!(
        entry.attr.mode.get() & PERMISSIONS,
        0o6755,
        "the create reply presents the mode the guest asked for"
    );
    assert_eq!(host_mode(&fixture, "made.bin"), 0o0755);

    let made = client
        .mkdir(ROOT, "made.dir", 0o2755)
        .expect("the mkdir lands");
    assert_eq!(made.attr.mode.get() & PERMISSIONS, 0o2755);
    assert_eq!(host_mode(&fixture, "made.dir"), 0o0755);

    // A fifo records too: every file kind does.
    let fifo = client
        .mknod(ROOT, "made.fifo", 0o010_000 | 0o4644)
        .expect("the mknod lands");
    assert_eq!(fifo.attr.mode.get() & PERMISSIONS, 0o4644);
    assert_eq!(host_mode(&fixture, "made.fifo"), 0o0644);
}

/// One inode, one record: an assignment through one name presents and strips
/// through every name of a hard link.
#[test]
fn every_name_of_a_hard_link_presents_and_strips_the_one_record() {
    let fixture = Fixture::start("privbits-link");
    let mut client = fixture.server.mount("plain", "/tree");
    let entry = client.lookup(ROOT, "data.bin").expect("resolves");
    client
        .link(ROOT, entry.node_id, "second.bin")
        .expect("the link lands");

    client
        .setattr(entry.node_id, chmod(0o6755))
        .expect("the chmod succeeds");
    assert_eq!(presented(&mut client, "data.bin"), 0o6755);
    assert_eq!(
        presented(&mut client, "second.bin"),
        0o6755,
        "the other name of the inode presents the same record"
    );

    // And a write through one name strips for both.
    let second = client.lookup(ROOT, "second.bin").expect("resolves");
    marked_write(&mut client, second.node_id, "second.bin");
    assert_eq!(presented(&mut client, "second.bin"), 0o0755);
    assert_eq!(
        presented(&mut client, "data.bin"),
        0o0755,
        "one inode, one record: the strip is visible through every name"
    );
}

/// The strip is the kernel's own mode-only predicate: setuid always, setgid
/// only where group-execute is set.
#[test]
fn a_marked_write_strips_setuid_always_and_setgid_with_group_execute() {
    let fixture = Fixture::start("privbits-strip");
    let mut client = fixture.server.mount("plain", "/tree");

    // Group-execute set: both bits go.
    let both = client
        .create(ROOT, "both.bin", O_RDONLY, 0o6755)
        .expect("the create lands");
    client.release(both.1).expect("the handle releases");
    marked_write(&mut client, both.0.node_id, "both.bin");
    assert_eq!(presented(&mut client, "both.bin"), 0o0755);

    // No group-execute: setgid is mandatory locking, not privilege, and a
    // write leaves it alone.
    let locking = client
        .create(ROOT, "locking.bin", O_RDONLY, 0o6745)
        .expect("the create lands");
    client.release(locking.1).expect("the handle releases");
    marked_write(&mut client, locking.0.node_id, "locking.bin");
    assert_eq!(
        presented(&mut client, "locking.bin"),
        0o2745,
        "setuid went, setgid without group-execute stayed"
    );

    // Every chunk of a split write carries the mark, and stripping is
    // idempotent: a second marked write changes nothing further.
    marked_write(&mut client, locking.0.node_id, "locking.bin");
    assert_eq!(presented(&mut client, "locking.bin"), 0o2745);

    // A marked write on a file with nothing recorded is a no-op that leaves
    // the presented mode exactly as it was.
    let plain = client
        .create(ROOT, "plain.bin", O_RDONLY, 0o0644)
        .expect("the create lands");
    client.release(plain.1).expect("the handle releases");
    marked_write(&mut client, plain.0.node_id, "plain.bin");
    assert_eq!(presented(&mut client, "plain.bin"), 0o0644);

    // A flag this version does not define is ignored on receive, which is what
    // makes the field's forward compatibility real in both directions: it is
    // how an elder peer treats the strip mark, and how this one treats
    // whatever comes next.
    let unknown = client
        .create(ROOT, "unknown.bin", O_RDONLY, 0o4755)
        .expect("the create lands");
    let handle = client
        .open(unknown.0.node_id, O_WRONLY)
        .expect("the file opens");
    client
        .write_marked(unknown.0.node_id, handle, 0, b"x", 1 << 31)
        .expect("an unknown write flag is not a framing error");
    client.release(handle).expect("the handle releases");
    client.release(unknown.1).expect("the handle releases");
    assert_eq!(presented(&mut client, "unknown.bin"), 0o4755);

    // An unmarked write strips nothing: the mark is the guest kernel's
    // delegation, and a server that stripped without it would be inventing
    // policy.
    let kept = client
        .create(ROOT, "kept.bin", O_RDONLY, 0o4755)
        .expect("the create lands");
    let handle = client
        .open(kept.0.node_id, O_WRONLY)
        .expect("the file opens");
    client.write(handle, 0, b"x").expect("the write lands");
    client.release(handle).expect("the handle releases");
    client.release(kept.1).expect("the handle releases");
    assert_eq!(presented(&mut client, "kept.bin"), 0o4755);
}

/// Setting is an assignment, never a merge: a plain chmod clears exactly as
/// local semantics demand, and the record is deleted when its last bit goes.
#[test]
fn a_plain_chmod_clears_the_record_and_nothing_resurrects_it() {
    let fixture = Fixture::start("privbits-clear");
    let mut client = fixture.server.mount("plain", "/tree");
    let entry = client.lookup(ROOT, "data.bin").expect("resolves");

    client
        .setattr(entry.node_id, chmod(0o6755))
        .expect("the chmod succeeds");
    assert_eq!(presented(&mut client, "data.bin"), 0o6755);

    // Assignment: setting one bit replaces both, it does not merge.
    client
        .setattr(entry.node_id, chmod(0o2755))
        .expect("the chmod succeeds");
    assert_eq!(presented(&mut client, "data.bin"), 0o2755);

    // And the last bit clearing deletes the record.
    client
        .setattr(entry.node_id, chmod(0o0644))
        .expect("the chmod succeeds");
    assert_eq!(presented(&mut client, "data.bin"), 0o0644);
    assert_eq!(host_mode(&fixture, "data.bin"), 0o0644);
}

/// A disabled namespace masks recorded and host-real bits alike, refuses a
/// chmod that would set one, and — the read-modify-write case — neither
/// records nor deletes.
#[test]
fn a_disabled_namespace_masks_refuses_and_keeps_what_it_recorded() {
    let fixture = Fixture::start("privbits-disabled");
    let mut control = fixture.server.connect();
    let mut client = fixture.server.mount("plain", "/tree");
    let entry = client.lookup(ROOT, "data.bin").expect("resolves");
    client
        .setattr(entry.node_id, chmod(0o6755))
        .expect("the chmod succeeds");

    control.expect_ok(&Request::PrivilegedBitsSet {
        namespace: NamespaceName::new("plain").expect("a valid namespace name"),
        enabled: false,
    });

    // Live at the next operation that reaches the server.
    assert_eq!(
        presented(&mut client, "data.bin"),
        0o0755,
        "a disabled namespace shows no privileged bits"
    );
    assert_eq!(
        client.setattr(entry.node_id, chmod(0o4755)),
        Err(-libc::EPERM),
        "and refuses a chmod that would set one"
    );

    // The read-modify-write case: the guest was shown a mode without the bits,
    // so a chmod carrying none must not destroy what other mounts present.
    client
        .setattr(entry.node_id, chmod(0o0700))
        .expect("a plain chmod still works");
    assert_eq!(presented(&mut client, "data.bin"), 0o0700);

    control.expect_ok(&Request::PrivilegedBitsSet {
        namespace: NamespaceName::new("plain").expect("a valid namespace name"),
        enabled: true,
    });
    assert_eq!(
        presented(&mut client, "data.bin"),
        0o6700,
        "recorded truth was masked, never discarded"
    );
}

/// Recorded truth survives a server restart through the revalidating sidecar,
/// and a cold listing is complete.
#[test]
fn the_records_survive_a_restart_through_the_sidecar() {
    let fixture = Fixture::start("privbits-restart");
    let mut client = fixture.server.mount("plain", "/tree");
    let entry = client.lookup(ROOT, "data.bin").expect("resolves");
    client
        .setattr(entry.node_id, chmod(0o4755))
        .expect("the chmod succeeds");

    // Teardown flushes every store before the instance lock drops, which is
    // what makes the sidecar complete without waiting for the debounce.
    let (directory, server) = restarted(fixture);
    let mut client = server.mount("plain", "/tree");
    assert_eq!(
        presented(&mut client, "data.bin"),
        0o4755,
        "the row revalidated against the file it names"
    );
    // A cold listing is complete: the table is the single point of truth, and
    // the listing walk reads it like every other path.
    let listed = client
        .list(ROOT)
        .expect("the root lists")
        .into_iter()
        .find(|entry| entry.name() == "data.bin")
        .expect("the entry is listed");
    assert_eq!(listed.entry.attr.mode.get() & PERMISSIONS, 0o4755);
    // The fixture's directory outlives the server that was restarted in it.
    drop(directory);
}

/// A rename through the server takes the locator with it, in all three forms:
/// the entry itself, everything beneath a renamed directory, and both halves of
/// an exchange. The restart is the assertion — a locator left naming the old
/// place is revalidated against a name the server itself removed, and the row
/// goes silently.
#[test]
fn a_rename_through_the_server_carries_the_records_across_a_restart() {
    let fixture = Fixture::start("privbits-rename");
    let mut client = fixture.server.mount("plain", "/tree");

    // The entry form: the record follows the inode, whatever name reached it.
    let entry = client.lookup(ROOT, "data.bin").expect("resolves");
    client
        .setattr(entry.node_id, chmod(0o4755))
        .expect("the chmod succeeds");
    client
        .rename(ROOT, "data.bin", ROOT, "renamed.bin")
        .expect("the rename lands");

    // The subtree form: a record underneath a directory that moves.
    let sub = client.lookup(ROOT, "sub").expect("resolves");
    let inner = client.lookup(sub.node_id, "inner").expect("resolves");
    client
        .setattr(inner.node_id, chmod(0o2755))
        .expect("the chmod succeeds");
    client
        .rename(ROOT, "sub", ROOT, "moved")
        .expect("the rename lands");

    // The exchange form: two records, each following its own inode to where the
    // other one was. One pass over the table, so neither is carried back.
    let (left, handle) = client
        .create(ROOT, "left.bin", O_RDONLY, 0o4700)
        .expect("the create lands");
    client.release(handle).expect("the handle releases");
    let (right, handle) = client
        .create(ROOT, "right.bin", O_RDONLY, 0o2710)
        .expect("the create lands");
    client.release(handle).expect("the handle releases");
    client
        .rename_with(ROOT, "left.bin", ROOT, "right.bin", RENAME_EXCHANGE)
        .expect("the exchange lands");
    assert_eq!(
        client.getattr(left.node_id).expect("stats").mode.get() & PERMISSIONS,
        0o4700
    );
    assert_eq!(
        client.getattr(right.node_id).expect("stats").mode.get() & PERMISSIONS,
        0o2710
    );

    let (directory, server) = restarted(fixture);
    let mut client = server.mount("plain", "/tree");
    assert_eq!(
        presented(&mut client, "renamed.bin"),
        0o4755,
        "the record followed the entry the server renamed"
    );
    let moved = client
        .lookup(ROOT, "moved")
        .expect("the directory resolves");
    assert_eq!(
        presented_in(&mut client, moved.node_id, "inner"),
        0o2755,
        "and the records beneath a renamed directory followed it too"
    );
    assert_eq!(
        presented(&mut client, "right.bin"),
        0o4700,
        "the exchanged inode presents its own record at the name it took"
    );
    assert_eq!(presented(&mut client, "left.bin"), 0o2710);
    drop(directory);
}

/// What is recorded under a directory the server itself renamed names where the
/// host has the entry now, not where the namespace still describes it — for a
/// create carrying the bits and for a chmod delivering them alike.
#[test]
fn records_made_under_a_renamed_directory_name_where_the_host_has_them() {
    let fixture = Fixture::start("privbits-renamed-parent");
    let mut client = fixture.server.mount("plain", "/tree");

    // The node keeps naming the directory after the rename — the server never
    // stales what it moved itself — so everything below is resolved through a
    // node whose recorded path and whose namespace description disagree.
    let sub = client.lookup(ROOT, "sub").expect("resolves");
    client
        .rename(ROOT, "sub", ROOT, "moved")
        .expect("the rename lands");

    let (made, handle) = client
        .create(sub.node_id, "made.bin", O_RDONLY, 0o4711)
        .expect("the create lands");
    client.release(handle).expect("the handle releases");
    assert_eq!(made.attr.mode.get() & PERMISSIONS, 0o4711);

    let (plain, handle) = client
        .create(sub.node_id, "chmodded.bin", O_RDONLY, 0o0644)
        .expect("the create lands");
    client.release(handle).expect("the handle releases");
    client
        .setattr(plain.node_id, chmod(0o2750))
        .expect("the chmod succeeds");

    let (directory, server) = restarted(fixture);
    let mut client = server.mount("plain", "/tree");
    let moved = client
        .lookup(ROOT, "moved")
        .expect("the directory resolves");
    assert_eq!(
        presented_in(&mut client, moved.node_id, "made.bin"),
        0o4711,
        "the create's locator named the directory's host path, not its old one"
    );
    assert_eq!(
        presented_in(&mut client, moved.node_id, "chmodded.bin"),
        0o2750,
        "and so did the chmod's"
    );
    drop(directory);
}

/// Removing the namespace deletes its recorded truth with it, and a re-created
/// name starts empty.
#[test]
fn deleting_a_namespace_deletes_its_records() {
    let fixture = Fixture::start("privbits-removal");
    let mut control = fixture.server.connect();
    let mut client = fixture.server.mount("plain", "/tree");
    let entry = client.lookup(ROOT, "data.bin").expect("resolves");
    client
        .setattr(entry.node_id, chmod(0o4755))
        .expect("the chmod succeeds");

    let sidecars = || {
        fs::read_dir(fixture.directory.path())
            .expect("the directory reads")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".records.toml")
            })
            .count()
    };
    // Nothing is on disk until something takes the write; the removal below
    // must delete the sidecar whether or not the debounce has fired, so the
    // assertion is on what is left afterwards.
    let name = NamespaceName::new("plain").expect("a valid namespace name");
    control.expect_ok(&Request::NamespaceDelete { name: name.clone() });
    assert_eq!(sidecars(), 0, "recorded truth dies with the namespace");

    // The session that was serving keeps its tombstone and its store, and the
    // store takes no further writes.
    assert_eq!(presented(&mut client, "data.bin"), 0o4755);
    client
        .setattr(entry.node_id, chmod(0o2755))
        .expect("the chmod still reaches the host");
    assert_eq!(
        host_mode(&fixture, "data.bin"),
        0o0755,
        "the host took the chmod, masked as always"
    );
    assert_eq!(
        presented(&mut client, "data.bin"),
        0o4755,
        "a retired store answers with what it holds and takes no further writes"
    );
}
