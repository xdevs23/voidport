#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::fs;
use std::os::unix::fs::MetadataExt as _;

use rustix::fs::OFlags;
use support::Dial as _;
use support::TempDir;
use support::fixture::Fixture;
use support::wire::{ROOT, WireClient, status};
use voidport_control::{NamespaceName, Request};
use voidport_proto::ops::dir::rename_flags::EXCHANGE as RENAME_EXCHANGE;
use voidport_proto::ops::file::write_flags;
use voidport_proto::ops::node::{SetattrRequest, setattr_valid};
use voidport_test_support::{RunningServer, daemon_config};
use zerocopy::byteorder::little_endian::{U32, U64};

const PERMISSIONS: u32 = 0o7777;

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

fn presented(client: &mut WireClient, name: &str) -> u32 {
    presented_in(client, ROOT, name)
}

fn presented_in(client: &mut WireClient, parent: u64, name: &str) -> u32 {
    client
        .lookup(parent, name)
        .expect("the entry resolves")
        .attr
        .mode
        .get()
        & PERMISSIONS
}

/// A stale locator shows after the restart, since every row is revalidated
/// against the path it names.
fn restarted(fixture: Fixture) -> (TempDir, RunningServer) {
    let state_file = fixture.join("state.toml");
    let Fixture {
        directory,
        mut server,
        ..
    } = fixture;
    server.stop();
    drop(server);
    let config = daemon_config(&state_file);
    let server = RunningServer::start(&config).expect("the server starts again");
    (directory, server)
}

fn host_mode(fixture: &Fixture, name: &str) -> u32 {
    fs::metadata(fixture.tree(name))
        .expect("the host entry exists")
        .mode()
        & PERMISSIONS
}

/// Writes one byte to a file, with the mark the guest kernel sets when the
/// writer does not hold the file-mode privilege.
fn marked_write(client: &mut WireClient, node: u64, name: &str) {
    let handle = client.open(node, OFlags::WRONLY).expect("the file opens");
    client
        .write_marked(node, handle, 0, b"x", write_flags::PRIVILEGED_STRIP)
        .unwrap_or_else(|error| panic!("the write of {name} failed: {error}"));
    client.release(handle).expect("the handle releases");
}

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

    assert_eq!(host_mode(&fixture, "data.bin"), 0o0755);

    let mut other = fixture.server.mount("plain", "/tree");
    assert_eq!(presented(&mut other, "data.bin"), 0o6755);
}

#[test]
fn a_create_masks_the_host_mode_and_presents_the_record() {
    let fixture = Fixture::start("privbits-create");
    let mut client = fixture.server.mount("plain", "/tree");

    let (entry, handle) = client
        .create(ROOT, "made.bin", OFlags::RDONLY, 0o6755)
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

    let fifo = client
        .mknod(ROOT, "made.fifo", 0o010_000 | 0o4644)
        .expect("the mknod lands");
    assert_eq!(fifo.attr.mode.get() & PERMISSIONS, 0o4644);
    assert_eq!(host_mode(&fixture, "made.fifo"), 0o0644);
}

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

    let second = client.lookup(ROOT, "second.bin").expect("resolves");
    marked_write(&mut client, second.node_id, "second.bin");
    assert_eq!(presented(&mut client, "second.bin"), 0o0755);
    assert_eq!(
        presented(&mut client, "data.bin"),
        0o0755,
        "one inode, one record: the strip is visible through every name"
    );
}

#[test]
fn a_marked_write_strips_setuid_always_and_setgid_with_group_execute() {
    let fixture = Fixture::start("privbits-strip");
    let mut client = fixture.server.mount("plain", "/tree");

    let both = client
        .create(ROOT, "both.bin", OFlags::RDONLY, 0o6755)
        .expect("the create lands");
    client.release(both.1).expect("the handle releases");
    marked_write(&mut client, both.0.node_id, "both.bin");
    assert_eq!(presented(&mut client, "both.bin"), 0o0755);

    // No group-execute: setgid is mandatory locking, not privilege, and a
    // write leaves it alone.
    let locking = client
        .create(ROOT, "locking.bin", OFlags::RDONLY, 0o6745)
        .expect("the create lands");
    client.release(locking.1).expect("the handle releases");
    marked_write(&mut client, locking.0.node_id, "locking.bin");
    assert_eq!(
        presented(&mut client, "locking.bin"),
        0o2745,
        "setuid went, setgid without group-execute stayed"
    );

    marked_write(&mut client, locking.0.node_id, "locking.bin");
    assert_eq!(presented(&mut client, "locking.bin"), 0o2745);

    let plain = client
        .create(ROOT, "plain.bin", OFlags::RDONLY, 0o0644)
        .expect("the create lands");
    client.release(plain.1).expect("the handle releases");
    marked_write(&mut client, plain.0.node_id, "plain.bin");
    assert_eq!(presented(&mut client, "plain.bin"), 0o0644);

    // A flag this version does not define is ignored on receive: an older peer
    // ignores the strip mark the same way.
    let unknown = client
        .create(ROOT, "unknown.bin", OFlags::RDONLY, 0o4755)
        .expect("the create lands");
    let handle = client
        .open(unknown.0.node_id, OFlags::WRONLY)
        .expect("the file opens");
    client
        .write_marked(unknown.0.node_id, handle, 0, b"x", 1 << 31)
        .expect("an unknown write flag is not a framing error");
    client.release(handle).expect("the handle releases");
    client.release(unknown.1).expect("the handle releases");
    assert_eq!(presented(&mut client, "unknown.bin"), 0o4755);

    let kept = client
        .create(ROOT, "kept.bin", OFlags::RDONLY, 0o4755)
        .expect("the create lands");
    let handle = client
        .open(kept.0.node_id, OFlags::WRONLY)
        .expect("the file opens");
    client.write(handle, 0, b"x").expect("the write lands");
    client.release(handle).expect("the handle releases");
    client.release(kept.1).expect("the handle releases");
    assert_eq!(presented(&mut client, "kept.bin"), 0o4755);
}

#[test]
fn a_plain_chmod_clears_the_record_and_nothing_resurrects_it() {
    let fixture = Fixture::start("privbits-clear");
    let mut client = fixture.server.mount("plain", "/tree");
    let entry = client.lookup(ROOT, "data.bin").expect("resolves");

    client
        .setattr(entry.node_id, chmod(0o6755))
        .expect("the chmod succeeds");
    assert_eq!(presented(&mut client, "data.bin"), 0o6755);

    client
        .setattr(entry.node_id, chmod(0o2755))
        .expect("the chmod succeeds");
    assert_eq!(presented(&mut client, "data.bin"), 0o2755);

    client
        .setattr(entry.node_id, chmod(0o0644))
        .expect("the chmod succeeds");
    assert_eq!(presented(&mut client, "data.bin"), 0o0644);
    assert_eq!(host_mode(&fixture, "data.bin"), 0o0644);
}

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

/// No lookup and no readdirplus entry contains the root, so its record has to
/// present through `getattr` alone, be found from its backing identity and
/// survive the restart that revalidates every row.
#[test]
fn a_host_backed_namespace_root_presents_its_own_record() {
    let fixture = Fixture::start("privbits-root");
    let mut client = fixture.server.mount("plain", "/tree");

    let settled = client
        .setattr(ROOT, chmod(0o2755))
        .expect("a chmod of the namespace root succeeds");
    assert_eq!(
        settled.mode.get() & PERMISSIONS,
        0o2755,
        "the setattr reply presents the root's own record"
    );
    assert_eq!(
        client.getattr(ROOT).expect("the root stats").mode.get() & PERMISSIONS,
        0o2755,
        "and so does a plain getattr of the root"
    );
    assert_eq!(
        fs::metadata(fixture.graft_root())
            .expect("the grafted directory exists")
            .mode()
            & PERMISSIONS,
        0o0755,
        "the host directory behind the root never gains the bit either"
    );

    let mut other = fixture.server.mount("plain", "/tree");
    assert_eq!(
        other.getattr(ROOT).expect("the root stats").mode.get() & PERMISSIONS,
        0o2755
    );

    let (directory, server) = restarted(fixture);
    let mut client = server.mount("plain", "/tree");
    assert_eq!(
        client.getattr(ROOT).expect("the root stats").mode.get() & PERMISSIONS,
        0o2755,
        "the root's row revalidated against the directory it names"
    );
    drop(directory);
}

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
    let listed = client
        .list(ROOT)
        .expect("the root lists")
        .into_iter()
        .find(|entry| entry.name() == "data.bin")
        .expect("the entry is listed");
    assert_eq!(listed.entry.attr.mode.get() & PERMISSIONS, 0o4755);
    // The directory of the fixture outlives the server restarted in it.
    drop(directory);
}

/// A rename through the server takes the locator with it, in all three forms:
/// the entry itself, everything beneath a renamed directory, and both halves of
/// an exchange. The restart is the assertion: a locator left naming the old
/// place is revalidated against a name the server itself removed, and the row
/// goes silently.
#[test]
fn a_rename_through_the_server_carries_the_records_across_a_restart() {
    let fixture = Fixture::start("privbits-rename");
    let mut client = fixture.server.mount("plain", "/tree");

    let entry = client.lookup(ROOT, "data.bin").expect("resolves");
    client
        .setattr(entry.node_id, chmod(0o4755))
        .expect("the chmod succeeds");
    client
        .rename(ROOT, "data.bin", ROOT, "renamed.bin")
        .expect("the rename lands");

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
        .create(ROOT, "left.bin", OFlags::RDONLY, 0o4700)
        .expect("the create lands");
    client.release(handle).expect("the handle releases");
    let (right, handle) = client
        .create(ROOT, "right.bin", OFlags::RDONLY, 0o2710)
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

#[test]
fn records_made_under_a_renamed_directory_name_where_the_host_has_them() {
    let fixture = Fixture::start("privbits-renamed-parent");
    let mut client = fixture.server.mount("plain", "/tree");

    // The node still names the directory after the rename, because the server
    // never stales what it moved itself, so everything below is resolved
    // through a node whose recorded path and whose namespace description
    // disagree.
    let sub = client.lookup(ROOT, "sub").expect("resolves");
    client
        .rename(ROOT, "sub", ROOT, "moved")
        .expect("the rename lands");

    let (made, handle) = client
        .create(sub.node_id, "made.bin", OFlags::RDONLY, 0o4711)
        .expect("the create lands");
    client.release(handle).expect("the handle releases");
    assert_eq!(made.attr.mode.get() & PERMISSIONS, 0o4711);

    let (plain, handle) = client
        .create(sub.node_id, "chmodded.bin", OFlags::RDONLY, 0o0644)
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
    // Nothing is on disk until the write is flushed; the removal below
    // must delete the sidecar whether or not the debounce has fired, so the
    // assertion is on what is left afterwards.
    let name = NamespaceName::new("plain").expect("a valid namespace name");
    control.expect_ok(&Request::NamespaceDelete { name: name.clone() });
    assert_eq!(sidecars(), 0, "recorded truth dies with the namespace");

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

/// The node is made stale the way a host makes one stale. A small descriptor
/// budget lets other lookups evict the descriptor of the node, and the host
/// then puts another file under its name, so the clear cannot reach the node.
/// The open handle still refers to the original file, which is where an
/// unwanted write would have gone.
#[test]
fn a_marked_write_whose_clear_cannot_be_carried_out_writes_nothing() {
    const BUDGET: usize = 32;

    let fixture = Fixture::start_with(
        "privbits-stale-clear",
        &format!("node_descriptor_budget = {BUDGET}\n"),
    );
    for index in 0..BUDGET * 4 {
        fs::write(fixture.tree(&format!("other-{index}")), b"").expect("writable");
    }
    let mut client = fixture.server.mount("plain", "/tree");
    let entry = client.lookup(ROOT, "data.bin").expect("resolves");
    client
        .setattr(entry.node_id, chmod(0o4755))
        .expect("the chmod records setuid");
    let handle = client
        .open(entry.node_id, OFlags::RDWR)
        .expect("the file opens");

    for index in 0..BUDGET * 4 {
        client
            .lookup(ROOT, &format!("other-{index}"))
            .expect("resolves");
    }
    fs::write(fixture.join("replacement"), b"replacement").expect("writable");
    fs::rename(fixture.join("replacement"), fixture.tree("data.bin")).expect("same filesystem");

    assert_eq!(
        client
            .write_marked(
                entry.node_id,
                handle,
                0,
                b"WRITTEN",
                write_flags::PRIVILEGED_STRIP
            )
            .expect_err("the clear cannot reach a stale node"),
        status::STALE
    );
    assert_eq!(
        client.read(handle, 0, 64).expect("the handle still reads"),
        b"0123456789",
        "the file the handle holds took no byte"
    );
    assert_eq!(
        fs::read(fixture.tree("data.bin")).expect("readable"),
        b"replacement",
        "and neither did the file now under its name"
    );

    assert_eq!(
        client.write_marked(entry.node_id, handle, 0, b"WRITTEN", 0),
        Ok(7)
    );
}

#[test]
fn a_marked_write_through_a_read_only_handle_is_refused_and_clears_nothing() {
    let fixture = Fixture::start("privbits-read-only-write");
    let mut client = fixture.server.mount("plain", "/tree");
    let entry = client.lookup(ROOT, "data.bin").expect("resolves");
    client
        .setattr(entry.node_id, chmod(0o4755))
        .expect("the chmod records setuid");

    let handle = client
        .open(entry.node_id, OFlags::RDONLY)
        .expect("the file opens");
    assert_eq!(
        client
            .write_marked(
                entry.node_id,
                handle,
                0,
                b"x",
                write_flags::PRIVILEGED_STRIP
            )
            .expect_err("a read-only descriptor takes no write"),
        status::BADF
    );
    assert_eq!(
        presented(&mut client, "data.bin"),
        0o4755,
        "the refused write left the recorded setuid bit as it was"
    );
    assert_eq!(
        fs::read(fixture.tree("data.bin")).expect("readable"),
        b"0123456789",
        "and the file took no byte"
    );
}
