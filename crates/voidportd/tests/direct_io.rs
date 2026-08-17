//! Host-side direct I/O: the per-namespace posture that decides whether the
//! server's backing reads and writes ride the host page cache.
//!
//! A mount's own direct-io option is guest-side presentation — it keeps the
//! guest from holding a page cache so the host's is the one cache — and this
//! setting is the only thing that puts `O_DIRECT` on a *backing* description.
//! Three postures: the cached default, passthrough (the backing open carries
//! what the guest handle asked for), and always (every backing open is
//! uncached).
//!
//! Nothing here is asserted from the request the server made. The server runs
//! in the test's own process, so `/proc/self/fdinfo` is its descriptor table
//! and every claim below is read back off the description the kernel actually
//! created. The node's own pin is an `O_PATH` descriptor — it names an inode
//! and does no I/O — so it is not a backing open and is filtered out
//! everywhere.
//!
//! The uncached postures owe more than a flag: the server's own buffers are not
//! block-aligned and direct I/O refuses them, so an aligned guest request only
//! serves because the server bounces it through an aligned buffer. That is what
//! the round-trip proofs are for — real bytes, out and back, through an
//! uncached descriptor — and the answer the backing filesystem gives a
//! misaligned request, refusal or service, is proved to pass through unchanged
//! beside them.
//!
//! Uncached I/O is the backing filesystem's to offer: one that supports no
//! `O_DIRECT` at all cannot prove the two uncached postures, and the tests that
//! need it say so out loud instead of passing quietly.

mod support;

use std::fs;
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::path::Path;

use rustix::fs::OFlags;
use support::wire::ROOT;
use support::{Dial as _, RunningServer, TempDir, daemon_config, descriptor_flags, environment};
use voidport_control::{HostDirectIo, NamespaceName, Reply, Request};
use voidportd::state::load_document;

/// `O_RDONLY` and `O_RDWR`, as the guest sends them.
const O_RDONLY: u32 = 0;
const O_RDWR: u32 = 2;

/// The alignment a local filesystem asks of direct I/O, and the size of every
/// request here that means to be aligned.
const BLOCK: usize = 512;

/// The file each graft holds, one page long.
const CONTENTS: [u8; 4096] = [b'v'; 4096];

/// The three namespaces, their postures as the state file spells them, and the
/// graft directory each one shares.
const NAMESPACES: [(&str, HostDirectIo); 3] = [
    ("cached", HostDirectIo::Cached),
    ("through", HostDirectIo::Passthrough),
    ("uncached", HostDirectIo::Always),
];

/// A server serving one namespace per posture, each grafting its own
/// directory: a descriptor census by path is then a census of one posture.
fn start(label: &str) -> (TempDir, RunningServer) {
    let directory = TempDir::new(label);
    let mut state = String::from(
        r#"
[[server.listeners]]
transport = "tcp"
addr = "127.0.0.1:0"
"#,
    );
    for (namespace, posture) in NAMESPACES {
        let graft = directory.directory(namespace);
        for file in ["data.bin", "other.bin"] {
            fs::write(graft.join(file), CONTENTS).expect("writable");
        }
        state.push_str(&format!(
            r#"
[[namespaces]]
name = "{namespace}"
direct_io = "{posture}"

[[namespaces.rules]]
path = "/tree"
mode = "rw"
target = "{graft}"
"#,
            graft = graft.display()
        ));
    }
    let state_file = directory.write("state.toml", &state);
    let config = daemon_config(&state_file, environment(directory.path()));
    let server = RunningServer::start(&config).expect("the server starts");
    (directory, server)
}

fn name(raw: &str) -> NamespaceName {
    NamespaceName::new(raw).expect("valid namespace name")
}

/// The open flags a guest sends for a direct-I/O handle.
fn direct(access: u32) -> u32 {
    access | OFlags::DIRECT.bits()
}

/// The flags of every descriptor the server holds on `path` for real I/O.
fn backing_flags(path: &Path) -> Vec<u32> {
    descriptor_flags(path)
        .into_iter()
        .filter(|flags| flags & OFlags::PATH.bits() == 0)
        .collect()
}

/// Whether a description opened on `path` is uncached.
fn is_uncached(flags: u32) -> bool {
    flags & OFlags::DIRECT.bits() != 0
}

/// The one backing description the server holds on `path`.
fn only_backing(path: &Path) -> u32 {
    let flags = backing_flags(path);
    assert_eq!(
        flags.len(),
        1,
        "expected one backing description of {}, found {flags:?}",
        path.display()
    );
    flags[0]
}

/// A `BLOCK`-aligned window of `buffer`, which is what a local program doing
/// direct I/O hands the kernel.
fn aligned(buffer: &mut [u8]) -> &mut [u8] {
    let start = buffer.as_ptr() as usize;
    let offset = start.next_multiple_of(BLOCK) - start;
    &mut buffer[offset..offset + BLOCK]
}

/// Whether the filesystem holding `path` serves direct I/O at all.
///
/// Probed the way the server would open it — and read through, because a
/// filesystem may accept the flag and refuse the transfer.
fn serves_uncached_io(path: &Path) -> bool {
    let Ok(file) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::DIRECT.bits() as i32)
        .open(path)
    else {
        return false;
    };
    let mut buffer = vec![0u8; BLOCK * 2];
    file.read_at(aligned(&mut buffer), 0).is_ok()
}

/// A block of recognizable bytes, distinct from what the fixture wrote.
fn payload(marker: u8) -> Vec<u8> {
    (0..BLOCK).map(|index| index as u8 ^ marker).collect()
}

// ---------------------------------------------------------------------------
// Criterion 1 — the setting round-trips the state file and the control plane,
// persisted, live at the next open; the default posture masks a guest handle's
// own O_DIRECT.
// ---------------------------------------------------------------------------

#[test]
fn every_posture_round_trips_the_state_file_the_summary_and_a_mutation() {
    let (directory, server) = start("posture-state");
    let mut control = server.connect();

    // As the file spells them, through the source form the operator reads.
    for (namespace, posture) in NAMESPACES {
        let Reply::Namespace { namespace: spec } = control.expect_ok(&Request::NamespaceShow {
            name: name(namespace),
        }) else {
            panic!("expected a namespace");
        };
        assert_eq!(spec.direct_io, posture, "{namespace}");
    }

    // And through the summary the list surface answers with.
    let Reply::NamespaceList { namespaces } = control.expect_ok(&Request::NamespaceList {}) else {
        panic!("expected a namespace list");
    };
    for (namespace, posture) in NAMESPACES {
        let summary = namespaces
            .iter()
            .find(|summary| summary.name.as_str() == namespace)
            .expect("every namespace is listed");
        assert_eq!(summary.direct_io, posture, "{namespace}");
    }

    // The mutation, and what it leaves on disk: the state file is the whole
    // configuration, so a posture that did not persist would be gone at the
    // next launch.
    control.expect_ok(&Request::DirectIoSet {
        namespace: name("cached"),
        posture: HostDirectIo::Always,
    });
    let document = load_document(&directory.join("state.toml")).expect("the file parses");
    let persisted = document
        .namespaces
        .iter()
        .find(|spec| spec.name.as_str() == "cached")
        .expect("the namespace is in the file");
    assert_eq!(persisted.direct_io, HostDirectIo::Always);
    assert_eq!(document, server.service().snapshot().document);

    // A namespace that does not exist is a `NotFound`, not a silent create.
    assert_eq!(
        control
            .expect_error(&Request::DirectIoSet {
                namespace: name("absent"),
                posture: HostDirectIo::Cached,
            })
            .code,
        voidport_control::ErrorCode::NotFound
    );
}

/// The stated change: a guest handle's `O_DIRECT` used to reach the backing
/// open unconditionally, and the decided caching model masks it.
///
/// This is the pin for that change. Everything else about the handle is
/// untouched — the reads answer at any offset and any length, which is what a
/// page-cached description does and what an uncached one would refuse.
#[test]
fn the_cached_default_masks_a_guest_handles_direct_io() {
    let (directory, server) = start("posture-cached");
    let path = directory.join("cached").join("data.bin");
    let mut guest = server.mount("cached", "/tree");
    let file = guest.lookup(ROOT, "data.bin").expect("the file");

    for flags in [O_RDONLY, direct(O_RDONLY), O_RDWR, direct(O_RDWR)] {
        let handle = guest.open(file.node_id, flags).expect("the file opens");
        assert!(
            !is_uncached(only_backing(&path)),
            "flags {flags:#o} reached the backing open"
        );
        // Reads are the host page cache's, at any offset and any length:
        // nothing about this handle carries an alignment demand.
        assert_eq!(guest.read(handle, 1, 7).expect("readable"), &CONTENTS[1..8]);
        guest.release(handle).expect("the handle releases");
    }
}

#[test]
fn a_posture_change_reaches_the_next_open_and_leaves_open_handles_alone() {
    let (directory, server) = start("posture-live");
    let path = directory.join("cached").join("data.bin");
    if !serves_uncached_io(&path) {
        eprintln!(
            "skipping the live-posture proof: {} serves no direct I/O",
            path.display()
        );
        return;
    }

    let mut guest = server.mount("cached", "/tree");
    let file = guest.lookup(ROOT, "data.bin").expect("the file");

    // The default posture: the guest asked for direct I/O and the backing
    // description rides the host cache anyway.
    let cached = guest
        .open(file.node_id, direct(O_RDONLY))
        .expect("the file opens");
    assert!(!is_uncached(only_backing(&path)));

    server.connect().expect_ok(&Request::DirectIoSet {
        namespace: name("cached"),
        posture: HostDirectIo::Passthrough,
    });

    // Live at the next open, and only there: the description already open is
    // exactly the description it was, the way a share-mode change leaves an
    // open handle alone.
    let uncached = guest
        .open(file.node_id, direct(O_RDONLY))
        .expect("the file opens");
    let flags = backing_flags(&path);
    assert_eq!(flags.len(), 2, "{flags:?}");
    assert_eq!(
        flags.iter().filter(|flags| is_uncached(**flags)).count(),
        1,
        "exactly the newer open is uncached: {flags:?}"
    );

    // The older handle still serves what a cached description serves — an
    // unaligned length, which the newer one could not answer.
    assert_eq!(guest.read(cached, 1, 7).expect("readable"), &CONTENTS[1..8]);

    guest.release(cached).expect("the handle releases");
    guest.release(uncached).expect("the handle releases");
}

// ---------------------------------------------------------------------------
// Criterion 2 — passthrough: the guest handle decides, an aligned request
// round-trips real data, and the backing filesystem's alignment answers for
// itself.
// ---------------------------------------------------------------------------

#[test]
fn passthrough_puts_o_direct_on_the_backing_open_exactly_where_the_guest_did() {
    let (directory, server) = start("posture-through");
    let path = directory.join("through").join("data.bin");
    if !serves_uncached_io(&path) {
        eprintln!(
            "skipping the passthrough flag proof: {} serves no direct I/O",
            path.display()
        );
        return;
    }

    let mut guest = server.mount("through", "/tree");
    let file = guest.lookup(ROOT, "data.bin").expect("the file");

    // A handle that did not ask rides the host cache, unchanged.
    let plain = guest.open(file.node_id, O_RDONLY).expect("the file opens");
    assert!(!is_uncached(only_backing(&path)));
    assert_eq!(guest.read(plain, 1, 7).expect("readable"), &CONTENTS[1..8]);
    guest.release(plain).expect("the handle releases");

    // One that did gets an uncached backing description — read off the
    // description, not off the request.
    for access in [O_RDONLY, O_RDWR] {
        let handle = guest
            .open(file.node_id, direct(access))
            .expect("the file opens");
        assert!(
            is_uncached(only_backing(&path)),
            "access {access:#o} did not reach the backing open"
        );
        guest.release(handle).expect("the handle releases");
    }
}

/// The production contract of an uncached posture: real bytes, through the
/// storage, both ways.
///
/// The server's own buffers are byte-aligned — a read lands behind a fixed
/// response head, a write is a slice of the frame that arrived — so without the
/// bounce every one of these transfers would be `EINVAL` however carefully the
/// guest aligned its request. The host file is read back afterwards to prove
/// the bytes really left the server.
#[test]
fn passthrough_round_trips_real_data_through_an_uncached_descriptor() {
    let (directory, server) = start("posture-through-data");
    let path = directory.join("through").join("other.bin");
    if !serves_uncached_io(&path) {
        eprintln!(
            "skipping the passthrough data proof: {} serves no direct I/O",
            path.display()
        );
        return;
    }

    let mut guest = server.mount("through", "/tree");
    let file = guest.lookup(ROOT, "other.bin").expect("the file");
    let handle = guest
        .open(file.node_id, direct(O_RDWR))
        .expect("the file opens");
    assert!(is_uncached(only_backing(&path)));

    let written = payload(0x5A);
    for offset in [0u64, BLOCK as u64 * 3] {
        assert_eq!(
            guest.write(handle, offset, &written).expect("aligned"),
            BLOCK as u32
        );
        assert_eq!(
            guest.read(handle, offset, BLOCK as u32).expect("aligned"),
            written,
            "an aligned read at {offset} did not return what was written"
        );
    }
    guest.release(handle).expect("the handle releases");

    // And it is on the host, not in a buffer the server kept.
    let host = fs::read(&path).expect("readable");
    assert_eq!(&host[..BLOCK], &written[..]);
    assert_eq!(&host[BLOCK * 3..BLOCK * 4], &written[..]);
}

#[test]
fn an_unaligned_request_answers_what_the_backing_filesystem_answers_locally() {
    let (directory, server) = start("posture-align");
    let path = directory.join("through").join("data.bin");
    if !serves_uncached_io(&path) {
        eprintln!(
            "skipping the alignment proof: {} serves no direct I/O",
            path.display()
        );
        return;
    }

    // What the filesystem itself says, to a local program holding an aligned
    // buffer and naming an offset that is not a multiple of a block. Refusal
    // is one filesystem's policy, not a law — ext4 answers `EINVAL`, btrfs
    // serves the request from its buffered fallback — so the answer is taken
    // as it comes, and the guest is owed that same answer, whichever it is.
    let local = fs::OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::DIRECT.bits() as i32)
        .open(&path)
        .expect("the host file opens uncached");
    let mut buffer = vec![0u8; BLOCK * 2];
    let window = aligned(&mut buffer);
    let locally = local.read_at(window, 1);

    let mut guest = server.mount("through", "/tree");
    let file = guest.lookup(ROOT, "data.bin").expect("the file");
    let handle = guest
        .open(file.node_id, direct(O_RDONLY))
        .expect("the file opens");

    // The same misalignment over the wire, and the same answer back: the
    // bounce fixes the buffer the guest cannot see and never repairs the
    // offset or the length it chose.
    match locally {
        // The wire carries a status, which is the negated errno.
        Err(refused) => {
            eprintln!("the backing filesystem refuses the misaligned offset");
            let locally = refused.raw_os_error().expect("an errno");
            assert_eq!(
                guest
                    .read(handle, 1, BLOCK as u32)
                    .expect_err("the same unaligned request"),
                -locally
            );
        }
        // A filesystem that repairs the offset serves the guest the same
        // bytes it served the local program.
        Ok(served) => {
            eprintln!("the backing filesystem repairs the misaligned offset");
            assert_eq!(
                guest
                    .read(handle, 1, BLOCK as u32)
                    .expect("the same request served")
                    .as_slice(),
                &window[..served]
            );
        }
    }
    guest.release(handle).expect("the handle releases");
}

// ---------------------------------------------------------------------------
// Criterion 3 — always: every backing open in the namespace is uncached, and
// serves through the bounce.
// ---------------------------------------------------------------------------

#[test]
fn under_always_every_backing_open_in_the_namespace_is_uncached() {
    let (directory, server) = start("posture-always");
    let graft = directory.join("uncached");
    if !serves_uncached_io(&graft.join("data.bin")) {
        eprintln!(
            "skipping the always-posture census: {} serves no direct I/O",
            graft.display()
        );
        return;
    }

    let mut guest = server.mount("uncached", "/tree");

    // A read handle, a write handle, and the open a create performs — none of
    // the three asked for direct I/O, and the census below is over all of them
    // at once.
    let read = guest.lookup(ROOT, "data.bin").expect("the file");
    let read_handle = guest.open(read.node_id, O_RDONLY).expect("the file opens");
    let written = guest.lookup(ROOT, "other.bin").expect("the file");
    let write_handle = guest.open(written.node_id, O_RDWR).expect("the file opens");
    let (_, created_handle) = guest
        .create(ROOT, "new.bin", O_RDWR, 0o644)
        .expect("the file is created");

    let census: Vec<u32> = ["data.bin", "other.bin", "new.bin"]
        .into_iter()
        .flat_map(|file| backing_flags(&graft.join(file)))
        .collect();
    assert_eq!(census.len(), 3, "{census:?}");
    assert!(
        census.iter().copied().all(is_uncached),
        "a backing open rode the host cache: {census:?}"
    );

    for handle in [read_handle, write_handle, created_handle] {
        guest.release(handle).expect("the handle releases");
    }
}

/// Under `always` an ordinary guest — one that never asked for direct I/O at
/// all — still gets its data, which is the whole point of the posture: the
/// operator moves the caching, not the guest's semantics.
#[test]
fn under_always_aligned_requests_serve_through_the_bounce() {
    let (directory, server) = start("posture-always-data");
    let graft = directory.join("uncached");
    let path = graft.join("other.bin");
    if !serves_uncached_io(&path) {
        eprintln!(
            "skipping the always-posture data proof: {} serves no direct I/O",
            graft.display()
        );
        return;
    }

    let mut guest = server.mount("uncached", "/tree");
    let file = guest.lookup(ROOT, "other.bin").expect("the file");
    let handle = guest.open(file.node_id, O_RDWR).expect("the file opens");
    assert!(is_uncached(only_backing(&path)));

    let written = payload(0xA5);
    assert_eq!(
        guest.write(handle, 0, &written).expect("aligned"),
        BLOCK as u32
    );
    assert_eq!(
        guest.read(handle, 0, BLOCK as u32).expect("aligned"),
        written
    );
    guest.release(handle).expect("the handle releases");

    // A file the guest created in this namespace serves the same way.
    let (_, created) = guest
        .create(ROOT, "fresh.bin", O_RDWR, 0o644)
        .expect("the file is created");
    assert_eq!(
        guest.write(created, 0, &written).expect("aligned"),
        BLOCK as u32
    );
    assert_eq!(
        guest.read(created, 0, BLOCK as u32).expect("aligned"),
        written
    );
    guest.release(created).expect("the handle releases");
    assert_eq!(
        fs::read(graft.join("fresh.bin")).expect("readable"),
        written,
        "the created file's bytes did not reach the host"
    );
}
