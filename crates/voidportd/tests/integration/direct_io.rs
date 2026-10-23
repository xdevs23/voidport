//! The server runs in the process of the test, so `/proc/self/fdinfo` is its
//! descriptor table. The cached descriptor of a node is `O_PATH` and does no
//! I/O, so it is not a backing open and is filtered out everywhere.
//!
//! A filesystem without `O_DIRECT` cannot prove the uncached postures, and the
//! tests that need it print a skip.

#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::fs;
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::path::Path;

use rustix::fs::OFlags;
use support::wire::ROOT;
use support::{Dial as _, RunningServer, TempDir, daemon_config, descriptor_flags};
use voidport_control::{HostDirectIo, NamespaceName, Reply, Request};
use voidportd::state::load_document;

const BLOCK: usize = 512;

const CONTENTS: [u8; 4096] = [b'v'; 4096];

const NAMESPACES: [(&str, HostDirectIo); 3] = [
    ("cached", HostDirectIo::Cached),
    ("through", HostDirectIo::Passthrough),
    ("uncached", HostDirectIo::Always),
];

/// A server serving one namespace per posture, each grafting its own directory,
/// so a descriptor census by path is a census of one posture.
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
    let config = daemon_config(&state_file);
    let server = RunningServer::start(&config).expect("the server starts");
    (directory, server)
}

fn name(raw: &str) -> NamespaceName {
    NamespaceName::new(raw).expect("valid namespace name")
}

fn direct(access: OFlags) -> OFlags {
    access | OFlags::DIRECT
}

fn backing_flags(path: &Path) -> Vec<u32> {
    descriptor_flags(path)
        .into_iter()
        .filter(|flags| flags & OFlags::PATH.bits() == 0)
        .collect()
}

fn is_uncached(flags: u32) -> bool {
    flags & OFlags::DIRECT.bits() != 0
}

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

fn aligned(buffer: &mut [u8]) -> &mut [u8] {
    let start = buffer.as_ptr() as usize;
    let offset = start.next_multiple_of(BLOCK) - start;
    &mut buffer[offset..offset + BLOCK]
}

/// Probed the way the server would open it, and read through, because a
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

fn payload(marker: u8) -> Vec<u8> {
    (0..BLOCK).map(|index| index as u8 ^ marker).collect()
}

#[test]
fn every_posture_round_trips_the_state_file_the_summary_and_a_mutation() {
    let (directory, server) = start("posture-state");
    let mut control = server.connect();

    for (namespace, posture) in NAMESPACES {
        let Reply::Namespace { namespace: spec } = control.expect_ok(&Request::NamespaceShow {
            name: name(namespace),
        }) else {
            panic!("expected a namespace");
        };
        assert_eq!(spec.direct_io, posture, "{namespace}");
    }

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

#[test]
fn the_cached_default_masks_a_guest_handles_direct_io() {
    let (directory, server) = start("posture-cached");
    let path = directory.join("cached").join("data.bin");
    let mut guest = server.mount("cached", "/tree");
    let file = guest.lookup(ROOT, "data.bin").expect("the file");

    for flags in [
        OFlags::RDONLY,
        direct(OFlags::RDONLY),
        OFlags::RDWR,
        direct(OFlags::RDWR),
    ] {
        let handle = guest.open(file.node_id, flags).expect("the file opens");
        assert!(
            !is_uncached(only_backing(&path)),
            "flags {flags:#o} reached the backing open"
        );
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

    let cached = guest
        .open(file.node_id, direct(OFlags::RDONLY))
        .expect("the file opens");
    assert!(!is_uncached(only_backing(&path)));

    server.connect().expect_ok(&Request::DirectIoSet {
        namespace: name("cached"),
        posture: HostDirectIo::Passthrough,
    });

    let uncached = guest
        .open(file.node_id, direct(OFlags::RDONLY))
        .expect("the file opens");
    assert!(
        is_uncached(only_backing(&path)),
        "the newer open is uncached"
    );

    assert_eq!(guest.read(cached, 1, 7).expect("readable"), &CONTENTS[1..8]);
    assert!(
        !is_uncached(only_backing(&path)),
        "the older handle transfers cached"
    );

    guest.release(cached).expect("the handle releases");
    guest.release(uncached).expect("the handle releases");
}

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

    let plain = guest
        .open(file.node_id, OFlags::RDONLY)
        .expect("the file opens");
    assert!(!is_uncached(only_backing(&path)));
    assert_eq!(guest.read(plain, 1, 7).expect("readable"), &CONTENTS[1..8]);
    guest.release(plain).expect("the handle releases");

    for access in [OFlags::RDONLY, OFlags::RDWR] {
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
        .open(file.node_id, direct(OFlags::RDWR))
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

    // Refusal is the policy of one filesystem: ext4 returns `EINVAL`, btrfs
    // serves the request from its buffered fallback, so the guest gets that
    // same result whichever it is.
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
        .open(file.node_id, direct(OFlags::RDONLY))
        .expect("the file opens");

    // The aligned buffer belongs to the server, and the offset and the length
    // that the guest chose are never repaired.
    match locally {
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

    let read = guest.lookup(ROOT, "data.bin").expect("the file");
    let read_handle = guest
        .open(read.node_id, OFlags::RDONLY)
        .expect("the file opens");
    let written = guest.lookup(ROOT, "other.bin").expect("the file");
    let write_handle = guest
        .open(written.node_id, OFlags::RDWR)
        .expect("the file opens");
    let (_, created_handle) = guest
        .create(ROOT, "new.bin", OFlags::RDWR, 0o644)
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

#[test]
fn under_always_aligned_requests_serve_through_an_aligned_buffer() {
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
    let handle = guest
        .open(file.node_id, OFlags::RDWR)
        .expect("the file opens");
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

    let (_, created) = guest
        .create(ROOT, "fresh.bin", OFlags::RDWR, 0o644)
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

/// The offset alignment reported by `statx`, or the logical block size for a
/// filesystem that reports none.
fn offset_alignment(path: &Path) -> usize {
    let stat = rustix::fs::statx(
        rustix::fs::CWD,
        path,
        rustix::fs::AtFlags::empty(),
        rustix::fs::StatxFlags::DIOALIGN,
    )
    .expect("statx answers");
    let filled = rustix::fs::StatxFlags::from_bits_truncate(stat.stx_mask);
    if filled.contains(rustix::fs::StatxFlags::DIOALIGN) && stat.stx_dio_offset_align > 0 {
        stat.stx_dio_offset_align as usize
    } else {
        BLOCK
    }
}

#[test]
fn a_misaligned_length_serves_its_aligned_pieces() {
    let (directory, server) = start("posture-tail");
    let graft = directory.join("uncached");
    let path = graft.join("other.bin");
    if !serves_uncached_io(&path) {
        eprintln!(
            "skipping the misaligned-length proof: {} serves no direct I/O",
            graft.display()
        );
        return;
    }
    let alignment = offset_alignment(&path);
    let aligned_len = 2 * alignment;
    let len = aligned_len + 100;
    // The file reaches one alignment past the aligned pieces, so the tail lies
    // inside it whatever the offset alignment is.
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .and_then(|file| file.set_len((aligned_len + alignment) as u64))
        .expect("the host file takes its length");

    let local = fs::OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::DIRECT.bits() as i32)
        .open(&path)
        .expect("the host file opens uncached");
    let mut buffer = vec![0u8; len + 2 * alignment];
    let start = buffer.as_ptr() as usize;
    let skip = start.next_multiple_of(alignment) - start;
    let refuses = local
        .read_at(&mut buffer[skip..skip + alignment + 100], 0)
        .is_err();
    eprintln!(
        "the backing filesystem {} a misaligned direct length",
        if refuses { "refuses" } else { "serves" }
    );

    let mut guest = server.mount("uncached", "/tree");
    let file = guest.lookup(ROOT, "other.bin").expect("the file");
    let handle = guest
        .open(file.node_id, OFlags::RDWR)
        .expect("the file opens");
    let data: Vec<u8> = (0..len).map(|index| (index % 251) as u8).collect();
    let written = guest.write(handle, 0, &data).expect("the aligned pieces");
    let (read, closing) = guest
        .read_closing(handle, 0, len as u32)
        .expect("the aligned pieces");
    if refuses {
        assert_eq!(
            written as usize, aligned_len,
            "the aligned pieces are written"
        );
        assert_eq!(read, data[..aligned_len], "the aligned pieces are read");
        assert_eq!(
            closing.status,
            -rustix::io::Errno::INVAL.raw_os_error(),
            "the tail's errno closes the read"
        );
    } else {
        assert_eq!(written as usize, len);
        assert_eq!(read, data);
        assert_eq!(closing.status, 0);
    }
    guest.release(handle).expect("the handle releases");
}
