//! Privileged mode bits through a real mount, on a real kernel.
//!
//! The server's own suite pins the contract against the wire; this one pins it
//! against the thing the contract is a claim *about* — the guest kernel. Three
//! questions only a real mount can answer are asked here:
//!
//! * **does stripping match local semantics?** Every strip case is run twice,
//!   once against a plain host directory and once through the mount, and the
//!   two answers are compared. A local directory is the only honest control:
//!   the design says "as local semantics demand", so the assertion is against
//!   what a local filesystem actually does on this kernel, not against a mode
//!   this suite believes it should produce.
//! * **does the kernel really mark direct-io writes without being asked to?**
//!   A frame-aware relay in front of the server records what the guest kernel
//!   put on the wire, so the mark is counted where it arrives.
//! * **does the mount option hold?** `--no-privileged-bits` masks, refuses, and
//!   leaves recorded truth alone when a read-modify-write chmod comes back
//!   through it.
//!
//! Every unprivileged caller here is a thread that dropped its effective uid,
//! which is the suite's established way of running as somebody else inside a
//! root process, and every mount that such a thread reaches is mounted with
//! `allow_other` so the refusal under test is never FUSE's owner check.

mod support;

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use support::{Fixture, Guest, NOBODY_ID, errno};
use voidport::mount::MountOptions;
use voidport_proto::frame::{FRAME_HEADER_LEN, Frame, FrameHeader, FrameKind};
use voidport_proto::ops::file::{WriteRequest, write_flags};
use voidport_proto::ops::node::{SetattrRequest, setattr_valid};
use zerocopy::FromBytes as _;

/// The permission, setuid, setgid and sticky bits of a mode word.
const PERMISSIONS: u32 = 0o7777;

/// The frame bound the server announces, which is what a relay in front of it
/// has to parse with.
const MAX_FRAME_LEN: u32 = 1024 * 1024;

/// A mode carrying both privileged bits, with group-execute set.
///
/// Group-execute is what makes setgid a real setgid instead of the
/// mandatory-locking mark, so this is the mode where both bits go. The write
/// bits are open to the group as well as to everyone else because the
/// unprivileged caller in these tests keeps the process's group membership and
/// the files are group-owned by it: the group class is the one that decides,
/// and a mode that only opened the other class would refuse the write for a
/// reason that has nothing to do with what is under test.
const BOTH_BITS: u32 = 0o6777;

/// The same, with group-execute cleared: setgid here is mandatory locking, and
/// only setuid goes.
const LOCKING_SETGID: u32 = 0o6767;

/// A write large enough that the guest kernel has to split it across several
/// frames, whichever of the two write paths carries it.
///
/// The frame bound is one mebibyte, so four of them cannot be one request.
const SPLIT_WRITE: usize = 4 * 1024 * 1024;

/// An id no caller in this suite is a member of, used as a file's group so that
/// a chmod by its owner is a chmod by somebody outside its group.
const FOREIGN_GROUP: u32 = 65534;

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

/// Runs `work` on a thread whose effective uid is unprivileged.
///
/// Per-thread credentials: only this thread drops privilege, the saved id stays
/// root, and nothing else in the process is affected. Dropping the effective
/// uid also empties the effective capability set, which is the whole point —
/// `CAP_FSETID` is what the kernel's own strip predicate asks about.
fn as_unprivileged<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    thread::spawn(move || {
        rustix::thread::set_thread_res_uid(
            None,
            Some(rustix::process::Uid::from_raw(NOBODY_ID)),
            None,
        )
        .expect("a thread may drop privilege");
        work()
    })
    .join()
    .expect("the unprivileged thread finishes")
}

/// The permission bits a path presents right now.
fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("{} should stat: {error}", path.display()))
        .permissions()
        .mode()
        & PERMISSIONS
}

/// Creates `name` inside `directory` with `mode` and some content.
///
/// The mode is set explicitly after the create, because no umask may be allowed
/// to decide what the case under test starts from — and because a create cannot
/// carry setuid through `File::create` anyway.
fn seed(directory: &Path, name: &str, mode: u32) -> PathBuf {
    let path = directory.join(name);
    std::fs::write(&path, b"0123456789")
        .unwrap_or_else(|error| panic!("{} should be creatable: {error}", path.display()));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|error| panic!("{} should take a mode: {error}", path.display()));
    assert_eq!(
        mode_of(&path),
        mode,
        "the case starts from the mode it names"
    );
    path
}

/// Mount options for these tests: another user may reach the mount, and no
/// attribute is cached.
///
/// The zero attribute timeout is deliberate. The design bounds how long a stale
/// mode may be shown by the mount's attribute TTL, and a suite comparing
/// *semantics* against a local directory must not be measuring that window: with
/// no attribute caching every `stat` here is a real question to the server, so
/// what is compared is the answer and nothing else.
fn options(direct_io: bool) -> MountOptions {
    MountOptions {
        attr_timeout: Duration::ZERO,
        allow_other: true,
        direct_io,
        // The run's chunk unit ([`support::write_stream_bytes`]): the
        // shipped streaming default ordinarily, and zero for the pinned
        // serial pass. Streaming is where the suid-kill mark has to ride
        // every chunk of every write, which is exactly what this suite
        // measures.
        write_stream: support::write_stream_bytes(),
        ..MountOptions::default()
    }
}

/// The three places one sequence is run: a plain host directory, a page-cached
/// mount, and a direct-io mount.
struct Arena {
    local: PathBuf,
    cached: Guest,
    direct: Guest,
}

impl Arena {
    /// Builds the control directory and both mounts of one fixture.
    fn new(fixture: &Fixture) -> Self {
        Self {
            local: fixture.directory.directory("local"),
            cached: fixture.mount_with(
                "cached",
                &fixture.tcp_url("plain", "/tree"),
                &options(false),
            ),
            direct: fixture.mount_with(
                "direct",
                &fixture.tcp_url("plain", "/tree"),
                &options(true),
            ),
        }
    }

    /// Runs `sequence` in each of the three places and returns what each left
    /// behind, the control first.
    ///
    /// Each place gets its own file name, so the two mounts never race over one
    /// host inode and the control is a file of its own.
    fn compare(&self, name: &str, mode: u32, sequence: impl Fn(&Path)) -> (u32, u32, u32) {
        let run = |directory: &Path, label: &str| {
            let path = seed(directory, &format!("{name}-{label}.bin"), mode);
            sequence(&path);
            mode_of(&path)
        };
        (
            run(&self.local, "local"),
            run(self.cached.root(), "cached"),
            run(self.direct.root(), "direct"),
        )
    }
}

/// Asserts that both mounts left exactly what the local directory left.
fn agrees(what: &str, (local, cached, direct): (u32, u32, u32)) {
    assert_eq!(
        cached, local,
        "{what}: the page-cached mount left {cached:o} where a local directory leaves {local:o}"
    );
    assert_eq!(
        direct, local,
        "{what}: the direct-io mount left {direct:o} where a local directory leaves {local:o}"
    );
}

// ---------------------------------------------------------------------------
// Criterion 2 — stripping matches local semantics, on both mount modes
// ---------------------------------------------------------------------------

/// A write by a caller without the file-mode privilege strips exactly what the
/// same write strips in a local directory, on both mount modes.
///
/// The predicate under test is the kernel's own and is mode-only: setuid always
/// goes, setgid goes only where group-execute is set. Neither mount is told
/// that predicate — the page-cached mount has the kernel apply it and send the
/// resulting mode, the direct-io mount has the kernel mark the write and the
/// server apply it — and the control directory is where the predicate actually
/// lives. All three have to agree.
#[test]
fn a_write_strips_what_a_local_directory_strips_on_both_mount_modes() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("privbits-paired-write");
    let arena = Arena::new(&fixture);

    let one_byte = |path: &Path| {
        let path = path.to_path_buf();
        as_unprivileged(move || {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap_or_else(|error| {
                    panic!("{} should be writable by anyone: {error}", path.display())
                });
            file.write_all(b"x").expect("the write lands");
        });
    };

    let both = arena.compare("both", BOTH_BITS, one_byte);
    assert_eq!(
        both.0,
        BOTH_BITS & !0o6000,
        "a local directory clears both bits on a write by an unprivileged caller"
    );
    agrees("a write with group-execute set", both);

    let locking = arena.compare("locking", LOCKING_SETGID, one_byte);
    assert_eq!(
        locking.0,
        LOCKING_SETGID & !0o4000,
        "setgid without group-execute is mandatory locking, and a local directory keeps it"
    );
    agrees("a write without group-execute", locking);

    // Every chunk of a split write carries the mark, and stripping is
    // idempotent, so a write the kernel had to cut into several frames leaves
    // exactly what a one-byte write leaves.
    let split = arena.compare("split", BOTH_BITS, |path| {
        let path = path.to_path_buf();
        as_unprivileged(move || {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("writable");
            file.write_all(&vec![b'x'; SPLIT_WRITE])
                .expect("the split write lands");
        });
    });
    agrees("a write the kernel split", split);
}

/// A truncate clears through the kernel's own path, and the record follows —
/// again exactly as a local directory does it, on both mount modes.
///
/// Truncate is not the write path: the kernel turns the kill into an explicit
/// mode change and sends it as a `setattr`, in either caching mode. Nothing in
/// the client is involved, and the table follows the mode change like any
/// other chmod, which is what makes this a check that nothing was turned off
/// instead of a check that something was implemented.
#[test]
fn a_truncate_clears_what_a_local_directory_clears_on_both_mount_modes() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("privbits-paired-truncate");
    let arena = Arena::new(&fixture);

    let truncate = |path: &Path| {
        let path = path.to_path_buf();
        as_unprivileged(move || {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("writable");
            file.set_len(0).expect("the truncate lands");
        });
    };

    let both = arena.compare("both", BOTH_BITS, truncate);
    assert_eq!(
        both.0,
        BOTH_BITS & !0o6000,
        "a local truncate by an unprivileged caller clears both bits"
    );
    agrees("a truncate with group-execute set", both);

    let locking = arena.compare("locking", LOCKING_SETGID, truncate);
    assert_eq!(
        locking.0,
        LOCKING_SETGID & !0o4000,
        "and leaves the mandatory-locking mark alone"
    );
    agrees("a truncate without group-execute", locking);
}

/// A chmod by a caller outside the file's group arrives already stripped.
///
/// This is the predicate no wire field could carry: whether the caller is a
/// member of the file's group. The mount's unconditional `default_permissions`
/// posture is what makes the guest kernel evaluate it under the caller's full
/// credentials and hand the server the post-VFS mode, so the server can take
/// that mode's privileged bits as the record's new value without ever asking
/// who the caller was. What is pinned here is that the delivered mode really
/// does arrive without the bit — observed as the mode the mount presents
/// afterwards, since a mode that arrived would have been recorded and
/// presented.
#[test]
fn an_out_of_group_chmod_arrives_stripped_by_the_guest_kernel() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("privbits-out-of-group");
    // Owned by the unprivileged caller so that the chmod is permitted at all,
    // and grouped somewhere that caller is not a member of, which is the
    // condition under test. Both are set on the host: the namespace passes
    // ownership through, so this is what the guest sees.
    let host = fixture.host("tree/grouped.bin");
    std::fs::write(&host, b"grouped").expect("writable");
    std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o0755))
        .expect("a settable mode");
    rustix::fs::chown(
        &host,
        Some(rustix::process::Uid::from_raw(NOBODY_ID)),
        Some(rustix::process::Gid::from_raw(FOREIGN_GROUP)),
    )
    .expect("the suite runs privileged enough to chown");

    let guest = fixture.mount_with(
        "out-of-group",
        &fixture.tcp_url("plain", "/tree"),
        &options(false),
    );
    let path = guest.path("grouped.bin");

    let asked = path.clone();
    as_unprivileged(move || {
        std::fs::set_permissions(&asked, std::fs::Permissions::from_mode(0o2755))
            .expect("the owner may chmod its own file");
    });
    assert_eq!(
        mode_of(&path),
        0o0755,
        "the guest kernel dropped setgid before the mode reached the wire, so nothing recorded it"
    );

    // The same caller, the same file, the bit the group predicate does not
    // govern: setuid arrives, is recorded, and is presented — which is what
    // makes the case above a stripped mode and not a refused chmod.
    let asked = path.clone();
    as_unprivileged(move || {
        std::fs::set_permissions(&asked, std::fs::Permissions::from_mode(0o4755))
            .expect("the owner may chmod its own file");
    });
    assert_eq!(mode_of(&path), 0o4755);
    assert_eq!(
        mode_of(&host),
        0o0755,
        "and the host file behind it never gained the bit"
    );
}

// ---------------------------------------------------------------------------
// Criterion 3 — the wire census
// ---------------------------------------------------------------------------

/// What one guest kernel put on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    /// A write, with the flags the kernel set on it and how much it carried.
    Write { flags: u32, len: u32 },
    /// An attribute change, with what it declared valid and the mode it named.
    Setattr { valid: u32, mode: u32 },
}

/// A frame-aware tcp front for the server's unix socket that records the
/// requests passing through it.
///
/// The relay in `replay.rs` is the precedent, and the reason is the same: a
/// claim about what the *kernel* sent cannot be checked against the client's
/// own bookkeeping, because the client is what would be at fault. Frames are
/// read with the protocol crate's own types, so nothing here parses by hand.
struct WireCensus {
    address: SocketAddr,
    sent: Arc<Mutex<Vec<Sent>>>,
}

impl WireCensus {
    /// Starts a relay in front of the server's unix data socket.
    fn start(server: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
        let address = listener.local_addr().expect("a bound address");
        let sent = Arc::new(Mutex::new(Vec::new()));
        let recording = Arc::clone(&sent);
        let server = server.to_path_buf();
        thread::spawn(move || {
            while let Ok((client, _)) = listener.accept() {
                let sent = Arc::clone(&recording);
                let server = server.clone();
                thread::spawn(move || serve(client, &server, &sent));
            }
        });
        Self { address, sent }
    }

    /// The url a mount dials to reach the server through the census.
    fn url(&self, namespace: &str, subpath: &str) -> String {
        format!("voidport://{}/@{namespace}{subpath}", self.address)
    }

    /// Forgets everything recorded so far, so one case is counted alone.
    fn reset(&self) {
        self.sent.lock().expect("unpoisoned").clear();
    }

    /// Everything recorded since the last reset.
    fn taken(&self) -> Vec<Sent> {
        self.sent.lock().expect("unpoisoned").clone()
    }

    /// Just the writes.
    fn writes(&self) -> Vec<(u32, u32)> {
        self.taken()
            .into_iter()
            .filter_map(|record| match record {
                Sent::Write { flags, len } => Some((flags, len)),
                Sent::Setattr { .. } => None,
            })
            .collect()
    }

    /// Just the modes attribute changes carried.
    fn modes(&self) -> Vec<u32> {
        self.taken()
            .into_iter()
            .filter_map(|record| match record {
                Sent::Setattr { valid, mode } if valid & setattr_valid::MODE != 0 => {
                    Some(mode & PERMISSIONS)
                }
                _ => None,
            })
            .collect()
    }
}

/// Pumps one accepted connection in both directions, recording requests.
///
/// Whichever direction ends first ends the other, so neither pump is left
/// parked on a peer that has gone away.
fn serve(client: TcpStream, server: &Path, sent: &Arc<Mutex<Vec<Sent>>>) {
    let Ok(upstream) = UnixStream::connect(server) else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let (Ok(from_client), Ok(to_client)) = (client.try_clone(), client.try_clone()) else {
        return;
    };
    let (Ok(from_server), Ok(to_server)) = (upstream.try_clone(), upstream.try_clone()) else {
        return;
    };
    let requests = {
        let sent = Arc::clone(sent);
        let ends = (client.try_clone(), upstream.try_clone());
        thread::spawn(move || {
            let _ = pump(from_client, to_server, |frame| record(frame, &sent));
            if let (Ok(client), Ok(server)) = ends {
                let _ = client.shutdown(Shutdown::Both);
                let _ = server.shutdown(Shutdown::Both);
            }
        })
    };
    let _ = pump(from_server, to_client, |_| {});
    let _ = client.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
    let _ = requests.join();
}

/// Records one request frame, if it is one of the two this census counts.
fn record(frame: &[u8], sent: &Arc<Mutex<Vec<Sent>>>) {
    let Ok(parsed) = Frame::parse(frame, MAX_FRAME_LEN) else {
        return;
    };
    if parsed.kind() != FrameKind::Request {
        return;
    }
    let record = if let Ok(write) = parsed.request::<WriteRequest>() {
        Sent::Write {
            flags: write.body().write_flags.get(),
            len: write.body().data_len.get(),
        }
    } else if let Ok(setattr) = parsed.request::<SetattrRequest>() {
        Sent::Setattr {
            valid: setattr.body().valid.get(),
            mode: setattr.body().mode.get(),
        }
    } else {
        return;
    };
    sent.lock().expect("unpoisoned").push(record);
}

/// Copies whole frames from one stream to another, showing each to `seen`.
fn pump(mut from: impl Read, mut to: impl Write, seen: impl Fn(&[u8])) -> io::Result<()> {
    loop {
        let mut header = [0u8; FRAME_HEADER_LEN];
        if from.read_exact(&mut header).is_err() {
            return Ok(());
        }
        let len = FrameHeader::ref_from_prefix(&header)
            .ok()
            .map(|(header, _)| header.len.get() as usize)
            .filter(|len| *len >= FRAME_HEADER_LEN)
            .ok_or_else(|| io::Error::other("a frame with an impossible length"))?;
        let mut frame = vec![0u8; len];
        frame[..FRAME_HEADER_LEN].copy_from_slice(&header);
        from.read_exact(&mut frame[FRAME_HEADER_LEN..])?;
        seen(&frame);
        to.write_all(&frame)?;
    }
}

/// The mark the guest kernel sets on a direct-io write arrives on every chunk,
/// is absent for a caller holding the file-mode privilege, and coexists with
/// the kernel's own stripping — which is what "no capability is negotiated"
/// looks like from the wire.
///
/// The two halves are one measurement. A kernel that had been told the server
/// handles the kill would stop doing its own: the page-cached write would carry
/// the mark instead of an explicit mode change. Seeing the mark on the direct
/// path *and* the kernel's own mode change on the cached path is the state that
/// only holds when nothing was negotiated.
#[test]
fn the_wire_census_finds_the_mark_on_direct_writes_and_the_kernel_still_strips_its_own() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("privbits-census");
    let census = WireCensus::start(fixture.server.data_unix());

    // The direct-io half.
    let direct = fixture.mount_with(
        "census-direct",
        &census.url("plain", "/tree"),
        &options(true),
    );
    let path = seed(direct.root(), "census-direct.bin", BOTH_BITS);

    census.reset();
    let asked = path.clone();
    as_unprivileged(move || {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&asked)
            .expect("writable");
        file.write_all(&vec![b'x'; SPLIT_WRITE])
            .expect("the split write lands");
    });
    let split = census.writes();
    assert!(
        split.len() > 1,
        "a {SPLIT_WRITE}-byte write should not fit one frame, but the census saw {split:?}"
    );
    assert_eq!(
        split.len(),
        split
            .iter()
            .filter(|(flags, _)| flags & write_flags::PRIVILEGED_STRIP != 0)
            .count(),
        "every chunk of the split write carries the mark, not just the first: {split:?}"
    );
    assert_eq!(
        split.iter().map(|(_, len)| *len as usize).sum::<usize>(),
        SPLIT_WRITE,
        "and the chunks are the whole write"
    );

    // The same file, a caller that holds the file-mode privilege: no mark.
    census.reset();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("writable");
    file.write_all(b"x").expect("the write lands");
    drop(file);
    let privileged = census.writes();
    assert!(!privileged.is_empty(), "the write reached the wire");
    assert!(
        privileged
            .iter()
            .all(|(flags, _)| flags & write_flags::PRIVILEGED_STRIP == 0),
        "a caller holding CAP_FSETID is marked by nobody: {privileged:?}"
    );

    // A truncate on the same mount: the kernel's own path, alive under direct
    // I/O too, carrying an explicit mode instead of a mark. The writes above
    // already took the bits off this file, so it starts the case where it
    // started the last one.
    let path = seed(direct.root(), "census-truncate.bin", BOTH_BITS);
    census.reset();
    let asked = path.clone();
    as_unprivileged(move || {
        std::fs::OpenOptions::new()
            .write(true)
            .open(&asked)
            .expect("writable")
            .set_len(0)
            .expect("the truncate lands");
    });
    assert!(
        census.modes().contains(&(BOTH_BITS & !0o6000)),
        "a truncate strips through the kernel's own mode change: {:?}",
        census.taken()
    );

    // The page-cached half.
    let cached = fixture.mount_with(
        "census-cached",
        &census.url("plain", "/tree"),
        &options(false),
    );
    let path = seed(cached.root(), "census-cached.bin", BOTH_BITS);
    census.reset();
    let asked = path.clone();
    as_unprivileged(move || {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&asked)
            .expect("writable");
        file.write_all(b"x").expect("the write lands");
    });
    let writes = census.writes();
    assert!(!writes.is_empty(), "the write reached the wire");
    assert!(
        writes
            .iter()
            .all(|(flags, _)| flags & write_flags::PRIVILEGED_STRIP == 0),
        "the kernel does not mark a page-cached write: {writes:?}"
    );
    assert!(
        census.modes().contains(&(BOTH_BITS & !0o6000)),
        "it strips through its own mode change instead, which is the capability nobody \
         negotiated away: {:?}",
        census.taken()
    );
}

// ---------------------------------------------------------------------------
// Criterion 4 — the mount option
// ---------------------------------------------------------------------------

/// `--no-privileged-bits` masks presentation, refuses a chmod that would set a
/// bit, and leaves recorded truth exactly where it was when a read-modify-write
/// chmod comes back through it.
///
/// The last part is the one that needs two mounts to show at all: the opted-out
/// mount was shown a mode without the bits, so a chmod carrying the mode it
/// read back would tell the server to delete a record the other mount still
/// presents. It does not, because the client puts the bits the server holds
/// back into the mode it sends.
#[test]
fn an_opted_out_mount_masks_refuses_and_keeps_the_record() {
    if !support::preflight() {
        return;
    }
    let fixture = Fixture::start("privbits-mount-option");
    let presenting = fixture.mount_with(
        "presenting",
        &fixture.tcp_url("plain", "/tree"),
        &options(false),
    );
    let opted_out = fixture.mount_with(
        "opted-out",
        &fixture.tcp_url("plain", "/tree"),
        &MountOptions {
            privileged_bits: false,
            ..options(false)
        },
    );

    let seeded = seed(presenting.root(), "option.bin", 0o0644);
    std::fs::set_permissions(&seeded, std::fs::Permissions::from_mode(0o6755))
        .expect("a chmod that sets both bits succeeds");
    assert_eq!(mode_of(&seeded), 0o6755);

    let masked = opted_out.path("option.bin");
    assert_eq!(
        mode_of(&masked),
        0o0755,
        "the opted-out mount shows no privileged bits at all"
    );
    assert_eq!(
        errno(
            &std::fs::set_permissions(&masked, std::fs::Permissions::from_mode(0o4755))
                .expect_err("a mount that shows no bits takes none either")
        ),
        rustix::io::Errno::PERM.raw_os_error()
    );

    // The read-modify-write: the mode this mount was shown, with one permission
    // bit changed, sent back.
    let read_back = mode_of(&masked);
    assert_eq!(read_back, 0o0755);
    std::fs::set_permissions(&masked, std::fs::Permissions::from_mode(0o0700))
        .expect("a plain chmod through an opted-out mount still works");
    assert_eq!(mode_of(&masked), 0o0700, "and takes effect");
    assert_eq!(
        mode_of(&seeded),
        0o6700,
        "while the mount that presents them still presents them: masked, never discarded"
    );
    assert_eq!(
        mode_of(&fixture.host("tree/option.bin")),
        0o0700,
        "and the host file behind it never carried a privileged bit"
    );
}
