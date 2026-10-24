//! Every unprivileged caller here is a thread that dropped its effective uid,
//! and every mount such a thread reaches is mounted with `allow_other`, so the
//! refusal under test is never the owner check of FUSE.

use voidport_test_client as support;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use support::{Fixture, Guest, NOBODY_ID, errno};
use voidport::mount::MountOptions;
use voidport_proto::frame::{Frame, FrameKind, Parsed};
use voidport_proto::ops::file::{WriteRequest, write_flags};
use voidport_proto::ops::node::{SetattrRequest, setattr_valid};

const PERMISSIONS: u32 = 0o7777;

/// Group-execute makes setgid a real setgid instead of the mandatory-locking
/// mark. The write bits are open to the group because the unprivileged caller
/// keeps the group membership of the process and the files are group-owned by
/// it: the group class decides.
const BOTH_BITS: u32 = 0o6777;

/// The same, with group-execute cleared: setgid here is mandatory locking, and
/// only setuid goes.
const LOCKING_SETGID: u32 = 0o6767;

/// The frame bound is one mebibyte, so four of them cannot be one request.
const SPLIT_WRITE: usize = 4 * 1024 * 1024;

/// An id no caller in this suite is a member of, used as a file's group so that
/// a chmod by its owner is a chmod by somebody outside its group.
const FOREIGN_GROUP: u32 = 65534;

/// Per-thread credentials: only this thread drops privilege. Dropping the
/// effective uid also empties the effective capability set, and `CAP_FSETID` is
/// what the strip predicate of the kernel asks about.
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

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("{} should stat: {error}", path.display()))
        .permissions()
        .mode()
        & PERMISSIONS
}

/// The mode is set explicitly after the create, because no umask may decide
/// what the case starts from, and a create cannot carry setuid through
/// `File::create`.
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

/// The zero attribute timeout is deliberate: a suite comparing semantics
/// against a local directory must not measure the window of the attribute TTL.
fn options() -> MountOptions {
    MountOptions {
        attr_timeout: Duration::ZERO,
        allow_other: true,
        ..MountOptions::default()
    }
}

struct Arena {
    local: PathBuf,
    mounted: Guest,
}

impl Arena {
    fn new(fixture: &Fixture) -> Self {
        Self {
            local: fixture.directory.directory("local"),
            mounted: fixture.mount_with("mounted", &fixture.tcp_url("plain", "/tree"), &options()),
        }
    }

    /// Each place gets a separate file name, so the control is a separate file.
    fn compare(&self, name: &str, mode: u32, sequence: impl Fn(&Path)) -> (u32, u32) {
        let run = |directory: &Path, label: &str| {
            let path = seed(directory, &format!("{name}-{label}.bin"), mode);
            sequence(&path);
            mode_of(&path)
        };
        (
            run(&self.local, "local"),
            run(self.mounted.root(), "mounted"),
        )
    }
}

fn agrees(what: &str, (local, mounted): (u32, u32)) {
    assert_eq!(
        mounted, local,
        "{what}: the mount left {mounted:o} where a local directory leaves {local:o}"
    );
}

/// The predicate of the kernel is mode-only: setuid always goes, setgid goes
/// only where group-execute is set. The kernel applies it and sends the
/// resulting mode, and the control directory shows what it does locally.
#[test]
fn a_write_strips_what_a_local_directory_strips() {
    support::preflight();
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

/// Truncate is not the write path: the kernel turns the kill into an explicit
/// mode change and sends it as a `setattr`. Nothing in the client is involved.
#[test]
fn a_truncate_clears_what_a_local_directory_clears() {
    support::preflight();
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

/// No wire field could carry this predicate: whether the caller is a member of
/// the file's group. `default_permissions` makes the guest kernel evaluate it
/// under the full credentials of the caller and hand the server the post-VFS
/// mode. The test observes that the delivered mode arrives without the bit, as
/// the mode the mount presents afterwards.
#[test]
fn an_out_of_group_chmod_arrives_stripped_by_the_guest_kernel() {
    support::preflight();
    let fixture = Fixture::start("privbits-out-of-group");
    // Owned by the unprivileged caller so that the chmod is permitted, and
    // grouped somewhere that caller is not a member of. Both are set on the
    // host: the namespace passes ownership through.
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
        &options(),
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

    // The bit the group predicate does not govern: setuid arrives, is recorded
    // and is presented, so the case above is a stripped mode and not a refused
    // chmod.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    Write { flags: u32, len: u32 },
    Setattr { valid: u32, mode: u32 },
}

/// A claim about what the kernel sent cannot be checked against the bookkeeping
/// of the client, because the client is what would be at fault.
struct WireCensus {
    address: SocketAddr,
    sent: Arc<Mutex<Vec<Sent>>>,
}

impl WireCensus {
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

    fn url(&self, namespace: &str, subpath: &str) -> String {
        support::tcp_url(self.address, namespace, subpath)
    }

    fn reset(&self) {
        self.sent.lock().expect("unpoisoned").clear();
    }

    fn taken(&self) -> Vec<Sent> {
        self.sent.lock().expect("unpoisoned").clone()
    }

    fn writes(&self) -> Vec<(u32, u32)> {
        self.taken()
            .into_iter()
            .filter_map(|record| match record {
                Sent::Write { flags, len } => Some((flags, len)),
                Sent::Setattr { .. } => None,
            })
            .collect()
    }

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

/// Whichever direction ends first ends the other, so neither pump is left
/// parked on a peer that has gone away.
fn serve(client: TcpStream, server: &Path, sent: &Arc<Mutex<Vec<Sent>>>) {
    let Ok(upstream) = UnixStream::connect(server) else {
        let _peer_may_be_gone = client.shutdown(Shutdown::Both);
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
            pump(from_client, to_server, |frame| record(frame, &sent));
            if let (Ok(client), Ok(server)) = ends {
                let _client_side_may_be_shut_already = client.shutdown(Shutdown::Both);
                let _server_side_may_be_shut_already = server.shutdown(Shutdown::Both);
            }
        })
    };
    pump(from_server, to_client, |_| {});
    let _client_side_may_be_shut_already = client.shutdown(Shutdown::Both);
    let _server_side_may_be_shut_already = upstream.shutdown(Shutdown::Both);
    let _panic_was_printed = requests.join();
}

fn record(frame: &[u8], sent: &Arc<Mutex<Vec<Sent>>>) {
    // A write's data follows its frame; the frame is what is counted.
    let Ok(Parsed::Frame(parsed)) = Frame::parse_prefix(frame, &voidport_proto::limits::LIMITS)
    else {
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

/// Returns once either side ends.
fn pump(mut from: impl Read, mut to: impl Write, seen: impl Fn(&[u8])) {
    while let Ok(frame) = support::read_message(&mut from) {
        seen(&frame);
        if to.write_all(&frame).is_err() {
            return;
        }
    }
}

/// A kernel told that the server handles the kill would stop doing its own: the
/// page-cached write would carry the mark instead of an explicit mode change.
/// The mark on the uncached path and the mode change of the kernel on the
/// cached path only hold together when nothing was negotiated. A file is
/// uncached while a host writer has it open, because the server cannot lease it
/// then.
#[test]
fn the_wire_census_finds_the_mark_on_uncached_writes_and_the_kernel_still_strips_its_own() {
    support::preflight();
    let fixture = Fixture::start("privbits-census");
    let census = WireCensus::start(fixture.server.data_unix());
    let mounted = fixture.mount_with("census", &census.url("plain", "/tree"), &options());

    let path = seed(mounted.root(), "census-uncached.bin", BOTH_BITS);
    let _host_writer = std::fs::OpenOptions::new()
        .write(true)
        .open(fixture.host("tree/census-uncached.bin"))
        .expect("the host writer opens");

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

    // A truncate of an uncached file sends an explicit mode instead of a mark.
    let path = seed(mounted.root(), "census-truncate.bin", BOTH_BITS);
    let _truncate_host_writer = std::fs::OpenOptions::new()
        .write(true)
        .open(fixture.host("tree/census-truncate.bin"))
        .expect("the host writer opens");
    census.reset();
    as_unprivileged(move || {
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("writable")
            .set_len(0)
            .expect("the truncate lands");
    });
    assert!(
        census.modes().contains(&(BOTH_BITS & !0o6000)),
        "a truncate strips through the kernel's own mode change: {:?}",
        census.taken()
    );

    let path = seed(mounted.root(), "census-cached.bin", BOTH_BITS);
    census.reset();
    as_unprivileged(move || {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
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

/// The last part needs two mounts to show: the opted-out mount was shown a mode
/// without the bits, so a chmod carrying the mode it read back would tell the
/// server to delete a record the other mount still presents. The client puts
/// the bits the server has back into the mode it sends.
#[test]
fn an_opted_out_mount_masks_refuses_and_keeps_the_record() {
    support::preflight();
    let fixture = Fixture::start("privbits-mount-option");
    let presenting =
        fixture.mount_with("presenting", &fixture.tcp_url("plain", "/tree"), &options());
    let opted_out = fixture.mount_with(
        "opted-out",
        &fixture.tcp_url("plain", "/tree"),
        &MountOptions {
            privileged_bits: false,
            ..options()
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
