//! What each class actually does to the filesystem.
//!
//! One function per class, each shaped the same way: it is handed a worker's
//! own state and performs **one operation**, which is the unit the latency
//! ceilings and the progress watchdog are stated in. Operations are small on
//! purpose — a tree walk yields one directory at a time, not one whole
//! walk — so a stalled class is visible in seconds instead of at the end of
//! whatever it was doing.
//!
//! Failure is expected here and is not an error. Every class runs beside every
//! other, so a name a walk is about to stat may already be unlinked, a mount a
//! reader is using may be coming down, and a lock a waiter wants may be held.
//! Each operation reports its errno and the invariant layer decides which of
//! them mean the filesystem is working (`ENOENT`, `EEXIST`, `EBUSY`) and which
//! mean it broke (`EIO`, `ENOTCONN`).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use voidport::mount::MountOptions;
use voidport::url::{Endpoint, MountUrl};
use voidport_control::{
    Client, ErrorCode, Listener, NamespaceName, Reply, Request, Response, Rule, ShareMode,
    XattrRule, XattrVerdict,
};

use crate::invariant::{Findings, Outage, Violation};
use crate::metrics::Class;
use crate::mounts::{Fleet, TortureMount};
use crate::server::{Stop, Supervisor};
use crate::wire;

/// The record an append worker writes.
const APPEND_RECORD: usize = 128;

/// The block a churn or contention worker writes.
const BLOCK: usize = 4096;

/// The block a streamed-write worker writes and reads back in one operation.
///
/// Several chunk units, so every operation of the class really is a window of
/// chunks on the wire and not a single one wearing the name.
const STREAM_BLOCK: usize = 512 * 1024;

/// The chunk unit the streamed-write class mounts with.
///
/// The readahead engine's measured chunk, which is the nearest measured number
/// this client has until the write matrix sets its own.
const STREAM_UNIT: usize = 128 * 1024;

/// How many blocks a streamed-write worker cycles its file through.
const STREAM_BLOCKS: u64 = 4;

/// How many owners one lock-storm worker stacks on the shared file.
///
/// This is the multiplier that makes the storm a storm: at the default
/// intensity it is already hundreds of waiters, and it scales with intensity
/// into the thousands the design names.
pub const LOCK_OWNERS_PER_WORKER: u64 = 64;

/// How long a lock-storm worker waits for a reply before calling the server
/// unresponsive and reconnecting.
const LOCK_REPLY_PATIENCE: Duration = Duration::from_secs(30);

/// How long a policy change is given to bind.
///
/// Policy binds at the *next lookup*, and the guest kernel holds an entry for
/// its cache lifetime, so a name hidden this instant legitimately keeps
/// resolving for up to that lifetime. This is that bound with a wide margin for
/// a machine under the whole harness at once: past it, the name did not stop
/// resolving because of caching, it did not stop resolving at all.
const POLICY_PATIENCE: Duration = Duration::from_secs(20);

/// How often a bounded wait looks again.
const POLL: Duration = Duration::from_millis(50);

/// How long a listener class waits between cycles.
///
/// Every add and every removal persists the state file, so an unpaced listener
/// worker would be a `fsync` storm and not listener churn.
const LISTENER_CADENCE: Duration = Duration::from_millis(200);

/// How long the listener class gives a handshake on an endpoint it just made.
const LISTENER_PATIENCE: Duration = Duration::from_secs(10);

/// How often the restart arm wakes to look at its clock.
///
/// Small on purpose: this is what a restart worker's operation costs when no
/// restart is due, so it is also how long the teardown waits for that worker.
const RESTART_SLICE: Duration = Duration::from_millis(250);

/// How long every mount is given to serve again once the server is back.
///
/// A mount heals in a second or so — the entry cache expires, the kernel
/// retries the walk from the root, the reconnect task has long since installed
/// the new connection. This is the bound past which it is not healing at all.
pub(crate) const HEAL_PATIENCE: Duration = Duration::from_secs(45);

/// How often the special-file class checks the owner of what it made.
///
/// A sample, not every operation: the ownership policy is a property of the
/// server's presentation, not of the individual node, so checking one in
/// sixteen proves the same thing at a fraction of the syscalls.
const OWNER_SAMPLE: u64 = 16;

/// The names the working set is built under, all relative to a mount root.
pub mod names {
    /// The static tree the walkers walk.
    pub const TREE: &str = "torture-tree";
    /// The one crowded directory the listing storm lists.
    pub const CROWDED: &str = "torture-crowded";
    /// Files every mount shares: the lock target, the append log, the
    /// contention set.
    pub const SHARED: &str = "torture-shared";
    /// Per-worker scratch, one directory per worker.
    pub const WORK: &str = "torture-work";
    /// The file the lock storm contends for.
    pub const LOCK_FILE: &str = "torture-shared/lock.target";
    /// The file the append storm appends to.
    pub const APPEND_FILE: &str = "torture-shared/append.log";
}

/// How large the working set is.
#[derive(Clone, Copy, Debug)]
pub struct Seed {
    /// Directories in the static tree.
    pub tree_dirs: u64,
    /// Files in each of them.
    pub tree_files: u64,
    /// Entries in the crowded directory.
    pub crowded: u64,
    /// Files the contention class shares.
    pub contended: u64,
    /// Files each open/close worker cycles through.
    pub open_set: u64,
}

impl Default for Seed {
    fn default() -> Self {
        Self {
            tree_dirs: 8,
            tree_files: 32,
            crowded: 512,
            contended: 8,
            open_set: 32,
        }
    }
}

impl Seed {
    /// How many entries the working set holds, which is what the node and
    /// descriptor bounds are stated relative to.
    #[must_use]
    pub fn entries(&self) -> u64 {
        self.tree_dirs * (self.tree_files + 1) + self.crowded + self.contended + 16
    }

    /// Builds the working set through one mount.
    ///
    /// Everything is created through the filesystem under test, because a
    /// working set written behind the mount's back would be a working set the
    /// server never admitted.
    ///
    /// # Errors
    ///
    /// Returns the first failure to create it.
    pub fn build(&self, root: &Path) -> io::Result<()> {
        for directory in [names::TREE, names::CROWDED, names::SHARED, names::WORK] {
            fs::create_dir_all(root.join(directory))?;
        }
        for directory in 0..self.tree_dirs {
            let path = root.join(names::TREE).join(format!("dir-{directory}"));
            fs::create_dir_all(&path)?;
            for file in 0..self.tree_files {
                write_if_absent(&path.join(format!("file-{file}")), b"torture")?;
            }
        }
        for entry in 0..self.crowded {
            write_if_absent(
                &root.join(names::CROWDED).join(format!("entry-{entry}")),
                b"torture",
            )?;
        }
        write_if_absent(&root.join(names::LOCK_FILE), &[0u8; 64])?;
        write_if_absent(&root.join(names::APPEND_FILE), &[])?;
        for file in 0..self.contended {
            write_if_absent(
                &root.join(names::SHARED).join(format!("contend-{file}")),
                &vec![0u8; BLOCK * 4],
            )?;
        }
        Ok(())
    }
}

/// Creates a file with these contents unless it is already there.
fn write_if_absent(path: &Path, contents: &[u8]) -> io::Result<()> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => file.write_all(contents),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

/// What one worker carries between its operations.
///
/// A worker is a thread that does one class's operation over and over, so
/// whatever it would otherwise rebuild every time — a walk's stack, a lock
/// storm's session, an open/close set — lives here.
#[derive(Debug)]
pub enum State {
    /// A walk in progress, as a stack of directories still to visit.
    Walk(Vec<PathBuf>),
    /// A rotating counter, for the classes whose next operation is only a
    /// number away.
    Counter(u64),
    /// A lock storm's connection and the owners it has in flight.
    Storm(Box<Storm>),
    /// The restart arm's clock: when the next restart is due, and how many it
    /// has already performed — which is also what decides whether the next one
    /// is graceful or hard.
    Restarts {
        /// When the next restart is due; `None` before the first is scheduled.
        due: Option<Instant>,
        /// How many have been performed.
        performed: u64,
    },
    /// The listener arm's bookkeeping: the endpoints it added and has not seen
    /// removed. A cycle the server died in the middle of leaves one, and the
    /// next cycle takes it out.
    Listeners(Vec<String>),
    /// The streamed-write arm's own mount, and where it is writing next.
    Stream(Box<Streaming>),
    /// Nothing to carry.
    Empty,
}

/// One streamed-write worker's mount and its place in the file.
///
/// The mount is the worker's own because the engine runs in one posture only —
/// direct data caching, with a chunk unit — and the run's own mounts carry the
/// defaults. It is made on the first operation and kept for the rest of the
/// run, and it is let go whenever an operation fails, so the next one works
/// through a mount that was made against whatever server is there now.
#[derive(Debug, Default)]
pub struct Streaming {
    mount: Option<TortureMount>,
    counter: u64,
}

impl State {
    /// The state a class's worker starts with.
    #[must_use]
    pub fn for_class(class: Class) -> Self {
        match class {
            Class::Walk => Self::Walk(Vec::new()),
            Class::Locks => Self::Storm(Box::default()),
            Class::Churn
            | Class::Rename
            | Class::OpenClose
            | Class::Contend
            | Class::Xattr
            | Class::Special
            | Class::Rules => Self::Counter(0),
            Class::Listeners => Self::Listeners(Vec::new()),
            Class::Stream => Self::Stream(Box::default()),
            Class::Restart => Self::Restarts {
                due: None,
                performed: 0,
            },
            Class::List | Class::Append | Class::Remount => Self::Empty,
        }
    }

    /// The walk stack, or an empty one for a state that is not a walk.
    fn walk(&mut self) -> &mut Vec<PathBuf> {
        match self {
            Self::Walk(stack) => stack,
            _ => unreachable!("a walk worker carries a walk stack"),
        }
    }

    /// The rotating counter, advanced by one.
    fn next(&mut self) -> u64 {
        match self {
            Self::Counter(counter) => {
                *counter = counter.wrapping_add(1);
                *counter
            }
            _ => unreachable!("this class's worker carries a counter"),
        }
    }
}

/// One lock-storm worker's connection and its owners in flight.
#[derive(Debug, Default)]
pub struct Storm {
    session: Option<wire::Session>,
    handle: u64,
    /// The request id of every lock request awaiting a reply, and the owner it
    /// belongs to.
    locking: Vec<(u64, u64)>,
    /// The same for the releases.
    unlocking: Vec<(u64, u64)>,
}

/// Everything a worker's operation may reach.
pub struct Site<'a> {
    /// The mounts the run holds open, in the order they were made.
    pub mounts: &'a [TortureMount],
    /// Where the cycling class mounts from.
    pub fleet: &'a Fleet,
    /// This worker's index within its class.
    pub index: u64,
    /// The working set's shape.
    pub seed: Seed,
    /// The server the run owns, for the class whose operation is a restart.
    /// Absent when the run was pointed at a server somebody else runs.
    pub server: Option<&'a Supervisor>,
    /// The server's control socket, for the classes that change its policy.
    pub control: Option<&'a Path>,
    /// Where a worker files a contract it proved wrong.
    pub findings: &'a Findings,
    /// The windows in which the restart arm took the server away.
    pub outage: &'a Outage,
    /// When the run started, so a worker can stamp what it files.
    pub started: Instant,
    /// How long the restart arm leaves between restarts.
    pub restart_interval: Duration,
}

/// Which of the run's mounts a worker of this index works through.
///
/// The one selector: a worker's mount, its neighbour's mount and its URL are
/// all stated in terms of this, so no two of them can be dealt out over
/// different lengths and end up naming different servers.
const fn mount_index(index: u64, mounts: usize) -> usize {
    (index as usize) % mounts
}

impl Site<'_> {
    /// The mount this worker works through, which is its own share of them.
    fn mount(&self) -> &Path {
        self.mounts[mount_index(self.index, self.mounts.len())].root()
    }

    /// A mount other than [`Self::mount`], so the contention class really does
    /// contend across mounts, not within one.
    fn other_mount(&self) -> &Path {
        self.mounts[mount_index(self.index + 1, self.mounts.len())].root()
    }

    /// The URL this worker's own mount was made from.
    ///
    /// Taken from the mount and never from the fleet by worker index: the
    /// mounts are dealt out over the URLs and the workers are dealt out over
    /// the mounts, so a worker that indexed the URLs itself would — whenever
    /// the two lengths do not divide — be adding rules to one namespace while
    /// looking for their effect through a mount of another.
    fn url(&self) -> &MountUrl {
        self.mounts[mount_index(self.index, self.mounts.len())].url()
    }

    /// This worker's own scratch directory, relative to a mount root.
    fn scratch_name(&self, class: Class) -> String {
        format!("{}/{}-{}", names::WORK, class.name(), self.index)
    }

    /// This worker's own scratch directory, created on first use.
    fn scratch(&self, class: Class) -> io::Result<PathBuf> {
        let path = self.mount().join(self.scratch_name(class));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// The namespace path of something `relative` to a mount root.
    ///
    /// A mount is a namespace *subpath*, so the name a rule is keyed by is not
    /// the name a mounted guest uses: the subpath the URL named goes in front.
    fn namespace_path(&self, relative: &str) -> String {
        let subpath = String::from_utf8_lossy(&self.url().subpath).into_owned();
        format!("{}/{relative}", subpath.trim_end_matches('/'))
    }

    /// The namespace this worker's own mount is a view of.
    fn namespace(&self) -> &NamespaceName {
        &self.url().namespace
    }

    /// Milliseconds into the run.
    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Files a contract this worker proved wrong.
    fn prove_wrong(&self, class: Class, detail: String) {
        self.findings.file(Violation::Contract {
            class,
            detail,
            elapsed_ms: self.elapsed_ms(),
        });
    }

    /// How many times the server has gone away and come back.
    ///
    /// The control classes take this before they start a cycle and check it
    /// again at every step: a cycle whose two halves saw two different server
    /// lifetimes proves nothing about either, so it is abandoned instead of
    /// judged.
    fn server_generation(&self) -> u64 {
        self.outage.generation()
    }

    /// Whether the cycle that started at `generation` is still about one
    /// server lifetime.
    fn same_server(&self, generation: u64) -> bool {
        !self.outage.open_now() && self.server_generation() == generation
    }

    /// One control-plane call, made while the restart arm is not signalling.
    ///
    /// A connection or transport failure is an ordinary operation failure: the
    /// server may be going away underneath, which the restart class is there to
    /// make happen. A *structured refusal* is not — the server answered, and
    /// answering "no" to a mutation this class is allowed to make is the
    /// server-side error class this run forbids. `tolerated` names the codes
    /// this call is allowed to be refused with anyway.
    fn control_call(
        &self,
        class: Class,
        request: &Request,
        tolerated: &[ErrorCode],
    ) -> io::Result<Option<Reply>> {
        let socket = self
            .control
            .ok_or_else(|| io::Error::other("this run has no control socket"))?;
        let _mutating = self.server.map(Supervisor::mutating);
        let mut client = Client::connect(socket).map_err(io::Error::other)?;
        let answer = client.call(request).map_err(io::Error::other)?;
        match answer.response {
            Response::Ok { result } => Ok(Some(result)),
            Response::Error { error } if tolerated.contains(&error.code) => Ok(None),
            Response::Error { error } => {
                // A refusal that arrived while the server was being replaced is
                // about the replacement, not about the request.
                if !self.outage.open_now() {
                    self.prove_wrong(
                        class,
                        format!(
                            "the server refused {} with {}: {}",
                            request.operation(),
                            error.code.as_str(),
                            error.message
                        ),
                    );
                }
                Err(io::Error::other(format!(
                    "{} refused: {}",
                    request.operation(),
                    error.code.as_str()
                )))
            }
        }
    }
}

/// Polls until `condition` holds, or the patience runs out.
fn eventually(patience: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + patience;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL);
    }
}

/// Performs one operation of `class`.
///
/// # Errors
///
/// Returns whatever the filesystem said. The caller records it; almost none of
/// them are violations.
pub fn step(class: Class, site: &Site<'_>, state: &mut State) -> io::Result<()> {
    match class {
        Class::Walk => walk(site, state),
        Class::List => list(site),
        Class::Churn => churn(site, state),
        Class::Locks => locks(site, state),
        Class::Append => append(site),
        Class::Xattr => xattr(site, state),
        Class::Rename => rename(site, state),
        Class::OpenClose => open_close(site, state),
        Class::Remount => remount(site),
        Class::Contend => contend(site, state),
        Class::Restart => restart(site, state),
        Class::Special => special(site, state),
        Class::Rules => rules(site, state),
        Class::Listeners => listeners(site, state),
        Class::Stream => streamed_write(site, state),
    }
}

/// One directory of a tree walk: read it, stat what it holds, queue its
/// subdirectories.
fn walk(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let root = site.mount().to_path_buf();
    let stack = state.walk();
    let directory = stack.pop().unwrap_or(root);
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        // A name another class is churning may already be gone, which is the
        // filesystem being right, not an error to abandon the walk for.
        if let Ok(metadata) = entry.metadata()
            && metadata.is_dir()
        {
            stack.push(entry.path());
        }
    }
    Ok(())
}

/// One full listing of the crowded directory.
fn list(site: &Site<'_>) -> io::Result<()> {
    let mut entries = 0;
    for entry in fs::read_dir(site.mount().join(names::CROWDED))? {
        entry?;
        entries += 1;
    }
    debug_assert!(entries >= 0);
    Ok(())
}

/// One create-write-close-unlink cycle.
fn churn(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let scratch = site.scratch(Class::Churn)?;
    let counter = state.next();
    let path = scratch.join(format!("churn-{counter}"));
    let mut file = File::create(&path)?;
    file.write_all(&vec![b'c'; BLOCK])?;
    drop(file);
    fs::remove_file(&path)
}

/// One acquisition from the lock storm.
///
/// The worker keeps [`LOCK_OWNERS_PER_WORKER`] blocking requests stacked on the
/// one shared file at all times: whenever an owner's lock is granted it is
/// released again and the owner re-queues, so the storm is a standing wave of
/// waiters, not a burst. One operation is one *acquisition* — replies to
/// the releases are consumed on the way past.
fn locks(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let State::Storm(storm) = state else {
        unreachable!("a lock worker carries a storm");
    };
    let base = site.index * LOCK_OWNERS_PER_WORKER + 1;
    if storm.session.is_none() {
        let mut session =
            wire::Session::mount(site.url(), LOCK_REPLY_PATIENCE).map_err(io::Error::other)?;
        let node = session
            .lookup(names::SHARED)
            .and_then(|shared| {
                session
                    .lookup_in(shared, "lock.target")
                    .map(|node| (shared, node))
            })
            .map_err(io::Error::other)?;
        storm.handle = session.open(node.1).map_err(io::Error::other)?;
        storm.locking.clear();
        storm.unlocking.clear();
        for owner in base..base + LOCK_OWNERS_PER_WORKER {
            let request = session
                .send_lock(storm.handle, owner, true)
                .map_err(io::Error::other)?;
            storm.locking.push((request, owner));
        }
        storm.session = Some(session);
    }

    let outcome = one_acquisition(storm);
    if outcome.is_err() {
        // A storm worker that lost its footing — a timed-out reply, a closed
        // connection — starts a fresh session instead of limping. Dropping the
        // session releases every lock it held, which is what keeps a failure
        // here from wedging every other worker.
        storm.session = None;
    }
    outcome
}

/// Reads replies until one of them is a granted lock.
fn one_acquisition(storm: &mut Storm) -> io::Result<()> {
    let session = storm
        .session
        .as_mut()
        .ok_or_else(|| io::Error::other("no session"))?;
    loop {
        let (request, status) = session.receive_lock().map_err(io::Error::other)?;
        if let Some(position) = storm
            .locking
            .iter()
            .position(|(pending, _)| *pending == request)
        {
            let (_, owner) = storm.locking.remove(position);
            if status != 0 {
                return Err(io::Error::from_raw_os_error(-status));
            }
            // Granted: let go at once, so the next waiter can have it.
            let request = session
                .send_unlock(storm.handle, owner)
                .map_err(io::Error::other)?;
            storm.unlocking.push((request, owner));
            return Ok(());
        }
        if let Some(position) = storm
            .unlocking
            .iter()
            .position(|(pending, _)| *pending == request)
        {
            let (_, owner) = storm.unlocking.remove(position);
            let request = session
                .send_lock(storm.handle, owner, true)
                .map_err(io::Error::other)?;
            storm.locking.push((request, owner));
        }
    }
}

/// One record appended to the file every appender shares.
fn append(site: &Site<'_>) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(site.mount().join(names::APPEND_FILE))?;
    file.write_all(&[b'a'; APPEND_RECORD])
}

/// The errnos an extended-attribute operation may legitimately answer while a
/// namespace's rules are being changed underneath it.
///
/// A rule change is a live reconfiguration, so a name that was writable when
/// the cycle started may be denied by the time the write lands: `EPERM` is a
/// **policy decision arriving**, not a broken mount. `ENODATA` is the same fact
/// on the read side — a denied read is hidden, so it looks exactly like an
/// attribute that is not there. `EOPNOTSUPP` is the host filesystem saying it
/// does not store the namespace at all (tmpfs before 6.6 for `user.*`), and
/// `EPERM` also covers the kernel's own refusal of `user.*` on a FIFO or a
/// socket, which is a legitimate host answer this class now creates.
///
/// The transport errnos are deliberately absent: those still fail the run.
const XATTR_POLICY_ERRNOS: [rustix::io::Errno; 3] = [
    rustix::io::Errno::PERM,
    rustix::io::Errno::NODATA,
    rustix::io::Errno::OPNOTSUPP,
];

/// Runs one attribute operation, tolerating exactly the policy-legitimate
/// errnos above and propagating everything else.
fn tolerating(outcome: Result<(), rustix::io::Errno>) -> io::Result<()> {
    match outcome {
        Ok(()) => Ok(()),
        Err(errno) if XATTR_POLICY_ERRNOS.contains(&errno) => Ok(()),
        Err(errno) => Err(io::Error::from_raw_os_error(errno.raw_os_error())),
    }
}

/// One set-get-list-remove cycle of an extended attribute, plus one
/// special-file creation.
///
/// The class drives **rule-governed** names on purpose: `user.*`, which the
/// defaults allow writing, and one reserved-namespace name, which they deny —
/// so an operator changing rules mid-run flips real outcomes, not
/// nothing. Each step tolerates the policy errnos and carries on, because the
/// alternative is a class whose throughput collapses the moment a rule denies
/// something, which would make the invariant layer report a defect where the
/// design says there is none.
///
/// The special files ride here too: a FIFO and a socket are created, stat'd and
/// removed each cycle. Nothing opens the FIFO — a reader with no writer blocks
/// forever, and this class holds no second thread to be the other end.
fn xattr(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let scratch = site.scratch(Class::Xattr)?;
    let counter = state.next();
    let path = scratch.join("xattr-target");
    write_if_absent(&path, b"x")?;
    let value = counter.to_le_bytes();
    let path = path.to_string_lossy().into_owned();

    for name in [
        format!("user.torture-{}", counter % 8),
        // A name outside `user.*`: allowed only where a rule says so, which is
        // exactly the churn this class is asked to survive.
        format!("security.torture-{}", counter % 4),
    ] {
        tolerating(rustix::fs::setxattr(
            path.as_str(),
            &name,
            &value,
            rustix::fs::XattrFlags::empty(),
        ))?;
        let mut buffer = [0u8; 64];
        tolerating(rustix::fs::getxattr(path.as_str(), &name, &mut buffer).map(|_| ()))?;
        tolerating(rustix::fs::listxattr(path.as_str(), &mut [0u8; 1024]).map(|_| ()))?;
        tolerating(rustix::fs::removexattr(path.as_str(), &name))?;
    }

    special_files(&scratch, counter).map(|_| ())
}

/// One create-stat-remove cycle of a FIFO and of a socket file.
///
/// Returns what it stat'd, so a caller whose subject is the *ownership* of what
/// it made can look at it; the attribute class ignores the answer.
fn special_files(scratch: &Path, counter: u64) -> io::Result<Vec<(PathBuf, fs::Metadata)>> {
    let mut made = Vec::with_capacity(2);
    for (kind, label) in [
        (rustix::fs::FileType::Fifo, "fifo"),
        (rustix::fs::FileType::Socket, "socket"),
    ] {
        let path = scratch.join(format!("{label}-{counter}"));
        match rustix::fs::mknodat(
            rustix::fs::CWD,
            &path,
            kind,
            rustix::fs::Mode::from_bits_truncate(0o644),
            0,
        ) {
            Ok(()) => {}
            // Another cycle of this worker left the name behind, or the mount
            // is going down under the remount class: both are the filesystem
            // working, and the removal below cleans up either way.
            Err(rustix::io::Errno::EXIST) => {}
            Err(errno) => return Err(io::Error::from_raw_os_error(errno.raw_os_error())),
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.len() > 0 {
            return Err(io::Error::other(format!(
                "{} is a {label} and should hold no data, got {} bytes",
                path.display(),
                metadata.len()
            )));
        }
        fs::remove_file(&path)?;
        made.push((path, metadata));
    }
    Ok(made)
}

/// One create-read-stat-remove cycle of a symbolic link.
///
/// Returns what it stat'd, for the same reason [`special_files`] does. The link
/// target is deliberately a relative name that is not there: a symbolic link is
/// a string the server stores and gives back, and resolving it is the guest
/// kernel's business, not the wire's.
fn symbolic_link(scratch: &Path, counter: u64) -> io::Result<(PathBuf, fs::Metadata)> {
    let path = scratch.join(format!("link-{counter}"));
    let target = format!("target-{counter}");
    match std::os::unix::fs::symlink(&target, &path) {
        Ok(()) => {}
        // The name is this worker's own, so it is here because a previous cycle
        // of this worker left it, which the removal below cleans up either way.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let read = fs::read_link(&path)?;
    if read != Path::new(&target) {
        return Err(io::Error::other(format!(
            "{} was made to point at {target:?} and reads back as {read:?}",
            path.display()
        )));
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_symlink() {
        return Err(io::Error::other(format!(
            "{} was made as a symbolic link and stats as {:?}",
            path.display(),
            metadata.file_type()
        )));
    }
    fs::remove_file(&path)?;
    Ok((path, metadata))
}

/// One cycle of the special-file class: a FIFO, a socket file and a symbolic
/// link, each made, stat'd and removed through a mount.
///
/// This is the mknod surface and the symbolic-link surface under everything
/// else's load, which is the shape a single-purpose test cannot produce. On a
/// sample of the cycles it also checks the **ownership contract**: what the
/// server presents for a node this session just made must be what it presents
/// for the working set the same session made earlier. Stating it that way and
/// not as a fixed uid is what keeps the check true whatever ownership policy
/// the run's namespace carries.
fn special(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let scratch = site.scratch(Class::Special)?;
    let counter = state.next();
    let mut made = special_files(&scratch, counter)?;
    made.push(symbolic_link(&scratch, counter)?);

    if counter.is_multiple_of(OWNER_SAMPLE) {
        let reference = fs::metadata(site.mount().join(names::LOCK_FILE))?;
        for (path, metadata) in &made {
            if (metadata.uid(), metadata.gid()) != (reference.uid(), reference.gid()) {
                site.prove_wrong(
                    Class::Special,
                    format!(
                        "{} is presented as {}:{} where everything else this mount made is {}:{}",
                        path.display(),
                        metadata.uid(),
                        metadata.gid(),
                        reference.uid(),
                        reference.gid()
                    ),
                );
            }
        }
    }
    Ok(())
}

/// One rename-and-unlink-while-open cycle.
///
/// The file is renamed and then removed **with the descriptor still open**, and
/// written and read through afterwards: the inode outlives both names, exactly
/// as it does on a local filesystem, and the server must keep serving the
/// handle after the name it was opened by is gone.
fn rename(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let scratch = site.scratch(Class::Rename)?;
    let counter = state.next();
    let original = scratch.join(format!("rename-{counter}"));
    let renamed = scratch.join(format!("renamed-{counter}"));

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&original)?;
    file.write_all(b"before the rename")?;
    fs::rename(&original, &renamed)?;
    file.write_all(b"after the rename")?;

    fs::remove_file(&renamed)?;
    file.write_all(b"after the unlink")?;
    file.seek(SeekFrom::Start(0))?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    if contents.is_empty() {
        return Err(io::Error::other("an unlinked open file read back empty"));
    }
    Ok(())
}

/// One open and close of a prepared file.
fn open_close(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let scratch = site.scratch(Class::OpenClose)?;
    let counter = state.next();
    let path = scratch.join(format!("open-{}", counter % site.seed.open_set));
    write_if_absent(&path, b"o")?;
    let mut file = File::open(&path)?;
    let mut byte = [0u8; 1];
    let _ = file.read(&mut byte)?;
    Ok(())
}

/// One whole mount-work-unmount cycle.
fn remount(site: &Site<'_>) -> io::Result<()> {
    let mut mount = site
        .fleet
        .mount(&format!("cycle-{}", site.index), site.url())
        .map_err(io::Error::other)?;
    let listed = fs::read_dir(mount.root())?.count();
    let read = fs::read(mount.root().join(names::LOCK_FILE));
    mount.unmount()?;
    debug_assert!(listed > 0 || read.is_err());
    Ok(())
}

/// One write, read and stat of a file another mount is working on too.
fn contend(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let counter = state.next();
    let name = format!("contend-{}", counter % site.seed.contended);
    let mine = site.mount().join(names::SHARED).join(&name);
    let theirs = site.other_mount().join(names::SHARED).join(&name);

    let offset = (counter % 4) * BLOCK as u64;
    let mut file = OpenOptions::new().read(true).write(true).open(&mine)?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&vec![b'w'; BLOCK])?;
    drop(file);

    let mut file = File::open(&theirs)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut block = vec![0u8; BLOCK];
    file.read_exact(&mut block)?;
    fs::metadata(&theirs)?;
    Ok(())
}

/// The mount the streamed-write class works through.
///
/// Direct data caching, because that is the only mode the engine runs in, and a
/// chunk unit below the frame bound, because a mount without one streams
/// nothing. Everything else is what every other mount in the run carries.
fn streamed_mount() -> MountOptions {
    MountOptions {
        direct_io: true,
        write_stream: STREAM_UNIT,
        ..MountOptions::default()
    }
}

/// One large write through a streaming mount, read back through the same
/// mount.
///
/// The read is the assertion, and it is made with nothing flushed and nothing
/// synced: the write returned, so every chunk of it was answered, so the bytes
/// are the server's — and on a direct mount the read that fetches them crosses
/// the wire instead of a cache that could be agreeing with the writer. It also
/// puts the invalidation bracket under the whole harness's load, which is where
/// a bracket taken per chunk instead of per write would show.
fn streamed_write(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let State::Stream(streaming) = state else {
        unreachable!("a streamed-write worker carries its own mount");
    };
    if streaming.mount.is_none() {
        streaming.mount = Some(
            site.fleet
                .mount_with(
                    &format!("stream-{}", site.index),
                    site.url(),
                    &streamed_mount(),
                )
                .map_err(io::Error::other)?,
        );
    }
    let outcome = one_streamed_write(site, streaming);
    if let Err(error) = &outcome {
        // A mount is let go only on the errnos that say the mount itself may
        // be gone, exactly as a lock-storm worker lets go of its session. The
        // errnos the harness calls the filesystem working under concurrent
        // load — a name already unlinked, a thing already there, a mountpoint
        // busy — keep the mount: churning a whole FUSE mount per benign errno
        // would spend the class's time on mounts instead of writes.
        let benign = [
            rustix::io::Errno::NOENT,
            rustix::io::Errno::EXIST,
            rustix::io::Errno::BUSY,
        ]
        .iter()
        .any(|errno| error.raw_os_error() == Some(errno.raw_os_error()));
        if !benign {
            streaming.mount = None;
        }
    }
    outcome
}

/// The operation itself, once the worker has a mount.
fn one_streamed_write(site: &Site<'_>, streaming: &mut Streaming) -> io::Result<()> {
    let root = streaming
        .mount
        .as_ref()
        .ok_or_else(|| io::Error::other("this worker has no mount"))?
        .root()
        .to_path_buf();
    let scratch = root.join(site.scratch_name(Class::Stream));
    fs::create_dir_all(&scratch)?;
    streaming.counter = streaming.counter.wrapping_add(1);
    let counter = streaming.counter;

    // Bytes whose value depends on where they are and on which round wrote
    // them, so a chunk placed at the wrong offset — or a stale one served
    // back — fails the comparison instead of looking plausible.
    let block: Vec<u8> = (0..STREAM_BLOCK)
        .map(|at| ((at + counter as usize) % 251 + 1) as u8)
        .collect();
    let offset = (counter % STREAM_BLOCKS) * STREAM_BLOCK as u64;
    let path = scratch.join("streamed.bin");

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    file.write_all_at(&block, offset)?;
    let mut read = vec![0u8; STREAM_BLOCK];
    file.read_exact_at(&mut read, offset)?;
    if read != block {
        return Err(io::Error::other(format!(
            "{} read back differently at {offset} right after the write returned",
            path.display()
        )));
    }
    Ok(())
}

/// One cycle of control-plane policy churn on the namespace the load is using.
///
/// Every other class asks what the filesystem does while it is busy. This one
/// asks what it does while its **policy is being rewritten underneath it**, on
/// names the rest of the harness is actively walking past. A cycle is:
///
/// 1. make a name, and hide it with a literal rule;
/// 2. prove it stops resolving — policy binds at the next lookup, and the guest
///    holds an entry for its cache lifetime, so this is a bounded wait and not
///    an instantaneous assertion;
/// 3. remove the rule and prove it resolves again;
/// 4. re-mode this worker's own directory read-only and back, which is a remove
///    and an add because the control plane has no modify;
/// 5. set an attribute, deny reading it with an attribute rule, prove it reads
///    back as absent, lift the rule and prove it returns.
///
/// Steps 2 and 5 are the no-wrong-admission assertions: a hidden name that
/// still resolves, or a denied attribute that still reads, is policy that did
/// not bind — which is the failure this class exists to find. Everything is
/// keyed by this worker's own index, so several workers churn one namespace
/// without ever contending for a rule.
fn rules(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let _cycle = state.next();
    let generation = site.server_generation();
    let namespace = site.namespace().clone();
    let directory = site.namespace_path(&site.scratch_name(Class::Rules));
    let hidden_path = format!("{directory}/hidden");

    // A cycle whose server died halfway through it left its rules behind, and
    // some of them — a hidden name, a read-only directory — would stop the next
    // cycle before it could take them out. So a cycle starts by removing its
    // own, which is a no-op on the ordinary path.
    for path in [&hidden_path, &directory] {
        let _ = site.control_call(
            Class::Rules,
            &Request::RuleRemove {
                namespace: namespace.clone(),
                path: path.clone(),
                r#match: None,
            },
            &[ErrorCode::NotFound],
        )?;
    }

    let scratch = site.scratch(Class::Rules)?;
    let file = scratch.join("hidden");
    write_if_absent(&file, b"r")?;

    let hide = Request::RuleAdd {
        namespace: namespace.clone(),
        rule: Rule::new(&hidden_path, ShareMode::Hidden),
    };
    let reveal = Request::RuleRemove {
        namespace: namespace.clone(),
        path: hidden_path.clone(),
        r#match: None,
    };

    let _ = site.control_call(Class::Rules, &hide, &[ErrorCode::AlreadyExists])?;
    // `ENOENT` and nothing else: a hidden name is a name that is *not there*,
    // and a lookup that fails `EIO` because the transport broke has said
    // nothing about the rule. Any other errno keeps the wait going, so a
    // mount that is briefly answering badly costs patience and not a verdict.
    let hidden = eventually(
        POLICY_PATIENCE,
        || matches!(fs::symlink_metadata(&file), Err(error) if error.kind() == io::ErrorKind::NotFound),
    );
    if !hidden && site.same_server(generation) {
        site.prove_wrong(
            Class::Rules,
            format!(
                "{hidden_path} still resolved {} s after a hidden rule landed on it",
                POLICY_PATIENCE.as_secs()
            ),
        );
    }
    // The removal runs whatever the assertion found: a rule left behind would
    // hide the name from every later cycle and from every other class.
    let _ = site.control_call(Class::Rules, &reveal, &[ErrorCode::NotFound])?;
    if site.same_server(generation)
        && !eventually(POLICY_PATIENCE, || fs::symlink_metadata(&file).is_ok())
    {
        site.prove_wrong(
            Class::Rules,
            format!(
                "{hidden_path} still did not resolve {} s after its hidden rule was removed",
                POLICY_PATIENCE.as_secs()
            ),
        );
    }

    if !site.same_server(generation) {
        return Ok(());
    }
    re_mode(site, &namespace, &directory)?;
    if !site.same_server(generation) {
        return Ok(());
    }
    attribute_rule(site, generation, &namespace, &scratch)
}

/// Steps this worker's own directory read-only and back again.
///
/// The control plane has no modify operation — a change is a removal and an
/// addition — so this is what an operator re-moding a share actually does, and
/// the load rides through it. The directory is the worker's own, so nothing
/// else in the run is writing under it while it is read-only.
fn re_mode(site: &Site<'_>, namespace: &NamespaceName, path: &str) -> io::Result<()> {
    for mode in [ShareMode::Ro, ShareMode::Rw] {
        let _ = site.control_call(
            Class::Rules,
            &Request::RuleAdd {
                namespace: namespace.clone(),
                rule: Rule::new(path, mode),
            },
            &[ErrorCode::AlreadyExists],
        )?;
        let _ = site.control_call(
            Class::Rules,
            &Request::RuleRemove {
                namespace: namespace.clone(),
                path: path.to_owned(),
                r#match: None,
            },
            &[ErrorCode::NotFound],
        )?;
    }
    Ok(())
}

/// Denies reading one attribute, proves it reads back as absent, and lifts it.
///
/// A denied read is *hidden*, not refused: the name is absent from the listing
/// and the get answers `ENODATA`, exactly as an attribute that was never set
/// would. That is the property here — a denied attribute whose value can still
/// be read is a leak, and the harness has no other place that would notice it
/// under load.
fn attribute_rule(
    site: &Site<'_>,
    generation: u64,
    namespace: &NamespaceName,
    scratch: &Path,
) -> io::Result<()> {
    let target = scratch.join("rules-target");
    write_if_absent(&target, b"a")?;
    let target = target.to_string_lossy().into_owned();
    let attribute = format!("user.torture-rules-{}", site.index);

    // As with the share rules: a cycle the server died inside left its rule
    // behind, and this is where it goes.
    let _ = site.control_call(
        Class::Rules,
        &Request::XattrRemove {
            namespace: namespace.clone(),
            r#match: attribute.clone(),
        },
        &[ErrorCode::NotFound],
    )?;

    rustix::fs::setxattr(
        target.as_str(),
        &attribute,
        b"visible",
        rustix::fs::XattrFlags::empty(),
    )
    .map_err(|errno| io::Error::from_raw_os_error(errno.raw_os_error()))?;

    // `ENODATA` and nothing else, for the reason the share rule's wait states:
    // a denied read is *hidden*, and hidden is the one errno that says the rule
    // bound. `EIO` from a mount that is having a bad moment is not an answer
    // about the rule at all, so it keeps the wait going instead of ending it.
    let denied_read = || {
        let mut buffer = [0u8; 64];
        matches!(
            rustix::fs::getxattr(target.as_str(), &attribute, &mut buffer),
            Err(rustix::io::Errno::NODATA)
        )
    };
    let deny = Request::XattrAdd {
        namespace: namespace.clone(),
        rule: XattrRule::new(&attribute).with_read(XattrVerdict::Deny),
    };
    let allow = Request::XattrRemove {
        namespace: namespace.clone(),
        r#match: attribute.clone(),
    };

    let _ = site.control_call(Class::Rules, &deny, &[ErrorCode::AlreadyExists])?;
    let denied = eventually(POLICY_PATIENCE, denied_read);
    let _ = site.control_call(Class::Rules, &allow, &[ErrorCode::NotFound])?;
    if !denied && site.same_server(generation) {
        site.prove_wrong(
            Class::Rules,
            format!("{attribute} still read back under a rule denying reads of it"),
        );
    }

    let _ = rustix::fs::removexattr(target.as_str(), &attribute);
    Ok(())
}

/// One cycle of listener churn: bind a spare port, prove it serves, remove it,
/// prove the session it accepted survives the removal.
///
/// The two halves are the contract's own two halves. A listener that is added
/// under load must take **new** connections at once, and a listener that is
/// removed must stop taking them without evicting anything — "sessions already
/// accepted on it keep serving" is the sentence, and the only way to see it is
/// to hold such a session across the removal and keep using it.
///
/// The port is picked by binding one and letting go, so two workers never ask
/// for the same one: the server refuses a duplicate *source form*, and
/// `127.0.0.1:0` is one source form however many callers write it. Losing the
/// race to another process between the pick and the server's own bind is a
/// tolerated refusal, not a defect. The pick is held reserved for the whole
/// cycle, because an endpoint this cycle is making statements about must not
/// be a port some other worker has meanwhile been handed.
fn listeners(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let State::Listeners(held) = state else {
        unreachable!("a listener worker carries the endpoints it added");
    };
    // A listener an interrupted cycle added is still bound, and its port is
    // still in the state file, so it comes out before anything else happens.
    held.retain(|endpoint| {
        matches!(
            remove_listener(site, endpoint),
            Err(RemovalFailure::Unreachable)
        )
    });

    let generation = site.server_generation();
    let reserved = spare_port()?;
    let address = reserved.address;
    let Some(Reply::Listener { listener }) = site.control_call(
        Class::Listeners,
        &Request::ListenerAdd {
            listener: Listener::Tcp { addr: address },
        },
        &[ErrorCode::BindFailed],
    )?
    else {
        // The bind lost its race with another process for the port; the next
        // cycle picks another one.
        std::thread::sleep(LISTENER_CADENCE);
        return Ok(());
    };
    let endpoint = listener.endpoint;
    held.push(endpoint.clone());

    let outcome = one_listener(site, generation, &endpoint);
    // The cycle removes the listener itself, as part of what it asserts; this
    // is the cleanup for a cycle that could not get that far.
    if !matches!(
        remove_listener(site, &endpoint),
        Err(RemovalFailure::Unreachable)
    ) {
        held.retain(|held| *held != endpoint);
    }
    drop(reserved);
    std::thread::sleep(LISTENER_CADENCE);
    outcome
}

/// Why a listener removal did not take the listener out.
#[derive(Debug)]
enum RemovalFailure {
    /// The server answered, and answered that there is no such listener: it is
    /// gone, which is what the caller wanted.
    Refused,
    /// The server could not be reached at all, so the listener may still be
    /// there and the caller has to come back to it.
    Unreachable,
}

/// Removes one listener, saying whether the caller may forget about it.
fn remove_listener(site: &Site<'_>, endpoint: &str) -> Result<(), RemovalFailure> {
    match site.control_call(
        Class::Listeners,
        &Request::ListenerRemove {
            endpoint: endpoint.to_owned(),
        },
        &[ErrorCode::NotFound],
    ) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(RemovalFailure::Refused),
        Err(_) => Err(RemovalFailure::Unreachable),
    }
}

/// What is asserted about one listener between its addition and its removal.
fn one_listener(site: &Site<'_>, generation: u64, endpoint: &str) -> io::Result<()> {
    let url = endpoint_url(site, endpoint)?;
    let mut session = match wire::Session::mount(&url, LISTENER_PATIENCE) {
        Ok(session) => session,
        Err(error) => {
            if site.same_server(generation) {
                site.prove_wrong(
                    Class::Listeners,
                    format!("a listener added at {endpoint} took no connection: {error:#}"),
                );
            }
            return Err(io::Error::other(error.to_string()));
        }
    };
    session.lookup(names::SHARED).map_err(io::Error::other)?;

    if let Err(RemovalFailure::Unreachable) = remove_listener(site, endpoint) {
        return Err(io::Error::other(format!("{endpoint} could not be removed")));
    }
    // Removal is not an eviction: this session was accepted before the listener
    // closed and owes the listener nothing.
    if let Err(error) = session.lookup(names::SHARED)
        && site.same_server(generation)
    {
        site.prove_wrong(
            Class::Listeners,
            format!("a session accepted at {endpoint} stopped serving when the listener was removed: {error:#}"),
        );
    }
    // And the server stops serving it, which is asked of the server and not of
    // the address. A dial that is refused proves nothing a closed socket does
    // not already give, and a dial that *succeeds* need not be this listener at
    // all: the port returns to the ephemeral range the moment it is freed. So
    // the fact is taken where it is stated — the live listener list the control
    // plane answers with.
    let closed = eventually(LISTENER_PATIENCE, || !still_listed(site, endpoint));
    if !closed && site.same_server(generation) {
        site.prove_wrong(
            Class::Listeners,
            format!("{endpoint} is still served as a listener after it was removed"),
        );
    }
    Ok(())
}

/// Whether the server still names this endpoint among the listeners it serves.
///
/// A server that cannot be reached answers nothing, and nothing is not "still
/// listed": the caller is proving a removal, and an unreachable server is the
/// restart arm's business, which the generation check beside every one of these
/// assertions already covers.
fn still_listed(site: &Site<'_>, endpoint: &str) -> bool {
    matches!(
        site.control_call(Class::Listeners, &Request::ServerInfo {}, &[]),
        Ok(Some(Reply::ServerInfo { listeners, .. }))
            if listeners.iter().any(|listener| listener.endpoint == endpoint)
    )
}

/// The mount URL of this run's namespace on another endpoint of the same
/// server.
fn endpoint_url(site: &Site<'_>, endpoint: &str) -> io::Result<MountUrl> {
    let address: SocketAddr = endpoint
        .parse()
        .map_err(|error| io::Error::other(format!("{endpoint} is not an address: {error}")))?;
    let mounted = site.url();
    Ok(MountUrl {
        endpoint: Endpoint::Tcp {
            host: address.ip().to_string(),
            port: address.port(),
        },
        namespace: mounted.namespace.clone(),
        subpath: mounted.subpath.clone(),
    })
}

/// The loopback ports the listener class is using right now.
///
/// A port a cycle frees is back in the ephemeral range at once, so without this
/// two workers can be handed the same one while the first is still making
/// statements about it — and "this endpoint is gone" would then be a statement
/// about somebody else's listener. Held for the length of a cycle and given
/// back after it, so the set is never larger than the class's worker count.
static IN_USE: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<u16>>> =
    std::sync::LazyLock::new(std::sync::Mutex::default);

/// A loopback port reserved against the rest of the run, released on drop.
#[derive(Debug)]
struct ReservedPort {
    address: SocketAddr,
}

impl Drop for ReservedPort {
    fn drop(&mut self) {
        IN_USE
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&self.address.port());
    }
}

/// How many ports a pick tries before it calls the machine out of them.
const PORT_ATTEMPTS: usize = 16;

/// A loopback port nothing is listening on and no other worker is using.
///
/// Found by binding it and letting go, which is the same small race every
/// ephemeral-port fixture in this workspace runs; the caller's own bind follows
/// immediately and a lost race is answered as a refused bind. A port another
/// worker holds is not taken: the rejected bindings are kept open until a free
/// one comes back, which is what makes the kernel offer a different one.
fn spare_port() -> io::Result<ReservedPort> {
    let mut rejected = Vec::new();
    for _ in 0..PORT_ATTEMPTS {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let reserved = IN_USE
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(address.port());
        if reserved {
            drop(listener);
            return Ok(ReservedPort { address });
        }
        rejected.push(listener);
    }
    Err(io::Error::other(
        "no loopback port came back that this run is not already using",
    ))
}

/// One turn of the restart arm: wait for the next restart to fall due, and
/// when it does, take the server away and prove everything came back.
///
/// The waiting is sliced instead of slept through in one piece, so the arm's
/// operation is short whenever no restart is due — which is what lets the
/// teardown collect this worker as promptly as any other, and what keeps the
/// class visibly making progress between restarts.
///
/// The two stops alternate, so a run of any length gets both: `SIGTERM`, where
/// the server finishes what it was doing, and `SIGKILL`, where it does not.
fn restart(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let State::Restarts { due, performed } = state else {
        unreachable!("a restart worker carries its own clock");
    };
    std::thread::sleep(RESTART_SLICE);
    let deadline = *due.get_or_insert_with(|| Instant::now() + site.restart_interval);
    if Instant::now() < deadline {
        return Ok(());
    }
    let server = site
        .server
        .ok_or_else(|| io::Error::other("this run owns no server to restart"))?;
    let stop = if performed.is_multiple_of(2) {
        Stop::Graceful
    } else {
        Stop::Hard
    };
    *performed += 1;
    let attempt = *performed;

    site.outage.open(site.elapsed_ms());
    let outcome = one_restart(site, server, stop, attempt);
    site.outage.close(site.elapsed_ms());
    *due = Some(Instant::now() + site.restart_interval);
    outcome
}

/// One whole restart: stop, check what the stop left, start, and heal.
///
/// The two stops are two different questions about the state file, so they are
/// two different stops here: an ordered shutdown must leave the file exactly as
/// it found it, and a crash must leave a whole document whatever it interrupted.
fn one_restart(site: &Site<'_>, server: &Supervisor, stop: Stop, attempt: u64) -> io::Result<()> {
    match stop {
        Stop::Graceful => graceful_stop(site, server)?,
        Stop::Hard => hard_stop(site, server, attempt)?,
    }
    server.start_again().map_err(io::Error::other)?;
    heal(site);
    Ok(())
}

/// A `SIGTERM` with nothing in flight, and the state file across it.
///
/// The picture is taken under the quiet gate, so *the last persisted mutation*
/// is a well-defined thing to compare against: an ordered shutdown finishes
/// what it was doing and publishes nothing new, so the file after the stop is
/// the file before it, byte for byte.
fn graceful_stop(site: &Site<'_>, server: &Supervisor) -> io::Result<()> {
    let before = {
        let _quiet = server.quiesce();
        let before = fs::read(server.state_file());
        server.stop(Stop::Graceful).map_err(io::Error::other)?;
        before
    }?;

    let after = fs::read(server.state_file())?;
    if after != before {
        site.findings.file(Violation::CrashInconsistent {
            stop: Stop::Graceful.name(),
            detail: format!(
                "the file went from {} bytes to {} bytes with no mutation in flight",
                before.len(),
                after.len()
            ),
        });
    }
    if let Err(error) = parses_as_state(&after, site.namespace().as_str()) {
        site.findings.file(Violation::CrashInconsistent {
            stop: Stop::Graceful.name(),
            detail: error,
        });
    }
    Ok(())
}

/// The name the restart arm keys its own rule by, under a mount root.
///
/// Nothing else in the run names it and nothing is ever created there: a rule
/// on a name that does not exist changes what the server persists and nothing
/// any other worker can see.
const CRASH_PROBE: &str = "torture-crash-probe";

/// How long the arm waits for its own request to reach the wire.
const MUTATION_PATIENCE: Duration = Duration::from_secs(5);

/// How many places the signal is walked to across the persist.
const KILL_OFFSETS: u64 = 8;

/// How far past the request the signal is held back, cycle by cycle.
///
/// The window the kill has to fall inside is one write and one rename behind a
/// durable flush — hundreds of microseconds, not a fixed number of them. A
/// single delay would either always fall short of the rename or always past it,
/// so the delay walks across the window and a soak covers all of it.
fn kill_offset(attempt: u64) -> Duration {
    Duration::from_micros(200 * ((attempt / 2) % KILL_OFFSETS))
}

/// A `SIGKILL` delivered **inside** a control mutation, and the two documents
/// the state file is then allowed to hold.
///
/// A kill with nothing in flight proves nothing a crash could violate: bytes
/// nobody is writing cannot change, so the file is trivially what it was and
/// the assertion is unreachable. The arm therefore issues a mutation of its own
/// — one rule, on a name nothing else in the run uses — and signals between the
/// request and its reply, which is the interval the server's write-and-rename
/// persist lives in.
///
/// The quiet gate is still held, and that is what keeps the question
/// two-valued: no *other* worker's persist can land in the window, so the file
/// afterwards is either the document from before the mutation, byte for byte,
/// or the whole document that mutation published. A truncation, a half-written
/// table or a document that no longer serves the namespace is neither.
fn hard_stop(site: &Site<'_>, server: &Supervisor, attempt: u64) -> io::Result<()> {
    let socket = site.control.ok_or_else(|| {
        io::Error::other("the restart class kills the server inside a mutation of its own")
    })?;
    let namespace = site.namespace().clone();
    let probe = site.namespace_path(CRASH_PROBE);
    let _quiet = server.quiesce();

    // The previous cycle's rule comes out first, so this cycle's addition is a
    // change the server must persist and not a duplicate it can refuse without
    // writing anything.
    let _ = one_call(
        socket,
        &Request::RuleRemove {
            namespace: namespace.clone(),
            path: probe.clone(),
            r#match: None,
        },
    );

    let before = fs::read(server.state_file())?;
    let publish = Request::RuleAdd {
        namespace,
        rule: Rule::new(&probe, ShareMode::Hidden),
    };
    let sent = std::sync::atomic::AtomicBool::new(false);
    let (stopped, inside) = std::thread::scope(|scope| {
        let mutation = scope.spawn(|| one_call_from(socket, &publish, &sent));
        let on_the_wire = armed(&sent, MUTATION_PATIENCE);
        std::thread::sleep(kill_offset(attempt));
        let stopped = server.stop(Stop::Hard);
        let answered = mutation
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("the mutation could not be carried out")));
        // The request was on the wire and no reply ever came, so the signal
        // fell strictly between them — which is the only placement that proves
        // anything about a persist.
        (stopped, on_the_wire && answered.is_err())
    });
    stopped.map_err(io::Error::other)?;
    if inside {
        server.note_stop_inside_mutation();
    }

    let after = fs::read(server.state_file())?;
    if let Err(detail) = crash_consistent(&before, &after, site.namespace().as_str(), &probe) {
        site.findings.file(Violation::CrashInconsistent {
            stop: Stop::Hard.name(),
            detail,
        });
    }
    Ok(())
}

/// Waits for the mutation's request to reach the wire, yielding instead of
/// sleeping.
///
/// The window this arms for is well under a millisecond, so a wait that slept
/// in the tens of milliseconds every other bounded wait here uses would put
/// every signal long past the persist it is meant to fall inside.
fn armed(sent: &std::sync::atomic::AtomicBool, patience: Duration) -> bool {
    let deadline = Instant::now() + patience;
    while !sent.load(std::sync::atomic::Ordering::SeqCst) {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::yield_now();
    }
    true
}

/// One control call, made without taking the quiet gate.
///
/// The restart arm holds that gate exclusively while it works, so its own calls
/// cannot go through [`Site::control_call`] — they would wait for a lock the
/// caller is holding. Nothing is asserted about the answer either: this is the
/// arm making the server write, not a class judging what it wrote.
fn one_call(socket: &Path, request: &Request) -> io::Result<()> {
    let sent = std::sync::atomic::AtomicBool::new(false);
    one_call_from(socket, request, &sent)
}

/// The same, saying when the request reached the wire.
///
/// Split from the client's own request-and-answer call for that flag alone: the
/// restart arm signals on it, and what it has to mean is "the request is on the
/// wire and no reply has come".
fn one_call_from(
    socket: &Path,
    request: &Request,
    sent: &std::sync::atomic::AtomicBool,
) -> io::Result<()> {
    let mut client = Client::connect(socket).map_err(io::Error::other)?;
    let line = serde_json::to_vec(request).map_err(io::Error::other)?;
    client.send_line(&line).map_err(io::Error::other)?;
    sent.store(true, std::sync::atomic::Ordering::SeqCst);
    client
        .read_line()
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("the server closed without answering"))?;
    Ok(())
}

/// Whether the state file a kill left is one of the two documents it may be.
///
/// A persist is a write to a temporary and a rename over the name, so the only
/// two things a signal can leave behind are the document from before the
/// mutation and the whole document the mutation published. Whole-ness is
/// [`parses_as_state`]'s: a document parse, over the whole file, that still
/// finds the namespace the run is mounted on.
fn crash_consistent(
    before: &[u8],
    after: &[u8],
    namespace: &str,
    published: &str,
) -> Result<(), String> {
    parses_as_state(after, namespace)?;
    if after == before || holds_rule(after, namespace, published) {
        return Ok(());
    }
    Err(format!(
        "it is neither the {} bytes from before the mutation nor a document holding \
         the rule {published} the mutation was publishing",
        before.len()
    ))
}

/// Whether a state document keys a rule of this namespace by this path.
fn holds_rule(bytes: &[u8], namespace: &str, path: &str) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Ok(document) = text.parse::<toml::Table>() else {
        return false;
    };
    document
        .get("namespaces")
        .and_then(toml::Value::as_array)
        .is_some_and(|namespaces| {
            namespaces
                .iter()
                .filter(|entry| entry.get("name").and_then(toml::Value::as_str) == Some(namespace))
                .filter_map(|entry| entry.get("rules").and_then(toml::Value::as_array))
                .flatten()
                .any(|rule| rule.get("path").and_then(toml::Value::as_str) == Some(path))
        })
}

/// Whether the state file the server is about to be restarted onto is a whole
/// document that still serves the run's namespace.
///
/// Parsed here, independently of the server, because "the server started again"
/// and "the file survived" are two facts and a harness that only had the first
/// would miss a truncation the server happened to tolerate. The parse is a
/// document parse — `toml`'s — not a search for text.
fn parses_as_state(bytes: &[u8], namespace: &str) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|error| format!("not valid text: {error}"))?;
    let document: toml::Table = text
        .parse()
        .map_err(|error| format!("not a whole document: {error}"))?;
    let serves = document
        .get("namespaces")
        .and_then(toml::Value::as_array)
        .is_some_and(|namespaces| {
            namespaces
                .iter()
                .any(|entry| entry.get("name").and_then(toml::Value::as_str) == Some(namespace))
        });
    if serves {
        Ok(())
    } else {
        Err(format!("it no longer holds the namespace {namespace:?}"))
    }
}

/// Waits for every mount to serve again, and reports the ones that do not.
///
/// This is the reconnect contract asserted: a path-based operation is what the
/// kernel's own `ESTALE` retry heals, so a fresh listing and a fresh stat from
/// each mount root are what a healed mount answers. Nothing here reopens
/// anything — descriptors held across the gap are *supposed* to surface their
/// stale errno, and the classes holding them meet that as an ordinary failure.
fn heal(site: &Site<'_>) {
    let roots: Vec<&Path> = site.mounts.iter().map(TortureMount::root).collect();
    heal_all(&roots, HEAL_PATIENCE, site.findings);
}

/// Waits out every mount at once, and reports the ones that never answered.
///
/// All of them together, and that is the restart budget's own reason: what a
/// restart costs the progress watchdog is one stop plus one start plus one
/// healing, and mounts waited out one after another would multiply the last
/// term by the mount count until the three no longer fitted inside the
/// watchdog. Every mount heals independently of every other, so waiting for
/// them in turn buys nothing but that multiplication.
fn heal_all(roots: &[&Path], patience: Duration, findings: &Findings) {
    std::thread::scope(|scope| {
        for root in roots {
            scope.spawn(move || {
                let mut last = String::from("it was never reached");
                let healed = eventually(patience, || match probe_mount(root) {
                    Ok(()) => true,
                    Err(error) => {
                        last = error.to_string();
                        false
                    }
                });
                if !healed {
                    findings.file(Violation::MountUnhealed {
                        mountpoint: root.display().to_string(),
                        patience_ms: u64::try_from(patience.as_millis()).unwrap_or(u64::MAX),
                        detail: last,
                    });
                }
            });
        }
    });
}

/// One path-based read of a mount, which is what a healed mount answers.
fn probe_mount(root: &Path) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        entry?;
    }
    fs::metadata(root.join(names::LOCK_FILE))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The state-file check after a stop: a whole document that still serves
    /// the run's namespace passes, and the ways a crash could have left
    /// something else do not.
    #[test]
    fn the_state_file_check_accepts_only_a_whole_document() {
        let whole = b"\n[server]\n\n[[namespaces]]\nname = \"torture\"\n";
        assert_eq!(parses_as_state(whole, "torture"), Ok(()));

        // Truncated mid-document, which is what a write with no rename could
        // leave.
        assert!(parses_as_state(&whole[..whole.len() - 12], "torture").is_err());
        // Empty, which is what a create-then-crash could leave.
        assert!(parses_as_state(b"", "torture").is_err());
        // Whole, and no longer about this run's namespace.
        assert!(parses_as_state(whole, "elsewhere").is_err());
    }

    /// The whole state file of one namespace with one rule, spelled as the
    /// server persists it.
    fn document(rules: &[&str]) -> Vec<u8> {
        let mut text = String::from("[server]\n\n[[namespaces]]\nname = \"torture\"\n");
        for path in rules {
            text.push_str(&format!(
                "\n[[namespaces.rules]]\npath = \"{path}\"\nmode = \"hidden\"\n"
            ));
        }
        text.into_bytes()
    }

    /// What a kill inside a control mutation is allowed to leave: the document
    /// from before it, or the whole document it was publishing. The states a
    /// write with no rename would leave are none of those, and neither is a
    /// third document nobody was writing.
    #[test]
    fn a_kill_inside_a_mutation_leaves_one_of_two_documents() {
        let before = document(&[]);
        let after = document(&["/tree/torture-crash-probe"]);

        // Neither half of the mutation landed.
        assert_eq!(
            crash_consistent(&before, &before, "torture", "/tree/torture-crash-probe"),
            Ok(())
        );
        // It landed whole.
        assert_eq!(
            crash_consistent(&before, &after, "torture", "/tree/torture-crash-probe"),
            Ok(())
        );

        // Truncated mid-document, which is what a write with no rename could
        // leave, and what the rename exists to make impossible.
        assert!(
            crash_consistent(
                &before,
                &after[..after.len() - 12],
                "torture",
                "/tree/torture-crash-probe"
            )
            .is_err()
        );
        // Whole, and neither the document from before nor the one the mutation
        // was publishing.
        assert!(
            crash_consistent(
                &before,
                &document(&["/tree/somebody-elses-rule"]),
                "torture",
                "/tree/torture-crash-probe"
            )
            .is_err()
        );
    }

    /// The signal walks across the persist instead of always landing in the
    /// same place, and every cycle of the walk is a delay a persist could still
    /// be inside.
    #[test]
    fn the_kill_offset_walks_across_the_persist() {
        let offsets: Vec<Duration> = (0..KILL_OFFSETS * 2).map(kill_offset).collect();
        assert_eq!(offsets[0], Duration::ZERO);
        assert!(
            offsets
                .iter()
                .all(|offset| *offset < Duration::from_millis(2))
        );
        assert_eq!(
            offsets
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            usize::try_from(KILL_OFFSETS).expect("a small count")
        );
    }

    /// Healing costs one patience however many mounts a run holds. That is what
    /// keeps a restart's whole budget — the stop, the start and this — inside
    /// the progress watchdog, which is asserted against the sum of the three
    /// and not against the sum times the mount count.
    #[test]
    fn every_mount_heals_at_once_and_not_one_after_another() {
        let findings = Findings::default();
        let unreachable = [
            Path::new("/proc/self/fd/no-mount-here-0"),
            Path::new("/proc/self/fd/no-mount-here-1"),
            Path::new("/proc/self/fd/no-mount-here-2"),
            Path::new("/proc/self/fd/no-mount-here-3"),
        ];
        let patience = Duration::from_millis(300);

        let started = Instant::now();
        heal_all(&unreachable, patience, &findings);
        let took = started.elapsed();

        assert!(
            took < patience * 2,
            "four mounts that never healed took {took:?} against a {patience:?} patience"
        );
        assert_eq!(findings.drain().len(), unreachable.len());
    }

    /// A worker's URL is its own mount's, and not the fleet's URL at the
    /// worker's index. The two orderings agree only when the mount count and
    /// the URL count divide, and a worker that took the second one would be
    /// keying rules by a namespace its own mount is not a view of.
    #[test]
    fn a_worker_takes_its_url_from_the_mount_it_works_through() {
        let urls = [
            "voidport://127.0.0.1:9000/@one".to_owned(),
            "voidport+vsock://1:9001/@two".to_owned(),
        ];
        let fleet = Fleet::new(&urls, Path::new("/proc/self/fd")).expect("two parseable URLs");
        // Three mounts over two URLs, made the way a run makes them.
        let mounts: Vec<TortureMount> = (0..3)
            .map(|index| {
                TortureMount::unmounted(
                    PathBuf::from(format!("/proc/self/fd/mnt-{index}")),
                    fleet.url(index).clone(),
                )
            })
            .collect();
        let findings = Findings::default();
        let outage = Outage::default();

        for index in 0..6 {
            let site = Site {
                mounts: &mounts,
                fleet: &fleet,
                index,
                seed: Seed::default(),
                server: None,
                control: None,
                findings: &findings,
                outage: &outage,
                started: Instant::now(),
                restart_interval: Duration::from_secs(1),
            };
            let mine = &mounts[mount_index(index, mounts.len())];
            assert_eq!(site.url(), mine.url(), "worker {index}");
            assert_eq!(site.mount(), mine.root(), "worker {index}");
            assert_eq!(site.namespace(), &mine.url().namespace, "worker {index}");
        }

        // And the two orderings really do disagree, which is what makes taking
        // the URL from the mount the load-bearing choice it is.
        assert_ne!(
            mounts[mount_index(3, mounts.len())].url(),
            fleet.url(3),
            "three mounts over two URLs part company at the fourth worker"
        );
    }

    /// A bounded wait answers whether the condition held, not how long it
    /// waited: the assertions built on it read as "it did" or "it never did".
    #[test]
    fn a_bounded_wait_reports_whether_the_condition_ever_held() {
        let mut looks = 0;
        assert!(eventually(Duration::from_secs(5), || {
            looks += 1;
            looks == 3
        }));
        assert_eq!(looks, 3);
        assert!(!eventually(Duration::from_millis(1), || false));
    }
}
