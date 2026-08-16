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
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::metrics::Class;
use crate::mounts::{Fleet, TortureMount};
use crate::wire;

/// The record an append worker writes.
const APPEND_RECORD: usize = 128;

/// The block a churn or contention worker writes.
const BLOCK: usize = 4096;

/// How many owners one lock-storm worker stacks on the shared file.
///
/// This is the multiplier that makes the storm a storm: at the default
/// intensity it is already hundreds of waiters, and it scales with intensity
/// into the thousands the design names.
pub const LOCK_OWNERS_PER_WORKER: u64 = 64;

/// How long a lock-storm worker waits for a reply before calling the server
/// unresponsive and reconnecting.
const LOCK_REPLY_PATIENCE: Duration = Duration::from_secs(30);

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
    /// Nothing to carry.
    Empty,
}

impl State {
    /// The state a class's worker starts with.
    #[must_use]
    pub fn for_class(class: Class) -> Self {
        match class {
            Class::Walk => Self::Walk(Vec::new()),
            Class::Locks => Self::Storm(Box::default()),
            Class::Churn | Class::Rename | Class::OpenClose | Class::Contend | Class::Xattr => {
                Self::Counter(0)
            }
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
}

impl Site<'_> {
    /// The mount this worker works through, which is its own share of them.
    fn mount(&self) -> &Path {
        self.mounts[self.index as usize % self.mounts.len()].root()
    }

    /// A mount other than [`Self::mount`], so the contention class really does
    /// contend across mounts, not within one.
    fn other_mount(&self) -> &Path {
        self.mounts[(self.index as usize + 1) % self.mounts.len()].root()
    }

    /// This worker's own scratch directory, created on first use.
    fn scratch(&self, class: Class) -> io::Result<PathBuf> {
        let path = self
            .mount()
            .join(names::WORK)
            .join(format!("{}-{}", class.name(), self.index));
        fs::create_dir_all(&path)?;
        Ok(path)
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
        let mut session = wire::Session::mount(site.fleet.url(), LOCK_REPLY_PATIENCE)
            .map_err(io::Error::other)?;
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

    special_files(&scratch, counter)
}

/// One create-stat-remove cycle of a FIFO and of a socket file.
fn special_files(scratch: &Path, counter: u64) -> io::Result<()> {
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
        .mount(&format!("cycle-{}", site.index))
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
