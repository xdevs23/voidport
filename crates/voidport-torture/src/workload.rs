use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use voidport::mount::TeardownError;
use voidport::url::{Endpoint, MountUrl};
use voidport_control::{
    Client, ErrorCode, Listener, NamespaceName, Reply, Request, Response, Rule, ShareMode,
    Timeouts, XattrRule, XattrVerdict,
};

use crate::connections::{Connection, Connections, Registration};
use crate::invariant::{Findings, Outage, Violation};
use crate::metrics::Class;
use crate::mounts::{Fleet, TortureMount};
use crate::server::{Stop, Supervisor};
use crate::wire;

const APPEND_RECORD: usize = 128;

const BLOCK: usize = 4096;

const STREAM_BLOCK: usize = 512 * 1024;

const STREAM_BLOCKS: u64 = 4;

pub const LOCK_OWNERS_PER_WORKER: u64 = 64;

const LOCK_REPLY_PATIENCE: Duration = Duration::from_secs(30);

/// Policy binds at the next lookup and the guest kernel holds an entry for its
/// cache lifetime, so a hidden name keeps resolving for up to that lifetime.
/// This is that bound with a wide margin: past it, the name did not stop
/// resolving at all.
const POLICY_PATIENCE: Duration = Duration::from_secs(20);

const POLL: Duration = Duration::from_millis(50);

/// Every add and removal persists the state file, so an unpaced listener
/// worker would be a `fsync` storm and not listener churn.
const LISTENER_CADENCE: Duration = Duration::from_millis(200);

const LISTENER_PATIENCE: Duration = Duration::from_secs(10);

/// This is what a restart worker's operation costs when no restart is due, so
/// it is also how long the teardown waits for that worker.
const RESTART_SLICE: Duration = Duration::from_millis(250);

/// A healthy mount heals quickly. This is the bound past which it is not
/// healing at all.
pub(crate) const HEAL_PATIENCE: Duration = Duration::from_secs(45);

/// A sample: the ownership policy is a property of the presentation of the
/// server, not of the individual node.
const OWNER_SAMPLE: u64 = 16;

pub mod names {
    pub const TREE: &str = "torture-tree";
    pub const CROWDED: &str = "torture-crowded";
    pub const SHARED: &str = "torture-shared";
    pub const WORK: &str = "torture-work";
    pub const LOCK_FILE: &str = "torture-shared/lock.target";
    pub const APPEND_FILE: &str = "torture-shared/append.log";
}

#[derive(Clone, Copy, Debug)]
pub struct Seed {
    pub tree_dirs: u64,
    pub tree_files: u64,
    pub crowded: u64,
    pub contended: u64,
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
    #[must_use]
    pub fn entries(&self) -> u64 {
        self.tree_dirs * (self.tree_files + 1) + self.crowded + self.contended + 16
    }

    /// Everything is created through the filesystem under test, because a working
    /// set written behind the back of the mount would never be admitted by the
    /// server.
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

fn write_if_absent(path: &Path, contents: &[u8]) -> io::Result<()> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => file.write_all(contents),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

#[derive(Debug)]
pub enum State {
    Walk(Vec<PathBuf>),
    Counter(u64),
    Storm(Box<Storm>),
    Restarts {
        due: Option<Instant>,
        performed: u64,
    },
    Listeners(Vec<String>),
    Empty,
}

impl State {
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
            | Class::Rules
            | Class::Stream => Self::Counter(0),
            Class::Listeners => Self::Listeners(Vec::new()),
            Class::Restart => Self::Restarts {
                due: None,
                performed: 0,
            },
            Class::List | Class::Append | Class::Remount => Self::Empty,
        }
    }

    fn walk(&mut self) -> &mut Vec<PathBuf> {
        match self {
            Self::Walk(stack) => stack,
            _ => unreachable!("a walk worker carries a walk stack"),
        }
    }

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

#[derive(Debug, Default)]
pub struct Storm {
    session: Option<wire::Session>,
    handle: u64,
    locking: Vec<(u64, u64)>,
    unlocking: Vec<(u64, u64)>,
}

pub struct Site<'a> {
    pub mounts: &'a [TortureMount],
    pub fleet: &'a Fleet,
    pub index: u64,
    pub seed: Seed,
    pub server: Option<&'a Supervisor>,
    pub control: Option<&'a Path>,
    pub findings: &'a Findings,
    pub connections: &'a Arc<Connections>,
    pub outage: &'a Outage,
    pub started: Instant,
    pub restart_interval: Duration,
}

/// The one selector: the mount, the neighbour mount and the URL of a worker
/// are all computed with this, so none of them can be computed over a different
/// length and point at a different server.
const fn mount_index(index: u64, mounts: usize) -> usize {
    (index as usize) % mounts
}

impl Site<'_> {
    fn mount(&self) -> &Path {
        self.mounts[mount_index(self.index, self.mounts.len())].root()
    }

    fn other_mount(&self) -> &Path {
        self.mounts[mount_index(self.index + 1, self.mounts.len())].root()
    }

    /// Taken from the mount and never from the fleet by worker index: when the
    /// two lengths do not divide, a worker that indexed the URLs itself would add
    /// rules to one namespace while looking for their effect through a mount of
    /// another.
    fn url(&self) -> &MountUrl {
        self.mounts[mount_index(self.index, self.mounts.len())].url()
    }

    fn scratch_name(&self, class: Class) -> String {
        format!("{}/{}-{}", names::WORK, class.name(), self.index)
    }

    fn scratch(&self, class: Class) -> io::Result<PathBuf> {
        let path = self.mount().join(self.scratch_name(class));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// A mount is a namespace subpath, so the name a rule is keyed by is the name
    /// of the guest with the subpath in front.
    fn namespace_path(&self, relative: &str) -> String {
        let subpath = String::from_utf8_lossy(&self.url().subpath).into_owned();
        format!("{}/{relative}", subpath.trim_end_matches('/'))
    }

    fn namespace(&self) -> &NamespaceName {
        &self.url().namespace
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn prove_wrong(&self, class: Class, detail: String) {
        self.findings.file(Violation::Contract {
            class,
            detail,
            elapsed_ms: self.elapsed_ms(),
        });
    }

    /// A cycle whose two halves saw two different server lifetimes proves nothing
    /// about either, so it is abandoned instead of judged.
    fn server_generation(&self) -> u64 {
        self.outage.generation()
    }

    fn same_server(&self, generation: u64) -> bool {
        !self.outage.open_now() && self.server_generation() == generation
    }

    /// A connection or transport failure is an ordinary operation failure,
    /// since the server may be going away underneath. A structured refusal is
    /// not: answering "no" to a mutation this class may make is the server-side
    /// error class the run forbids. `tolerated` lists the codes this call may
    /// be refused with anyway.
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
        let mut control = connect(socket, self.connections)?;
        let answer = control.client.call(request).map_err(io::Error::other)?;
        match answer.response {
            Response::Ok { result } => Ok(Some(result)),
            Response::Error { error } if tolerated.contains(&error.code) => Ok(None),
            Response::Error { error } => {
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

/// Returns the result of the filesystem call. The caller records it, and almost
/// none of the errors are violations.
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

fn walk(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let root = site.mount().to_path_buf();
    let stack = state.walk();
    let directory = stack.pop().unwrap_or(root);
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        // A name another class is churning may already be gone, which is the
        // filesystem being right.
        if let Ok(metadata) = entry.metadata()
            && metadata.is_dir()
        {
            stack.push(entry.path());
        }
    }
    Ok(())
}

fn list(site: &Site<'_>) -> io::Result<()> {
    let mut entries = 0;
    for entry in fs::read_dir(site.mount().join(names::CROWDED))? {
        entry?;
        entries += 1;
    }
    debug_assert!(entries >= 0);
    Ok(())
}

fn churn(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let scratch = site.scratch(Class::Churn)?;
    let counter = state.next();
    let path = scratch.join(format!("churn-{counter}"));
    let mut file = File::create(&path)?;
    file.write_all(&vec![b'c'; BLOCK])?;
    drop(file);
    fs::remove_file(&path)
}

/// The worker keeps [`LOCK_OWNERS_PER_WORKER`] blocking requests stacked on
/// the shared file: whenever a lock is granted it is released and the owner
/// re-queues. One operation is one acquisition, and replies to the releases
/// are consumed on the way past.
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
        // A worker with a timed-out reply or a closed connection starts a fresh
        // session. Dropping the session releases every lock it held, so a
        // failure does not wedge every other worker.
        storm.session = None;
    }
    outcome
}

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

fn append(site: &Site<'_>) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(site.mount().join(names::APPEND_FILE))?;
    file.write_all(&[b'a'; APPEND_RECORD])
}

/// A rule change is a live reconfiguration, so a name that was writable when
/// the cycle started may be denied when the write arrives: `EPERM` is a policy
/// decision arriving. `ENODATA` is the same fact on the read side, since a
/// denied read is hidden. `EOPNOTSUPP` is the host filesystem not storing the
/// namespace at all (tmpfs before 6.6 for `user.*`), and `EPERM` also covers
/// the refusal of the kernel of `user.*` on a FIFO or a socket. The transport
/// errnos are absent: those still fail the run.
const XATTR_POLICY_ERRNOS: [rustix::io::Errno; 3] = [
    rustix::io::Errno::PERM,
    rustix::io::Errno::NODATA,
    rustix::io::Errno::OPNOTSUPP,
];

fn tolerating(outcome: Result<(), rustix::io::Errno>) -> io::Result<()> {
    match outcome {
        Ok(()) => Ok(()),
        Err(errno) if XATTR_POLICY_ERRNOS.contains(&errno) => Ok(()),
        Err(errno) => Err(io::Error::from_raw_os_error(errno.raw_os_error())),
    }
}

/// The class uses rule-governed names: `user.*`, which the defaults allow
/// writing, and one reserved-namespace name, which they deny, so changing
/// rules mid-run flips real outcomes. Each step tolerates the policy errnos
/// and carries on. Nothing opens the FIFO, because a reader with no writer
/// blocks forever.
fn xattr(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let scratch = site.scratch(Class::Xattr)?;
    let counter = state.next();
    let path = scratch.join("xattr-target");
    write_if_absent(&path, b"x")?;
    let value = counter.to_le_bytes();
    let path = path.to_string_lossy().into_owned();

    for name in [
        format!("user.torture-{}", counter % 8),
        // A name outside `user.*` is allowed only where a rule allows it.
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

/// Returns what it stat'd, so a caller whose subject is the ownership of what
/// it made can look at it.
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
            // Another cycle left the name behind, or the mount is going down under the
            // remount class. The removal below cleans up either way.
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

/// The link target is a relative name that is not there: a symbolic link is a
/// string the server stores, and resolving it is the business of the guest
/// kernel.
fn symbolic_link(scratch: &Path, counter: u64) -> io::Result<(PathBuf, fs::Metadata)> {
    let path = scratch.join(format!("link-{counter}"));
    let target = format!("target-{counter}");
    match std::os::unix::fs::symlink(&target, &path) {
        Ok(()) => {}
        // A previous cycle of this worker left the name, which the removal below
        // cleans up.
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

/// On a sample of the cycles it checks the ownership contract: what the
/// server presents for a node just made must be what it presents for the
/// working set made earlier by the same session. That holds whatever
/// ownership policy the namespace has, unlike a fixed uid.
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

/// The file is renamed and then removed with the descriptor still open, and
/// written and read through afterwards: the handle must still work after the
/// name it was opened by is gone.
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

fn remount(site: &Site<'_>) -> io::Result<()> {
    let mut mount = site
        .fleet
        .mount(&format!("cycle-{}", site.index), site.url())
        .map_err(io::Error::other)?;
    let listed = fs::read_dir(mount.root())?.count();
    let read = fs::read(mount.root().join(names::LOCK_FILE));
    mount.unmount().map_err(|error| match error {
        TeardownError::Unmount(kernel) => kernel,
        ended => io::Error::other(ended),
    })?;
    debug_assert!(listed > 0 || read.is_err());
    Ok(())
}

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

/// The read is made with nothing flushed and nothing synced: the write
/// returned, so the bytes are the server's. The other mount opens the file
/// while this handle still writes it, so the server lets it cache nothing and
/// the read crosses the wire.
fn streamed_write(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let counter = state.next();
    let scratch = site.scratch(Class::Stream)?;

    // Bytes whose value depends on position and round, so a wrong offset or a
    // stale byte fails the comparison.
    let block: Vec<u8> = (0..STREAM_BLOCK)
        .map(|at| ((at + counter as usize) % 251 + 1) as u8)
        .collect();
    let offset = (counter % STREAM_BLOCKS) * STREAM_BLOCK as u64;
    let path = scratch.join("streamed.bin");

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    file.write_all_at(&block, offset)?;
    let theirs = site
        .other_mount()
        .join(site.scratch_name(Class::Stream))
        .join("streamed.bin");
    let mut read = vec![0u8; STREAM_BLOCK];
    File::open(&theirs)?.read_exact_at(&mut read, offset)?;
    drop(file);
    if read != block {
        return Err(io::Error::other(format!(
            "{} read back differently at {offset} right after the write returned",
            theirs.display()
        )));
    }
    Ok(())
}

/// Everything is keyed by the index of this worker, so several workers change
/// one namespace without contending for a rule.
fn rules(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let _cycle = state.next();
    let generation = site.server_generation();
    let namespace = site.namespace().clone();
    let directory = site.namespace_path(&site.scratch_name(Class::Rules));
    let hidden_path = format!("{directory}/hidden");

    // A cycle whose server died halfway left rules behind that would stop the
    // next cycle, so a cycle starts by removing its own.
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
    // `ENOENT` and nothing else: a lookup that fails `EIO` because the transport
    // broke does not show anything about the rule. Any other errno makes the
    // wait continue.
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
    // The removal runs whatever the assertion found, because a rule left behind
    // would hide the name from every later cycle.
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

/// The control plane has no modify operation, so a change is a removal and an
/// addition. The directory belongs to this worker, so nothing else writes under
/// it while it is read-only.
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

/// A denied read is hidden: the get fails with `ENODATA`, as for an
/// attribute that was never set. A denied attribute whose value can still be
/// read is a leak.
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

    // `ENODATA` and nothing else, as for the share rule: `EIO` from a mount is not
    // an answer about the rule, so it makes the wait continue.
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

/// The port is picked by binding one and letting go, so two workers never ask
/// for the same one: the server rejects a duplicate source form, and
/// `127.0.0.1:0` is one source form however many callers write it. Losing the
/// race to another process between the pick and the bind of the server is
/// tolerated. The port is reserved for the whole cycle.
fn listeners(site: &Site<'_>, state: &mut State) -> io::Result<()> {
    let State::Listeners(held) = state else {
        unreachable!("a listener worker carries the endpoints it added");
    };
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
        std::thread::sleep(LISTENER_CADENCE);
        return Ok(());
    };
    let endpoint = listener.endpoint;
    held.push(endpoint.clone());

    let outcome = one_listener(site, generation, &endpoint);
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

#[derive(Debug)]
enum RemovalFailure {
    Refused,
    Unreachable,
}

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
    if let Err(error) = session.lookup(names::SHARED)
        && site.same_server(generation)
    {
        site.prove_wrong(
            Class::Listeners,
            format!("a session accepted at {endpoint} stopped serving when the listener was removed: {error:#}"),
        );
    }
    // Asked of the live listener list of the control plane and not of the
    // address: a refused dial proves nothing a closed socket does not give, and a
    // dial that succeeds need not be this listener, since the freed port returns
    // to the ephemeral range.
    let closed = eventually(LISTENER_PATIENCE, || !still_listed(site, endpoint));
    if !closed && site.same_server(generation) {
        site.prove_wrong(
            Class::Listeners,
            format!("{endpoint} is still served as a listener after it was removed"),
        );
    }
    Ok(())
}

/// An unreachable server is not "still listed": it is the business of the
/// restart arm, which the generation check beside every assertion covers.
fn still_listed(site: &Site<'_>, endpoint: &str) -> bool {
    matches!(
        site.control_call(Class::Listeners, &Request::ServerInfo {}, &[]),
        Ok(Some(Reply::ServerInfo { listeners, .. }))
            if listeners.iter().any(|listener| listener.endpoint == endpoint)
    )
}

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

/// A port freed by a cycle is back in the ephemeral range at once, so without
/// this two workers can be handed the same one. A port is in the set for the
/// length of a cycle.
static IN_USE: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<u16>>> =
    std::sync::LazyLock::new(std::sync::Mutex::default);

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

const PORT_ATTEMPTS: usize = 16;

/// Found by binding it and letting go, the same small race as every
/// ephemeral-port fixture in the workspace. A port another worker holds is
/// not taken: the rejected bindings are kept open until a free one comes
/// back, which makes the kernel offer a different one.
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

/// The waiting is sliced, so the operation is short whenever no restart is
/// due and the teardown collects this worker as promptly as any other. The
/// two stops alternate: `SIGTERM`, where the server finishes what it was
/// doing, and `SIGKILL`, where it does not.
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

/// An ordered shutdown must leave the state file exactly as it found it, and
/// a crash must leave a whole document whatever it interrupted.
fn one_restart(site: &Site<'_>, server: &Supervisor, stop: Stop, attempt: u64) -> io::Result<()> {
    match stop {
        Stop::Graceful => graceful_stop(site, server)?,
        Stop::Hard => hard_stop(site, server, attempt)?,
    }
    server.start_again().map_err(io::Error::other)?;
    heal(site);
    Ok(())
}

/// The picture is taken under the quiet lock, so the last persisted mutation
/// is well-defined: an ordered shutdown publishes nothing new, so the file
/// after the stop is the file before it, byte for byte.
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

/// Nothing else in the run uses it and nothing is ever created there: a rule
/// on a name that does not exist changes what the server persists and nothing
/// any other worker can see.
const CRASH_PROBE: &str = "torture-crash-probe";

const MUTATION_PATIENCE: Duration = Duration::from_secs(5);

const KILL_OFFSETS: u64 = 8;

/// The window the kill has to fall inside is one write and one rename behind
/// a durable flush, hundreds of microseconds wide. A single delay would
/// always fall short of the rename or always past it, so the delay walks
/// across the window.
fn kill_offset(attempt: u64) -> Duration {
    Duration::from_micros(200 * ((attempt / 2) % KILL_OFFSETS))
}

/// A kill with nothing in flight proves nothing a crash could violate, so the
/// arm issues a mutation of its own, one rule on a name nothing else uses,
/// and signals between the request and the reply, the interval of the
/// write-and-rename persist of the server.
///
/// The quiet lock is still held, so no other persist can happen in the window
/// and the file afterwards is either the document from before the mutation or
/// the whole document it published. A truncation or a half-written table is
/// neither.
fn hard_stop(site: &Site<'_>, server: &Supervisor, attempt: u64) -> io::Result<()> {
    let socket = site.control.ok_or_else(|| {
        io::Error::other("the restart class kills the server inside a mutation of its own")
    })?;
    let namespace = site.namespace().clone();
    let probe = site.namespace_path(CRASH_PROBE);
    let _quiet = server.quiesce();

    // The rule of the previous cycle comes out first, so this addition is a
    // change that the server must persist and not a duplicate it can reject
    // without writing.
    let _ = one_call(
        site,
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
        let mutation = scope.spawn(|| one_call_from(site, socket, &publish, &sent));
        let on_the_wire = armed(&sent, MUTATION_PATIENCE);
        std::thread::sleep(kill_offset(attempt));
        let stopped = server.stop(Stop::Hard);
        let answered = mutation
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("the mutation could not be carried out")));
        // The request was on the wire and no reply came, so the signal fell between
        // them, the only placement that proves anything about a persist.
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

/// The window is well under a millisecond, so a wait that slept in the tens
/// of milliseconds would put every signal long past the persist.
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

/// The server replies to a mutation only after it synced the state file and its
/// directory, and that sync has no fixed bound. A client that gave up earlier
/// would release the quiet lock while the mutation is still on its way to the
/// disk, and the server would persist it after the restart arm took its
/// picture. When the server never replies, the operation is still in flight
/// when the load ends, and the run reports it as stalled and ends the
/// connection.
fn connect(socket: &Path, connections: &Arc<Connections>) -> io::Result<ControlConnection> {
    let client = Client::connect_with(
        socket,
        Timeouts {
            read: None,
            ..Timeouts::default()
        },
    )
    .map_err(io::Error::other)?;
    let listed = connections.register(Connection::Control(client.stream().try_clone()?));
    Ok(ControlConnection {
        client,
        _listed: listed,
    })
}

struct ControlConnection {
    client: Client,
    _listed: Registration,
}

/// The restart arm holds the quiet lock exclusively while it works, so its
/// calls cannot go through [`Site::control_call`], which would wait for a lock
/// the caller holds.
fn one_call(site: &Site<'_>, socket: &Path, request: &Request) -> io::Result<()> {
    let sent = std::sync::atomic::AtomicBool::new(false);
    one_call_from(site, socket, request, &sent)
}

/// The restart arm signals on the flag: it means the request is on the wire
/// and no reply has come.
fn one_call_from(
    site: &Site<'_>,
    socket: &Path,
    request: &Request,
    sent: &std::sync::atomic::AtomicBool,
) -> io::Result<()> {
    let mut control = connect(socket, site.connections)?;
    let line = serde_json::to_vec(request).map_err(io::Error::other)?;
    control.client.send_line(&line).map_err(io::Error::other)?;
    sent.store(true, std::sync::atomic::Ordering::SeqCst);
    control
        .client
        .read_line()
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("the server closed without answering"))?;
    Ok(())
}

/// A persist is a write to a temporary and a rename over the name, so a
/// signal leaves either the document from before the mutation or the whole
/// document it published, which is what [`parses_as_state`] checks.
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

/// Parsed here, independently of the server, because "the server started
/// again" and "the file survived" are two facts.
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

/// A path-based operation is what the `ESTALE` retry of the kernel heals, so
/// a fresh listing and a fresh stat from each mount root show a healed mount.
/// Descriptors held across the gap are supposed to surface their stale errno.
fn heal(site: &Site<'_>) {
    let roots: Vec<&Path> = site.mounts.iter().map(TortureMount::root).collect();
    heal_all(&roots, HEAL_PATIENCE, site.findings);
}

/// All of them together, because mounts waited out one after another would
/// multiply the healing term of the restart budget by the mount count until
/// the stop, the start and the healing no longer fit inside the watchdog.
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
    use crate::mounts::tests::guardian;

    #[test]
    fn the_state_file_check_accepts_only_a_whole_document() {
        let whole = b"\n[server]\n\n[[namespaces]]\nname = \"torture\"\n";
        assert_eq!(parses_as_state(whole, "torture"), Ok(()));

        assert!(parses_as_state(&whole[..whole.len() - 12], "torture").is_err());
        assert!(parses_as_state(b"", "torture").is_err());
        assert!(parses_as_state(whole, "elsewhere").is_err());
    }

    fn document(rules: &[&str]) -> Vec<u8> {
        let mut text = String::from("[server]\n\n[[namespaces]]\nname = \"torture\"\n");
        for path in rules {
            text.push_str(&format!(
                "\n[[namespaces.rules]]\npath = \"{path}\"\nmode = \"hidden\"\n"
            ));
        }
        text.into_bytes()
    }

    #[test]
    fn a_kill_inside_a_mutation_leaves_one_of_two_documents() {
        let before = document(&[]);
        let after = document(&["/tree/torture-crash-probe"]);

        assert_eq!(
            crash_consistent(&before, &before, "torture", "/tree/torture-crash-probe"),
            Ok(())
        );
        assert_eq!(
            crash_consistent(&before, &after, "torture", "/tree/torture-crash-probe"),
            Ok(())
        );

        assert!(
            crash_consistent(
                &before,
                &after[..after.len() - 12],
                "torture",
                "/tree/torture-crash-probe"
            )
            .is_err()
        );
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

    /// The two orderings agree only when the mount count and the URL count
    /// divide, and a worker that took the URL by its own index would key rules by
    /// a namespace its mount is not a view of.
    #[test]
    fn a_worker_takes_its_url_from_the_mount_it_works_through() {
        let urls = [
            "voidport://127.0.0.1:9000/@one".to_owned(),
            "voidport+vsock://1:9001/@two".to_owned(),
        ];
        let connections = Arc::new(Connections::default());
        let fleet = Fleet::new(
            &urls,
            Path::new("/proc/self/fd"),
            guardian(),
            Arc::clone(&connections),
        )
        .expect("two parseable URLs");
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
                connections: &connections,
                outage: &outage,
                started: Instant::now(),
                restart_interval: Duration::from_secs(1),
            };
            let mine = &mounts[mount_index(index, mounts.len())];
            assert_eq!(site.url(), mine.url(), "worker {index}");
            assert_eq!(site.mount(), mine.root(), "worker {index}");
            assert_eq!(site.namespace(), &mine.url().namespace, "worker {index}");
        }

        assert_ne!(
            mounts[mount_index(3, mounts.len())].url(),
            fleet.url(3),
            "three mounts over two URLs part company at the fourth worker"
        );
    }

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
