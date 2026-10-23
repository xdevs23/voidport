//! A passthrough filesystem for tests that can fail or delay the directory sync
//! after the rename that moves `manifest.json` into place, and counts the write
//! requests of every file renamed into place. Nothing outside the filesystem can
//! make that sync fail or stop a process between the rename and the sync.

use rustix::{
    event::{EventfdFlags, PollFd, PollFlags, eventfd, poll},
    fs::{AtFlags, Mode, OFlags, mkdirat, open, openat, renameat_with, statat},
    io::Errno,
    mount::{UnmountFlags, unmount},
    process::{Pid, PidfdFlags, pidfd_open},
};
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fs::{DirEntry, File, OpenOptions, read_dir},
    io,
    num::NonZeroUsize,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::fs::{DirEntryExt, FileExt, MetadataExt},
    },
    path::{Path, PathBuf},
    process::Child,
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::Duration,
};
use voidport_fuse::{
    Attributes, Create, Entry, ErrorReply, FileType, Filesystem, FilesystemStats, FopenFlags,
    MountOptions, MountSource, Operation, Permissions, Read, Rename, RenameFlags, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyWrite, Request,
    ServeError, Session, Timestamp, Write,
};

const MANIFEST: &str = "manifest.json";
/// The kernel asks again for every attribute and name, so it never shows a
/// state the directory no longer has.
const TTL: Duration = Duration::ZERO;

#[derive(Default)]
enum SyncOutcome {
    #[default]
    Pass,
    Fail,
    Hold(OwnedFd),
}

#[derive(Default)]
struct Plan {
    sync: SyncOutcome,
    renamed_into: Option<u64>,
    held: Option<ReplyEmpty>,
}

#[derive(Default)]
struct Writes {
    pending: HashMap<u64, usize>,
    published: Vec<(OsString, usize)>,
}

struct Passthrough {
    /// A descriptor for every node the kernel looked up, by inode number. An
    /// open descriptor stops the inode number from being handed out again.
    nodes: Mutex<HashMap<u64, Arc<File>>>,
    plan: Arc<Mutex<Plan>>,
    writes: Arc<Mutex<Writes>>,
}

/// The path that opens `node` again, whatever its name has become.
fn path_of(node: &File) -> String {
    format!("/proc/self/fd/{}", node.as_raw_fd())
}
fn reopen(node: &File, options: &OpenOptions) -> io::Result<File> {
    options.open(path_of(node))
}
fn timestamp(seconds: i64, nanoseconds: i64) -> Timestamp {
    Timestamp {
        seconds,
        nanoseconds: nanoseconds as u32,
    }
}
fn attribute(node: &File, ino: u64) -> io::Result<Attributes> {
    let metadata = node.metadata()?;
    Ok(Attributes {
        ino,
        size: metadata.size(),
        blocks: metadata.blocks(),
        atime: timestamp(metadata.atime(), metadata.atime_nsec()),
        mtime: timestamp(metadata.mtime(), metadata.mtime_nsec()),
        ctime: timestamp(metadata.ctime(), metadata.ctime_nsec()),
        kind: FileType::from_raw_mode(metadata.mode()),
        permissions: Permissions::from_mode(metadata.mode()),
        nlink: metadata.nlink() as u32,
        uid: metadata.uid(),
        gid: metadata.gid(),
        rdev: metadata.rdev() as u32,
        blksize: metadata.blksize() as u32,
    })
}
fn entry(node: u64, attributes: Attributes) -> Entry {
    Entry {
        node,
        generation: 0,
        attributes,
        entry_valid: TTL,
        attr_valid: TTL,
    }
}
fn reply_with<R: ErrorReply, T>(reply: R, result: io::Result<T>, send: impl FnOnce(R, T)) {
    match result {
        Ok(value) => send(reply, value),
        Err(error) => reply.error(Errno::from_io_error(&error).unwrap_or(Errno::IO)),
    }
}
fn replied(result: io::Result<()>, reply: ReplyEmpty) {
    reply_with(reply, result, |reply, ()| reply.ok());
}
fn entry_replied(result: io::Result<Attributes>, reply: ReplyEntry) {
    let send = |reply: ReplyEntry, attributes: Attributes| {
        reply.entry(&entry(attributes.ino, attributes));
    };
    reply_with(reply, result, send);
}

impl Passthrough {
    fn node(&self, ino: u64) -> io::Result<Arc<File>> {
        let nodes = self.nodes.lock().unwrap();
        let node = nodes.get(&ino).ok_or(Errno::NOENT)?;
        Ok(Arc::clone(node))
    }
    fn lookup_child(&self, parent: u64, name: &OsStr) -> io::Result<Attributes> {
        let child = File::from(openat(
            &*self.node(parent)?,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let ino = child.metadata()?.ino();
        let attributes = attribute(&child, ino)?;
        self.nodes
            .lock()
            .unwrap()
            .entry(ino)
            .or_insert_with(|| Arc::new(child));
        Ok(attributes)
    }
    fn sync(&self, ino: u64) -> io::Result<()> {
        reopen(&*self.node(ino)?, OpenOptions::new().read(true))?.sync_all()
    }
    fn create(&self, create: &Create<'_>, reply: ReplyCreate) {
        let created = self.node(create.parent).and_then(|directory| {
            openat(
                &*directory,
                create.name,
                create.flags | OFlags::CREATE,
                Mode::from_bits_truncate(create.mode & !create.umask),
            )?;
            self.lookup_child(create.parent, create.name)
        });
        let send = |reply: ReplyCreate, attributes: Attributes| {
            reply.created(&entry(attributes.ino, attributes), 0, FopenFlags::empty());
        };
        reply_with(reply, created, send);
    }
    fn read(&self, read: &Read) -> io::Result<Vec<u8>> {
        let node = self.node(read.node)?;
        let mut bytes = vec![0; read.size as usize];
        let length =
            reopen(&node, OpenOptions::new().read(true))?.read_at(&mut bytes, read.offset)?;
        bytes.truncate(length);
        Ok(bytes)
    }
    fn write(&self, write: &Write<'_>) -> io::Result<u32> {
        let node = self.node(write.node)?;
        reopen(&node, OpenOptions::new().write(true))?.write_all_at(write.data, write.offset)?;
        *self
            .writes
            .lock()
            .unwrap()
            .pending
            .entry(write.node)
            .or_default() += 1;
        Ok(write.data.len() as u32)
    }
    fn list(&self, ino: u64) -> io::Result<Vec<DirEntry>> {
        let node = self.node(ino)?;
        let mut entries = read_dir(path_of(&node))?.collect::<io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        Ok(entries)
    }
    fn rename(&self, rename: &Rename<'_>) -> io::Result<()> {
        let into = self.node(rename.new_parent)?;
        renameat_with(
            &*self.node(rename.parent)?,
            rename.name,
            &*into,
            rename.new_name,
            rename.flags,
        )?;
        if rename.flags.contains(RenameFlags::NOREPLACE) || rename.new_name == MANIFEST {
            let ino = statat(&*into, rename.new_name, AtFlags::SYMLINK_NOFOLLOW)?.st_ino;
            let mut writes = self.writes.lock().unwrap();
            let requests = writes.pending.remove(&ino).unwrap_or(0);
            writes
                .published
                .push((rename.new_name.to_owned(), requests));
        }
        if rename.new_name == MANIFEST {
            self.plan.lock().unwrap().renamed_into = Some(rename.new_parent);
        }
        Ok(())
    }
    fn fsyncdir(&self, ino: u64, reply: ReplyEmpty) {
        let mut plan = self.plan.lock().unwrap();
        let sync = match plan.renamed_into.take_if(|directory| *directory == ino) {
            Some(_) => std::mem::take(&mut plan.sync),
            None => SyncOutcome::Pass,
        };
        match sync {
            SyncOutcome::Pass => replied(self.sync(ino), reply),
            SyncOutcome::Fail => reply.error(Errno::IO),
            SyncOutcome::Hold(arrived) => {
                plan.held = Some(reply);
                rustix::io::write(&arrived, &1u64.to_ne_bytes()).unwrap();
            }
        }
    }
}

impl Filesystem for Passthrough {
    fn handle(&self, _request: Request, operation: Operation<'_>) {
        match operation {
            Operation::Lookup(lookup, reply) => {
                entry_replied(self.lookup_child(lookup.parent, lookup.name), reply);
            }
            Operation::Getattr(getattr, reply) => {
                let attributes = self
                    .node(getattr.node)
                    .and_then(|node| attribute(&node, getattr.node));
                let send = |reply: ReplyAttr, attributes| reply.attr(&attributes, TTL);
                reply_with(reply, attributes, send);
            }
            Operation::Mkdir(mkdir, reply) => {
                let made = self.node(mkdir.parent).and_then(|directory| {
                    mkdirat(
                        &*directory,
                        mkdir.name,
                        Mode::from_bits_truncate(mkdir.mode & !mkdir.umask),
                    )?;
                    self.lookup_child(mkdir.parent, mkdir.name)
                });
                entry_replied(made, reply);
            }
            Operation::Create(create, reply) => self.create(&create, reply),
            Operation::Read(read, reply) => {
                let send = |reply: ReplyData, bytes: Vec<u8>| reply.data(&bytes);
                reply_with(reply, self.read(&read), send);
            }
            Operation::Write(write, reply) => {
                let send = |reply: ReplyWrite, length| reply.written(length);
                reply_with(reply, self.write(&write), send);
            }
            Operation::Readdir(read, reply) => {
                let send = |mut reply: ReplyDirectory, entries: Vec<DirEntry>| {
                    for (index, entry) in entries.iter().enumerate().skip(read.offset as usize) {
                        let kind = entry.metadata().map_or(FileType::Unknown, |metadata| {
                            FileType::from_raw_mode(metadata.mode())
                        });
                        if reply.add(entry.ino(), index as u64 + 1, kind, &entry.file_name()) {
                            break;
                        }
                    }
                    reply.ok();
                };
                reply_with(reply, self.list(read.node), send);
            }
            Operation::Rename(rename, reply) => replied(self.rename(&rename), reply),
            Operation::Fsync(fsync, reply) => replied(self.sync(fsync.node), reply),
            Operation::Fsyncdir(fsync, reply) => self.fsyncdir(fsync.node, reply),
            Operation::Open(_, reply) | Operation::Opendir(_, reply) => {
                reply.opened(0, FopenFlags::empty());
            }
            Operation::Release(_, reply) | Operation::Releasedir(_, reply) => reply.ok(),
            Operation::Statfs(_, reply) => reply.statfs(&FilesystemStats {
                blocks: 0,
                free_blocks: 0,
                available_blocks: 0,
                files: 0,
                free_files: 0,
                block_size: 512,
                name_length: 255,
                fragment_size: 0,
            }),
            Operation::Forget(_) => {}
            other => other.unsupported(),
        }
    }
}

pub struct FaultyFilesystem {
    pub mountpoint: PathBuf,
    plan: Arc<Mutex<Plan>>,
    writes: Arc<Mutex<Writes>>,
    session: Option<JoinHandle<Result<(), ServeError>>>,
}

impl FaultyFilesystem {
    pub fn mount(backing: &Path, mountpoint: &Path) -> Self {
        std::fs::create_dir(backing).unwrap();
        std::fs::create_dir(mountpoint).unwrap();
        let root = open(backing, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).unwrap();
        let plan = Arc::default();
        let writes = Arc::default();
        let filesystem = Passthrough {
            nodes: Mutex::new(HashMap::from([(
                voidport_fuse::ROOT_ID,
                Arc::new(File::from(root)),
            )])),
            plan: Arc::clone(&plan),
            writes: Arc::clone(&writes),
        };
        let options = MountOptions {
            source: MountSource::new("faulty-filesystem").expect("a plain source"),
            default_permissions: false,
            allow_other: false,
            read_only: false,
            auto_unmount: None,
        };
        let session = Session::mount(mountpoint, &options, |_| Ok(filesystem))
            .expect("mount the faulty filesystem, which needs /dev/fuse");
        let session = std::thread::spawn(move || {
            // The stopper is dropped only once the session has returned, so
            // that only the end of the connection ends the session.
            let (stop, _running) = voidport_fuse::stop().unwrap();
            session.serve(NonZeroUsize::MIN, &stop, |_| Ok(()))
        });
        Self {
            mountpoint: mountpoint.to_owned(),
            plan,
            writes,
            session: Some(session),
        }
    }
    pub fn published_files(&self) -> Vec<(OsString, usize)> {
        self.writes.lock().unwrap().published.clone()
    }
    pub fn fail_next_sync(&self) {
        self.plan.lock().unwrap().sync = SyncOutcome::Fail;
    }
    pub fn hold_next_sync(&self) -> OwnedFd {
        let arrived = eventfd(0, EventfdFlags::CLOEXEC).unwrap();
        self.plan.lock().unwrap().sync = SyncOutcome::Hold(arrived.try_clone().unwrap());
        arrived
    }
    /// A process cannot end while a request it sent to the filesystem waits for
    /// its reply, so a process killed at the held sync ends only now.
    pub fn release_held_sync(&self) {
        let held = self.plan.lock().unwrap().held.take();
        held.expect("a held sync").ok();
    }
    /// A process started with `voidport_spawn` gets no file of the test
    /// process, so a process started by another test does not make the unmount
    /// fail.
    pub fn unmount(mut self) {
        unmount(&self.mountpoint, UnmountFlags::empty()).unwrap_or_else(|errno| {
            panic!(
                "unmounting the faulty filesystem at {} failed: {errno}. EBUSY \
                 means that the test left a process or a file in the filesystem",
                self.mountpoint.display()
            )
        });
        let session = self.session.take().unwrap();
        session.join().unwrap().unwrap();
    }
}

pub fn wait_for_held_sync(arrived: &OwnedFd, process: &mut Child) {
    let ended = pidfd_open(Pid::from_child(process), PidfdFlags::empty()).unwrap();
    let mut events = [
        PollFd::new(arrived, PollFlags::IN),
        PollFd::new(&ended, PollFlags::IN),
    ];
    poll(&mut events, None).unwrap();
    assert!(
        events[0].revents().contains(PollFlags::IN),
        "the process ended before the sync arrived: {:?}",
        process.wait()
    );
}

/// The test can end while a process it started still has a file open in the
/// filesystem or runs with its working directory in it. A plain unmount fails
/// then, and the mount would remain in the mount table. A detached mount leaves
/// the table at once.
impl Drop for FaultyFilesystem {
    fn drop(&mut self) {
        if self.session.is_some()
            && let Err(errno) = unmount(&self.mountpoint, UnmountFlags::DETACH)
        {
            eprintln!(
                "detaching the faulty filesystem at {} failed: {errno}",
                self.mountpoint.display()
            );
        }
    }
}
