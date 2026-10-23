// SPDX-License-Identifier: GPL-2.0

use super::guest::{lasting, raw_mount, require_balanced};
use super::server::{
    Behaviour, Flow, Handle, Rendezvous, Session, State, Stream, error_reply, send, serve_sessions,
};
use crate::{Result, attr, read_reply, response};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{CStr, CString};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, TcpListener};
use std::os::fd::AsRawFd;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use voidport_proto::attr::{Attr, EntryOut};
use voidport_proto::frame::Frame;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::dir::{MknodRequest, MknodResponse};
use voidport_proto::ops::file::{
    CreateRequest, CreateResponse, FileLock, FlushRequest, FlushResponse, FsyncRequest,
    FsyncResponse, GetlkRequest, GetlkResponse, OpenRequest, OpenResponse, ReadRequest,
    ReleaseRequest, ReleaseResponse, SetlkRequest, SetlkResponse, WriteRequest, WriteResponse,
    fsync_flags, lock_type, setlk_flags,
};
use voidport_proto::ops::node::{
    ForgetRequest, GetattrRequest, GetattrResponse, LookupRequest, LookupResponse, SetattrRequest,
    SetattrResponse, StatfsResponse, setattr_valid,
};
use voidport_proto::ops::xattr::GetxattrRequest;
use zerocopy::byteorder::little_endian::{U32, U64};

pub(super) const MOUNT: &str = "/vfs-writable";
const NAMESPACE: &CStr = c"vfs-writable";

const ROOT: u64 = 1;
pub(super) const FIRST_FILE: u64 = 2;

const FLUSH: &str = "flush-withheld-";

const PIECE: usize = 65_536;

/// The bytes a write with `seed` puts at `range` of a file, `seed` 0 being
/// the bytes a file of a case starts with. No page size is a multiple of the
/// period, so bytes placed at the wrong page differ.
pub(super) fn pattern(seed: u8, range: Range<u64>) -> Vec<u8> {
    range
        .map(|offset| ((offset % 251) as u8).wrapping_add(seed))
        .collect()
}

pub(super) struct Mapping {
    address: *mut u8,
    len: usize,
}

impl Mapping {
    pub(super) fn new(file: &std::fs::File, len: usize) -> Result<Self> {
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            address: address.cast(),
            len,
        })
    }

    pub(super) fn store(&self, seed: u8, range: Range<u64>) {
        let bytes = pattern(seed, range.clone());
        assert!(range.end as usize <= self.len);
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.address.add(range.start as usize),
                bytes.len(),
            )
        };
    }

    pub(super) fn sync(&self) -> std::io::Result<()> {
        if unsafe { libc::msync(self.address.cast(), self.len, libc::MS_SYNC) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.address.cast(), self.len) };
    }
}

pub(super) fn path(name: &str) -> String {
    format!("{MOUNT}/{name}")
}

pub(super) struct Held {
    name: Vec<u8>,
    mode: u32,
    content: Vec<u8>,
    mtime: i64,
}

impl Held {
    pub(super) fn new(name: &str, mode: u32, content: Vec<u8>) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            mode,
            content,
            mtime: 1,
        }
    }

    fn attributes(&self, node: u64) -> Attr {
        let mut value = attr(node, self.content.len() as u64);
        value.mode = U32::new(self.mode);
        value.mtime.sec = self.mtime.into();
        value
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Received {
    Open {
        node: u64,
        flags: u32,
    },
    Read {
        node: u64,
        offset: u64,
        size: u32,
    },
    Write {
        node: u64,
        offset: u64,
        len: u32,
    },
    Flush {
        node: u64,
        owner: u64,
    },
    Fsync {
        node: u64,
        datasync: bool,
    },
    Release {
        node: u64,
    },
    Setattr {
        node: u64,
        change: Change,
    },
    Create {
        name: Vec<u8>,
    },
    Forget {
        node: u64,
        count: u64,
    },
    Setlk {
        node: u64,
        handle: u64,
        lock: FileLock,
        wait: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Change {
    pub(super) valid: u32,
    pub(super) mode: u32,
    pub(super) size: u64,
    pub(super) handle: u64,
    pub(super) atime: i64,
    pub(super) mtime: i64,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Answer {
    Took(u32),
    Failed(i32),
}

#[derive(Default)]
struct Log {
    received: Vec<Received>,
    seen: usize,
    withheld: Vec<Opcode>,
    /// The connections whose request the peer withholds the reply to, until
    /// that reply is among the withheld ones. The peer decides this before it
    /// records the request, so once no connection is left here, the reply to
    /// every request a case has seen withheld is among them.
    withholding: HashSet<u64>,
    answers: VecDeque<Answer>,
    stop_at_data: bool,
    stopped: bool,
}

struct Files {
    held: HashMap<u64, Held>,
    next_node: u64,
    handles: HashMap<u64, (u64, u32)>,
    next_handle: u64,
}

impl Files {
    fn node_named(&self, name: &[u8]) -> Option<u64> {
        self.held
            .iter()
            .find(|(_, file)| file.name == name)
            .map(|(&node, _)| node)
    }

    fn attributes(&self, node: u64) -> Result<Attr> {
        if node == ROOT {
            let mut root = attr(ROOT, 0);
            root.mode = U32::new(libc::S_IFDIR | 0o755);
            return Ok(root);
        }
        Ok(self.held(node)?.attributes(node))
    }

    fn held(&self, node: u64) -> Result<&Held> {
        self.held
            .get(&node)
            .ok_or_else(|| format!("unknown node {node}").into())
    }

    fn held_mut(&mut self, node: u64) -> Result<&mut Held> {
        self.held
            .get_mut(&node)
            .ok_or_else(|| format!("unknown node {node}").into())
    }

    fn entry(&self, node: u64) -> Result<EntryOut> {
        Ok(EntryOut {
            node_id: U64::new(node),
            generation: U64::new(1),
            attr: self.attributes(node)?,
        })
    }

    fn add(&mut self, file: Held) -> u64 {
        let node = self.next_node;
        self.next_node += 1;
        self.held.insert(node, file);
        node
    }

    fn open(&mut self, node: u64, flags: u32) -> u64 {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.handles.insert(handle, (node, flags));
        handle
    }

    fn handle(&self, handle: u64) -> Result<(u64, u32)> {
        self.handles
            .get(&handle)
            .copied()
            .ok_or_else(|| format!("unknown handle {handle}").into())
    }
}

pub(super) struct Peer {
    files: Mutex<Files>,
    log: Rendezvous<Log>,
    flushes: AtomicUsize,
    withheld: Mutex<Vec<(Box<dyn Handle>, Vec<u8>)>>,
    serving: OnceLock<Weak<State>>,
}

impl Peer {
    pub(super) fn new(files: Vec<Held>) -> Arc<Self> {
        let mut held = Files {
            held: HashMap::new(),
            next_node: FIRST_FILE,
            handles: HashMap::new(),
            next_handle: 1,
        };
        for file in files {
            held.add(file);
        }
        Arc::new(Self {
            files: Mutex::new(held),
            log: Rendezvous::default(),
            flushes: AtomicUsize::new(0),
            withheld: Mutex::default(),
            serving: OnceLock::new(),
        })
    }

    pub(super) fn withhold(&self, opcodes: &[Opcode]) {
        self.log.update(|log| log.withheld = opcodes.to_vec());
    }

    pub(super) fn answer_writes(&self, answers: &[Answer]) {
        self.log.update(|log| log.answers.extend(answers));
    }

    pub(super) fn stop_at_data(&self) {
        self.log.update(|log| log.stop_at_data = true);
    }

    pub(super) fn wait_stopped(&self) -> Result {
        self.log.wait(|log| log.stopped)
    }

    pub(super) fn resume(&self) {
        self.log.update(|log| {
            log.stop_at_data = false;
            log.stopped = false;
        });
    }

    pub(super) fn send_withheld(&self) {
        self.send_withheld_and_withhold(&[]);
    }

    pub(super) fn send_withheld_and_withhold(&self, opcodes: &[Opcode]) {
        self.withhold(opcodes);
        let flush = self.flushes.fetch_add(1, Ordering::Relaxed);
        let found = std::fs::metadata(path(&format!("{FLUSH}{flush}")));
        assert_eq!(found.unwrap_err().raw_os_error(), Some(libc::ENOENT));
    }

    pub(super) fn send_withheld_and_cut(&self) -> Result {
        self.end_withheld(true)
    }

    pub(super) fn cut_withheld(&self) -> Result {
        self.end_withheld(false)
    }

    fn end_withheld(&self, send: bool) -> Result {
        for (mut connection, reply) in self.take_withheld()? {
            if send {
                connection.write_all(&reply)?;
            }
            connection.shut()?;
        }
        Ok(())
    }

    pub(super) fn wait_retired(&self, count: usize) -> Result {
        let state = self.serving.get().and_then(Weak::upgrade);
        let state = state.ok_or("the peer serves no session")?;
        state.wait_retired(1, count).map(drop)
    }

    pub(super) fn wait(&self, ready: impl Fn(&[Received]) -> bool) -> Result {
        self.log.wait(|log| ready(&log.received[log.seen..]))
    }

    pub(super) fn wait_for(&self, request: &Received) -> Result {
        self.wait(|fresh| fresh.contains(request))
    }

    pub(super) fn take(&self) -> Vec<Received> {
        let mut taken = Vec::new();
        self.log.update(|log| {
            taken = log.received[log.seen..].to_vec();
            log.seen = log.received.len();
        });
        taken
    }

    pub(super) fn received(&self) -> Vec<Received> {
        self.log.read(|log| log.received.clone())
    }

    pub(super) fn content(&self, node: u64) -> Vec<u8> {
        self.files.lock().unwrap().held[&node].content.clone()
    }

    fn record(&self, request: Received) {
        self.log.update(|log| log.received.push(request));
    }

    fn take_withheld(&self) -> Result<Vec<(Box<dyn Handle>, Vec<u8>)>> {
        self.log.wait(|log| log.withholding.is_empty())?;
        Ok(std::mem::take(&mut *self.withheld.lock().unwrap()))
    }
}

#[derive(Debug)]
struct CutInWrite;

impl std::fmt::Display for CutInWrite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the connection ended inside the bytes of a write")
    }
}

impl std::error::Error for CutInWrite {}

impl Behaviour for Peer {
    fn namespace(&self) -> &'static [u8] {
        NAMESPACE.to_bytes()
    }

    fn arrived(&self, _state: &State, _serial: u64, frame: &Frame<'_>) -> Result<Flow> {
        if frame.opcode()? == Opcode::Lookup
            && frame
                .request::<LookupRequest>()?
                .name()
                .starts_with(FLUSH.as_bytes())
        {
            for (mut connection, reply) in self.take_withheld()? {
                connection.write_all(&reply)?;
            }
        }
        Ok(Flow::Next)
    }

    fn reply(
        &self,
        _session: &Session,
        frame: &Frame<'_>,
        stream: &mut dyn Stream,
    ) -> Result<Option<Vec<u8>>> {
        let (opcode, connection) = (frame.opcode()?, stream.connection());
        self.log.update(|log| {
            if log.withheld.contains(&opcode) {
                log.withholding.insert(connection);
            }
        });
        reply(self, frame, stream)
    }

    fn deliver(
        &self,
        _state: &State,
        _serial: u64,
        _frame: &Frame<'_>,
        reply: Vec<u8>,
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        let connection = stream.connection();
        if !self.log.read(|log| log.withholding.contains(&connection)) {
            return send(stream, &reply);
        }
        self.withheld
            .lock()
            .unwrap()
            .push((stream.handle()?, reply));
        self.log.update(|log| {
            log.withholding.remove(&connection);
        });
        Ok(Flow::Next)
    }

    fn severed(&self, error: &(dyn std::error::Error + 'static)) -> bool {
        error.is::<CutInWrite>()
    }

    fn ended(&self) {
        self.log.end();
    }
}

fn reply(peer: &Peer, frame: &Frame<'_>, stream: &mut dyn Stream) -> Result<Option<Vec<u8>>> {
    let id = frame.request_id();
    let opcode = frame.opcode()?;
    let mut files = peer.files.lock().unwrap();
    Ok(Some(match opcode {
        Opcode::Getattr => {
            let node = frame.request::<GetattrRequest>()?.head().node_id.get();
            let attr = files.attributes(node)?;
            response(id, &GetattrResponse { attr }, &[])?
        }
        Opcode::Statfs => response(id, &StatfsResponse::default(), &[])?,
        // The kernel asks for the capabilities of a file before a change that
        // removes them, and the files of this peer have no extended
        // attributes.
        Opcode::Getxattr => {
            frame.request::<GetxattrRequest>()?;
            error_reply(id, opcode, libc::ENODATA)?
        }
        Opcode::Lookup => {
            let request = frame.request::<LookupRequest>()?;
            assert_eq!(request.head().node_id.get(), ROOT);
            match files.node_named(request.name()) {
                Some(node) => {
                    let entry = files.entry(node)?;
                    response(id, &LookupResponse { entry }, &[])?
                }
                None => error_reply(id, opcode, libc::ENOENT)?,
            }
        }
        Opcode::Open => {
            let request = frame.request::<OpenRequest>()?;
            let (node, flags) = (request.head().node_id.get(), request.body().flags.get());
            if flags & libc::O_TRUNC as u32 != 0 {
                files.held_mut(node)?.content.clear();
            }
            let handle = files.open(node, flags);
            peer.record(Received::Open { node, flags });
            let open = OpenResponse {
                handle: U64::new(handle),
                flags: U32::ZERO,
                reserved: U32::ZERO,
            };
            response(id, &open, &[])?
        }
        Opcode::Create => {
            let request = frame.request::<CreateRequest>()?;
            assert_eq!(request.head().node_id.get(), ROOT);
            let body = request.body();
            let mode = libc::S_IFREG | (body.mode.get() & !body.umask.get() & 0o7777);
            let node = files.add(Held::new(
                std::str::from_utf8(request.name())?,
                mode,
                vec![],
            ));
            let handle = files.open(node, body.flags.get());
            peer.record(Received::Create {
                name: request.name().to_vec(),
            });
            let created = CreateResponse {
                entry: files.entry(node)?,
                handle: U64::new(handle),
                flags: U32::ZERO,
                reserved: U32::ZERO,
            };
            response(id, &created, &[])?
        }
        Opcode::Mknod => {
            let request = frame.request::<MknodRequest>()?;
            let body = request.body();
            let mode = body.mode.get() & !(body.umask.get() & 0o7777);
            let node = files.add(Held::new(
                std::str::from_utf8(request.name())?,
                mode,
                vec![],
            ));
            let entry = files.entry(node)?;
            response(id, &MknodResponse { entry }, &[])?
        }
        Opcode::Read => {
            let body = *frame.request::<ReadRequest>()?.body();
            let (node, _) = files.handle(body.handle.get())?;
            let (offset, size) = (body.offset.get(), body.size.get());
            peer.record(Received::Read { node, offset, size });
            let content = &files.held(node)?.content;
            let start = usize::try_from(offset)?.min(content.len());
            let end = (start + size as usize).min(content.len());
            let pieces: Vec<&[u8]> = content[start..end].chunks(PIECE).collect();
            read_reply(id, &pieces, 0, end == content.len())?
        }
        Opcode::Write => {
            let body = *frame.request::<WriteRequest>()?.body();
            let (node, flags) = files.handle(body.handle.get())?;
            let (offset, len) = (body.offset.get(), body.data_len.get());
            peer.record(Received::Write { node, offset, len });
            let mut stopped = false;
            peer.log.update(|log| {
                stopped = log.stop_at_data;
                log.stopped = stopped;
            });
            if stopped {
                drop(files);
                peer.log.wait(|log| !log.stopped)?;
                files = peer.files.lock().unwrap();
            }
            let mut data = vec![0; len as usize];
            stream.read_exact(&mut data).map_err(
                |error| -> Box<dyn std::error::Error + Send + Sync> {
                    match error.kind() {
                        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset => {
                            Box::new(CutInWrite)
                        }
                        _ => Box::new(error),
                    }
                },
            )?;
            let mut answer = None;
            peer.log.update(|log| answer = log.answers.pop_front());
            let took = match answer.unwrap_or(Answer::Took(len)) {
                Answer::Took(took) => took,
                Answer::Failed(errno) => return Ok(Some(error_reply(id, opcode, errno)?)),
            };
            let file = files.held_mut(node)?;
            let at = if flags & libc::O_APPEND as u32 != 0 {
                file.content.len()
            } else {
                usize::try_from(offset)?
            };
            let end = at + took as usize;
            if file.content.len() < end {
                file.content.resize(end, 0);
            }
            file.content[at..end].copy_from_slice(&data[..took as usize]);
            file.mtime += 1;
            response(
                id,
                &WriteResponse {
                    written: U32::new(took),
                },
                &[],
            )?
        }
        Opcode::Setattr => {
            let request = frame.request::<SetattrRequest>()?;
            let (node, body) = (request.head().node_id.get(), *request.body());
            let change = Change {
                valid: body.valid.get(),
                mode: body.mode.get(),
                size: body.size.get(),
                handle: body.handle.get(),
                atime: body.atime.sec.get(),
                mtime: body.mtime.sec.get(),
            };
            peer.record(Received::Setattr { node, change });
            let file = files.held_mut(node)?;
            if change.valid & setattr_valid::MODE != 0 {
                file.mode = (file.mode & libc::S_IFMT) | (change.mode & 0o7777);
            }
            if change.valid & setattr_valid::SIZE != 0 {
                file.content.resize(usize::try_from(change.size)?, 0);
            }
            if change.valid & setattr_valid::MTIME != 0 {
                file.mtime = change.mtime;
            }
            let attr = file.attributes(node);
            response(id, &SetattrResponse { attr }, &[])?
        }
        Opcode::Flush => {
            let body = *frame.request::<FlushRequest>()?.body();
            let (node, _) = files.handle(body.handle.get())?;
            let owner = body.lock_owner.get();
            peer.record(Received::Flush { node, owner });
            response(id, &FlushResponse {}, &[])?
        }
        Opcode::Fsync => {
            let body = *frame.request::<FsyncRequest>()?.body();
            let (node, _) = files.handle(body.handle.get())?;
            let datasync = body.flags.get() & fsync_flags::DATASYNC != 0;
            peer.record(Received::Fsync { node, datasync });
            response(id, &FsyncResponse {}, &[])?
        }
        Opcode::Getlk => {
            let body = *frame.request::<GetlkRequest>()?.body();
            files.handle(body.handle.get())?;
            let mut lock = body.lock;
            lock.lock_type = U32::new(lock_type::UNLOCK);
            response(id, &GetlkResponse { lock }, &[])?
        }
        Opcode::Setlk => {
            let request = frame.request::<SetlkRequest>()?;
            let (node, body) = (request.head().node_id.get(), *request.body());
            peer.record(Received::Setlk {
                node,
                handle: body.handle.get(),
                lock: body.lock,
                wait: body.flags.get() & setlk_flags::WAIT != 0,
            });
            response(id, &SetlkResponse {}, &[])?
        }
        Opcode::Release => {
            let body = *frame.request::<ReleaseRequest>()?.body();
            let (node, _) = files
                .handles
                .remove(&body.handle.get())
                .ok_or("a release of an unknown handle")?;
            peer.record(Received::Release { node });
            response(id, &ReleaseResponse {}, &[])?
        }
        Opcode::Forget => {
            let request = frame.request::<ForgetRequest>()?;
            peer.record(Received::Forget {
                node: request.head().node_id.get(),
                count: request.body().nlookup.get(),
            });
            return Ok(None);
        }
        opcode => return Err(format!("unexpected writable peer opcode {opcode:?}").into()),
    }))
}

pub(super) fn mount(peer: &Arc<Peer>, options: &str) -> Result<std::thread::JoinHandle<Result>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let state = Arc::new(State::with(peer.clone()));
    peer.serving
        .set(Arc::downgrade(&state))
        .map_err(|_| "the peer is mounted already")?;
    let serving = peer.clone();
    let session = std::thread::spawn(move || -> Result {
        serve_sessions(&listener, 1, &state, |_| Ok(()), &|_| {})?;
        if !serving.withheld.lock().unwrap().is_empty() {
            return Err("withheld replies were never sent".into());
        }
        Ok(())
    });
    std::fs::create_dir_all(MOUNT)?;
    let options = CString::new(format!(
        "addr=127.0.0.1,port={port},{},{options}",
        lasting()
    ))?;
    let target = CString::new(MOUNT)?;
    if raw_mount(NAMESPACE, &target, &options, 0) != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(session)
}

pub(super) fn remount(read_only: bool) -> std::io::Result<()> {
    let target = CString::new(MOUNT)?;
    let flags = libc::MS_REMOUNT | if read_only { libc::MS_RDONLY } else { 0 };
    if raw_mount(NAMESPACE, &target, c"", flags) == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub(super) fn unmount(session: std::thread::JoinHandle<Result>) -> Result {
    let target = CString::new(MOUNT)?;
    assert_eq!(
        unsafe { libc::umount(target.as_ptr()) },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
    session.join().map_err(|_| "the writable peer panicked")??;
    require_balanced()
}
