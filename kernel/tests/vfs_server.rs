// SPDX-License-Identifier: GPL-2.0

use crate::supervision::{Connection, Listener, Supervision, spawn_peer};
use crate::{LIMITS, Result, accepting_reply, attr, piece_of, read_frame, read_reply, response};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Condvar, Mutex};
use voidport_proto::attr::{Attr, EntryOut};
use voidport_proto::frame::{Frame, FrameWriter};
use voidport_proto::message::Request;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::connection::{
    OutcomeRequest, OutcomeResponse, RetireRequest, RetireResponse, outcome_state,
};
use voidport_proto::ops::dir::{
    DirEntryHeader, EntryType, MkdirRequest, MkdirResponse, ReaddirplusRequest, ReaddirplusResponse,
};
use voidport_proto::ops::file::{
    FsyncRequest, FsyncResponse, OpenRequest, OpenResponse, ReadRequest, ReleaseRequest,
    ReleaseResponse,
};
use voidport_proto::ops::handshake::HelloRequest;
use voidport_proto::ops::node::{
    ForgetRequest, GetattrRequest, GetattrResponse, LookupRequest, LookupResponse, ReadlinkRequest,
    ReadlinkResponse, StatfsRequest, StatfsResponse,
};
use voidport_proto::piece::Closing;
use zerocopy::IntoBytes;
use zerocopy::byteorder::little_endian::{U32, U64};

pub(super) enum Flow {
    Next,
    End,
    Close,
    Sever,
}

pub(super) trait Stream: Read + Write {
    fn connection(&self) -> u64;

    fn handle(&self) -> std::io::Result<Box<dyn Handle>>;
}

pub(super) trait Handle: Write + Send {
    fn shut(&self) -> std::io::Result<()>;
}

impl<S: Connection> Handle for S {
    fn shut(&self) -> std::io::Result<()> {
        self.close()
    }
}

struct Link<S> {
    connection: u64,
    stream: S,
}

impl<S: Read> Read for Link<S> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buffer)
    }
}

impl<S: Write> Write for Link<S> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl<S: Connection> Stream for Link<S> {
    fn connection(&self) -> u64 {
        self.connection
    }

    fn handle(&self) -> std::io::Result<Box<dyn Handle>> {
        Ok(Box::new(self.stream.duplicate()?))
    }
}

pub(super) fn send(stream: &mut dyn Stream, reply: &[u8]) -> Result<Flow> {
    stream.write_all(reply)?;
    Ok(Flow::Next)
}

/// Once the peer has ended, a wait for a value that is not there fails
/// instead of waiting for ever.
pub(super) struct Rendezvous<T> {
    waited: Mutex<Waited<T>>,
    changed: Condvar,
}

struct Waited<T> {
    pub(super) value: T,
    pub(super) ended: bool,
}

impl<T> Rendezvous<T> {
    pub(super) fn new(value: T) -> Self {
        Self {
            waited: Mutex::new(Waited {
                value,
                ended: false,
            }),
            changed: Condvar::new(),
        }
    }

    pub(super) fn update(&self, change: impl FnOnce(&mut T)) {
        change(&mut self.waited.lock().unwrap().value);
        self.changed.notify_all();
    }

    pub(super) fn read<R>(&self, read: impl FnOnce(&T) -> R) -> R {
        read(&self.waited.lock().unwrap().value)
    }

    pub(super) fn wait(&self, ready: impl Fn(&T) -> bool) -> Result {
        let waited = self
            .changed
            .wait_while(self.waited.lock().unwrap(), |waited| {
                !ready(&waited.value) && !waited.ended
            })
            .unwrap();
        if ready(&waited.value) {
            Ok(())
        } else {
            Err("the peer ended before the event".into())
        }
    }

    pub(super) fn end(&self) {
        self.waited.lock().unwrap().ended = true;
        self.changed.notify_all();
    }
}

impl<T: Default> Default for Rendezvous<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

pub(super) trait Behaviour: Send + Sync {
    fn namespace(&self) -> &'static [u8] {
        b"vfs-options"
    }

    fn path(&self) -> &'static [u8] {
        b""
    }

    fn hello(
        &self,
        _state: &State,
        _serial: u64,
        reply: &[u8],
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        send(stream, reply)
    }

    fn join(
        &self,
        _state: &State,
        _serial: u64,
        _id: u64,
        reply: &[u8],
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        send(stream, reply)
    }

    fn attributes(&self, _index: u64, _attr: &mut Attr) {}

    fn entry(&self, _serial: u64, _opcode: Opcode, _index: u64, _entry: &mut EntryOut) {}

    fn listing(&self, _cookie: u64, _listing: &mut Listing) {}

    fn link(&self, _target: &mut &'static [u8]) {}

    fn statfs(&self, _reply: &mut StatfsResponse) {}

    /// Runs when `frame` arrives in the session `serial`, before the peer
    /// applies it. Any flow but [`Flow::Next`] leaves the request unapplied
    /// and unanswered.
    fn arrived(&self, _state: &State, _serial: u64, _frame: &Frame<'_>) -> Result<Flow> {
        Ok(Flow::Next)
    }

    fn reply(
        &self,
        session: &Session,
        frame: &Frame<'_>,
        _stream: &mut dyn Stream,
    ) -> Result<Option<Vec<u8>>> {
        session.own_reply(frame)
    }

    fn applied(&self, _state: &State, _serial: u64, _frame: &Frame<'_>) -> Result<Flow> {
        Ok(Flow::Next)
    }

    fn deliver(
        &self,
        _state: &State,
        _serial: u64,
        _frame: &Frame<'_>,
        reply: Vec<u8>,
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        send(stream, &reply)
    }

    fn end(&self, _state: &State, _stream: &mut dyn Stream) -> Result {
        Ok(())
    }

    fn severed(&self, _error: &(dyn std::error::Error + 'static)) -> bool {
        false
    }

    fn ended(&self) {}
}

struct Server;

impl Behaviour for Server {}

pub(super) struct Listing {
    pub(super) entries: Vec<Listed>,
    pub(super) exhausted: bool,
}

pub(super) struct Listed {
    pub(super) index: u64,
    pub(super) name: &'static [u8],
    pub(super) next_cookie: u64,
    pub(super) entry_type: u32,
}

impl Listed {
    pub(super) fn new(index: u64, name: &'static [u8]) -> Self {
        Self {
            index,
            name,
            next_cookie: index,
            entry_type: EntryType::Regular as u32,
        }
    }
}

pub(super) struct State {
    behaviour: Arc<dyn Behaviour>,
    pub(super) gets: AtomicUsize,
    pub(super) version: AtomicUsize,
    read_boundaries: Mutex<Vec<usize>>,
    events: Rendezvous<Events>,
    sessions: Mutex<Vec<Arc<Session>>>,
}

impl Default for State {
    fn default() -> Self {
        Self::with(Arc::new(Server))
    }
}

pub(super) const FLUSH: &str = "flush-withheld";

pub(super) const MADE: &str = "made";

#[derive(Default)]
pub(super) struct Events {
    finished: Vec<u64>,
    pub(super) forgotten: HashMap<(u64, u64), u64>,
    pub(super) lookups: HashMap<(u64, String), Vec<u64>>,
    pub(super) released: usize,
    pub(super) fsyncs: Vec<u32>,
    connections: HashMap<u64, u64>,
    closed: HashMap<u64, u64>,
    settled: HashMap<u64, Vec<Settled>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Settled {
    Asked {
        connection: u64,
        request: u64,
        state: u32,
    },
    Retired {
        connection: u64,
    },
}

impl State {
    pub(super) fn with(behaviour: Arc<dyn Behaviour>) -> Self {
        Self {
            behaviour,
            gets: AtomicUsize::new(0),
            version: AtomicUsize::new(0),
            read_boundaries: Mutex::default(),
            events: Rendezvous::default(),
            sessions: Mutex::default(),
        }
    }

    pub(super) fn wait(&self, serial: u64, observed: impl Fn(&Events) -> bool) -> Result {
        self.events
            .wait(|events| observed(events) || events.finished.contains(&serial))?;
        if self.events.read(&observed) {
            Ok(())
        } else {
            Err(format!("peer session {serial} exited before its expected event").into())
        }
    }

    pub(super) fn forgotten(&self, serial: u64, index: u64) -> u64 {
        self.events.read(|events| {
            events
                .forgotten
                .get(&(serial, wire_node(serial, index)))
                .copied()
                .unwrap_or(0)
        })
    }

    pub(super) fn wait_forgotten(&self, serial: u64, expected: &[(u64, u64)]) -> Result {
        self.wait(serial, |events| {
            expected.iter().all(|&(index, count)| {
                events
                    .forgotten
                    .get(&(serial, wire_node(serial, index)))
                    .copied()
                    .unwrap_or(0)
                    >= count
            })
        })?;
        for &(index, count) in expected {
            assert_eq!(self.forgotten(serial, index), count, "FORGET index={index}");
        }
        Ok(())
    }

    pub(super) fn lookups(&self, serial: u64, name: &str) -> usize {
        self.events.read(|events| {
            events
                .lookups
                .get(&(serial, name.to_owned()))
                .map_or(0, Vec::len)
        })
    }

    pub(super) fn released(&self) -> usize {
        self.events.read(|events| events.released)
    }

    pub(super) fn fsyncs(&self) -> Vec<u32> {
        self.events.read(|events| events.fsyncs.clone())
    }

    pub(super) fn connections(&self, serial: u64) -> u64 {
        self.events
            .read(|events| events.connections.get(&serial).copied().unwrap_or(0))
    }

    pub(super) fn closed(&self, serial: u64) -> u64 {
        self.events
            .read(|events| events.closed.get(&serial).copied().unwrap_or(0))
    }

    pub(super) fn wait_closed(&self, serial: u64) -> Result {
        self.events
            .wait(|events| events.closed.contains_key(&serial) || events.finished.contains(&serial))
    }

    pub(super) fn wait_retired(&self, serial: u64, count: usize) -> Result<Vec<Settled>> {
        let retired = |events: &Events| {
            events.settled.get(&serial).map_or(0, |settled| {
                settled
                    .iter()
                    .filter(|settled| matches!(settled, Settled::Retired { .. }))
                    .count()
            })
        };
        self.wait(serial, |events| retired(events) >= count)?;
        Ok(self
            .events
            .read(|events| events.settled.get(&serial).cloned().unwrap_or_default()))
    }

    fn settled(&self, serial: u64, settled: Settled) {
        self.events
            .update(|events| events.settled.entry(serial).or_default().push(settled));
    }

    fn open(self: &Arc<Self>, serial: u64) -> Arc<Session> {
        let session = Arc::new(Session {
            state: self.clone(),
            serial,
            token: format!("vfs-session-{serial}").into_bytes(),
            records: Mutex::new(Records {
                identities: HashMap::from([(1, 0)]),
                next_handle: 1,
                ..Records::default()
            }),
            connections: Mutex::default(),
            closed: Condvar::new(),
        });
        self.sessions.lock().unwrap().push(session.clone());
        session
    }

    fn named(&self, token: &[u8]) -> Option<Arc<Session>> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .iter()
            .find(|session| session.token == token)
            .cloned()
    }

    fn cut(&self) {
        let sessions = self.sessions.lock().unwrap().clone();
        for session in sessions {
            // The failure that ends the sessions is the one the peer reports.
            let _ = session.cut();
        }
    }
}

#[derive(Default)]
pub(super) struct Withhold {
    opcodes: Mutex<Vec<Opcode>>,
    replies: Mutex<Vec<(Opcode, Box<dyn Handle>, Vec<u8>)>>,
    requests: Rendezvous<Vec<(Opcode, u64)>>,
}

impl Withhold {
    pub(super) fn set(&self, opcodes: &[Opcode]) {
        *self.opcodes.lock().unwrap() = opcodes.to_vec();
    }

    pub(super) fn flush(&self) -> Result {
        self.flush_with(|_| Ok(()))
    }

    pub(super) fn flush_with(&self, follow: impl Fn(&mut dyn Handle) -> Result) -> Result {
        self.set(&[]);
        for (_, mut connection, withheld) in self.replies.lock().unwrap().drain(..).rev() {
            connection.write_all(&withheld)?;
            follow(&mut *connection)?;
        }
        Ok(())
    }

    pub(super) fn sever(&self, opcode: Opcode) -> Result {
        let mut replies = self.replies.lock().unwrap();
        for (_, connection, _) in replies.iter().filter(|(withheld, ..)| *withheld == opcode) {
            shut(&**connection)?;
        }
        replies.retain(|(withheld, ..)| *withheld != opcode);
        Ok(())
    }

    pub(super) fn wait(&self, opcode: Opcode, count: usize) -> Result {
        self.requests.wait(|requests| {
            requests
                .iter()
                .filter(|(withheld, _)| *withheld == opcode)
                .count()
                == count
        })
    }
}

impl Behaviour for Withhold {
    fn deliver(
        &self,
        _state: &State,
        _serial: u64,
        frame: &Frame<'_>,
        reply: Vec<u8>,
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        let opcode = frame.opcode()?;
        if opcode == Opcode::Lookup && frame.request::<LookupRequest>()?.name() == FLUSH.as_bytes()
        {
            self.flush()?;
        } else if self.opcodes.lock().unwrap().contains(&opcode) {
            self.replies
                .lock()
                .unwrap()
                .push((opcode, stream.handle()?, reply));
            let request = (opcode, frame.request_id());
            self.requests.update(|requests| requests.push(request));
            return Ok(Flow::Next);
        }
        send(stream, &reply)
    }

    fn ended(&self) {
        self.requests.end();
    }
}

pub(super) type Readers = Vec<(u64, std::thread::JoinHandle<std::io::Result<Vec<u8>>>)>;

pub(super) fn spawn_readers(indexes: std::ops::Range<u64>) -> Readers {
    indexes
        .map(|index| {
            let reader = std::thread::spawn(move || fs::read(format!("/vfs-options/n{index}")));
            (index, reader)
        })
        .collect()
}

pub(super) fn busy(withhold: &Withhold) -> Result<Readers> {
    withhold.set(&[Opcode::Read]);
    let readers = spawn_readers(DISTINCT.start..DISTINCT.start + 1);
    withhold.wait(Opcode::Read, 1)?;
    Ok(readers)
}

pub(super) fn flush_readers(readers: Readers) -> Result {
    assert_eq!(
        fs::metadata(format!("/vfs-options/{FLUSH}"))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    join_readers(readers)
}

pub(super) fn join_readers(readers: Readers) -> Result {
    for (index, reader) in readers {
        let content = reader.join().map_err(|_| "a reader panicked")??;
        assert_eq!(content, distinct_content(index), "the reply of n{index}");
    }
    Ok(())
}

#[derive(Default)]
struct ReleaseProgress {
    releases_withheld: usize,
    end_seen: bool,
    end_released: bool,
}

#[derive(Default)]
pub(super) struct LateRelease {
    hold: bool,
    replies: Mutex<Vec<(u64, Vec<u8>)>>,
    progress: Rendezvous<ReleaseProgress>,
}

impl LateRelease {
    pub(super) fn holding() -> Self {
        Self {
            hold: true,
            ..Self::default()
        }
    }

    pub(super) fn wait_releases(&self, count: usize) -> Result {
        self.progress
            .wait(|progress| progress.releases_withheld == count)
    }

    pub(super) fn wait_end(&self) -> Result {
        self.progress.wait(|progress| progress.end_seen)
    }

    pub(super) fn release_end(&self) {
        self.progress
            .update(|progress| progress.end_released = true);
    }
}

impl Behaviour for LateRelease {
    fn deliver(
        &self,
        _state: &State,
        _serial: u64,
        frame: &Frame<'_>,
        reply: Vec<u8>,
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        if frame.opcode()? != Opcode::Release {
            return send(stream, &reply);
        }
        self.replies
            .lock()
            .unwrap()
            .push((stream.connection(), reply));
        self.progress
            .update(|progress| progress.releases_withheld += 1);
        Ok(Flow::Next)
    }

    fn end(&self, _state: &State, stream: &mut dyn Stream) -> Result {
        if self.hold {
            self.progress.update(|progress| progress.end_seen = true);
            self.progress.wait(|progress| progress.end_released)?;
        }
        // The module still reads after it ended its sending direction.
        let connection = stream.connection();
        let mut replies = self.replies.lock().unwrap();
        for (_, reply) in replies.iter().filter(|(on, _)| *on == connection) {
            stream.write_all(reply)?;
        }
        replies.retain(|(on, _)| *on != connection);
        Ok(())
    }

    fn ended(&self) {
        self.progress.end();
    }
}

pub(super) fn wire_node(serial: u64, index: u64) -> u64 {
    if index == 0 {
        1
    } else {
        (serial << 56) | (index << 32) | 7
    }
}

pub(super) fn generation(state: &State, index: u64) -> u64 {
    if index == 8 {
        state.version.load(Ordering::SeqCst) as u64 + 1
    } else {
        1
    }
}

/// The most one read reply of this peer carries, less than a page, so a folio
/// is filled by several replies that each end short without the exhausted
/// bit, and the module asks again from where each stopped.
const REPLY_LIMIT: usize = 3000;
/// The piece size this peer streams a read reply in, which no page boundary
/// divides.
const PIECE_LEN: usize = 1000;
const LARGE_LEN: usize = 1024 * 1024 + 3;

pub(super) const DISTINCT: std::ops::Range<u64> = 5000..5128;

fn distinct_content(index: u64) -> Vec<u8> {
    format!("{:03}", index - DISTINCT.start).into_bytes()
}

fn fixture_byte(offset: usize) -> u8 {
    (1 + (offset.wrapping_mul(73) ^ (offset >> 8) ^ (offset >> 16)) % 255) as u8
}

pub(super) fn check_large(file: &File, state: &State) -> Result {
    let expected: Vec<_> = (0..LARGE_LEN).map(fixture_byte).collect();
    let mut actual = vec![0; LARGE_LEN];
    file.read_exact_at(&mut actual, 0)?;
    assert!(actual == expected, "complete short-reply file differs");
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    let payload = REPLY_LIMIT;
    let mut boundaries = state.read_boundaries.lock().unwrap().clone();
    assert!(
        boundaries.len() > LARGE_LEN / page,
        "no within-folio wire chunking observed"
    );
    boundaries.extend((page..LARGE_LEN).step_by(page));
    {
        for boundary in boundaries.into_iter().filter(|b| *b > 0 && *b < LARGE_LEN) {
            let start = boundary - 1;
            let end = (boundary + 2).min(LARGE_LEN);
            let mut slice = vec![0; end - start];
            file.read_exact_at(&mut slice, start as u64)?;
            assert_eq!(slice, expected[start..end], "boundary {boundary}");
        }
    }
    // A folio filled only up to the payload leaves a zero tail. The same
    // comparison must reject that tail, not merely validate the byte count.
    let mut corrupt = actual;
    corrupt[payload..page].fill(0);
    assert_ne!(
        corrupt, expected,
        "zero-fill negative control is ineffective"
    );
    println!(
        "vfs acceptance: short replies of {REPLY_LIMIT} bytes in {PIECE_LEN}-byte pieces, page={page}, complete and boundary bytes verified; zero-fill rejected"
    );
    Ok(())
}

pub(super) fn attributes(index: u64, state: &State) -> Attr {
    let mut value = attr(if index <= 2 { 42 } else { 100 + index }, 3);
    if index == 0 {
        value.ino = U64::new(9);
        value.mode = U32::new(libc::S_IFDIR | 0o555);
        value.size = U64::ZERO;
    } else {
        if index == 4 {
            value.size = U64::new(LARGE_LEN as u64);
        }
        value.mtime.sec = (state.version.load(Ordering::SeqCst) as i64 + 1).into();
        if index == 7 || (index == 8 && state.version.load(Ordering::SeqCst) != 0) {
            value.mode = U32::new(libc::S_IFDIR | 0o555);
            value.size = U64::ZERO;
        }
        if (4000..4005).contains(&index) {
            value.mode = U32::new(
                match index {
                    4000 => libc::S_IFIFO,
                    4001 => libc::S_IFCHR,
                    4002 => libc::S_IFBLK,
                    4003 => libc::S_IFSOCK,
                    _ => 0,
                } | 0o444,
            );
        }
    }
    if (3000..=3002).contains(&index) {
        value.mode = U32::new(match index {
            3000 => libc::S_IFREG | 0o444,
            3001 => libc::S_IFDIR | 0o555,
            _ => libc::S_IFLNK | 0o777,
        });
    }
    state.behaviour.attributes(index, &mut value);
    value
}

pub(super) fn error_reply(id: u64, opcode: Opcode, errno: i32) -> Result<Vec<u8>> {
    let mut bytes = [0; 128];
    let reply = FrameWriter::error_response(&mut bytes, id, opcode, -errno)?;
    Ok(reply.to_vec())
}

/// The next request on `stream`, or none at the end of file from the module,
/// which arrives only between two requests. A frame that the end of file cuts
/// short fails the session.
pub(super) fn next_request(stream: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut first = [0];
    if stream.read(&mut first)? == 0 {
        return Ok(None);
    }
    Ok(Some(read_frame(&mut (&first[..]).chain(stream))?))
}

#[derive(Default)]
struct Records {
    identities: HashMap<u64, u64>,
    lookups: HashMap<u64, u64>,
    handles: HashMap<u64, u64>,
    next_handle: u64,
    kept: HashMap<(u64, u64), Kept>,
}

#[derive(Clone)]
enum Kept {
    Applied,
    Replied(Vec<u8>),
}

#[derive(Default)]
struct Connections {
    open: HashMap<u64, Box<dyn Handle>>,
    opened: u64,
    ended: bool,
}

pub(super) struct Session {
    state: Arc<State>,
    serial: u64,
    token: Vec<u8>,
    records: Mutex<Records>,
    connections: Mutex<Connections>,
    closed: Condvar,
}

fn shut(handle: &dyn Handle) -> Result {
    match handle.shut() {
        Err(error) if error.raw_os_error() == Some(libc::ENOTCONN) => Ok(()),
        shut => Ok(shut?),
    }
}

impl Session {
    fn attach<S: Connection>(&self, stream: S) -> Result<Option<Link<S>>> {
        let mut connections = self.connections.lock().unwrap();
        if connections.ended {
            return Ok(None);
        }
        connections.opened += 1;
        let connection = connections.opened;
        connections
            .open
            .insert(connection, Box::new(stream.duplicate()?));
        self.state.events.update(|events| {
            events.connections.insert(self.serial, connection);
        });
        Ok(Some(Link { connection, stream }))
    }

    fn accepting<S>(&self, id: u64, link: &Link<S>) -> Result<Vec<u8>> {
        accepting_reply(
            id,
            voidport_proto::PROTOCOL_VERSION,
            link.connection,
            &self.token,
        )
    }

    pub(super) fn cut(&self) -> Result {
        let mut connections = self.connections.lock().unwrap();
        connections.ended = true;
        connections
            .open
            .values()
            .try_for_each(|handle| shut(&**handle))
    }

    fn close(&self, connection: u64) -> Result {
        let connections = self.connections.lock().unwrap();
        if let Some(handle) = connections.open.get(&connection) {
            shut(&**handle)?;
        }
        drop(
            self.closed
                .wait_while(connections, |connections| {
                    connections.open.contains_key(&connection)
                })
                .unwrap(),
        );
        Ok(())
    }

    fn leave(&self, connection: u64) -> bool {
        let mut connections = self.connections.lock().unwrap();
        connections.open.remove(&connection);
        let last = connections.open.is_empty();
        connections.ended |= last;
        drop(connections);
        self.closed.notify_all();
        if last {
            self.finish();
        }
        last
    }

    /// Records the end of the session. A session that ended owns every
    /// reference still live in it: every explicit cleanup was matched against
    /// its individual full ID before it was counted down.
    fn finish(&self) {
        let serial = self.serial;
        let records = self.records.lock().unwrap();
        for (id, count) in records.lookups.iter().filter(|(_, count)| **count != 0) {
            println!("vfs peer: session={serial} node={id} teardown={count}");
        }
        for (handle, node) in &records.handles {
            println!("vfs peer: session={serial} handle={handle} node={node} teardown=1");
        }
        drop(records);
        self.state
            .sessions
            .lock()
            .unwrap()
            .retain(|session| !std::ptr::eq(&**session, self));
        self.state.behaviour.ended();
        self.state
            .events
            .update(|events| events.finished.push(serial));
    }

    fn reply(
        &self,
        connection: u64,
        frame: &Frame<'_>,
        stream: &mut dyn Stream,
    ) -> Result<Option<Vec<u8>>> {
        let id = frame.request_id();
        match frame.opcode()? {
            Opcode::Outcome => return Ok(Some(self.outcome(id, frame.request()?)?)),
            Opcode::Retire => return Ok(Some(self.retire(id, frame.request()?)?)),
            _ => {}
        }
        let reply = self.state.behaviour.reply(self, frame, stream)?;
        let kept = reply.clone().map_or(Kept::Applied, Kept::Replied);
        self.records
            .lock()
            .unwrap()
            .kept
            .insert((connection, id), kept);
        Ok(reply)
    }

    pub(super) fn own_reply(&self, frame: &Frame<'_>) -> Result<Option<Vec<u8>>> {
        Replying {
            state: &self.state,
            serial: self.serial,
            records: &mut self.records.lock().unwrap(),
        }
        .reply(frame)
    }

    /// The answer to the outcome request `id`. As the server does, the peer
    /// answers once the connection it asks about is closed and every request
    /// read from that connection has ended, and closes it first, so an answer
    /// of "not started" stays true.
    fn outcome(&self, id: u64, request: Request<'_, OutcomeRequest>) -> Result<Vec<u8>> {
        let asked = request.body();
        let (connection, request_id) = (asked.connection_id.get(), asked.request_id.get());
        self.close(connection)?;
        let kept = self
            .records
            .lock()
            .unwrap()
            .kept
            .get(&(connection, request_id))
            .cloned();
        let (state, stored) = match kept {
            None => (outcome_state::NOT_STARTED, Vec::new()),
            Some(Kept::Applied) => (outcome_state::APPLIED, Vec::new()),
            Some(Kept::Replied(reply)) => (outcome_state::REPLIED, reply),
        };
        println!(
            "vfs peer: session={} OUTCOME request={id} connection={connection} asked={request_id} state={state}",
            self.serial
        );
        let asked = Settled::Asked {
            connection,
            request: request_id,
            state,
        };
        self.state.settled(self.serial, asked);
        let body = OutcomeResponse {
            state: U32::new(state),
            reserved: U32::ZERO,
        };
        let mut answer = response(id, &body, &[])?;
        if !stored.is_empty() {
            answer.extend(piece_of(&stored));
        }
        answer.extend_from_slice(&Closing::done(false).encode());
        Ok(answer)
    }

    fn retire(&self, id: u64, request: Request<'_, RetireRequest>) -> Result<Vec<u8>> {
        let connection = request.body().connection_id.get();
        self.close(connection)?;
        self.records
            .lock()
            .unwrap()
            .kept
            .retain(|(on, _), _| *on != connection);
        println!(
            "vfs peer: session={} RETIRE request={id} connection={connection}",
            self.serial
        );
        self.state
            .settled(self.serial, Settled::Retired { connection });
        response(
            id,
            &RetireResponse {
                reserved: U32::ZERO,
            },
            &[],
        )
    }
}

struct Replying<'a> {
    state: &'a State,
    serial: u64,
    records: &'a mut Records,
}

impl Replying<'_> {
    fn reply(&mut self, frame: &Frame<'_>) -> Result<Option<Vec<u8>>> {
        let id = frame.request_id();
        Ok(Some(match frame.opcode()? {
            Opcode::Getattr => self.getattr(id, frame.request()?)?,
            Opcode::Lookup => self.lookup(id, frame.request()?)?,
            Opcode::Open => self.open(id, frame.request()?)?,
            Opcode::Read => self.read(id, frame.request()?)?,
            Opcode::Readlink => self.readlink(id, frame.request()?)?,
            Opcode::Statfs => {
                frame.request::<StatfsRequest>()?;
                let mut reply = StatfsResponse::default();
                self.state.behaviour.statfs(&mut reply);
                // The frame writer refuses a reserved field that is not zero,
                // so the reply is written without it, and its body then
                // overwritten with the statistics as they are.
                let valid = StatfsResponse {
                    reserved: U32::ZERO,
                    ..reply
                };
                let mut bytes = response(id, &valid, &[])?;
                let body = bytes.len() - size_of::<StatfsResponse>();
                bytes[body..].copy_from_slice(reply.as_bytes());
                bytes
            }
            Opcode::Readdirplus => self.list(id, frame.request()?)?,
            Opcode::Release => self.release(id, frame.request()?)?,
            Opcode::Fsync => self.fsync(id, frame.request()?)?,
            Opcode::Mkdir => self.mkdir(id, frame.request()?)?,
            Opcode::Forget => {
                self.forget(id, frame.request()?)?;
                return Ok(None);
            }
            opcode => return Err(format!("unexpected VFS opcode {opcode:?}").into()),
        }))
    }

    pub(super) fn index(&self, wire: u64) -> Result<u64> {
        Ok(*self
            .records
            .identities
            .get(&wire)
            .ok_or("unknown or truncated node ID")?)
    }

    fn admit(&mut self, opcode: Opcode, index: u64) -> EntryOut {
        let mut entry = EntryOut {
            node_id: U64::new(wire_node(self.serial, index)),
            generation: U64::new(generation(self.state, index)),
            attr: attributes(index, self.state),
        };
        self.state
            .behaviour
            .entry(self.serial, opcode, index, &mut entry);
        let wire = entry.node_id.get();
        self.records.identities.insert(wire, index);
        *self.records.lookups.entry(wire).or_default() += 1;
        entry
    }

    fn getattr(&mut self, id: u64, request: Request<'_, GetattrRequest>) -> Result<Vec<u8>> {
        let index = self.index(request.head().node_id.get())?;
        self.state.gets.fetch_add(1, Ordering::SeqCst);
        let attr = attributes(index, self.state);
        response(id, &GetattrResponse { attr }, &[])
    }

    fn named(&self, name: &str) -> Option<u64> {
        let changed = self.state.version.load(Ordering::SeqCst) != 0;
        match name {
            "a" => Some(1),
            "b" => Some(2),
            "oversized" => Some(3),
            "retry-absent" => changed.then_some(30),
            "retry-generation" => Some(8),
            "retry-replaced" => Some(if changed { 7 } else { 6 }),
            name => name.strip_prefix('n')?.parse().ok(),
        }
    }

    pub(super) fn lookup(
        &mut self,
        id: u64,
        request: Request<'_, LookupRequest>,
    ) -> Result<Vec<u8>> {
        assert_eq!(request.head().node_id.get(), 1);
        let name = std::str::from_utf8(request.name())?;
        let serial = self.serial;
        self.state.events.update(|events| {
            events
                .lookups
                .entry((serial, name.to_owned()))
                .or_default()
                .push(id)
        });
        println!("vfs peer: session={serial} LOOKUP request={id} name={name}");
        let Some(index) = self.named(name) else {
            return error_reply(id, Opcode::Lookup, libc::ENOENT);
        };
        let entry = self.admit(Opcode::Lookup, index);
        response(id, &LookupResponse { entry }, &[])
    }

    pub(super) fn open(&mut self, id: u64, request: Request<'_, OpenRequest>) -> Result<Vec<u8>> {
        let wire = request.head().node_id.get();
        self.index(wire)?;
        let handle = self.records.next_handle;
        self.records.next_handle += 1;
        assert!(self.records.handles.insert(handle, wire).is_none());
        let reply = OpenResponse {
            handle: U64::new(handle),
            flags: U32::ZERO,
            reserved: U32::ZERO,
        };
        response(id, &reply, &[])
    }

    pub(super) fn content(&self, index: u64) -> Vec<u8> {
        if index == 4 {
            (0..LARGE_LEN).map(fixture_byte).collect()
        } else if DISTINCT.contains(&index) {
            distinct_content(index)
        } else if self.state.version.load(Ordering::SeqCst) == 0 {
            b"old".to_vec()
        } else {
            b"new".to_vec()
        }
    }

    pub(super) fn read(&mut self, id: u64, request: Request<'_, ReadRequest>) -> Result<Vec<u8>> {
        let body = request.body();
        let wire = *self
            .records
            .handles
            .get(&body.handle.get())
            .ok_or("unknown READ handle")?;
        assert_eq!(
            request.head().node_id.get(),
            wire,
            "truncated/colliding READ ID"
        );
        let index = self.index(wire)?;
        let data = self.content(index);
        let offset = usize::try_from(body.offset.get())?.min(data.len());
        let end = (offset + (body.size.get() as usize).min(REPLY_LIMIT)).min(data.len());
        if index == 4 {
            let mut boundaries = self.state.read_boundaries.lock().unwrap();
            boundaries.extend([offset, end]);
        }
        let parts: Vec<&[u8]> = data[offset..end].chunks(PIECE_LEN).collect();
        read_reply(id, &parts, 0, end == data.len())
    }

    pub(super) fn readlink(
        &mut self,
        id: u64,
        request: Request<'_, ReadlinkRequest>,
    ) -> Result<Vec<u8>> {
        assert_eq!(self.index(request.head().node_id.get())?, 3002);
        let mut target: &[u8] = b"a";
        self.state.behaviour.link(&mut target);
        let reply = ReadlinkResponse {
            target_len: U32::new(target.len() as u32),
        };
        response(id, &reply, target)
    }

    pub(super) fn list(
        &mut self,
        id: u64,
        request: Request<'_, ReaddirplusRequest>,
    ) -> Result<Vec<u8>> {
        assert_eq!(request.head().node_id.get(), 1);
        let cookie = request.body().cookie.get();
        let mut listing = Listing {
            entries: if cookie == 0 {
                vec![Listed::new(1, b"a"), Listed::new(2, b"b")]
            } else {
                Vec::new()
            },
            exhausted: true,
        };
        self.state.behaviour.listing(cookie, &mut listing);
        let type_word = std::mem::offset_of!(DirEntryHeader, next_cookie) + size_of::<U64>();
        let mut reply = response(id, &ReaddirplusResponse, &[])?;
        for listed in &listing.entries {
            let entry = self.admit(Opcode::Readdirplus, listed.index);
            let name_len = listed.name.len() as u32;
            let mut header =
                DirEntryHeader::new(entry, listed.next_cookie, EntryType::Unknown, name_len);
            header.as_mut_bytes()[type_word..type_word + 4]
                .copy_from_slice(&listed.entry_type.to_le_bytes());
            reply.extend(piece_of(&[header.as_bytes(), listed.name].concat()));
        }
        reply.extend_from_slice(&voidport_proto::piece::Closing::done(listing.exhausted).encode());
        Ok(reply)
    }

    pub(super) fn release(
        &mut self,
        id: u64,
        request: Request<'_, ReleaseRequest>,
    ) -> Result<Vec<u8>> {
        assert!(
            self.records
                .handles
                .remove(&request.body().handle.get())
                .is_some(),
            "duplicate RELEASE"
        );
        self.state.events.update(|events| events.released += 1);
        response(id, &ReleaseResponse {}, &[])
    }

    fn fsync(&mut self, id: u64, request: Request<'_, FsyncRequest>) -> Result<Vec<u8>> {
        assert!(
            self.records
                .handles
                .contains_key(&request.body().handle.get()),
            "FSYNC of an unknown handle"
        );
        let flags = request.body().flags.get();
        self.state.events.update(|events| events.fsyncs.push(flags));
        response(id, &FsyncResponse {}, &[])
    }

    fn mkdir(&mut self, id: u64, request: Request<'_, MkdirRequest>) -> Result<Vec<u8>> {
        assert_eq!(request.head().node_id.get(), 1);
        assert_eq!(request.name(), MADE.as_bytes(), "a MKDIR of another name");
        println!(
            "vfs peer: session={} MKDIR request={id} name={MADE}",
            self.serial
        );
        let entry = self.admit(Opcode::Mkdir, 3001);
        response(id, &MkdirResponse { entry }, &[])
    }

    fn forget(&mut self, id: u64, request: Request<'_, ForgetRequest>) -> Result {
        let wire = request.head().node_id.get();
        let held = self
            .records
            .lookups
            .get_mut(&wire)
            .ok_or("unknown/truncated FORGET ID")?;
        let count = request.body().nlookup.get();
        assert!(count > 0 && count <= *held, "duplicate FORGET");
        *held -= count;
        let serial = self.serial;
        self.state.events.update(|events| {
            *events.forgotten.entry((serial, wire)).or_default() += count;
        });
        println!("vfs peer: session={serial} FORGET request={id} node={wire} count={count}");
        Ok(())
    }
}

fn serve_link<S: Connection>(session: &Session, mut link: Link<S>, mut flow: Flow) -> Result {
    let state = &*session.state;
    let mut module_ended = false;
    while let Flow::Next = flow {
        let Some(bytes) = next_request(&mut link)? else {
            module_ended = true;
            break;
        };
        let frame = Frame::parse(&bytes, &LIMITS)?;
        flow = state.behaviour.arrived(state, session.serial, &frame)?;
        if !matches!(flow, Flow::Next) {
            break;
        }
        let Some(reply) = session.reply(link.connection, &frame, &mut link)? else {
            flow = state.behaviour.applied(state, session.serial, &frame)?;
            continue;
        };
        flow = match state
            .behaviour
            .deliver(state, session.serial, &frame, reply, &mut link)
        {
            Ok(flow) => flow,
            // RELEASE is asynchronous. Both normal unmount after the last
            // close and final release of a detached mount can close the
            // connection before this reply. The exact handle is retired
            // above; session teardown owns any remaining references.
            Err(error)
                if frame.opcode()? == Opcode::Release
                    && error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::BrokenPipe) =>
            {
                module_ended = true;
                break;
            }
            Err(error) => return Err(error),
        };
    }
    match flow {
        Flow::Close => return session.cut(),
        Flow::Sever => return Ok(()),
        Flow::Next | Flow::End => {}
    }
    state.behaviour.end(state, &mut link)?;
    if !module_ended {
        return session.cut();
    }
    state
        .events
        .update(|events| *events.closed.entry(session.serial).or_default() += 1);
    Ok(())
}

fn serve_accepted<S: Connection>(
    session: &Session,
    mut link: Link<S>,
    (id, reply): (u64, &[u8]),
    opens: bool,
) -> Result {
    let state = &*session.state;
    let serial = session.serial;
    let flow = if opens {
        state.behaviour.hello(state, serial, reply, &mut link)?
    } else {
        match state.behaviour.join(state, serial, id, reply, &mut link) {
            Err(error) if dial_cancelled(&*error) => return Ok(()),
            joined => joined?,
        }
    };
    serve_link(session, link, flow)
}

/// Whether `error`, from the write of a reply to a joining hello, found the
/// connection closed by the module. A teardown of the mount cancels the dial
/// of a join that has sent its hello and closes its connection.
fn dial_cancelled(error: &(dyn std::error::Error + 'static)) -> bool {
    error.downcast_ref::<std::io::Error>().is_some_and(|error| {
        matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
        )
    })
}

fn unless_severed(state: &State, outcome: Result) -> Result {
    match outcome {
        Err(error) if state.behaviour.severed(&*error) => Ok(()),
        outcome => outcome,
    }
}

type Failure = Box<dyn std::error::Error + Send + Sync>;

fn fail(state: &State, error: Failure, report: Report) -> Failure {
    report(&error.to_string());
    state.cut();
    error
}

type Report<'a> = &'a (dyn Fn(&str) + Sync);

fn run<S: Connection>(
    session: &Session,
    link: Link<S>,
    hello: (u64, &[u8]),
    opens: bool,
    report: Report,
) -> Result<bool> {
    let state = &*session.state;
    let connection = link.connection;
    let served = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        serve_accepted(session, link, hello, opens)
    }))
    .unwrap_or_else(|_| Err("a panic".into()));
    let served = unless_severed(state, served).map_err(|error| {
        let error = format!("serving session {}: {error}", session.serial);
        fail(state, error.into(), report)
    });
    let ended = session.leave(connection);
    served.map(|()| ended)
}

fn hello_of(bytes: &[u8], behaviour: &dyn Behaviour) -> Result<(u64, Option<Vec<u8>>)> {
    let frame = Frame::parse(bytes, &LIMITS)?;
    let hello = frame.request::<HelloRequest>()?;
    if hello.body().joins() {
        return Ok((frame.request_id(), Some(hello.token().to_vec())));
    }
    assert_eq!(hello.namespace(), behaviour.namespace());
    assert_eq!(hello.subpath(), behaviour.path());
    Ok((frame.request_id(), None))
}

pub(super) fn refused_join(id: u64) -> Result<Vec<u8>> {
    error_reply(id, Opcode::Hello, libc::ENOENT)
}

pub(super) fn serve<S: Connection>(mut stream: S, serial: u64, state: Arc<State>) -> Result {
    let (id, joins) = hello_of(&read_frame(&mut stream)?, &*state.behaviour)?;
    if joins.is_some() {
        return Err("the first hello joins a session".into());
    }
    let session = state.open(serial);
    let link = session
        .attach(stream)?
        .ok_or("the session ended before its first connection")?;
    let reply = session.accepting(id, &link)?;
    run(&session, link, (id, &reply), true, &|_| {}).map(|_| ())
}

pub(super) struct Opened<S> {
    pub(super) stream: S,
    session: Arc<Session>,
}

impl<S> Opened<S> {
    pub(super) fn serial(&self) -> u64 {
        self.session.serial
    }

    pub(super) fn cut(&self) -> Result {
        self.session.cut()
    }
}

struct Serving {
    sessions: u64,
    opened: Mutex<u64>,
    failure: Mutex<Option<String>>,
}

fn serve_connection<S: Connection>(
    mut stream: S,
    state: &Arc<State>,
    serving: &Serving,
    opened: &(impl Fn(Opened<S>) -> Result + Sync),
    report: Report,
) -> Result<Option<u64>> {
    let accepted = (|| -> Result<Option<(Arc<Session>, Link<S>, (u64, Vec<u8>), bool)>> {
        // A dial that the module cancelled before its hello ends here, and one
        // it cancelled after the hello ends at the write of the reply.
        let Some(bytes) = next_request(&mut stream)? else {
            return Ok(None);
        };
        let (id, joins) = hello_of(&bytes, &*state.behaviour)?;
        let (session, opens) = match joins {
            Some(token) => match state.named(&token) {
                Some(session) => (session, false),
                None => match stream.write_all(&refused_join(id)?) {
                    Err(error) if !dial_cancelled(&error) => return Err(error.into()),
                    _ => return Ok(None),
                },
            },
            None => {
                let serial = {
                    let mut count = serving.opened.lock().unwrap();
                    *count += 1;
                    *count
                };
                if serial > serving.sessions {
                    return Ok(None);
                }
                let session = state.open(serial);
                opened(Opened {
                    stream: stream.duplicate()?,
                    session: session.clone(),
                })?;
                (session, true)
            }
        };
        let Some(link) = session.attach(stream)? else {
            // Only a join comes after the end of its session.
            return Ok(None);
        };
        let reply = session.accepting(id, &link)?;
        Ok(Some((session, link, (id, reply), opens)))
    })();
    let (session, link, (id, reply), opens) = match accepted {
        Ok(Some(accepted)) => accepted,
        Ok(None) => return Ok(None),
        Err(error) if state.behaviour.severed(&*error) => return Ok(None),
        Err(error) => return Err(fail(state, error, report)),
    };
    Ok(run(&session, link, (id, &reply), opens, report)?.then_some(session.serial))
}

/// A hello past the last session gets no reply, and its connection is closed,
/// as is a connection that ends before its hello.
pub(super) fn serve_sessions<L: Listener>(
    listener: &L,
    sessions: u64,
    state: &Arc<State>,
    opened: impl Fn(Opened<L::Stream>) -> Result + Sync,
    report: Report,
) -> Result {
    let serving = Serving {
        sessions,
        opened: Mutex::new(0),
        failure: Mutex::new(None),
    };
    let failed = |error: &dyn std::fmt::Display| {
        serving
            .failure
            .lock()
            .unwrap()
            .get_or_insert_with(|| error.to_string());
    };
    std::thread::scope(|scope| {
        loop {
            let stream = match listener.next_unless_stopped() {
                Ok(Some(stream)) => stream,
                // This peer stopped the listener, or the case did.
                Ok(None) => break,
                Err(error) => {
                    failed(&fail(state, error.into(), report));
                    break;
                }
            };
            let (serving, opened, failed) = (&serving, &opened, &failed);
            scope.spawn(move || {
                match serve_connection(stream, state, serving, opened, report) {
                    Ok(Some(serial)) if serial == sessions => {}
                    Ok(_) => return,
                    Err(error) => failed(&error),
                }
                if let Err(error) = listener.stop() {
                    failed(&fail(state, error.into(), report));
                }
            });
        }
    });
    match serving.failure.into_inner().unwrap() {
        Some(failure) => Err(failure.into()),
        None => Ok(()),
    }
}

pub(super) fn serve_one(
    listener: impl Listener,
    state: &Arc<State>,
) -> std::thread::JoinHandle<Result> {
    let state = state.clone();
    std::thread::spawn(move || serve_sessions(&listener, 1, &state, |_| Ok(()), &|_| {}))
}

pub(super) fn spawn_vfs_peer<L: Listener>(
    listener: L,
    state: &Arc<State>,
    sessions: u64,
    supervision: &Supervision,
) -> (std::thread::JoinHandle<Result>, Receiver<Opened<L::Stream>>) {
    let (accepted, opened) = std::sync::mpsc::channel();
    let state = state.clone();
    let peer = spawn_peer(supervision, move |report| {
        let open = |opened: Opened<L::Stream>| -> Result {
            if opened.serial() < sessions {
                accepted
                    .send(opened)
                    .map_err(|_| "the case stopped taking sessions")?;
            }
            Ok(())
        };
        serve_sessions(&listener, sessions, &state, open, report)
    });
    (peer, opened)
}
