use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;

use voidport::client::{Client, Origin};
use voidport::url::Endpoint;
use voidport_proto::frame::{FLAG_RESPONSE, FRAME_HEADER_LEN, Frame, FrameHeader, Parsed};
use voidport_proto::limits::LIMITS;
use voidport_proto::message::Follows;
use voidport_proto::opcode::Opcode;
use voidport_proto::piece::{self, CLOSING_LEN, PIECE_LEN_LEN};
use zerocopy::FromBytes as _;

#[derive(Clone, Debug)]
pub enum Cut {
    DropRequest,
    HoldRequest(Latch),
    /// The relay passes the request message and this many bytes of the data
    /// after it to the server.
    Request {
        data: usize,
    },
    /// The relay passes the whole request to the server and ends the connection
    /// before the reply.
    AfterRequest,
    /// The relay passes the whole request to the server and nothing more from
    /// the client on that connection, and ends the connection once the latch is
    /// released. A test can then see the server apply a request without a reply,
    /// such as a forget, before the connection ends.
    AfterRequestUntil(Latch),
    DiscardReply,
    /// The relay passes the reply message and this many of its pieces to the
    /// client.
    Reply {
        pieces: usize,
    },
    HoldReply(Latch),
}

#[derive(Clone, Debug, Default)]
pub struct Latch(Arc<(Mutex<bool>, Condvar)>);

impl Latch {
    /// A latch already released: a hold on it only reports the connection on which
    /// the message came.
    #[must_use]
    pub fn released() -> Self {
        let latch = Self::default();
        latch.release();
        latch
    }

    pub fn release(&self) {
        let (open, changed) = &*self.0;
        *open.lock().expect("unpoisoned") = true;
        changed.notify_all();
    }

    fn wait(&self) {
        let (open, changed) = &*self.0;
        let mut open = open.lock().expect("unpoisoned");
        while !*open {
            open = changed.wait(open).expect("unpoisoned");
        }
    }
}

#[derive(Debug)]
struct Trap {
    opcode: u16,
    cut: Cut,
    sprung: mpsc::Sender<usize>,
}

#[derive(Debug)]
pub struct Relay {
    address: SocketAddr,
    state: Arc<State>,
}

#[derive(Debug)]
struct State {
    server: Mutex<PathBuf>,
    /// Whether a new connection is passed on. Any other connection is closed at
    /// once, before its hello gets to the server.
    accepting: AtomicBool,
    traps: Mutex<Vec<Trap>>,
    carried: Mutex<Vec<u16>>,
    connections: AtomicUsize,
    refused: AtomicUsize,
    /// Every request passed on whole, with the number of its connection.
    /// Connections are numbered from one in the order they were accepted.
    log: Mutex<Vec<(usize, u16)>>,
    ends: Mutex<Vec<(usize, Ends)>>,
}

impl Relay {
    #[must_use]
    pub fn start(server: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
        let address = listener.local_addr().expect("a bound address");
        let state = Arc::new(State {
            server: Mutex::new(server.to_path_buf()),
            accepting: AtomicBool::new(true),
            traps: Mutex::new(Vec::new()),
            carried: Mutex::new(Vec::new()),
            connections: AtomicUsize::new(0),
            refused: AtomicUsize::new(0),
            log: Mutex::new(Vec::new()),
            ends: Mutex::new(Vec::new()),
        });
        let accepting = Arc::clone(&state);
        thread::spawn(move || {
            while let Ok((client, _)) = listener.accept() {
                if !accepting.accepting.load(Ordering::SeqCst) {
                    let _peer_may_be_gone = client.shutdown(Shutdown::Both);
                    accepting.refused.fetch_add(1, Ordering::SeqCst);
                    continue;
                }
                let number = accepting.connections.fetch_add(1, Ordering::SeqCst) + 1;
                let state = Arc::clone(&accepting);
                thread::spawn(move || state.serve(number, client));
            }
        });
        Self { address, state }
    }

    #[must_use]
    pub fn url(&self, namespace: &str, subpath: &str) -> String {
        crate::tcp_url(self.address, namespace, subpath)
    }

    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        Endpoint::Tcp {
            host: self.address.ip().to_string(),
            port: self.address.port(),
        }
    }

    /// Arms a trap for the next message of `opcode`: a request for the
    /// request cuts, a reply for the reply cuts. Once the trap fires, the
    /// receiver gets the number of the connection on which it fired.
    pub fn arm(&self, opcode: Opcode, cut: Cut) -> mpsc::Receiver<usize> {
        let (sprung, fired) = mpsc::channel();
        self.state.traps.lock().expect("unpoisoned").push(Trap {
            opcode: opcode.as_u16(),
            cut,
            sprung,
        });
        fired
    }

    /// The server applies the requests of a connection in the order it reads them,
    /// and a forget before it reads the next request, so each reply proves that
    /// everything written before it on its connection was applied. A getattr that
    /// finds no idle connection opens a new one, so a pool that did not grow proves
    /// that each getattr took a connection nobody else held. A pool that grew is
    /// fenced again.
    pub fn fence(&self, runtime: &tokio::runtime::Runtime, client: &Arc<Client>) {
        loop {
            let pool = client.connections().expect("a session").pooled;
            self.fence_over(runtime, client, pool);
            if client.connections().expect("a session").pooled == pool {
                return;
            }
        }
    }

    fn fence_over(&self, runtime: &tokio::runtime::Runtime, client: &Arc<Client>, pool: usize) {
        let latch = Latch::default();
        let held: Vec<_> = (0..pool)
            .map(|_| self.arm(Opcode::Getattr, Cut::HoldReply(latch.clone())))
            .collect();
        let releasing = thread::spawn(move || {
            for reply in &held {
                reply.recv().expect("the reply is held");
            }
            latch.release();
        });
        let root = client.root_node_id();
        runtime.block_on(async {
            let mut asking = tokio::task::JoinSet::new();
            for _ in 0..pool {
                let client = Arc::clone(client);
                asking.spawn(async move { client.getattr(Origin::default(), root, None).await });
            }
            while let Some(asked) = asking.join_next().await {
                asked.expect("joined").expect("the getattr is answered");
            }
        });
        releasing.join().expect("every reply was held");
    }

    pub fn refuse_new(&self, refuse: bool) {
        self.state.accepting.store(!refuse, Ordering::SeqCst);
    }

    #[must_use]
    pub fn refused(&self) -> usize {
        self.state.refused.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn carried(&self, opcode: Opcode) -> usize {
        self.state
            .carried
            .lock()
            .expect("unpoisoned")
            .iter()
            .filter(|carried| **carried == opcode.as_u16())
            .count()
    }

    #[must_use]
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }

    pub fn redirect(&self, server: &Path) {
        *self.state.server.lock().expect("unpoisoned") = server.to_path_buf();
    }

    #[must_use]
    pub fn carried_beside(&self, opcode: Opcode) -> Vec<Opcode> {
        let log = self.state.log.lock().expect("unpoisoned");
        let carriers: Vec<usize> = log
            .iter()
            .filter(|(_, carried)| *carried == opcode.as_u16())
            .map(|(number, _)| *number)
            .collect();
        log.iter()
            .filter(|(number, _)| carriers.contains(number))
            .filter_map(|(_, carried)| Opcode::try_from(*carried).ok())
            .collect()
    }

    pub fn end_carriers(&self, opcode: Opcode) {
        let carriers: Vec<usize> = self
            .state
            .log
            .lock()
            .expect("unpoisoned")
            .iter()
            .filter(|(_, carried)| *carried == opcode.as_u16())
            .map(|(number, _)| *number)
            .collect();
        for (number, ends) in self.state.ends.lock().expect("unpoisoned").iter() {
            if carriers.contains(number) {
                ends.end();
            }
        }
    }
}

impl State {
    /// Whichever direction ends first ends the other.
    fn serve(self: Arc<Self>, number: usize, client: TcpStream) {
        let _batching_only_slows_it = client.set_nodelay(true);
        let path = self.server.lock().expect("unpoisoned").clone();
        let Ok(server) = UnixStream::connect(&path) else {
            let _peer_may_be_gone = client.shutdown(Shutdown::Both);
            return;
        };
        let ends = Ends {
            client: client.try_clone().expect("a second client handle"),
            server: server.try_clone().expect("a second server handle"),
        };
        self.ends
            .lock()
            .expect("unpoisoned")
            .push((number, ends.clone()));
        let upstream = {
            let state = Arc::clone(&self);
            let ends = ends.clone();
            let (from, to) = (
                client.try_clone().expect("a client handle"),
                server.try_clone().expect("a server handle"),
            );
            thread::spawn(move || ends.end_after(&state.requests(number, from, to)))
        };
        ends.end_after(&self.replies(number, server, client));
        let _panic_was_printed = upstream.join();
    }

    fn take(&self, opcode: u16, reply: bool) -> Option<(Cut, mpsc::Sender<usize>)> {
        let mut traps = self.traps.lock().expect("unpoisoned");
        let at = traps.iter().position(|trap| {
            trap.opcode == opcode
                && reply
                    == matches!(
                        trap.cut,
                        Cut::DiscardReply | Cut::Reply { .. } | Cut::HoldReply(_)
                    )
        })?;
        let trap = traps.remove(at);
        Some((trap.cut, trap.sprung))
    }

    /// The request counts as passed on before its last byte is written, since
    /// the server can reply to it from then on, and stops counting if the write
    /// fails.
    fn carry(
        &self,
        number: usize,
        opcode: u16,
        write: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        self.carried.lock().expect("unpoisoned").push(opcode);
        self.log.lock().expect("unpoisoned").push((number, opcode));
        write().inspect_err(|_| {
            let mut carried = self.carried.lock().expect("unpoisoned");
            if let Some(at) = carried.iter().rposition(|carried| *carried == opcode) {
                carried.remove(at);
            }
            let mut log = self.log.lock().expect("unpoisoned");
            if let Some(at) = log.iter().rposition(|entry| *entry == (number, opcode)) {
                log.remove(at);
            }
        })
    }

    fn requests(&self, number: usize, mut from: TcpStream, mut to: UnixStream) -> io::Result<()> {
        loop {
            let (message, follows) = read_frame(&mut from)?;
            let opcode = header_opcode(&message);
            let data = match follows {
                Follows::Data(len) => len as usize,
                _ => 0,
            };
            match self.take(opcode, false) {
                None => self.carry(number, opcode, || {
                    to.write_all(&message)?;
                    copy(&mut from, &mut to, data)
                })?,
                Some((Cut::HoldRequest(latch), sprung)) => {
                    let _unwatched_trap = sprung.send(number);
                    latch.wait();
                    self.carry(number, opcode, || {
                        to.write_all(&message)?;
                        copy(&mut from, &mut to, data)
                    })?;
                }
                Some((cut, sprung)) => {
                    match &cut {
                        Cut::DropRequest => {}
                        Cut::Request { data: through } => {
                            to.write_all(&message)?;
                            copy(&mut from, &mut to, (*through).min(data))?;
                        }
                        Cut::AfterRequest | Cut::AfterRequestUntil(_) => {
                            self.carry(number, opcode, || {
                                to.write_all(&message)?;
                                copy(&mut from, &mut to, data)
                            })?;
                        }
                        Cut::HoldRequest(_)
                        | Cut::DiscardReply
                        | Cut::Reply { .. }
                        | Cut::HoldReply(_) => {
                            unreachable!("handled above, or a reply trap")
                        }
                    }
                    to.flush()?;
                    let _unwatched_trap = sprung.send(number);
                    if let Cut::AfterRequestUntil(latch) = &cut {
                        latch.wait();
                    }
                    return Ok(());
                }
            }
        }
    }

    fn replies(&self, number: usize, mut from: UnixStream, mut to: TcpStream) -> io::Result<()> {
        loop {
            let (message, follows) = read_frame(&mut from)?;
            let pieces = match follows {
                Follows::Pieces(_) => read_pieces(&mut from)?,
                _ => Vec::new(),
            };
            let reply = header_flags(&message) & FLAG_RESPONSE != 0;
            let trap = reply
                .then(|| self.take(header_opcode(&message), true))
                .flatten();
            match trap {
                None => {
                    to.write_all(&message)?;
                    for piece in &pieces {
                        to.write_all(piece)?;
                    }
                }
                Some((Cut::HoldReply(latch), sprung)) => {
                    let _unwatched_trap = sprung.send(number);
                    latch.wait();
                    to.write_all(&message)?;
                    for piece in &pieces {
                        to.write_all(piece)?;
                    }
                }
                Some((cut, sprung)) => {
                    if let Cut::Reply { pieces: through } = cut {
                        to.write_all(&message)?;
                        for piece in pieces.iter().take(through) {
                            to.write_all(piece)?;
                        }
                    }
                    to.flush()?;
                    let _unwatched_trap = sprung.send(number);
                    return Ok(());
                }
            }
        }
    }
}

#[derive(Debug)]
struct Ends {
    client: TcpStream,
    server: UnixStream,
}

impl Clone for Ends {
    fn clone(&self) -> Self {
        Self {
            client: self.client.try_clone().expect("a client handle"),
            server: self.server.try_clone().expect("a server handle"),
        }
    }
}

impl Ends {
    fn end(&self) {
        let _client_side_may_be_shut_already = self.client.shutdown(Shutdown::Both);
        let _server_side_may_be_shut_already = self.server.shutdown(Shutdown::Both);
    }

    /// Ends both sides once one direction stopped. An error other than the end
    /// of a side is printed, since the relay itself broke the connection then.
    fn end_after(&self, passed: &io::Result<()>) {
        if let Err(error) = passed
            && !matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
            )
        {
            eprintln!("the relay ended a connection: {error}");
        }
        self.end();
    }
}

fn read_frame(from: &mut impl Read) -> io::Result<(Vec<u8>, Follows)> {
    let mut bytes = vec![0u8; FRAME_HEADER_LEN];
    from.read_exact(&mut bytes)?;
    loop {
        let needed = match Frame::parse_prefix(&bytes, &LIMITS).map_err(io::Error::other)? {
            Parsed::Frame(frame) => return Ok((bytes.clone(), frame.follows())),
            Parsed::Need(needed) => needed,
        };
        let have = bytes.len();
        bytes.resize(needed, 0);
        from.read_exact(&mut bytes[have..])?;
    }
}

fn read_pieces(from: &mut impl Read) -> io::Result<Vec<Vec<u8>>> {
    let mut pieces = Vec::new();
    loop {
        let mut length = [0u8; PIECE_LEN_LEN];
        from.read_exact(&mut length)?;
        let len = piece::read_length(&length) as usize;
        let mut bytes = length.to_vec();
        bytes.resize(PIECE_LEN_LEN + if len == 0 { CLOSING_LEN } else { len }, 0);
        from.read_exact(&mut bytes[PIECE_LEN_LEN..])?;
        pieces.push(bytes);
        if len == 0 {
            return Ok(pieces);
        }
    }
}

fn copy(from: &mut impl Read, to: &mut impl Write, len: usize) -> io::Result<()> {
    let mut rest = len;
    let mut buffer = [0u8; 8192];
    while rest > 0 {
        let step = rest.min(buffer.len());
        from.read_exact(&mut buffer[..step])?;
        to.write_all(&buffer[..step])?;
        rest -= step;
    }
    Ok(())
}

fn header(message: &[u8]) -> &FrameHeader {
    FrameHeader::ref_from_prefix(message)
        .map(|(header, _)| header)
        .expect("a whole message starts with its header")
}

fn header_opcode(message: &[u8]) -> u16 {
    header(message).opcode.get()
}

fn header_flags(message: &[u8]) -> u16 {
    header(message).flags.get()
}
