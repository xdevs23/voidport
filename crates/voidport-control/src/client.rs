//! The blocking control-socket client.
//!
//! One connection, one request line, one response line — the control plane is
//! low-frequency operator traffic, so the client is deliberately synchronous
//! and unpipelined. It lives here, behind the `client` cargo feature, because
//! three consumers need exactly this and must not each grow their own: the
//! operator CLI, the operator TUI, and the workspace's test scaffolding. Off by
//! default, so a consumer that wants only the typed protocol pays for nothing
//! but serde.
//!
//! # Timeouts
//!
//! Every wait is finite. A control socket that accepts a connection and then
//! never answers — a server wedged mid-mutation, a socket file left behind by a
//! process that is still alive but not serving — is otherwise indistinguishable
//! from a slow answer, and a caller drawing a terminal would hang there
//! forever. The three bounds are [`Timeouts`]:
//!
//! * connect — [`DEFAULT_CONNECT_TIMEOUT`], enforced by a non-blocking
//!   `connect(2)` plus `poll(2)`, because a listener with a full backlog blocks
//!   an ordinary connect indefinitely;
//! * read — [`DEFAULT_READ_TIMEOUT`], the answer bound;
//! * write — [`DEFAULT_WRITE_TIMEOUT`], for a peer that stops draining.
//!
//! Each bound is a **deadline for the whole operation**, not an inactivity
//! timeout per syscall. A socket timeout alone bounds one `read(2)`, so a peer
//! that drips one byte just inside every bound extends a single call without
//! limit — and the caller joining a worker thread that is inside it waits just
//! as long. So the line read and the line write take the deadline once and each
//! syscall gets what is left of it.
//!
//! A timeout is reported as [`ClientError::Timeout`] and leaves the connection
//! unusable: the stream position is no longer known, so the caller reconnects
//! instead of reusing it.
//!
//! # Verbatim lines
//!
//! [`Answer`] carries the response line exactly as the server wrote it
//! alongside the parsed envelope. `voidport-ctl --json` prints that line
//! **verbatim** — it is the stable script interface, and re-serializing the
//! parsed value would silently reshape it.

use std::io::{self, BufRead as _, BufReader, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::net::{
    AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with, sockopt,
};

use crate::request::Request;
use crate::response::{ControlError, Response};

/// How long a connection attempt may take.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the client waits for a response line.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the client waits for a request line to be accepted.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// The three finite waits a client performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// The bound on `connect(2)`.
    pub connect: Duration,
    /// The bound on reading one response line.
    pub read: Duration,
    /// The bound on writing one request line.
    pub write: Duration,
}

impl Default for Timeouts {
    /// The stated defaults: [`DEFAULT_CONNECT_TIMEOUT`],
    /// [`DEFAULT_READ_TIMEOUT`], [`DEFAULT_WRITE_TIMEOUT`].
    fn default() -> Self {
        Self {
            connect: DEFAULT_CONNECT_TIMEOUT,
            read: DEFAULT_READ_TIMEOUT,
            write: DEFAULT_WRITE_TIMEOUT,
        }
    }
}

/// Which wait ran out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// Connecting to the socket.
    Connect,
    /// Sending a request.
    Send,
    /// Waiting for a response.
    Receive,
}

impl std::fmt::Display for Wait {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Connect => "connecting",
            Self::Send => "sending a request",
            Self::Receive => "waiting for a response",
        })
    }
}

/// One answered request: the server's line, and what it parsed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The response line exactly as the server wrote it, newline stripped.
    pub line: String,
    /// The parsed envelope.
    pub response: Response,
}

impl Answer {
    /// The error the server answered with, if it rejected the operation.
    #[must_use]
    pub fn as_error(&self) -> Option<&ControlError> {
        self.response.as_error()
    }
}

/// A connection to a running server's control socket.
#[derive(Debug)]
pub struct Client {
    socket: PathBuf,
    timeouts: Timeouts,
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Client {
    /// Connects to a control socket with the default [`Timeouts`].
    ///
    /// # Errors
    ///
    /// Fails if the socket cannot be reached within the connect bound — most
    /// often because no server is running, or because it serves a different
    /// path.
    pub fn connect(socket: &Path) -> Result<Self, ClientError> {
        Self::connect_with(socket, Timeouts::default())
    }

    /// Connects to a control socket with explicit timeouts.
    ///
    /// # Errors
    ///
    /// As [`Self::connect`], plus [`ClientError::Timeout`] when the connect
    /// bound runs out.
    pub fn connect_with(socket: &Path, timeouts: Timeouts) -> Result<Self, ClientError> {
        let stream = dial(socket, timeouts.connect)?;
        let failed = |source: io::Error| ClientError::Connect {
            socket: socket.to_path_buf(),
            source,
        };
        stream
            .set_read_timeout(Some(timeouts.read))
            .map_err(failed)?;
        stream
            .set_write_timeout(Some(timeouts.write))
            .map_err(failed)?;
        // The reader owns its own descriptor for the same socket, so a read and
        // a write never contend for one cursor; it carries the same bounds.
        let read_half = stream.try_clone().map_err(failed)?;
        read_half
            .set_read_timeout(Some(timeouts.read))
            .map_err(failed)?;
        Ok(Self {
            socket: socket.to_path_buf(),
            timeouts,
            stream,
            reader: BufReader::new(read_half),
        })
    }

    /// The socket this client is connected to.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The underlying socket.
    ///
    /// Exposed for callers that need byte-level facts the request/response API
    /// does not carry — how much the server has queued unread, for instance.
    #[must_use]
    pub fn stream(&self) -> &UnixStream {
        &self.stream
    }

    /// Sends one request and reads its answer.
    ///
    /// # Errors
    ///
    /// Fails on any I/O error or timeout, on a server that closes without
    /// answering ([`ClientError::Closed`]), and on a line that is not a valid
    /// response envelope ([`ClientError::Malformed`]).
    pub fn call(&mut self, request: &Request) -> Result<Answer, ClientError> {
        let line = serde_json::to_vec(request).map_err(ClientError::Encode)?;
        self.send_line(&line)?;
        let line = self.read_line()?.ok_or(ClientError::Closed)?;
        let response = serde_json::from_str(&line).map_err(|source| ClientError::Malformed {
            line: line.clone(),
            source,
        })?;
        Ok(Answer { line, response })
    }

    /// Sends raw bytes followed by a newline.
    ///
    /// # Errors
    ///
    /// Propagates the write failure or the write timeout.
    pub fn send_line(&mut self, line: &[u8]) -> Result<(), ClientError> {
        let mut framed = Vec::with_capacity(line.len() + 1);
        framed.extend_from_slice(line);
        framed.push(b'\n');
        self.send_bytes(&framed)
    }

    /// Sends raw bytes with no newline of its own.
    ///
    /// The whole write is bounded by [`Timeouts::write`]: a peer that drains a
    /// few bytes at a time cannot stretch it, because every syscall in the loop
    /// carries only what is left of the one deadline.
    ///
    /// # Errors
    ///
    /// Propagates the write failure or the write timeout.
    pub fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), ClientError> {
        let bound = self.timeouts.write;
        let deadline = Instant::now() + bound;
        let mut rest = bytes;
        while !rest.is_empty() {
            let left = remaining(deadline).ok_or(ClientError::Timeout {
                wait: Wait::Send,
                after: bound,
            })?;
            if let Err(source) = self.stream.set_write_timeout(Some(left)) {
                return Err(self.io_error(Wait::Send, bound, source));
            }
            match self.stream.write(rest) {
                Ok(0) => {
                    return Err(self.io_error(
                        Wait::Send,
                        bound,
                        io::Error::from(io::ErrorKind::WriteZero),
                    ));
                }
                Ok(written) => rest = &rest[written..],
                Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
                Err(source) => return Err(self.io_error(Wait::Send, bound, source)),
            }
        }
        self.stream
            .flush()
            .map_err(|source| self.io_error(Wait::Send, bound, source))
    }

    /// Reads one response line, newline stripped.
    ///
    /// `None` means the server closed the connection instead of answering.
    ///
    /// The whole line is bounded by [`Timeouts::read`], for the same reason the
    /// write is: a server dripping one byte per bound would otherwise never be
    /// detected as wedged.
    ///
    /// # Errors
    ///
    /// Propagates the read failure or the read timeout.
    pub fn read_line(&mut self) -> Result<Option<String>, ClientError> {
        let bound = self.timeouts.read;
        let deadline = Instant::now() + bound;
        let mut line = Vec::new();
        loop {
            let left = remaining(deadline).ok_or(ClientError::Timeout {
                wait: Wait::Receive,
                after: bound,
            })?;
            if let Err(source) = self.reader.get_ref().set_read_timeout(Some(left)) {
                return Err(self.io_error(Wait::Receive, bound, source));
            }
            let chunk = match self.reader.fill_buf() {
                Ok(chunk) => chunk,
                Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(self.io_error(Wait::Receive, bound, source)),
            };
            if chunk.is_empty() {
                // The peer hung up. Nothing at all means it never answered; a
                // partial line is an answer this client cannot parse, and it is
                // returned as such, not silently discarded.
                if line.is_empty() {
                    return Ok(None);
                }
                return decode(&line)
                    .map(Some)
                    .map_err(|source| self.io_error(Wait::Receive, bound, source));
            }
            let (taken, complete) = match chunk.iter().position(|byte| *byte == b'\n') {
                Some(end) => (end + 1, true),
                None => (chunk.len(), false),
            };
            line.extend_from_slice(&chunk[..taken]);
            self.reader.consume(taken);
            if complete {
                return decode(&line)
                    .map(Some)
                    .map_err(|source| self.io_error(Wait::Receive, bound, source));
            }
        }
    }

    /// Classifies an I/O failure, separating "the bound ran out" from
    /// everything else: the two mean different things to a caller that
    /// reconnects.
    fn io_error(&self, wait: Wait, after: Duration, source: io::Error) -> ClientError {
        if matches!(
            source.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) {
            ClientError::Timeout { wait, after }
        } else {
            ClientError::Io { wait, source }
        }
    }
}

/// What is left of a deadline, or `None` once it has passed.
///
/// A zero duration is `None`, not a zero timeout, because a zero socket
/// timeout means *no* timeout — the very thing the deadline exists to prevent.
fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

/// One line's bytes as text, newline stripped.
///
/// A line that is not UTF-8 is an I/O failure, not a lossy conversion:
/// replacement characters would turn a corrupt line into one that might parse.
fn decode(line: &[u8]) -> io::Result<String> {
    let text = std::str::from_utf8(line).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the server sent a line that is not UTF-8",
        )
    })?;
    Ok(text.trim_end_matches(['\n', '\r']).to_owned())
}

/// Connects within `timeout`.
///
/// A blocking `connect(2)` on a unix socket has no bound of its own: a listener
/// whose backlog is full leaves the caller waiting for as long as the server
/// takes to accept. So the socket is created non-blocking, the connect is
/// started, and the wait is `poll(2)`'s — which does take a bound.
pub(crate) fn dial(socket: &Path, timeout: Duration) -> Result<UnixStream, ClientError> {
    let failed = |source: Errno| ClientError::Connect {
        socket: socket.to_path_buf(),
        source: source.into(),
    };
    let address = SocketAddrUnix::new(socket).map_err(failed)?;
    let fd = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(failed)?;

    match connect(&fd, &address) {
        Ok(()) => {}
        Err(Errno::INPROGRESS | Errno::AGAIN) => {
            await_connected(&fd, socket, timeout)?;
        }
        Err(source) => return Err(failed(source)),
    }

    let stream = UnixStream::from(fd);
    stream
        .set_nonblocking(false)
        .map_err(|source| ClientError::Connect {
            socket: socket.to_path_buf(),
            source,
        })?;
    Ok(stream)
}

/// Waits for an in-progress connect to finish, or for the bound to run out.
fn await_connected(fd: &OwnedFd, socket: &Path, timeout: Duration) -> Result<(), ClientError> {
    let failed = |source: Errno| ClientError::Connect {
        socket: socket.to_path_buf(),
        source: source.into(),
    };
    let deadline = Timespec {
        tv_sec: timeout.as_secs().try_into().unwrap_or(i64::MAX),
        tv_nsec: timeout.subsec_nanos().into(),
    };
    let mut fds = [PollFd::new(fd, PollFlags::OUT)];
    let ready = rustix::io::retry_on_intr(|| poll(&mut fds, Some(&deadline))).map_err(failed)?;
    if ready == 0 {
        return Err(ClientError::Timeout {
            wait: Wait::Connect,
            after: timeout,
        });
    }
    // A failed connect is reported through SO_ERROR, not through poll: the
    // descriptor is writable either way.
    match sockopt::socket_error(fd).map_err(failed)? {
        Ok(()) => Ok(()),
        Err(source) => Err(failed(source)),
    }
}

/// Why a control-plane call did not produce an answer.
///
/// A *rejected* operation is not one of these: the server answered, and the
/// answer carries a [`ControlError`]. These are the ways the conversation
/// itself failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The socket could not be connected to.
    #[error("cannot connect to the voidportd control socket {socket}")]
    Connect {
        /// The socket path.
        socket: PathBuf,
        /// Why the connection failed.
        #[source]
        source: io::Error,
    },
    /// A finite wait ran out. The connection is unusable afterwards.
    #[error("the control socket stopped responding: {wait} took longer than {after:?}")]
    Timeout {
        /// Which wait ran out.
        wait: Wait,
        /// The bound it exceeded.
        after: Duration,
    },
    /// The connection failed while the client was using it.
    #[error("the control socket failed while {wait}")]
    Io {
        /// What the client was doing.
        wait: Wait,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// The server closed the connection without answering.
    #[error("the server closed the connection without answering")]
    Closed,
    /// The request could not be encoded.
    #[error("cannot encode the request")]
    Encode(#[source] serde_json::Error),
    /// The server sent something that is not a response envelope.
    #[error("the server sent a response this client cannot read: {line}")]
    Malformed {
        /// The offending line.
        line: String,
        /// Why it did not parse.
        #[source]
        source: serde_json::Error,
    },
}

impl ClientError {
    /// Whether the connection is dead — every variant but a malformed line and
    /// an encoding failure, both of which are about one message, not
    /// about the socket.
    ///
    /// This is the reconnect decision: a caller that drops and redials on
    /// *every* failure would tear down a healthy connection over one unreadable
    /// reply, and would then redial forever against a server whose replies it
    /// cannot read.
    #[must_use]
    pub fn is_disconnect(&self) -> bool {
        matches!(
            self,
            Self::Connect { .. } | Self::Timeout { .. } | Self::Io { .. } | Self::Closed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// A socket path that removes itself.
    ///
    /// The path is under `/tmp` for the reason every socket-binding suite in
    /// this workspace uses `/tmp`: a unix socket path must fit `sun_path`, and
    /// `$TMPDIR` is not bounded. The guard exists because a failing assertion
    /// unwinds past any cleanup written at the end of a case, and a bound
    /// socket left behind is a file the next run has to reclaim.
    #[derive(Debug)]
    struct Socket {
        path: PathBuf,
    }

    impl Socket {
        fn new(label: &str) -> Self {
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            Self {
                path: PathBuf::from(format!(
                    "/tmp/voidport-client-{label}-{}-{}.sock",
                    std::process::id(),
                    SEQUENCE.fetch_add(1, Ordering::Relaxed)
                )),
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        /// Binds a listener on it.
        fn listen(&self) -> UnixListener {
            UnixListener::bind(&self.path).expect("a bindable socket path")
        }
    }

    impl Drop for Socket {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn a_missing_socket_is_a_connect_failure() {
        let socket = Socket::new("missing");
        let error = Client::connect(socket.path()).expect_err("nothing listens");
        assert!(matches!(error, ClientError::Connect { .. }), "{error}");
        assert!(error.is_disconnect());
    }

    #[test]
    fn a_request_is_answered_verbatim_and_parsed() {
        let socket = Socket::new("answer");
        let listener = socket.listen();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("a connection");
            let mut request = String::new();
            BufReader::new(stream.try_clone().expect("clone"))
                .read_line(&mut request)
                .expect("a request line");
            assert_eq!(request.trim_end(), r#"{"op":"namespace-list"}"#);
            stream
                .write_all(
                    b"{\"status\":\"ok\",\"result\":{\"reply\":\"namespace-list\",\"namespaces\":[]}}\n",
                )
                .expect("an answer");
        });

        let mut client = Client::connect(socket.path()).expect("the socket accepts");
        let answer = client
            .call(&Request::NamespaceList {})
            .expect("an answered request");
        assert_eq!(
            answer.line,
            r#"{"status":"ok","result":{"reply":"namespace-list","namespaces":[]}}"#
        );
        assert!(answer.as_error().is_none());
        server.join().expect("the fake server finishes");
    }

    #[test]
    fn a_server_that_never_answers_is_detected_by_the_read_timeout() {
        let socket = Socket::new("wedged");
        let listener = socket.listen();
        // Accept and then do nothing at all: the wedged server the timeouts
        // exist for.
        let server = std::thread::spawn(move || listener.accept().expect("a connection").0);

        let mut client = Client::connect_with(
            socket.path(),
            Timeouts {
                read: Duration::from_millis(150),
                ..Timeouts::default()
            },
        )
        .expect("the socket accepts");
        let error = client
            .call(&Request::ServerInfo {})
            .expect_err("the server never answers");
        assert!(matches!(error, ClientError::Timeout { .. }), "{error}");
        assert!(error.is_disconnect(), "{error}");
        drop(server.join().expect("the fake server holds its connection"));
    }

    /// How long a drip test is allowed to take before the bound is judged
    /// unenforced. Far above the bounds the cases set, far below the minutes a
    /// per-syscall inactivity timeout would allow.
    const PATIENCE: Duration = Duration::from_secs(5);

    #[test]
    fn a_server_that_drips_its_answer_is_bounded_by_the_read_deadline() {
        let socket = Socket::new("drip");
        let listener = socket.listen();
        // One byte every 50 ms and never a newline: each `read(2)` returns well
        // inside any per-syscall bound, so only a deadline over the whole line
        // ever ends this.
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("a connection");
            let mut request = String::new();
            BufReader::new(stream.try_clone().expect("clone"))
                .read_line(&mut request)
                .expect("a request line");
            while stream.write_all(b"x").is_ok() {
                let _ = stream.flush();
                std::thread::sleep(Duration::from_millis(50));
            }
        });

        let mut client = Client::connect_with(
            socket.path(),
            Timeouts {
                read: Duration::from_millis(300),
                ..Timeouts::default()
            },
        )
        .expect("the socket accepts");
        let started = Instant::now();
        let error = client
            .call(&Request::ServerInfo {})
            .expect_err("the answer never completes");
        let elapsed = started.elapsed();
        assert!(matches!(error, ClientError::Timeout { .. }), "{error}");
        assert!(
            elapsed < PATIENCE,
            "the read outlived its bound: {elapsed:?}"
        );
        drop(client);
        server.join().expect("the fake server finishes");
    }

    #[test]
    fn a_peer_that_drains_a_trickle_is_bounded_by_the_write_deadline() {
        use std::io::Read as _;

        let socket = Socket::new("trickle");
        let listener = socket.listen();
        // The mirror image: a byte taken every 50 ms keeps every `write(2)`
        // making progress, so only a deadline over the whole request ends it.
        // The flag ends the trickle when the case is over — draining what the
        // kernel already queued, one byte at a time, would take hours.
        let done = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let done = Arc::clone(&done);
            move || {
                let (mut stream, _) = listener.accept().expect("a connection");
                let mut byte = [0_u8; 1];
                while !done.load(Ordering::Relaxed) && matches!(stream.read(&mut byte), Ok(1)) {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        });

        let mut client = Client::connect_with(
            socket.path(),
            Timeouts {
                write: Duration::from_millis(300),
                ..Timeouts::default()
            },
        )
        .expect("the socket accepts");
        // Bigger than any socket buffer, so the write really does wait on the
        // peer, not on the kernel.
        let payload = vec![b'x'; 4 * 1024 * 1024];
        let started = Instant::now();
        let error = client
            .send_bytes(&payload)
            .expect_err("the peer never drains it");
        let elapsed = started.elapsed();
        assert!(matches!(error, ClientError::Timeout { .. }), "{error}");
        assert!(
            elapsed < PATIENCE,
            "the write outlived its bound: {elapsed:?}"
        );
        done.store(true, Ordering::Relaxed);
        drop(client);
        server.join().expect("the fake server finishes");
    }

    #[test]
    fn a_server_that_closes_without_answering_says_so() {
        let socket = Socket::new("closed");
        let listener = socket.listen();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("a connection");
            // Take the request, then hang up without answering it.
            let mut request = String::new();
            BufReader::new(stream.try_clone().expect("clone"))
                .read_line(&mut request)
                .expect("a request line");
            drop(stream);
        });

        let mut client = Client::connect(socket.path()).expect("the socket accepts");
        let error = client
            .call(&Request::ServerInfo {})
            .expect_err("the server hangs up");
        assert!(matches!(error, ClientError::Closed), "{error}");
        server.join().expect("the fake server finishes");
    }

    #[test]
    fn a_line_that_is_not_an_envelope_is_a_malformed_answer() {
        let socket = Socket::new("garbage");
        let listener = socket.listen();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("a connection");
            let mut request = String::new();
            BufReader::new(stream.try_clone().expect("clone"))
                .read_line(&mut request)
                .expect("a request line");
            stream.write_all(b"not an envelope\n").expect("an answer");
        });

        let mut client = Client::connect(socket.path()).expect("the socket accepts");
        let error = client
            .call(&Request::ServerInfo {})
            .expect_err("the answer is not an envelope");
        assert!(matches!(error, ClientError::Malformed { .. }), "{error}");
        assert!(
            !error.is_disconnect(),
            "a malformed line is about one message, not about the socket"
        );
        server.join().expect("the fake server finishes");
    }
}
