//! The blocking control-socket client: one connection, one request line, one
//! response line.
//!
//! Every wait is finite unless the caller asks for no bound by name, because a
//! control socket that accepts a connection and never answers is otherwise
//! indistinguishable from a slow answer.
//!
//! Each read and write bound is a deadline for the whole operation. A socket
//! timeout alone bounds one syscall, so a peer that drips one byte just inside
//! every bound would extend a single call without limit. A wait without a bound
//! sets no socket timeout and has no deadline.
//!
//! A timeout leaves the connection unusable, because the stream position is no
//! longer known.
//!
//! [`Answer`] carries the response line exactly as the server wrote it, because
//! `voidport-ctl --json` prints that line verbatim and re-serializing the
//! parsed value would reshape it.

use std::io::{self, BufReader};
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

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    pub connect: Option<Duration>,
    pub read: Option<Duration>,
    pub write: Option<Duration>,
}

impl Timeouts {
    /// Connecting, sending and receiving each wait for as long as the server
    /// takes. A server that never answers blocks the caller forever.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            connect: None,
            read: None,
            write: None,
        }
    }
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Some(DEFAULT_CONNECT_TIMEOUT),
            read: Some(DEFAULT_READ_TIMEOUT),
            write: Some(DEFAULT_WRITE_TIMEOUT),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    Connect,
    Send,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub line: String,
    pub response: Response,
}

impl Answer {
    #[must_use]
    pub fn as_error(&self) -> Option<&ControlError> {
        self.response.as_error()
    }
}

#[derive(Debug)]
pub struct Client {
    socket: PathBuf,
    timeouts: Timeouts,
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Client {
    /// # Errors
    ///
    /// Fails if the socket cannot be reached within the connect bound.
    pub fn connect(socket: &Path) -> Result<Self, ClientError> {
        Self::connect_with(socket, Timeouts::default())
    }

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
        stream.set_read_timeout(timeouts.read).map_err(failed)?;
        stream.set_write_timeout(timeouts.write).map_err(failed)?;
        // The reader owns its own descriptor for the same socket, so a read and
        // a write never contend for one cursor; it carries the same bounds.
        let read_half = stream.try_clone().map_err(failed)?;
        read_half.set_read_timeout(timeouts.read).map_err(failed)?;
        Ok(Self {
            socket: socket.to_path_buf(),
            timeouts,
            stream,
            reader: BufReader::new(read_half),
        })
    }

    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// For callers that need byte-level facts the request/response API does not
    /// carry, such as how much the server has queued unread.
    #[must_use]
    pub fn stream(&self) -> &UnixStream {
        &self.stream
    }

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

    /// # Errors
    ///
    /// Propagates the write failure or the write timeout.
    pub fn send_line(&mut self, line: &[u8]) -> Result<(), ClientError> {
        let mut framed = Vec::with_capacity(line.len() + 1);
        framed.extend_from_slice(line);
        framed.push(b'\n');
        self.send_bytes(&framed)
    }

    /// The whole write is bounded by [`Timeouts::write`], with every syscall
    /// of the loop carrying only what is left of the one deadline.
    ///
    /// # Errors
    ///
    /// Propagates the write failure or the write timeout.
    pub fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), ClientError> {
        write_bytes(
            &mut self.stream,
            bytes,
            self.timeouts.write,
            Instant::now,
            |stream, left| stream.set_write_timeout(left),
        )
    }

    /// Reads one response line with the whole-operation deadline.
    ///
    /// # Errors
    ///
    /// Propagates read errors, invalid UTF-8 and expiration of the read deadline.
    pub fn read_line(&mut self) -> Result<Option<String>, ClientError> {
        read_line(
            &mut self.reader,
            self.timeouts.read,
            Instant::now,
            |reader, left| reader.get_ref().set_read_timeout(left),
        )
    }
}

#[derive(Clone, Copy, Debug)]
struct Deadline {
    at: Instant,
    bound: Duration,
}

impl Deadline {
    fn of(bound: Option<Duration>, now: Instant) -> Option<Self> {
        bound.map(|bound| Self {
            at: now + bound,
            bound,
        })
    }
}

/// How long the next syscall of `wait` may block: nothing without a deadline,
/// and what is left of the deadline otherwise.
///
/// # Errors
///
/// [`ClientError::Timeout`] once the deadline has passed.
fn next_wait(
    deadline: Option<Deadline>,
    now: Instant,
    wait: Wait,
) -> Result<Option<Duration>, ClientError> {
    deadline
        .map(|deadline| {
            remaining(deadline.at, now).ok_or(ClientError::Timeout {
                wait,
                after: deadline.bound,
            })
        })
        .transpose()
}

fn write_bytes<W: io::Write>(
    writer: &mut W,
    bytes: &[u8],
    bound: Option<Duration>,
    now: impl Fn() -> Instant,
    mut timeout: impl FnMut(&W, Option<Duration>) -> io::Result<()>,
) -> Result<(), ClientError> {
    let deadline = Deadline::of(bound, now());
    let mut rest = bytes;
    while !rest.is_empty() {
        let left = next_wait(deadline, now(), Wait::Send)?;
        if let Err(source) = timeout(writer, left) {
            return Err(io_error(Wait::Send, bound, source));
        }
        match writer.write(rest) {
            Ok(0) => {
                return Err(io_error(
                    Wait::Send,
                    bound,
                    io::Error::from(io::ErrorKind::WriteZero),
                ));
            }
            Ok(written) => rest = &rest[written..],
            Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => return Err(io_error(Wait::Send, bound, source)),
        }
    }
    writer
        .flush()
        .map_err(|source| io_error(Wait::Send, bound, source))
}

/// `None` means the server closed the connection instead of answering,
/// including partway through a line. The whole line is bounded by
/// [`Timeouts::read`], so a server dripping one byte per bound is detected.
///
/// # Errors
///
/// Propagates the read failure or the read timeout.
fn read_line<R: io::BufRead>(
    reader: &mut R,
    bound: Option<Duration>,
    now: impl Fn() -> Instant,
    mut timeout: impl FnMut(&R, Option<Duration>) -> io::Result<()>,
) -> Result<Option<String>, ClientError> {
    let deadline = Deadline::of(bound, now());
    let mut line = Vec::new();
    loop {
        let left = next_wait(deadline, now(), Wait::Receive)?;
        if let Err(source) = timeout(reader, left) {
            return Err(io_error(Wait::Receive, bound, source));
        }
        let chunk = match reader.fill_buf() {
            Ok(chunk) => chunk,
            Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => return Err(io_error(Wait::Receive, bound, source)),
        };
        if chunk.is_empty() {
            // The newline ends an answer, so bytes without one are an answer
            // the server abandoned during shutdown.
            return Ok(None);
        }
        let (taken, complete) = match chunk.iter().position(|byte| *byte == b'\n') {
            Some(end) => (end + 1, true),
            None => (chunk.len(), false),
        };
        line.extend_from_slice(&chunk[..taken]);
        reader.consume(taken);
        if complete {
            return decode(&line)
                .map(Some)
                .map_err(|source| io_error(Wait::Receive, bound, source));
        }
    }
}

/// Separates "the bound ran out" from everything else, because the two mean
/// different things to a caller that reconnects.
fn io_error(wait: Wait, bound: Option<Duration>, source: io::Error) -> ClientError {
    match bound {
        Some(after)
            if matches!(
                source.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            ClientError::Timeout { wait, after }
        }
        _ => ClientError::Io { wait, source },
    }
}

/// What is left of a deadline, or `None` once it has passed. A zero duration is
/// `None`, because a zero socket timeout means no timeout.
fn remaining(deadline: Instant, now: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|left| !left.is_zero())
}

/// A line that is not UTF-8 is an I/O failure, not a lossy conversion, because
/// replacement characters could turn a corrupt line into one that parses.
fn decode(line: &[u8]) -> io::Result<String> {
    let text = std::str::from_utf8(line).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the server sent a line that is not UTF-8",
        )
    })?;
    Ok(text.trim_end_matches(['\n', '\r']).to_owned())
}

/// A blocking `connect(2)` on a unix socket has no bound of its own: a listener
/// whose backlog is full leaves the caller waiting. So the socket is created
/// non-blocking, and the wait is `poll(2)`'s.
pub(crate) fn dial(socket: &Path, timeout: Option<Duration>) -> Result<UnixStream, ClientError> {
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

fn await_connected(
    fd: &OwnedFd,
    socket: &Path,
    timeout: Option<Duration>,
) -> Result<(), ClientError> {
    let failed = |source: Errno| ClientError::Connect {
        socket: socket.to_path_buf(),
        source: source.into(),
    };
    let deadline = timeout.map(|timeout| Timespec {
        tv_sec: timeout.as_secs().try_into().unwrap_or(i64::MAX),
        tv_nsec: timeout.subsec_nanos().into(),
    });
    let mut fds = [PollFd::new(fd, PollFlags::OUT)];
    let ready = rustix::io::retry_on_intr(|| poll(&mut fds, deadline.as_ref())).map_err(failed)?;
    // A poll without a bound returns only once the socket is ready.
    if let (0, Some(after)) = (ready, timeout) {
        return Err(ClientError::Timeout {
            wait: Wait::Connect,
            after,
        });
    }
    // A failed connect is reported through SO_ERROR, not through poll: the
    // descriptor is writable either way.
    match sockopt::socket_error(fd).map_err(failed)? {
        Ok(()) => Ok(()),
        Err(source) => Err(failed(source)),
    }
}

/// A rejected operation is not one of these: the server answered, and the
/// answer carries a [`ControlError`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error("cannot connect to the voidportd control socket {socket}")]
    Connect {
        socket: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the control socket stopped responding: {wait} took longer than {after:?}")]
    Timeout { wait: Wait, after: Duration },
    #[error("the control socket failed while {wait}")]
    Io {
        wait: Wait,
        #[source]
        source: io::Error,
    },
    #[error("the server closed the connection without answering")]
    Closed,
    #[error("cannot encode the request")]
    Encode(#[source] serde_json::Error),
    #[error("the server sent a response this client cannot read: {line}")]
    Malformed {
        line: String,
        #[source]
        source: serde_json::Error,
    },
}

impl ClientError {
    /// Whether the connection is dead: every variant but a malformed line and
    /// an encoding failure. A caller that redialed on every failure would tear
    /// down a healthy connection over one unreadable reply.
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
    use std::cell::Cell;
    use std::io::{BufRead as _, Write as _};
    use std::os::unix::net::UnixListener;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// The path is under `/tmp` because a unix socket path must fit `sun_path`
    /// and `$TMPDIR` is not bounded. Its drop removes the socket after a
    /// failing assertion unwinds past the cleanup of a case.
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

    struct Progress {
        now: Rc<Cell<Instant>>,
        step: Duration,
        operations: usize,
    }

    impl io::Read for Progress {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            assert!(!bytes.is_empty());
            self.operations += 1;
            self.now.set(self.now.get() + self.step);
            bytes[0] = b'x';
            Ok(1)
        }
    }

    impl io::Write for Progress {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            assert!(!bytes.is_empty());
            self.operations += 1;
            self.now.set(self.now.get() + self.step);
            Ok(1)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_last_line_without_its_newline_is_no_answer() {
        let read = |bytes: &'static [u8]| {
            let mut reader = BufReader::new(bytes);
            let mut lines = Vec::new();
            while let Some(line) = read_line(
                &mut reader,
                Some(Duration::from_secs(5)),
                Instant::now,
                |_, _| Ok(()),
            )
            .expect("the bytes read")
            {
                lines.push(line);
            }
            lines
        };
        assert_eq!(
            read(b"{\"ok\":1}\n{\"ok\":2}\n"),
            ["{\"ok\":1}", "{\"ok\":2}"]
        );
        assert_eq!(read(b"{\"ok\":1}\n{\"ok\":2}"), ["{\"ok\":1}"]);
        assert_eq!(read(b"{\"ok\":1}\n{\"o"), ["{\"ok\":1}"]);
        assert!(read(b"{\"ok\":1}").is_empty());
        assert!(read(b"").is_empty());
    }

    #[test]
    fn a_server_that_never_answers_is_detected_by_the_read_timeout() {
        struct Silent;
        impl io::Read for Silent {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::TimedOut.into())
            }
        }
        let now = Instant::now();
        let bound = Duration::from_secs(5);
        let error = read_line(
            &mut BufReader::new(Silent),
            Some(bound),
            || now,
            |_, left| {
                assert_eq!(left, Some(bound));
                Ok(())
            },
        )
        .expect_err("the transport reports its wait expired");
        assert!(
            matches!(error, ClientError::Timeout { wait: Wait::Receive, after } if after == bound)
        );
        assert!(error.is_disconnect());
    }

    #[test]
    fn a_server_that_drips_its_answer_is_bounded_by_the_read_deadline() {
        let now = Rc::new(Cell::new(Instant::now()));
        let mut reader = BufReader::new(Progress {
            now: Rc::clone(&now),
            step: Duration::from_secs(1),
            operations: 0,
        });
        let mut waits = Vec::new();
        let bound = Duration::from_secs(3);
        let error = read_line(
            &mut reader,
            Some(bound),
            || now.get(),
            |_, left| {
                waits.push(left);
                Ok(())
            },
        )
        .expect_err("partial progress does not renew the deadline");
        assert!(
            matches!(error, ClientError::Timeout { wait: Wait::Receive, after } if after == bound)
        );
        assert_eq!(reader.get_ref().operations, 3);
        assert_eq!(
            waits,
            [3, 2, 1].map(|seconds| Some(Duration::from_secs(seconds)))
        );
    }

    #[test]
    fn a_peer_that_drains_a_trickle_is_bounded_by_the_write_deadline() {
        let now = Rc::new(Cell::new(Instant::now()));
        let mut writer = Progress {
            now: Rc::clone(&now),
            step: Duration::from_secs(1),
            operations: 0,
        };
        let mut waits = Vec::new();
        let bound = Duration::from_secs(3);
        let error = write_bytes(
            &mut writer,
            b"unfinished",
            Some(bound),
            || now.get(),
            |_, left| {
                waits.push(left);
                Ok(())
            },
        )
        .expect_err("partial progress does not renew the deadline");
        assert!(
            matches!(error, ClientError::Timeout { wait: Wait::Send, after } if after == bound)
        );
        assert_eq!(writer.operations, 3);
        assert_eq!(
            waits,
            [3, 2, 1].map(|seconds| Some(Duration::from_secs(seconds)))
        );
    }

    struct Late {
        bytes: &'static [u8],
        now: Rc<Cell<Instant>>,
    }

    impl io::Read for Late {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let Some((first, rest)) = self.bytes.split_first() else {
                return Ok(0);
            };
            self.now.set(self.now.get() + Duration::from_secs(3600));
            buffer[0] = *first;
            self.bytes = rest;
            Ok(1)
        }
    }

    #[test]
    fn an_unbounded_read_sets_no_socket_timeout_and_waits_for_a_late_answer() {
        let now = Rc::new(Cell::new(Instant::now()));
        let mut reader = BufReader::with_capacity(
            1,
            Late {
                bytes: b"{\"ok\":1}\n",
                now: Rc::clone(&now),
            },
        );
        let mut waits = Vec::new();
        let line = read_line(
            &mut reader,
            None,
            || now.get(),
            |_, left| {
                waits.push(left);
                Ok(())
            },
        )
        .expect("no deadline passes");
        assert_eq!(line.as_deref(), Some("{\"ok\":1}"));
        assert_eq!(waits, [None; 9]);
    }

    #[test]
    fn an_unbounded_write_sets_no_socket_timeout_and_waits_for_a_slow_peer() {
        let now = Rc::new(Cell::new(Instant::now()));
        let mut writer = Progress {
            now: Rc::clone(&now),
            step: Duration::from_secs(3600),
            operations: 0,
        };
        let mut waits = Vec::new();
        write_bytes(
            &mut writer,
            b"unfinished",
            None,
            || now.get(),
            |_, left| {
                waits.push(left);
                Ok(())
            },
        )
        .expect("no deadline passes");
        assert_eq!(writer.operations, 10);
        assert_eq!(waits, [None; 10]);
    }

    #[test]
    fn a_socket_timeout_without_a_bound_is_a_failure_not_a_timeout() {
        struct Expired;
        impl io::Read for Expired {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::TimedOut.into())
            }
        }
        let error = read_line(&mut BufReader::new(Expired), None, Instant::now, |_, _| {
            Ok(())
        })
        .expect_err("the transport fails");
        assert!(
            matches!(
                error,
                ClientError::Io {
                    wait: Wait::Receive,
                    ..
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn the_default_timeouts_bound_every_wait_and_the_unbounded_ones_bound_none() {
        let default = Timeouts::default();
        assert_eq!(
            [default.connect, default.read, default.write],
            [
                Some(DEFAULT_CONNECT_TIMEOUT),
                Some(DEFAULT_READ_TIMEOUT),
                Some(DEFAULT_WRITE_TIMEOUT)
            ]
        );
        let unbounded = Timeouts::unbounded();
        assert_eq!(
            [unbounded.connect, unbounded.read, unbounded.write],
            [None; 3]
        );
    }

    #[test]
    fn an_unbounded_client_sets_no_socket_timeout_and_is_answered() {
        let socket = Socket::new("unbounded");
        let listener = socket.listen();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("a connection");
            let mut request = String::new();
            BufReader::new(stream.try_clone().expect("clone"))
                .read_line(&mut request)
                .expect("a request line");
            stream
                .write_all(b"{\"status\":\"ok\",\"result\":{\"reply\":\"done\"}}\n")
                .expect("an answer");
        });

        let mut client =
            Client::connect_with(socket.path(), Timeouts::unbounded()).expect("the socket accepts");
        assert_eq!(client.stream().read_timeout().expect("readable"), None);
        assert_eq!(client.stream().write_timeout().expect("readable"), None);
        let answer = client
            .call(&Request::ServerInfo {})
            .expect("an answered request");
        assert_eq!(answer.line, r#"{"status":"ok","result":{"reply":"done"}}"#);
        server.join().expect("the fake server finishes");
    }

    #[test]
    fn a_zero_remaining_bound_is_expired_not_an_unbounded_socket_wait() {
        let deadline = Instant::now();
        assert_eq!(
            remaining(deadline, deadline - Duration::from_nanos(1)),
            Some(Duration::from_nanos(1))
        );
        assert_eq!(remaining(deadline, deadline), None);
        assert_eq!(
            remaining(deadline, deadline + Duration::from_nanos(1)),
            None
        );
    }

    #[test]
    fn a_server_that_closes_without_answering_says_so() {
        let socket = Socket::new("closed");
        let listener = socket.listen();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("a connection");
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
