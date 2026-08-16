//! The test suites' view of the control socket.
//!
//! The connection itself is the product one — `voidport_control::Client`, the
//! same blocking client the operator CLI and the operator TUI drive — so the
//! suites cannot pass against a client nobody ships. What this wrapper adds is
//! only what a test wants and a product client must not have: assertions
//! instead of `Result`s, and two byte-level probes (`send_raw`, `send_unread`)
//! that exist to send exactly what no typed client would ever produce.

use std::path::Path;
use std::time::{Duration, Instant};

use voidport_control::client::{Client, Timeouts};
use voidport_control::{ControlError, Reply, Request, Response};

/// A blocking newline-delimited JSON client for a control socket.
#[derive(Debug)]
pub struct ControlClient {
    client: Client,
}

impl ControlClient {
    /// Connects to a control socket.
    ///
    /// # Errors
    ///
    /// Propagates the connection failure, which the bind-contract tests use to
    /// prove a socket is dead.
    pub fn connect(socket: &Path) -> Result<Self, voidport_control::ClientError> {
        // A long read bound: one suite deliberately wedges the server to prove
        // backpressure, and the assertion there is about queue depth, not about
        // how patient a client is.
        Client::connect_with(
            socket,
            Timeouts {
                read: Duration::from_secs(60),
                ..Timeouts::default()
            },
        )
        .map(|client| Self { client })
    }

    /// Sends raw bytes followed by a newline and reads one response line.
    ///
    /// Returns `None` if the server closed the connection instead of
    /// answering.
    pub fn send_line(&mut self, line: &[u8]) -> Option<String> {
        self.client.send_line(line).expect("the socket accepts");
        self.read_line()
    }

    /// Sends raw bytes with no newline of its own.
    ///
    /// Write failures are deliberately ignored: this is the path the oversized
    /// line test uses, and a server that answers and closes mid-write is
    /// exactly the behaviour under test — the answer, read below, is the
    /// assertion that matters.
    pub fn send_raw(&mut self, bytes: &[u8]) -> Option<String> {
        let _ = self.client.send_bytes(bytes);
        self.read_line()
    }

    /// Sends a request and deliberately does not read its answer.
    ///
    /// This is how a test builds backpressure: unread answers pile up in the
    /// socket buffer until the server's own write blocks.
    pub fn send_unread(&mut self, request: &Request) {
        let line = serde_json::to_vec(request).expect("the request encodes");
        self.client.send_line(&line).expect("the socket accepts");
    }

    /// Waits until the server stops making progress on this connection.
    ///
    /// Unread answers pile up in the socket buffer until the server's own
    /// write blocks; when the queue stops growing, the server is wedged in
    /// that write. Returns how many bytes are queued unread.
    #[must_use]
    pub fn wait_for_a_blocked_server(&self, timeout: Duration) -> u64 {
        let deadline = Instant::now() + timeout;
        let mut previous = 0;
        let mut unchanged = 0;
        loop {
            let queued = rustix::io::ioctl_fionread(self.client.stream()).expect("a queue length");
            unchanged = if queued > 0 && queued == previous {
                unchanged + 1
            } else {
                0
            };
            if unchanged >= 5 || Instant::now() >= deadline {
                return queued;
            }
            previous = queued;
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Reads one response line.
    pub fn read_line(&mut self) -> Option<String> {
        self.client.read_line().expect("the socket is readable")
    }

    /// Sends a typed request and parses the response envelope.
    #[must_use]
    pub fn call(&mut self, request: &Request) -> Response {
        self.client
            .call(request)
            .unwrap_or_else(|error| panic!("{request:?} was not answered: {error}"))
            .response
    }

    /// Sends a request that must succeed, returning its reply.
    ///
    /// # Panics
    ///
    /// If the server rejects it: a test that wanted the rejection asks for it
    /// with [`Self::expect_error`].
    pub fn expect_ok(&mut self, request: &Request) -> Reply {
        match self.call(request) {
            Response::Ok { result } => result,
            Response::Error { error } => panic!("{request:?} was rejected: {error}"),
        }
    }

    /// Sends a request that must fail, returning the error.
    ///
    /// # Panics
    ///
    /// If the server accepts it.
    pub fn expect_error(&mut self, request: &Request) -> ControlError {
        match self.call(request) {
            Response::Ok { result } => panic!("{request:?} unexpectedly succeeded: {result:?}"),
            Response::Error { error } => error,
        }
    }
}
