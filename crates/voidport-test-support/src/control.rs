use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use voidport_control::{ControlError, Reply, Request, Response};

#[derive(Debug)]
pub struct ControlClient {
    stream: BufReader<UnixStream>,
}

impl ControlClient {
    pub fn connect(socket: &Path) -> io::Result<Self> {
        Ok(Self {
            stream: BufReader::new(UnixStream::connect(socket)?),
        })
    }

    pub fn send_line(&mut self, line: &[u8]) -> Option<String> {
        self.write_line(line);
        self.read_line()
    }

    fn write_line(&mut self, line: &[u8]) {
        let stream = self.stream.get_mut();
        stream.write_all(line).expect("the socket accepts");
        stream
            .write_all(b"\n")
            .expect("the socket accepts the line ending");
        stream.flush().expect("the socket flushes");
    }

    /// The server may close while the bytes are written.
    pub fn send_raw(&mut self, bytes: &[u8]) -> Option<String> {
        let _ = self.stream.get_mut().write_all(bytes);
        self.read_line()
    }

    pub fn send_unread(&mut self, request: &Request) {
        self.write_line(&serde_json::to_vec(request).expect("the request encodes"));
    }

    /// A last line without its newline does not count as a reply, as in the real
    /// client.
    pub fn read_line(&mut self) -> Option<String> {
        let mut line = String::new();
        self.stream
            .read_line(&mut line)
            .expect("the socket is readable");
        line.ends_with('\n').then_some(line)
    }

    #[must_use]
    pub fn call(&mut self, request: &Request) -> Response {
        self.send_unread(request);
        let line = self
            .read_line()
            .unwrap_or_else(|| panic!("{request:?} was not answered"));
        serde_json::from_str(&line).expect("a valid control response")
    }

    pub fn expect_ok(&mut self, request: &Request) -> Reply {
        match self.call(request) {
            Response::Ok { result } => result,
            Response::Error { error } => panic!("{request:?} was rejected: {error}"),
        }
    }

    pub fn expect_error(&mut self, request: &Request) -> ControlError {
        match self.call(request) {
            Response::Ok { result } => panic!("{request:?} unexpectedly succeeded: {result:?}"),
            Response::Error { error } => error,
        }
    }
}
