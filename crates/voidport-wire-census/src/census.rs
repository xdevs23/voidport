use std::io::{self, Read, Write as _};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::num::TryFromIntError;
use std::ops::Add;
use std::os::fd::AsFd;
use std::panic;
use std::thread::{self, ScopedJoinHandle};

use rustix::event::{PollFd, PollFlags, poll};
use serde::Serialize;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{Frame, FrameKind, Parsed};
use voidport_proto::limits::LIMITS;
use voidport_proto::message::Follows;

const CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CensusError {
    #[error("cannot listen for connections")]
    Listen(#[source] io::Error),
    #[error("cannot wait for a connection or for the end of standard input")]
    Wait(#[source] io::Error),
    #[error("cannot accept a connection")]
    Accept(#[source] io::Error),
    #[error("cannot connect to the server")]
    Connect(#[source] io::Error),
    #[error("cannot forward a connection")]
    Forward(#[source] io::Error),
    #[error("cannot count the bytes of one read")]
    Count(#[source] TryFromIntError),
    #[error("cannot read a frame sent toward the server")]
    Frame(#[source] FramingError),
    #[error("a request toward the server announces write data longer than memory")]
    DataLength(#[source] TryFromIntError),
    #[error("a request toward the server is followed by streamed pieces")]
    Pieces,
    #[error("cannot print the result")]
    Print(#[source] io::Error),
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Totals {
    pub requests: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
}

impl Add for Totals {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            requests: self.requests + other.requests,
            bytes_received: self.bytes_received + other.bytes_received,
            bytes_sent: self.bytes_sent + other.bytes_sent,
        }
    }
}

/// Once the mount is gone and `stop` ends, the connections accepted so far,
/// including every connection waiting in the queue of the listener, are all
/// the connections there are.
pub fn count(
    listener: &TcpListener,
    server: SocketAddr,
    stop: impl Read + AsFd,
) -> Result<Totals, CensusError> {
    thread::scope(|scope| {
        let mut forwards = Vec::new();
        let accepted = accept_until(listener, stop, |client| {
            forwards.push(scope.spawn(move || forward(&client, server)));
        });
        let totals = forwards
            .into_iter()
            .map(joined)
            .try_fold(Totals::default(), |sum, totals| Ok(sum + totals?));
        accepted.and(totals)
    })
}

/// A connection that waits in the queue of the listener is accepted before
/// the end of `stop` is read.
fn accept_until(
    listener: &TcpListener,
    mut stop: impl Read + AsFd,
    mut accepted: impl FnMut(TcpStream),
) -> Result<(), CensusError> {
    listener
        .set_nonblocking(true)
        .map_err(CensusError::Listen)?;
    let mut discarded = [0; 512];
    loop {
        let mut waiting = [
            PollFd::new(listener, PollFlags::IN),
            PollFd::new(&stop, PollFlags::IN),
        ];
        match poll(&mut waiting, None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(errno) => return Err(CensusError::Wait(errno.into())),
        }
        let [connection, end] = waiting.map(|waited| !waited.revents().is_empty());
        if connection {
            match listener.accept() {
                Ok((client, _)) => accepted(client),
                // The connection was reset while it waited in the queue.
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(CensusError::Accept(error)),
            }
        } else if end {
            match stop.read(&mut discarded) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(CensusError::Wait(error)),
            }
        }
    }
}

fn joined<T>(handle: ScopedJoinHandle<'_, T>) -> T {
    handle
        .join()
        .unwrap_or_else(|payload| panic::resume_unwind(payload))
}

fn forward(client: &TcpStream, server: SocketAddr) -> Result<Totals, CensusError> {
    let server = TcpStream::connect(server).map_err(CensusError::Connect)?;
    // Frames are sent at once, so small writes must not wait. The accepted
    // connection does not inherit the non-blocking mode of the listener on
    // Linux, but the census does not rely on that.
    client
        .set_nonblocking(false)
        .and_then(|()| client.set_nodelay(true))
        .and_then(|()| server.set_nodelay(true))
        .map_err(CensusError::Forward)?;
    thread::scope(|scope| {
        let toward_server = scope.spawn(|| {
            let mut frames = Frames::default();
            let mut requests = 0;
            let bytes = relay(client, &server, |bytes| {
                requests += frames.count(bytes)?;
                Ok(())
            })?;
            Ok::<_, CensusError>((requests, bytes))
        });
        let bytes_sent = relay(&server, client, |_| Ok(()));
        let (requests, bytes_received) = joined(toward_server)?;
        Ok(Totals {
            requests,
            bytes_received,
            bytes_sent: bytes_sent?,
        })
    })
}

enum End {
    Finished,
    Broken,
}

fn relay(
    source: &TcpStream,
    destination: &TcpStream,
    mut observe: impl FnMut(&[u8]) -> Result<(), CensusError>,
) -> Result<u64, CensusError> {
    let mut passed = 0;
    let ended = copy(source, destination, &mut observe, &mut passed);
    let closed = match ended {
        Ok(End::Finished) => shut(destination, Shutdown::Write),
        Ok(End::Broken) | Err(_) => {
            shut(source, Shutdown::Both).and(shut(destination, Shutdown::Both))
        }
    };
    ended?;
    closed?;
    Ok(passed)
}

fn copy(
    mut source: &TcpStream,
    mut destination: &TcpStream,
    observe: &mut impl FnMut(&[u8]) -> Result<(), CensusError>,
    passed: &mut u64,
) -> Result<End, CensusError> {
    let mut buffer = vec![0; CHUNK_BYTES];
    loop {
        let read = match source.read(&mut buffer) {
            Ok(0) => return Ok(End::Finished),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if broken(&error) => return Ok(End::Broken),
            Err(error) => return Err(CensusError::Forward(error)),
        };
        let chunk = &buffer[..read];
        observe(chunk)?;
        match destination.write_all(chunk) {
            Ok(()) => *passed += u64::try_from(read).map_err(CensusError::Count)?,
            Err(error) if broken(&error) => return Ok(End::Broken),
            Err(error) => return Err(CensusError::Forward(error)),
        }
    }
}

fn broken(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
    )
}

fn shut(stream: &TcpStream, how: Shutdown) -> Result<(), CensusError> {
    match stream.shutdown(how) {
        // The peer closed the connection first, which ends it as well.
        Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(()),
        result => result.map_err(CensusError::Forward),
    }
}

#[derive(Default)]
struct Frames {
    frame: Vec<u8>,
    /// The bytes of write data after the last frame that have not passed yet.
    data: usize,
}

impl Frames {
    fn count(&mut self, mut bytes: &[u8]) -> Result<u64, CensusError> {
        let mut requests = 0;
        loop {
            if self.data > 0 {
                if bytes.is_empty() {
                    return Ok(requests);
                }
                let passed = self.data.min(bytes.len());
                self.data -= passed;
                bytes = &bytes[passed..];
                continue;
            }
            match Frame::parse_prefix(&self.frame, &LIMITS).map_err(CensusError::Frame)? {
                Parsed::Frame(frame) => {
                    if frame.kind() == FrameKind::Request {
                        requests += 1;
                    }
                    self.data = match frame.follows() {
                        Follows::Nothing => 0,
                        Follows::Data(length) => {
                            usize::try_from(length).map_err(CensusError::DataLength)?
                        }
                        Follows::Pieces(_) => return Err(CensusError::Pieces),
                    };
                    self.frame.clear();
                }
                Parsed::Need(needed) => {
                    if bytes.is_empty() {
                        return Ok(requests);
                    }
                    let taken = (needed - self.frame.len()).min(bytes.len());
                    self.frame.extend_from_slice(&bytes[..taken]);
                    bytes = &bytes[taken..];
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{PipeReader, pipe};

    use voidport_proto::frame::FrameWriter;
    use voidport_proto::message::RequestHead;
    use voidport_proto::ops::file::WriteRequest;
    use voidport_proto::ops::node::LookupRequest;
    use zerocopy::FromZeros;
    use zerocopy::byteorder::little_endian::U32;

    use super::*;

    fn three_requests() -> Vec<u8> {
        let head = RequestHead::new(1, 0, 0, 0);
        let mut buffer = [0; 128];
        let name_len = U32::new(4);
        let mut lookup =
            FrameWriter::request(&mut buffer, &LIMITS, 1, &head, &LookupRequest { name_len })
                .expect("a lookup frame");
        lookup.payload(b"tree").expect("the name of the lookup");
        let lookup = lookup.finish().expect("a lookup frame").to_vec();
        let mut write = WriteRequest::new_zeroed();
        write.data_len = U32::new(100);
        let mut buffer = [0; 128];
        let write = FrameWriter::request(&mut buffer, &LIMITS, 2, &head, &write)
            .and_then(FrameWriter::finish)
            .expect("a write frame");
        let data = lookup.repeat(4);
        [lookup.as_slice(), write, &data[..100], &lookup].concat()
    }

    #[test]
    fn requests_are_counted_at_every_split_and_never_inside_write_data() {
        let stream = three_requests();
        for split in 0..=stream.len() {
            let mut frames = Frames::default();
            let requests = frames.count(&stream[..split]).expect("the first part")
                + frames.count(&stream[split..]).expect("the second part");
            assert_eq!(requests, 3, "split at {split}");
        }
    }

    fn loopback() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").expect("a loopback listener")
    }

    fn ended<T: Default>(result: io::Result<T>) -> T {
        result
            .or_else(|error| {
                if broken(&error) {
                    Ok(T::default())
                } else {
                    Err(error)
                }
            })
            .expect("the connection")
    }

    fn length(bytes: &[u8]) -> u64 {
        u64::try_from(bytes.len()).expect("a length that fits in 64 bits")
    }

    fn forwarded(request: &[u8], reply: &[u8]) -> (Result<Totals, CensusError>, Vec<u8>, Vec<u8>) {
        let server = loopback();
        let census = loopback();
        let (stop, stopped): (PipeReader, _) = pipe().expect("a pipe");
        let server_address = server.local_addr().expect("the server address");
        let census_address = census.local_addr().expect("the census address");
        thread::scope(|scope| {
            let counted = scope.spawn(|| count(&census, server_address, stop));
            let answering = scope.spawn(|| {
                let (mut connection, _) = server.accept().expect("the forwarded connection");
                let mut received = Vec::new();
                ended(connection.read_to_end(&mut received));
                ended(connection.write_all(reply));
                received
            });
            let mut client = TcpStream::connect(census_address).expect("a connection");
            ended(client.write_all(request));
            ended(client.shutdown(Shutdown::Write));
            let mut answered = Vec::new();
            ended(client.read_to_end(&mut answered));
            drop(stopped);
            (joined(counted), joined(answering), answered)
        })
    }

    #[test]
    fn a_forwarded_connection_is_counted_once_both_directions_end() {
        let request = three_requests();
        let reply = b"three replies";
        let (totals, received, answered) = forwarded(&request, reply);
        assert_eq!(received, request);
        assert_eq!(answered, reply);
        assert_eq!(
            totals.expect("the census counts"),
            Totals {
                requests: 3,
                bytes_received: length(&request),
                bytes_sent: length(reply),
            }
        );
    }

    #[test]
    fn a_frame_the_census_cannot_read_ends_the_connection_and_fails_the_count() {
        let (totals, received, answered) = forwarded(&[0xff; 64], b"");
        assert!(received.is_empty());
        assert!(answered.is_empty());
        assert!(
            matches!(totals, Err(CensusError::Frame(_))),
            "the census returned {totals:?}"
        );
    }
}
