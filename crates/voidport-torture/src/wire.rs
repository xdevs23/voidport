//! A data-plane client, for the one class a mount cannot express.
//!
//! # Why the lock storm does not go through a mount
//!
//! Every other class here drives real FUSE mounts, because that is the product.
//! Stacked blocking lock waiters cannot be: a POSIX record lock's owner is the
//! *process* (`fl_owner` is the caller's `files_struct`), so the guest kernel
//! gives every thread of one process the same lock owner, the server files them
//! all under one open file description, and their locks coalesce instead of
//! conflicting. One process therefore cannot stack two waiters through a mount,
//! however many threads it runs — which is exactly the reason the server has
//! per-owner descriptions in the first place.
//!
//! The storm is therefore driven where the owners are: on the wire, where one
//! connection can name as many lock owners as the design says a guest may. This
//! is a load generator, not a second client — it speaks the same
//! `voidport-proto` the product does, and it implements exactly the four
//! operations the storm needs.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use voidport::url::{Endpoint, MountUrl};
use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::frame::{FRAME_HEADER_LEN, Frame, FrameWriter, MAX_HELLO_FRAME_LEN};
use voidport_proto::message::{
    REQUEST_HEAD_LEN, RequestBody, RequestHead, ResponseBody, ResponseOutcome,
};
use voidport_proto::ops::file::{
    FileLock, OpenRequest, OpenResponse, SetlkRequest, SetlkResponse, lock_type, setlk_flags,
};
use voidport_proto::ops::handshake::{HelloReply, HelloRequest};
use voidport_proto::ops::node::{LookupRequest, LookupResponse};
use zerocopy::byteorder::little_endian::{U32, U64};

/// The node id of a session's mount root.
const ROOT: u64 = 1;

/// `O_RDWR`, as a guest sends it.
const O_RDWR: u32 = 2;

/// Whichever stream the session arrived on.
#[derive(Debug)]
enum Transport {
    Tcp(TcpStream),
    Unix(UnixStream),
    Vsock(vsock::VsockStream),
}

impl Read for Transport {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer),
            Self::Unix(stream) => stream.read(buffer),
            Self::Vsock(stream) => stream.read(buffer),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buffer),
            Self::Unix(stream) => stream.write(buffer),
            Self::Vsock(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            Self::Unix(stream) => stream.flush(),
            Self::Vsock(stream) => stream.flush(),
        }
    }
}

impl Transport {
    fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_read_timeout(Some(timeout)),
            Self::Unix(stream) => stream.set_read_timeout(Some(timeout)),
            Self::Vsock(stream) => stream.set_read_timeout(Some(timeout)),
        }
    }
}

/// One data-plane session.
#[derive(Debug)]
pub struct Session {
    stream: Transport,
    max_frame_len: u32,
    next_request_id: u64,
}

impl Session {
    /// Dials the endpoint a mount URL names and mounts its namespace.
    ///
    /// `read_timeout` bounds every read, so a storm worker can never hang for
    /// the whole run on a server that owes it an answer.
    ///
    /// # Errors
    ///
    /// Returns the connection failure, or the errno the handshake was refused
    /// with.
    pub fn mount(url: &MountUrl, read_timeout: Duration) -> anyhow::Result<Self> {
        let stream = match &url.endpoint {
            Endpoint::Tcp { host, port } => {
                let stream = TcpStream::connect((host.as_str(), *port))?;
                stream.set_nodelay(true)?;
                Transport::Tcp(stream)
            }
            Endpoint::Unix { path } => Transport::Unix(UnixStream::connect(path)?),
            Endpoint::Vsock { cid, port } => Transport::Vsock(
                vsock::VsockStream::connect_with_cid_port(*cid, u32::from(*port))?,
            ),
        };
        stream.set_read_timeout(read_timeout)?;
        let mut session = Self {
            stream,
            max_frame_len: MAX_HELLO_FRAME_LEN,
            next_request_id: 1,
        };
        session.hello(url.namespace.as_str(), &url.subpath)?;
        Ok(session)
    }

    /// Handshakes, adopting the frame bound the server announces.
    fn hello(&mut self, namespace: &str, subpath: &[u8]) -> anyhow::Result<()> {
        let namespace = namespace.as_bytes();
        let body = HelloRequest {
            protocol_version: U32::new(PROTOCOL_VERSION),
            flags: U32::ZERO,
            namespace_len: U32::new(namespace.len() as u32),
            subpath_len: U32::new(subpath.len() as u32),
            auth_len: U32::ZERO,
        };
        let mut payload = Vec::with_capacity(namespace.len() + subpath.len());
        payload.extend_from_slice(namespace);
        payload.extend_from_slice(subpath);
        let reply = self.call::<_, HelloReply>(0, &body, &payload)?;
        self.max_frame_len = reply.max_frame_len.get();
        Ok(())
    }

    /// Resolves a name under the mount root.
    ///
    /// # Errors
    ///
    /// Returns the transport failure or the errno the server answered.
    pub fn lookup(&mut self, name: &str) -> anyhow::Result<u64> {
        self.lookup_in(ROOT, name)
    }

    /// Resolves a name in a directory.
    ///
    /// # Errors
    ///
    /// Returns the transport failure or the errno the server answered.
    pub fn lookup_in(&mut self, parent: u64, name: &str) -> anyhow::Result<u64> {
        let body = LookupRequest {
            name_len: U32::new(name.len() as u32),
        };
        let reply = self.call::<_, LookupResponse>(parent, &body, name.as_bytes())?;
        Ok(reply.entry.node_id.get())
    }

    /// Opens a node read-write.
    ///
    /// # Errors
    ///
    /// Returns the transport failure or the errno the server answered.
    pub fn open(&mut self, node_id: u64) -> anyhow::Result<u64> {
        let body = OpenRequest {
            flags: U32::new(O_RDWR),
            reserved: U32::ZERO,
        };
        let reply = self.call::<_, OpenResponse>(node_id, &body, &[])?;
        Ok(reply.handle.get())
    }

    /// Sends a whole-file lock request without waiting for its reply, and
    /// returns the request id that will answer it.
    ///
    /// This is the storm: a hundred of these on one connection are a hundred
    /// waiters the server must hold at once.
    ///
    /// # Errors
    ///
    /// Returns the failure to write the frame.
    pub fn send_lock(&mut self, handle: u64, owner: u64, wait: bool) -> anyhow::Result<u64> {
        self.send(
            0,
            &SetlkRequest {
                handle: U64::new(handle),
                lock: whole_file(owner, lock_type::WRITE),
                flags: U32::new(if wait { setlk_flags::WAIT } else { 0 }),
                reserved: U32::ZERO,
            },
            &[],
        )
    }

    /// Releases an owner's whole-file lock, without waiting for the reply.
    ///
    /// # Errors
    ///
    /// Returns the failure to write the frame.
    pub fn send_unlock(&mut self, handle: u64, owner: u64) -> anyhow::Result<u64> {
        self.send(
            0,
            &SetlkRequest {
                handle: U64::new(handle),
                lock: whole_file(owner, lock_type::UNLOCK),
                flags: U32::ZERO,
                reserved: U32::ZERO,
            },
            &[],
        )
    }

    /// Reads the next lock reply: its request id and the errno it carries.
    ///
    /// # Errors
    ///
    /// Returns the transport failure, including the read timeout — which for a
    /// storm worker means the server owes it an answer it never sent.
    pub fn receive_lock(&mut self) -> anyhow::Result<(u64, i32)> {
        let bytes = self.receive()?;
        let frame = Frame::parse(&bytes, self.max_frame_len)?;
        let status = match frame.response::<SetlkResponse>()? {
            ResponseOutcome::Success(_) => 0,
            ResponseOutcome::Error(status) => status,
        };
        Ok((frame.request_id(), status))
    }

    /// Sends one request and reads its reply.
    fn call<M: RequestBody, R: ResponseBody + Copy>(
        &mut self,
        node_id: u64,
        body: &M,
        payload: &[u8],
    ) -> anyhow::Result<R> {
        let request_id = self.send(node_id, body, payload)?;
        let bytes = self.receive()?;
        let frame = Frame::parse(&bytes, self.max_frame_len)?;
        anyhow::ensure!(
            frame.request_id() == request_id,
            "a reply for request {} arrived for request {request_id}",
            frame.request_id()
        );
        match frame.response::<R>()? {
            ResponseOutcome::Success(response) => Ok(*response.body()),
            ResponseOutcome::Error(status) => {
                anyhow::bail!("the server answered {status}")
            }
        }
    }

    /// Encodes and writes one request, returning its id.
    fn send<M: RequestBody>(
        &mut self,
        node_id: u64,
        body: &M,
        payload: &[u8],
    ) -> anyhow::Result<u64> {
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        let head = RequestHead::new(node_id, 0, 0, std::process::id());
        let mut buffer =
            vec![0u8; FRAME_HEADER_LEN + REQUEST_HEAD_LEN + size_of::<M>() + payload.len()];
        let mut writer =
            FrameWriter::request(&mut buffer, self.max_frame_len, request_id, &head, body)?;
        writer.payload(payload)?;
        let frame = writer.finish()?.to_vec();
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        Ok(request_id)
    }

    /// Reads one whole frame.
    fn receive(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut header = [0u8; FRAME_HEADER_LEN];
        self.stream.read_exact(&mut header)?;
        let len = Frame::peek_len(&header, self.max_frame_len)?
            .ok_or_else(|| anyhow::anyhow!("the server closed the connection"))?;
        let mut bytes = vec![0u8; len as usize];
        bytes[..FRAME_HEADER_LEN].copy_from_slice(&header);
        self.stream.read_exact(&mut bytes[FRAME_HEADER_LEN..])?;
        Ok(bytes)
    }
}

/// A whole-file lock description for one wire owner.
fn whole_file(owner: u64, kind: u32) -> FileLock {
    FileLock {
        start: U64::ZERO,
        end: U64::new(u64::MAX),
        owner: U64::new(owner),
        pid: U32::new(std::process::id()),
        lock_type: U32::new(kind),
    }
}
