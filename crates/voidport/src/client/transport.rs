//! The byte stream a mount runs over.
//!
//! The framing is transport-agnostic by design, so everything above this
//! module sees one stream type and never asks which endpoint it came from.
//!
//! **A connection is split by the transport, not by a lock.** The reading half
//! and the writing half of a mount's socket are driven by different tasks at
//! the same time, and `tokio::io::split` implements that by putting the whole
//! stream behind one `std::sync::Mutex` that both halves take on every poll —
//! so a reply being read contends with a request being written on the same
//! connection. `TcpStream` and `UnixStream` each own a lock-free split, and
//! [`Stream::split`] is the enum's: one match, then two halves that never meet
//! again.
//!
//! Vsock has no such split of its own — `tokio-vsock`'s owned one is the mutex
//! this module exists to avoid — so it is split by **duplicating the socket's
//! descriptor**: `read(2)` and `write(2)` act on the socket, not on the
//! descriptor, so two descriptors for one socket are two independent halves of
//! it. That is the same mechanism [`Stream::duplicate`] already relies on for
//! the death path, and the server splits its side of a vsock connection the
//! same way.

use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream, tcp, unix};
use tokio_vsock::{VsockAddr, VsockStream};

use crate::url::Endpoint;

/// A connected data-plane stream.
#[derive(Debug)]
pub enum Stream {
    /// A tcp connection.
    Tcp(TcpStream),
    /// A unix socket connection.
    Unix(UnixStream),
    /// A vsock connection.
    Vsock(VsockStream),
}

impl Stream {
    /// Dials an endpoint.
    ///
    /// # Errors
    ///
    /// Returns the connection failure, which the mount reports with the
    /// endpoint it was dialling.
    pub async fn connect(endpoint: &Endpoint) -> io::Result<Self> {
        match endpoint {
            Endpoint::Tcp { host, port } => {
                let stream = TcpStream::connect((host.as_str(), *port)).await?;
                // As the server does on its side: a request held back by Nagle
                // waiting for a delayed ACK turns a microsecond round trip into
                // forty milliseconds.
                stream.set_nodelay(true)?;
                Ok(Self::Tcp(stream))
            }
            Endpoint::Unix { path } => Ok(Self::Unix(UnixStream::connect(path).await?)),
            Endpoint::Vsock { cid, port } => Ok(Self::Vsock(
                // The grammar's port is 16-bit; the kernel's is 32-bit, and the
                // server's listeners are constrained to the range the grammar
                // can name so that the two always agree.
                VsockStream::connect(VsockAddr::new(*cid, u32::from(*port))).await?,
            )),
        }
    }

    /// A second descriptor for the same socket.
    ///
    /// The connection is split into a reading and a writing half, and the
    /// writing half is owned by whichever task is putting a frame on the wire.
    /// A duplicate descriptor is how the death path reaches the socket without
    /// waiting for that task: `shutdown(2)` acts on the socket, not on the
    /// descriptor, so shutting this one down aborts an in-flight write instead
    /// of queueing behind it. It is a duplicate, not a raw number,
    /// precisely so it cannot name a recycled descriptor later.
    ///
    /// # Errors
    ///
    /// Returns the duplication failure, which means the process is out of
    /// descriptors.
    pub fn duplicate(&self) -> io::Result<std::os::fd::OwnedFd> {
        self.as_fd().try_clone_to_owned()
    }

    /// Splits the stream into its reading and its writing half.
    ///
    /// Each transport's own `into_split` is used where there is one, so the two
    /// halves share no lock: the reader task and whichever caller holds the
    /// writer never contend, which is what keeps the read side's cost the
    /// socket's and not the connection's write traffic. Vsock has no such split
    /// — its crate's owned one is a mutex — so it is split by duplicating the
    /// descriptor, which is the only arm that can fail.
    ///
    /// # Errors
    ///
    /// Returns the duplication failure, which means the process is out of
    /// descriptors.
    pub fn split(self) -> io::Result<(ReadHalf, WriteHalf)> {
        match self {
            Self::Tcp(stream) => {
                let (reader, writer) = stream.into_split();
                Ok((ReadHalf::Tcp(reader), WriteHalf::Tcp(writer)))
            }
            Self::Unix(stream) => {
                let (reader, writer) = stream.into_split();
                Ok((ReadHalf::Unix(reader), WriteHalf::Unix(writer)))
            }
            Self::Vsock(stream) => {
                let duplicate = vsock::VsockStream::from(stream.as_fd().try_clone_to_owned()?);
                Ok((
                    ReadHalf::Vsock(stream),
                    WriteHalf::Vsock(VsockStream::new(duplicate)?),
                ))
            }
        }
    }
}

/// The reading half of a connected data-plane stream.
#[derive(Debug)]
pub enum ReadHalf {
    /// A tcp connection's read half.
    Tcp(tcp::OwnedReadHalf),
    /// A unix socket connection's read half.
    Unix(unix::OwnedReadHalf),
    /// One of a vsock connection's two descriptors, read from only.
    Vsock(VsockStream),
}

/// The writing half of a connected data-plane stream.
#[derive(Debug)]
pub enum WriteHalf {
    /// A tcp connection's write half.
    Tcp(tcp::OwnedWriteHalf),
    /// A unix socket connection's write half.
    Unix(unix::OwnedWriteHalf),
    /// The other of a vsock connection's two descriptors, written to only.
    Vsock(VsockStream),
}

impl AsyncRead for ReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(reader) => Pin::new(reader).poll_read(context, buffer),
            Self::Unix(reader) => Pin::new(reader).poll_read(context, buffer),
            Self::Vsock(reader) => Pin::new(reader).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for WriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(writer) => Pin::new(writer).poll_write(context, buffer),
            Self::Unix(writer) => Pin::new(writer).poll_write(context, buffer),
            Self::Vsock(writer) => Pin::new(writer).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(writer) => Pin::new(writer).poll_flush(context),
            Self::Unix(writer) => Pin::new(writer).poll_flush(context),
            Self::Vsock(writer) => Pin::new(writer).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(writer) => Pin::new(writer).poll_shutdown(context),
            Self::Unix(writer) => Pin::new(writer).poll_shutdown(context),
            Self::Vsock(writer) => Pin::new(writer).poll_shutdown(context),
        }
    }
}

impl AsFd for Stream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Tcp(stream) => stream.as_fd(),
            Self::Unix(stream) => stream.as_fd(),
            Self::Vsock(stream) => stream.as_fd(),
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Unix(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Vsock(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Unix(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Vsock(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(context),
            Self::Unix(stream) => Pin::new(stream).poll_flush(context),
            Self::Vsock(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Vsock(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}
