//! `tokio::io::split` puts the whole stream behind one mutex that both halves
//! take on every poll, so a reply being read contends with a request being
//! written on the same connection. `TcpStream` and `UnixStream` have a
//! lock-free split of their own. The owned split of `tokio-vsock` is that mutex,
//! so a vsock stream is split by duplicating its descriptor: `read(2)` and
//! `write(2)` act on the socket, not on the descriptor, so two descriptors of
//! one socket are two independent halves.

use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream, tcp, unix};
use tokio_vsock::{VsockAddr, VsockStream};

use crate::url::Endpoint;

#[derive(Debug)]
pub enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
    Vsock(VsockStream),
}

impl Stream {
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
                // The grammar's port is 16-bit and the kernel's is 32-bit. The
                // listeners of the server are constrained to the range the
                // grammar can name, so the two agree.
                VsockStream::connect(VsockAddr::new(*cid, u32::from(*port))).await?,
            )),
        }
    }

    /// `shutdown(2)` acts on the socket, not on the descriptor, so shutting this
    /// duplicate down aborts an in-flight write instead of queueing behind the
    /// task that owns the writing half. Unlike a raw descriptor number, a
    /// duplicate cannot name a recycled descriptor later.
    pub fn duplicate(&self) -> io::Result<std::os::fd::OwnedFd> {
        self.as_fd().try_clone_to_owned()
    }

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

#[derive(Debug)]
pub enum ReadHalf {
    Tcp(tcp::OwnedReadHalf),
    Unix(unix::OwnedReadHalf),
    Vsock(VsockStream),
}

#[derive(Debug)]
pub enum WriteHalf {
    Tcp(tcp::OwnedWriteHalf),
    Unix(unix::OwnedWriteHalf),
    Vsock(VsockStream),
}

impl AsFd for ReadHalf {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Tcp(reader) => reader.as_ref().as_fd(),
            Self::Unix(reader) => reader.as_ref().as_fd(),
            Self::Vsock(reader) => reader.as_fd(),
        }
    }
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
