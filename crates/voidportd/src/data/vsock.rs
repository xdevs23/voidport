//! The vsock data transport.
//!
//! Vsock is the transport a VM guest reaches its host over without a network
//! stack: no interface, no route, no address anyone off the machine can name.
//! It is a byte stream like the other two, so everything above [`conn`] is
//! unchanged — what lives here is the two joints where vsock differs from tcp
//! and unix, and both come from crates, not from tokio itself.
//!
//! **Binding happens before the runtime does.** The listener contract is
//! all-or-nothing startup ([`BoundListener`](super::listener::BoundListener)),
//! which means every endpoint is bound while the process is still synchronous.
//! `tokio_vsock::VsockListener::bind` cannot do that: it registers the
//! descriptor with the runtime's reactor and therefore panics with no runtime
//! to register it in. The synchronous `vsock` crate binds instead, exactly as
//! `std::net::TcpListener` does for the tcp arm, and [`Acceptor`] hands the
//! bound descriptor to the reactor once the runtime is up.
//!
//! **A connection is split by duplicating its descriptor.** The reader task and
//! the writer task of one connection run at the same time, so the two halves
//! may not share a lock — `tokio_vsock`'s own owned split puts the stream
//! behind a mutex both halves take on every poll, which is precisely the
//! contention [`DataStream`] exists to rule out. `shutdown(2)`, `read(2)` and
//! `write(2)` act on the socket, not on the descriptor, so two
//! descriptors for one socket are two independent halves of it: [`Connection`]
//! duplicates the accepted descriptor and registers each copy separately. The
//! `vsock` crate's `From<OwnedFd>` is what makes that conversion a safe one.

use std::io;
use std::os::fd::AsFd as _;

use tokio::io::unix::AsyncFd;
use tokio_vsock::{VsockAddr, VsockStream};

use super::conn::DataStream;

/// A bound vsock listener, serving.
///
/// The bind already happened, synchronously and before any runtime existed;
/// this is that same descriptor registered with the reactor of the runtime that
/// serves it.
#[derive(Debug)]
pub struct Acceptor {
    inner: AsyncFd<vsock::VsockListener>,
}

impl Acceptor {
    /// Registers a bound listener with the current runtime's reactor.
    ///
    /// # Errors
    ///
    /// Returns the registration failure. The listener is expected to be
    /// non-blocking already — [`bind`] makes it so — because a blocking
    /// descriptor in the reactor would stall the whole runtime on one
    /// `accept(2)`.
    pub fn new(listener: vsock::VsockListener) -> io::Result<Self> {
        Ok(Self {
            inner: AsyncFd::new(listener)?,
        })
    }

    /// Accepts one connection, already split into its two halves.
    ///
    /// # Errors
    ///
    /// Returns the `accept(2)` failure, or the failure to duplicate the
    /// accepted descriptor, which means the process is out of descriptors.
    pub async fn accept(&self) -> io::Result<(Connection, VsockAddr)> {
        loop {
            let mut ready = self.inner.readable().await?;
            match ready.try_io(|listener| listener.get_ref().accept()) {
                Ok(Ok((socket, address))) => return Ok((Connection::new(socket)?, address)),
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(error),
                // The readiness was stale: `try_io` has cleared it, so the next
                // wait is a real one, not a spin.
                Err(_would_block) => continue,
            }
        }
    }
}

/// Binds a vsock listener, synchronously.
///
/// The listener is put in non-blocking mode here, not at serve time, so
/// that what [`Acceptor`] registers is already a descriptor the reactor may
/// hold.
///
/// # Errors
///
/// Returns the `bind(2)` failure — `EADDRINUSE` for a port already served on
/// this cid, `EAFNOSUPPORT` where the kernel has no vsock transport at all.
pub fn bind(cid: u32, port: u32) -> io::Result<vsock::VsockListener> {
    let listener = vsock::VsockListener::bind_with_cid_port(cid, port)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// One accepted vsock connection, held as its two halves.
///
/// It is split at accept time, not in [`DataStream::split`], because
/// duplicating a descriptor can fail and the trait's split cannot: a connection
/// that cannot be split is one the accept loop declines, with the failure
/// logged, instead of a connection served through a lock.
#[derive(Debug)]
pub struct Connection {
    reader: VsockStream,
    writer: VsockStream,
}

impl Connection {
    /// Duplicates the socket and registers both descriptors with the reactor.
    ///
    /// # Errors
    ///
    /// Returns the duplication or registration failure.
    pub fn new(socket: vsock::VsockStream) -> io::Result<Self> {
        let duplicate = vsock::VsockStream::from(socket.as_fd().try_clone_to_owned()?);
        Ok(Self {
            reader: VsockStream::new(socket)?,
            writer: VsockStream::new(duplicate)?,
        })
    }
}

impl DataStream for Connection {
    type Reader = VsockStream;
    type Writer = VsockStream;

    fn split(self) -> (Self::Reader, Self::Writer) {
        (self.reader, self.writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// The two halves of a split connection really are one socket: what is
    /// written through the writer arrives at the peer, and what the peer sends
    /// arrives at the reader — with neither half holding a lock the other
    /// takes.
    #[tokio::test]
    async fn a_connection_splits_into_two_descriptors_for_one_socket() {
        if !crate::testing::vsock::preflight() {
            return;
        }
        let port = crate::testing::vsock::free_port().expect("a free vsock port");
        let listener = bind(vsock::VMADDR_CID_ANY, port).expect("the port is free");
        let acceptor = Acceptor::new(listener).expect("the reactor takes it");

        let dialling = tokio::spawn(async move {
            VsockStream::connect(VsockAddr::new(vsock::VMADDR_CID_LOCAL, port))
                .await
                .expect("the loopback cid accepts")
        });
        let (connection, _) = acceptor.accept().await.expect("the connection arrives");
        let mut client = dialling.await.expect("the dial finishes");

        let (mut reader, mut writer) = connection.split();
        client.write_all(b"ping").await.expect("the client writes");
        let mut received = [0u8; 4];
        reader.read_exact(&mut received).await.expect("it arrives");
        assert_eq!(&received, b"ping");

        writer.write_all(b"pong").await.expect("the server writes");
        let mut answered = [0u8; 4];
        client.read_exact(&mut answered).await.expect("it arrives");
        assert_eq!(&answered, b"pong");
    }
}
