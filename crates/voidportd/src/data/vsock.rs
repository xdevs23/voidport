//! The listener is bound before the runtime exists, because
//! `tokio_vsock::VsockListener::bind` registers the descriptor with the reactor
//! and panics without a runtime. The synchronous `vsock` crate binds instead,
//! and [`Acceptor`] hands the descriptor to the reactor later.
//!
//! A connection is split by duplicating its descriptor, because the owned split
//! of `tokio_vsock` puts the stream behind a mutex that both halves take on
//! every poll, which [`DataStream`] exists to rule out. `shutdown(2)`,
//! `read(2)` and `write(2)` act on the socket, so two descriptors for one
//! socket are two independent halves.

use std::io;
use std::ops::RangeInclusive;
use std::os::fd::AsFd as _;

use tokio::io::unix::AsyncFd;
use tokio_vsock::{VsockAddr, VsockStream};
use voidport_control::{VSOCK_PORTS, VsockPort};

use super::conn::DataStream;
use crate::random;

#[derive(Debug)]
pub struct Acceptor {
    inner: AsyncFd<vsock::VsockListener>,
}

impl Acceptor {
    /// The listener is expected to be non-blocking already ([`bind`] makes it
    /// so), because a blocking descriptor in the reactor would stall the whole
    /// runtime on one `accept(2)`.
    pub fn new(listener: vsock::VsockListener) -> io::Result<Self> {
        Ok(Self {
            inner: AsyncFd::new(listener)?,
        })
    }

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

/// The kernel lets only a privileged process bind the ports below it.
const FIRST_ANY_PORT: u32 = 1024;

const ANY_PORTS: RangeInclusive<u32> = FIRST_ANY_PORT..=*VSOCK_PORTS.end();

/// [`VsockPort::Any`] binds a free port inside [`ANY_PORTS`], the range that a
/// mount URL accepts. The port chosen by the kernel for a vsock bind is a
/// 32-bit number, mostly above that range, so a listener on it would print a
/// mount line that no client can parse.
pub fn bind(cid: u32, port: VsockPort) -> io::Result<vsock::VsockListener> {
    let listener = match port {
        VsockPort::Any => bind_any(cid)?,
        VsockPort::Number(port) => vsock::VsockListener::bind_with_cid_port(cid, port.get())?,
    };
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// The start differs per call so that binds running at the same time do not
/// try the same ports in the same order, and so that a port released a moment
/// ago is not the first one tried by the next bind.
fn bind_any(cid: u32) -> io::Result<vsock::VsockListener> {
    let span = ANY_PORTS.end() - ANY_PORTS.start() + 1;
    let first = ANY_PORTS.start() + u32::from_le_bytes(random::bytes()?) % span;
    bind_in(cid, &ANY_PORTS, first)
}

fn search_order(ports: &RangeInclusive<u32>, first: u32) -> impl Iterator<Item = u32> {
    (first..=*ports.end()).chain(*ports.start()..first)
}

fn bind_in(cid: u32, ports: &RangeInclusive<u32>, first: u32) -> io::Result<vsock::VsockListener> {
    for port in search_order(ports, first) {
        match vsock::VsockListener::bind_with_cid_port(cid, port) {
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            bound => return bound,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "every vsock port from {} to {} is in use",
            ports.start(),
            ports.end()
        ),
    ))
}

/// Split at accept time, not in [`DataStream::split`], because duplicating a
/// descriptor can fail and the split of the trait cannot: the accept loop
/// declines a connection that cannot be split.
#[derive(Debug)]
pub struct Connection {
    reader: VsockStream,
    writer: VsockStream,
}

impl Connection {
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

    fn port_of(listener: &vsock::VsockListener) -> u32 {
        listener.local_addr().expect("a bound address").port()
    }

    #[test]
    fn a_bind_on_any_port_claims_distinct_ports_of_the_range() {
        if !voidport_test_host::vsock::preflight() {
            return;
        }
        let listeners: Vec<_> = (0..4)
            .map(|_| bind(vsock::VMADDR_CID_ANY, VsockPort::Any).expect("a free port binds"))
            .collect();
        let mut ports: Vec<u32> = listeners.iter().map(port_of).collect();
        for port in &ports {
            assert!(ANY_PORTS.contains(port), "{port}");
        }
        ports.sort_unstable();
        ports.dedup();
        assert_eq!(ports.len(), listeners.len(), "{ports:?}");
    }

    #[test]
    fn a_search_skips_a_port_in_use_and_reports_a_range_in_use() {
        if !voidport_test_host::vsock::preflight() {
            return;
        }
        let held = bind(vsock::VMADDR_CID_ANY, VsockPort::Any).expect("a free port binds");
        let taken = port_of(&held);

        let listener = bind_in(vsock::VMADDR_CID_ANY, &ANY_PORTS, taken)
            .expect("another port of the range is free");
        assert_ne!(port_of(&listener), taken);

        let error = bind_in(vsock::VMADDR_CID_ANY, &(taken..=taken), taken)
            .expect_err("the only port of the range is in use");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(
            error
                .to_string()
                .contains(&format!("from {taken} to {taken}")),
            "{error}"
        );
    }

    #[test]
    fn a_search_wraps_around_the_range() {
        let order = |first| search_order(&(10..=14), first).collect::<Vec<_>>();
        assert_eq!(order(12), [12, 13, 14, 10, 11]);
        assert_eq!(order(10), [10, 11, 12, 13, 14]);
    }

    #[tokio::test]
    async fn a_connection_splits_into_two_descriptors_for_one_socket() {
        if !voidport_test_host::vsock::preflight() {
            return;
        }
        let listener = bind(vsock::VMADDR_CID_ANY, VsockPort::Any).expect("a free port binds");
        let port = port_of(&listener);
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
