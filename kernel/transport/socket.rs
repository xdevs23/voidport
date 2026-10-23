// SPDX-License-Identifier: GPL-2.0
//! Kernel-owned stream sockets to the server: TCP to a numeric IPv4 or IPv6
//! address, or a unix stream socket named by an absolute path.
//!
//! Calls run in task context. Established I/O has no transfer or idle timer:
//! blocking calls end through task interruption, peer failure or shutdown. A
//! send that continues a frame on its way is the exception: no signal ends it,
//! so the peer receives the frame whole. The handshake's `Dialer` bounds each
//! whole connection attempt separately.
//!
//! Sockets live in the network namespace a mount was made in, which the mount
//! has a reference to for as long as it can dial, and every socket has a
//! reference of its own until it is freed.

use core::mem::{offset_of, MaybeUninit};
use core::num::{NonZeroU16, NonZeroUsize};
use core::ptr::NonNull;

use kernel::bindings;
use kernel::error::{to_result, Error};
use kernel::prelude::*;
use voidport_bindings as generated;

/// A counted reference to a network namespace, the one a mount's sockets are
/// created in.
///
/// # Invariants
///
/// `net` points to a network namespace this value has one reference to,
/// taken when it was created and given back when it is dropped.
pub struct Network {
    net: NonNull<bindings::net>,
}

// SAFETY: a namespace reference is not tied to the task that took it, and it
// is given back from whichever task drops it.
unsafe impl Send for Network {}

// SAFETY: the namespace is only handed to socket creation, which takes its
// own synchronization.
unsafe impl Sync for Network {}

impl Network {
    /// Takes a reference to the namespace `net` points to.
    ///
    /// # Safety
    ///
    /// `net` points to a live network namespace for the duration of the call,
    /// one the caller has a reference to.
    pub unsafe fn get(net: *mut bindings::net) -> Self {
        // SAFETY: the namespace is live and already referenced, per the
        // caller's contract, so its count cannot drop to zero meanwhile.
        unsafe { generated::voidport_get_net(net) };
        Self {
            // SAFETY: a pointer to a live namespace is not null.
            net: unsafe { NonNull::new_unchecked(net) },
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        // SAFETY: gives back the reference this value has, exactly once.
        unsafe { generated::voidport_put_net(self.net.as_ptr()) };
    }
}

/// The longest unix socket path an address can store, in bytes.
pub const UNIX_PATH_MAX: usize = generated::UNIX_PATH_MAX as usize;

/// Storage the size of every socket address, as the kernel's own system calls
/// hand an address to a socket family.
type Storage = bindings::__kernel_sockaddr_storage;

const SUN_PATH: usize = offset_of!(generated::sockaddr_un, sun_path);

static_assert!(bindings::AF_INET <= u16::MAX as u32);
static_assert!(bindings::AF_INET6 <= u16::MAX as u32);
static_assert!(bindings::AF_UNIX <= u16::MAX as u32);
static_assert!(size_of::<generated::sockaddr_in>() <= size_of::<Storage>());
static_assert!(align_of::<generated::sockaddr_in>() <= align_of::<Storage>());
static_assert!(size_of::<bindings::sockaddr_in6>() <= size_of::<Storage>());
static_assert!(align_of::<bindings::sockaddr_in6>() <= align_of::<Storage>());
static_assert!(align_of::<bindings::__kernel_sa_family_t>() <= align_of::<Storage>());
// The unix family terminates a path in the byte after it, which for a path of
// the full UNIX_PATH_MAX bytes lies past the end of a unix socket address.
static_assert!(SUN_PATH + UNIX_PATH_MAX < size_of::<Storage>());

/// A numeric server address, in network byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Address {
    /// An IPv4 address.
    V4([u8; 4]),
    /// An IPv6 address.
    V6([u8; 16]),
}

impl Address {
    /// Reads a numeric IPv4 or IPv6 address with the kernel's own parsers.
    /// Anything else, a host name or trailing text included, is EINVAL.
    pub fn parse(text: &[u8]) -> Result<Self> {
        let len = c_int::try_from(text.len()).map_err(|_| EINVAL)?;
        let source = text.as_ptr().cast::<c_char>();
        // The parsers stop at the first byte they cannot take; only a parse
        // that consumed every byte is the address.
        let whole = |end: *const c_char| end == source.wrapping_add(text.len());
        let mut end = core::ptr::null();
        let mut v4 = [0u8; 4];
        // SAFETY: the parser reads at most `len` bytes of `text`, writes at
        // most the four bytes of `v4` and stores a pointer into `text` in `end`.
        if unsafe { generated::in4_pton(source, len, v4.as_mut_ptr(), -1, &mut end) } == 1
            && whole(end)
        {
            return Ok(Self::V4(v4));
        }
        let mut v6 = [0u8; 16];
        // SAFETY: as above, with the sixteen bytes of `v6`.
        if unsafe { generated::in6_pton(source, len, v6.as_mut_ptr(), -1, &mut end) } == 1
            && whole(end)
        {
            return Ok(Self::V6(v6));
        }
        Err(EINVAL)
    }
}

/// An absolute unix socket path that fits a socket address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnixPath {
    bytes: [u8; UNIX_PATH_MAX],
    len: usize,
}

impl UnixPath {
    /// EINVAL for a relative path, an empty one, one with a NUL byte, or one
    /// longer than a unix socket address can store. The path is stored byte
    /// for byte, unresolved.
    pub fn new(path: &[u8]) -> Result<Self> {
        if path.first() != Some(&b'/') || path.len() > UNIX_PATH_MAX || path.contains(&0) {
            return Err(EINVAL);
        }
        let mut bytes = [0; UNIX_PATH_MAX];
        bytes[..path.len()].copy_from_slice(path);
        Ok(Self {
            bytes,
            len: path.len(),
        })
    }

    /// The path as given.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Where a mount's server is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A TCP listener.
    Tcp {
        /// Its numeric address.
        address: Address,
        /// Its port.
        port: NonZeroU16,
    },
    /// A unix stream socket, its path looked up in the root of init, PID 1,
    /// also on kernels that give kernel threads an empty root.
    Unix(UnixPath),
}

impl Endpoint {
    fn family(&self) -> u16 {
        match self {
            Self::Tcp {
                address: Address::V4(_),
                ..
            } => bindings::AF_INET as u16,
            Self::Tcp {
                address: Address::V6(_),
                ..
            } => bindings::AF_INET6 as u16,
            Self::Unix(_) => bindings::AF_UNIX as u16,
        }
    }
}

/// An endpoint's socket address, held in storage the size of every socket
/// address, and the number of its bytes the kernel reads.
///
/// # Invariants
///
/// `len` is at most the size of `storage`, and the first `len` bytes of
/// `storage` are a socket address of the family given by its first field. A
/// unix address leaves the byte after its path inside `storage`.
struct EndpointAddress {
    storage: Storage,
    len: usize,
}

impl EndpointAddress {
    fn of(endpoint: &Endpoint) -> Self {
        let mut storage: Storage = pin_init::zeroed();
        let base = (&raw mut storage).cast::<u8>();
        let len = match endpoint {
            Endpoint::Tcp {
                address: Address::V4(bytes),
                port,
            } => {
                let address = generated::sockaddr_in {
                    sin_family: endpoint.family(),
                    sin_port: port.get().to_be(),
                    sin_addr: generated::in_addr {
                        s_addr: u32::from_ne_bytes(*bytes),
                    },
                    ..pin_init::zeroed()
                };
                // SAFETY: the storage is at least as large and as aligned as
                // the address, asserted at compile time.
                unsafe { base.cast::<generated::sockaddr_in>().write(address) };
                size_of::<generated::sockaddr_in>()
            }
            Endpoint::Tcp {
                address: Address::V6(bytes),
                port,
            } => {
                let address = bindings::sockaddr_in6 {
                    sin6_family: endpoint.family(),
                    sin6_port: port.get().to_be(),
                    sin6_addr: bindings::in6_addr {
                        in6_u: bindings::in6_addr__bindgen_ty_1 { u6_addr8: *bytes },
                    },
                    ..Default::default()
                };
                // SAFETY: as above, for the IPv6 address.
                unsafe { base.cast::<bindings::sockaddr_in6>().write(address) };
                size_of::<bindings::sockaddr_in6>()
            }
            Endpoint::Unix(path) => {
                let path = path.as_bytes();
                // SAFETY: the family is the storage's aligned first field. The
                // path has at most UNIX_PATH_MAX bytes, which fit in the
                // storage from SUN_PATH on with a byte to spare, and it does
                // not overlap the local storage.
                unsafe {
                    base.cast::<bindings::__kernel_sa_family_t>()
                        .write(endpoint.family());
                    core::ptr::copy_nonoverlapping(path.as_ptr(), base.add(SUN_PATH), path.len());
                }
                // The length counts the path's bytes; the kernel terminates it.
                SUN_PATH + path.len()
            }
        };
        Self { storage, len }
    }
}

/// A kernel-owned socket created for one endpoint and not connected yet.
///
/// Connecting it is the only way to a [`Stream`], and it connects to the
/// endpoint it was created for, so a socket never meets an address of
/// another family.
pub struct Unconnected<'a> {
    stream: Stream,
    endpoint: &'a Endpoint,
}

impl<'a> Unconnected<'a> {
    /// A socket in the endpoint's family, in the network namespace `network`.
    /// EAFNOSUPPORT identifies a family this kernel does not offer.
    pub fn open(network: &Network, endpoint: &'a Endpoint) -> Result<Self> {
        let mut sock: *mut bindings::socket = core::ptr::null_mut();
        // SAFETY: the namespace is referenced by `network`; sock_create_kern
        // initializes the output pointer on success.
        to_result(unsafe {
            bindings::sock_create_kern(
                network.net.as_ptr(),
                c_int::from(endpoint.family()),
                bindings::sock_type_SOCK_STREAM as c_int,
                0,
                &mut sock,
            )
        })?;
        let stream = Stream {
            sock: NonNull::new(sock).ok_or(EINVAL)?,
        };
        // SAFETY: a kernel socket owned here, whose sock is set by creation
        // and has only its passive namespace reference yet.
        let sk = unsafe { (*stream.sock.as_ptr()).sk };
        // SAFETY: as above; this is the socket's one upgrade.
        unsafe { generated::sk_net_refcnt_upgrade(sk) };
        if matches!(endpoint, Endpoint::Tcp { .. }) {
            // A TCP socket sends every frame at once, as the userspace client
            // does: a request held back for a delayed acknowledgement would
            // stall a round trip for the length of the acknowledgement timer.
            // SAFETY: the sock of a kernel TCP socket owned here.
            unsafe { generated::tcp_sock_set_nodelay(sk) };
        }
        Ok(Self { stream, endpoint })
    }

    /// Connect in interruptible task context. A bounded attempt needs another
    /// task that can interrupt this one: shutdown alone does not terminate a
    /// connect that is still waiting for the peer.
    pub fn connect(self) -> Result<Stream> {
        let mut address = EndpointAddress::of(self.endpoint);
        let len = c_int::try_from(address.len).map_err(|_| EINVAL)?;
        let sock = self.stream.sock.as_ptr();
        let storage = &raw mut address.storage;
        // SAFETY: the socket is valid. By the address's invariant its first
        // `len` bytes are a socket address of the socket's own family inside
        // storage the kernel may write the byte after a unix path into, and
        // the kernel copies them before using them.
        to_result(unsafe {
            match self.endpoint {
                Endpoint::Tcp { .. } => bindings::kernel_connect(
                    sock,
                    storage.cast::<crate::compat::SocketAddress>(),
                    len,
                    0,
                ),
                Endpoint::Unix(_) => generated::voidport_connect_from_init_root(sock, storage, len),
            }
        })?;
        Ok(self.stream)
    }
}

/// The size of the stack buffer that bytes the reader drops are read into. It
/// is small because it is on the kernel stack of the reading task, and a
/// longer run of bytes is read through it in turns.
pub const SCRATCH_LEN: usize = 256;

/// What one receive took from the stream.
enum Received {
    Bytes(NonZeroUsize),
    /// The peer has ended its sending direction.
    EndOfStream,
}

/// A kernel-owned stream socket.
///
/// # Invariants
///
/// `sock` is a socket produced by sock_create_kern, exclusively owned here
/// and valid until Drop releases it. Its sock has an active reference to the
/// network namespace it was created in, which the sock gives back when it is
/// freed, so the namespace outlives the socket.
///
/// Creation gives a kernel socket only a passive reference to the namespace,
/// which protects the memory of the namespace but not the namespace itself:
/// once the last active reference is gone the namespace is torn down, and
/// releasing a socket afterwards accesses the tables that the teardown freed.
/// A socket is owned apart from the [`Network`] it was opened in and may
/// outlive it. A TCP sock is freed after its release, once a closed
/// connection has finished with the peer, as the TCP sockets of the kernel's
/// own network filesystems are.
pub struct Stream {
    sock: NonNull<bindings::socket>,
}

// SAFETY: the socket is not tied to the creating task; every operation takes
// its execution context from its caller.
unsafe impl Send for Stream {}

// SAFETY: the socket layer synchronizes its state. The caller serializes
// complete frames in each direction to prevent interleaved protocol bytes.
unsafe impl Sync for Stream {}

impl Stream {
    /// End established transfers, including another task's blocked I/O.
    /// The socket remains allocated until this `Stream` is dropped.
    pub fn shutdown(&self) {
        self.shut(bindings::sock_shutdown_cmd_SHUT_RDWR);
    }

    /// End the sending direction only. The peer reads an end of file after
    /// the bytes already sent, and this end still receives what the peer
    /// sends until the peer ends its own direction.
    pub fn shutdown_send(&self) {
        self.shut(bindings::sock_shutdown_cmd_SHUT_WR);
    }

    fn shut(&self, how: bindings::sock_shutdown_cmd) {
        // SAFETY: shutdown is valid concurrently with transfers on this socket.
        let _ = unsafe { bindings::kernel_sock_shutdown(self.sock.as_ptr(), how) };
    }

    /// Read and drop `len` bytes the reader will not keep. The bytes go
    /// through a stack buffer in turns, so a declared length does not size an
    /// allocation. An end of the stream before the last of them is `EPIPE`.
    pub fn discard(&self, mut len: usize) -> Result {
        while len > 0 {
            match self.receive_dropped(len, bindings::MSG_WAITALL as c_int)? {
                Received::Bytes(received) => len -= received.get(),
                Received::EndOfStream => return Err(EPIPE),
            }
        }
        Ok(())
    }

    /// Read and drop what arrives until the peer ends its sending direction.
    /// A transport error, a signal among them, ends the read first.
    pub fn discard_to_end(&self) -> Result {
        while let Received::Bytes(_) = self.receive_dropped(usize::MAX, 0)? {}
        Ok(())
    }

    /// One receive of at most `at_most` bytes into a stack buffer of
    /// [`SCRATCH_LEN`] bytes, which are dropped.
    fn receive_dropped(&self, at_most: usize, flags: c_int) -> Result<Received> {
        let mut scratch = [0u8; SCRATCH_LEN];
        self.receive(&mut scratch[..at_most.min(SCRATCH_LEN)], flags)
    }

    /// Send one complete frame under the caller's serialization lock.
    /// On any error the caller closes the connection before releasing that
    /// lock, including interruption after a positive partial send.
    pub fn send_interruptibly(&self, frame: &[u8]) -> Result<usize> {
        let mut sent = 0;
        while sent < frame.len() {
            sent += self.send(&frame[sent..], 0)?;
        }
        Ok(sent)
    }

    /// Sends all of `bytes`, which continue a frame on its way, under the
    /// caller's serialization lock, until a fatal signal arrives. Another
    /// signal that cuts the send makes the task wait for room in the socket
    /// in a sleep that only a fatal signal ends, so the peer receives the
    /// frame whole and the connection lives on. A fatal signal or an error of
    /// the socket, its shutdown among them, ends the send early, and the
    /// caller then closes the connection, whose frame cannot be completed.
    pub fn send_killably(&self, bytes: &[u8]) -> Result {
        let mut sent = 0;
        while sent < bytes.len() {
            match self.send(&bytes[sent..], 0) {
                Ok(count) => sent += count,
                Err(error) if error == ERESTARTSYS || error == EINTR => {
                    return self.send_through_signals(&bytes[sent..]);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Sends all of `bytes` with sends that never wait, and waits for room
    /// between them on the wait queue of the socket. The task is on that
    /// queue before each send, so the wakeup of room that frees up after a
    /// send that found none ends the next wait. A fatal signal ends the wait
    /// and the send with `ERESTARTSYS`.
    fn send_through_signals(&self, bytes: &[u8]) -> Result {
        let mut wait = MaybeUninit::<bindings::wait_queue_entry>::uninit();
        // SAFETY: the socket is valid, and the entry remains on this stack
        // frame until it is removed from the queue below.
        let queue =
            unsafe { generated::voidport_socket_wait_add(self.sock.as_ptr(), wait.as_mut_ptr()) };
        let mut sent = 0;
        let outcome = loop {
            if sent == bytes.len() {
                break Ok(());
            }
            match self.send(&bytes[sent..], bindings::MSG_DONTWAIT) {
                Ok(count) => sent += count,
                Err(error) if error == EAGAIN => {
                    // SAFETY: the entry is on the queue of the socket.
                    if unsafe { generated::voidport_wait_woken_killable(wait.as_mut_ptr()) } {
                        break Err(ERESTARTSYS);
                    }
                }
                Err(error) => break Err(error),
            }
        };
        // SAFETY: the entry was added to `queue` above, which the socket has
        // for as long as it is valid.
        unsafe { bindings::remove_wait_queue(queue, wait.as_mut_ptr()) };
        outcome
    }

    /// One send of the start of `chunk` with the message flags `flags`, and
    /// how many bytes of it the socket accepted.
    fn send(&self, chunk: &[u8], flags: c_uint) -> Result<usize> {
        let mut vector = bindings::kvec {
            iov_base: chunk.as_ptr().cast_mut().cast::<c_void>(),
            iov_len: chunk.len(),
        };
        let mut message = bindings::msghdr {
            msg_flags: bindings::MSG_NOSIGNAL | flags,
            ..Default::default()
        };
        // SAFETY: the socket and borrowed kernel buffer remain live for the
        // call; the iterator cannot read beyond the supplied slice.
        advance(unsafe {
            bindings::kernel_sendmsg(
                self.sock.as_ptr(),
                &mut message,
                &mut vector,
                1,
                chunk.len(),
            )
        })
    }

    /// Fill a frame region completely or return a transport error. No part
    /// of the buffer may be released before this call returns. Closure returns
    /// EPIPE whether zero or some bytes arrived; partial progress is not exposed.
    pub fn receive_exact(&self, buf: &mut [u8]) -> Result {
        let mut filled = 0;
        while filled < buf.len() {
            match self.receive(&mut buf[filled..], bindings::MSG_WAITALL as c_int)? {
                Received::Bytes(received) => filled += received.get(),
                Received::EndOfStream => return Err(EPIPE),
            }
        }
        Ok(())
    }

    fn receive(&self, buf: &mut [u8], flags: c_int) -> Result<Received> {
        let room = buf.len();
        let mut vector = bindings::kvec {
            iov_base: buf.as_mut_ptr().cast::<c_void>(),
            iov_len: room,
        };
        let mut message = bindings::msghdr::default();
        // SAFETY: the socket is valid and the writable kernel buffer is
        // exclusively borrowed for the call's entire duration.
        let received = unsafe {
            bindings::kernel_recvmsg(
                self.sock.as_ptr(),
                &mut message,
                &mut vector,
                1,
                room,
                flags,
            )
        };
        to_result(received)?;
        let received = usize::try_from(received).map_err(|_| EINVAL)?;
        Ok(NonZeroUsize::new(received).map_or(Received::EndOfStream, Received::Bytes))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: the socket is exclusively owned here, released exactly once.
        unsafe { bindings::sock_release(self.sock.as_ptr()) };
    }
}

/// Zero bytes on a stream means peer closure, not transfer progress.
fn advance(transferred: c_int) -> Result<usize> {
    if transferred < 0 {
        return Err(Error::from_errno(transferred));
    }
    if transferred == 0 {
        return Err(EPIPE);
    }
    usize::try_from(transferred).map_err(|_| EINVAL)
}
