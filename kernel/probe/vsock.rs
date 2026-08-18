// SPDX-License-Identifier: GPL-2.0

//! A kernel-owned AF_VSOCK stream socket.
//!
//! The kernel's `net` abstraction covers PHY devices only, so there is no Rust
//! socket type to reach for and this module is that abstraction for the surface
//! the voidport client needs. It is built over the kernel's generated bindings
//! alone — no C helper file — because every call it makes is a plain exported
//! function the bindings crate already declares.
//!
//! This is the module's only unsafe boundary: nothing above it holds a raw
//! kernel pointer, and the socket's release is owned by [`Stream`]'s drop, so
//! no failure path can leak one.
//!
//! Every call here may sleep, so a caller must run in task context. Every wait
//! on the peer is bounded, so a caller always gets an answer: a peer that
//! accepts and then stops moving bytes ends the transfer with `ETIMEDOUT`.

use core::ptr::NonNull;

use kernel::bindings;
use kernel::error::{to_result, Error};
use kernel::prelude::*;
use kernel::time::{delay::fsleep, Delta};

/// How long one transfer waits for a peer that is moving no bytes.
///
/// The socket's own receive timeout would be the place for this, and the
/// generated bindings reach neither it nor a setter for it: `struct sock` is
/// opaque there. So each transfer is asked for without blocking and the wait
/// is this file's, which is what keeps a stalled peer from holding the caller
/// for the machine's uptime.
const TRANSFER_TIMEOUT: Delta = Delta::from_secs(30);

/// How long a transfer that would block waits before asking again.
const TRANSFER_POLL: Delta = Delta::from_millis(1);

/// The address family value, narrowed once so no call site casts.
const FAMILY: u16 = bindings::AF_VSOCK as u16;
static_assert!(bindings::AF_VSOCK <= u16::MAX as u32);

/// `struct sockaddr_vm`, mirrored from `include/uapi/linux/vm_sockets.h`.
///
/// The kernel generates its bindings from a fixed header list that does not
/// include `vm_sockets.h`, and an out-of-tree module cannot add to that list.
/// The layout mirrored here is a UAPI one, which the kernel holds fixed for its
/// userspace ABI. The assertions below say what a mirror can say: the offsets
/// and the alignment hold a careless edit of this file to the layout it claims,
/// and the size is compared against the kernel's own `struct sockaddr`, which
/// every socket address is sized against.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrVm {
    family: u16,
    reserved1: u16,
    port: u32,
    cid: u32,
    flags: u8,
    zero: [u8; 3],
}

static_assert!(size_of::<SockaddrVm>() == size_of::<bindings::sockaddr>());
static_assert!(size_of::<SockaddrVm>() == 16);
static_assert!(align_of::<SockaddrVm>() == 4);
static_assert!(core::mem::offset_of!(SockaddrVm, family) == 0);
static_assert!(core::mem::offset_of!(SockaddrVm, reserved1) == 2);
static_assert!(core::mem::offset_of!(SockaddrVm, port) == 4);
static_assert!(core::mem::offset_of!(SockaddrVm, cid) == 8);
static_assert!(core::mem::offset_of!(SockaddrVm, flags) == 12);

impl SockaddrVm {
    /// The address of `port` on `cid`.
    fn new(cid: u32, port: u32) -> Self {
        Self {
            family: FAMILY,
            reserved1: 0,
            port,
            cid,
            flags: 0,
            zero: [0; 3],
        }
    }
}

/// A kernel-owned vsock stream socket.
///
/// # Invariants
///
/// `sock` points at a `struct socket` produced by `sock_create_kern` that this
/// value exclusively owns, and it stays valid until this value is dropped.
pub(crate) struct Stream {
    sock: NonNull<bindings::socket>,
}

// SAFETY: a `struct socket` is not bound to the task that created it --
// `sock_create_kern` records nothing of `current`, and every operation takes
// its context from whichever task calls it -- so moving the sole owner of one
// between tasks is sound. `Sync` is deliberately not claimed: concurrent use of
// one connection is the caller's to serialize, which is what the wire's
// linearization point asks for anyway.
unsafe impl Send for Stream {}

impl Stream {
    /// Opens a kernel-owned socket of the vsock family.
    pub(crate) fn open() -> Result<Self> {
        let mut sock: *mut bindings::socket = core::ptr::null_mut();
        // SAFETY: `sock_create_kern` is family-agnostic and writes the new
        // socket through its last argument; `init_net` is the kernel's own
        // network namespace and outlives every module.
        to_result(unsafe {
            bindings::sock_create_kern(
                &raw mut bindings::init_net,
                c_int::from(FAMILY),
                bindings::sock_type_SOCK_STREAM as c_int,
                0,
                &mut sock,
            )
        })?;
        // INVARIANT: a successful `sock_create_kern` wrote a valid socket, and
        // this is the only reference to it. The null check restates that
        // contract instead of trusting it; it is not a path the socket layer
        // can take.
        Ok(Self {
            sock: NonNull::new(sock).ok_or(EINVAL)?,
        })
    }

    /// Connects the socket to `cid:port`.
    ///
    /// A socket that fails to connect is released by its owner's drop, so no
    /// error path here leaks one. This wait carries no deadline of its own:
    /// the vsock family bounds its connect by the socket's connect timeout,
    /// which is a live default the family sets when it creates the socket.
    pub(crate) fn connect(&self, cid: u32, port: u32) -> Result {
        let mut address = SockaddrVm::new(cid, port);
        // SAFETY: by the type invariant the socket is valid; `address` is a
        // live, correctly sized socket address of the family the socket was
        // created with, and `kernel_connect` only reads it.
        to_result(unsafe {
            bindings::kernel_connect(
                self.sock.as_ptr(),
                core::ptr::from_mut(&mut address).cast::<bindings::sockaddr_unsized>(),
                size_of::<SockaddrVm>() as c_int,
                0,
            )
        })
    }

    /// Writes every byte of `frame`.
    ///
    /// A stream send may take fewer bytes than offered, and the wire's
    /// linearization point is the complete frame on the socket, so a partial
    /// send is completed here before the call returns.
    pub(crate) fn send_all(&self, frame: &[u8]) -> Result<usize> {
        let mut sent = 0;
        while sent < frame.len() {
            let chunk = &frame[sent..];
            let held = chunk.len();
            let mut vector = bindings::kvec {
                iov_base: chunk.as_ptr().cast_mut().cast::<c_void>(),
                iov_len: held,
            };
            let mut message = bindings::msghdr {
                msg_flags: bindings::MSG_NOSIGNAL | bindings::MSG_DONTWAIT,
                ..Default::default()
            };
            sent += awaited(|| {
                // SAFETY: by the type invariant the socket is valid; the vector
                // describes `chunk`, which is borrowed for the whole call, and
                // `kernel_sendmsg` wraps it in a kernel-space iterator, so no
                // userspace address space is implied.
                unsafe {
                    bindings::kernel_sendmsg(self.sock.as_ptr(), &mut message, &mut vector, 1, held)
                }
            })?;
        }
        Ok(sent)
    }

    /// Fills `buf` completely.
    ///
    /// `MSG_WAITALL` is what a framed protocol wants, and it still returns
    /// short when the wait is cut off, so the fill is completed here.
    pub(crate) fn receive_exact(&self, buf: &mut [u8]) -> Result {
        let wanted = buf.len();
        let mut filled = 0;
        while filled < wanted {
            let chunk = &mut buf[filled..];
            let room = chunk.len();
            let mut vector = bindings::kvec {
                iov_base: chunk.as_mut_ptr().cast::<c_void>(),
                iov_len: room,
            };
            let mut message = bindings::msghdr::default();
            filled += awaited(|| {
                // SAFETY: by the type invariant the socket is valid; the vector
                // describes `chunk`, which is borrowed mutably for the whole
                // call, and `kernel_recvmsg` writes at most `chunk.len()` bytes
                // into it.
                unsafe {
                    bindings::kernel_recvmsg(
                        self.sock.as_ptr(),
                        &mut message,
                        &mut vector,
                        1,
                        room,
                        (bindings::MSG_WAITALL | bindings::MSG_DONTWAIT) as c_int,
                    )
                }
            })?;
        }
        Ok(())
    }
}

/// Repeats one transfer until it moves bytes, fails, or the deadline passes.
///
/// The socket layer answers a transfer that would block with `EAGAIN`, which
/// is the only answer this waits out: everything else is the peer's or the
/// socket's, and belongs to the caller immediately.
fn awaited(mut transfer: impl FnMut() -> c_int) -> Result<usize> {
    for _ in 0..(TRANSFER_TIMEOUT / TRANSFER_POLL) {
        let moved = transfer();
        if moved != EAGAIN.to_errno() {
            return advance(moved);
        }
        fsleep(TRANSFER_POLL);
    }
    Err(ETIMEDOUT)
}

impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: by the type invariant this value exclusively owns a socket
        // from `sock_create_kern`, and drop runs once.
        unsafe { bindings::sock_release(self.sock.as_ptr()) };
    }
}

/// Turns one transfer's return value into the number of bytes it moved.
///
/// A negative value is the errno the socket layer answered; zero on a stream
/// is the peer's close, which no half of a frame may be split by.
fn advance(transferred: c_int) -> Result<usize> {
    if transferred < 0 {
        return Err(Error::from_errno(transferred));
    }
    if transferred == 0 {
        return Err(EPIPE);
    }
    usize::try_from(transferred).map_err(|_| EINVAL)
}
