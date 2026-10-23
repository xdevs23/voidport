// SPDX-License-Identifier: GPL-2.0
//! The error codes this module needs that the kernel crate does not name.

use kernel::bindings;
use kernel::error::Error;

fn of(errno: u32) -> Error {
    Error::from_errno(-(errno as i32))
}

/// The transport is absent, or a socket has been shut down.
pub fn enotconn() -> Error {
    of(bindings::ENOTCONN)
}

/// The peer reset the connection.
pub fn econnreset() -> Error {
    of(bindings::ECONNRESET)
}

/// The peer is not speaking the protocol.
pub fn eproto() -> Error {
    of(bindings::EPROTO)
}

/// Refreshed attributes describe a different kind than the cached inode's.
pub fn estale() -> Error {
    of(bindings::ESTALE)
}

/// An extended attribute does not exist.
pub fn enodata() -> Error {
    of(bindings::ENODATA)
}

/// No record lock can be placed the way the caller asks.
pub fn enolck() -> Error {
    of(bindings::ENOLCK)
}

/// A name does not fit.
pub fn enametoolong() -> Error {
    of(bindings::ENAMETOOLONG)
}

/// The address family is not supported by this kernel.
pub fn eafnosupport() -> Error {
    of(bindings::EAFNOSUPPORT)
}

/// A read whose caller left while its reply streamed into the caller's pages:
/// the reader completes it.
pub fn einprogress() -> Error {
    of(bindings::EINPROGRESS)
}
