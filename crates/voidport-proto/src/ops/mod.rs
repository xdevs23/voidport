//! Per-operation message bodies, grouped by the part of the filesystem they
//! act on.
//!
//! Each operation has a request body and — except `forget`, which is answered
//! by nothing at all — a response body. Fields follow FUSE semantics adapted
//! to this framing; this rustdoc is the field-level reference and the golden
//! byte-vector tests are the ABI lock.
//!
//! [`share`] is the exception to the request/response shape: it holds the
//! server-initiated notifications of the share subscription, which answer
//! nothing and are never answered. [`subscribe`] holds the two requests that
//! turn that stream on and off.

pub mod dir;
pub mod file;
pub mod handshake;
pub mod node;
pub mod share;
pub mod subscribe;
pub mod xattr;
