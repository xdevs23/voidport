//! The decisions of a voidport client session, shared by the userspace client
//! and the in-kernel client. The crate does no I/O: frames, instants and the
//! seed enter as arguments, and every outcome leaves as a value. It depends on
//! [`voidport_proto`] and `core` only.
//!
//! One monotonic deadline bounds every request stalled while the mount
//! reconnects. It wins every tie: a handshake that completes in the same
//! instant finds the window closed. The tie is decided on the instant that the
//! adapter supplies after its wait ([`Machine::woke`](reconnect::Machine::woke)).
//!
//! One reconnect task makes every transition out of Connected, and every report
//! of a connection loss goes to that task. A report contains the generation it
//! observed, and a report of a generation that the mount has replaced is
//! discarded. A probe has a token for the same reason, because cancelling a
//! task is not synchronous.
//!
//! A request is queued (never fully written), written, or answered. After a
//! re-handshake a queued request is sent, a written request is sent again only
//! if it is idempotent, and a written non-idempotent mutation fails. A queued
//! request never reached the server, because its socket is shut down before
//! anything is retried. Requests that expect no reply and releases for a dead
//! generation are dropped, because what they refer to ended with the session.
//! Nothing retains a frame: a resend re-encodes from the arguments of the
//! caller.
//!
//! A request whose connection was lost while its session lives on is not
//! replayed this way: [`pool::Pool::after_loss`] returns whether it is sent
//! again or asked about.

#![forbid(unsafe_code)]
#![no_std]

#[cfg(test)]
extern crate std;

pub mod backoff;
pub mod cache;
pub mod cleanup;
pub mod handshake;
pub mod interrupt;
pub mod metadata;
pub mod options;
pub mod owed;
pub mod pool;
pub mod probe;
pub mod reconnect;
pub mod replay;
pub mod settling;
pub mod table;
pub mod time;
pub mod window;
pub mod write;

pub use backoff::{Backoff, Schedule};
pub use handshake::{Accepted, HandshakeError, Negotiated};
pub use reconnect::{Lost, Machine, Phase, Recovery, Serve, Woke};
pub use replay::{Decision, OpenFlags, Replay, Sent, Settle};
pub use table::{Answer, Requests, Slot, Ticket};
pub use time::Instant;
pub use window::Window;
