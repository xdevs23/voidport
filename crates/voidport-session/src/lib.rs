//! The session core: one authority for what a voidport client decides, for
//! every client that speaks the protocol.
//!
//! This crate holds the decisions a session is made of — handshake validation,
//! request-id allocation and request tracking, the replay discipline and the
//! per-operation classification it consumes, the reconnect state machine with
//! its monotonic stall deadline, and the backoff schedule. It holds no I/O.
//! The userspace FUSE client and the in-kernel client are **adapters**: they
//! own sockets, tasks and wakeups, they supply instants and a seed, and they
//! perform the verdicts this crate returns. Neither of them decides any of the
//! above, which is what stops the resilience contract from existing twice.
//!
//! ## A synchronous decision machine
//!
//! Frames, instants and the seed enter as arguments; every outcome leaves as a
//! value — what to write, whom to wake, when to wake next, what to fail with.
//! Nothing here reads a clock, touches a socket, allocates, or owns a string:
//! the tables live in storage the adapter hands over at construction
//! ([`Requests::new`](table::Requests::new)), the error classes are enums, and
//! prose reasons are the adapter's business. The dependency set is the wire
//! crate's and nothing more: [`voidport_proto`] and `core`.
//!
//! ## The mount is a state machine
//!
//! * **Connected** — a connection is installed and requests flow.
//! * **Reconnecting** — the server broke away. Newly arriving callbacks *stall*
//!   here, bounded by **one monotonic deadline** shared by every stalled
//!   request — not by a per-request timer, so a request that arrives late in
//!   the window is not given a fresh window of its own. That deadline wins
//!   every tie: a stall that reaches it fails, and a handshake that completes
//!   in the same instant finds the window already closed, so no amount of
//!   scheduler delay can serve a request past its window. The tie is decided
//!   here, on the instant the adapter supplies after its wait
//!   ([`Machine::woke`](reconnect::Machine::woke)); an adapter never compares
//!   times itself.
//! * **Degraded** — the deadline passed. Stalled and subsequent requests fail
//!   **immediately**, and the probe keeps running on a slower backoff.
//! * **Closed** — the mount was torn down. Nothing reconnects.
//!
//! One reconnect task owns every transition out of Connected. Death
//! observations coalesce onto it: whoever notices first reports the
//! *generation* it observed, and a report naming a generation the mount has
//! already replaced is discarded — that is what stops a dying connection from
//! poisoning its own replacement. A completed handshake **is** the probe, and
//! installing it returns the mount to Connected. The probe carries a token for
//! the same reason a connection carries a generation: cancelling a task is not
//! synchronous, so a superseded attempt is identified and discarded, not
//! allowed to transition the mount that replaced it.
//!
//! ## Replay discipline
//!
//! A request is *queued* (never fully written), *written*, or *answered*. The
//! linearization point is the write itself, and the task that performed the
//! write is the one that asks its ticket what became of it
//! ([`Ticket::decide`](table::Ticket::decide)). After a re-handshake a
//! queued request is simply sent — it provably never reached the server, whose
//! socket is shut down before anything is retried. A written-but-unanswered
//! request is re-sent only if it is idempotent; a written-but-unanswered
//! non-idempotent mutation fails instead of risking double application.
//! No-response requests and releases addressing a dead generation are dropped
//! as moot: their referents died with the session. Which operation is which is
//! [`replay::of`], the protocol's own table.
//!
//! **Replay retention is the request table, and payload bytes stay with the
//! caller.** Nothing here retains a frame: a resend re-encodes from the
//! awaiting caller's own arguments under the current connection's bound, and a
//! bound that shrank below the request fails it. What is retained is
//! per-request replay state and nothing else: the opcode and the id in the
//! table, the replay class and the lifecycle position on the ticket the table
//! issues, and the generation the table itself belongs to.
//!
//! ## Fixed capacity, and a full table waits
//!
//! The table is sized once, at construction, from the mount's own bounded
//! engines, and it neither grows nor overflows. A caller that finds it full is
//! parked by the adapter until a slot frees — the same observable class as a
//! caller queueing at the single writer over a back-pressuring socket. It is
//! never an error.

#![no_std]

#[cfg(test)]
extern crate std;

pub mod backoff;
pub mod handshake;
pub mod reconnect;
pub mod replay;
pub mod table;
pub mod time;

pub use backoff::{Backoff, Schedule};
pub use handshake::{HandshakeError, Negotiated};
pub use reconnect::{Lost, Machine, Phase, Recovery, Serve, Woke};
pub use replay::{Decision, OpenFlags, Replay, Sent};
pub use table::{Answer, Requests, Slot, Ticket};
pub use time::Instant;
