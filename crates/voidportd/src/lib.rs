//! voidport server library.
//!
//! The `voidportd` binary is a thin shell around this library: the policy and
//! serving logic lives here so it can be unit- and integration-tested without
//! a running server.
//!
//! The modules follow the design's layering:
//!
//! * [`rules`] — the namespace rule engine (increment 3). Pure logic: no
//!   syscalls, no I/O, no clock, everything environmental injected.
//! * [`state`] — the state file's source document, its loader, and durable
//!   persistence. The source/runtime split lives here: the document keeps what
//!   the operator wrote, and engine state is built from it.
//! * [`lockfile`] — the sidecar advisory lock both the state file and the
//!   control socket path are owned through.
//! * [`namespace`] and [`registry`] — built, immutable namespaces and the
//!   name-keyed registry that publishes them.
//! * [`socket`] — the bind/reclaim/unlink contract of a server-owned unix
//!   socket, shared by the control socket and a `unix` data listener.
//! * [`control`] — the control plane: the newline-delimited JSON listener and
//!   the serialized validate → persist → swap service.
//! * [`host`] — host filesystem I/O: fd-pinned grafts, contained `openat2`
//!   descent, presented attributes, xattrs, OFD locks.
//! * [`data`] — the data plane: listeners, sessions, node and handle tables,
//!   and the wire operations served over them.
//! * [`reclaim`] — what a drained node table gives back: the allocator settings
//!   and the debounced trim that turn "the guest forgot it" into "the host got
//!   the memory back".
//! * [`seed`] — the configuration a `voidportd share <DIR>` launch adds to the
//!   state file before serving it, applied additively and refusing collisions.
//! * [`launch`] — what such a launch tells its operator: the exact mount
//!   command per bound listener and the `voidport-ctl` line for the socket it
//!   bound, as a value the binary prints and the operator TUI will render.
//! * [`daemon`] — assembly: start, serve, shut down cleanly.
//!
//! One module is not product: [`testing`] holds the scaffolding the workspace's
//! test suites share — a daemon on a thread, a blocking control client — which
//! lives here because `tests/support` cannot cross a crate boundary.
//!
//! See `docs/DESIGN.md` for the authoritative model.

#![deny(missing_docs)]

pub mod control;
pub mod daemon;
pub mod data;
pub mod error;
pub mod host;
pub mod launch;
pub mod lockfile;
pub mod namespace;
pub mod reclaim;
pub mod registry;
pub mod rules;
pub mod seed;
pub mod share;
pub mod socket;
pub mod state;

#[doc(hidden)]
pub mod testing;
