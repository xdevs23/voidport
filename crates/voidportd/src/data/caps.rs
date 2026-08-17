//! Resource caps.
//!
//! Every cap is **opt-in** (decided 2026-08-14): a cap exists only where
//! an operator configured one, and a server that configured none refuses
//! nothing of its own accord. What remains is the machine — the process's
//! descriptor table, which the daemon opens to the OS maximum at startup — and
//! when that binds, the OS's own errno is the answer.
//!
//! Two things are bounded without an operator asking, and neither is
//! deliberately a cap. One is how many `O_PATH` node pins the server keeps
//! **cache-resident** ([`crate::data::pin`]). It refuses nothing — a node whose
//! pin the cache dropped is re-pinned on its next use, not denied — so it takes
//! nothing away from a guest; it exists because the alternative was measured
//! and fatal, a descriptor per name ever resolved exhausting the table under a
//! source-tree walk. So [`max_nodes`](Limits::max_nodes) bounds table *entries*
//! and no longer implies descriptors at all, while
//! [`max_handles`](Limits::max_handles) still does: an open handle really does
//! hold an open file for as long as the guest keeps it.
//!
//! The other is how far a client may run ahead of the server on a connection
//! nobody capped ([`crate::data::conn`]). It refuses nothing either — it is the
//! read pause below, at a number the data plane chose instead of one an
//! operator wrote — and it exists for the same kind of reason: a read loop with
//! no bound was measured under a flood of cheap requests and cost the blocking
//! pool's whole thread ceiling and a third again of the resident set
//! (2026-08-17).
//!
//! Configured, the caps come in two shapes, deliberately:
//!
//! * **In-flight requests are bounded by backpressure, not by an error.** The
//!   connection's read loop stops reading once
//!   [`max_inflight`](Limits::max_inflight) requests are being served; the
//!   socket buffer fills and the client is throttled by the transport, which is
//!   what a client's kernel already knows how to handle. This also bounds the
//!   blocking-pool usage and the reply queue, since neither can outgrow the
//!   number of requests in flight. Unconfigured, the same pause happens at the
//!   run-ahead bound above, so what a configured cap changes is the number and
//!   nothing else (see [`crate::data::conn`]).
//! * **Everything else that a cap would bound gets an errno**: nodes
//!   (`ENFILE`), handles (`EMFILE`), materialized listing entries
//!   (`EOVERFLOW`), and sessions (the excess connection is answered and
//!   closed). Each is a resource the guest asked for explicitly, so a guest
//!   error is the honest answer — but only where the operator asked for the
//!   ceiling. The numeric defaults that once shipped are gone: they twice
//!   refused a real source-tree walk the host filesystem carries without
//!   complaint, which is the failure the decision answers.
//!
//! With `auth.mode: none`, per-peer caps remain the v1 lever for a server
//! exposed to a peer it does not trust: an operator serving one trusted VM
//! configures nothing, and one serving forty configures the throttle their
//! machine can carry. The values are read at startup; changing them takes a
//! restart (v1).
//!
//! The type itself is part of the state file's schema and therefore lives with
//! the source document, in [`crate::state`] — the same way a
//! [`Listener`](crate::state::Listener) does. The data plane consumes it; it
//! never defines configuration the state layer has to reach up for.

pub use crate::state::Limits;
