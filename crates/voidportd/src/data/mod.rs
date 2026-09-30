//! The data plane: sessions, host I/O, and the wire operations over them.
//!
//! One connection is one session is one mount. The plane is built from the
//! bottom up:
//!
//! * [`caps`] — the resource caps, and the shape of the backpressure;
//! * [`ids`] — server-global, generation-disjoint node and handle ids, so an id
//!   a client still holds after a reconnect names nothing, not something
//!   else;
//! * [`ino`] — server-global inode-number allocation, so guest-visible identity
//!   is stable across sessions and hardlink aliases agree;
//! * [`pin`] — the server-global descriptor cache a node's `O_PATH` pin is a
//!   slot in, and the identity-verified re-pin that makes evicting one safe;
//! * [`node`] and [`handle`] — the per-session tables: what a node id names,
//!   and what a handle holds;
//! * [`locks`] — the record locks a session holds, one set per host file,
//!   shared by every handle on that file;
//! * [`session`] — a mount: the namespace it serves by name, the lookups it
//!   resolves against the registry's current snapshot of it, and the listings
//!   it materializes;
//! * [`ops`] — one function per wire operation, all of them pure functions of a
//!   session and a parsed request;
//! * [`conn`] — framing, the handshake, and the reader/writer pair that runs
//!   requests concurrently and answers out of order;
//! * [`listener`], [`vsock`] and [`server`] — the transports and the state they
//!   share.
//!
//! Every host name the server resolves is resolved by [`crate::host`], under
//! its containment discipline; the policy deciding what may be reached lives in
//! [`crate::rules`]. What the operations below issue directly are the syscalls
//! that take a descriptor already obtained that way — they can name nothing the
//! server was not already holding. This module tree is what joins the two to a
//! socket.

pub mod caps;
pub mod conn;
pub mod handle;
pub mod ids;
pub mod ino;
pub mod listener;
pub mod locks;
pub mod node;
pub mod ops;
pub mod pin;
pub mod server;
pub mod session;
pub mod sessions;
pub mod subscribe;
pub mod vsock;

pub use caps::Limits;
pub use conn::MAX_FRAME_LEN;
pub use listener::{BoundListener, DataListeners, Endpoint, ListenerError, Transport};
pub use pin::{DescriptorBudget, NodePin};
pub use server::{DataPlane, Identity};
pub use session::{Peer, Session};
pub use sessions::Sessions;
pub use subscribe::{NotificationQueue, Subscribers};
