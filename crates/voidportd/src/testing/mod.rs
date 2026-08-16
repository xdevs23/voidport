//! Scaffolding the workspace's test suites share.
//!
//! Three suites drive a real server — this crate's own integration tests, the
//! client's end-to-end suite, and the operator CLI's — and each needs the same
//! thing to do it: a daemon started exactly as its binary starts it, running on
//! its own thread with its own runtime, plus a blocking client for the control
//! socket. An integration test's `tests/support` cannot be imported by another
//! crate, so the runner layer lives here, in the library, where all three can
//! reach it.
//!
//! What deliberately does **not** live here: each suite's host tree and state
//! file. Those are the fixtures the assertions are written against — the data
//! tests assert exact listings — and merging them into one superset tree would
//! couple every suite to every other suite's fixture. Only the machinery is
//! shared, never the subject matter.
//!
//! Hidden from the documentation because it is scaffolding, not product.

mod control;
mod scratch;
mod server;
pub mod vsock;

pub use control::ControlClient;
pub use scratch::{Scratch, create_directory, scratch_root};
pub use server::{
    RunningServer, daemon_config, invoking_environment, open_descriptors, pinned_environment,
};
