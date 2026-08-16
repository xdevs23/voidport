//! The voidport torture harness.
//!
//! # What it is for
//!
//! The design's robustness mandate is a statement about brutal conditions: if
//! every operation the system has runs at once, in every shape, for hours, the
//! software may consume every resource it has — and it may not starve, stall,
//! delay or wedge. That is not a benchmark question, and it cannot be answered
//! by a suite of tests that each drive one thing at a time. It is answered by a
//! load generator that drives *all* of them concurrently for as long as
//! somebody is willing to wait, with the invariants asserted the whole time.
//!
//! # Why this is not a `voidport-bench` scenario
//!
//! `voidport-bench` is deliberately ignorant of voidport: it is handed a
//! directory and measures what that directory does, which is exactly what makes
//! one command comparable across a tmpfs, a voidport mount and a 9p mount. It
//! measures one workload per invocation, under controlled conditions, and
//! reports a number.
//!
//! This harness needs the opposite of all three. It must *make* and destroy
//! mounts (mount/unmount cycling, multi-mount contention), so it knows about
//! mount URLs; it must see the server's own accounting to tell a busy session
//! from a leaking one, so it knows about the control plane; and it must speak
//! the data plane directly for the one class a single process cannot express
//! through a mount (see [`wire`]). Its output is not a number but a verdict.
//! Folding that into the benchmark harness would cost the benchmark exactly the
//! property it exists for. So: a sibling binary, sharing the workspace and
//! nothing else.
//!
//! # Shape
//!
//! [`run`] is the whole engine, and the smoke variant in this crate's own test
//! suite is the same function with a small [`Plan`]. Around it:
//!
//! * [`metrics`] — what is counted, lock-free, per class;
//! * [`workload`] — what each class does to the filesystem, one operation at a
//!   time;
//! * [`invariant`] — what the harness refuses to see, checked once a second;
//! * [`resource`] — what the server is holding, sampled from `/proc` and the
//!   control socket;
//! * [`mounts`] — the mounts themselves, and the leak probes the teardown ends
//!   with.
#![deny(missing_docs)]

pub mod invariant;
pub mod metrics;
pub mod mounts;
pub mod resource;
pub mod run;
pub mod wire;
pub mod workload;

pub use invariant::{Ceilings, Violation};
pub use metrics::Class;
pub use resource::Probe;
pub use run::{Plan, Report, run};
pub use workload::Seed;
