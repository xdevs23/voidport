//! Recorded metadata: guest truth the host backing cannot hold.
//!
//! Whenever the guest expects a real filesystem to hold something the host
//! backing cannot represent — because the server's user lacks the privilege, or
//! the host would give the value a meaning it must not have there — the answer
//! is one mechanism and never a special case: the guest truth is **recorded**,
//! with its two roles split. In memory the record store is keyed by node
//! identity, which makes hard links correct by construction; on disk a
//! per-namespace sidecar persists each record against a revalidating locator,
//! so nothing can be resurrected onto an unrelated file after a reboot.
//!
//! The first instance of the class is the **privileged mode bits** — setuid and
//! setgid — and this module is the whole of it:
//!
//! * [`bits`] — the three pure rules: the host mode a create or a chmod
//!   applies, the mode a guest is presented, and what a write strips;
//! * [`store`] — the per-namespace store the registry owns, its
//!   copy-on-write table and its debounced sidecar;
//! * [`sidecar`] — the file, its bounded and injective name, and the
//!   revalidation every row passes at load.
//!
//! Enforcement of recorded meaning is always the guest kernel's, in its own
//! trust domain: the server presents bits, the guest decides what exec does
//! with them.

pub mod bits;
pub mod sidecar;
pub mod store;

pub use bits::{PRIVILEGED_BITS, Privileged, PrivilegedBits, host_mode};
pub use sidecar::{HostLocator, RecordHome, SidecarDocument};
pub use store::{Record, RecordError, RecordStore, Records, SIDECAR_CADENCE};
