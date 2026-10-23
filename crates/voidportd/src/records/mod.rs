//! The guest truth that the host backing cannot hold is recorded. In memory the
//! store is keyed by node identity, which makes hard links correct by
//! construction. On disk a per-namespace sidecar persists each record against a
//! revalidating locator, so nothing can be resurrected onto an unrelated file
//! after a reboot. Enforcement is left to the guest kernel.

pub mod bits;
pub mod sidecar;
pub mod store;

pub use bits::{PRIVILEGED_BITS, Privileged, PrivilegedBits, host_mode};
pub use sidecar::{HostLocator, RecordHome, SidecarDocument};
pub use store::{Record, RecordError, RecordStore, Records, SIDECAR_CADENCE};
