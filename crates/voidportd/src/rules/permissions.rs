//! Presented permission bits.
//!
//! Presentation is UX only. Enforcement is server-side, always: a write
//! through a read-only graft fails at the server regardless of what bits were
//! displayed, because guest root is untrusted.
//!
//! v1 permission policy is passthrough: every host entry presents the mode bits
//! it has on the host, whatever its share mode. The one fixed value is the mode
//! of a synthesized directory, which has no host entry to pass through.

/// The permission bits a synthesized directory presents, `0o555`.
///
/// A synthesized directory has no host backing: nothing can be created in it,
/// so it presents as traversable and readable but never writable.
pub const SYNTHESIZED_DIR_PERMISSIONS: u32 = 0o555;
