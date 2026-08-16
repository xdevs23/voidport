//! Presented permission bits.
//!
//! Presentation is UX only. Enforcement is server-side, always: a write
//! through a read-only graft fails at the server regardless of what bits were
//! displayed, because guest root is untrusted.
//!
//! v1 permission policy is passthrough, with exactly one transformation: a
//! read-only graft strips the write bits from the *presented* mode.

use super::mode::EffectiveMode;

/// The write bits a read-only graft clears, `0o222`.
pub const WRITE_BITS: u32 = 0o222;

/// The permission bits a synthesized directory presents, `0o555`.
///
/// A synthesized directory has no host backing: nothing can be created in it,
/// so it presents as traversable and readable but never writable. The bits
/// survive [`presented_mode`] unchanged in either share mode, since they carry
/// no write bits to clear.
pub const SYNTHESIZED_DIR_PERMISSIONS: u32 = 0o555;

/// The mode bits an entry presents, given the host's `st_mode` and the
/// effective share mode.
///
/// `rw` passes the host bits through; `ro` clears exactly [`WRITE_BITS`] and
/// preserves everything else, file type and set-user-id/set-group-id/sticky
/// bits included. `hidden` has no presentation: it never surfaces, which is
/// why [`EffectiveMode`] cannot express it.
#[must_use]
pub fn presented_mode(host_mode: u32, mode: EffectiveMode) -> u32 {
    if mode.is_writable() {
        host_mode
    } else {
        host_mode & !WRITE_BITS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `S_IFREG | 0o644` and `S_IFDIR | 0o755`, as the host records them.
    const REGULAR_FILE: u32 = 0o100_644;
    const DIRECTORY: u32 = 0o040_755;

    #[test]
    fn rw_presents_the_host_bits_unchanged() {
        for host_mode in [REGULAR_FILE, DIRECTORY, 0o100_777, 0o104_755, 0o100_000] {
            assert_eq!(presented_mode(host_mode, EffectiveMode::Rw), host_mode);
        }
    }

    #[test]
    fn ro_clears_exactly_the_write_bits() {
        assert_eq!(WRITE_BITS, 0o222);
        assert_eq!(presented_mode(REGULAR_FILE, EffectiveMode::Ro), 0o100_444);
        assert_eq!(presented_mode(DIRECTORY, EffectiveMode::Ro), 0o040_555);
        assert_eq!(presented_mode(0o100_777, EffectiveMode::Ro), 0o100_555);
    }

    #[test]
    fn ro_preserves_every_bit_that_is_not_a_write_bit() {
        // File type, setuid/setgid/sticky and the read/execute bits all survive.
        for host_mode in 0..=0o177_777_u32 {
            let presented = presented_mode(host_mode, EffectiveMode::Ro);
            assert_eq!(
                presented & WRITE_BITS,
                0,
                "write bits survived {host_mode:o}"
            );
            assert_eq!(
                presented & !WRITE_BITS,
                host_mode & !WRITE_BITS,
                "other bits changed for {host_mode:o}"
            );
        }
    }

    #[test]
    fn synthesized_directories_present_read_and_traverse_only() {
        assert_eq!(SYNTHESIZED_DIR_PERMISSIONS, 0o555);
        // A synthesized directory carries no write bits, so its presentation is
        // the same under either share mode.
        assert_eq!(
            presented_mode(SYNTHESIZED_DIR_PERMISSIONS, EffectiveMode::Rw),
            SYNTHESIZED_DIR_PERMISSIONS
        );
        assert_eq!(
            presented_mode(SYNTHESIZED_DIR_PERMISSIONS, EffectiveMode::Ro),
            SYNTHESIZED_DIR_PERMISSIONS
        );
    }
}
