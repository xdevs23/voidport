//! Presentation is UX only: a write through a read-only graft fails at the
//! server whatever bits were displayed, because guest root is untrusted.

use super::mode::EffectiveMode;

pub const WRITE_BITS: u32 = 0o222;

/// A synthesized directory has no host backing and nothing can be created in
/// it, so the bits carry no write bits to clear.
pub const SYNTHESIZED_DIR_PERMISSIONS: u32 = 0o555;

/// `ro` clears exactly [`WRITE_BITS`] and preserves everything else. `hidden`
/// never surfaces, which is why [`EffectiveMode`] cannot express it.
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
