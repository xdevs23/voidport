//! Pure arithmetic on a mode word: the masking rule ([`host_mode`]), the
//! presentation rule ([`Privileged::apply`]) and the strip rule
//! ([`PrivilegedBits::stripped`]).

use serde::{Deserialize, Serialize};

/// `S_ISUID | S_ISGID`: the bits the host backing of an unprivileged server must
/// never have, and the bits a record contains instead.
pub const PRIVILEGED_BITS: u32 = 0o6000;

const SETUID: u32 = 0o4000;

const SETGID: u32 = 0o2000;

/// Setgid without group-execute is mandatory locking, not privilege, and a write
/// does not clear it.
const GROUP_EXECUTE: u32 = 0o0010;

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct PrivilegedBits(u32);

impl PrivilegedBits {
    pub const NONE: Self = Self(0);

    #[must_use]
    pub fn of(mode: u32) -> Self {
        Self(mode & PRIVILEGED_BITS)
    }

    #[must_use]
    pub fn new(setuid: bool, setgid: bool) -> Self {
        Self((u32::from(setuid) * SETUID) | (u32::from(setgid) * SETGID))
    }

    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub fn setuid(self) -> bool {
        self.0 & SETUID != 0
    }

    #[must_use]
    pub fn setgid(self) -> bool {
        self.0 & SETGID != 0
    }

    /// The predicate of the kernel, evaluated against the mode the guest sees:
    /// setuid always goes, and setgid goes when group-execute is set. Idempotent,
    /// so forwarding the mark on every chunk of a split write is correct.
    #[must_use]
    pub fn stripped(self, mode: u32) -> Self {
        let mut left = self.0 & !SETUID;
        if mode & GROUP_EXECUTE != 0 {
            left &= !SETGID;
        }
        Self(left)
    }
}

#[must_use]
pub fn host_mode(delivered: u32) -> u32 {
    delivered & !PRIVILEGED_BITS
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Privileged {
    /// The switch is on: the recorded bits are ORed into the presented mode. A
    /// host file carrying bits presents them as they are.
    Recorded(PrivilegedBits),
    #[default]
    Masked,
}

impl Privileged {
    #[must_use]
    pub fn apply(self, host_mode: u32) -> u32 {
        match self {
            Self::Recorded(bits) => host_mode | bits.bits(),
            Self::Masked => host_mode & !PRIVILEGED_BITS,
        }
    }

    #[must_use]
    pub fn is_masked(self) -> bool {
        matches!(self, Self::Masked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_masking_rule_takes_the_privileged_bits_and_nothing_else() {
        assert_eq!(host_mode(0o6755), 0o0755);
        assert_eq!(host_mode(0o4644), 0o0644);
        assert_eq!(host_mode(0o2755), 0o0755);
        for mode in 0..=0o7777u32 {
            assert_eq!(host_mode(mode) & PRIVILEGED_BITS, 0, "{mode:o}");
            assert_eq!(host_mode(mode) & !PRIVILEGED_BITS, mode & !PRIVILEGED_BITS);
        }
    }

    #[test]
    fn a_record_holds_the_privileged_bits_of_the_mode_it_was_assigned() {
        assert_eq!(PrivilegedBits::of(0o6755).bits(), 0o6000);
        assert_eq!(PrivilegedBits::of(0o4755), PrivilegedBits::new(true, false));
        assert_eq!(PrivilegedBits::of(0o2755), PrivilegedBits::new(false, true));
        assert_eq!(PrivilegedBits::of(0o0755), PrivilegedBits::NONE);
        assert!(PrivilegedBits::NONE.is_empty());
        assert!(PrivilegedBits::of(0o4000).setuid());
        assert!(!PrivilegedBits::of(0o4000).setgid());
        assert!(PrivilegedBits::of(0o2000).setgid());
    }

    #[test]
    fn a_write_strips_setuid_always_and_setgid_only_with_group_execute() {
        let both = PrivilegedBits::of(0o6000);
        assert_eq!(both.stripped(0o6755), PrivilegedBits::NONE);
        assert_eq!(
            both.stripped(0o6745),
            PrivilegedBits::new(false, true),
            "setgid without group-execute survives a write"
        );
        assert_eq!(
            PrivilegedBits::of(0o4000).stripped(0o4644),
            PrivilegedBits::NONE
        );
        let once = both.stripped(0o6755);
        assert_eq!(once.stripped(0o6755), once);
        assert_eq!(PrivilegedBits::NONE.stripped(0o777), PrivilegedBits::NONE);
    }

    #[test]
    fn presentation_ors_the_record_in_and_masking_takes_both_kinds_away() {
        let recorded = Privileged::Recorded(PrivilegedBits::of(0o4000));
        assert_eq!(recorded.apply(0o100_755), 0o104_755);
        assert_eq!(
            Privileged::Recorded(PrivilegedBits::NONE).apply(0o102_755),
            0o102_755
        );
        assert_eq!(Privileged::Masked.apply(0o106_755), 0o100_755);
        assert!(Privileged::Masked.is_masked());
        assert!(!recorded.is_masked());
    }
}
