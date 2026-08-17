//! The privileged mode bits, and the three rules that govern them.
//!
//! Everything here is pure arithmetic on a mode word — no syscalls, no state —
//! so the rules the design states once are stated once in code too:
//!
//! * [`host_mode`] is the **masking rule**: the mode a chmod or a create
//!   applies to the host backing never carries a privileged bit, on either
//!   path;
//! * [`Privileged::apply`] is the **presentation rule**: the recorded bits are
//!   ORed into what the guest is shown, or masked away where the namespace
//!   switch is off — recorded and host-real alike;
//! * [`PrivilegedBits::stripped`] is the **strip rule**: what a write by a
//!   caller without the file-mode privilege leaves behind, which is the
//!   kernel's own predicate and is fully evaluable from the mode.

use serde::{Deserialize, Serialize};

/// `S_ISUID | S_ISGID`: the bits an unprivileged server's host backing must
/// never carry, and the bits a record holds instead.
pub const PRIVILEGED_BITS: u32 = 0o6000;

/// `S_ISUID`.
const SETUID: u32 = 0o4000;

/// `S_ISGID`.
const SETGID: u32 = 0o2000;

/// `S_IXGRP`, the bit the kernel's setgid-strip predicate reads.
///
/// Setgid without group-execute is mandatory locking, not privilege, and a
/// write does not clear it — which is why the predicate is a predicate and not
/// "clear both".
const GROUP_EXECUTE: u32 = 0o0010;

/// The privileged bits of one mode word.
///
/// A record holds exactly this and nothing else: the truth the host backing
/// cannot carry.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct PrivilegedBits(u32);

impl PrivilegedBits {
    /// No privileged bits at all — the value that means "no record".
    pub const NONE: Self = Self(0);

    /// The privileged bits a mode word carries.
    #[must_use]
    pub fn of(mode: u32) -> Self {
        Self(mode & PRIVILEGED_BITS)
    }

    /// The bits named individually, as the sidecar spells them.
    #[must_use]
    pub fn new(setuid: bool, setgid: bool) -> Self {
        Self((u32::from(setuid) * SETUID) | (u32::from(setgid) * SETGID))
    }

    /// The bits, as a mode word fragment.
    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }

    /// Whether there is nothing to record.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether `S_ISUID` is set.
    #[must_use]
    pub fn setuid(self) -> bool {
        self.0 & SETUID != 0
    }

    /// Whether `S_ISGID` is set.
    #[must_use]
    pub fn setgid(self) -> bool {
        self.0 & SETGID != 0
    }

    /// What is left after a write by a caller without the file-mode privilege.
    ///
    /// The kernel's own predicate, evaluated against the mode the guest sees:
    /// setuid always goes, setgid goes when group-execute is set. Idempotent,
    /// which is what makes forwarding the mark on every chunk of a split write
    /// correct, and not merely harmless.
    #[must_use]
    pub fn stripped(self, mode: u32) -> Self {
        let mut left = self.0 & !SETUID;
        if mode & GROUP_EXECUTE != 0 {
            left &= !SETGID;
        }
        Self(left)
    }
}

/// The mode a chmod or a create applies to the host backing.
///
/// The one shared masking rule, used by both paths: whatever the guest
/// delivered, the host file never gains a privileged bit the server's own user
/// set.
#[must_use]
pub fn host_mode(delivered: u32) -> u32 {
    delivered & !PRIVILEGED_BITS
}

/// How one operation presents privileged bits.
///
/// Resolved once per operation, from the namespace switch and the record store,
/// and then applied at the attribute funnel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Privileged {
    /// The switch is on: these are the bits the record holds, ORed into the
    /// presented mode. A host file genuinely carrying bits presents them as-is,
    /// which is what makes the OR the whole of the merge.
    Recorded(PrivilegedBits),
    /// The switch is off: privileged bits are masked out of the presented
    /// mode, recorded and host-real alike.
    #[default]
    Masked,
}

impl Privileged {
    /// The presented mode.
    #[must_use]
    pub fn apply(self, host_mode: u32) -> u32 {
        match self {
            Self::Recorded(bits) => host_mode | bits.bits(),
            Self::Masked => host_mode & !PRIVILEGED_BITS,
        }
    }

    /// Whether presentation is masked, which is also what decides that a
    /// delivered mode neither records nor deletes.
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
        // Every other bit survives, sticky included.
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

    /// The kernel's own write-strip predicate: setuid always, setgid only where
    /// group-execute is set — setgid without it is mandatory locking.
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
        // Idempotent, which is what makes every chunk of a split write safe.
        let once = both.stripped(0o6755);
        assert_eq!(once.stripped(0o6755), once);
        assert_eq!(PrivilegedBits::NONE.stripped(0o777), PrivilegedBits::NONE);
    }

    #[test]
    fn presentation_ors_the_record_in_and_masking_takes_both_kinds_away() {
        let recorded = Privileged::Recorded(PrivilegedBits::of(0o4000));
        assert_eq!(recorded.apply(0o100_755), 0o104_755);
        // A host file genuinely carrying a bit presents it as-is.
        assert_eq!(
            Privileged::Recorded(PrivilegedBits::NONE).apply(0o102_755),
            0o102_755
        );
        // Masked takes the recorded and the host-real bits alike.
        assert_eq!(Privileged::Masked.apply(0o106_755), 0o100_755);
        assert!(Privileged::Masked.is_masked());
        assert!(!recorded.is_masked());
    }
}
