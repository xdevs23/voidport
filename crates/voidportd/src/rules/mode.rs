//! A rule sets a [`ShareMode`], and an admitted entry has an
//! [`EffectiveMode`]. `hidden` is a rule mode that never surfaces to a guest, so
//! it cannot appear in a resolution result, in a directory context or in a node
//! key.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShareMode {
    Rw,
    /// Read-only: the entry is admitted; writes fail server-side and the
    /// presented permission bits lose their write bits.
    Ro,
    /// Hidden: the entry does not resolve, does not stat, does not appear in
    /// a listing, and nothing beneath it is reachable through it.
    Hidden,
}

impl ShareMode {
    /// The mode an admitted entry would have, or `None` for [`Self::Hidden`].
    #[must_use]
    pub fn effective(self) -> Option<EffectiveMode> {
        match self {
            Self::Rw => Some(EffectiveMode::Rw),
            Self::Ro => Some(EffectiveMode::Ro),
            Self::Hidden => None,
        }
    }

    #[must_use]
    pub fn admits(self) -> bool {
        self.effective().is_some()
    }
}

impl From<EffectiveMode> for ShareMode {
    fn from(mode: EffectiveMode) -> Self {
        match mode {
            EffectiveMode::Rw => Self::Rw,
            EffectiveMode::Ro => Self::Ro,
        }
    }
}

/// The share mode of an entry that resolution admitted.
///
/// This is the mode enforcement uses and the mode a session node id is keyed
/// by: the policy of the path that admitted the entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EffectiveMode {
    Rw,
    /// Writes are refused by the server, whatever the presented bits say.
    Ro,
}

impl EffectiveMode {
    #[must_use]
    pub fn is_writable(self) -> bool {
        matches!(self, Self::Rw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_has_no_effective_mode() {
        assert_eq!(ShareMode::Rw.effective(), Some(EffectiveMode::Rw));
        assert_eq!(ShareMode::Ro.effective(), Some(EffectiveMode::Ro));
        assert_eq!(ShareMode::Hidden.effective(), None);
        assert!(ShareMode::Rw.admits());
        assert!(!ShareMode::Hidden.admits());
    }

    #[test]
    fn effective_modes_round_trip_and_report_writability() {
        assert_eq!(ShareMode::from(EffectiveMode::Rw), ShareMode::Rw);
        assert_eq!(ShareMode::from(EffectiveMode::Ro), ShareMode::Ro);
        assert!(EffectiveMode::Rw.is_writable());
        assert!(!EffectiveMode::Ro.is_writable());
    }
}
