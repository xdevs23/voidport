//! Share modes.
//!
//! A rule states a [`ShareMode`]; an admitted entry carries an
//! [`EffectiveMode`]. The two types are deliberately distinct: `hidden` is a
//! first-class rule mode that never surfaces to a guest, so it cannot appear
//! in a resolution result, in a directory context, or in a node key.

/// The share mode a rule states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShareMode {
    /// Read-write: the entry is admitted and writable.
    Rw,
    /// Read-only: the entry is admitted and presents its host permission
    /// bits; writes fail server-side.
    Ro,
    /// Hidden: the entry does not resolve, does not stat, does not appear in
    /// a listing, and nothing beneath it is reachable through it.
    Hidden,
}

impl ShareMode {
    /// The mode an admitted entry would carry, or `None` for [`Self::Hidden`].
    #[must_use]
    pub fn effective(self) -> Option<EffectiveMode> {
        match self {
            Self::Rw => Some(EffectiveMode::Rw),
            Self::Ro => Some(EffectiveMode::Ro),
            Self::Hidden => None,
        }
    }

    /// Whether the mode admits the entry at all.
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
    /// Writes are permitted.
    Rw,
    /// Writes are refused by the server, whatever the presented bits say.
    Ro,
}

impl EffectiveMode {
    /// Whether writes through this entry are permitted.
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
