//! Path components.
//!
//! A [`Name`] is one component of a namespace path: a directory entry name as
//! the host filesystem stores it — a non-empty byte string containing neither
//! a separator nor a NUL, and never `.` or `..`.
//!
//! Names are bytes, not text. Host directory entries are arbitrary byte
//! strings and the wire protocol carries them as such, so the engine must not
//! force them through UTF-8. Rule paths do come from UTF-8 configuration, and
//! parsing one simply yields the same byte components.

use std::fmt;

/// One component of a namespace path.
///
/// The rule engine assumes lookup components are already single names — the
/// server rejects anything containing `/`, `.` or `..` before the engine sees
/// it (design: "Rule engine contract"). [`Name::new`] is where that rejection
/// is implemented, so the assumption is enforced by the type, not
/// merely documented.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(Vec<u8>);

impl Name {
    /// Validates a byte string as a path component.
    ///
    /// # Errors
    ///
    /// Returns a [`NameError`] for the empty string, for `.` and `..`, and for
    /// components containing a `/` separator or a NUL byte (neither can occur
    /// in a host directory entry, and both would change the meaning of a path
    /// handed to `openat2`).
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, NameError> {
        let bytes = bytes.into();
        match bytes.as_slice() {
            b"" => return Err(NameError::Empty),
            b"." => return Err(NameError::CurrentDir),
            b".." => return Err(NameError::ParentDir),
            _ => {}
        }
        if bytes.contains(&b'/') {
            return Err(NameError::Separator);
        }
        if bytes.contains(&0) {
            return Err(NameError::Nul);
        }
        Ok(Self(bytes))
    }

    /// The component's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Name {
    /// Lossily, for diagnostics: a component need not be valid UTF-8.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

impl fmt::Debug for Name {
    /// Quoted and lossy, so test failures read like paths, not byte
    /// arrays.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(&self.0))
    }
}

/// Why a byte string is not a valid path component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameError {
    /// The component was empty.
    #[error("a path component must not be empty")]
    Empty,
    /// The component contained a `/`.
    #[error("a path component must not contain a `/` separator")]
    Separator,
    /// The component was `.`.
    #[error("`.` is not a valid path component")]
    CurrentDir,
    /// The component was `..`.
    #[error("`..` is not a valid path component")]
    ParentDir,
    /// The component contained a NUL byte.
    #[error("a path component must not contain a NUL byte")]
    Nul,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_components_are_accepted() {
        assert_eq!(Name::new("foo").unwrap().as_bytes(), b"foo");
        assert_eq!(Name::new("...").unwrap().as_bytes(), b"...");
        assert_eq!(
            Name::new(vec![0xff, 0xfe]).unwrap().as_bytes(),
            &[0xff, 0xfe]
        );
    }

    #[test]
    fn invalid_components_are_rejected() {
        assert_eq!(Name::new(""), Err(NameError::Empty));
        assert_eq!(Name::new("."), Err(NameError::CurrentDir));
        assert_eq!(Name::new(".."), Err(NameError::ParentDir));
        assert_eq!(Name::new("a/b"), Err(NameError::Separator));
        assert_eq!(Name::new(vec![b'a', 0]), Err(NameError::Nul));
    }

    #[test]
    fn non_utf8_names_display_lossily() {
        let name = Name::new(vec![b'a', 0xff]).unwrap();
        assert_eq!(name.to_string(), "a\u{fffd}");
        assert_eq!(format!("{name:?}"), "\"a\u{fffd}\"");
    }
}
