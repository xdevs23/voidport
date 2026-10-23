//! Names are bytes, not text: host directory entries are arbitrary byte strings
//! and the wire protocol sends them as such, so the engine does not force them
//! through UTF-8.

use std::fmt;
use std::sync::Arc;

/// The rule engine assumes lookup components are single names. [`Name::new`]
/// rejects anything containing `/`, `.` or `..`, so the type enforces it. A clone
/// shares the bytes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(Arc<[u8]>);

impl Name {
    /// # Errors
    ///
    /// Returns a [`NameError`] for the empty string, for `.` and `..`, and for
    /// components containing a `/` separator or a NUL byte, which would change
    /// the meaning of a path handed to `openat2`.
    pub fn new(bytes: impl AsRef<[u8]>) -> Result<Self, NameError> {
        let bytes = bytes.as_ref();
        match bytes {
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
        Ok(Self(Arc::from(bytes)))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Name {
    /// Lossily, because a component need not be valid UTF-8.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(&self.0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameError {
    #[error("a path component must not be empty")]
    Empty,
    #[error("a path component must not contain a `/` separator")]
    Separator,
    #[error("`.` is not a valid path component")]
    CurrentDir,
    #[error("`..` is not a valid path component")]
    ParentDir,
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
