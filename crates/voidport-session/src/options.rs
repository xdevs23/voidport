//! The kernel client reads its mount options under the names defined here, and
//! the userspace client passes a mount on to it under the same names.

use core::ffi::CStr;
use core::fmt;
use core::time::Duration;

pub const DEFAULT_CACHE_LIFETIME: Duration = Duration::from_secs(1);

pub const DEFAULT_RECONNECT_STALL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MountOption {
    /// The mount source, which the mount table shows. It is the namespace
    /// unless [`MountOption::Namespace`] is given.
    Source,
    Namespace,
    Addr,
    Port,
    Unix,
    Path,
    AttrTimeout,
    EntryTimeout,
    ReconnectStall,
    /// Shows no setuid or setgid bits, and rejects a chmod that sets one.
    NoPrivilegedBits,
    /// Reads and writes the data of every file past the page cache of the
    /// guest, apart from mappings.
    DirectIo,
    Tag,
}

impl MountOption {
    pub const ALL: [Self; 12] = [
        Self::Source,
        Self::Namespace,
        Self::Addr,
        Self::Port,
        Self::Unix,
        Self::Path,
        Self::AttrTimeout,
        Self::EntryTimeout,
        Self::ReconnectStall,
        Self::NoPrivilegedBits,
        Self::DirectIo,
        Self::Tag,
    ];

    #[must_use]
    pub const fn name(self) -> &'static CStr {
        match self {
            Self::Source => c"source",
            Self::Namespace => c"namespace",
            Self::Addr => c"addr",
            Self::Port => c"port",
            Self::Unix => c"unix",
            Self::Path => c"path",
            Self::AttrTimeout => c"attr_timeout",
            Self::EntryTimeout => c"entry_timeout",
            Self::ReconnectStall => c"reconnect_stall",
            Self::NoPrivilegedBits => c"no_privileged_bits",
            Self::DirectIo => c"direct_io",
            Self::Tag => c"tag",
        }
    }

    #[must_use]
    pub fn named(name: &[u8]) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|option| option.name().to_bytes() == name)
    }

    #[must_use]
    pub const fn value_kind(self) -> ValueKind {
        match self {
            Self::Source | Self::Namespace | Self::Path => ValueKind::Bytes,
            Self::Port => ValueKind::U32,
            Self::Addr
            | Self::Unix
            | Self::AttrTimeout
            | Self::EntryTimeout
            | Self::ReconnectStall
            | Self::Tag => ValueKind::String,
            Self::NoPrivilegedBits | Self::DirectIo => ValueKind::Flag,
        }
    }

    #[must_use]
    pub const fn selects_the_share(self) -> bool {
        matches!(
            self,
            Self::Source
                | Self::Namespace
                | Self::Addr
                | Self::Port
                | Self::Unix
                | Self::Tag
                | Self::Path
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueKind {
    /// Bytes of any length: a string, or a blob for a value longer than a
    /// string can be.
    Bytes,
    String,
    U32,
    Flag,
}

/// A duration as decimal seconds to the nanosecond, the form in which the
/// kernel client reads a duration option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seconds(pub Duration);

impl fmt::Display for Seconds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:09}", self.0.as_secs(), self.0.subsec_nanos())
    }
}

#[cfg(test)]
mod tests {
    use std::string::ToString as _;

    use super::*;

    #[test]
    fn every_option_is_found_by_its_name() {
        for option in MountOption::ALL {
            assert_eq!(MountOption::named(option.name().to_bytes()), Some(option));
        }
        assert_eq!(MountOption::named(b"ro"), None);
    }

    #[test]
    fn seconds_are_written_to_the_nanosecond() {
        assert_eq!(
            Seconds(Duration::from_millis(1500)).to_string(),
            "1.500000000"
        );
        assert_eq!(Seconds(Duration::from_nanos(1)).to_string(), "0.000000001");
        assert_eq!(Seconds(DEFAULT_RECONNECT_STALL).to_string(), "5.000000000");
    }
}
