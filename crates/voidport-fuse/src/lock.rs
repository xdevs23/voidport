use linux_raw_sys::general as uapi;
use zerocopy::byteorder::native_endian::{U32, U64};

use crate::abi;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockType {
    Read,
    Write,
    /// No lock, `F_UNLCK`: a release, or a test that found no conflict.
    Unlock,
}

impl LockType {
    fn decode(raw: u32) -> Option<Self> {
        match raw {
            uapi::F_RDLCK => Some(Self::Read),
            uapi::F_WRLCK => Some(Self::Write),
            uapi::F_UNLCK => Some(Self::Unlock),
            _ => None,
        }
    }

    fn encode(self) -> u32 {
        match self {
            Self::Read => uapi::F_RDLCK,
            Self::Write => uapi::F_WRLCK,
            Self::Unlock => uapi::F_UNLCK,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileLock {
    /// The first byte.
    pub start: u64,
    /// The last byte.
    pub end: u64,
    pub lock_type: LockType,
    pub pid: u32,
}

impl FileLock {
    pub(crate) fn decode(lock: &abi::FileLock) -> Option<Self> {
        Some(Self {
            start: lock.start.get(),
            end: lock.end.get(),
            lock_type: LockType::decode(lock.lock_type.get())?,
            pid: lock.pid.get(),
        })
    }

    pub(crate) fn encode(&self) -> abi::FileLock {
        abi::FileLock {
            start: U64::new(self.start),
            end: U64::new(self.end),
            lock_type: U32::new(self.lock_type.encode()),
            pid: U32::new(self.pid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lock_decodes_to_what_it_encodes_from() {
        for lock_type in [LockType::Read, LockType::Write, LockType::Unlock] {
            let lock = FileLock {
                start: 3,
                end: 9,
                lock_type,
                pid: 77,
            };
            assert_eq!(FileLock::decode(&lock.encode()), Some(lock));
        }
    }

    #[test]
    fn a_lock_type_linux_does_not_have_does_not_decode() {
        let mut lock = FileLock {
            start: 0,
            end: 0,
            lock_type: LockType::Read,
            pid: 1,
        }
        .encode();
        lock.lock_type = U32::new(3);
        assert_eq!(FileLock::decode(&lock), None);
    }
}
