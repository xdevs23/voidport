use voidport_proto::opcode::Opcode;
use voidport_proto::ops::file::lock_type;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookups {
    None,
    /// One, of the node the reply describes.
    One,
    /// One for each entry the reply lists.
    EveryEntry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct Owed {
    pub forget: Lookups,
    pub release: bool,
}

impl Owed {
    pub const NOTHING: Self = Self {
        forget: Lookups::None,
        release: false,
    };
    const FORGET: Self = Self {
        forget: Lookups::One,
        release: false,
    };
}

pub const fn of(opcode: Opcode) -> Owed {
    match opcode {
        Opcode::Lookup | Opcode::Mkdir | Opcode::Mknod | Opcode::Symlink | Opcode::Link => {
            Owed::FORGET
        }
        Opcode::Create => Owed {
            forget: Lookups::One,
            release: true,
        },
        Opcode::Open => Owed {
            forget: Lookups::None,
            release: true,
        },
        Opcode::Readdirplus => Owed {
            forget: Lookups::EveryEntry,
            release: false,
        },
        Opcode::Hello
        | Opcode::Forget
        | Opcode::Getattr
        | Opcode::Setattr
        | Opcode::Readlink
        | Opcode::Unlink
        | Opcode::Rmdir
        | Opcode::Rename
        | Opcode::Read
        | Opcode::Write
        | Opcode::Statfs
        | Opcode::Release
        | Opcode::Fsync
        | Opcode::Setxattr
        | Opcode::Getxattr
        | Opcode::Listxattr
        | Opcode::Removexattr
        | Opcode::Flush
        | Opcode::Getlk
        | Opcode::Setlk
        | Opcode::Subscribe
        | Opcode::Unsubscribe
        | Opcode::Outcome
        | Opcode::Retire
        | Opcode::Recalled
        | Opcode::Renew
        | Opcode::Cancel
        | Opcode::Relinquish => Owed::NOTHING,
    }
}

pub const fn setlk_leaves_lock(lock_type: u32) -> bool {
    matches!(lock_type, lock_type::READ | lock_type::WRITE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_placed_record_lock_is_given_back() {
        assert!(setlk_leaves_lock(lock_type::READ));
        assert!(setlk_leaves_lock(lock_type::WRITE));
        for placed_nothing in [lock_type::UNLOCK, u32::MAX] {
            assert!(!setlk_leaves_lock(placed_nothing), "{placed_nothing}");
        }
    }
}
