//! What an interrupt does to a request that was sent, by what the server may
//! still do with the request once the caller of the request receives `EINTR`.

use voidport_proto::opcode::Opcode;

use crate::owed::setlk_leaves_lock;
use crate::replay::OpenFlags;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptClass {
    /// The request is sent and completes as if no interrupt came.
    NeverCutShort,
    CutShort(Ending),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    /// The caller gets `EINTR` at once, and a cancel ends the request if it
    /// waits in the server. Applying the request changes nothing the kernel
    /// sees, and what a later reply counts on the server is given back.
    AnswerNow,
    /// A cancel ends the request, unapplied, if it waits in the server, and the
    /// caller waits for the answer otherwise. The server may have applied the
    /// change already, which nothing undoes, so only the answer shows whether
    /// it took effect.
    CancelAndWait,
}

/// `open` matters for [`Opcode::Open`] alone. A lock request that
/// [`setlk_cut_short`] refuses is sent without the interrupt.
#[must_use]
pub fn of(opcode: Opcode, open: OpenFlags) -> InterruptClass {
    match opcode {
        Opcode::Lookup
        | Opcode::Getattr
        | Opcode::Readlink
        | Opcode::Read
        | Opcode::Statfs
        | Opcode::Readdirplus
        | Opcode::Getxattr
        | Opcode::Listxattr
        | Opcode::Getlk => InterruptClass::CutShort(Ending::AnswerNow),
        Opcode::Open => {
            if open.intersects(OpenFlags::MUTATING) {
                InterruptClass::CutShort(Ending::CancelAndWait)
            } else {
                InterruptClass::CutShort(Ending::AnswerNow)
            }
        }
        Opcode::Setattr
        | Opcode::Symlink
        | Opcode::Mkdir
        | Opcode::Mknod
        | Opcode::Unlink
        | Opcode::Rmdir
        | Opcode::Rename
        | Opcode::Link
        | Opcode::Create
        | Opcode::Write
        | Opcode::Fsync
        | Opcode::Setxattr
        | Opcode::Removexattr
        | Opcode::Setlk => InterruptClass::CutShort(Ending::CancelAndWait),
        // The kernel has closed the descriptor already: a flush cut short
        // leaves the locks of that descriptor in the server, and a release
        // cut short leaves its handle open there.
        Opcode::Flush | Opcode::Release => InterruptClass::NeverCutShort,
        // No program waits for these: the client sends them without a request
        // of the kernel.
        Opcode::Hello
        | Opcode::Forget
        | Opcode::Subscribe
        | Opcode::Unsubscribe
        | Opcode::Outcome
        | Opcode::Retire
        | Opcode::Recalled
        | Opcode::Renew
        | Opcode::Cancel
        | Opcode::Relinquish => InterruptClass::NeverCutShort,
    }
}

/// An unlock is never cut short, so a program interrupted while it releases a
/// lock leaves no lock behind.
#[must_use]
pub const fn setlk_cut_short(lock_type: u32) -> bool {
    setlk_leaves_lock(lock_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_open_waits_for_its_answer_only_when_it_changes_the_file() {
        assert_eq!(
            of(Opcode::Open, OpenFlags::APPEND),
            InterruptClass::CutShort(Ending::AnswerNow)
        );
        for changing in [OpenFlags::CREATE, OpenFlags::TRUNCATE] {
            assert_eq!(
                of(Opcode::Open, changing.union(OpenFlags::APPEND)),
                InterruptClass::CutShort(Ending::CancelAndWait)
            );
        }
    }
}
