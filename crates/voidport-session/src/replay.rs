//! The replay discipline and its per-operation table apply to a request whose
//! session ended. A request whose connection was lost while the session lives
//! on is settled by [`settle`] instead, because the server can report what
//! became of it.

use voidport_proto::opcode::Opcode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replay {
    /// Idempotent: applying it twice is applying it once, so it is re-sent
    /// whether or not it reached the server.
    Idempotent,
    /// A mutation that must not be applied twice. A *written* attempt may
    /// already have taken effect, so it fails; a *queued* one provably did not,
    /// so it is re-sent.
    Once,
    /// Its referent, a handle or a node, died with the session, so a lost
    /// attempt is moot and is reported as a success.
    Moot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    /// The complete frame reached the socket. The server may have received,
    /// dispatched and applied it, so only an idempotent request may be sent
    /// again.
    Written,
    /// Nothing, or only part of the frame, reached a socket that is now shut
    /// down. The server never dispatches a frame it has not received whole, so
    /// this request provably did not take effect and may be sent as it is.
    Queued,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Resend,
    Fail,
    Moot,
}

impl Replay {
    #[must_use]
    pub fn decide(self, sent: Sent) -> Decision {
        match (self, sent) {
            (Self::Moot, _) => Decision::Moot,
            (_, Sent::Queued) | (Self::Idempotent, Sent::Written) => Decision::Resend,
            (Self::Once, Sent::Written) => Decision::Fail,
        }
    }
}

/// By name, because the numeric values differ between architectures. An
/// adapter maps its own constants onto these.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenFlags(u8);

impl OpenFlags {
    pub const NONE: Self = Self(0);
    pub const CREATE: Self = Self(1 << 0);
    pub const EXCLUSIVE: Self = Self(1 << 1);
    pub const TRUNCATE: Self = Self(1 << 2);
    /// Not a mutation: opening a file for appending twice leaves the file as one
    /// open would. The writes through such a handle must not be repeated, and
    /// [`Opcode::Write`] is classified accordingly.
    pub const APPEND: Self = Self(1 << 3);

    /// A plain open may be repeated after a reconnect. One that creates, fails
    /// on an existing file, or truncates cannot, because a second application
    /// would see or make a different state.
    pub const MUTATING: Self = Self(Self::CREATE.0 | Self::EXCLUSIVE.0 | Self::TRUNCATE.0);

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

/// `open` matters for [`Opcode::Open`] alone. `flush` and `fsync` are
/// [`Replay::Once`] because they act on server-side state that a client may not
/// re-apply for a guest. `hello` is never replayed on a dead connection,
/// because a session is re-established by dialling.
#[must_use]
pub fn of(opcode: Opcode, open: OpenFlags) -> Replay {
    match opcode {
        Opcode::Lookup
        | Opcode::Getattr
        | Opcode::Readlink
        | Opcode::Read
        | Opcode::Statfs
        | Opcode::Readdirplus
        | Opcode::Getxattr
        | Opcode::Listxattr
        | Opcode::Getlk
        // A `Subscribe` on an already-subscribed session returns a fresh
        // snapshot on the same stream, and an `Unsubscribe` on a session that
        // never subscribed succeeds: both are safe to send again.
        | Opcode::Subscribe
        | Opcode::Unsubscribe
        // Asking twice gives the same answer, and retiring twice is answered
        // the same way.
        | Opcode::Outcome
        | Opcode::Retire
        // A renewal sent again renews the window from the moment it was sent
        // again, in whichever session answers it.
        | Opcode::Renew => Replay::Idempotent,
        Opcode::Open => {
            if open.intersects(OpenFlags::MUTATING) {
                Replay::Once
            } else {
                Replay::Idempotent
            }
        }
        // A recall refers to a lease of the session that sent it, a cancel to
        // a request of that session, and a relinquish to all of its leases,
        // which ended with it.
        Opcode::Release
        | Opcode::Forget
        | Opcode::Recalled
        | Opcode::Cancel
        | Opcode::Relinquish => Replay::Moot,
        Opcode::Hello
        | Opcode::Setattr
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
        | Opcode::Flush
        | Opcode::Setxattr
        | Opcode::Removexattr
        | Opcode::Setlk => Replay::Once,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settle {
    Resend,
    /// Ask the server what became of it with an outcome request, on another
    /// connection of the same session, and take the answer: the reply the
    /// server kept, "applied" for a forget, or "not started", which sends it
    /// again.
    Ask,
}

/// How a request whose connection was lost while its session lives on is
/// settled. The requests that change nothing on the server are sent again.
/// Every mutation, a release, a forget, a lookup, an open and a listing are
/// asked about: a lookup, an open and a listing count a lookup or make a
/// handle on the server, and sending one again while the session lives would
/// count it twice. Asking about a request that never
/// reached the server is answered "not started", so asking is right whether or
/// not any of it was written.
///
/// `hello` never reaches this question: a connection is joined by dialling,
/// never by resending its handshake.
#[must_use]
pub fn settle(opcode: Opcode) -> Settle {
    match opcode {
        Opcode::Getattr
        | Opcode::Readlink
        | Opcode::Read
        | Opcode::Statfs
        | Opcode::Getxattr
        | Opcode::Listxattr
        | Opcode::Getlk
        | Opcode::Subscribe
        | Opcode::Unsubscribe
        | Opcode::Outcome
        | Opcode::Retire
        // A recall received twice receives the same reply, a cancel of a
        // request that no longer waits does nothing, and leases given up
        // remain given up.
        | Opcode::Recalled
        | Opcode::Cancel
        | Opcode::Relinquish
        | Opcode::Renew => Settle::Resend,
        Opcode::Hello
        | Opcode::Lookup
        | Opcode::Open
        | Opcode::Readdirplus
        | Opcode::Release
        | Opcode::Forget
        | Opcode::Setattr
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
        | Opcode::Flush
        | Opcode::Setxattr
        | Opcode::Removexattr
        | Opcode::Setlk => Settle::Ask,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lost_connection_of_a_live_session_is_settled_by_asking() {
        for resend in [
            Opcode::Getattr,
            Opcode::Readlink,
            Opcode::Read,
            Opcode::Statfs,
            Opcode::Getxattr,
            Opcode::Listxattr,
            Opcode::Getlk,
            Opcode::Subscribe,
            Opcode::Unsubscribe,
            Opcode::Outcome,
            Opcode::Retire,
            Opcode::Renew,
        ] {
            assert_eq!(settle(resend), Settle::Resend, "{resend}");
            assert_eq!(of(resend, OpenFlags::NONE), Replay::Idempotent, "{resend}");
        }
        for asked in [Opcode::Lookup, Opcode::Open, Opcode::Readdirplus] {
            assert_eq!(settle(asked), Settle::Ask, "{asked}");
            assert_eq!(of(asked, OpenFlags::NONE), Replay::Idempotent, "{asked}");
        }
        for asked in [Opcode::Release, Opcode::Forget] {
            assert_eq!(settle(asked), Settle::Ask, "{asked}");
            assert_eq!(of(asked, OpenFlags::NONE), Replay::Moot, "{asked}");
        }
        for resent in [Opcode::Recalled, Opcode::Cancel, Opcode::Relinquish] {
            assert_eq!(settle(resent), Settle::Resend, "{resent}");
            assert_eq!(of(resent, OpenFlags::NONE), Replay::Moot, "{resent}");
        }
        for opcode in Opcode::ALL {
            if of(opcode, OpenFlags::NONE) == Replay::Once {
                assert_eq!(settle(opcode), Settle::Ask, "every mutation: {opcode}");
            }
        }
    }

    #[test]
    fn the_replay_discipline_is_the_contracts() {
        assert_eq!(
            Replay::Idempotent.decide(Sent::Queued),
            Decision::Resend,
            "a queued idempotent request is sent as it is"
        );
        assert_eq!(
            Replay::Once.decide(Sent::Queued),
            Decision::Resend,
            "a queued mutation cannot have been applied, so it is sent as it is"
        );
        assert_eq!(Replay::Idempotent.decide(Sent::Written), Decision::Resend);
        assert_eq!(
            Replay::Once.decide(Sent::Written),
            Decision::Fail,
            "a written mutation must not risk a second application"
        );
        assert_eq!(Replay::Moot.decide(Sent::Written), Decision::Moot);
        assert_eq!(Replay::Moot.decide(Sent::Queued), Decision::Moot);
    }

    #[test]
    fn only_an_open_that_creates_or_truncates_is_a_mutation() {
        assert_eq!(of(Opcode::Open, OpenFlags::NONE), Replay::Idempotent);
        assert_eq!(
            of(Opcode::Open, OpenFlags::APPEND),
            Replay::Idempotent,
            "appending is a property of the handle, not a change to the file"
        );
        for mutating in [OpenFlags::CREATE, OpenFlags::EXCLUSIVE, OpenFlags::TRUNCATE] {
            assert_eq!(
                of(Opcode::Open, OpenFlags::APPEND.union(mutating)),
                Replay::Once,
                "{mutating:?} makes an open a mutation"
            );
        }
    }

    #[test]
    fn the_reads_are_idempotent_and_the_mutations_are_not() {
        for idempotent in [
            Opcode::Lookup,
            Opcode::Getattr,
            Opcode::Readlink,
            Opcode::Read,
            Opcode::Statfs,
            Opcode::Readdirplus,
            Opcode::Getxattr,
            Opcode::Listxattr,
            Opcode::Getlk,
            Opcode::Subscribe,
            Opcode::Unsubscribe,
            Opcode::Outcome,
            Opcode::Retire,
            Opcode::Renew,
        ] {
            assert_eq!(
                of(idempotent, OpenFlags::NONE),
                Replay::Idempotent,
                "{idempotent}"
            );
        }
        for once in [
            Opcode::Hello,
            Opcode::Setattr,
            Opcode::Symlink,
            Opcode::Mkdir,
            Opcode::Mknod,
            Opcode::Unlink,
            Opcode::Rmdir,
            Opcode::Rename,
            Opcode::Link,
            Opcode::Create,
            Opcode::Write,
            // A durability barrier and a lock-owner drop that the guest was told
            // nothing about are not ones a client may re-issue on its own.
            Opcode::Fsync,
            Opcode::Flush,
            Opcode::Setxattr,
            Opcode::Removexattr,
            Opcode::Setlk,
        ] {
            assert_eq!(of(once, OpenFlags::NONE), Replay::Once, "{once}");
        }
        for moot in [Opcode::Release, Opcode::Forget] {
            assert_eq!(of(moot, OpenFlags::NONE), Replay::Moot, "{moot}");
        }
    }
}
