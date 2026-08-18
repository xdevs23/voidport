//! The replay discipline, and the per-operation table it consumes.
//!
//! Two questions, answered in one place because neither is answerable without
//! the other: **may this operation be applied twice?** ([`of`]) and **what
//! becomes of an attempt that got as far as this?** ([`Replay::decide`]).
//!
//! The classification is protocol semantics, not I/O, so it lives here beside
//! the discipline instead of at each client's call sites: a client re-deriving
//! one classification by hand would be a second copy of the contract, and the
//! two copies would disagree the first time an opcode joined the wire.

use voidport_proto::opcode::Opcode;

/// What the replay discipline may do with a request whose connection died.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replay {
    /// Idempotent: applying it twice is applying it once, so it is re-sent
    /// whether or not it reached the server.
    Idempotent,
    /// A mutation that must not be applied twice. A *written* attempt may
    /// already have taken effect, so it fails; a *queued* one provably did not,
    /// so it is re-sent.
    Once,
    /// Its referent — a handle, a node — died with the session, so a lost
    /// attempt is moot and answers as though it had succeeded.
    Moot,
}

/// How far a request got before its connection died: the replay contract's
/// linearization point, recorded where the frame is actually written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    /// The complete frame reached the socket. The server may have received it,
    /// dispatched it, and applied it — so only an idempotent request may be
    /// sent again.
    Written,
    /// Nothing, or only part of the frame, reached a socket that is now shut
    /// down. The server never dispatches a frame it has not received whole, so
    /// this request provably did not take effect and may be sent as it is.
    Queued,
}

/// What becomes of one lost attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Send it again on the replacement connection.
    Resend,
    /// Fail it: it may already have been applied.
    Fail,
    /// Answer as though it had succeeded.
    Moot,
}

impl Replay {
    /// What to do with an attempt that got as far as `sent`.
    #[must_use]
    pub fn decide(self, sent: Sent) -> Decision {
        match (self, sent) {
            (Self::Moot, _) => Decision::Moot,
            (_, Sent::Queued) | (Self::Idempotent, Sent::Written) => Decision::Resend,
            (Self::Once, Sent::Written) => Decision::Fail,
        }
    }
}

/// The open flags the classification distinguishes, by name.
///
/// By name and not by number on purpose: the numeric values are the guest
/// ABI's and differ between architectures, so an adapter maps its own
/// constants onto these and the core decides what they mean. Which flags make
/// an open a mutation is the decision; which bit `O_CREAT` is, is not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenFlags(u8);

impl OpenFlags {
    /// No flag that bears on the classification: a plain open.
    pub const NONE: Self = Self(0);
    /// The open creates the file if it is absent.
    pub const CREATE: Self = Self(1 << 0);
    /// The open refuses to proceed if the file is present.
    pub const EXCLUSIVE: Self = Self(1 << 1);
    /// The open truncates the file.
    pub const TRUNCATE: Self = Self(1 << 2);
    /// The open places writes at the end of the file.
    ///
    /// Carried for completeness and deliberately *not* a mutation: appending
    /// describes how the handle places writes, and opening a file for
    /// appending twice leaves the file exactly as one open would. The
    /// **writes** through such a handle are the ones that must not be
    /// repeated, and [`Opcode::Write`] is classified accordingly.
    pub const APPEND: Self = Self(1 << 3);

    /// The flags that make an open a mutation.
    ///
    /// A plain open may be repeated freely after a reconnect; one that creates,
    /// refuses to create, or truncates cannot, because a second application
    /// would see — or make — a different world.
    pub const MUTATING: Self = Self(Self::CREATE.0 | Self::EXCLUSIVE.0 | Self::TRUNCATE.0);

    /// Both sets of flags at once.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether any flag of `other` is set here.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

/// How a request of this opcode may be replayed.
///
/// `open` is meaningful for [`Opcode::Open`] alone — the one operation whose
/// class depends on its arguments — and every other opcode ignores it.
///
/// The lists are the design's:
///
/// * [`Replay::Idempotent`] — lookup, getattr, read, readdirplus, the xattr
///   reads, statfs, readlink, getlk, the subscription pair, and an `open` that
///   neither creates nor truncates;
/// * [`Replay::Moot`] — `release` and `forget`, whose referents died with the
///   session;
/// * [`Replay::Once`] — everything else. Every mutation; an `open` carrying
///   the mutating flags, because those *are* mutations; `flush` and `fsync`,
///   which the idempotent list leaves out and which act on server-side state —
///   the caller's record-lock owner, the host file's durability — that a client
///   may not re-apply on a guest's behalf; and `hello`, which is never replayed
///   on a dead connection at all, because a session is re-established by
///   dialling and not by resending its handshake.
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
        // A `Subscribe` on an already-subscribed session answers a fresh
        // snapshot on the same stream, and an `Unsubscribe` against a session
        // that never subscribed answers success: both re-send safely.
        | Opcode::Subscribe
        | Opcode::Unsubscribe => Replay::Idempotent,
        Opcode::Open => {
            if open.intersects(OpenFlags::MUTATING) {
                Replay::Once
            } else {
                Replay::Idempotent
            }
        }
        Opcode::Release | Opcode::Forget => Replay::Moot,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_replay_discipline_is_the_contracts() {
        // A queued request provably never reached the server, whatever it is.
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
        // A written one may have been dispatched.
        assert_eq!(Replay::Idempotent.decide(Sent::Written), Decision::Resend);
        assert_eq!(
            Replay::Once.decide(Sent::Written),
            Decision::Fail,
            "a written mutation must not risk a second application"
        );
        // A moot request's referent died with the session either way.
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
        ] {
            assert_eq!(
                of(idempotent, OpenFlags::NONE),
                Replay::Idempotent,
                "{idempotent}"
            );
        }
        for once in [
            // The handshake itself: a replacement connection opens with a
            // fresh hello of its own, never a re-issued one.
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
            // Not on the design's idempotent list: a durability barrier and a
            // lock-owner drop the guest was told nothing about are not ones a
            // client may re-issue on its own.
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
