//! The request table: request-id allocation, and the fixed-capacity record of
//! what is outstanding.
//!
//! The table **is** the replay retention. It holds no frame bytes — a resend
//! re-encodes from the awaiting caller's own arguments, under the bound of the
//! connection it is finally written to — and what it does hold, per request, is
//! the id and the opcode a reply must echo. The generation is the table's own:
//! a table belongs to exactly one connection, which is what makes a late reply
//! from a replaced connection addressed to an object nothing points at any
//! more.
//!
//! The rest of a request's replay state rides on the [`Ticket`] the table
//! issues: the replay class, and — through [`Ticket::decide`] — the lifecycle
//! position. It rides there because **the task that writes the frame is the
//! only one that can know that position**: the linearization point is the
//! complete frame on the socket, not any lock, so a table consulted from
//! another task could only ever hold a stale answer, and a stale answer here
//! means either a mutation applied twice or a request failed that need not
//! have been.
//!
//! **Fixed capacity, sized at construction from storage the adapter owns.**
//! The core allocates nothing: the userspace client hands over a vector from
//! its heap, the kernel client a flagged allocation, and neither ever grows.
//! A caller that finds every slot taken is told so ([`Requests::claim`] answers
//! `None`) and the adapter parks it until one frees — the same observable class
//! as a caller queueing at the single writer over a back-pressuring socket. It
//! is never an error, and there is no overflow class to have a bug in.
//!
//! Lookup is a scan of the slots. The capacity is a mount's concurrency bound —
//! tens of entries, one cache-resident array — so a scan costs less than the
//! bookkeeping a map would need, and it needs no allocator at all.

use core::marker::PhantomData;

use voidport_proto::opcode::Opcode;

use crate::replay::{Decision, Replay, Sent};

/// One slot of the request table: an outstanding request, or nothing.
///
/// `W` is whatever the adapter wakes a caller with — a channel sender in
/// userspace, a completion in kernel space. The core never looks inside it.
#[derive(Debug)]
pub struct Slot<W>(Option<Outstanding<W>>);

/// One request the table is holding.
#[derive(Debug)]
struct Outstanding<W> {
    request_id: u64,
    opcode: Opcode,
    /// The adapter's wakeup, from the moment the request is armed until it is
    /// answered, abandoned or buried.
    wake: Option<W>,
}

impl<W> Slot<W> {
    /// A slot holding nothing: what an adapter fills its storage with.
    #[must_use]
    pub const fn vacant() -> Self {
        Self(None)
    }
}

impl<W> Default for Slot<W> {
    fn default() -> Self {
        Self::vacant()
    }
}

/// Storage for a request table.
///
/// Implemented for anything that is a slice of slots, so an adapter hands over
/// whatever its allocator produced and the core borrows it as a slice.
pub trait Slots<W> {
    /// The slots, for reading.
    fn slots(&self) -> &[Slot<W>];
    /// The slots, for writing.
    fn slots_mut(&mut self) -> &mut [Slot<W>];
}

impl<W, T> Slots<W> for T
where
    T: AsRef<[Slot<W>]> + AsMut<[Slot<W>]>,
{
    fn slots(&self) -> &[Slot<W>] {
        self.as_ref()
    }

    fn slots_mut(&mut self) -> &mut [Slot<W>] {
        self.as_mut()
    }
}

/// A claimed slot, and everything its caller needs to speak about it again.
///
/// It carries the replay class the table recorded, so a caller can ask what
/// becomes of a lost attempt ([`Ticket::decide`]) without a second lookup and
/// without a second copy of the classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    index: usize,
    request_id: u64,
    replay: Replay,
}

impl Ticket {
    /// The id this request carries on the wire.
    #[must_use]
    pub fn request_id(self) -> u64 {
        self.request_id
    }

    /// What the discipline does with this request, given how far it got.
    #[must_use]
    pub fn decide(self, sent: Sent) -> Decision {
        self.replay.decide(sent)
    }
}

/// What a response frame is owed.
#[derive(Debug)]
pub enum Answer<W> {
    /// Wake this caller with the frame.
    Deliver(W),
    /// A response for an id nothing is waiting on — a stray reply, or a second
    /// one for an id already answered.
    Unknown,
    /// The response echoed an opcode that is not the one the request carried.
    Mismatch {
        /// The opcode the outstanding request was sent under.
        expected: Opcode,
    },
}

/// The outstanding requests of one connection.
#[derive(Debug)]
pub struct Requests<W, S> {
    storage: S,
    /// The next id to hand out. Monotonic, so an id is never outstanding twice
    /// on this connection.
    next_request_id: u64,
    outstanding: usize,
    wake: PhantomData<W>,
}

impl<W, S: Slots<W>> Requests<W, S> {
    /// A table over `storage`, for the connection whose handshake has just
    /// completed.
    ///
    /// Ids continue after the handshake's, so "allocated monotonically and
    /// never reused" holds across the whole connection and not only after it.
    /// The capacity is the storage's length and never changes.
    #[must_use]
    pub fn new(storage: S) -> Self {
        Self {
            storage,
            next_request_id: crate::handshake::HELLO_REQUEST_ID + 1,
            outstanding: 0,
            wake: PhantomData,
        }
    }

    /// How many requests may be outstanding at once.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.storage.slots().len()
    }

    /// How many are, right now.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.outstanding
    }

    /// The next request id, for a request that expects no reply and therefore
    /// occupies no slot.
    ///
    /// Its id retires the moment the frame reaches the transport: nothing is
    /// ever outstanding for it, so nothing has to be freed either.
    pub fn take_request_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        id
    }

    /// Claims a slot for a request of `opcode`, or answers `None` when every
    /// slot is taken.
    ///
    /// `None` is backpressure and not a failure: the adapter parks the caller
    /// until a slot frees and asks again. The table never grows and never
    /// errors.
    pub fn claim(&mut self, opcode: Opcode, replay: Replay) -> Option<Ticket> {
        let request_id = self.next_request_id;
        let index = self
            .storage
            .slots()
            .iter()
            .position(|slot| slot.0.is_none())?;
        self.next_request_id += 1;
        self.outstanding += 1;
        self.storage.slots_mut()[index] = Slot(Some(Outstanding {
            request_id,
            opcode,
            wake: None,
        }));
        Some(Ticket {
            index,
            request_id,
            replay,
        })
    }

    /// Arms a claimed request with the wakeup its caller waits on.
    ///
    /// Done before the frame is written, so a reply can never arrive before the
    /// waiter that is owed it is in the table. A stale ticket arms nothing.
    pub fn arm(&mut self, ticket: Ticket, wake: W) -> bool {
        let Some(slot) = self.storage.slots_mut().get_mut(ticket.index) else {
            return false;
        };
        match &mut slot.0 {
            Some(outstanding) if outstanding.request_id == ticket.request_id => {
                outstanding.wake = Some(wake);
                true
            }
            _ => false,
        }
    }

    /// Gives up a claimed request that will never be answered on this
    /// connection, and frees its slot.
    ///
    /// The request that could not be encoded, and the one whose frame never
    /// reached the socket.
    pub fn abandon(&mut self, ticket: Ticket) -> Option<W> {
        let slot = self.storage.slots_mut().get_mut(ticket.index)?;
        match &slot.0 {
            Some(outstanding) if outstanding.request_id == ticket.request_id => {}
            _ => return None,
        }
        self.outstanding -= 1;
        slot.0.take().and_then(|outstanding| outstanding.wake)
    }

    /// Matches a response to the caller waiting for it.
    ///
    /// Removing is also the duplicate check: a second response for one id finds
    /// nothing outstanding. The opcode a response echoes is checked here
    /// because the table is what knows which opcode was sent under that id —
    /// taken raw, because a reply may carry an opcode this client cannot even
    /// name, and the mismatch it reports must still state the real
    /// expectation.
    pub fn answer(&mut self, request_id: u64, opcode: u16) -> Answer<W> {
        let Some(index) = self.index_of(request_id) else {
            return Answer::Unknown;
        };
        self.outstanding -= 1;
        let outstanding = self.storage.slots_mut()[index]
            .0
            .take()
            .expect("the slot the scan just found");
        if outstanding.opcode.as_u16() != opcode {
            return Answer::Mismatch {
                expected: outstanding.opcode,
            };
        }
        match outstanding.wake {
            Some(wake) => Answer::Deliver(wake),
            // A request whose frame is still being written cannot be answered
            // yet: the reply names an id nothing is waiting on.
            None => Answer::Unknown,
        }
    }

    /// Ends every outstanding request, handing each caller's wakeup back.
    ///
    /// What a connection's death does to the requests it was carrying: every
    /// caller is woken, and each asks its own ticket what the discipline makes
    /// of the lifecycle position its own write reached. The table is empty
    /// afterwards, and its slots are free for whoever is queueing behind them.
    pub fn bury(&mut self, mut wake: impl FnMut(W)) {
        for slot in self.storage.slots_mut() {
            // A request nobody has armed yet — its caller is still encoding —
            // has no wakeup to hand back, and loses its slot with the rest.
            if let Some(waiter) = slot.0.take().and_then(|outstanding| outstanding.wake) {
                wake(waiter);
            }
        }
        self.outstanding = 0;
    }

    /// Where `request_id` is outstanding, if it is.
    fn index_of(&self, request_id: u64) -> Option<usize> {
        self.storage.slots().iter().position(|slot| {
            slot.0
                .as_ref()
                .is_some_and(|held| held.request_id == request_id)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::HELLO_REQUEST_ID;
    use std::vec::Vec;

    /// A table of `capacity` slots over a caller's own storage, waking with a
    /// name so the tests can say who was woken.
    fn table(capacity: usize) -> Requests<&'static str, Vec<Slot<&'static str>>> {
        let mut storage = Vec::new();
        storage.resize_with(capacity, Slot::vacant);
        Requests::new(storage)
    }

    #[test]
    fn the_ids_continue_after_the_handshakes_and_never_repeat() {
        let mut requests = table(4);
        let first = requests
            .claim(Opcode::Lookup, Replay::Idempotent)
            .expect("a free slot");
        assert_eq!(
            first.request_id(),
            HELLO_REQUEST_ID + 1,
            "the handshake already used the connection's first id"
        );
        // A request with no reply takes an id and no slot at all.
        assert_eq!(requests.take_request_id(), HELLO_REQUEST_ID + 2);
        let second = requests
            .claim(Opcode::Getattr, Replay::Idempotent)
            .expect("a free slot");
        assert_eq!(second.request_id(), HELLO_REQUEST_ID + 3);
        // Answering frees the slot without ever handing its id out again.
        requests.arm(second, "getattr");
        assert!(matches!(
            requests.answer(second.request_id(), Opcode::Getattr.as_u16()),
            Answer::Deliver("getattr")
        ));
        let third = requests
            .claim(Opcode::Read, Replay::Idempotent)
            .expect("the freed slot");
        assert_eq!(third.request_id(), HELLO_REQUEST_ID + 4);
        assert_eq!(requests.outstanding(), 2);
    }

    #[test]
    fn a_full_table_answers_none_and_frees_by_answering() {
        let mut requests = table(2);
        let first = requests
            .claim(Opcode::Read, Replay::Idempotent)
            .expect("one");
        let second = requests
            .claim(Opcode::Read, Replay::Idempotent)
            .expect("two");
        assert_eq!(requests.outstanding(), requests.capacity());
        assert_eq!(
            requests.claim(Opcode::Read, Replay::Idempotent),
            None,
            "a full table is backpressure, never an error and never a growth"
        );
        requests.arm(first, "first");
        assert!(matches!(
            requests.answer(first.request_id(), Opcode::Read.as_u16()),
            Answer::Deliver("first")
        ));
        let third = requests
            .claim(Opcode::Read, Replay::Idempotent)
            .expect("the answered request's slot");
        assert_eq!(requests.outstanding(), 2);
        // And abandoning frees one just the same.
        requests.abandon(second);
        requests.abandon(third);
        assert_eq!(requests.outstanding(), 0);
        assert!(requests.claim(Opcode::Read, Replay::Idempotent).is_some());
    }

    #[test]
    fn a_stray_response_and_a_second_one_are_both_unknown() {
        let mut requests = table(2);
        let ticket = requests
            .claim(Opcode::Lookup, Replay::Idempotent)
            .expect("a free slot");
        requests.arm(ticket, "lookup");
        assert!(matches!(
            requests.answer(9_999, Opcode::Lookup.as_u16()),
            Answer::Unknown
        ));
        assert!(matches!(
            requests.answer(ticket.request_id(), Opcode::Lookup.as_u16()),
            Answer::Deliver("lookup")
        ));
        assert!(matches!(
            requests.answer(ticket.request_id(), Opcode::Lookup.as_u16()),
            Answer::Unknown
        ));
    }

    #[test]
    fn a_response_carrying_another_opcode_is_a_mismatch() {
        let mut requests = table(2);
        let ticket = requests
            .claim(Opcode::Lookup, Replay::Idempotent)
            .expect("a free slot");
        requests.arm(ticket, "lookup");
        assert!(matches!(
            requests.answer(ticket.request_id(), Opcode::Read.as_u16()),
            Answer::Mismatch {
                expected: Opcode::Lookup
            }
        ));
    }

    /// An opcode outside this client's naming still mismatches against the
    /// real expectation — the answer is raw for exactly this reply.
    #[test]
    fn an_opcode_the_client_cannot_name_still_states_the_real_expectation() {
        let mut requests = table(2);
        let ticket = requests
            .claim(Opcode::Lookup, Replay::Idempotent)
            .expect("a free slot");
        requests.arm(ticket, "lookup");
        assert!(matches!(
            requests.answer(ticket.request_id(), 0xFFFF),
            Answer::Mismatch {
                expected: Opcode::Lookup
            }
        ));
    }

    /// A dying connection wakes every caller it was carrying, and each of them
    /// is owed what the discipline makes of the lifecycle its own write
    /// reached — every position, every class.
    #[test]
    fn burial_wakes_every_caller_and_each_ticket_decides() {
        let mut requests = table(4);
        let mutation = requests
            .claim(Opcode::Setattr, Replay::Once)
            .expect("a slot");
        requests.arm(mutation, "mutation");
        let read = requests
            .claim(Opcode::Read, Replay::Idempotent)
            .expect("a slot");
        requests.arm(read, "read");
        let release = requests
            .claim(Opcode::Release, Replay::Moot)
            .expect("a slot");
        requests.arm(release, "release");
        // A claimed request nobody armed — its caller is still encoding — has
        // nobody to wake and is dropped with the rest.
        let unarmed = requests
            .claim(Opcode::Lookup, Replay::Idempotent)
            .expect("a slot");

        let mut woken = Vec::new();
        requests.bury(|wake| woken.push(wake));
        assert_eq!(woken, std::vec!["mutation", "read", "release"]);
        assert_eq!(requests.outstanding(), 0, "a buried table holds nothing");
        assert!(requests.abandon(unarmed).is_none());

        // A queued attempt provably never reached the server, whatever it is.
        assert_eq!(mutation.decide(Sent::Queued), Decision::Resend);
        // A written one may already have been applied.
        assert_eq!(mutation.decide(Sent::Written), Decision::Fail);
        // Applying a read twice is applying it once.
        assert_eq!(read.decide(Sent::Written), Decision::Resend);
        // A release's handle died with the session either way.
        assert_eq!(release.decide(Sent::Written), Decision::Moot);
        assert_eq!(release.decide(Sent::Queued), Decision::Moot);
    }

    #[test]
    fn a_stale_ticket_touches_nothing() {
        let mut requests = table(1);
        let first = requests
            .claim(Opcode::Read, Replay::Idempotent)
            .expect("a slot");
        requests.abandon(first);
        let second = requests
            .claim(Opcode::Read, Replay::Idempotent)
            .expect("a slot");
        assert_ne!(first.request_id(), second.request_id());
        assert!(
            !requests.arm(first, "gone"),
            "the slot is another request's"
        );
        assert!(requests.abandon(first).is_none());
        assert_eq!(
            requests.outstanding(),
            1,
            "the request that holds the slot is untouched"
        );
    }
}
