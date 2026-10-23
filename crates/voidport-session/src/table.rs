//! The table contains no frame bytes: a resend re-encodes from the arguments of
//! the awaiting caller. Per request it contains the id and the opcode that a
//! reply must echo. A table belongs to one connection, so a late reply from a
//! replaced connection addresses nothing.
//!
//! The replay class and the lifecycle position are in the [`Ticket`], because
//! only the task that writes the frame knows that position: it is the complete
//! frame on the socket, not any lock. A table consulted from another task could
//! contain only a stale answer, which means either a mutation applied twice or a
//! request failed that need not have been.
//!
//! Storage grows on demand through the adapter, and an allocation refusal fails
//! only the request that needs more storage. A compressed binary radix index
//! follows at most 64 discriminating bits of a wire id.

use core::marker::PhantomData;

use voidport_proto::opcode::Opcode;

use crate::replay::{Decision, Replay, Sent};

pub const INITIAL_SLOTS: usize = 8;

#[derive(Debug)]
pub struct Slot<W> {
    held: Option<Outstanding<W>>,
    branch: Option<Branch>,
    free_leaf: Option<usize>,
    free_branch: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
enum Link {
    Leaf(usize),
    Branch(usize),
}

#[derive(Clone, Copy, Debug)]
struct Branch {
    bit: u32,
    children: [Link; 2],
}

impl Branch {
    fn side(self, id: u64) -> usize {
        ((id >> self.bit) & 1) as usize
    }
}

#[derive(Debug)]
struct Outstanding<W> {
    request_id: u64,
    opcode: Opcode,
    wake: Option<W>,
    previous: Option<u64>,
    next: Option<u64>,
}

impl<W> Slot<W> {
    #[must_use]
    pub const fn vacant() -> Self {
        Self {
            held: None,
            branch: None,
            free_leaf: None,
            free_branch: None,
        }
    }
}

impl<W> Default for Slot<W> {
    fn default() -> Self {
        Self::vacant()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocationRefused;

/// The request index or its adapter storage does not satisfy the table contract.
/// No request may be sent after this error. End the connection and bury its table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvariantError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimError {
    Allocation,
    Invariant(InvariantError),
}

impl From<AllocationRefused> for ClaimError {
    fn from(_: AllocationRefused) -> Self {
        Self::Allocation
    }
}

impl From<InvariantError> for ClaimError {
    fn from(error: InvariantError) -> Self {
        Self::Invariant(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    InvalidLength,
}

/// Both accessors must expose the same slots. Their length must remain unchanged
/// except through successful growth. Initial slots must be vacant.
pub trait Slots<W> {
    fn slots(&self) -> &[Slot<W>];
    fn slots_mut(&mut self) -> &mut [Slot<W>];
    /// Enlarge to exactly `len`, preserving existing slots and appending vacant ones.
    /// A length no larger than the current length succeeds without changing slots.
    /// On refusal, the length and every existing slot must remain unchanged.
    fn grow(&mut self, len: usize) -> Result<(), AllocationRefused>;
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ticket {
    request_id: u64,
    opcode: Opcode,
    replay: Replay,
    phase: Phase,
}

#[derive(Debug, PartialEq, Eq)]
enum Phase {
    Claimed,
    Armed,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleError {
    Armed,
    Retired,
    Invariant(InvariantError),
}

impl From<InvariantError> for LifecycleError {
    fn from(error: InvariantError) -> Self {
        Self::Invariant(error)
    }
}

impl Ticket {
    #[must_use]
    pub fn request_id(&self) -> u64 {
        self.request_id
    }

    #[must_use]
    pub fn opcode(&self) -> Opcode {
        self.opcode
    }

    #[must_use]
    pub fn decide(&self, sent: Sent) -> Decision {
        self.replay.decide(sent)
    }
}

#[derive(Debug)]
pub enum Answer<W> {
    Invariant(InvariantError),
    Deliver(W),
    Unknown,
    Mismatch {
        expected: Opcode,
        /// The removed caller, if armed. The adapter must retain and fail it
        /// while handling the protocol fault; burial does not find it.
        wake: Option<W>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingFault {
    Invariant(InvariantError),
    UnknownResponseId(u64),
    OpcodeMismatch { expected: u16, found: u16 },
}

impl core::fmt::Display for RoutingFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invariant(_) => f.write_str("inconsistent request table"),
            Self::UnknownResponseId(id) => {
                write!(f, "a response to request {id}, which is not pending")
            }
            Self::OpcodeMismatch { expected, found } => {
                write!(
                    f,
                    "response opcode {found} does not match request opcode {expected}"
                )
            }
        }
    }
}

#[derive(Debug)]
pub struct RoutingFailure<W> {
    pub fault: RoutingFault,
    pub wake: Option<W>,
}

impl<W> Answer<W> {
    pub fn route(self, request_id: u64, opcode: u16) -> Result<W, RoutingFailure<W>> {
        match self {
            Self::Invariant(error) => Err(RoutingFailure {
                fault: RoutingFault::Invariant(error),
                wake: None,
            }),
            Self::Deliver(wake) => Ok(wake),
            Self::Unknown => Err(RoutingFailure {
                fault: RoutingFault::UnknownResponseId(request_id),
                wake: None,
            }),
            Self::Mismatch { expected, wake } => Err(RoutingFailure {
                fault: RoutingFault::OpcodeMismatch {
                    expected: expected.as_u16(),
                    found: opcode,
                },
                wake,
            }),
        }
    }
}

#[derive(Debug)]
pub struct Requests<W, S> {
    storage: S,
    root: Option<Link>,
    free_leaf: Option<usize>,
    free_branch: Option<usize>,
    next_request_id: u64,
    outstanding: usize,
    first: Option<u64>,
    last: Option<u64>,
    wake: PhantomData<W>,
}

impl<W, S: Slots<W>> Requests<W, S> {
    /// Ids start after the handshake and wrap, skipping zero and held ids.
    /// Storage must contain a nonzero power-of-two number of vacant slots.
    pub fn new(storage: S) -> Result<Self, StorageError> {
        if !storage.slots().len().is_power_of_two() {
            return Err(StorageError::InvalidLength);
        }
        let mut table = Self {
            storage,
            root: None,
            free_leaf: None,
            free_branch: None,
            next_request_id: crate::handshake::HELLO_REQUEST_ID + 1,
            outstanding: 0,
            first: None,
            last: None,
            wake: PhantomData,
        };
        table.add_free_storage(0);
        Ok(table)
    }

    #[must_use]
    pub fn storage_len(&self) -> usize {
        self.storage.slots().len()
    }

    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.outstanding
    }

    /// A request that expects no reply occupies no slot: its id retires the moment
    /// the frame reaches the transport.
    pub fn take_request_id(&mut self) -> Result<u64, InvariantError> {
        loop {
            let id = self.next_request_id;
            self.next_request_id = id.wrapping_add(1);
            if id != 0 && self.index_of(id)?.is_none() {
                return Ok(id);
            }
        }
    }

    pub fn claim(&mut self, opcode: Opcode, replay: Replay) -> Result<Ticket, ClaimError> {
        let request_id = self.take_request_id()?;
        if self.free_leaf.is_none() {
            let len = self.storage.slots().len();
            let grown = len.checked_mul(2).ok_or(AllocationRefused)?;
            self.storage.grow(grown)?;
            if self.storage.slots().len() != grown {
                return Err(InvariantError.into());
            }
            self.add_free_storage(len);
        }
        let index = self.free_leaf.ok_or(InvariantError)?;
        let slot = self.storage.slots().get(index).ok_or(InvariantError)?;
        if slot.held.is_some() {
            return Err(InvariantError.into());
        }
        let free_leaf = slot.free_leaf;
        let outstanding = self.outstanding.checked_add(1).ok_or(InvariantError)?;
        let last = self
            .last
            .map(|id| self.index_of(id)?.ok_or(InvariantError))
            .transpose()?;
        // Validate the list before changing the index. No waiter is moved until
        // all fallible radix work has completed.
        if let Some(last) = last
            && self.storage.slots()[last]
                .held
                .as_ref()
                .ok_or(InvariantError)?
                .next
                .is_some()
        {
            return Err(InvariantError.into());
        }
        self.insert_leaf(index, request_id)?;
        if let Some(last) = last {
            self.storage.slots_mut()[last]
                .held
                .as_mut()
                .ok_or(InvariantError)?
                .next = Some(request_id);
        } else {
            self.first = Some(request_id);
        }
        self.free_leaf = free_leaf;
        self.storage.slots_mut()[index].held = Some(Outstanding {
            request_id,
            opcode,
            wake: None,
            previous: self.last,
            next: None,
        });
        self.outstanding = outstanding;
        self.last = Some(request_id);
        Ok(Ticket {
            request_id,
            opcode,
            replay,
            phase: Phase::Claimed,
        })
    }

    fn add_free_storage(&mut self, start: usize) {
        for index in (start..self.storage.slots().len()).rev() {
            let slot = &mut self.storage.slots_mut()[index];
            slot.free_leaf = self.free_leaf;
            slot.free_branch = self.free_branch;
            self.free_leaf = Some(index);
            self.free_branch = Some(index);
        }
    }

    fn insert_leaf(&mut self, index: usize, id: u64) -> Result<(), InvariantError> {
        let Some(mut link) = self.root else {
            self.root = Some(Link::Leaf(index));
            return Ok(());
        };
        let other_index = self.slot_index(id)?.ok_or(InvariantError)?;
        let other = self.storage.slots()[other_index]
            .held
            .as_ref()
            .ok_or(InvariantError)?
            .request_id;
        // Equal ids have no discriminating bit and cannot form a new branch.
        let bit = 63u32
            .checked_sub((id ^ other).leading_zeros())
            .ok_or(InvariantError)?;
        let mut parent = None;
        while let Link::Branch(branch_index) = link {
            let branch = self
                .storage
                .slots()
                .get(branch_index)
                .ok_or(InvariantError)?
                .branch
                .ok_or(InvariantError)?;
            if branch.bit < bit {
                break;
            }
            let side = branch.side(id);
            parent = Some((branch_index, side));
            link = branch.children[side];
        }
        // A binary tree with n leaves has n-1 branches. Reserving the new leaf
        // therefore also guarantees a vacant branch without another allocation.
        let branch_index = self.free_branch.ok_or(InvariantError)?;
        let slot = self
            .storage
            .slots()
            .get(branch_index)
            .ok_or(InvariantError)?;
        if slot.branch.is_some() {
            return Err(InvariantError);
        }
        self.free_branch = slot.free_branch;
        let mut children = [link; 2];
        children[((id >> bit) & 1) as usize] = Link::Leaf(index);
        self.storage.slots_mut()[branch_index].branch = Some(Branch { bit, children });
        self.replace_link(parent, Some(Link::Branch(branch_index)))
    }

    fn replace_link(
        &mut self,
        parent: Option<(usize, usize)>,
        link: Option<Link>,
    ) -> Result<(), InvariantError> {
        if let Some((index, side)) = parent {
            let child = self
                .storage
                .slots_mut()
                .get_mut(index)
                .ok_or(InvariantError)?
                .branch
                .as_mut()
                .ok_or(InvariantError)?
                .children
                .get_mut(side)
                .ok_or(InvariantError)?;
            *child = link.ok_or(InvariantError)?;
        } else {
            self.root = link;
        }
        Ok(())
    }

    fn unlink_leaf(&mut self, id: u64, index: usize) -> Result<(), InvariantError> {
        let mut link = self.root.ok_or(InvariantError)?;
        let mut parent = None;
        let mut grandparent = None;
        while let Link::Branch(branch_index) = link {
            let branch = self
                .storage
                .slots()
                .get(branch_index)
                .ok_or(InvariantError)?
                .branch
                .ok_or(InvariantError)?;
            let side = branch.side(id);
            grandparent = parent;
            parent = Some((branch_index, side));
            link = branch.children[side];
        }
        if let Some((branch_index, side)) = parent {
            let branch = self.storage.slots()[branch_index]
                .branch
                .ok_or(InvariantError)?;
            self.replace_link(grandparent, Some(branch.children[1 - side]))?;
            self.storage.slots_mut()[branch_index].branch = None;
            self.storage.slots_mut()[branch_index].free_branch = self.free_branch;
            self.free_branch = Some(branch_index);
        } else {
            self.root = None;
        }
        self.storage.slots_mut()[index].free_leaf = self.free_leaf;
        self.free_leaf = Some(index);
        Ok(())
    }

    /// Armed before the frame is written, so a reply can never arrive before the
    /// waiter that is owed it is in the table. A stale ticket arms nothing,
    /// and `wake` makes the wakeup only for a claim that takes it.
    pub fn arm(
        &mut self,
        ticket: &mut Ticket,
        wake: impl FnOnce() -> W,
    ) -> Result<(), LifecycleError> {
        let index = self.claimed(ticket)?;
        let outstanding = self.storage.slots_mut()[index]
            .held
            .as_mut()
            .ok_or(InvariantError)?;
        outstanding.wake = Some(wake());
        ticket.phase = Phase::Armed;
        Ok(())
    }

    pub fn abandon(&mut self, ticket: &mut Ticket) -> Result<(), LifecycleError> {
        self.claimed(ticket)?;
        self.remove(ticket.request_id)?;
        ticket.phase = Phase::Retired;
        Ok(())
    }

    fn claimed(&self, ticket: &Ticket) -> Result<usize, LifecycleError> {
        match ticket.phase {
            Phase::Armed => return Err(LifecycleError::Armed),
            Phase::Retired => return Err(LifecycleError::Retired),
            Phase::Claimed => {}
        }
        let index = self
            .index_of(ticket.request_id)?
            .ok_or(LifecycleError::Retired)?;
        if self.storage.slots()[index]
            .held
            .as_ref()
            .ok_or(InvariantError)?
            .wake
            .is_some()
        {
            return Err(LifecycleError::Armed);
        }
        Ok(index)
    }

    /// Removing is also the duplicate check: a second response for one id finds
    /// nothing outstanding. The opcode is taken raw, because a reply can
    /// contain an opcode this client cannot name, and the mismatch must still
    /// show the opcode that was expected.
    pub fn answer(&mut self, request_id: u64, opcode: u16) -> Answer<W> {
        let outstanding = match self.remove(request_id) {
            Ok(Some(outstanding)) => outstanding,
            Ok(None) => return Answer::Unknown,
            Err(error) => return Answer::Invariant(error),
        };
        if outstanding.opcode.as_u16() != opcode {
            return Answer::Mismatch {
                expected: outstanding.opcode,
                wake: outstanding.wake,
            };
        }
        match outstanding.wake {
            Some(wake) => Answer::Deliver(wake),
            // A request whose frame is still being written cannot be answered
            // yet: the reply has an id nothing is waiting on.
            None => Answer::Unknown,
        }
    }

    /// Every caller is woken, and each asks its ticket what the replay
    /// discipline makes of the lifecycle position reached by its write. The
    /// table is empty afterwards, and its slots are free for the requests
    /// queued behind them.
    pub fn bury(&mut self, mut wake: impl FnMut(W)) {
        self.bury_with(|_, _, waiter| {
            if let Some(waiter) = waiter {
                wake(waiter);
            }
        });
    }

    pub fn bury_with(&mut self, mut finish: impl FnMut(u64, Opcode, Option<W>)) {
        while let Some(id) = self.first {
            match self.remove(id) {
                Ok(Some(outstanding)) => finish(id, outstanding.opcode, outstanding.wake),
                // A damaged index must not strand waiters or loop on the same
                // id. Only this failure path scans storage, independent of links.
                Ok(None) | Err(_) => break,
            }
        }
        if self.outstanding != 0 || self.first.is_some() {
            for slot in self.storage.slots_mut() {
                if let Some(held) = slot.held.take() {
                    finish(held.request_id, held.opcode, held.wake);
                }
                slot.branch = None;
            }
            self.root = None;
            self.first = None;
            self.last = None;
            self.outstanding = 0;
            self.free_leaf = None;
            self.free_branch = None;
            self.add_free_storage(0);
        }
    }

    fn remove(&mut self, id: u64) -> Result<Option<Outstanding<W>>, InvariantError> {
        let Some(index) = self.index_of(id)? else {
            return Ok(None);
        };
        let held = self.storage.slots()[index]
            .held
            .as_ref()
            .ok_or(InvariantError)?;
        let (previous, next) = (held.previous, held.next);
        let previous_index = previous
            .map(|id| self.index_of(id)?.ok_or(InvariantError))
            .transpose()?;
        let next_index = next
            .map(|id| self.index_of(id)?.ok_or(InvariantError))
            .transpose()?;
        let count = self.outstanding.checked_sub(1).ok_or(InvariantError)?;
        // Check both neighbors while the waiter still belongs to its slot.
        // An error leaves it available to connection burial.
        if let Some(previous) = previous_index {
            if previous == index
                || self.storage.slots()[previous]
                    .held
                    .as_ref()
                    .ok_or(InvariantError)?
                    .next
                    != Some(id)
            {
                return Err(InvariantError);
            }
        } else if self.first != Some(id) {
            return Err(InvariantError);
        }
        if let Some(next) = next_index {
            if next == index
                || self.storage.slots()[next]
                    .held
                    .as_ref()
                    .ok_or(InvariantError)?
                    .previous
                    != Some(id)
            {
                return Err(InvariantError);
            }
        } else if self.last != Some(id) {
            return Err(InvariantError);
        }
        self.unlink_leaf(id, index)?;
        if let Some(previous) = previous_index {
            self.storage.slots_mut()[previous]
                .held
                .as_mut()
                .ok_or(InvariantError)?
                .next = next;
        } else {
            self.first = next;
        }
        if let Some(next) = next_index {
            self.storage.slots_mut()[next]
                .held
                .as_mut()
                .ok_or(InvariantError)?
                .previous = previous;
        } else {
            self.last = previous;
        }
        self.outstanding = count;
        Ok(self.storage.slots_mut()[index].held.take())
    }

    fn index_of(&self, request_id: u64) -> Result<Option<usize>, InvariantError> {
        let Some(index) = self.slot_index(request_id)? else {
            return Ok(None);
        };
        let held = self.storage.slots()[index]
            .held
            .as_ref()
            .ok_or(InvariantError)?;
        Ok((held.request_id == request_id).then_some(index))
    }

    fn slot_index(&self, request_id: u64) -> Result<Option<usize>, InvariantError> {
        let Some(mut link) = self.root else {
            return Ok(None);
        };
        let mut previous_bit = u64::BITS;
        loop {
            match link {
                Link::Leaf(index) => {
                    self.storage.slots().get(index).ok_or(InvariantError)?;
                    return Ok(Some(index));
                }
                Link::Branch(index) => {
                    let branch = self
                        .storage
                        .slots()
                        .get(index)
                        .ok_or(InvariantError)?
                        .branch
                        .ok_or(InvariantError)?;
                    // Radix bits strictly decrease. This also rejects cycles and
                    // out-of-range shifts before following a malformed branch.
                    if branch.bit >= previous_bit {
                        return Err(InvariantError);
                    }
                    previous_bit = branch.bit;
                    link = branch.children[branch.side(request_id)];
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::HELLO_REQUEST_ID;
    use std::vec::Vec;

    impl<W> Slots<W> for Vec<Slot<W>> {
        fn slots(&self) -> &[Slot<W>] {
            self
        }
        fn slots_mut(&mut self) -> &mut [Slot<W>] {
            self
        }
        fn grow(&mut self, len: usize) -> Result<(), AllocationRefused> {
            if len <= self.len() {
                return Ok(());
            }
            self.try_reserve(len - self.len())
                .map_err(|_| AllocationRefused)?;
            self.resize_with(len, Slot::vacant);
            Ok(())
        }
    }

    impl<W, const N: usize> Slots<W> for [Slot<W>; N] {
        fn slots(&self) -> &[Slot<W>] {
            self
        }
        fn slots_mut(&mut self) -> &mut [Slot<W>] {
            self
        }
        fn grow(&mut self, len: usize) -> Result<(), AllocationRefused> {
            if len <= N {
                Ok(())
            } else {
                Err(AllocationRefused)
            }
        }
    }

    fn table(capacity: usize) -> Requests<&'static str, Vec<Slot<&'static str>>> {
        let mut storage = Vec::new();
        storage.resize_with(capacity, Slot::vacant);
        Requests::new(storage).unwrap()
    }

    #[test]
    fn duplicate_radix_id_returns_an_error_without_changing_the_request() {
        let mut requests = table(2);
        let mut ticket = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
        requests.arm(&mut ticket, || "held").unwrap();
        let vacant = requests.free_leaf.unwrap();
        assert_eq!(
            requests.insert_leaf(vacant, ticket.request_id()),
            Err(InvariantError)
        );
        assert_eq!(requests.outstanding(), 1);
        assert!(matches!(
            requests.answer(ticket.request_id(), Opcode::Read.as_u16()),
            Answer::Deliver("held")
        ));
    }

    #[test]
    fn invalid_radix_links_fail_and_burial_returns_every_waiter() {
        for damage in 0..4 {
            let mut requests = table(2);
            let mut first = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
            let mut second = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
            requests.arm(&mut first, || "first").unwrap();
            requests.arm(&mut second, || "second").unwrap();
            let Some(Link::Branch(root)) = requests.root else {
                panic!("two leaves need a branch")
            };
            match damage {
                0 => requests.storage[root].branch = None,
                1 => requests.storage[root].branch.as_mut().unwrap().bit = 64,
                2 => {
                    requests.storage[root].branch.as_mut().unwrap().children =
                        [Link::Branch(root); 2]
                }
                _ => {
                    requests.storage[root].branch.as_mut().unwrap().children =
                        [Link::Leaf(usize::MAX); 2]
                }
            }
            assert_eq!(requests.take_request_id(), Err(InvariantError));
            assert_eq!(
                requests.claim(Opcode::Read, Replay::Idempotent),
                Err(ClaimError::Invariant(InvariantError))
            );
            let failure = requests
                .answer(first.request_id(), Opcode::Read.as_u16())
                .route(first.request_id(), Opcode::Read.as_u16())
                .unwrap_err();
            assert_eq!(failure.fault, RoutingFault::Invariant(InvariantError));
            assert_eq!(failure.wake, None);
            let mut completed = Vec::new();
            requests.bury(|wake| completed.push(wake));
            completed.sort_unstable();
            assert_eq!(completed, ["first", "second"]);
            assert_eq!(requests.outstanding(), 0);
            requests.bury(|_| panic!("waiter completed twice"));
            assert!(requests.claim(Opcode::Read, Replay::Idempotent).is_ok());
        }
    }

    #[test]
    fn invalid_list_links_preserve_waiters_for_burial() {
        for damage in 0..4 {
            let mut requests = table(2);
            let mut first = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
            let mut second = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
            requests.arm(&mut first, || "first").unwrap();
            requests.arm(&mut second, || "second").unwrap();
            let first_index = requests.index_of(first.request_id()).unwrap().unwrap();
            let second_index = requests.index_of(second.request_id()).unwrap().unwrap();
            match damage {
                0 => requests.storage[first_index].held.as_mut().unwrap().next = Some(99),
                1 => {
                    requests.storage[second_index]
                        .held
                        .as_mut()
                        .unwrap()
                        .previous = Some(99)
                }
                2 => {
                    requests.storage[first_index].held.as_mut().unwrap().next =
                        Some(first.request_id())
                }
                _ => requests.first = None,
            }
            assert!(matches!(
                requests.answer(first.request_id(), Opcode::Read.as_u16()),
                Answer::Invariant(_)
            ));
            let mut completed = Vec::new();
            requests.bury(|wake| completed.push(wake));
            completed.sort_unstable();
            assert_eq!(completed, ["first", "second"]);
            assert_eq!(requests.outstanding(), 0);
        }
    }

    #[test]
    fn missing_free_branch_fails_before_installing_a_claim() {
        let mut requests = table(2);
        let mut first = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
        requests.arm(&mut first, || "first").unwrap();
        requests.free_branch = None;
        assert_eq!(
            requests.claim(Opcode::Read, Replay::Idempotent),
            Err(ClaimError::Invariant(InvariantError))
        );
        assert_eq!(requests.outstanding(), 1);
        requests.bury(|wake| assert_eq!(wake, "first"));
    }

    #[test]
    fn routing_delivers_or_ends_only_the_producing_connection() {
        let mut source = table(4);
        let mut other = table(4);
        let mut unrelated = other.claim(Opcode::Read, Replay::Idempotent).unwrap();
        other.arm(&mut unrelated, || "other connection").unwrap();
        let unknown = source.answer(99, 0).route(99, 0).unwrap_err();
        assert_eq!(unknown.fault, RoutingFault::UnknownResponseId(99));
        assert_eq!(unknown.wake, None);
        for armed in [false, true] {
            let mut ticket = source.claim(Opcode::Read, Replay::Idempotent).unwrap();
            if armed {
                source.arm(&mut ticket, || "removed caller").unwrap();
            }
            let failure = source
                .answer(ticket.request_id(), u16::MAX)
                .route(ticket.request_id(), u16::MAX)
                .unwrap_err();
            assert_eq!(
                failure.fault,
                RoutingFault::OpcodeMismatch {
                    expected: Opcode::Read.as_u16(),
                    found: u16::MAX,
                }
            );
            assert_eq!(failure.wake, armed.then_some("removed caller"));
            source.bury(|_| panic!("removed waiter is not in the table"));
        }
        assert_eq!(other.outstanding(), 1);
        assert_eq!(
            other
                .answer(unrelated.request_id(), Opcode::Read.as_u16())
                .route(unrelated.request_id(), Opcode::Read.as_u16())
                .unwrap(),
            "other connection",
        );
    }

    #[test]
    fn invalid_storage_lengths_return_a_typed_error() {
        for len in [0, 3, 5, 6, 7, 9] {
            let mut storage: Vec<Slot<()>> = Vec::new();
            storage.resize_with(len, Slot::vacant);
            assert!(matches!(
                Requests::new(storage),
                Err(StorageError::InvalidLength)
            ));
        }
        for len in [1, 2, 4, 8, 16] {
            assert_eq!(table(len).storage_len(), len);
        }
    }

    #[test]
    fn nonincreasing_growth_preserves_storage_and_requests() {
        let mut requests = table(4);
        let mut ticket = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
        assert!(requests.arm(&mut ticket, || "read").is_ok());
        for len in [4, 3, 0] {
            assert_eq!(requests.storage.grow(len), Ok(()));
            assert_eq!(requests.storage_len(), 4);
        }
        assert!(matches!(
            requests.answer(ticket.request_id(), Opcode::Read.as_u16()),
            Answer::Deliver("read")
        ));
        let mut fixed = [Slot::<()>::vacant()];
        assert_eq!(fixed.grow(1), Ok(()));
        assert_eq!(fixed.grow(0), Ok(()));
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
        assert_eq!(requests.take_request_id(), Ok(HELLO_REQUEST_ID + 2));
        let mut second = requests
            .claim(Opcode::Getattr, Replay::Idempotent)
            .expect("a free slot");
        assert_eq!(second.request_id(), HELLO_REQUEST_ID + 3);
        requests.arm(&mut second, || "getattr").unwrap();
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
    fn termination_visits_armed_and_unarmed_requests_once() {
        let mut requests = table(2);
        let mut read = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
        let metadata = requests.claim(Opcode::Getattr, Replay::Idempotent).unwrap();
        assert!(requests.arm(&mut read, || "read").is_ok());
        let mut completed = Vec::new();
        requests.bury_with(|id, opcode, waiter| completed.push((id, opcode, waiter)));
        assert_eq!(
            completed,
            [
                (read.request_id(), Opcode::Read, Some("read")),
                (metadata.request_id(), Opcode::Getattr, None),
            ]
        );
        assert_eq!(requests.outstanding(), 0);
        requests.bury_with(|_, _, _| panic!("a request completed twice"));
    }

    #[test]
    fn growth_preserves_outstanding_requests_and_tickets() {
        let mut requests = table(2);
        let mut tickets = Vec::new();
        for _ in 0..129 {
            tickets.push(requests.claim(Opcode::Read, Replay::Idempotent).unwrap());
        }
        assert_eq!(requests.outstanding(), 129);
        assert!(requests.storage_len() >= 129);
        let mut observed = Vec::new();
        let mut current = requests.first;
        while let Some(id) = current {
            observed.push(id);
            let index = requests.index_of(id).unwrap().expect("outstanding");
            current = requests.storage.slots()[index]
                .held
                .as_ref()
                .expect("held")
                .next;
        }
        assert_eq!(
            observed,
            tickets
                .iter()
                .map(|ticket| ticket.request_id())
                .collect::<Vec<_>>()
        );
        for mut ticket in tickets {
            assert!(requests.arm(&mut ticket, || "read").is_ok());
            assert!(matches!(
                requests.answer(ticket.request_id(), Opcode::Read.as_u16()),
                Answer::Deliver("read")
            ));
        }
        assert_eq!(requests.outstanding(), 0);
    }

    #[test]
    fn allocation_refusal_preserves_every_outstanding_request() {
        let mut requests = Requests::new([Slot::vacant(), Slot::vacant()]).unwrap();
        let mut first = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
        let mut second = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
        assert!(requests.arm(&mut first, || "first").is_ok());
        assert!(requests.arm(&mut second, || "second").is_ok());
        assert_eq!(
            requests.claim(Opcode::Read, Replay::Idempotent),
            Err(ClaimError::Allocation)
        );
        assert_eq!(requests.outstanding(), 2);
        assert!(matches!(
            requests.answer(first.request_id(), Opcode::Read.as_u16()),
            Answer::Deliver("first")
        ));
        assert!(matches!(
            requests.answer(second.request_id(), Opcode::Read.as_u16()),
            Answer::Deliver("second")
        ));
        assert_eq!(requests.outstanding(), 0);
    }

    #[test]
    fn refusal_after_growth_keeps_relocated_requests_answerable() {
        struct Storage(Vec<Slot<&'static str>>);
        impl Slots<&'static str> for Storage {
            fn slots(&self) -> &[Slot<&'static str>] {
                &self.0
            }
            fn slots_mut(&mut self) -> &mut [Slot<&'static str>] {
                &mut self.0
            }
            fn grow(&mut self, len: usize) -> Result<(), AllocationRefused> {
                if len > 4 {
                    return Err(AllocationRefused);
                }
                self.0.grow(len)
            }
        }
        let mut requests =
            Requests::new(Storage(std::vec![Slot::vacant(), Slot::vacant()])).unwrap();
        let mut first = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
        assert!(requests.arm(&mut first, || "first").is_ok());
        requests.next_request_id = first.request_id() + 4;
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(requests.claim(Opcode::Read, Replay::Idempotent).unwrap());
        }
        assert_eq!(requests.storage_len(), 4);
        assert_eq!(
            requests.claim(Opcode::Read, Replay::Idempotent),
            Err(ClaimError::Allocation)
        );
        assert_eq!(requests.outstanding(), 4);
        for mut ticket in held {
            requests.abandon(&mut ticket).unwrap();
        }
        assert!(matches!(
            requests.answer(first.request_id(), Opcode::Read.as_u16()),
            Answer::Deliver("first")
        ));
        let mut retry = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
        assert!(requests.arm(&mut retry, || "retry").is_ok());
        requests.bury(|wake| assert_eq!(wake, "retry"));
        assert_eq!(requests.outstanding(), 0);
    }

    #[test]
    fn held_requests_do_not_turn_completed_traffic_into_storage() {
        let mut requests = table(2);
        let mut held = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
        assert!(requests.arm(&mut held, || "held").is_ok());
        for _ in 0..100_000 {
            let mut ticket = requests.claim(Opcode::Getattr, Replay::Idempotent).unwrap();
            assert!(requests.arm(&mut ticket, || "short").is_ok());
            assert!(matches!(
                requests.answer(ticket.request_id(), Opcode::Getattr.as_u16()),
                Answer::Deliver("short")
            ));
            assert_eq!(requests.storage_len(), 2);
        }
        assert!(matches!(
            requests.answer(held.request_id(), Opcode::Read.as_u16()),
            Answer::Deliver("held")
        ));
    }

    #[test]
    fn radix_index_survives_arbitrary_removal_and_slot_reuse() {
        let mut requests = table(2);
        let mut tickets = Vec::new();
        for bit in 0..64 {
            requests.next_request_id = 1u64 << bit;
            tickets.push(requests.claim(Opcode::Read, Replay::Idempotent).unwrap());
        }
        for index in (0..64).step_by(2) {
            requests.abandon(&mut tickets[index]).unwrap();
        }
        for _ in 0..32 {
            requests.claim(Opcode::Getattr, Replay::Idempotent).unwrap();
        }
        assert_eq!(requests.storage_len(), 64);
        for index in (1..64).step_by(2) {
            assert!(requests.arm(&mut tickets[index], || "retained").is_ok());
            assert!(matches!(
                requests.answer(tickets[index].request_id(), Opcode::Read.as_u16()),
                Answer::Deliver("retained")
            ));
        }
        requests.bury(|_| {});
        assert_eq!(requests.outstanding(), 0);
    }

    #[test]
    fn ids_wrap_skipping_zero_and_every_outstanding_id() {
        let mut requests = table(2);
        let held = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
        requests.next_request_id = u64::MAX;
        let top = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
        assert_eq!(top.request_id(), u64::MAX);
        let one = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
        assert_eq!(one.request_id(), 1);
        assert_eq!(requests.take_request_id(), Ok(3));
        requests.next_request_id = u64::MAX;
        assert_eq!(requests.take_request_id(), Ok(3));
        for mut ticket in [held, top, one] {
            assert!(requests.arm(&mut ticket, || "held").is_ok());
            assert!(matches!(
                requests.answer(ticket.request_id(), Opcode::Read.as_u16()),
                Answer::Deliver("held")
            ));
        }
    }

    #[test]
    fn a_stray_response_and_a_second_one_are_both_unknown() {
        let mut requests = table(2);
        let mut ticket = requests
            .claim(Opcode::Lookup, Replay::Idempotent)
            .expect("a free slot");
        requests.arm(&mut ticket, || "lookup").unwrap();
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
        let mut ticket = requests
            .claim(Opcode::Lookup, Replay::Idempotent)
            .expect("a free slot");
        requests.arm(&mut ticket, || "lookup").unwrap();
        assert!(matches!(
            requests.answer(ticket.request_id(), Opcode::Read.as_u16()),
            Answer::Mismatch {
                expected: Opcode::Lookup,
                wake: Some("lookup"),
            }
        ));
    }

    #[test]
    fn an_opcode_the_client_cannot_name_still_states_the_real_expectation() {
        let mut requests = table(2);
        let mut ticket = requests
            .claim(Opcode::Lookup, Replay::Idempotent)
            .expect("a free slot");
        requests.arm(&mut ticket, || "lookup").unwrap();
        assert!(matches!(
            requests.answer(ticket.request_id(), 0xFFFF),
            Answer::Mismatch {
                expected: Opcode::Lookup,
                wake: Some("lookup"),
            }
        ));
    }

    #[test]
    fn burial_wakes_every_caller_and_each_ticket_decides() {
        let mut requests = table(4);
        let mut mutation = requests
            .claim(Opcode::Setattr, Replay::Once)
            .expect("a slot");
        requests.arm(&mut mutation, || "mutation").unwrap();
        let mut read = requests
            .claim(Opcode::Read, Replay::Idempotent)
            .expect("a slot");
        requests.arm(&mut read, || "read").unwrap();
        let mut release = requests
            .claim(Opcode::Release, Replay::Moot)
            .expect("a slot");
        requests.arm(&mut release, || "release").unwrap();
        let mut unarmed = requests
            .claim(Opcode::Lookup, Replay::Idempotent)
            .expect("a slot");

        let mut woken = Vec::new();
        requests.bury(|wake| woken.push(wake));
        assert_eq!(woken, std::vec!["mutation", "read", "release"]);
        assert_eq!(requests.outstanding(), 0, "a buried table holds nothing");
        assert!(requests.abandon(&mut unarmed).is_err());

        assert_eq!(mutation.decide(Sent::Queued), Decision::Resend);
        assert_eq!(mutation.decide(Sent::Written), Decision::Fail);
        assert_eq!(read.decide(Sent::Written), Decision::Resend);
        assert_eq!(release.decide(Sent::Written), Decision::Moot);
        assert_eq!(release.decide(Sent::Queued), Decision::Moot);
    }

    #[test]
    fn mismatch_returns_the_exact_removed_waiter_before_burial() {
        let mut requests = Requests::new([Slot::vacant(), Slot::vacant()]).unwrap();
        let (bad_sender, bad_receiver) = std::sync::mpsc::channel();
        let (other_sender, other_receiver) = std::sync::mpsc::channel();
        let mut bad = requests.claim(Opcode::Open, Replay::Idempotent).unwrap();
        let mut other = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
        assert!(requests.arm(&mut bad, || bad_sender).is_ok());
        assert!(requests.arm(&mut other, || other_sender).is_ok());
        let Answer::Mismatch { expected, wake } =
            requests.answer(bad.request_id(), Opcode::Read.as_u16())
        else {
            panic!("a mismatched opcode was accepted");
        };
        assert_eq!(expected, Opcode::Open);
        wake.unwrap().send("bad-source-loss").unwrap();
        assert_eq!(bad_receiver.try_recv().unwrap(), "bad-source-loss");
        assert!(matches!(
            other_receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert_eq!(requests.outstanding(), 1);
        requests.bury(|sender| sender.send("source-burial").unwrap());
        assert_eq!(other_receiver.try_recv().unwrap(), "source-burial");
        assert_eq!(requests.outstanding(), 0);
        assert!(matches!(
            requests.answer(bad.request_id(), Opcode::Open.as_u16()),
            Answer::Unknown
        ));
    }

    #[test]
    fn early_responses_make_ordinary_and_cleanup_tickets_unarmable() {
        for opcode in [Opcode::Read, Opcode::Release] {
            for response in [opcode.as_u16(), Opcode::Hello.as_u16()] {
                let mut requests = Requests::new([Slot::vacant()]).unwrap();
                let mut ticket = requests.claim(opcode, Replay::Moot).unwrap();
                assert!(matches!(
                    requests.answer(ticket.request_id(), response),
                    Answer::Unknown | Answer::Mismatch { wake: None, .. }
                ));
                let (sender, receiver) = std::sync::mpsc::channel::<()>();
                assert!(requests.arm(&mut ticket, || sender).is_err());
                assert!(matches!(
                    receiver.try_recv(),
                    Err(std::sync::mpsc::TryRecvError::Disconnected)
                ));
                assert_eq!(requests.outstanding(), 0);
                requests.bury(|_| panic!("an early response retained a waiter"));
            }
        }
    }

    #[test]
    fn a_rejected_arm_makes_no_waiter_and_keeps_the_armed_one() {
        let mut requests = Requests::new([Slot::vacant()]).unwrap();
        let mut ticket = requests.claim(Opcode::Read, Replay::Idempotent).unwrap();
        let (first, received) = std::sync::mpsc::channel();
        requests.arm(&mut ticket, || first).unwrap();
        assert_eq!(
            requests.arm(&mut ticket, || panic!("a rejected arm made its waiter")),
            Err(LifecycleError::Armed)
        );
        assert_eq!(requests.abandon(&mut ticket), Err(LifecycleError::Armed));
        assert_eq!(requests.outstanding(), 1);
        assert!(matches!(
            received.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        let Answer::Deliver(first) = requests.answer(ticket.request_id(), Opcode::Read.as_u16())
        else {
            panic!("first waiter was displaced");
        };
        first.send("answered").unwrap();
        assert_eq!(received.try_recv().unwrap(), "answered");
        assert_eq!(ticket.decide(Sent::Written), Decision::Resend);
        assert_eq!(
            requests.arm(&mut ticket, || panic!("an answered ticket made a waiter")),
            Err(LifecycleError::Armed)
        );
        assert_eq!(requests.outstanding(), 0);
    }

    #[test]
    fn a_stale_ticket_touches_nothing() {
        let mut requests = table(1);
        let mut first = requests
            .claim(Opcode::Read, Replay::Idempotent)
            .expect("a slot");
        requests.abandon(&mut first).unwrap();
        let second = requests
            .claim(Opcode::Read, Replay::Idempotent)
            .expect("a slot");
        assert_ne!(first.request_id(), second.request_id());
        assert!(
            requests.arm(&mut first, || "gone").is_err(),
            "the slot is another request's"
        );
        assert!(requests.abandon(&mut first).is_err());
        assert_eq!(
            requests.outstanding(),
            1,
            "the request that holds the slot is untouched"
        );
    }
}
