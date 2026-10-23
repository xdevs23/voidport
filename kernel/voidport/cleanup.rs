// SPDX-License-Identifier: GPL-2.0

use kernel::prelude::*;
use kernel::rbtree::{RBTree, RBTreeNodeReservation};
use kernel::sync::{new_mutex, Arc, Mutex};
use voidport_proto::error::FramingError;
use voidport_proto::frame::Frame;

use crate::connection::{Connection, Landing, Pieces, Reply};
use crate::handle::Handle;
use crate::stats::{self, Discharge, Event, Reference};
use crate::wire::Caller;
use voidport_proto::message::{ResponseBody, ResponseOutcome};
use voidport_proto::ops::file::{
    release_flags, FlushRequest, FlushResponse, ReleaseRequest, ReleaseResponse, SetlkRequest,
    SetlkResponse,
};
use voidport_session::cleanup::{
    AfterPass, Backlog, Charge, Disposition, List, Listing, ReferenceCount, Retirement,
    SessionState, WorkerStep,
};
use voidport_session::time::Instant;
use zerocopy::byteorder::little_endian::{U32, U64};

#[derive(Clone, Copy, Default)]
pub(crate) struct Closing {
    pub(crate) flags: u32,
    /// The lock owner whose record locks on the file end with the handle.
    pub(crate) lock_owner: Option<u64>,
}

impl Closing {
    fn request(self, handle: u64) -> ReleaseRequest {
        ReleaseRequest {
            handle: U64::new(handle),
            lock_owner: U64::new(self.lock_owner.unwrap_or_default()),
            flags: U32::new(self.flags),
            release_flags: U32::new(if self.lock_owner.is_some() {
                release_flags::UNLOCK
            } else {
                0
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Node,
    Handle,
}

pub(crate) enum Retiring {
    /// `count` lookups of the node `id`.
    Nodes { id: u64, count: u64 },
    /// The open handle `id`, whose release sends `closing`.
    Handle { id: u64, closing: Closing },
}

impl Retiring {
    fn key_and_count(&self) -> ((Kind, u64), u64) {
        match *self {
            Self::Nodes { id, count } => ((Kind::Node, id), count),
            Self::Handle { id, .. } => ((Kind::Handle, id), 1),
        }
    }
}

type References = Option<KBox<Cleanup>>;
type BySession = RBTree<u64, Arc<Group>>;
type ByIdentity = RBTree<(Kind, u64), Arc<Group>>;

/// The storage the first admission of an identity in a session fills: the
/// nodes of both indexes and the group with the count.
struct IndexReservation {
    identity: RBTreeNodeReservation<(Kind, u64), BySession>,
    session: RBTreeNodeReservation<u64, ByIdentity>,
    in_identity: RBTreeNodeReservation<u64, Arc<Group>>,
    in_session: RBTreeNodeReservation<(Kind, u64), Arc<Group>>,
    group: Arc<Group>,
}

impl IndexReservation {
    fn new(count: ReferenceCount) -> Result<Self> {
        Ok(Self {
            identity: RBTreeNodeReservation::new(GFP_KERNEL)?,
            session: RBTreeNodeReservation::new(GFP_KERNEL)?,
            in_identity: RBTreeNodeReservation::new(GFP_KERNEL)?,
            in_session: RBTreeNodeReservation::new(GFP_KERNEL)?,
            group: Arc::pin_init(
                pin_init!(Group {
                    state <- new_mutex!(Retained {
                        count,
                        work: None,
                        id: 0,
                    }, "voidport::retained"),
                }),
                GFP_KERNEL,
            )?,
        })
    }
}

/// One session's count for one identity. Its work record alternates between
/// this object and the worker, so eviction never allocates a queue entry.
#[pin_data]
struct Group {
    #[pin]
    state: Mutex<Retained>,
}

struct Retained {
    count: ReferenceCount,
    work: References,
    id: u64,
}

impl Drop for Retained {
    fn drop(&mut self) {
        while let Some(mut work) = self.work.take() {
            self.work = work.next.take();
        }
    }
}

/// The references of a session that ended, completed without the mount's
/// records mutex.
#[derive(Default)]
pub(crate) struct EndedSession(ByIdentity);

impl EndedSession {
    pub(crate) fn complete(mut self) {
        while let Some(node) = crate::compat::pop_first(&mut self.0) {
            let (_, group) = node.to_key_value();
            let mut state = group.state.lock();
            let Some(count) = state.count.end() else {
                continue;
            };
            if state.count.aggregates() {
                stats::record(Event::Discharged {
                    reference: Reference::Node,
                    count,
                    by: Discharge::Teardown,
                });
                if let Some(work) = &mut state.work {
                    work.detach_session();
                }
            } else {
                let mut next = state.work.as_mut();
                while let Some(work) = next {
                    work.session_ended();
                    next = work.next.as_mut();
                }
            }
        }
    }
}

pub(crate) type DecodeId = fn(&Frame<'_>) -> core::result::Result<Option<u64>, FramingError>;
type VisitDirectory =
    fn(&Frame<'_>, &[u8], &mut dyn FnMut(u64)) -> core::result::Result<(), FramingError>;

struct Scalar {
    decode: DecodeId,
    id: Option<u64>,
    index: Option<IndexReservation>,
}

impl Scalar {
    fn new(decode: DecodeId, count: ReferenceCount) -> Result<Self> {
        Ok(Self {
            decode,
            id: None,
            index: Some(IndexReservation::new(count)?),
        })
    }
}

enum Ownership {
    Node {
        scalar: Scalar,
        /// While the worker has the record of the owed count of the node, the
        /// group with that count.
        group: Option<Arc<Group>>,
    },
    Handle {
        scalar: Scalar,
        reply: Option<Arc<Reply>>,
        closing: Closing,
    },
    Directory {
        visit: VisitDirectory,
        listing: Listing,
    },
    /// A record lock that a Setlk on the node `node_id` places, which
    /// `unlock` gives back with `reply` when the reply placed it after its
    /// caller left.
    Lock {
        node_id: u64,
        unlock: SetlkRequest,
        placed: bool,
        reply: Option<Arc<Reply>>,
    },
    /// The Flush of the node `node_id` for the lock owner of `flush`, which
    /// the worker sends with `reply` through the handle `through` when the
    /// process that placed a lock died while it closed a descriptor.
    Flush {
        node_id: u64,
        flush: FlushRequest,
        through: Option<Arc<Handle>>,
        reply: Option<Arc<Reply>>,
    },
}

#[derive(Clone, Copy)]
enum Admission {
    Reserved,
    Admitted(u64),
    /// Their session ended, which ended them on the server too.
    Ended,
}

impl Admission {
    fn generation(self) -> Option<u64> {
        match self {
            Self::Admitted(generation) => Some(generation),
            Self::Reserved | Self::Ended => None,
        }
    }
}

/// Ownership storage reserved before admission and retained until cleanup
/// completes. A failed RELEASE retains its reply and its session for the next
/// pass of the worker.
pub(crate) struct Cleanup {
    caller: Caller,
    ownership: Ownership,
    admission: Admission,
    next: References,
    filled: Option<Landing>,
    paired: References,
}

impl Cleanup {
    pub(crate) fn node(caller: Caller, decode: DecodeId) -> Result<KBox<Self>> {
        Self::new(
            caller,
            Ownership::Node {
                scalar: Scalar::new(decode, ReferenceCount::lookups())?,
                group: None,
            },
        )
    }

    pub(crate) fn handle(caller: Caller, decode: DecodeId) -> Result<KBox<Self>> {
        Self::new(
            caller,
            Ownership::Handle {
                scalar: Scalar::new(decode, ReferenceCount::opens())?,
                reply: Some(callerless_reply::<ReleaseResponse>()?),
                closing: Closing::default(),
            },
        )
    }

    pub(crate) fn directory(caller: Caller, visit: VisitDirectory) -> Result<KBox<Self>> {
        Self::new(
            caller,
            Ownership::Directory {
                visit,
                listing: Listing::default(),
            },
        )
    }

    pub(crate) fn lock(caller: Caller, node_id: u64, unlock: SetlkRequest) -> Result<KBox<Self>> {
        Self::new(
            caller,
            Ownership::Lock {
                node_id,
                unlock,
                placed: false,
                reply: Some(callerless_reply::<SetlkResponse>()?),
            },
        )
    }

    pub(crate) fn flush(caller: Caller, node_id: u64, lock_owner: u64) -> Result<KBox<Self>> {
        Self::new(
            caller,
            Ownership::Flush {
                node_id,
                flush: FlushRequest {
                    handle: U64::ZERO,
                    lock_owner: U64::new(lock_owner),
                },
                through: None,
                reply: Some(callerless_reply::<FlushResponse>()?),
            },
        )
    }

    pub(crate) fn through(mut self: KBox<Self>, handle: Arc<Handle>) -> KBox<Self> {
        if let Ownership::Flush { flush, through, .. } = &mut self.ownership {
            flush.handle = U64::new(handle.id());
            *through = Some(handle);
        }
        self
    }

    fn new(caller: Caller, ownership: Ownership) -> Result<KBox<Self>> {
        Ok(KBox::new(
            Self {
                caller,
                ownership,
                admission: Admission::Reserved,
                next: None,
                filled: None,
                paired: None,
            },
            GFP_KERNEL,
        )?)
    }

    pub(crate) fn paired_with(mut self: KBox<Self>, second: KBox<Self>) -> KBox<Self> {
        self.paired = Some(second);
        self
    }

    /// The paired record, which receives the reply once this one is admitted.
    pub(crate) fn take_paired(&mut self) -> References {
        self.paired.take()
    }

    /// What the statistics count the references of this record as. The
    /// unlock of a record lock and a Flush give back none.
    fn reference(&self) -> Option<Reference> {
        match self.ownership {
            Ownership::Node { .. } | Ownership::Directory { .. } => Some(Reference::Node),
            Ownership::Handle { .. } => Some(Reference::Handle),
            Ownership::Lock { .. } | Ownership::Flush { .. } => None,
        }
    }

    fn key(&self) -> Option<(Kind, u64)> {
        match &self.ownership {
            Ownership::Node { scalar, .. } => Some((Kind::Node, scalar.id?)),
            Ownership::Handle { scalar, .. } => Some((Kind::Handle, scalar.id?)),
            _ => None,
        }
    }

    /// Whether the reply leaves something on the server for the worker to
    /// give back, when it goes where `disposition` sends it. A caller that
    /// kept the reply of a Setlk took the lock it placed with it.
    pub(crate) fn owes(&self, disposition: Disposition) -> bool {
        match self.ownership {
            Ownership::Lock { placed, .. } => placed && disposition == Disposition::GiveBack,
            _ => true,
        }
    }

    fn scalar(&self) -> Option<&Scalar> {
        match &self.ownership {
            Ownership::Node { scalar, .. } | Ownership::Handle { scalar, .. } => Some(scalar),
            _ => None,
        }
    }

    fn scalar_mut(&mut self) -> Option<&mut Scalar> {
        match &mut self.ownership {
            Ownership::Node { scalar, .. } | Ownership::Handle { scalar, .. } => Some(scalar),
            _ => None,
        }
    }

    fn single(&self) -> Option<u64> {
        self.scalar().and_then(|scalar| scalar.id)
    }

    fn owe_for(&mut self, group: Arc<Group>) {
        if let Ownership::Node { group: owed, .. } = &mut self.ownership {
            *owed = Some(group);
        }
    }

    fn take_owed_for(&mut self) -> Option<Arc<Group>> {
        match &mut self.ownership {
            Ownership::Node { group, .. } => group.take(),
            _ => None,
        }
    }

    /// Transfer the complete reply, including entries not copied or delivered.
    pub(crate) fn carry(&mut self, landing: Landing) {
        self.filled = Some(landing);
    }

    /// Validate before publication and resolve single-reference identities once.
    fn prepare(&mut self) -> core::result::Result<(), FramingError> {
        let (Some(landing), Admission::Admitted(_)) = (&self.filled, self.admission) else {
            return Ok(());
        };
        let frame = Frame::parse(landing.bytes(), &crate::wire::LIMITS)?;
        match &mut self.ownership {
            Ownership::Node { scalar, .. } | Ownership::Handle { scalar, .. } => {
                scalar.id = (scalar.decode)(&frame)?
            }
            Ownership::Directory { visit, .. } => {
                return visit(&frame, landing.pieces.entries(), &mut |_| {})
            }
            Ownership::Lock { placed, .. } => {
                *placed = matches!(
                    frame.response::<SetlkResponse>()?,
                    ResponseOutcome::Success(_)
                );
            }
            Ownership::Flush { .. } => {}
        }
        let landing = self.filled.take();
        if let Some(paired) = &mut self.paired {
            paired.filled = landing;
        }
        Ok(())
    }

    /// Visit scalar references directly; only complete directory batches decode.
    pub(crate) fn visit(
        &self,
        mut reference: impl FnMut(u64),
    ) -> core::result::Result<(), FramingError> {
        if self.admission.generation().is_none() {
            return Ok(());
        }
        if let Some(id) = self.single() {
            reference(id);
        } else if let Ownership::Directory { visit, .. } = self.ownership {
            if let Some(landing) = &self.filled {
                let frame = Frame::parse(landing.bytes(), &crate::wire::LIMITS)?;
                visit(&frame, landing.pieces.entries(), &mut reference)?;
            }
        }
        Ok(())
    }

    /// Visits the references the worker has not given back yet: those of
    /// [`Self::visit`], past the entries of a directory batch that earlier
    /// passes forgot.
    fn visit_unforgotten(
        &self,
        mut reference: impl FnMut(u64),
    ) -> core::result::Result<(), FramingError> {
        let listing = match self.ownership {
            Ownership::Directory { listing, .. } => listing,
            _ => Listing::default(),
        };
        let mut index = 0;
        self.visit(|id| {
            if listing.owes(index) {
                reference(id);
            }
            index += 1;
        })
    }

    pub(crate) fn admit(&mut self, generation: u64) -> core::result::Result<(), FramingError> {
        self.admission = Admission::Admitted(generation);
        self.prepare()?;
        self.visit(|_| {
            if let Some(reference) = self.reference() {
                stats::record(Event::Admitted {
                    reference,
                    count: 1,
                })
            }
        })
    }

    /// Complete references whose session ended, which ended them on the server
    /// too, retaining only scalar identities for later inode/handle retirement.
    fn session_ended(&mut self) {
        let _ = self.visit_unforgotten(|_| {
            if let Some(reference) = self.reference() {
                stats::record(Event::Discharged {
                    reference,
                    count: 1,
                    by: Discharge::Teardown,
                })
            }
        });
        self.detach_session();
    }

    /// Detaches the record from the session that ended: drops the generation,
    /// and the reply and the storage for a RELEASE reply, which only that
    /// session could use.
    fn detach_session(&mut self) {
        self.admission = Admission::Ended;
        self.filled = None;
        if let Ownership::Handle { reply, .. } = &mut self.ownership {
            *reply = None;
        }
    }

    /// Puts back the reserved reply of a record whose request no connection
    /// took.
    fn keep_reply(&mut self, kept: Arc<Reply>) {
        if let Ownership::Handle { reply, .. }
        | Ownership::Lock { reply, .. }
        | Ownership::Flush { reply, .. } = &mut self.ownership
        {
            *reply = Some(kept);
        }
    }

    /// Ends the references of a record that was refused again after the mount
    /// closed, unsent: the close ended their session. The record of a node
    /// count ends what its node owes.
    fn end_unsent(&mut self) {
        match self.take_owed_for() {
            Some(group) => stats::record(Event::Discharged {
                reference: Reference::Node,
                count: group.state.lock().count.take_owed(),
                by: Discharge::Teardown,
            }),
            None => self.session_ended(),
        }
    }
}

/// The storage of the reply to a request of the cleanup worker, whose body
/// fits in `R`.
fn callerless_reply<R: ResponseBody>() -> Result<Arc<Reply>> {
    Reply::new(crate::wire::reply_capacity::<R>(0), Pieces::None, None)
}

#[derive(Clone, Copy)]
pub(crate) struct Notice {
    caller: Caller,
    node_id: u64,
    body: NoticeBody,
}

#[derive(Clone, Copy)]
enum NoticeBody {
    Release(ReleaseRequest),
    /// The unlock of a record lock that a Setlk placed after its caller left.
    Unlock(SetlkRequest),
    /// The Flush of a descriptor that a process closed as it died.
    Flush(FlushRequest),
}

impl Notice {
    pub(crate) fn send(&self, connection: &Connection, reply: Arc<Reply>) -> Result {
        let (caller, node_id) = (self.caller, self.node_id);
        match &self.body {
            NoticeBody::Release(body) => connection.send_callerless(caller, node_id, body, reply),
            NoticeBody::Unlock(body) => connection.send_callerless(caller, node_id, body, reply),
            NoticeBody::Flush(body) => connection.send_callerless(caller, node_id, body, reply),
        }
    }
}

/// Marks a reply as the reply to a request of the cleanup worker, which no
/// caller waits for. Taking the marker out of the reply ends the request
/// once: when the reply arrives, when the loss of its connection is settled,
/// or when its session ends.
pub(crate) struct Callerless {
    notice: Notice,
    /// The handle a Flush goes through. It is given back once the Flush
    /// ended, so that the release of the handle comes after the Flush.
    through: Option<Arc<Handle>>,
}

impl Callerless {
    pub(crate) fn notice(&self) -> Notice {
        self.notice
    }

    /// Cleanup has no waiting caller to check its typed response.
    pub(crate) fn validate(&self, bytes: &[u8]) -> core::result::Result<(), FramingError> {
        let frame = Frame::parse(bytes, &crate::wire::LIMITS)?;
        match self.notice.body {
            NoticeBody::Release(_) => frame.response::<ReleaseResponse>().map(|_| ()),
            NoticeBody::Unlock(_) => frame.response::<SetlkResponse>().map(|_| ()),
            NoticeBody::Flush(_) => frame.response::<FlushResponse>().map(|_| ()),
        }
    }

    /// Ends the request. A release counts its handle as given back, by the
    /// request when `answered` and by the end of the session otherwise.
    pub(crate) fn finish(self, answered: bool) {
        if let NoticeBody::Release(_) = self.notice.body {
            stats::record(Event::Discharged {
                reference: Reference::Handle,
                count: 1,
                by: if answered {
                    Discharge::Sent
                } else {
                    Discharge::Teardown
                },
            });
        }
        // The release of the handle a Flush went through can follow now.
        drop(self.through);
    }
}

/// Identity lookup and session teardown have separate indexes over the same
/// counts. All index nodes and worker queue storage precede admission.
#[derive(Default)]
pub(crate) struct Records {
    live: RBTree<(Kind, u64), BySession>,
    sessions: RBTree<u64, ByIdentity>,
    backlog: Backlog<Batch>,
}

impl Records {
    pub(crate) fn step(&mut self, now: Instant) -> WorkerStep<Batch> {
        self.backlog.step(now)
    }

    /// Moves a record after its attempt to where the core sends it: the record
    /// of a node count to its group, to the worker again or to the refused
    /// records, and any other record to the refused records.
    pub(crate) fn finish_cleanup(&mut self, mut cleanup: KBox<Cleanup>) {
        let Some(group) = cleanup.take_owed_for() else {
            self.refuse(cleanup);
            return;
        };
        let mut state = group.state.lock();
        match state.count.after_pass() {
            AfterPass::Settled => {
                if state.count.session() == SessionState::Ended {
                    cleanup.detach_session();
                }
                state.work = Some(cleanup);
            }
            AfterPass::Again => {
                cleanup.owe_for(group.clone());
                self.backlog.arrive(cleanup);
            }
            AfterPass::Refused => {
                drop(state);
                cleanup.owe_for(group);
                self.refuse(cleanup);
            }
        }
    }

    /// Hands a record whose attempt was refused to the backlog, or ends its
    /// references unsent once the mount closed.
    fn refuse(&mut self, cleanup: KBox<Cleanup>) {
        if let Some(mut cleanup) = self.backlog.refuse(cleanup) {
            cleanup.end_unsent();
        }
    }

    /// Retains the record of a reply in the count of the session that admitted
    /// it until the identity it admitted is retired, unless the backlog has the
    /// worker attempt it at once.
    pub(crate) fn insert(&mut self, mut cleanup: KBox<Cleanup>, disposition: Disposition) {
        let retained = cleanup.key().filter(|_| self.backlog.retains(disposition));
        let (Some(key), Some(generation)) = (retained, cleanup.admission.generation()) else {
            self.backlog.arrive(cleanup);
            return;
        };
        let id = key.1;
        let indexed = self
            .live
            .get(&key)
            .and_then(|sessions| sessions.get(&generation))
            .cloned();
        let (group, first) = match indexed {
            Some(group) => (group, false),
            None => {
                // Only a key that is not live yet uses the index reservation.
                // A repeat admission does not use the reservation, so the
                // record still contains it.
                let Some(IndexReservation {
                    identity,
                    session,
                    in_identity,
                    in_session,
                    group: reserved_group,
                }) = cleanup.scalar_mut().and_then(|scalar| scalar.index.take())
                else {
                    self.backlog.arrive(cleanup);
                    return;
                };
                if self.live.get(&key).is_none() {
                    self.live.insert(identity.into_node(key, BySession::new()));
                }
                if let Some(sessions) = self.live.get_mut(&key) {
                    sessions.insert(in_identity.into_node(generation, reserved_group.clone()));
                }
                if self.sessions.get(&generation).is_none() {
                    self.sessions
                        .insert(session.into_node(generation, ByIdentity::new()));
                }
                if let Some(identities) = self.sessions.get_mut(&generation) {
                    identities.insert(in_session.into_node(key, reserved_group.clone()));
                }
                (reserved_group, true)
            }
        };
        let mut state = group.state.lock();
        if first {
            state.id = id;
        }
        match state.count.admit() {
            SessionState::Ended => cleanup.session_ended(),
            SessionState::Lasting => {
                // Each open of a handle has a separate record, which sends a
                // RELEASE for that open alone. The first record of a node sends
                // the count of every lookup of the node.
                if first || !state.count.aggregates() {
                    cleanup.next = state.work.take();
                    state.work = Some(cleanup);
                }
            }
        }
    }

    /// Retires the references of `retiring`, charged to the sessions in which
    /// they are live in the order that the core returns, with one operation
    /// for each session. A record that the worker is attempting still
    /// accumulates retirements.
    pub(crate) fn release(&mut self, retiring: Retiring, caller: Caller) -> bool {
        let (key, count) = retiring.key_and_count();
        let mut retirement = Retirement::new(count);
        loop {
            let generations = self
                .live
                .get(&key)
                .into_iter()
                .flat_map(|sessions| sessions.iter().map(|(generation, _)| *generation));
            let generation = match retirement.next_charge(generations) {
                Charge::Session(generation) => generation,
                Charge::Done => return true,
                Charge::Unmatched => return false,
            };
            let Some(group) = self
                .live
                .get(&key)
                .and_then(|sessions| sessions.get(&generation))
                .cloned()
            else {
                return false;
            };
            let mut state = group.state.lock();
            let retired = retirement.charge(&mut state.count);
            if retired.emptied {
                let emptied = self.live.get_mut(&key).is_some_and(|sessions| {
                    sessions.remove(&generation);
                    sessions.is_empty()
                });
                if emptied {
                    self.live.remove(&key);
                }
                if let Some(identities) = self.sessions.get_mut(&generation) {
                    identities.remove(&key);
                    if identities.is_empty() {
                        self.sessions.remove(&generation);
                    }
                }
            }
            if retired.session == SessionState::Lasting {
                if let Some(mut work) = state.work.take() {
                    if state.count.aggregates() {
                        work.owe_for(group.clone());
                    } else {
                        state.work = work.next.take();
                        work.caller = caller;
                    }
                    if let (
                        Retiring::Handle { closing, .. },
                        Ownership::Handle { closing: sent, .. },
                    ) = (&retiring, &mut work.ownership)
                    {
                        *sent = *closing;
                    }
                    self.backlog.arrive(work);
                }
            }
        }
    }

    /// Hands the worker `flush`, the record of a Flush through the handle
    /// `handle`, in the latest session in which that handle is live. Returns
    /// the record when the handle is live in none.
    pub(crate) fn flush_after_close(
        &mut self,
        mut flush: KBox<Cleanup>,
        handle: u64,
    ) -> Option<KBox<Cleanup>> {
        let latest = self
            .live
            .get(&(Kind::Handle, handle))
            .and_then(|sessions| sessions.iter().map(|(generation, _)| *generation).last());
        let Some(generation) = latest else {
            return Some(flush);
        };
        flush.admission = Admission::Admitted(generation);
        self.backlog.arrive(flush);
        None
    }

    /// One indexed removal detaches exactly the session of `generation`.
    /// Completion happens after the caller releases the records mutex.
    pub(crate) fn session_ended(&mut self, generation: u64) -> EndedSession {
        self.sessions
            .remove(&generation)
            .map(EndedSession)
            .unwrap_or_default()
    }

    /// The mount closes: the worker gets every record that the core returns
    /// as owed, and the indexes empty.
    pub(crate) fn close(&mut self) {
        self.backlog.close();
        while let Some(node) = crate::compat::pop_first(&mut self.live) {
            let (_, mut sessions) = node.to_key_value();
            while let Some(node) = crate::compat::pop_first(&mut sessions) {
                let (_, group) = node.to_key_value();
                let mut state = group.state.lock();
                if state.count.mount_closed() == SessionState::Lasting {
                    while let Some(mut work) = state.work.take() {
                        state.work = work.next.take();
                        if state.count.aggregates() {
                            work.owe_for(group.clone());
                        }
                        self.backlog.arrive(work);
                    }
                }
            }
        }
        self.sessions = RBTree::new();
    }
}

/// An exclusively owned list with iterative removal and destruction.
#[derive(Default)]
pub(crate) struct Batch(References);

impl Batch {
    /// Order a detached batch outside the records mutex without allocating.
    pub(crate) fn oldest_first(self) -> Self {
        let mut ordered = Self::default();
        for cleanup in self {
            ordered.push(cleanup);
        }
        ordered
    }
}

impl List for Batch {
    type Record = KBox<Cleanup>;

    fn push(&mut self, mut cleanup: KBox<Cleanup>) {
        cleanup.next = self.0.take();
        self.0 = Some(cleanup);
    }

    fn is_empty(&self) -> bool {
        self.0.is_none()
    }
}

impl Iterator for Batch {
    type Item = KBox<Cleanup>;
    fn next(&mut self) -> Option<Self::Item> {
        let mut cleanup = self.0.take()?;
        self.0 = cleanup.next.take();
        Some(cleanup)
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        while self.next().is_some() {}
    }
}

/// Where cleanup is written: on the connections of the session that
/// admitted the references.
pub(crate) trait Connections {
    fn lasts(&self, generation: u64) -> bool;

    /// Writes one cleanup frame with `write` on a connection of the session
    /// of `generation`. `write` returns whether a reply is still owed on that
    /// connection, which the thread of the connection then reads.
    fn write_cleanup(
        &self,
        generation: u64,
        write: &mut dyn FnMut(&Arc<Connection>) -> Result<bool>,
    ) -> Written;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Written {
    /// It was written, or left to the thread of its connection to settle.
    Sent,
    /// The session ended, which ended the references with it.
    Ended,
    Later,
}

/// Discharges a departed caller's cleanup: the reply the reader filled carries
/// a server-side reference, and this gives it back on a connection of the
/// session of that reply. Once that session ended, the reference ended with
/// it. Cleanup that was not written returns to the worker for a later pass.
pub(crate) fn discharge(
    cleanup: KBox<Cleanup>,
    connections: &impl Connections,
) -> Option<KBox<Cleanup>> {
    let generation = cleanup.admission.generation()?;
    match cleanup.ownership {
        Ownership::Node { group: Some(_), .. } => {
            Some(discharge_count(cleanup, generation, connections))
        }
        Ownership::Handle { .. } => discharge_handle(cleanup, generation, connections),
        Ownership::Node { .. } | Ownership::Directory { .. } => {
            discharge_nodes(cleanup, generation, connections)
        }
        Ownership::Lock { .. } | Ownership::Flush { .. } => {
            discharge_notice(cleanup, generation, connections)
        }
    }
}

/// What is owed for a node becomes one FORGET. Retirements during the I/O
/// accumulate for the next pass, and a count that was not written waits for
/// the pass over refused records.
fn discharge_count(
    cleanup: KBox<Cleanup>,
    generation: u64,
    connections: &impl Connections,
) -> KBox<Cleanup> {
    let Ownership::Node {
        group: Some(group), ..
    } = &cleanup.ownership
    else {
        return cleanup;
    };
    let group = group.clone();
    let (count, id) = {
        let mut state = group.state.lock();
        (state.count.take_owed(), state.id)
    };
    let written = connections.write_cleanup(generation, &mut |connection| {
        connection.forget(cleanup.caller, id, count).map(|()| false)
    });
    let by = match written {
        Written::Sent => Discharge::Sent,
        Written::Ended => Discharge::Teardown,
        Written::Later => {
            group.state.lock().count.refused(count);
            return cleanup;
        }
    };
    stats::record(Event::Discharged {
        reference: Reference::Node,
        count,
        by,
    });
    cleanup
}

fn discharge_handle(
    mut cleanup: KBox<Cleanup>,
    generation: u64,
    connections: &impl Connections,
) -> Option<KBox<Cleanup>> {
    let id = cleanup.single()?;
    let caller = cleanup.caller;
    let Ownership::Handle { reply, closing, .. } = &mut cleanup.ownership else {
        return None;
    };
    let Some(reply) = reply.take() else {
        crate::diag::warn_limited!(Cleanup, "handle cleanup is missing its reserved reply");
        return if connections.lasts(generation) {
            Some(cleanup)
        } else {
            cleanup.session_ended();
            None
        };
    };
    let notice = Notice {
        caller,
        node_id: 0,
        body: NoticeBody::Release(closing.request(id)),
    };
    let completion = Callerless {
        notice,
        through: None,
    };
    match write_callerless(&reply, completion, generation, connections) {
        Written::Sent => None,
        Written::Ended => {
            cleanup.session_ended();
            None
        }
        Written::Later => {
            cleanup.keep_reply(reply);
            Some(cleanup)
        }
    }
}

/// Sends the unlock of a record lock that a Setlk placed after its caller
/// left, with the same owner, range and handle, or the Flush of a descriptor
/// that a process closed as it died, on a connection of the session of the
/// record. Once that session ended, the lock ended with it on the server.
fn discharge_notice(
    mut cleanup: KBox<Cleanup>,
    generation: u64,
    connections: &impl Connections,
) -> Option<KBox<Cleanup>> {
    let caller = cleanup.caller;
    let (node_id, body, through, reply) = match &mut cleanup.ownership {
        Ownership::Lock {
            node_id,
            unlock,
            placed: true,
            reply,
        } => (*node_id, NoticeBody::Unlock(*unlock), None, reply),
        Ownership::Flush {
            node_id,
            flush,
            through,
            reply,
        } => (*node_id, NoticeBody::Flush(*flush), through.clone(), reply),
        _ => return None,
    };
    let reply = reply.take()?;
    let completion = Callerless {
        notice: Notice {
            caller,
            node_id,
            body,
        },
        through,
    };
    match write_callerless(&reply, completion, generation, connections) {
        Written::Sent | Written::Ended => None,
        Written::Later => {
            cleanup.keep_reply(reply);
            Some(cleanup)
        }
    }
}

/// Sends the request of `completion`, armed with `reply`, on a connection of
/// the session `generation`, and takes the completion back out of a reply
/// that no connection took.
fn write_callerless(
    reply: &Arc<Reply>,
    completion: Callerless,
    generation: u64,
    connections: &impl Connections,
) -> Written {
    let notice = completion.notice();
    reply.complete_cleanup(completion);
    let written = connections.write_cleanup(generation, &mut |connection| {
        notice.send(connection, reply.clone()).map(|()| true)
    });
    if written != Written::Sent {
        drop(reply.withdraw_callerless());
    }
    written
}

/// One FORGET for every entry of a directory batch, from the first one a
/// pass has not written yet.
fn discharge_nodes(
    mut cleanup: KBox<Cleanup>,
    generation: u64,
    connections: &impl Connections,
) -> Option<KBox<Cleanup>> {
    // An ended session needs no temporary storage and no peer I/O.
    if !connections.lasts(generation) {
        cleanup.session_ended();
        return None;
    }
    let mut identities = KVec::new();
    let mut collected = Ok(());
    let parsed = cleanup.visit_unforgotten(|id| {
        if collected.is_ok() {
            collected = identities.push(id, GFP_KERNEL);
        }
    });
    if parsed.is_err() {
        cleanup.session_ended();
        return None;
    }
    // Nothing of the entries left has been sent in this pass. Retain the
    // batch for a later pass if the host cannot supply temporary identity
    // storage.
    if collected.is_err() {
        return Some(cleanup);
    }
    let mut ended = false;
    for &id in identities.iter() {
        let written = if ended {
            Written::Ended
        } else {
            connections.write_cleanup(generation, &mut |connection| {
                connection.forget(cleanup.caller, id, 1).map(|()| false)
            })
        };
        let by = match written {
            Written::Sent => Discharge::Sent,
            Written::Ended => {
                ended = true;
                Discharge::Teardown
            }
            Written::Later => return Some(cleanup),
        };
        stats::record(Event::Discharged {
            reference: Reference::Node,
            count: 1,
            by,
        });
        if let Ownership::Directory { listing, .. } = &mut cleanup.ownership {
            listing.sent_one();
        }
    }
    None
}
