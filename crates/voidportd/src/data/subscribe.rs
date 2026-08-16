//! The share subscription: the per-session notification queue and the
//! subscriber registry the publish path fans out through.
//!
//! Two objects, and the whole failure-isolation contract lives in how they are
//! wired to the rest of the server:
//!
//! * a [`NotificationQueue`] per connection, drained by that connection's
//!   writer beside its reply queue. **The mutation path never blocks on a
//!   subscriber**: pushing is a short mutex and a wakeup, never a wait, and a
//!   queue that fills is *dropped*, never waited on. That is the required
//!   "enqueue or lapse, nothing else".
//! * a [`Subscribers`] registry, held by
//!   [`Published`](crate::control::service::Published) so that **registration
//!   and publication linearize against each other**: both run under the
//!   published snapshot's write lock, so every delta a subscriber receives
//!   postdates its snapshot and none falls between.
//!
//! # Lapsing, and why it is a state and not a message
//!
//! There is no lapse wire message. An **unsolicited** snapshot — one the
//! consumer did not just subscribe for — *is* the lapse signal. When a queue
//! overflows it is emptied and marked lapsed; every further event is dropped on
//! the floor, because a delta computed against a set the consumer never
//! received would be a lie. The writer, finding the queue drained and lapsed,
//! asks for a fresh snapshot, which is computed under the publish lock exactly
//! as the first one was. A lapse therefore costs the laggard a resnapshot and
//! costs nobody else anything.
//!
//! Scope, stated honestly: this isolates a slow-but-draining consumer. A reader
//! that stops reading its socket entirely stalls its own connection by ordinary
//! transport backpressure, as any dead peer does — which is why the example
//! mount manager subscribes on a session of its own.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::Notify;
use voidport_control::NamespaceName;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{FRAME_HEADER_LEN, FrameWriter};
use voidport_proto::ops::share::{
    SHARE_END_NAMESPACE_REMOVED, SHARE_KIND_DIRECTORY, SHARE_KIND_FILE, SHARE_KIND_UNKNOWN,
    SHARE_MODE_RO, SHARE_MODE_RW, ShareAdded, ShareChanged, ShareEnded, ShareEntryHeader,
    ShareEntryWriter, ShareRemoved, ShareSnapshotBegin, ShareSnapshotEnd, ShareSnapshotPart,
};
use zerocopy::byteorder::little_endian::{U16, U32};

use crate::data::conn::MAX_FRAME_LEN;
use crate::registry::Registry;
use crate::rules::{EffectiveMode, NamespacePath};
use crate::share::{ShareEntry, ShareKind, ShareSet, share_set};

/// How many notification frames one session's queue holds before it lapses.
///
/// It is a handoff depth, not a policy: a consumer that drains at all never
/// reaches it, and one that does not is exactly the case the lapse exists for.
/// Sized so an ordinary burst of control-plane edits — an operator rewriting a
/// namespace rule by rule — is absorbed whole.
pub const NOTIFICATION_QUEUE_DEPTH: usize = 256;

/// What the connection's writer is handed when it asks the queue for work.
#[derive(Debug)]
pub enum Wake {
    /// A notification frame to write. It bypasses request-id retirement: a
    /// notification answers nothing, so there is no id to retire.
    Frame(Vec<u8>),
    /// The queue overflowed and was dropped. The writer owes the consumer a
    /// fresh snapshot, which it asks the registry for.
    Lapsed,
}

/// One session's bounded notification queue.
#[derive(Debug)]
pub struct NotificationQueue {
    state: Mutex<QueueState>,
    ready: Notify,
    depth: usize,
}

#[derive(Debug)]
struct QueueState {
    frames: std::collections::VecDeque<Vec<u8>>,
    /// The queue overflowed: everything pushed is dropped until a fresh
    /// snapshot replaces it.
    lapsed: bool,
    /// The lapse has been handed to the writer, so it is not handed out again
    /// while the writer is off computing the resnapshot.
    announced: bool,
}

impl NotificationQueue {
    /// An empty queue of the default depth.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Self::with_depth(NOTIFICATION_QUEUE_DEPTH)
    }

    /// An empty queue of `depth` frames.
    #[must_use]
    pub fn with_depth(depth: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueueState {
                frames: std::collections::VecDeque::new(),
                lapsed: false,
                announced: false,
            }),
            ready: Notify::new(),
            depth: depth.max(1),
        })
    }

    /// Enqueues one frame, or lapses the subscription.
    ///
    /// Called from the publish path, which holds the published snapshot's write
    /// lock: it takes a short mutex and returns. It cannot wait, cannot fail,
    /// and cannot be made to allocate more than the frame it was handed.
    pub fn push(&self, frame: Vec<u8>) {
        let mut state = self.locked();
        if state.lapsed {
            // A delta relative to a set the consumer never received would be
            // worse than nothing; the pending resnapshot carries the truth.
            return;
        }
        if state.frames.len() >= self.depth {
            state.frames.clear();
            state.lapsed = true;
            state.announced = false;
            drop(state);
            self.ready.notify_one();
            return;
        }
        state.frames.push_back(frame);
        drop(state);
        self.ready.notify_one();
    }

    /// Enqueues the frame that ends the stream, whatever state the queue is in.
    ///
    /// A terminal frame is not a delta, so the rule that drops deltas while
    /// lapsed must not drop it: the resnapshot a lapse promises is computed
    /// from the subscriber registry, and the only thing that ends a stream is
    /// the subscriber leaving that registry — so a dropped `ended` is a
    /// consumer waiting forever for a snapshot nobody will ever compute. The
    /// lapse is cleared with it, because everything the lapse dropped is
    /// superseded by the stream being over.
    fn finish(&self, frame: Vec<u8>) {
        let mut state = self.locked();
        if state.lapsed {
            state.frames.clear();
            state.lapsed = false;
            state.announced = false;
        }
        state.frames.push_back(frame);
        drop(state);
        self.ready.notify_one();
    }

    /// Enqueues a whole snapshot and clears the lapse, atomically.
    ///
    /// Called under the publish lock, so the set the frames describe and the
    /// set the registry now records for this subscriber are the same set.
    fn resume(&self, frames: Vec<Vec<u8>>) {
        let mut state = self.locked();
        state.frames.clear();
        state.lapsed = false;
        state.announced = false;
        state.frames.extend(frames);
        drop(state);
        self.ready.notify_one();
    }

    /// Waits for the next thing the writer must do.
    ///
    /// It parks when there is nothing; the connection's own shutdown is what
    /// ends the writer, not this queue.
    pub async fn next(&self) -> Wake {
        loop {
            // Registered before the state is examined, so a push landing
            // between the two is not missed.
            let waiting = self.ready.notified();
            {
                let mut state = self.locked();
                if let Some(frame) = state.frames.pop_front() {
                    return Wake::Frame(frame);
                }
                if state.lapsed && !state.announced {
                    state.announced = true;
                    return Wake::Lapsed;
                }
            }
            waiting.await;
        }
    }

    /// Whether the queue has lapsed and not yet been resnapshotted.
    #[must_use]
    pub fn is_lapsed(&self) -> bool {
        self.locked().lapsed
    }

    fn locked(&self) -> MutexGuard<'_, QueueState> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// Every subscribed session, keyed by session id.
///
/// Owned by [`Published`](crate::control::service::Published) and only ever
/// touched under its write lock by the two paths that must linearize —
/// registration and publication — plus the lock-free
/// [`is_subscribed`](Self::is_subscribed) the session list reads.
#[derive(Debug, Default)]
pub struct Subscribers {
    state: Mutex<BTreeMap<u64, Subscriber>>,
}

/// One subscribed session.
#[derive(Debug)]
struct Subscriber {
    /// The namespace it mounted, by name — the same key its lookups resolve
    /// through.
    name: NamespaceName,
    /// The subpath it mounted, which scopes every entry and every event.
    subpath: NamespacePath,
    /// Its connection's notification queue.
    queue: Arc<NotificationQueue>,
    /// The entry set the consumer has been told about. A delta is the
    /// difference between this and a fresh computation, which is what makes an
    /// event a function of the *session-scoped* set, not of the raw
    /// table.
    entries: ShareSet,
}

impl Subscribers {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers — or re-registers — a session, and enqueues its snapshot.
    ///
    /// Re-registration is the consumer's resync path and is deliberately not a
    /// special case: the stored set is replaced by a fresh one and a fresh
    /// snapshot is queued, exactly as a first subscription does.
    ///
    /// The caller holds the published snapshot's write lock, which is what
    /// makes capturing the table and registering the subscriber one atomic step
    /// with respect to the mutation path's publish.
    ///
    /// **A namespace that has left the registry ends the stream here instead of
    /// opening one.** The request path refuses `Subscribe` on a tombstoned
    /// session, but it reads the registry outside this lock, so a namespace
    /// deleted in that window passes the refusal and arrives here — after the
    /// deletion's own fan-out has already ended every stream it knew about.
    /// Registering then would leave a consumer holding an empty snapshot, no
    /// `ended`, and a stream nothing can ever produce another event for. The
    /// truthful answer is the one the deletion would have sent: the stream is
    /// over, reason namespace removed.
    pub fn register(
        &self,
        id: u64,
        name: &NamespaceName,
        subpath: &NamespacePath,
        queue: &Arc<NotificationQueue>,
        registry: &Registry,
    ) {
        let Some(namespace) = registry.get(name) else {
            self.locked().remove(&id);
            queue.finish(ended_frame(SHARE_END_NAMESPACE_REMOVED));
            return;
        };
        let entries = share_set(&namespace, subpath);
        queue.resume(snapshot_frames(&entries));
        self.locked().insert(
            id,
            Subscriber {
                name: name.clone(),
                subpath: subpath.clone(),
                queue: Arc::clone(queue),
                entries,
            },
        );
    }

    /// Ends a session's subscription. A session that has none is untouched, and
    /// that is what makes `Unsubscribe` a plain success.
    pub fn unregister(&self, id: u64) {
        self.locked().remove(&id);
    }

    /// Whether a session is subscribed, for the operator's session list.
    #[must_use]
    pub fn is_subscribed(&self, id: u64) -> bool {
        self.locked().contains_key(&id)
    }

    /// Sends a lapsed subscriber a fresh snapshot.
    ///
    /// The writer asks for this once it has drained a queue the publish path
    /// dropped. It runs under the publish lock like every other snapshot, so
    /// the set the consumer is about to receive and the set the registry
    /// records for it are the same one.
    pub fn refresh(&self, id: u64, registry: &Registry) {
        let mut subscribers = self.locked();
        let Some(subscriber) = subscribers.get_mut(&id) else {
            return;
        };
        // Same rule as registration and fan-out: no subscriber outlives its
        // namespace. A resnapshot of a namespace that is gone would promise a
        // set nothing can ever change again.
        let Some(namespace) = registry.get(&subscriber.name) else {
            subscriber
                .queue
                .finish(ended_frame(SHARE_END_NAMESPACE_REMOVED));
            subscribers.remove(&id);
            return;
        };
        let entries = share_set(&namespace, &subscriber.subpath);
        subscriber.queue.resume(snapshot_frames(&entries));
        subscriber.entries = entries;
    }

    /// Fans a newly published registry out to every subscriber.
    ///
    /// Called under the publish lock, with the snapshot already installed. Each
    /// subscriber's own entry set is recomputed and diffed against what it was
    /// last told, so an operator's edit reaches exactly the sessions whose
    /// scope it changes and nobody else.
    ///
    /// A namespace that has left the registry ends its subscribers' streams
    /// with a final `ended` event: the session keeps serving on its tombstone,
    /// and a frozen tombstone can never change again, so there is nothing
    /// further to report.
    pub fn republish(&self, registry: &Registry) {
        let mut subscribers = self.locked();
        let mut ended = Vec::new();
        for (id, subscriber) in subscribers.iter_mut() {
            let Some(namespace) = registry.get(&subscriber.name) else {
                // Through `finish`, not `push`: the subscriber is about to
                // leave the registry, so a lapsed queue that swallowed this
                // frame could never be resnapshotted either.
                subscriber
                    .queue
                    .finish(ended_frame(SHARE_END_NAMESPACE_REMOVED));
                ended.push(*id);
                continue;
            };
            let entries = share_set(&namespace, &subscriber.subpath);
            for frame in diff_frames(&subscriber.entries, &entries) {
                subscriber.queue.push(frame);
            }
            subscriber.entries = entries;
        }
        for id in ended {
            subscribers.remove(&id);
        }
    }

    fn locked(&self) -> MutexGuard<'_, BTreeMap<u64, Subscriber>> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// The frames of one snapshot: begin, entry-carrying parts, end.
///
/// Parts are packed to the frame bound: an entry is added to the part being
/// built while it fits, and starts a new part when it does not. One entry
/// always fits one part by construction, because a rule path is capped at
/// [`MAX_RULE_PATH_LEN`](crate::rules::MAX_RULE_PATH_LEN) bytes and the frame
/// bound is orders of magnitude larger.
fn snapshot_frames(entries: &ShareSet) -> Vec<Vec<u8>> {
    let budget = part_budget();
    let mut frames = vec![begin_frame(entries.len())];

    let mut chunk: Vec<(&str, &ShareEntry)> = Vec::new();
    let mut chunk_len = 0usize;
    for (path, entry) in entries {
        let entry_len = size_of::<ShareEntryHeader>() + path.len();
        if !chunk.is_empty() && chunk_len + entry_len > budget {
            frames.push(part_frame(&chunk, chunk_len));
            chunk.clear();
            chunk_len = 0;
        }
        chunk.push((path, entry));
        chunk_len += entry_len;
    }
    if !chunk.is_empty() {
        frames.push(part_frame(&chunk, chunk_len));
    }

    frames.push(end_frame());
    frames
}

/// The deltas that carry `previous` to `current`.
///
/// A merge over two ordered maps: an entry only in `previous` was removed, one
/// only in `current` was added, and one in both whose mode or kind differs
/// changed. A single-publish re-mode is therefore one `changed`; an operator's
/// two-operation re-mode — a remove followed by an add, which is the only shape
/// the control plane has — arrives as the two publishes it was.
fn diff_frames(previous: &ShareSet, current: &ShareSet) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    for (path, was) in previous {
        match current.get(path) {
            None => frames.push(removed_frame(path)),
            Some(now) if now != was => frames.push(changed_frame(path, *now)),
            Some(_) => {}
        }
    }
    for (path, now) in current {
        if !previous.contains_key(path) {
            frames.push(added_frame(path, *now));
        }
    }
    frames
}

/// The largest entry stream one snapshot part may carry.
fn part_budget() -> usize {
    (MAX_FRAME_LEN as usize) - FRAME_HEADER_LEN - size_of::<ShareSnapshotPart>()
}

/// The mode as the wire spells it.
fn wire_mode(mode: EffectiveMode) -> u16 {
    match mode {
        EffectiveMode::Rw => SHARE_MODE_RW,
        EffectiveMode::Ro => SHARE_MODE_RO,
    }
}

/// The target kind as the wire spells it.
fn wire_kind(kind: ShareKind) -> u16 {
    match kind {
        ShareKind::Unknown => SHARE_KIND_UNKNOWN,
        ShareKind::Directory => SHARE_KIND_DIRECTORY,
        ShareKind::File => SHARE_KIND_FILE,
    }
}

fn begin_frame(entries: usize) -> Vec<u8> {
    encode(
        &ShareSnapshotBegin {
            entries: U32::new(u32::try_from(entries).unwrap_or(u32::MAX)),
            reserved: U32::ZERO,
        },
        &[],
    )
}

/// Encodes one snapshot part from the entries that fit into it.
///
/// The entry stream is built through the protocol crate's own stream writer,
/// so nothing here assembles wire bytes by hand: an entry is its fixed header
/// followed by exactly the path bytes that header declared.
fn part_frame(chunk: &[(&str, &ShareEntry)], len: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; len];
    let mut stream = ShareEntryWriter::new(&mut buffer);
    for (path, entry) in chunk {
        let header = ShareEntryHeader::new(
            wire_mode(entry.mode),
            wire_kind(entry.kind),
            u32::try_from(path.len()).unwrap_or(u32::MAX),
        );
        if let Err(error) = stream.push(&header, path.as_bytes()) {
            tracing::error!(%error, path, "a share entry could not be encoded");
        }
    }
    let bytes = stream.finish();
    encode(
        &ShareSnapshotPart {
            entries: U32::new(u32::try_from(chunk.len()).unwrap_or(u32::MAX)),
            entries_len: U32::new(u32::try_from(bytes.len()).unwrap_or(u32::MAX)),
        },
        bytes,
    )
}

fn end_frame() -> Vec<u8> {
    encode(
        &ShareSnapshotEnd {
            reserved: U32::ZERO,
        },
        &[],
    )
}

fn added_frame(path: &str, entry: ShareEntry) -> Vec<u8> {
    encode(
        &ShareAdded {
            mode: U16::new(wire_mode(entry.mode)),
            kind: U16::new(wire_kind(entry.kind)),
            path_len: U32::new(u32::try_from(path.len()).unwrap_or(u32::MAX)),
        },
        path.as_bytes(),
    )
}

fn changed_frame(path: &str, entry: ShareEntry) -> Vec<u8> {
    encode(
        &ShareChanged {
            mode: U16::new(wire_mode(entry.mode)),
            kind: U16::new(wire_kind(entry.kind)),
            path_len: U32::new(u32::try_from(path.len()).unwrap_or(u32::MAX)),
        },
        path.as_bytes(),
    )
}

fn removed_frame(path: &str) -> Vec<u8> {
    encode(
        &ShareRemoved {
            path_len: U32::new(u32::try_from(path.len()).unwrap_or(u32::MAX)),
        },
        path.as_bytes(),
    )
}

fn ended_frame(reason: u32) -> Vec<u8> {
    encode(
        &ShareEnded {
            reason: U32::new(reason),
        },
        &[],
    )
}

/// Encodes one notification frame.
///
/// An entry that cannot be encoded is dropped with a log, not allowed to
/// poison a connection: the rule-path cap makes that unreachable, and the one
/// thing a subscriber may never do is cost its session the mount.
fn encode<M: voidport_proto::message::NotificationBody>(body: &M, payload: &[u8]) -> Vec<u8> {
    let mut buffer = vec![0u8; FRAME_HEADER_LEN + size_of::<M>() + payload.len()];
    let mut build = || -> Result<Vec<u8>, FramingError> {
        let mut writer = FrameWriter::notification(&mut buffer, MAX_FRAME_LEN, body)?;
        writer.payload(payload)?;
        Ok(writer.finish()?.to_vec())
    };
    build().unwrap_or_else(|error| {
        tracing::error!(%error, "a share notification could not be encoded");
        Vec::new()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::ShareEntry;

    fn entry(mode: EffectiveMode, kind: ShareKind) -> ShareEntry {
        ShareEntry { mode, kind }
    }

    fn set(entries: &[(&str, EffectiveMode, ShareKind)]) -> ShareSet {
        entries
            .iter()
            .map(|(path, mode, kind)| ((*path).to_owned(), entry(*mode, *kind)))
            .collect()
    }

    /// The opcode of an encoded notification frame.
    fn opcode(frame: &[u8]) -> u16 {
        u16::from_le_bytes([frame[4], frame[5]])
    }

    #[test]
    fn a_diff_names_exactly_what_changed() {
        use voidport_proto::opcode::notifications;

        let before = set(&[
            ("/a", EffectiveMode::Rw, ShareKind::Directory),
            ("/b", EffectiveMode::Ro, ShareKind::Unknown),
        ]);
        let after = set(&[
            // `/a` is gone, `/b` was re-moded in one publish, `/c` is new.
            ("/b", EffectiveMode::Rw, ShareKind::Unknown),
            ("/c", EffectiveMode::Ro, ShareKind::File),
        ]);
        let frames: Vec<u16> = diff_frames(&before, &after)
            .iter()
            .map(|frame| opcode(frame))
            .collect();
        assert_eq!(
            frames,
            vec![
                notifications::SHARE_REMOVED,
                notifications::SHARE_CHANGED,
                notifications::SHARE_ADDED,
            ]
        );
        // An unchanged set produces nothing at all: a publish that does not
        // touch a session's scope is silent for that session.
        assert!(diff_frames(&after, &after).is_empty());
    }

    #[test]
    fn a_snapshot_is_a_begin_some_parts_and_an_end() {
        use voidport_proto::opcode::notifications;

        let frames = snapshot_frames(&set(&[
            ("/a", EffectiveMode::Rw, ShareKind::Directory),
            ("/b", EffectiveMode::Ro, ShareKind::File),
        ]));
        let opcodes: Vec<u16> = frames.iter().map(|frame| opcode(frame)).collect();
        assert_eq!(
            opcodes,
            vec![
                notifications::SHARE_SNAPSHOT_BEGIN,
                notifications::SHARE_SNAPSHOT_PART,
                notifications::SHARE_SNAPSHOT_END,
            ]
        );

        // An empty share set still brackets itself, so a consumer that had
        // entries learns they are all gone.
        let empty: Vec<u16> = snapshot_frames(&ShareSet::new())
            .iter()
            .map(|frame| opcode(frame))
            .collect();
        assert_eq!(
            empty,
            vec![
                notifications::SHARE_SNAPSHOT_BEGIN,
                notifications::SHARE_SNAPSHOT_END,
            ]
        );
    }

    /// A snapshot too large for one frame is chunked, and every part is inside
    /// the bound the session negotiated.
    #[test]
    fn a_large_snapshot_is_chunked_within_the_frame_bound() {
        use voidport_proto::opcode::notifications;

        // Long paths, enough of them to need several parts.
        let long = "b".repeat(3000);
        let entries: ShareSet = (0..2000)
            .map(|index| {
                (
                    format!("/{index:06}{long}"),
                    entry(EffectiveMode::Rw, ShareKind::Directory),
                )
            })
            .collect();
        let frames = snapshot_frames(&entries);
        let parts: Vec<&Vec<u8>> = frames
            .iter()
            .filter(|frame| opcode(frame) == notifications::SHARE_SNAPSHOT_PART)
            .collect();
        assert!(parts.len() > 1, "a snapshot this size needs several parts");
        for part in &parts {
            assert!(
                part.len() <= MAX_FRAME_LEN as usize,
                "a part must fit the frame bound"
            );
        }
        // Every entry is carried exactly once, across however many parts.
        let carried: usize = parts
            .iter()
            .map(|part| {
                let frame = voidport_proto::frame::Frame::parse(part, MAX_FRAME_LEN)
                    .expect("a legal frame");
                frame
                    .notification::<ShareSnapshotPart>()
                    .expect("a part")
                    .entries()
                    .count()
            })
            .sum();
        assert_eq!(carried, entries.len());
    }

    /// The isolation property, exactly as specified: the queue absorbs what it can,
    /// then drops instead of waiting, and the drained lapse asks for a
    /// resnapshot.
    #[tokio::test]
    async fn an_overflowing_queue_lapses_instead_of_blocking() {
        let queue = NotificationQueue::with_depth(4);
        for index in 0..4 {
            queue.push(vec![index]);
        }
        assert!(!queue.is_lapsed());
        // The fifth push does not wait: it drops the queue and lapses.
        queue.push(vec![4]);
        assert!(queue.is_lapsed());
        // Everything queued is gone, and further events are dropped, not
        // queued against a set the consumer never saw.
        queue.push(vec![5]);

        assert!(matches!(queue.next().await, Wake::Lapsed));
        // The lapse is handed out once, so a writer that asks again parks
        // instead of spinning.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), queue.next())
                .await
                .is_err(),
            "an announced lapse is not repeated"
        );

        // The resnapshot clears it and delivers the fresh frames.
        queue.resume(vec![vec![9], vec![10]]);
        assert!(!queue.is_lapsed());
        assert!(matches!(queue.next().await, Wake::Frame(frame) if frame == vec![9]));
        assert!(matches!(queue.next().await, Wake::Frame(frame) if frame == vec![10]));
    }

    /// The end of a stream outranks a lapse, in both orders the writer can
    /// observe one: the subscriber leaves the registry when its namespace does,
    /// so an `ended` a lapsed queue swallowed would leave the consumer waiting
    /// forever for a resnapshot nobody is left to compute.
    #[tokio::test]
    async fn the_end_of_a_stream_survives_a_lapse() {
        use voidport_proto::opcode::notifications;

        // The writer has not looked at the queue yet.
        let queue = NotificationQueue::with_depth(1);
        queue.push(vec![1]);
        queue.push(vec![2]);
        assert!(queue.is_lapsed());
        queue.finish(ended_frame(SHARE_END_NAMESPACE_REMOVED));
        assert!(!queue.is_lapsed(), "the stream is over, not behind");
        assert!(
            matches!(queue.next().await, Wake::Frame(frame) if opcode(&frame) == notifications::SHARE_ENDED)
        );

        // The writer already took the lapse and is off asking for a resnapshot
        // the registry can no longer produce.
        let queue = NotificationQueue::with_depth(1);
        queue.push(vec![1]);
        queue.push(vec![2]);
        assert!(matches!(queue.next().await, Wake::Lapsed));
        queue.finish(ended_frame(SHARE_END_NAMESPACE_REMOVED));
        assert!(
            matches!(queue.next().await, Wake::Frame(frame) if opcode(&frame) == notifications::SHARE_ENDED)
        );
    }

    /// The tombstone race, resolved where it linearizes: the request path
    /// refuses a `Subscribe` on a tombstoned session, but it reads the registry
    /// outside the publish lock, so a deletion landing in that window arrives
    /// here — after its own fan-out has already ended every stream it knew
    /// about. What the late registration may never do is open a stream nothing
    /// can ever end.
    #[tokio::test]
    async fn a_subscribe_that_lost_the_race_to_a_deletion_gets_the_ended_stream() {
        use voidport_proto::opcode::notifications;

        let queue = NotificationQueue::new();
        let subscribers = Subscribers::new();
        // The registry the publish lock hands over no longer holds the name:
        // this is exactly the state a delete publishes.
        let registry = Registry::new();
        let name = NamespaceName::new("gone").expect("a valid name");

        subscribers.register(7, &name, &NamespacePath::root(), &queue, &registry);

        assert!(
            !subscribers.is_subscribed(7),
            "nothing may stay registered against a namespace that is gone"
        );
        assert!(
            matches!(queue.next().await, Wake::Frame(frame) if opcode(&frame) == notifications::SHARE_ENDED),
            "the consumer is told the stream is over, not left waiting"
        );
        // And that is the whole stream: no snapshot, nothing after the end.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), queue.next())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn frames_are_delivered_in_the_order_they_were_enqueued() {
        let queue = NotificationQueue::new();
        for index in 0..16u8 {
            queue.push(vec![index]);
        }
        for index in 0..16u8 {
            assert!(matches!(queue.next().await, Wake::Frame(frame) if frame == vec![index]));
        }
    }
}
