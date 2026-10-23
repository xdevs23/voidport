//! The mutation path never blocks on a subscriber: pushing is a short mutex and
//! a wakeup, and a queue that fills is dropped, never waited on. The consumer
//! learns of the lapse from an unsolicited snapshot.
//!
//! Registration and publication both run under the write lock of the published
//! snapshot, so every delta a subscriber receives comes after its snapshot.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::Notify;
use voidport_control::NamespaceName;
use voidport_proto::error::FramingError;
use voidport_proto::frame::FrameWriter;
use voidport_proto::limits::LIMITS;
use voidport_proto::ops::recall::Recall;
use voidport_proto::ops::share::{
    SHARE_END_NAMESPACE_REMOVED, SHARE_KIND_DIRECTORY, SHARE_KIND_FILE, SHARE_KIND_UNKNOWN,
    SHARE_MODE_RO, SHARE_MODE_RW, ShareAdded, ShareChanged, ShareEnded, ShareEntryHeader,
    ShareRemoved, ShareSnapshotBegin, ShareSnapshotEnd,
};
use zerocopy::IntoBytes as _;
use zerocopy::byteorder::little_endian::{U16, U32, U64};

use crate::registry::Registry;
use crate::rules::{EffectiveMode, NamespacePath};
use crate::share::{ShareEntry, ShareKind, ShareSet, share_set};

/// A handoff depth: a consumer that drains at all never reaches it. Sized so an
/// ordinary burst of control-plane edits is absorbed whole.
pub const NOTIFICATION_QUEUE_DEPTH: usize = 256;

#[derive(Debug)]
pub enum Notice {
    /// A notification frame, whole. It bypasses request-id retirement: a
    /// notification replies to no request.
    Frame(Vec<u8>),
    Part(Vec<(String, ShareEntry)>),
}

#[derive(Debug)]
pub enum Wake {
    Notice(Notice),
    /// The queue overflowed and was dropped. The task sends the consumer a fresh
    /// snapshot.
    Lapsed,
}

#[derive(Debug)]
pub struct NotificationQueue {
    state: Mutex<QueueState>,
    ready: Notify,
}

#[derive(Debug)]
struct QueueState {
    recalls: std::collections::VecDeque<Vec<u8>>,
    frames: std::collections::VecDeque<Notice>,
    lapsed: bool,
    /// The lapse has been handed to the writer, so it is not handed out again
    /// while the writer computes the resnapshot.
    announced: bool,
}

impl NotificationQueue {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueueState {
                recalls: std::collections::VecDeque::new(),
                frames: std::collections::VecDeque::new(),
                lapsed: false,
                announced: false,
            }),
            ready: Notify::new(),
        })
    }

    /// Called from the publish path, which holds the write lock of the published
    /// snapshot, so it never waits and never allocates more than the frame.
    pub fn push(&self, frame: Vec<u8>) {
        self.push_notice(Notice::Frame(frame));
    }

    pub fn recall(&self, node_id: u64, recall: u64) {
        let frame = encode(
            &Recall {
                node_id: U64::new(node_id),
                recall: U64::new(recall),
            },
            &[],
        );
        self.locked().recalls.push_back(frame);
        self.ready.notify_one();
    }

    fn push_notice(&self, notice: Notice) {
        let mut state = self.locked();
        if state.lapsed {
            // A delta relative to a set the consumer never received would be
            // wrong. The pending resnapshot replaces it.
            return;
        }
        if state.frames.len() >= NOTIFICATION_QUEUE_DEPTH {
            state.frames.clear();
            state.lapsed = true;
            state.announced = false;
            drop(state);
            self.ready.notify_one();
            return;
        }
        state.frames.push_back(notice);
        drop(state);
        self.ready.notify_one();
    }

    /// A terminal frame is not a delta, so the rule that drops deltas while
    /// lapsed must not drop it: the only thing that ends a stream is the
    /// subscriber leaving the registry, which the resnapshot of a lapse is
    /// computed from, so a dropped `ended` leaves a consumer waiting forever.
    /// The lapse is cleared with it, because the stream being over supersedes
    /// everything the lapse dropped.
    fn finish(&self, frame: Vec<u8>) {
        let mut state = self.locked();
        if state.lapsed {
            state.frames.clear();
            state.lapsed = false;
            state.announced = false;
        }
        state.frames.push_back(Notice::Frame(frame));
        drop(state);
        self.ready.notify_one();
    }

    /// Called under the publish lock, so the set the notices describe and the
    /// set the registry now records for this subscriber are the same set.
    fn resume(&self, frames: Vec<Notice>) {
        let mut state = self.locked();
        state.frames.clear();
        state.lapsed = false;
        state.announced = false;
        state.frames.extend(frames);
        drop(state);
        self.ready.notify_one();
    }

    /// Waits for the next thing the notification task must do. It parks when
    /// there is nothing; the shutdown of the connection ends the task, not this
    /// queue.
    pub async fn next(&self) -> Wake {
        loop {
            // Registered before the state is examined, so a push arriving between
            // the two is not missed.
            let waiting = self.ready.notified();
            {
                let mut state = self.locked();
                if let Some(recall) = state.recalls.pop_front() {
                    return Wake::Notice(Notice::Frame(recall));
                }
                if let Some(notice) = state.frames.pop_front() {
                    return Wake::Notice(notice);
                }
                if state.lapsed && !state.announced {
                    state.announced = true;
                    return Wake::Lapsed;
                }
            }
            waiting.await;
        }
    }

    fn locked(&self) -> MutexGuard<'_, QueueState> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// Only changed under the write lock of
/// [`Published`](crate::control::service::Published) by registration and
/// publication, plus the lock-free [`is_subscribed`](Self::is_subscribed) the
/// session list reads.
#[derive(Debug, Default)]
pub struct Subscribers {
    state: Mutex<BTreeMap<u64, Subscriber>>,
}

#[derive(Debug)]
struct Subscriber {
    name: NamespaceName,
    subpath: NamespacePath,
    queue: Arc<NotificationQueue>,
    /// A delta is the difference between this and a fresh computation, so an
    /// event is a function of the session-scoped set, not of the raw table.
    entries: ShareSet,
}

impl Subscribers {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Re-registration is the resync path of the consumer: the stored set is
    /// replaced by a fresh one and a fresh snapshot is queued.
    ///
    /// The caller holds the write lock of the published snapshot, which makes
    /// capturing the table and registering the subscriber one atomic step with
    /// respect to publish.
    ///
    /// A namespace that has left the registry ends the stream here instead of
    /// opening one. The request path reads the registry outside this lock, so a
    /// namespace deleted in that window arrives here after the fan-out of its
    /// deletion ended every stream it knew about. Registering then would leave a
    /// consumer with a stream nothing can ever end.
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

    /// A session that has none is untouched, which makes `Unsubscribe` a plain
    /// success.
    pub fn unregister(&self, id: u64) {
        self.locked().remove(&id);
    }

    #[must_use]
    pub fn is_subscribed(&self, id: u64) -> bool {
        self.locked().contains_key(&id)
    }

    /// Runs under the publish lock like every other snapshot, so the set the
    /// consumer receives and the set the registry records for it are the same.
    pub fn refresh(&self, id: u64, registry: &Registry) {
        let mut subscribers = self.locked();
        let Some(subscriber) = subscribers.get_mut(&id) else {
            return;
        };
        // No subscriber outlives its namespace.
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

    /// The entry set of each subscriber is recomputed and diffed against the set
    /// last sent to it, so an edit reaches exactly the sessions whose scope it
    /// changes.
    ///
    /// A namespace that has left the registry ends the streams of its subscribers
    /// with a final `ended` event: a frozen tombstone can never change again.
    pub fn republish(&self, registry: &Registry) {
        let mut subscribers = self.locked();
        let mut ended = Vec::new();
        for (id, subscriber) in subscribers.iter_mut() {
            let Some(namespace) = registry.get(&subscriber.name) else {
                // Through `finish`, not `push`: the subscriber is about to leave
                // the registry, so a lapsed queue that swallowed this frame could
                // never be resnapshotted either.
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

/// An entry whose path is longer than the kernel accepts for a path is left out,
/// with a log, because a receiver would refuse its piece. The count the begin
/// contains is the count the part contains. An empty share set still brackets
/// itself, with no part between.
fn snapshot_frames(entries: &ShareSet) -> Vec<Notice> {
    let longest = LIMITS.path_max.saturating_sub(1) as usize;
    let carried: Vec<(String, ShareEntry)> = entries
        .iter()
        .filter(|(path, _)| {
            let fits = path.len() <= longest;
            if !fits {
                tracing::error!(path, "a share path is longer than a path can be carried");
            }
            fits
        })
        .map(|(path, entry)| (path.clone(), *entry))
        .collect();
    let mut notices = vec![Notice::Frame(begin_frame(carried.len()))];
    if !carried.is_empty() {
        notices.push(Notice::Part(carried));
    }
    notices.push(Notice::Frame(end_frame()));
    notices
}

#[must_use]
pub fn encode_entry(path: &str, entry: &ShareEntry, piece: &mut [u8]) -> Option<usize> {
    let header = ShareEntryHeader::new(
        wire_mode(entry.mode),
        wire_kind(entry.kind),
        u32::try_from(path.len()).ok()?,
    );
    let header = header.as_bytes();
    let len = header.len() + path.len();
    let slot = piece.get_mut(..len)?;
    slot[..header.len()].copy_from_slice(header);
    slot[header.len()..].copy_from_slice(path.as_bytes());
    Some(len)
}

/// An entry only in `previous` was removed, one only in `current` was added,
/// and one in both whose mode or kind differs changed. A two-operation re-mode,
/// a remove followed by an add, arrives as the two publishes it was.
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

fn wire_mode(mode: EffectiveMode) -> u16 {
    match mode {
        EffectiveMode::Rw => SHARE_MODE_RW,
        EffectiveMode::Ro => SHARE_MODE_RO,
    }
}

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

/// An entry that cannot be encoded is dropped with a log, not allowed to poison
/// a connection: a subscriber must never cost its session the mount.
fn encode<M: voidport_proto::message::NotificationBody>(body: &M, payload: &[u8]) -> Vec<u8> {
    let mut buffer = vec![0u8; FrameWriter::notification_len::<M>(payload.len())];
    let mut build = || -> Result<Vec<u8>, FramingError> {
        let mut writer = FrameWriter::notification(&mut buffer, &LIMITS, body)?;
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

    fn opcode(frame: &[u8]) -> u16 {
        u16::from_le_bytes([frame[0], frame[1]])
    }

    fn notice_opcode(notice: &Notice) -> u16 {
        match notice {
            Notice::Frame(frame) => opcode(frame),
            Notice::Part(_) => voidport_proto::opcode::notifications::SHARE_SNAPSHOT_PART,
        }
    }

    fn frame(byte: u8) -> Vec<u8> {
        vec![byte]
    }

    fn full_queue() -> Arc<NotificationQueue> {
        let queue = NotificationQueue::new();
        for _ in 0..NOTIFICATION_QUEUE_DEPTH {
            queue.push(frame(0));
        }
        queue
    }

    fn lapsed(queue: &NotificationQueue) -> bool {
        queue.locked().lapsed
    }

    fn is_frame(wake: &Wake, expected: &[u8]) -> bool {
        matches!(wake, Wake::Notice(Notice::Frame(frame)) if frame == expected)
    }

    #[test]
    fn a_diff_names_exactly_what_changed() {
        use voidport_proto::opcode::notifications;

        let before = set(&[
            ("/a", EffectiveMode::Rw, ShareKind::Directory),
            ("/b", EffectiveMode::Ro, ShareKind::Unknown),
        ]);
        let after = set(&[
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
        assert!(diff_frames(&after, &after).is_empty());
    }

    #[test]
    fn a_snapshot_is_a_begin_some_parts_and_an_end() {
        use voidport_proto::opcode::notifications;

        let frames = snapshot_frames(&set(&[
            ("/a", EffectiveMode::Rw, ShareKind::Directory),
            ("/b", EffectiveMode::Ro, ShareKind::File),
        ]));
        let opcodes: Vec<u16> = frames.iter().map(notice_opcode).collect();
        assert_eq!(
            opcodes,
            vec![
                notifications::SHARE_SNAPSHOT_BEGIN,
                notifications::SHARE_SNAPSHOT_PART,
                notifications::SHARE_SNAPSHOT_END,
            ]
        );

        let empty: Vec<u16> = snapshot_frames(&ShareSet::new())
            .iter()
            .map(notice_opcode)
            .collect();
        assert_eq!(
            empty,
            vec![
                notifications::SHARE_SNAPSHOT_BEGIN,
                notifications::SHARE_SNAPSHOT_END,
            ]
        );
    }

    #[test]
    fn a_large_snapshot_is_one_part_carrying_every_entry() {
        use voidport_proto::opcode::notifications;

        let long = "b".repeat(3000);
        let entries: ShareSet = (0..2000)
            .map(|index| {
                (
                    format!("/{index:06}{long}"),
                    entry(EffectiveMode::Rw, ShareKind::Directory),
                )
            })
            .collect();
        let notices = snapshot_frames(&entries);
        let parts: Vec<&Vec<(String, ShareEntry)>> = notices
            .iter()
            .filter_map(|notice| match notice {
                Notice::Part(entries) => Some(entries),
                Notice::Frame(frame) => {
                    assert_ne!(opcode(frame), notifications::SHARE_SNAPSHOT_PART);
                    None
                }
            })
            .collect();
        assert_eq!(parts.len(), 1, "one part, whatever the size");
        assert_eq!(parts[0].len(), entries.len());
        let mut piece = vec![0u8; size_of::<ShareEntryHeader>() + LIMITS.path_max as usize];
        for (path, entry) in parts[0] {
            let len = encode_entry(path, entry, &mut piece).expect("an entry fits its piece");
            assert_eq!(len, size_of::<ShareEntryHeader>() + path.len());
        }
    }

    #[test]
    fn a_path_longer_than_a_path_can_be_is_left_out_of_the_snapshot() {
        let long = format!("/{}", "c".repeat(LIMITS.path_max as usize));
        let entries = set(&[
            ("/a", EffectiveMode::Rw, ShareKind::Directory),
            (&long, EffectiveMode::Ro, ShareKind::File),
        ]);
        let notices = snapshot_frames(&entries);
        let Some(Notice::Part(carried)) = notices.get(1) else {
            panic!("a part follows the begin");
        };
        assert_eq!(carried.len(), 1);
        let Notice::Frame(begin) = &notices[0] else {
            panic!("the begin is a frame");
        };
        let frame = voidport_proto::frame::Frame::parse(begin, &LIMITS).expect("a frame");
        assert_eq!(
            frame
                .notification::<ShareSnapshotBegin>()
                .expect("a begin")
                .body()
                .entries
                .get(),
            1
        );
    }

    #[tokio::test]
    async fn an_overflowing_queue_lapses_instead_of_blocking() {
        let queue = full_queue();
        assert!(!lapsed(&queue));
        queue.push(frame(1));
        assert!(lapsed(&queue));
        queue.push(frame(2));

        assert!(matches!(queue.next().await, Wake::Lapsed));
        let mut next = std::pin::pin!(queue.next());
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(next.as_mut().poll(cx).is_pending())
            })
            .await,
            "an announced lapse is not repeated"
        );

        queue.resume(vec![Notice::Frame(frame(9)), Notice::Frame(frame(10))]);
        assert!(!lapsed(&queue));
        assert!(is_frame(&next.await, &[9]));
        assert!(is_frame(&queue.next().await, &[10]));
    }

    /// The end of a stream outranks a lapse in both orders the writer can
    /// observe one: an `ended` swallowed by a lapsed queue would leave the
    /// consumer waiting forever for a resnapshot nobody is left to compute.
    #[tokio::test]
    async fn the_end_of_a_stream_survives_a_lapse() {
        use voidport_proto::opcode::notifications;

        let queue = full_queue();
        queue.push(frame(1));
        assert!(lapsed(&queue));
        queue.finish(ended_frame(SHARE_END_NAMESPACE_REMOVED));
        assert!(!lapsed(&queue), "the stream is over, not behind");
        assert!(
            matches!(queue.next().await, Wake::Notice(Notice::Frame(frame)) if opcode(&frame) == notifications::SHARE_ENDED)
        );

        let queue = full_queue();
        queue.push(frame(1));
        assert!(matches!(queue.next().await, Wake::Lapsed));
        queue.finish(ended_frame(SHARE_END_NAMESPACE_REMOVED));
        assert!(
            matches!(queue.next().await, Wake::Notice(Notice::Frame(frame)) if opcode(&frame) == notifications::SHARE_ENDED)
        );
    }

    #[tokio::test]
    async fn a_subscribe_that_lost_the_race_to_a_deletion_gets_the_ended_stream() {
        use voidport_proto::opcode::notifications;

        let queue = NotificationQueue::new();
        let subscribers = Subscribers::new();
        let registry = Registry::new();
        let name = NamespaceName::new("gone").expect("a valid name");

        subscribers.register(7, &name, &NamespacePath::root(), &queue, &registry);

        assert!(
            !subscribers.is_subscribed(7),
            "nothing may stay registered against a namespace that is gone"
        );
        assert!(
            matches!(queue.next().await, Wake::Notice(Notice::Frame(frame)) if opcode(&frame) == notifications::SHARE_ENDED),
            "the consumer is told the stream is over, not left waiting"
        );
        let mut next = std::pin::pin!(queue.next());
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(next.as_mut().poll(cx).is_pending())
            })
            .await
        );
    }

    #[tokio::test]
    async fn frames_are_delivered_in_the_order_they_were_enqueued() {
        let queue = NotificationQueue::new();
        for index in 0..16u8 {
            queue.push(frame(index));
        }
        for index in 0..16u8 {
            assert!(is_frame(&queue.next().await, &[index]));
        }
    }
}
