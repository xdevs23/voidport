//! Listening to what a namespace shares.
//!
//! A guest that wants to mount and unmount directories as the operator adds and
//! removes them cannot poll for the answer: the data-plane tree mixes
//! synthesized parents with shared subtrees and nothing in it marks where a
//! shared directory's root begins. The subscription carries that path
//! explicitly, which is what makes the desired mount set knowable at all.
//!
//! It rides the **data plane**, on the mount's own protocol — the guest never
//! holds the operator's control socket — and it is **level-triggered**: every
//! subscription answers a snapshot first and deltas after it, so a consumer
//! reconciles instead of replaying. That is also what makes a reconnect
//! self-healing: the stream re-subscribes over the new connection and the fresh
//! snapshot replaces everything the consumer believed.
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use voidport::client::Client;
//! use voidport::subscribe::{ShareEvent, Subscription};
//! use voidport::url::MountUrl;
//!
//! let url = MountUrl::parse("voidport://127.0.0.1:9000/@project")?;
//! let client = Client::mount(&url.endpoint, url.namespace.as_str(), &url.subpath).await?;
//! let mut shares = Subscription::open(client).await?;
//! while let Some(event) = shares.next().await {
//!     match event {
//!         ShareEvent::Snapshot { entries } => { /* reconcile the whole set */ }
//!         ShareEvent::Added(entry) => { /* mount it */ }
//!         ShareEvent::Removed { path } => { /* unmount it */ }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use rustix::io::Errno;
use tokio::sync::mpsc;
use tokio::sync::watch;
use voidport_proto::frame::{Frame, FrameKind};
use voidport_proto::opcode::NotificationOpcode;
use voidport_proto::ops::share::{
    SHARE_END_NAMESPACE_REMOVED, SHARE_KIND_DIRECTORY, SHARE_KIND_FILE, SHARE_MODE_RW, ShareAdded,
    ShareChanged, ShareEnded, ShareRemoved, ShareSnapshotBegin, ShareSnapshotEnd,
    ShareSnapshotPart,
};

use crate::client::{Caller, Client, MountState};

/// The mode a share is offered with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareMode {
    /// Read-write.
    Rw,
    /// Read-only.
    Ro,
}

impl ShareMode {
    /// The word the CLI prints, and the one the schema fixes.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rw => "rw",
            Self::Ro => "ro",
        }
    }

    /// The mode a wire value names; anything unknown reads as read-only, which
    /// is the safe direction for a consumer that will act on it.
    fn of(raw: u16) -> Self {
        match raw {
            SHARE_MODE_RW => Self::Rw,
            // Read-only for `SHARE_MODE_RO` and for anything this build does
            // not know: a consumer acts on this, so the safe direction is the
            // one that grants less.
            _ => Self::Ro,
        }
    }
}

/// What kind of thing a share's target is.
///
/// [`ShareKind::Unknown`] is not a failure: the server reports a kind only
/// where it already knows one without host I/O, and a consumer treats unknown
/// as try-and-see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareKind {
    /// The server does not know.
    Unknown,
    /// A directory.
    Directory,
    /// A regular file.
    File,
}

impl ShareKind {
    /// The word the CLI prints.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Directory => "directory",
            Self::File => "file",
        }
    }

    fn of(raw: u16) -> Self {
        match raw {
            SHARE_KIND_DIRECTORY => Self::Directory,
            SHARE_KIND_FILE => Self::File,
            _ => Self::Unknown,
        }
    }
}

/// One share the session can see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareEntry {
    /// The path, relative to the session's mount root. Bytes, because host
    /// entry names are bytes.
    pub path: Vec<u8>,
    /// The mode the session sees it with.
    pub mode: ShareMode,
    /// What kind of thing it is, where the server knows.
    pub kind: ShareKind,
}

/// Why a subscription ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// The namespace was deleted. The mount keeps serving its tombstone, but a
    /// frozen tombstone can never change again, so there is nothing left to
    /// report.
    NamespaceRemoved,
    /// The mount itself is gone: it was torn down, or its server is
    /// permanently unreachable.
    MountClosed,
    /// A reason this build does not know. Newer servers may add some.
    Other,
}

impl EndReason {
    /// The word the CLI prints.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NamespaceRemoved => "namespace-removed",
            Self::MountClosed => "mount-closed",
            Self::Other => "other",
        }
    }
}

/// One thing that happened to what the session shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareEvent {
    /// The whole set, replacing everything the consumer believed.
    Snapshot {
        /// Every share the session can see, in path order.
        entries: Vec<ShareEntry>,
    },
    /// A share the session can now see.
    Added(ShareEntry),
    /// A share whose mode or kind changed.
    Changed(ShareEntry),
    /// A share the session can no longer see.
    Removed {
        /// Its path, relative to the mount root.
        path: Vec<u8>,
    },
    /// The server forced a resync: the snapshot that follows replaces
    /// everything.
    Lapsed,
    /// The connection broke away. Nothing arrives until `Resumed`.
    Disconnected,
    /// The connection is back and the subscription has been re-established; a
    /// fresh snapshot follows.
    Resumed,
    /// The stream is over.
    Ended {
        /// Why.
        reason: EndReason,
    },
}

/// A live subscription to what a mount's namespace shares.
///
/// It is the one implementation: the `voidport subscribe` command is written on
/// this type, so every test of the command exercises the library an embedder
/// would use.
#[derive(Debug)]
pub struct Subscription {
    client: Arc<Client>,
    frames: mpsc::UnboundedReceiver<Vec<u8>>,
    changes: watch::Receiver<u64>,
    /// The connection generation the stream is subscribed on, or `None` while
    /// the bracket is open — the mount is not serving, or a re-subscribe has
    /// not succeeded yet.
    ///
    /// The bracket keys on this, not on the phase word, because a watch
    /// receiver coalesces: a connection that died and came back inside one
    /// scheduling gap of this task produces a single wake reading `Connected`,
    /// and a phase-only test would conclude nothing had happened while the
    /// server had already torn the old session — subscription and all — down.
    subscribed: Option<u64>,
    /// The second half of a bracket a single wake owes the consumer, since
    /// [`Self::next`] hands out one event at a time. A flap observed whole
    /// reports `disconnected` and then `resumed`, exactly as a flap observed in
    /// two wakes does.
    pending: Option<ShareEvent>,
    /// Entries accumulated from the parts of the snapshot in flight; `None`
    /// between snapshots.
    building: Option<Vec<ShareEntry>>,
    /// Whether the snapshot in flight was asked for. An unsolicited one is the
    /// lapse signal — there is no lapse message on the wire — and the consumer
    /// is told so before the snapshot that supersedes its world.
    expected: bool,
    /// Nothing further will be produced.
    finished: bool,
    /// Whether this subscription still holds the mount's one notification
    /// routing. Given back exactly once — by [`Self::close`] or by the drop —
    /// so a subscription opened after this one closed is never released by this
    /// one's drop.
    routing: bool,
}

impl Subscription {
    /// Opens a subscription on an established mount.
    ///
    /// **One subscription per mount.** A mount carries one notification stream,
    /// and the server has no way to say which of two consumers a frame belongs
    /// to, so a second subscription on the same [`Client`] is refused, not
    /// allowed to starve the first. A subscription that has been dropped —
    /// or [`closed`](Self::close) — releases the mount for the next one.
    ///
    /// # Errors
    ///
    /// `ENOSYS` from a server that predates the subscription — the connection
    /// survives it, so a probe is safe — `ENOENT` when the namespace has been
    /// deleted, `EBUSY` when this mount already carries a subscription, or
    /// `EIO` on a mount that is not serving.
    pub async fn open(client: Arc<Client>) -> Result<Self, Errno> {
        let (sink, frames) = mpsc::unbounded_channel();
        let changes = client.changes();
        if !client.route_notifications(sink) {
            return Err(Errno::BUSY);
        }
        // Subscribing *after* the sink is installed, so the snapshot the server
        // queues behind its confirm has somewhere to land.
        //
        // The generation comes back from the call instead of being read around
        // it: the replay discipline may carry a written-but-unanswered
        // `Subscribe` across a reconnect, and then the session that holds the
        // subscription is the one that answered, not the one this task last
        // saw. Recording that generation is what keeps the bracket below from
        // re-subscribing on top of the replay and handing the consumer two
        // snapshots for one outage.
        let generation = match client.subscribe_on(Caller::default()).await {
            Ok(generation) => generation,
            Err(errno) => {
                client.release_notifications();
                return Err(errno);
            }
        };
        Ok(Self {
            client,
            frames,
            changes,
            subscribed: Some(generation),
            pending: None,
            building: None,
            expected: true,
            finished: false,
            routing: true,
        })
    }

    /// The next event, or `None` once the stream is over.
    ///
    /// Snapshot parts are aggregated here: a consumer sees one
    /// [`ShareEvent::Snapshot`] however many frames carried it.
    pub async fn next(&mut self) -> Option<ShareEvent> {
        loop {
            if let Some(event) = self.pending.take() {
                return Some(event);
            }
            if self.finished {
                return None;
            }
            tokio::select! {
                frame = self.frames.recv() => {
                    let frame = frame?;
                    if let Some(event) = self.decode(&frame) {
                        return Some(event);
                    }
                }
                changed = self.changes.changed() => {
                    if changed.is_err() {
                        // The mount is gone; so is the stream.
                        self.finished = true;
                        return Some(ShareEvent::Ended { reason: EndReason::MountClosed });
                    }
                    if let Some(event) = self.bracket().await {
                        return Some(event);
                    }
                }
            }
        }
    }

    /// Ends the subscription without ending the mount.
    ///
    /// # Errors
    ///
    /// As [`Self::open`]; a mount that is already gone is not an error to stop
    /// listening to.
    pub async fn close(&mut self) -> Result<(), Errno> {
        self.finished = true;
        self.subscribed = None;
        // Released here as well as on drop, so a consumer that closes and opens
        // another subscription on the same mount is not refused by its own
        // finished stream.
        self.release();
        match self.client.unsubscribe(Caller::default()).await {
            Ok(()) | Err(Errno::IO) => Ok(()),
            Err(errno) => Err(errno),
        }
    }

    /// The `disconnected` / `resumed` bracket, and the resubscription that
    /// closes it.
    ///
    /// The mount's own reconnect machinery does the recovering; this only
    /// reports it and re-establishes the stream on the connection that came
    /// back. A mount that ended for good ends the stream with it.
    ///
    /// It is driven by the *connection generation*, not by the phase word,
    /// because phase changes are coalesced by the watch channel that carries
    /// them: a mount that died and reconnected between two polls of this task
    /// reports `Connected` on the single wake it produces, and only the
    /// generation says that the connection under the stream is a different one.
    /// A subscription is bound to the connection it was made on — the server
    /// drops it when that connection goes — so a changed generation is exactly
    /// the condition to re-subscribe under, and `resumed` is not reported until
    /// that re-subscribe has actually succeeded.
    async fn bracket(&mut self) -> Option<ShareEvent> {
        if self.client.state() == MountState::Closed {
            self.finished = true;
            return Some(ShareEvent::Ended {
                reason: EndReason::MountClosed,
            });
        }
        let live = self.client.connected_generation();
        if live == self.subscribed {
            // Same connection, same subscription: a phase change that did not
            // touch the stream.
            return None;
        }
        // The connection the stream was subscribed on is gone, whether or not
        // this task ever saw the mount leave `Connected`.
        let disconnected = self
            .subscribed
            .take()
            .is_some()
            .then_some(ShareEvent::Disconnected);
        if live.is_none() {
            // Still down. The bracket stays open until a connection comes back.
            return disconnected;
        }
        // The new session is a fresh session: it never subscribed, and
        // `Subscribe` is idempotent, so re-issuing it is exactly the resync the
        // level-triggered consumer needs. The snapshot it answers with is
        // expected, not a lapse.
        self.expected = true;
        self.building = None;
        match self.client.subscribe_on(Caller::default()).await {
            // The connection that *answered*, which a second death during this
            // call makes a different one from the `live` read above: recording
            // anything else would either re-subscribe a session that is already
            // subscribed — a second snapshot the consumer never asked for — or
            // leave a live subscription looking unestablished.
            Ok(answered) => self.subscribed = Some(answered),
            // The namespace was deleted while the mount was away: the session
            // serves its tombstone, which can never change again, so the
            // truthful answer is the same `ended` a live subscriber would have
            // been sent.
            Err(Errno::NOENT) => {
                self.finished = true;
                self.pending = Some(ShareEvent::Ended {
                    reason: EndReason::NamespaceRemoved,
                });
                return disconnected;
            }
            Err(errno) => {
                tracing::warn!(?errno, "the share subscription could not be re-established");
                // The bracket stays open, so the next phase change tries again
                // and the consumer is never told the stream resumed when it did
                // not.
                return disconnected;
            }
        }
        match disconnected {
            // A flap seen whole owes the consumer both halves of its bracket.
            Some(disconnected) => {
                self.pending = Some(ShareEvent::Resumed);
                Some(disconnected)
            }
            None => Some(ShareEvent::Resumed),
        }
    }

    /// Gives the mount's notification routing back, at most once.
    fn release(&mut self) {
        if std::mem::take(&mut self.routing) {
            self.client.release_notifications();
        }
    }

    /// Turns one notification frame into an event, where it produces one.
    ///
    /// A snapshot part produces nothing on its own; the `end` marker is what
    /// hands the aggregated snapshot over. A frame this build does not
    /// understand is ignored, which is what the wire contract asks of a
    /// receiver in the notification range.
    fn decode(&mut self, bytes: &[u8]) -> Option<ShareEvent> {
        let frame = Frame::parse(bytes, self.client.max_frame_len()).ok()?;
        if frame.kind() != FrameKind::Notification {
            return None;
        }
        match frame.notification_opcode().ok()? {
            NotificationOpcode::ShareSnapshotBegin => {
                let begin = frame.notification::<ShareSnapshotBegin>().ok()?;
                self.building = Some(Vec::with_capacity(begin.body().entries.get() as usize));
                // An unsolicited snapshot *is* the lapse signal; there is no
                // lapse message on the wire.
                if self.expected {
                    self.expected = false;
                    None
                } else {
                    Some(ShareEvent::Lapsed)
                }
            }
            NotificationOpcode::ShareSnapshotPart => {
                let part = frame.notification::<ShareSnapshotPart>().ok()?;
                let building = self.building.as_mut()?;
                for entry in part.entries() {
                    let entry = entry.ok()?;
                    building.push(ShareEntry {
                        path: entry.tail.to_vec(),
                        mode: ShareMode::of(entry.header.mode.get()),
                        kind: ShareKind::of(entry.header.kind.get()),
                    });
                }
                None
            }
            NotificationOpcode::ShareSnapshotEnd => {
                frame.notification::<ShareSnapshotEnd>().ok()?;
                let entries = self.building.take()?;
                Some(ShareEvent::Snapshot { entries })
            }
            NotificationOpcode::ShareAdded => {
                let event = frame.notification::<ShareAdded>().ok()?;
                Some(ShareEvent::Added(ShareEntry {
                    path: event.path().to_vec(),
                    mode: ShareMode::of(event.body().mode.get()),
                    kind: ShareKind::of(event.body().kind.get()),
                }))
            }
            NotificationOpcode::ShareChanged => {
                let event = frame.notification::<ShareChanged>().ok()?;
                Some(ShareEvent::Changed(ShareEntry {
                    path: event.path().to_vec(),
                    mode: ShareMode::of(event.body().mode.get()),
                    kind: ShareKind::of(event.body().kind.get()),
                }))
            }
            NotificationOpcode::ShareRemoved => {
                let event = frame.notification::<ShareRemoved>().ok()?;
                Some(ShareEvent::Removed {
                    path: event.path().to_vec(),
                })
            }
            NotificationOpcode::ShareEnded => {
                let event = frame.notification::<ShareEnded>().ok()?;
                self.finished = true;
                Some(ShareEvent::Ended {
                    reason: match event.body().reason.get() {
                        SHARE_END_NAMESPACE_REMOVED => EndReason::NamespaceRemoved,
                        _ => EndReason::Other,
                    },
                })
            }
        }
    }
}

impl Drop for Subscription {
    /// A subscription that is gone no longer holds the mount's one notification
    /// stream, so the next [`Subscription::open`] on the same mount succeeds.
    ///
    /// It does not unsubscribe the session: that is a request, this is a drop,
    /// and the server drops the subscription with the connection anyway. What a
    /// consumer wants ended *now* it ends with [`Subscription::close`].
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use voidport_proto::ops::share::SHARE_MODE_RO;

    #[test]
    fn wire_values_map_to_the_documented_vocabulary() {
        assert_eq!(ShareMode::of(SHARE_MODE_RW).as_str(), "rw");
        assert_eq!(ShareMode::of(SHARE_MODE_RO).as_str(), "ro");
        // An unknown mode reads as the safer of the two, not as a panic.
        assert_eq!(ShareMode::of(0), ShareMode::Ro);

        assert_eq!(ShareKind::of(SHARE_KIND_DIRECTORY).as_str(), "directory");
        assert_eq!(ShareKind::of(SHARE_KIND_FILE).as_str(), "file");
        assert_eq!(ShareKind::of(0).as_str(), "unknown");
        assert_eq!(ShareKind::of(9).as_str(), "unknown");

        assert_eq!(EndReason::NamespaceRemoved.as_str(), "namespace-removed");
        assert_eq!(EndReason::MountClosed.as_str(), "mount-closed");
    }
}
