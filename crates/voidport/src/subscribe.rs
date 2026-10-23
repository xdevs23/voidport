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
use voidport_proto::limits::{LIMITS, Part};
use voidport_proto::opcode::NotificationOpcode;
use voidport_proto::ops::recall::Recall as RecallBody;
use voidport_proto::ops::share::{
    SHARE_END_NAMESPACE_REMOVED, SHARE_KIND_DIRECTORY, SHARE_KIND_FILE, SHARE_MODE_RW, ShareAdded,
    ShareChanged, ShareEnded, ShareEntryHeader, ShareRemoved, ShareSnapshotBegin, ShareSnapshotEnd,
    ShareSnapshotPart,
};
use voidport_proto::piece;

use crate::client::{Caller, Client, MountState, Notice};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareMode {
    Rw,
    Ro,
}

impl ShareMode {
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
            _ => Self::Ro,
        }
    }
}

/// [`ShareKind::Unknown`] is not a failure: the server reports a kind only where
/// it already knows one without host I/O, and a consumer treats unknown as
/// try-and-see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareKind {
    Unknown,
    Directory,
    File,
}

impl ShareKind {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareEntry {
    pub path: Vec<u8>,
    pub mode: ShareMode,
    pub kind: ShareKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// The mount keeps serving the tombstone of the deleted namespace, which can
    /// never change again, so nothing is left to report.
    NamespaceRemoved,
    MountClosed,
    Other,
}

impl EndReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NamespaceRemoved => "namespace-removed",
            Self::MountClosed => "mount-closed",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareEvent {
    Snapshot {
        entries: Vec<ShareEntry>,
    },
    Added(ShareEntry),
    Changed(ShareEntry),
    Removed {
        path: Vec<u8>,
    },
    Lapsed,
    /// The connection broke away. Nothing arrives until `Resumed`.
    Disconnected,
    Resumed,
    Ended {
        reason: EndReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recall {
    pub node_id: u64,
    pub recall: u64,
}

#[derive(Debug)]
pub struct Subscription {
    client: Arc<Client>,
    frames: mpsc::UnboundedReceiver<Notice>,
    changes: watch::Receiver<u64>,
    /// The session generation and the id of the connection the stream is
    /// subscribed on, or `None` while the bracket is open. The bracket keys on
    /// this and not on the phase word, because a watch receiver coalesces: a
    /// session that ended and came back inside one scheduling gap of this task
    /// produces a single wake reading `Connected`. The connection id is part of
    /// the key because a subscription belongs to the connection it was made on.
    subscribed: Option<(u64, u64)>,
    /// The second half of a bracket that a single wake owes the consumer, since
    /// [`Self::next`] hands out one event at a time.
    pending: Option<ShareEvent>,
    building: Option<Vec<ShareEntry>>,
    /// An unsolicited snapshot is the lapse signal, because the wire has no
    /// lapse message.
    expected: bool,
    finished: bool,
    /// Given back exactly once, by [`Self::close`] or by the drop, so a
    /// subscription opened after this one closed is never released by this one's
    /// drop.
    routing: bool,
    /// Without it the recalls are dropped.
    recalls: Option<mpsc::UnboundedSender<Recall>>,
}

impl Subscription {
    /// A mount carries one notification stream, and the server has no way to
    /// say which of two consumers a frame belongs to. A second subscription on
    /// the same [`Client`] therefore fails, so that it cannot starve the first.
    /// A dropped or [closed](Self::close) subscription releases the mount for
    /// the next one.
    ///
    /// # Errors
    ///
    /// `ENOENT` when the namespace has been deleted, `EBUSY` when this mount
    /// already carries a subscription, or `EIO` on a mount that is not serving.
    pub async fn open(client: Arc<Client>) -> Result<Self, Errno> {
        Self::open_with(client, None).await
    }

    pub async fn open_recalling(
        client: Arc<Client>,
        recalls: mpsc::UnboundedSender<Recall>,
    ) -> Result<Self, Errno> {
        Self::open_with(client, Some(recalls)).await
    }

    async fn open_with(
        client: Arc<Client>,
        recalls: Option<mpsc::UnboundedSender<Recall>>,
    ) -> Result<Self, Errno> {
        let (sink, frames) = mpsc::unbounded_channel();
        let changes = client.changes();
        if !client.route_notifications(sink) {
            return Err(Errno::BUSY);
        }
        // Subscribing after the sink is installed, so the snapshot the server
        // sends after its confirm has a receiver.
        //
        // The generation comes back from the call instead of being read around
        // it: the replay may carry a written-but-unanswered `Subscribe` across a
        // reconnect, and then the session that holds the subscription is the one
        // that answered. Recording that generation stops the bracket below from
        // re-subscribing on top of the replay and handing the consumer two
        // snapshots for one outage.
        let key = match client.subscribe_on(Caller::default()).await {
            Ok(key) => key,
            Err(errno) => {
                client.release_notifications();
                return Err(errno);
            }
        };
        Ok(Self {
            client,
            frames,
            changes,
            subscribed: Some(key),
            pending: None,
            building: None,
            expected: true,
            finished: false,
            routing: true,
            recalls,
        })
    }

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

    /// A mount that is already gone is not an error to stop listening to.
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

    /// The server drops a subscription when the connection it was made on goes
    /// while the session lives on, so a changed key means a re-subscribe, and
    /// `resumed` is reported only once the re-subscribe has succeeded.
    async fn bracket(&mut self) -> Option<ShareEvent> {
        if self.client.state() == MountState::Closed {
            self.finished = true;
            return Some(ShareEvent::Ended {
                reason: EndReason::MountClosed,
            });
        }
        let live = self.client.subscription_key();
        if live.is_some() && live == self.subscribed {
            return None;
        }
        let disconnected = self
            .subscribed
            .take()
            .is_some()
            .then_some(ShareEvent::Disconnected);
        if self.client.connected_generation().is_none() {
            return disconnected;
        }
        // The new session or connection holds no subscription, and `Subscribe`
        // is idempotent, so re-issuing it is the resync that the level-triggered
        // consumer needs. The snapshot it answers with is expected, not a lapse.
        self.expected = true;
        self.building = None;
        match self.client.subscribe_on(Caller::default()).await {
            // The connection that *answered*, which a second death during this
            // call makes a different one from the `live` read above. Recording
            // anything else would either re-subscribe a session that is already
            // subscribed, with a second snapshot the consumer never asked for,
            // or leave a live subscription looking unestablished.
            Ok(answered) => self.subscribed = Some(answered),
            // The namespace was deleted while the mount was away: the session
            // serves its tombstone, which can never change again, so the
            // consumer gets the same `ended` a live subscriber would have been
            // sent.
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

    fn release(&mut self) {
        if std::mem::take(&mut self.routing) {
            self.client.release_notifications();
        }
    }

    /// A snapshot part produces nothing on its own. The `end` marker hands the
    /// aggregated snapshot over, and the entries streamed after it arrive here
    /// one notice each.
    fn decode(&mut self, notice: &Notice) -> Option<ShareEvent> {
        let bytes = match notice {
            Notice::Message(bytes) => bytes,
            Notice::Entry(entry) => {
                self.take_entry(entry);
                return None;
            }
        };
        let frame = Frame::parse(bytes, &LIMITS).ok()?;
        if frame.kind() != FrameKind::Notification {
            return None;
        }
        match frame.notification_opcode().ok()? {
            NotificationOpcode::ShareSnapshotBegin => {
                let begin = frame.notification::<ShareSnapshotBegin>().ok()?;
                self.building = Some(Vec::with_capacity(begin.body().entries.get() as usize));
                if self.expected {
                    self.expected = false;
                    None
                } else {
                    Some(ShareEvent::Lapsed)
                }
            }
            NotificationOpcode::ShareSnapshotPart => {
                frame.notification::<ShareSnapshotPart>().ok()?;
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
            NotificationOpcode::Recall => {
                let recall = frame.notification::<RecallBody>().ok()?;
                if let Some(recalls) = &self.recalls {
                    let _ = recalls.send(Recall {
                        node_id: recall.body().node_id.get(),
                        recall: recall.body().recall.get(),
                    });
                }
                None
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

    /// An entry outside a snapshot, or a notice that is not exactly one
    /// well-formed entry, adds nothing.
    fn take_entry(&mut self, entry: &[u8]) {
        let Some(building) = self.building.as_mut() else {
            return;
        };
        let longest_path = LIMITS
            .bound(Part::Path)
            .expect("a path part always has a bound");
        let Ok(entry) = piece::entry::<ShareEntryHeader>(entry, longest_path) else {
            return;
        };
        building.push(ShareEntry {
            path: entry.tail.to_vec(),
            mode: ShareMode::of(entry.header.mode.get()),
            kind: ShareKind::of(entry.header.kind.get()),
        });
    }
}

impl Drop for Subscription {
    /// It does not unsubscribe the session, because the server drops the
    /// subscription with the connection anyway. A consumer that wants the
    /// subscription ended calls [`Subscription::close`].
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
        assert_eq!(ShareMode::of(0), ShareMode::Ro);

        assert_eq!(ShareKind::of(SHARE_KIND_DIRECTORY).as_str(), "directory");
        assert_eq!(ShareKind::of(SHARE_KIND_FILE).as_str(), "file");
        assert_eq!(ShareKind::of(0).as_str(), "unknown");
        assert_eq!(ShareKind::of(9).as_str(), "unknown");

        assert_eq!(EndReason::NamespaceRemoved.as_str(), "namespace-removed");
        assert_eq!(EndReason::MountClosed.as_str(), "mount-closed");
    }
}
