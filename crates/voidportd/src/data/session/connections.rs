//! The session records no retired ids: an id it gave out and no longer
//! holds was retired or closed with nothing read, and the counter alone tells
//! it from an id never given out.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use rustix::io::Errno;
use tokio::sync::watch;
use voidport_memory::{Buffer, Memory, Refused};

use super::Session;
use crate::data::sessions::{Registered, id_after};
use crate::data::subscribe::NotificationQueue;

#[derive(Debug)]
pub struct Link {
    id: u64,
    stop: watch::Sender<bool>,
    ended: watch::Sender<bool>,
    queue: Arc<NotificationQueue>,
    record: Mutex<Record>,
    /// Held by the stop signal, by a grant made for a request of this
    /// connection and by the installation of a subscription on it, so each of
    /// them and the close come in one order.
    closing: Mutex<()>,
}

#[derive(Debug, Default)]
struct Record {
    last_read: Option<u64>,
    kept: Option<(u64, Kept)>,
}

#[derive(Clone, Debug)]
pub enum Kept {
    /// It never started, and cannot start any more once its connection is
    /// closed.
    NotStarted,
    Replied(Arc<Buffer>),
}

#[derive(Clone, Debug)]
pub enum Outcome {
    NotStarted,
    Applied,
    Replied(Arc<Buffer>),
}

impl Link {
    #[must_use]
    pub(crate) fn new(id: u64) -> Self {
        Self {
            id,
            stop: watch::channel(false).0,
            ended: watch::channel(false).0,
            queue: NotificationQueue::new(),
            record: Mutex::default(),
            closing: Mutex::default(),
        }
    }

    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    #[must_use]
    pub fn queue(&self) -> &Arc<NotificationQueue> {
        &self.queue
    }

    pub fn stop(&self) {
        let _ordered = self.ordered();
        self.stop.send_replace(true);
    }

    /// The close and the grant are ordered: a close recorded before the grant
    /// means the grant is never made, and one recorded after it finds it made.
    pub fn unless_closed<R>(&self, grant: impl FnOnce() -> R) -> Option<R> {
        let _ordered = self.ordered();
        if *self.stop.borrow() {
            return None;
        }
        Some(grant())
    }

    fn ordered(&self) -> MutexGuard<'_, ()> {
        self.closing
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    #[must_use]
    pub fn stopped(&self) -> watch::Receiver<bool> {
        self.stop.subscribe()
    }

    pub fn end(&self) {
        self.ended.send_replace(true);
    }

    pub async fn ended(&self) {
        let mut ended = self.ended.subscribe();
        let _ = ended.wait_for(|ended| *ended).await;
    }

    fn read_any(&self) -> bool {
        self.locked().last_read.is_some()
    }

    /// A request of the settled classes starts out as not started, and its
    /// reply replaces that once it has one.
    pub fn read(&self, request_id: u64, settled: bool) {
        let mut record = self.locked();
        record.last_read = Some(request_id);
        record.kept = settled.then_some((request_id, Kept::NotStarted));
    }

    /// On a connection with several requests at once, each kept outcome
    /// replaces the one before, and such a client never asks.
    pub fn keep(&self, request_id: u64, kept: Kept) {
        self.locked().kept = Some((request_id, kept));
    }

    #[must_use]
    pub fn outcome(&self, request_id: u64) -> Outcome {
        let record = self.locked();
        if record.last_read.is_none_or(|last| request_id > last) {
            return Outcome::NotStarted;
        }
        match &record.kept {
            Some((kept, Kept::NotStarted)) if *kept == request_id => Outcome::NotStarted,
            Some((kept, Kept::Replied(reply))) if *kept == request_id => {
                Outcome::Replied(Arc::clone(reply))
            }
            _ => Outcome::Applied,
        }
    }

    fn locked(&self) -> MutexGuard<'_, Record> {
        self.record
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

#[derive(Debug, Default)]
pub(super) struct Connections {
    last_id: u64,
    open: usize,
    /// A map that can reserve room without aborting, which is how a joining
    /// connection is added.
    links: HashMap<u64, Arc<Link>>,
    registration: Option<Registered>,
    subscriber: Option<u64>,
    ended: bool,
}

impl Connections {
    fn add_link(&mut self) -> Result<Result<Arc<Link>, Errno>, Refused> {
        if self.ended {
            return Ok(Err(Errno::NOENT));
        }
        let id = match id_after(self.last_id) {
            Ok(id) => id,
            Err(overflow) => return Ok(Err(overflow)),
        };
        self.links.try_reserve(1).map_err(|_| Refused)?;
        // Arc::new aborts the process when memory is refused. Arc::try_new is
        // nightly-only, and Tokio makes its watch channel with Arc::new too, so
        // the record, its watch channels and the allocation of its notification
        // queue cannot be made fallibly.
        let link = Arc::new(Link::new(id));
        self.last_id = id;
        self.links.insert(id, Arc::clone(&link));
        self.open += 1;
        Ok(Ok(link))
    }
}

#[derive(Debug)]
pub enum Left {
    Open,
    /// Its place in the registry goes when the caller drops this, once the
    /// tables of the session are torn down.
    Ended(Option<Registered>),
}

impl Session {
    /// Room for it in the map of connections is reserved under the session
    /// lock with a reservation that fails instead of aborting, through
    /// `memory`, which parks a refused attempt outside the lock and tries again
    /// whenever this process releases memory.
    pub async fn attach(&self, memory: &Memory) -> Result<Arc<Link>, Errno> {
        memory.obtain(|| self.connections().add_link()).await
    }

    pub fn end(&self) {
        let mut connections = self.connections();
        connections.ended = true;
        for link in connections.links.values() {
            link.stop();
        }
    }

    pub fn hold(&self, registration: Registered) {
        self.connections().registration = Some(registration);
    }

    /// The caller tears down the tables, and the session leaves the
    /// registry when the caller drops the registration it is handed, after that
    /// teardown.
    pub fn detach(&self, link: &Link) -> Left {
        let id = link.id;
        let mut connections = self.connections();
        connections.open = connections.open.saturating_sub(1);
        if !link.read_any() {
            connections.links.remove(&id);
        }
        if connections.subscriber == Some(id) || connections.open == 0 {
            connections.subscriber = None;
            self.namespaces.unsubscribe(self.id);
            self.recalls.route(None);
        }
        if connections.open > 0 {
            return Left::Open;
        }
        connections.ended = true;
        connections.links.clear();
        Left::Ended(connections.registration.take())
    }

    /// Which connection holds the subscription and which queue the registry
    /// feeds change together, under the session lock, here, in
    /// [`Self::unsubscribe`] and in [`Self::detach`]. The published snapshot and
    /// the subscriber registry take their locks inside the session lock, and
    /// never the other way round.
    ///
    /// The check that `link` is open and the installation are one step, ordered
    /// against its close through [`Link::unless_closed`]: a close recorded
    /// before the step installs nothing, and a close started during the step is
    /// recorded after it, so [`Self::detach`] finds the subscription installed.
    /// The ordering lock of the connection is taken inside the session lock, as
    /// [`Self::end`] takes it.
    ///
    /// The connection has its sink from before this call until the confirm is
    /// flushed, so the snapshot queued here reaches the wire after the confirm.
    pub fn subscribe(&self, link: &Link) -> bool {
        let mut connections = self.connections();
        link.unless_closed(|| {
            connections.subscriber = Some(link.id);
            self.namespaces
                .subscribe(self.id, &self.name, &self.subpath, &link.queue);
            self.recalls.route(Some(&link.queue));
        })
        .is_some()
    }

    pub fn unsubscribe(&self) {
        let mut connections = self.connections();
        connections.subscriber = None;
        self.namespaces.unsubscribe(self.id);
        self.recalls.route(None);
    }

    pub fn link(&self, id: u64) -> Result<Arc<Link>, Errno> {
        let connections = self.connections();
        if connections.ended || id == 0 || id > connections.last_id {
            return Err(Errno::NOENT);
        }
        connections
            .links
            .get(&id)
            .map(Arc::clone)
            .ok_or(Errno::STALE)
    }

    pub fn retire(&self, link: &Link) {
        self.connections().links.remove(&link.id);
    }

    #[must_use]
    pub fn open_connections(&self) -> usize {
        self.connections().open
    }

    pub(super) fn connections(&self) -> MutexGuard<'_, Connections> {
        self.connections
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link() -> Link {
        Link::new(1)
    }

    async fn reply(bytes: &[u8]) -> Arc<Buffer> {
        let mut buffer = voidport_memory::Memory::host().buffer(bytes.len(), 1).await;
        buffer.copy_from_slice(bytes);
        Arc::new(buffer)
    }

    #[tokio::test]
    async fn a_request_is_not_started_until_it_has_a_reply() {
        let link = link();
        assert!(!link.read_any());
        assert!(matches!(link.outcome(1), Outcome::NotStarted), "never read");
        link.read(1, true);
        assert!(link.read_any());
        assert!(matches!(link.outcome(1), Outcome::NotStarted), "read only");
        link.keep(1, Kept::Replied(reply(b"reply").await));
        let Outcome::Replied(kept) = link.outcome(1) else {
            panic!("the reply is kept");
        };
        assert_eq!(&kept[..], b"reply");
        assert!(matches!(link.outcome(1), Outcome::Replied(_)));
        assert!(matches!(link.outcome(2), Outcome::NotStarted), "not read");
    }

    #[test]
    fn a_connection_gets_the_next_id_and_is_counted_open() {
        let mut connections = Connections::default();
        let Ok(Ok(first)) = connections.add_link() else {
            panic!("the first connection is added");
        };
        let Ok(Ok(second)) = connections.add_link() else {
            panic!("the second connection is added");
        };
        assert_eq!((first.id(), second.id()), (1, 2));
        assert_eq!(connections.open, 2);
        assert_eq!(connections.links.len(), 2);
    }

    #[test]
    fn an_attach_after_the_session_ended_fails_with_enoent() {
        let mut connections = Connections {
            ended: true,
            ..Connections::default()
        };
        assert!(matches!(connections.add_link(), Ok(Err(Errno::NOENT))));
        assert!(connections.links.is_empty());
    }

    #[test]
    fn the_connection_counter_at_its_last_value_fails_the_attach_with_eoverflow() {
        let mut connections = Connections {
            last_id: u64::MAX,
            ..Connections::default()
        };
        assert!(matches!(connections.add_link(), Ok(Err(Errno::OVERFLOW))));
        assert_eq!(connections.last_id, u64::MAX);
        assert_eq!(connections.open, 0);
        assert!(connections.links.is_empty());
    }

    #[tokio::test]
    async fn the_next_request_drops_the_kept_reply_and_a_forget_is_applied() {
        let link = link();
        link.read(1, true);
        link.keep(1, Kept::Replied(reply(b"reply").await));
        link.read(2, false);
        assert!(matches!(link.outcome(2), Outcome::Applied));
        assert!(
            matches!(link.outcome(1), Outcome::Applied),
            "the client had the reply once it sent the next request"
        );
        link.read(3, true);
        link.keep(3, Kept::NotStarted);
        assert!(matches!(link.outcome(3), Outcome::NotStarted), "cancelled");
        assert!(
            matches!(link.outcome(2), Outcome::Applied),
            "applied before 3"
        );
    }
}
