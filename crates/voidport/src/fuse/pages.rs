//! From the moment a recall starts until the server has received the reply, new
//! reads and writes of the node wait in this client: the server lets the writer
//! go ahead as it receives the reply, so a page read before that could be stale
//! right after it. The kernel discards the result of an invalidation
//! (`fuse_reverse_inval_inode`, `fs/fuse/inode.c`), so a drop cannot tell
//! whether it left a page behind. A drop unmaps and removes every page, and it
//! waits for the lock of every page it finds and for the writeback of a page
//! being written (`invalidate_inode_pages2_range`, `mm/truncate.c`). A dirty
//! page is written back first, as a write to this client, and it remains only
//! when that write fails. A page a read fills is locked from before the read
//! reaches this client until its reply has filled it, and so is the last page
//! of a write that leaves a page the cache did not have partly unwritten
//! (`fuse_fill_write_pages`, `fs/fuse/file.c`). A read or a write that started
//! before the recall therefore has its page removed by the drop, after it is
//! done. Two kinds need more:
//!
//! * a read or a write that waits here locked its pages before it waited, so the
//!   drop leaves the pages of every waiting one alone, which a read has not
//!   filled yet;
//! * a read or a write that reaches this client during the drop, the writeback
//!   the drop starts included, may have locked a page the drop waits for, so it
//!   goes ahead when its pages lie in what the drop removes, and another drop
//!   then removes the pages it adds, or the dirty page whose writeback failed.
//!
//! The drops end once one ran during which nothing went ahead. A drop the
//! kernel fails is tried again until it succeeds, because the recall is replied
//! to only once every page is gone. A mount that ended does not try again,
//! because the kernel fails every drop once the connection ended.
//!
//! The pages are valid only within a window the server grants the mount at
//! every renewal ([`voidport_session::window`]), because a server that cannot
//! reach the mount cannot recall them. A renewal replied to by another session
//! than the last one drops the pages too, since the leases of the session that
//! granted them are gone with it.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::ops::Range;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::{JoinError, JoinSet};
use tokio::time::Instant;
use voidport_fuse::{Errno, Notifier};
use voidport_session::Window;

use crate::client::{Caller, Client, Granted};
use crate::guardian::{Event, Feed};
use crate::subscribe::Recall;

pub async fn answer_recalls(
    pages: Arc<PageCache>,
    client: Arc<Client>,
    mut recalls: mpsc::UnboundedReceiver<Recall>,
) {
    let mut answering = JoinSet::new();
    loop {
        tokio::select! {
            recall = recalls.recv() => {
                let Some(Recall { node_id, recall }) = recall else {
                    return;
                };
                let (pages, client) = (Arc::clone(&pages), Arc::clone(&client));
                answering.spawn(async move {
                    let held = pages.recall(node_id).await;
                    if let Err(errno) = client.recalled(Caller::default(), node_id, recall).await {
                        tracing::warn!(node_id, %errno, "the server did not receive the reply to a recall");
                    }
                    drop(held);
                });
            }
            Some(_) = answering.join_next(), if !answering.is_empty() => {}
        }
    }
}

/// A renewal is sent one period after the last one was sent. One the mount could
/// not send is sent again once the mount changes its state, after a reconnect. A
/// server that grants no window leases no file to the mount any more, so the
/// pages cached under the last window are dropped and the renewals end.
pub async fn renew_window(
    pages: Arc<PageCache>,
    client: Arc<Client>,
    renewed: oneshot::Sender<()>,
) {
    let mut renewed = Some(renewed);
    let mut changes = client.changes();
    let mut validity = Validity::default();
    loop {
        let sent = Instant::now();
        let reply = validity
            .until_lapsed(&pages, client.renew(Caller::default()))
            .await;
        if let Some(renewed) = renewed.take() {
            // Nothing receives this once the start of the mount is over.
            let _start_over = renewed.send(());
        }
        match reply {
            Ok(Granted {
                window: Some(window),
                generation,
            }) => {
                validity.granted(&pages, sent, window, generation).await;
                let next = tokio::time::sleep_until(sent + window.period());
                validity.until_lapsed(&pages, next).await;
            }
            Ok(Granted { window: None, .. }) => {
                tracing::warn!(
                    "the server grants no window, so the mount caches no page of a leased file any more"
                );
                validity.lapse(&pages).await;
                return;
            }
            Err(errno) => {
                tracing::warn!(%errno, "the window of the pages the mount caches was not renewed");
                // The changes end only with the client, and so does the
                // renewal then.
                if validity
                    .until_lapsed(&pages, changes.changed())
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }
}

/// Gives the leases of the session up for a mount whose guardian is lost, the
/// way a renewal that grants no window does. The server leases the session no
/// file after that, so the requests through cached handles fail, and the others
/// go on.
pub async fn relinquish(pages: Arc<PageCache>, client: Arc<Client>) {
    let lapse = pages.lapse().await;
    if let Err(errno) = client.relinquish(Caller::default()).await {
        tracing::warn!(%errno, "the server was not told that the mount caches no page, so the leases of the session remain until the window has passed");
    }
    drop(lapse);
}

#[derive(Debug, Default)]
struct Validity {
    ends: Option<Instant>,
    generation: Option<u64>,
    lapse: Option<Lapse>,
}

impl Validity {
    async fn until_lapsed<T>(
        &mut self,
        pages: &Arc<PageCache>,
        future: impl Future<Output = T>,
    ) -> T {
        tokio::pin!(future);
        loop {
            let ends = self.ends.filter(|_| self.lapse.is_none());
            tokio::select! {
                output = &mut future => return output,
                () = sleep_until_some(ends) => self.lapse(pages).await,
            }
        }
    }

    /// The pages cached under an earlier session are dropped first, and a window
    /// that ended before its grant arrived blocks every read and write request.
    async fn granted(
        &mut self,
        pages: &Arc<PageCache>,
        sent: Instant,
        window: Window,
        generation: u64,
    ) {
        if self.generation.is_some_and(|earlier| earlier != generation) {
            self.lapse(pages).await;
        }
        self.generation = Some(generation);
        let ends = sent + window.length();
        self.ends = Some(ends);
        if Instant::now() < ends {
            self.lapse = None;
        }
    }

    async fn lapse(&mut self, pages: &Arc<PageCache>) {
        if self.lapse.is_none() {
            self.lapse = Some(pages.lapse().await);
        }
    }
}

async fn sleep_until_some(instant: Option<Instant>) {
    match instant {
        Some(instant) => tokio::time::sleep_until(instant).await,
        None => std::future::pending().await,
    }
}

pub trait Invalidate: Send + Sync + std::fmt::Debug + 'static {
    /// Drops the pages of node `node_id` in the byte range `offset` to
    /// `offset + len`, or to the end of the file for no `len`, and returns once
    /// the kernel has done so.
    fn invalidate(&self, node_id: u64, offset: u64, len: Option<u64>) -> Result<(), Errno>;
}

impl Invalidate for Notifier {
    fn invalidate(&self, node_id: u64, offset: u64, len: Option<u64>) -> Result<(), Errno> {
        self.invalidate_pages(node_id, offset, len)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DropError {
    #[error("no notifier of the session is attached")]
    Unattached,
    #[error("the kernel rejected the drop")]
    Kernel(#[source] Errno),
    #[error("the thread that sent the drop ended without a result")]
    Thread(#[source] JoinError),
}

/// The notifier belongs to the session, and the session does not exist until the
/// filesystem is handed to it. The adapter therefore stores this, and the mount
/// attaches the notifier before the first dispatch loop starts.
#[derive(Debug)]
pub struct PageCache {
    dropper: OnceLock<Arc<dyn Invalidate>>,
    feed: Arc<Feed>,
    /// The nodes, spread over one lock per processor, so that the reads of
    /// different nodes rarely take the same lock.
    shards: Box<[Mutex<Shard>]>,
    /// Woken when the fills of a node stop being held, and when a drop ends.
    changed: Notify,
    page: u64,
}

type Span = Range<u64>;

#[derive(Debug, Default)]
struct Shard {
    nodes: HashMap<u64, Fills>,
    /// The lookup count the kernel has of every node it has an inode of: one
    /// for every reply that handed it the node, less what its forgets gave
    /// back.
    lookups: HashMap<u64, u64>,
    lapses: usize,
}

#[derive(Debug)]
struct Fills {
    holds: usize,
    /// What may be cached that no drop has removed since: the whole file
    /// while nothing holds the reads and writes, and the spans of those that
    /// went ahead during a drop.
    cached: Vec<Span>,
    dropping: Option<Vec<Span>>,
    waiting: Vec<Span>,
    /// Once the guardian was told of the node, how many messages the feed
    /// has sent when the guardian has it.
    told: Option<u64>,
}

#[derive(Debug)]
pub struct Held<'a> {
    pages: &'a PageCache,
    node_id: u64,
}

#[derive(Debug)]
pub struct Lapse {
    pages: Arc<PageCache>,
}

#[derive(Clone, Copy, Debug)]
enum Retry {
    UntilDropped,
    /// Counts the node as one whose pages remain.
    Once,
}

struct Waiting<'a> {
    pages: &'a PageCache,
    node_id: u64,
    span: Span,
}

impl Default for Fills {
    fn default() -> Self {
        Self {
            holds: 0,
            cached: vec![WHOLE],
            dropping: None,
            waiting: Vec::new(),
            told: None,
        }
    }
}

const WHOLE: Span = 0..u64::MAX;

impl PageCache {
    pub fn new(feed: Arc<Feed>) -> Self {
        let shards = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        Self {
            dropper: OnceLock::new(),
            feed,
            shards: (0..shards).map(|_| Mutex::default()).collect(),
            changed: Notify::new(),
            page: rustix::param::page_size() as u64,
        }
    }

    pub fn attach(&self, notifier: Notifier) {
        self.attach_dropper(Arc::new(notifier));
    }

    fn attach_dropper(&self, dropper: Arc<dyn Invalidate>) {
        if self.dropper.set(dropper).is_err() {
            tracing::error!("a second session notifier was attached and is ignored");
        }
    }

    /// Lets a read or a write of `len` bytes at `offset` of node `node_id` go
    /// ahead, once the guardian has the node, no recall holds the reads and
    /// writes of the node, and the window has not lapsed.
    pub async fn fill(&self, node_id: u64, offset: u64, len: u64) {
        let told = *self
            .shard(node_id)
            .nodes
            .entry(node_id)
            .or_default()
            .told
            .get_or_insert_with(|| self.feed.tell(Event::Cached(node_id)));
        self.feed.written(told).await;
        let span = self.span(offset, len);
        let mut waiting = None;
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut shard = self.shard(node_id);
                let lapsed = shard.lapses > 0;
                let fills = shard.nodes.entry(node_id).or_default();
                if fills.holds == 0 && !lapsed {
                    return;
                }
                if fills
                    .dropping
                    .as_deref()
                    .is_some_and(|dropping| overlaps(dropping, &span))
                {
                    // The drop may wait for a page this request locked.
                    fills.cached.push(span);
                    return;
                }
                if waiting.is_none() {
                    fills.waiting.push(span.clone());
                    waiting = Some(Waiting {
                        pages: self,
                        node_id,
                        span: span.clone(),
                    });
                }
            }
            changed.await;
        }
    }

    /// Counts a lookup of node `node_id` that the kernel takes from a reply,
    /// before the reply is sent.
    pub fn looked_up(&self, node_id: u64) {
        *self.shard(node_id).lookups.entry(node_id).or_default() += 1;
    }

    /// The node is forgotten once no lookup is left: the kernel then has no inode
    /// of it, and no page. The count decides, and not the forget alone, because
    /// the kernel can give the node a new inode, through a lookup the client
    /// replies to, before the client receives the forget of the old inode. The
    /// guardian is told in the order of the messages of the node.
    pub fn forget(&self, node_id: u64, nlookup: u64) {
        let mut shard = self.shard(node_id);
        let Entry::Occupied(mut lookups) = shard.lookups.entry(node_id) else {
            return;
        };
        *lookups.get_mut() = lookups.get().saturating_sub(nlookup);
        if *lookups.get() > 0 {
            return;
        }
        lookups.remove();
        let Some(fills) = shard.nodes.get_mut(&node_id) else {
            return;
        };
        if fills.told.take().is_some() {
            self.feed.tell(Event::Forgot(node_id));
        }
        if fills.holds == 0 && fills.dropping.is_none() && fills.waiting.is_empty() {
            shard.nodes.remove(&node_id);
        }
    }

    /// The reads and writes are held until the server has received the reply,
    /// which is when the returned value is dropped.
    pub async fn recall(&self, node_id: u64) -> Held<'_> {
        self.shard(node_id).nodes.entry(node_id).or_default().holds += 1;
        let held = Held {
            pages: self,
            node_id,
        };
        self.drop_pages(node_id).await;
        held
    }

    async fn drop_pages(&self, node_id: u64) {
        let mut failures = 0;
        while let Err(error) = self.try_drop_pages(node_id).await {
            failures += 1;
            tracing::warn!(node_id, %error, "the kernel did not drop the pages of a file, so the drop is tried again");
            tokio::time::sleep(pause(failures)).await;
        }
    }

    async fn try_drop_pages(&self, node_id: u64) -> Result<(), DropError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let spans = {
                let mut shard = self.shard(node_id);
                let fills = shard.nodes.entry(node_id).or_default();
                if fills.dropping.is_some() {
                    None
                } else {
                    let spans = without(&std::mem::take(&mut fills.cached), &fills.waiting);
                    if spans.is_empty() {
                        return Ok(());
                    }
                    fills.dropping = Some(spans.clone());
                    Some(spans)
                }
            };
            // Another drop of the node's pages runs: this one goes on once
            // that drop ended.
            let Some(spans) = spans else {
                changed.await;
                continue;
            };
            let dropped = self.invalidate(node_id, spans.clone()).await;
            {
                let mut shard = self.shard(node_id);
                let fills = shard.nodes.entry(node_id).or_default();
                fills.dropping = None;
                if dropped.is_err() {
                    fills.cached.extend(spans);
                }
            }
            self.changed.notify_waiters();
            dropped?;
        }
    }

    /// A node first read meanwhile has no pages: its reads wait.
    async fn lapse(self: &Arc<Self>) -> Lapse {
        let (lapse, nodes) = self.hold();
        if !self.drop_every_node(nodes, Retry::UntilDropped).await {
            tracing::error!(
                "a drop of the pages of a file ended before it succeeded, so the guest may read pages of a lapsed window"
            );
        }
        lapse
    }

    /// Whether the kernel caches no page of a mount that ended, whose
    /// `nodes` are blocked: `destroyed` says that the kernel destroyed the
    /// connection, which removes every page with the superblock, and
    /// otherwise every node is dropped once.
    pub async fn shown_gone(self: &Arc<Self>, nodes: Vec<u64>, destroyed: bool) -> bool {
        destroyed || self.drop_every_node(nodes, Retry::Once).await
    }

    /// Drops the pages of every node in `nodes`, each in a task of its own,
    /// so that one node whose drop waits for a stalled read delays no other,
    /// and returns whether every drop succeeded. A task that ended without a
    /// result counts as a failed drop.
    async fn drop_every_node(self: &Arc<Self>, nodes: Vec<u64>, retry: Retry) -> bool {
        let mut drops = JoinSet::new();
        for node_id in nodes {
            let pages = Arc::clone(self);
            drops.spawn(async move {
                match retry {
                    Retry::UntilDropped => {
                        pages.drop_pages(node_id).await;
                        Ok(())
                    }
                    Retry::Once => pages.try_drop_pages(node_id).await,
                }
            });
        }
        let mut dropped = true;
        while let Some(drop) = drops.join_next().await {
            dropped &= matches!(drop, Ok(Ok(())));
        }
        dropped
    }

    pub fn hold(self: &Arc<Self>) -> (Lapse, Vec<u64>) {
        let mut nodes = Vec::new();
        for shard in &self.shards {
            let mut shard = locked(shard);
            shard.lapses += 1;
            nodes.extend(shard.nodes.keys().copied());
        }
        let lapse = Lapse {
            pages: Arc::clone(self),
        };
        (lapse, nodes)
    }

    /// The notification goes out from a blocking thread. The kernel waits for
    /// the lock of every page it drops, and a locked page can be waiting for a
    /// read reply that a task of this runtime has to send, so a runtime worker
    /// that waited here could be the one that never sends it.
    async fn invalidate(&self, node_id: u64, spans: Vec<Span>) -> Result<(), DropError> {
        let dropper = self.dropper.get().cloned().ok_or(DropError::Unattached)?;
        tokio::task::spawn_blocking(move || {
            spans.into_iter().try_for_each(|span| {
                let len = (span.end != u64::MAX).then(|| span.end - span.start);
                dropper.invalidate(node_id, span.start, len)
            })
        })
        .await
        .map_err(DropError::Thread)?
        .map_err(DropError::Kernel)
    }

    fn span(&self, offset: u64, len: u64) -> Span {
        let start = offset - offset % self.page;
        let end = offset.saturating_add(len).div_ceil(self.page);
        start..end.saturating_mul(self.page)
    }

    fn shard(&self, node_id: u64) -> MutexGuard<'_, Shard> {
        let shard = usize::try_from(node_id).unwrap_or(usize::MAX) % self.shards.len();
        locked(&self.shards[shard])
    }
}

fn locked(shard: &Mutex<Shard>) -> MutexGuard<'_, Shard> {
    shard.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn pause(failures: u32) -> Duration {
    Duration::from_millis(10u64 << failures.min(7)).min(Duration::from_secs(1))
}

fn overlaps(spans: &[Span], span: &Span) -> bool {
    spans
        .iter()
        .any(|other| other.start < span.end && span.start < other.end)
}

fn without(spans: &[Span], holes: &[Span]) -> Vec<Span> {
    let mut sorted = spans.to_vec();
    sorted.sort_by_key(|span| span.start);
    let mut merged: Vec<Span> = Vec::new();
    for span in sorted {
        match merged.last_mut() {
            Some(last) if span.start <= last.end => last.end = last.end.max(span.end),
            _ => merged.push(span),
        }
    }
    for hole in holes {
        merged = merged
            .into_iter()
            .flat_map(|span| {
                [
                    span.start..hole.start.min(span.end),
                    hole.end.max(span.start)..span.end,
                ]
            })
            .filter(|span| !span.is_empty())
            .collect();
    }
    merged
}

impl Drop for Held<'_> {
    /// The reads and writes go ahead once no recall holds them, and may cache any
    /// page then.
    fn drop(&mut self) {
        let mut shard = self.pages.shard(self.node_id);
        let lapsed = shard.lapses > 0;
        if let Some(fills) = shard.nodes.get_mut(&self.node_id) {
            fills.holds -= 1;
            if fills.holds == 0 && !lapsed {
                fills.cached = vec![WHOLE];
            }
        }
        drop(shard);
        self.pages.changed.notify_waiters();
    }
}

impl Drop for Lapse {
    /// Once no other lapse blocks them, the reads and writes of every node no
    /// recall covers go ahead, and may cache any page then.
    fn drop(&mut self) {
        for shard in &self.pages.shards {
            let mut shard = locked(shard);
            shard.lapses -= 1;
            if shard.lapses > 0 {
                continue;
            }
            for fills in shard.nodes.values_mut() {
                if fills.holds == 0 {
                    fills.cached = vec![WHOLE];
                }
            }
        }
        self.pages.changed.notify_waiters();
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if let Some(fills) = self.pages.shard(self.node_id).nodes.get_mut(&self.node_id)
            && let Some(at) = fills.waiting.iter().position(|span| *span == self.span)
        {
            fills.waiting.swap_remove(at);
        }
    }
}

#[cfg(test)]
mod tests;
