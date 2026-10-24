use std::os::fd::OwnedFd;
use std::sync::Mutex;

use rustix::io::Errno;
use tokio::runtime::Handle;
use tokio::sync::mpsc;

use super::*;
use crate::guardian::{Unstarted, receive};

#[derive(Debug)]
struct Dropper {
    drops: Mutex<Vec<(u64, u64, Option<u64>)>>,
    failing: Mutex<usize>,
    pausing: Option<Pausing>,
    ended: mpsc::UnboundedSender<u64>,
}

#[derive(Debug)]
struct Pausing {
    node_id: u64,
    started: mpsc::UnboundedSender<()>,
    go: Mutex<std::sync::mpsc::Receiver<()>>,
}

struct Pauses {
    go: std::sync::mpsc::Sender<()>,
    started: mpsc::UnboundedReceiver<()>,
}

impl Invalidate for Dropper {
    fn invalidate(&self, node_id: u64, offset: u64, len: Option<u64>) -> Result<(), Errno> {
        if let Some(pausing) = self.pausing.as_ref().filter(|p| p.node_id == node_id) {
            let _test_may_have_stopped_watching = pausing.started.send(());
            let _released_or_the_test_ended = pausing.go.lock().unwrap().recv();
        }
        self.drops.lock().unwrap().push((node_id, offset, len));
        let mut failing = self.failing.lock().unwrap();
        if *failing > 0 {
            *failing -= 1;
            return Err(Errno::BUSY);
        }
        let _test_may_have_stopped_watching = self.ended.send(node_id);
        Ok(())
    }
}

impl Dropper {
    fn drops(&self) -> Vec<(u64, u64, Option<u64>)> {
        self.drops.lock().unwrap().clone()
    }
}

fn unattached() -> (Arc<PageCache>, OwnedFd) {
    let Unstarted {
        feed,
        writer,
        theirs,
    } = Unstarted::new().expect("a feed");
    writer.start(&Handle::current());
    (Arc::new(PageCache::new(feed)), theirs)
}

fn pages(dropper: Dropper) -> (Arc<PageCache>, Arc<Dropper>, OwnedFd) {
    let dropper = Arc::new(dropper);
    let (pages, guardian) = unattached();
    pages.attach_dropper(Arc::clone(&dropper) as Arc<dyn Invalidate>);
    (pages, dropper, guardian)
}

fn plain(failing: usize) -> (Dropper, mpsc::UnboundedReceiver<u64>) {
    let (ended, endings) = mpsc::unbounded_channel();
    let dropper = Dropper {
        drops: Mutex::default(),
        failing: Mutex::new(failing),
        pausing: None,
        ended,
    };
    (dropper, endings)
}

fn pausing(node_id: u64) -> (Dropper, Pauses, mpsc::UnboundedReceiver<u64>) {
    let (started, starts) = mpsc::unbounded_channel();
    let (go, gone) = std::sync::mpsc::channel();
    let (dropper, endings) = plain(0);
    let dropper = Dropper {
        pausing: Some(Pausing {
            node_id,
            started,
            go: Mutex::new(gone),
        }),
        ..dropper
    };
    let pauses = Pauses {
        go,
        started: starts,
    };
    (dropper, pauses, endings)
}

async fn pending(future: &mut (impl Future + Unpin)) -> bool {
    tokio::select! {
        biased;
        _ = future => false,
        () = std::future::ready(()) => true,
    }
}

fn window() -> Window {
    Window::new(Duration::from_secs(10), Duration::from_secs(5)).expect("a window")
}

#[tokio::test(start_paused = true)]
async fn a_recall_holds_new_reads_until_its_reply_was_received() {
    let (pages, dropper, _guardian) = pages(plain(0).0);
    let held = pages.recall(7).await;
    assert_eq!(dropper.drops(), [(7, 0, None)]);

    let mut read = Box::pin(pages.fill(7, 0, 4096));
    assert!(
        pending(&mut read).await,
        "a read waits while the recall holds"
    );
    pages.fill(8, 0, 4096).await;

    drop(held);
    read.await;
}

#[tokio::test(start_paused = true)]
async fn a_read_that_goes_ahead_during_a_drop_is_dropped_by_another() {
    let (dropper, mut pauses, _) = pausing(7);
    let (pages, dropper, _guardian) = pages(dropper);
    let recalling = tokio::spawn({
        let pages = Arc::clone(&pages);
        async move {
            drop(pages.recall(7).await);
        }
    });

    pauses.started.recv().await.expect("the first drop starts");
    let page = pages.page;
    pages.fill(7, page * 2 + 1, 10).await;
    pauses.go.send(()).expect("the first drop ends");
    pauses.started.recv().await.expect("a second drop starts");
    pauses.go.send(()).expect("the second drop ends");
    recalling.await.expect("the recall ends");

    assert_eq!(
        dropper.drops(),
        [(7, 0, None), (7, page * 2, Some(page))],
        "the second drop removes the page of the read that went ahead"
    );
}

#[tokio::test(start_paused = true)]
async fn a_failed_drop_is_tried_again_before_the_recall_ends() {
    let (pages, dropper, _guardian) = pages(plain(2).0);
    drop(pages.recall(7).await);
    assert_eq!(dropper.drops(), [(7, 0, None); 3]);
}

#[tokio::test(start_paused = true)]
async fn a_recall_before_the_notifier_is_attached_waits_for_it() {
    let (pages, _guardian) = unattached();
    let recalling = tokio::spawn({
        let pages = Arc::clone(&pages);
        async move {
            drop(pages.recall(7).await);
        }
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !recalling.is_finished(),
        "nothing has dropped the pages yet"
    );

    let (dropper, _) = plain(0);
    let dropper = Arc::new(dropper);
    pages.attach_dropper(Arc::clone(&dropper) as Arc<dyn Invalidate>);
    recalling.await.expect("the recall ends");
    assert_eq!(dropper.drops(), [(7, 0, None)]);
}

#[test]
fn a_drop_leaves_the_pages_of_waiting_reads_alone() {
    use std::slice::from_ref;

    assert_eq!(
        without(&[0..100, 50..200, 300..400], &[20..30, 150..350]),
        [0..20, 30..150, 350..400]
    );
    assert_eq!(
        without(&[WHOLE], from_ref(&(0..10))),
        from_ref(&(10..u64::MAX))
    );
    assert!(without(from_ref(&(10..20)), from_ref(&(0..30))).is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_window_that_ends_unrenewed_holds_every_read_until_a_renewal() {
    let (pages, dropper, _guardian) = pages(plain(0).0);
    pages.fill(7, 0, 4096).await;
    let mut validity = Validity::default();
    validity.granted(&pages, Instant::now(), window(), 1).await;

    let renewal = tokio::time::sleep(Duration::from_secs(20));
    validity.until_lapsed(&pages, renewal).await;
    assert_eq!(
        dropper.drops(),
        [(7, 0, None)],
        "the pages of every node are dropped"
    );
    let mut read = Box::pin(pages.fill(8, 0, 4096));
    assert!(pending(&mut read).await, "every read waits");

    validity.granted(&pages, Instant::now(), window(), 1).await;
    read.await;
}

#[tokio::test(start_paused = true)]
async fn a_renewal_granted_by_another_session_drops_every_page() {
    let (pages, dropper, _guardian) = pages(plain(0).0);
    pages.fill(7, 0, 4096).await;
    let mut validity = Validity::default();
    validity.granted(&pages, Instant::now(), window(), 1).await;
    assert!(dropper.drops().is_empty());

    validity.granted(&pages, Instant::now(), window(), 2).await;
    assert_eq!(dropper.drops(), [(7, 0, None)]);
    pages.fill(7, 0, 4096).await;
}

#[tokio::test(start_paused = true)]
async fn a_grant_whose_window_ended_before_it_arrived_keeps_every_read_held() {
    let (pages, _, _guardian) = pages(plain(0).0);
    let mut validity = Validity::default();
    let sent = Instant::now();
    validity.granted(&pages, sent, window(), 1).await;
    let late = tokio::time::sleep(Duration::from_secs(20));
    validity.until_lapsed(&pages, late).await;

    validity.granted(&pages, sent, window(), 1).await;
    let mut read = Box::pin(pages.fill(7, 0, 4096));
    assert!(pending(&mut read).await, "the reads stay held");
}

#[tokio::test(start_paused = true)]
async fn the_block_of_an_ending_mount_outlasts_a_renewal() {
    let (pages, _, _guardian) = pages(plain(0).0);
    let mut validity = Validity::default();
    validity.granted(&pages, Instant::now(), window(), 1).await;

    let (ended, _) = pages.hold();
    let renewal = tokio::time::sleep(Duration::from_secs(20));
    validity.until_lapsed(&pages, renewal).await;
    validity.granted(&pages, Instant::now(), window(), 1).await;
    let mut read = Box::pin(pages.fill(8, 0, 4096));
    assert!(
        pending(&mut read).await,
        "a renewal after a lapse does not unblock the reads"
    );
    drop(ended);
    read.await;
}

#[tokio::test(start_paused = true)]
async fn an_ending_mount_shows_its_pages_gone_once_dropped_or_destroyed() {
    let (pages, dropper, _guardian) = pages(plain(1).0);
    pages.fill(7, 0, 4096).await;

    let (_held, nodes) = pages.hold();
    assert!(
        pages.shown_gone(nodes.clone(), true).await,
        "a destroyed connection removed the pages"
    );
    assert!(dropper.drops().is_empty(), "nothing is dropped");

    assert!(
        !pages.shown_gone(nodes.clone(), false).await,
        "a failed drop leaves the pages"
    );
    assert_eq!(dropper.drops(), [(7, 0, None)], "it is not tried again");

    assert!(pages.shown_gone(nodes, false).await, "the drop succeeds");
    assert_eq!(dropper.drops(), [(7, 0, None); 2]);
}

#[tokio::test(start_paused = true)]
async fn a_lapse_drops_each_node_on_its_own() {
    let (dropper, mut pauses, mut endings) = pausing(7);
    let (pages, _, _guardian) = pages(dropper);
    pages.fill(7, 0, 4096).await;
    pages.fill(8, 0, 4096).await;
    let lapsing = tokio::spawn({
        let pages = Arc::clone(&pages);
        async move { drop(pages.lapse().await) }
    });

    pauses
        .started
        .recv()
        .await
        .expect("the drop of node 7 starts");
    assert_eq!(
        endings.recv().await,
        Some(8),
        "node 8 is dropped while node 7 waits"
    );
    pauses.go.send(()).expect("the drop of node 7 ends");
    lapsing.await.expect("the lapse ends");
}

#[tokio::test(start_paused = true)]
async fn a_node_is_forgotten_once_the_kernel_gave_every_lookup_back() {
    let (pages, dropper, _guardian) = pages(plain(0).0);
    pages.looked_up(7);
    pages.fill(7, 0, 4096).await;
    // A lookup gives the node a new inode before the forget of the old
    // inode arrives.
    pages.looked_up(7);
    pages.forget(7, 1);
    drop(pages.lapse().await);
    assert_eq!(
        dropper.drops(),
        [(7, 0, None)],
        "the pages of the new inode are dropped"
    );

    pages.forget(7, 1);
    drop(pages.lapse().await);
    assert_eq!(
        dropper.drops(),
        [(7, 0, None)],
        "a node the kernel has no inode of has no pages to drop"
    );
}

#[tokio::test(start_paused = true)]
async fn the_guardian_is_told_of_a_node_once_and_of_its_forget_at_a_lookup_count_of_zero() {
    let (pages, _, guardian) = pages(plain(0).0);
    pages.looked_up(7);
    pages.fill(7, 0, 4096).await;
    pages.fill(7, 0, 4096).await;
    pages.looked_up(7);
    pages.forget(7, 1);
    pages.forget(7, 1);
    pages.looked_up(7);
    pages.fill(7, 0, 4096).await;

    pages.feed.close();
    pages.feed.written(u64::MAX).await;
    let told = std::iter::from_fn(|| receive(&guardian).expect("a message"));
    assert_eq!(
        told.collect::<Vec<_>>(),
        [Event::Cached(7), Event::Forgot(7), Event::Cached(7)]
    );
}
