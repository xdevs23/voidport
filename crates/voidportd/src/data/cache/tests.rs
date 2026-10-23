use super::*;
use std::time::Duration;

use rustix::fs::Mode;
use voidport_session::Window;
use voidport_test_host::Scratch;

use crate::data::descriptor_budget::DescriptorBudget;
use crate::data::leases::LeaseThread;
use crate::data::subscribe::NotificationQueue;
use crate::host::attr::HostAttr;

#[tokio::test]
async fn a_recall_without_a_reply_closes_once_the_window_has_surely_passed() {
    let thread = LeaseThread::start(DescriptorBudget::new(1)).expect("the lease thread starts");
    let scratch = Scratch::new("recall-deadline");
    let pinned = Arc::new(
        rustix::fs::open(scratch.file("file", b"data"), OFlags::PATH, Mode::empty())
            .expect("the file opens by path"),
    );
    let identity = HostAttr::of(pinned.as_fd())
        .expect("stattable")
        .node_identity();
    let recalls = Recalls::new();
    recalls.route(Some(&NotificationQueue::new()));
    let cache = FileCache::new(1, identity, &recalls, thread.leases());
    let locks = FileLocks::default();
    let window = Window::new(Duration::from_millis(500), Duration::from_millis(100));
    recalls.renew(window.expect("a window")).await;
    drop(cache.open(&pinned, OFlags::RDONLY, &locks, None));
    assert!(cache.leased(), "the file is leased");

    let Err(Unserved::Postponed(recalling)) = cache.open(&pinned, OFlags::RDWR, &locks, None)
    else {
        panic!("an open for writing recalls the pages of the read lease first");
    };
    recalling.ended().await.expect("the recall closes");
    assert!(!cache.leased(), "the lease is given up without a reply");
}
