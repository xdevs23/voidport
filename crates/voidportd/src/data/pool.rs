//! A thread is held for a host call and for nothing else: never while a socket
//! is written or waited for, and never while a request is parked on a file
//! lock or on the allocator. The pool has no queue of jobs, only the list of
//! waiting askers, served in the order they asked, so nothing waits here
//! holding the data of a request. The refusal of the host is the only limit on
//! the number of threads.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use tokio::sync::oneshot;

type Job = Box<dyn FnOnce() + Send + 'static>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Closed;

impl fmt::Display for Closed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the request pool has closed")
    }
}

impl std::error::Error for Closed {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failed;

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a host call on the request pool failed")
    }
}

impl std::error::Error for Failed {}

#[derive(Default)]
struct Slot {
    job: Option<Job>,
    running: bool,
    released: bool,
    leave: bool,
}

#[derive(Default)]
struct Worker {
    slot: Mutex<Slot>,
    changed: Condvar,
}

impl Worker {
    fn lock(&self) -> MutexGuard<'_, Slot> {
        self.slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

struct Asker {
    id: u64,
    grant: oneshot::Sender<Thread>,
}

#[derive(Default)]
struct State {
    idle: Vec<Arc<Worker>>,
    askers: VecDeque<Asker>,
    next_asker: u64,
    busy: usize,
    closed: bool,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// An asker whose future is gone hands the thread back through the drop of
    /// the grant, which comes straight back here, so it is sent to the next
    /// asker instead.
    fn give_back(self: &Arc<Self>, worker: Arc<Worker>) {
        let mut state = self.lock();
        state.busy -= 1;
        if state.closed {
            worker.lock().leave = true;
            worker.changed.notify_all();
            return;
        }
        if let Some(asker) = state.askers.pop_front() {
            state.busy += 1;
            drop(state);
            let thread = Thread {
                worker: Some(worker),
                shared: Arc::clone(self),
            };
            // A refused send drops the grant, whose drop gives the thread back
            // to the next asker.
            let _ = asker.grant.send(thread);
            return;
        }
        state.idle.push(worker);
    }

    fn serve(self: &Arc<Self>, worker: &Arc<Worker>) {
        let mut slot = worker.lock();
        loop {
            if slot.leave {
                return;
            }
            if let Some(job) = slot.job.take() {
                slot.running = true;
                drop(slot);
                // A call that unwinds takes no thread down; its holder learns
                // of it through the answer it never gets.
                if panic::catch_unwind(AssertUnwindSafe(job)).is_err() {
                    tracing::error!("a host call on the request pool failed");
                }
                slot = worker.lock();
                slot.running = false;
                if slot.released {
                    slot.released = false;
                    drop(slot);
                    self.give_back(Arc::clone(worker));
                    slot = worker.lock();
                }
                continue;
            }
            slot = worker
                .changed
                .wait(slot)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

/// A thread granted to one request.
///
/// Dropping it gives the thread back: at once when it is between calls, and
/// as soon as the call it is running returns otherwise, so a request that
/// stopped waiting for a call never lets a second call onto a thread that is
/// still inside the first.
pub struct Thread {
    worker: Option<Arc<Worker>>,
    shared: Arc<Shared>,
}

impl fmt::Debug for Thread {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Thread").finish_non_exhaustive()
    }
}

impl Thread {
    pub async fn run<R: Send + 'static>(
        &mut self,
        call: impl FnOnce() -> R + Send + 'static,
    ) -> Result<R, Failed> {
        let (answer, answered) = oneshot::channel();
        let worker = self.worker.as_ref().ok_or(Failed)?;
        {
            let mut slot = worker.lock();
            slot.job = Some(Box::new(move || {
                let _ = answer.send(call());
            }));
        }
        worker.changed.notify_all();
        answered.await.map_err(|_| Failed)
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        let Some(worker) = self.worker.take() else {
            return;
        };
        let mut slot = worker.lock();
        if slot.running || slot.job.is_some() {
            slot.released = true;
            return;
        }
        drop(slot);
        self.shared.give_back(worker);
    }
}

pub struct Pool {
    shared: Arc<Shared>,
}

impl fmt::Debug for Pool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.shared.lock();
        formatter
            .debug_struct("Pool")
            .field("idle", &state.idle.len())
            .field("busy", &state.busy)
            .field("askers", &state.askers.len())
            .field("closed", &state.closed)
            .finish_non_exhaustive()
    }
}

impl Pool {
    pub fn new() -> io::Result<Self> {
        let pool = Self {
            shared: Arc::new(Shared::default()),
        };
        let worker = pool.ask_for_a_thread()?;
        pool.shared.lock().idle.push(worker);
        Ok(pool)
    }

    /// Dropping the future leaves the list of askers, and a thread granted to
    /// it meanwhile goes back to the pool.
    pub async fn acquire(&self) -> Result<Thread, Closed> {
        {
            let mut state = self.shared.lock();
            if state.closed {
                return Err(Closed);
            }
            if let Some(worker) = state.idle.pop() {
                state.busy += 1;
                return Ok(self.thread(worker));
            }
        }
        // Asked with the lock released. A refusal from the host applies to this
        // moment; the asker then waits for a thread given back.
        if let Ok(worker) = self.ask_for_a_thread() {
            let mut state = self.shared.lock();
            if state.closed {
                worker.lock().leave = true;
                worker.changed.notify_all();
                return Err(Closed);
            }
            state.busy += 1;
            return Ok(self.thread(worker));
        }
        self.wait_for_a_thread().await
    }

    async fn wait_for_a_thread(&self) -> Result<Thread, Closed> {
        let (grant, granted) = oneshot::channel();
        let id = {
            let mut state = self.shared.lock();
            if state.closed {
                return Err(Closed);
            }
            if let Some(worker) = state.idle.pop() {
                state.busy += 1;
                return Ok(self.thread(worker));
            }
            let id = state.next_asker;
            state.next_asker = state.next_asker.wrapping_add(1);
            state.askers.push_back(Asker { id, grant });
            id
        };
        let _waiting = Waiting {
            shared: Arc::clone(&self.shared),
            id,
        };
        granted.await.map_err(|_| Closed)
    }

    fn closing(state: &mut State) {
        if state.closed {
            return;
        }
        state.closed = true;
        state.askers.clear();
        for worker in state.idle.drain(..) {
            worker.lock().leave = true;
            worker.changed.notify_all();
        }
    }

    fn thread(&self, worker: Arc<Worker>) -> Thread {
        Thread {
            worker: Some(worker),
            shared: Arc::clone(&self.shared),
        }
    }

    fn ask_for_a_thread(&self) -> io::Result<Arc<Worker>> {
        let worker = Arc::new(Worker::default());
        let shared = Arc::clone(&self.shared);
        let serving = Arc::clone(&worker);
        std::thread::Builder::new()
            .name("voidport-request".to_owned())
            .spawn(move || shared.serve(&serving))?;
        Ok(worker)
    }
}

impl Drop for Pool {
    /// Closes the pool without waiting: the last holder of the pool may be a
    /// task on a runtime worker, which must not block on a host call in
    /// flight.
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        Self::closing(&mut state);
    }
}

struct Waiting {
    shared: Arc<Shared>,
    id: u64,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.askers.retain(|asker| asker.id != self.id);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread::{JoinHandle, ThreadId};

    use super::*;

    fn pool() -> (Pool, JoinHandle<()>) {
        let shared = Arc::new(Shared::default());
        let worker = Arc::new(Worker::default());
        let thread = {
            let (shared, worker) = (Arc::clone(&shared), Arc::clone(&worker));
            std::thread::spawn(move || shared.serve(&worker))
        };
        shared.lock().idle.push(worker);
        (Pool { shared }, thread)
    }

    async fn pending<F: std::future::Future>(future: std::pin::Pin<&mut F>) -> bool {
        let mut future = future;
        std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx).is_pending()))
            .await
    }

    async fn ran_on(thread: &mut Thread) -> ThreadId {
        thread
            .run(|| std::thread::current().id())
            .await
            .expect("the call answers")
    }

    #[tokio::test]
    async fn an_idle_thread_runs_the_next_call() {
        let (pool, first) = pool();
        let mut thread = pool.acquire().await.expect("open");
        assert_eq!(ran_on(&mut thread).await, first.thread().id());
        drop(thread);
        let mut again = pool
            .wait_for_a_thread()
            .await
            .expect("the thread given back");
        assert_eq!(ran_on(&mut again).await, first.thread().id());
    }

    #[tokio::test]
    async fn an_acquire_while_the_only_thread_is_held_gets_another() {
        let (pool, _first) = pool();
        let mut first = pool.acquire().await.expect("open");
        let mut second = pool.acquire().await.expect("a second thread");
        assert_ne!(ran_on(&mut first).await, ran_on(&mut second).await);
    }

    #[tokio::test]
    async fn an_asker_waits_for_the_thread_given_back() {
        let (pool, _first) = pool();
        let mut first = pool.acquire().await.expect("open");
        let first_thread = ran_on(&mut first).await;
        let mut second = std::pin::pin!(pool.wait_for_a_thread());
        assert!(pending(second.as_mut()).await, "the only thread is held");
        drop(first);
        let mut second = second.await.expect("the thread given back");
        assert_eq!(ran_on(&mut second).await, first_thread);
    }

    #[tokio::test]
    async fn askers_are_served_in_the_order_they_asked() {
        let (pool, _first) = pool();
        let held = pool.acquire().await.expect("open");
        let mut early = std::pin::pin!(pool.wait_for_a_thread());
        let mut late = std::pin::pin!(pool.wait_for_a_thread());
        assert!(pending(early.as_mut()).await);
        assert!(pending(late.as_mut()).await);
        drop(held);
        assert!(pending(late.as_mut()).await, "the later asker still waits");
        let early = early.await.expect("the earlier asker is served");
        drop(early);
        late.await.expect("then the later one");
    }

    #[tokio::test]
    async fn a_dropped_acquire_that_was_granted_gives_the_thread_back() {
        let (pool, _first) = pool();
        let held = pool.acquire().await.expect("open");
        {
            let mut abandoned = std::pin::pin!(pool.wait_for_a_thread());
            assert!(pending(abandoned.as_mut()).await);
            drop(held);
        }
        let mut again = pool.acquire().await.expect("the thread came back");
        ran_on(&mut again).await;
    }

    #[tokio::test]
    async fn a_call_that_panics_leaves_its_thread_to_the_next() {
        let (pool, _first) = pool();
        let mut thread = pool.acquire().await.expect("open");
        let failed_on = ran_on(&mut thread).await;
        assert_eq!(
            thread.run(|| panic!("a call that fails")).await,
            Err::<(), _>(Failed)
        );
        drop(thread);
        let mut next = pool.wait_for_a_thread().await.expect("the survivor");
        assert_eq!(ran_on(&mut next).await, failed_on, "the thread survived");
    }

    #[tokio::test]
    async fn closing_wakes_a_waiting_asker_with_the_end() {
        let (pool, _first) = pool();
        let _held = pool.acquire().await.expect("open");
        let pool = Arc::new(pool);
        let waiting = {
            let pool = Arc::clone(&pool);
            tokio::spawn(async move { pool.wait_for_a_thread().await.map(drop) })
        };
        while pool.shared.lock().askers.is_empty() {
            tokio::task::yield_now().await;
        }
        Pool::closing(&mut pool.shared.lock());
        assert_eq!(waiting.await.expect("joined"), Err(Closed));
    }

    #[tokio::test]
    async fn closing_an_idle_pool_lets_its_thread_leave() {
        let (pool, first) = pool();
        Pool::closing(&mut pool.shared.lock());
        first.join().expect("the thread left");
        assert!(pool.acquire().await.is_err(), "an acquire after the close");
    }

    #[tokio::test]
    async fn a_thread_granted_at_the_close_leaves_once_given_back() {
        let (pool, first) = pool();
        let held = pool.acquire().await.expect("open");
        Pool::closing(&mut pool.shared.lock());
        assert!(
            !first.is_finished(),
            "a granted thread is still running until it is given back"
        );
        drop(held);
        first.join().expect("the thread that was held left");
    }

    // Two workers: this test blocks one of them on a channel while the call
    // it spawned has to be run by the other.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_a_pool_returns_at_once_and_the_call_still_finishes() {
        let (pool, first) = pool();
        let mut held = pool.acquire().await.expect("open");
        let (release, released) = mpsc::channel::<()>();
        let (entered, inside) = mpsc::channel();
        let call = tokio::spawn(async move {
            held.run(move || {
                entered.send(()).expect("reported");
                released.recv().expect("released");
            })
            .await
        });
        inside.recv().expect("inside the call");
        drop(pool);
        release.send(()).expect("the call is still running");
        call.await.expect("joined").expect("answered");
        first.join().expect("the thread left after its call");
    }
}
