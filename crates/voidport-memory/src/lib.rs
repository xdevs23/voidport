//! Memory that the kernel frees without this process freeing any raises no
//! wake. A parked request then waits until [`Memory::wake`] is called.

#![forbid(unsafe_code)]

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Notify;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Refused;

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the host refused the memory")
    }
}

impl std::error::Error for Refused {}

trait Host: Send + Sync {
    fn allocate(&self, len: usize) -> Result<Vec<u8>, Refused>;
}

#[derive(Clone, Copy, Debug, Default)]
struct HostMemory;

impl Host for HostMemory {
    fn allocate(&self, len: usize) -> Result<Vec<u8>, Refused> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| Refused)?;
        // Within the reservation just made, so this cannot allocate again.
        bytes.resize(len, 0);
        Ok(bytes)
    }
}

pub struct Memory {
    host: Box<dyn Host>,
    released: Notify,
    parked: AtomicUsize,
}

impl fmt::Debug for Memory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Memory")
            .field("parked", &self.parked())
            .finish_non_exhaustive()
    }
}

impl Memory {
    #[must_use]
    fn new(host: Box<dyn Host>) -> Arc<Self> {
        Arc::new(Self {
            host,
            released: Notify::new(),
            parked: AtomicUsize::new(0),
        })
    }

    #[must_use]
    pub fn host() -> Arc<Self> {
        Self::new(Box::new(HostMemory))
    }

    pub async fn buffer(self: &Arc<Self>, len: usize, alignment: usize) -> Buffer {
        self.obtain(|| self.make(len, alignment)).await
    }

    /// `attempt` is called again on every wake, so a refused attempt must hold
    /// no lock while the call is parked.
    pub async fn obtain<T>(&self, mut attempt: impl FnMut() -> Result<T, Refused>) -> T {
        if let Ok(obtained) = attempt() {
            return obtained;
        }
        let _parked = Parked::new(&self.parked);
        loop {
            // Registered before the retry: a wake raised between a refusal
            // and the wait below is kept by this future and ends the wait.
            let released = self.released.notified();
            if let Ok(obtained) = attempt() {
                return obtained;
            }
            released.await;
        }
    }

    pub fn make(self: &Arc<Self>, len: usize, alignment: usize) -> Result<Buffer, Refused> {
        let alignment = alignment.max(1);
        let slack = alignment - 1;
        let bytes = self.host.allocate(len.checked_add(slack).ok_or(Refused)?)?;
        let start = bytes.as_ptr() as usize;
        let offset = start.next_multiple_of(alignment) - start;
        Ok(Buffer {
            bytes,
            offset,
            len,
            memory: Arc::clone(self),
        })
    }

    pub fn wake(&self) {
        self.released.notify_waiters();
    }

    #[must_use]
    pub fn parked(&self) -> usize {
        self.parked.load(Ordering::SeqCst)
    }
}

struct Parked<'a>(&'a AtomicUsize);

impl<'a> Parked<'a> {
    fn new(parked: &'a AtomicUsize) -> Self {
        parked.fetch_add(1, Ordering::SeqCst);
        Self(parked)
    }
}

impl Drop for Parked<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct Buffer {
    bytes: Vec<u8>,
    offset: usize,
    len: usize,
    memory: Arc<Memory>,
}

impl Buffer {
    pub fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }
}

impl fmt::Debug for Buffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Buffer")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes[self.offset..self.offset + self.len]
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[self.offset..self.offset + self.len]
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.bytes = Vec::new();
        self.memory.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;

    struct Allowing(Arc<AtomicUsize>);

    impl Host for Allowing {
        fn allocate(&self, len: usize) -> Result<Vec<u8>, Refused> {
            if len > self.0.load(Ordering::SeqCst) {
                return Err(Refused);
            }
            Ok(vec![0; len])
        }
    }

    fn memory(allowed: usize) -> (Arc<Memory>, Arc<AtomicUsize>) {
        let allowing = Arc::new(AtomicUsize::new(allowed));
        (
            Memory::new(Box::new(Allowing(Arc::clone(&allowing)))),
            allowing,
        )
    }

    async fn pending<F: std::future::Future>(future: std::pin::Pin<&mut F>) -> bool {
        let mut future = future;
        std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx).is_pending()))
            .await
    }

    #[tokio::test]
    async fn a_buffer_is_as_long_and_as_aligned_as_it_was_asked_for() {
        let memory = Memory::host();
        for alignment in [1, 2, 512, 4096] {
            let mut buffer = memory.buffer(1000, alignment).await;
            assert_eq!(buffer.len(), 1000);
            assert_eq!(buffer.as_ptr() as usize % alignment, 0);
            buffer[999] = 7;
            buffer.truncate(10);
            assert_eq!(buffer.len(), 10);
        }
    }

    #[tokio::test]
    async fn a_refused_request_parks_and_is_served_when_the_refusal_ends() {
        let (memory, allowing) = memory(0);
        let mut asked = std::pin::pin!(memory.buffer(64, 1));
        assert!(pending(asked.as_mut()).await, "the host refuses");
        assert_eq!(memory.parked(), 1);
        allowing.store(64, Ordering::SeqCst);
        memory.wake();
        assert_eq!(asked.await.len(), 64);
        assert_eq!(memory.parked(), 0);
    }

    #[tokio::test]
    async fn a_released_buffer_serves_the_small_asker_and_keeps_the_large_one_parked() {
        let (memory, allowing) = memory(8);
        let held = memory.make(8, 1).expect("the host gives the first");
        allowing.store(0, Ordering::SeqCst);
        let mut large = std::pin::pin!(memory.buffer(1024, 1));
        let mut small = std::pin::pin!(memory.buffer(16, 1));
        assert!(pending(large.as_mut()).await);
        assert!(pending(small.as_mut()).await);
        assert_eq!(memory.parked(), 2);

        allowing.store(16, Ordering::SeqCst);
        drop(held);
        assert_eq!(small.await.len(), 16);
        assert!(pending(large.as_mut()).await, "the large one stays parked");
        assert_eq!(memory.parked(), 1);
    }

    #[derive(Default)]
    struct Releasing {
        refusals: AtomicUsize,
        refusing: AtomicBool,
        held: Mutex<Option<Buffer>>,
    }

    /// Releases a held buffer on its second refusal, between the refused retry
    /// of the asker and its wait.
    struct ReleasingOnRetry(Arc<Releasing>);

    impl Host for ReleasingOnRetry {
        fn allocate(&self, len: usize) -> Result<Vec<u8>, Refused> {
            let shared = &self.0;
            if !shared.refusing.load(Ordering::SeqCst) {
                return Ok(vec![0; len]);
            }
            if shared.refusals.fetch_add(1, Ordering::SeqCst) == 1 {
                shared.refusing.store(false, Ordering::SeqCst);
                let released = shared.held.lock().expect("the held buffer").take();
                drop(released);
            }
            Err(Refused)
        }
    }

    #[tokio::test]
    async fn a_release_between_a_refused_retry_and_the_wait_serves_the_asker() {
        let shared = Arc::new(Releasing::default());
        let memory = Memory::new(Box::new(ReleasingOnRetry(Arc::clone(&shared))));
        *shared.held.lock().expect("the held buffer") = Some(memory.make(8, 1).expect("given"));
        shared.refusing.store(true, Ordering::SeqCst);

        let mut asked = std::pin::pin!(memory.buffer(64, 1));
        assert!(
            !pending(asked.as_mut()).await,
            "the wake raised before the wait is not missed"
        );
        assert_eq!(shared.refusals.load(Ordering::SeqCst), 2);
        assert!(shared.held.lock().expect("the held buffer").is_none());
        assert_eq!(memory.parked(), 0);
    }

    #[tokio::test]
    async fn a_refused_attempt_parks_and_is_tried_again_on_a_wake() {
        let memory = Memory::host();
        let giving = AtomicBool::new(false);
        let tries = AtomicUsize::new(0);
        let mut asked = std::pin::pin!(memory.obtain(|| {
            tries.fetch_add(1, Ordering::SeqCst);
            if giving.load(Ordering::SeqCst) {
                Ok(7)
            } else {
                Err(Refused)
            }
        }));
        assert!(pending(asked.as_mut()).await, "the attempt is refused");
        assert_eq!(memory.parked(), 1);
        assert_eq!(tries.load(Ordering::SeqCst), 2, "tried, and tried again");
        giving.store(true, Ordering::SeqCst);
        memory.wake();
        assert_eq!(asked.await, 7);
        assert_eq!(memory.parked(), 0);
    }

    #[tokio::test]
    async fn a_dropped_request_is_no_longer_parked() {
        let (memory, _allowing) = memory(0);
        {
            let mut asked = std::pin::pin!(memory.buffer(64, 1));
            assert!(pending(asked.as_mut()).await);
            assert_eq!(memory.parked(), 1);
        }
        assert_eq!(memory.parked(), 0);
    }
}
