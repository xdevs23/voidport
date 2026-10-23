use std::time::Duration;

#[derive(Clone, Debug)]
pub(super) struct Clock {
    base: tokio::time::Instant,
}

impl Clock {
    pub(super) fn new() -> Self {
        Self {
            base: tokio::time::Instant::now(),
        }
    }

    pub(super) fn now(&self) -> Duration {
        self.base.elapsed()
    }

    pub(super) async fn until(&self, deadline: Duration) {
        tokio::time::sleep_until(self.base + deadline).await;
    }
}
