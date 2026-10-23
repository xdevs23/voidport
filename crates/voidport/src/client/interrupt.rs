use tokio::sync::watch;

use super::Caller;

/// Where a request comes from: the program it is sent for, and the interrupt
/// of the kernel request it serves.
#[derive(Clone, Copy, Debug)]
pub struct Origin<'a> {
    pub caller: Caller,
    pub interrupt: &'a Interrupt,
}

impl Origin<'static> {
    /// For a request that no interrupt ends.
    #[must_use]
    pub fn detached(caller: Caller) -> Self {
        Self {
            caller,
            interrupt: Interrupt::NEVER,
        }
    }
}

impl Default for Origin<'static> {
    fn default() -> Self {
        Self::detached(Caller::default())
    }
}

#[derive(Clone, Debug)]
pub struct Interrupt(Option<watch::Receiver<bool>>);

#[derive(Debug)]
pub struct Raise(watch::Sender<bool>);

impl Raise {
    pub fn raise(&self) {
        self.0.send_replace(true);
    }
}

impl Interrupt {
    #[must_use]
    pub fn new() -> (Raise, Self) {
        let (raise, raised) = watch::channel(false);
        (Raise(raise), Self(Some(raised)))
    }

    const NEVER: &'static Self = &Self(None);

    pub(crate) fn raised(&self) -> bool {
        self.0.as_ref().is_some_and(|raised| *raised.borrow())
    }

    /// Waits until it is raised. An interrupt whose raiser was dropped is
    /// never raised.
    pub(crate) async fn wait(&mut self) {
        if let Some(raised) = &mut self.0
            && raised.wait_for(|raised| *raised).await.is_ok()
        {
            return;
        }
        std::future::pending().await
    }
}
