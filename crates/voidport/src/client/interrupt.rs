use tokio::sync::watch;

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

    #[must_use]
    pub fn none() -> Self {
        Self(None)
    }

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
