//! What the model knows about one server-owned view.
//!
//! Nothing here is ever guessed. A view holds what the server last said, or
//! why it could not be asked — never a locally invented value and never a
//! silently kept stale one: a re-fetch that fails **replaces** the data with
//! the failure, because a list that quietly keeps showing namespaces the
//! server may no longer have is exactly the lie this system's
//! deterministic-state rule exists to prevent.

/// One server-owned value, in whichever state the last exchange left it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum View<T> {
    /// Never asked for.
    #[default]
    Idle,
    /// Asked for; no answer yet.
    Loading,
    /// The server's answer.
    Ready(T),
    /// The server could not be asked, or answered something unusable.
    Failed(String),
}

impl<T> View<T> {
    /// The value, if the last exchange produced one.
    pub fn ready(&self) -> Option<&T> {
        match self {
            Self::Ready(value) => Some(value),
            _ => None,
        }
    }

    /// The failure, if the last exchange produced one.
    pub fn failure(&self) -> Option<&str> {
        match self {
            Self::Failed(message) => Some(message),
            _ => None,
        }
    }

    /// Marks the view as being fetched, keeping nothing.
    ///
    /// Called on the tick, on focus entry and after a reconnect; a view being
    /// re-fetched shows its previous rendering until the answer lands, which
    /// is the render layer's business, not the model's.
    pub fn requested(&mut self) {
        if !matches!(self, Self::Ready(_)) {
            *self = Self::Loading;
        }
    }

    /// Forgets everything: the next render has nothing to show until a fresh
    /// answer arrives. This is what a reconnect does to every view.
    pub fn invalidate(&mut self) {
        *self = Self::Idle;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_view_reports_the_state_it_is_in() {
        let mut view: View<u8> = View::default();
        view.requested();
        assert_eq!(view, View::Loading);

        view = View::Ready(7);
        assert_eq!(view.ready(), Some(&7));
        // A refresh of a ready view keeps what it has: the screen does not
        // blank between ticks.
        view.requested();
        assert_eq!(view.ready(), Some(&7));

        view = View::Failed("no".to_owned());
        assert_eq!(view.failure(), Some("no"));
        assert_eq!(view.ready(), None);

        view.invalidate();
        assert_eq!(view, View::Idle);
    }
}
