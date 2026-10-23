#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum View<T> {
    #[default]
    Idle,
    Loading,
    Ready(T),
    /// A failed re-fetch replaces the data, so a list never shows stale
    /// entries.
    Failed(String),
}

impl<T> View<T> {
    pub fn ready(&self) -> Option<&T> {
        match self {
            Self::Ready(value) => Some(value),
            _ => None,
        }
    }

    pub fn failure(&self) -> Option<&str> {
        match self {
            Self::Failed(message) => Some(message),
            _ => None,
        }
    }

    pub fn requested(&mut self) {
        if !matches!(self, Self::Ready(_)) {
            *self = Self::Loading;
        }
    }

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
        // A refresh of a ready view leaves its data in place, so the screen
        // does not blank between ticks.
        view.requested();
        assert_eq!(view.ready(), Some(&7));

        view = View::Failed("no".to_owned());
        assert_eq!(view.failure(), Some("no"));
        assert_eq!(view.ready(), None);

        view.invalidate();
        assert_eq!(view, View::Idle);
    }
}
