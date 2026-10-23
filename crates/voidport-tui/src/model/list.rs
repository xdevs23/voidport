#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    selected: Option<String>,
    /// Set when the selected item vanished from a fetched list. It keeps the
    /// selection empty until the operator moves it, so the next destructive key
    /// is not aimed at an item that was never chosen.
    vacated: bool,
    filter: Option<String>,
    editing: bool,
}

impl Selection {
    #[must_use]
    pub fn selected(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    pub fn select(&mut self, key: impl Into<String>) {
        self.selected = Some(key.into());
        self.vacated = false;
    }

    /// The next fetched list adopts its first row, unlike [`Self::reconcile`],
    /// which leaves the list unselected after a deletion.
    pub fn clear(&mut self) {
        self.selected = None;
        self.vacated = false;
    }

    #[must_use]
    pub fn filter(&self) -> Option<&str> {
        self.filter.as_deref()
    }

    #[must_use]
    pub fn is_filtering(&self) -> bool {
        self.editing
    }

    pub fn start_filter(&mut self) {
        self.filter.get_or_insert_with(String::new);
        self.editing = true;
    }

    pub fn accept_filter(&mut self) {
        self.editing = false;
    }

    pub fn stop_filter(&mut self) {
        self.filter = None;
        self.editing = false;
    }

    pub fn push_filter(&mut self, character: char) {
        if let Some(filter) = &mut self.filter {
            filter.push(character);
        }
    }

    pub fn pop_filter(&mut self) {
        if let Some(filter) = &mut self.filter {
            filter.pop();
        }
    }

    #[must_use]
    pub fn visible<'a>(&self, keys: &'a [String]) -> Vec<&'a String> {
        match self.filter.as_deref().filter(|filter| !filter.is_empty()) {
            None => keys.iter().collect(),
            Some(filter) => {
                let needle = filter.to_lowercase();
                keys.iter()
                    .filter(|key| key.to_lowercase().contains(&needle))
                    .collect()
            }
        }
    }

    /// Returns [`Reconciled::Dropped`] when the selected item is gone. The
    /// selection then stays empty until the operator moves it, because adopting
    /// the neighbour would point the next `d` at something nobody chose.
    pub fn reconcile(&mut self, keys: &[String]) -> Reconciled {
        let visible = self.visible(keys);
        match &self.selected {
            // Against the whole list, not the filtered rows: a filter hides an
            // item, it does not delete it.
            Some(selected) if keys.contains(selected) => Reconciled::Kept,
            Some(gone) => {
                let gone = gone.clone();
                self.selected = None;
                self.vacated = true;
                Reconciled::Dropped(gone)
            }
            None if self.vacated => Reconciled::Kept,
            None => {
                self.selected = visible.first().map(|key| (*key).clone());
                Reconciled::Kept
            }
        }
    }

    /// Narrowing a filter is not a deletion, so the selection follows the filter
    /// instead of clearing.
    pub fn follow_filter(&mut self, keys: &[String]) {
        let visible = self.visible(keys);
        if self.index(&visible).is_none() {
            self.selected = visible.first().map(|key| (*key).clone());
            self.vacated = false;
        }
    }

    pub fn step(&mut self, keys: &[String], delta: isize) {
        let visible = self.visible(keys);
        let Some(last) = visible.len().checked_sub(1) else {
            self.selected = None;
            return;
        };
        let next = match self.index(&visible) {
            Some(current) => current.saturating_add_signed(delta).min(last),
            // Nothing is selected: the first move selects an end instead of
            // skipping a row.
            None if delta < 0 => last,
            None => 0,
        };
        self.selected = Some(visible[next].clone());
        self.vacated = false;
    }

    pub fn jump(&mut self, keys: &[String], to_end: bool) {
        let visible = self.visible(keys);
        self.selected = if to_end {
            visible.last().map(|key| (*key).clone())
        } else {
            visible.first().map(|key| (*key).clone())
        };
        self.vacated = false;
    }

    #[must_use]
    pub fn index(&self, visible: &[&String]) -> Option<usize> {
        let selected = self.selected.as_ref()?;
        visible.iter().position(|key| *key == selected)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reconciled {
    Kept,
    Dropped(String),
}

#[must_use]
pub fn window(len: usize, selected: Option<usize>, height: usize) -> std::ops::Range<usize> {
    if height == 0 || len == 0 {
        return 0..0;
    }
    let height = height.min(len);
    let selected = selected.unwrap_or(0).min(len - 1);
    let start = selected.saturating_sub(height - 1).min(len - height);
    let start = start.min(selected);
    start..start + height
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn a_selection_survives_a_refresh_by_key() {
        let mut selection = Selection::default();
        assert_eq!(
            selection.reconcile(&keys(&["a", "b", "c"])),
            Reconciled::Kept
        );
        assert_eq!(selection.selected(), Some("a"));

        selection.select("c");
        assert_eq!(
            selection.reconcile(&keys(&["a", "aa", "b", "c"])),
            Reconciled::Kept
        );
        assert_eq!(selection.selected(), Some("c"));
    }

    #[test]
    fn an_item_deleted_elsewhere_clears_the_selection_and_says_which() {
        let mut selection = Selection::default();
        selection.select("b");
        assert_eq!(
            selection.reconcile(&keys(&["a", "c"])),
            Reconciled::Dropped("b".to_owned())
        );
        assert_eq!(
            selection.selected(),
            None,
            "the neighbour of a deleted item is not a selection the operator made"
        );

        assert_eq!(selection.reconcile(&keys(&["a", "c"])), Reconciled::Kept);
        assert_eq!(selection.selected(), None);

        selection.step(&keys(&["a", "c"]), 1);
        assert_eq!(selection.selected(), Some("a"));
    }

    #[test]
    fn a_list_that_has_never_been_selected_adopts_its_first_row() {
        let mut selection = Selection::default();
        assert_eq!(selection.reconcile(&[]), Reconciled::Kept);
        assert_eq!(selection.selected(), None, "there is nothing to select yet");
        assert_eq!(selection.reconcile(&keys(&["a", "b"])), Reconciled::Kept);
        assert_eq!(selection.selected(), Some("a"));

        // Changing subject clears without vacating, so the first row of the
        // next list is selected.
        selection.clear();
        assert_eq!(selection.reconcile(&keys(&["c", "d"])), Reconciled::Kept);
        assert_eq!(selection.selected(), Some("c"));
    }

    #[test]
    fn stepping_clamps_at_both_ends() {
        let list = keys(&["a", "b", "c"]);
        let mut selection = Selection::default();
        selection.select("a");
        selection.step(&list, 1);
        assert_eq!(selection.selected(), Some("b"));
        selection.step(&list, -5);
        assert_eq!(selection.selected(), Some("a"));
        selection.step(&list, 10);
        assert_eq!(selection.selected(), Some("c"));
        selection.jump(&list, false);
        assert_eq!(selection.selected(), Some("a"));
        selection.jump(&list, true);
        assert_eq!(selection.selected(), Some("c"));
    }

    #[test]
    fn filtering_narrows_the_visible_rows_and_the_movement_with_them() {
        let list = keys(&["alpha", "beta", "gamma"]);
        let mut selection = Selection::default();
        selection.start_filter();
        assert!(selection.is_filtering());
        for character in "ma".chars() {
            selection.push_filter(character);
        }
        assert_eq!(selection.filter(), Some("ma"));
        assert_eq!(selection.visible(&list), vec![&"gamma".to_owned()]);

        selection.select("alpha");
        selection.follow_filter(&list);
        assert_eq!(selection.selected(), Some("gamma"));

        selection.pop_filter();
        assert_eq!(selection.filter(), Some("m"));
        selection.accept_filter();
        assert!(!selection.is_filtering());
        assert_eq!(selection.filter(), Some("m"));
        assert_eq!(selection.visible(&list), vec![&"gamma".to_owned()]);
        selection.stop_filter();
        assert_eq!(selection.filter(), None);
        assert_eq!(selection.visible(&list).len(), 3);
    }

    #[test]
    fn the_window_always_contains_the_selection() {
        assert_eq!(window(0, None, 5), 0..0);
        assert_eq!(window(3, Some(0), 5), 0..3);
        assert_eq!(window(10, Some(0), 3), 0..3);
        assert_eq!(window(10, Some(5), 3), 3..6);
        assert_eq!(window(10, Some(9), 3), 7..10);
        assert_eq!(window(10, Some(9), 0), 0..0);
        for selected in 0..10 {
            let window = window(10, Some(selected), 4);
            assert!(
                window.contains(&selected),
                "{selected} fell out of {window:?}"
            );
        }
    }
}
