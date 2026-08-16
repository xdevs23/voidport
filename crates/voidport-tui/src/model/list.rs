//! List selection and filtering.
//!
//! A selection is a **key**, never an index. Every list here is re-fetched
//! once a second, and an index survives a refresh only by accident: one
//! namespace created by another operator shifts every row below it. Keying the
//! selection makes "selections survive refresh where the item still exists"
//! true by construction, and makes its converse — the item is gone, so say so
//! — a single observable event.
//!
//! Scrolling is not stored. The visible window is derived from the selection
//! and the viewport height at render time ([`window`]), so "the selection is
//! always visible" cannot drift out of agreement with what was drawn.

/// The selection and filter of one list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    /// The selected item's key, if the list has one.
    selected: Option<String>,
    /// Set when the selected item vanished from a fetched list.
    ///
    /// It keeps the selection empty until the operator moves it themselves.
    /// Without it, the very next refresh would adopt the first row again and
    /// the clearing the design calls for would last one tick — long enough to
    /// aim the operator's next destructive key at an item they never chose.
    vacated: bool,
    /// The incremental filter, present once one has been started.
    filter: Option<String>,
    /// Whether the filter is being typed. An accepted filter keeps narrowing
    /// the list while the keyboard goes back to the list itself.
    editing: bool,
}

impl Selection {
    /// The selected key.
    #[must_use]
    pub fn selected(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    /// Selects a key outright.
    pub fn select(&mut self, key: impl Into<String>) {
        self.selected = Some(key.into());
        self.vacated = false;
    }

    /// Forgets the selection because the list is about to be about something
    /// else — another namespace's rules, say.
    ///
    /// The next fetched list adopts its first row, which is what an operator
    /// changing subject wants. An item *deleted* under the cursor takes the
    /// other path ([`Self::reconcile`]), which leaves the list unselected.
    pub fn clear(&mut self) {
        self.selected = None;
        self.vacated = false;
    }

    /// The filter text, if filtering.
    #[must_use]
    pub fn filter(&self) -> Option<&str> {
        self.filter.as_deref()
    }

    /// Whether the filter is being typed into.
    #[must_use]
    pub fn is_filtering(&self) -> bool {
        self.editing
    }

    /// Starts filtering, with an empty pattern.
    pub fn start_filter(&mut self) {
        self.filter.get_or_insert_with(String::new);
        self.editing = true;
    }

    /// Accepts the pattern: it keeps narrowing the list, and the keys go back
    /// to the list.
    pub fn accept_filter(&mut self) {
        self.editing = false;
    }

    /// Stops filtering and drops the pattern.
    pub fn stop_filter(&mut self) {
        self.filter = None;
        self.editing = false;
    }

    /// Adds a character to the filter.
    pub fn push_filter(&mut self, character: char) {
        if let Some(filter) = &mut self.filter {
            filter.push(character);
        }
    }

    /// Removes the last character of the filter.
    pub fn pop_filter(&mut self) {
        if let Some(filter) = &mut self.filter {
            filter.pop();
        }
    }

    /// The keys the filter admits, in order.
    ///
    /// Matching is a case-insensitive substring test on the key: an operator
    /// typing `pro` while looking at a hundred namespaces wants the obvious
    /// thing, and anything cleverer would be a query language nobody decided on.
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

    /// Reconciles the selection with a freshly fetched list.
    ///
    /// Returns [`Reconciled::Dropped`] when the selected item is gone — the
    /// caller says so on the status line, because an item vanishing under an
    /// operator's cursor is a fact about the server, not a glitch. The
    /// selection is then left **empty**, and stays empty until the operator
    /// moves it: the design rules that an externally deleted item clears the
    /// selection, and adopting the deleted item's neighbour instead would point
    /// the next `d` at something nobody chose.
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
            // A list that has never had a selection adopts its first row, so
            // the keyboard has somewhere to be as soon as there is anything to
            // be on.
            None if self.vacated => Reconciled::Kept,
            None => {
                self.selected = visible.first().map(|key| (*key).clone());
                Reconciled::Kept
            }
        }
    }

    /// Keeps the selection on a row a changed filter still shows.
    ///
    /// Narrowing a filter is not a deletion: the item is still there, the
    /// operator has merely looked away from it, so the selection follows the
    /// filter instead of clearing.
    pub fn follow_filter(&mut self, keys: &[String]) {
        let visible = self.visible(keys);
        if self.index(&visible).is_none() {
            self.selected = visible.first().map(|key| (*key).clone());
            self.vacated = false;
        }
    }

    /// Moves the selection by `delta` visible rows, clamped at both ends.
    pub fn step(&mut self, keys: &[String], delta: isize) {
        let visible = self.visible(keys);
        let Some(last) = visible.len().checked_sub(1) else {
            self.selected = None;
            return;
        };
        let next = match self.index(&visible) {
            Some(current) => current.saturating_add_signed(delta).min(last),
            // Nothing is selected — the list has just gained rows, or an item
            // was deleted under the cursor. The first move lands on an end
            // instead of skipping a row.
            None if delta < 0 => last,
            None => 0,
        };
        self.selected = Some(visible[next].clone());
        self.vacated = false;
    }

    /// Selects the first or last visible row.
    pub fn jump(&mut self, keys: &[String], to_end: bool) {
        let visible = self.visible(keys);
        self.selected = if to_end {
            visible.last().map(|key| (*key).clone())
        } else {
            visible.first().map(|key| (*key).clone())
        };
        self.vacated = false;
    }

    /// Where the selection sits among the visible rows.
    #[must_use]
    pub fn index(&self, visible: &[&String]) -> Option<usize> {
        let selected = self.selected.as_ref()?;
        visible.iter().position(|key| *key == selected)
    }
}

/// What reconciling a selection against a fresh list did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reconciled {
    /// The selection still names something visible (or the list is empty).
    Kept,
    /// The selected item is gone; it is named so the caller can say which.
    Dropped(String),
}

/// The slice of rows to draw so that `selected` is visible.
///
/// A pure function of the list length, the selected row and the viewport
/// height — which is why the model does not carry a scroll offset at all.
#[must_use]
pub fn window(len: usize, selected: Option<usize>, height: usize) -> std::ops::Range<usize> {
    if height == 0 || len == 0 {
        return 0..0;
    }
    let height = height.min(len);
    let selected = selected.unwrap_or(0).min(len - 1);
    // Keep the selection inside the window, sliding it as little as possible.
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
        // A namespace created above it shifts every index; the key does not.
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

        // And it stays empty: a refresh a second later must not quietly adopt
        // the row the cursor would have landed on.
        assert_eq!(selection.reconcile(&keys(&["a", "c"])), Reconciled::Kept);
        assert_eq!(selection.selected(), None);

        // Moving is the operator's own act, so it selects again.
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

        // Changing subject clears without vacating, so the next list is
        // selected again.
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
        // The filtered-out selection is not a deletion: it follows the filter.
        selection.follow_filter(&list);
        assert_eq!(selection.selected(), Some("gamma"));

        selection.pop_filter();
        assert_eq!(selection.filter(), Some("m"));
        // Accepting keeps the pattern; only clearing drops it.
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
