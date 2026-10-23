use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use super::{filter_line, header, panel, placeholder, row, selected};
use crate::model::Model;
use crate::model::list::window;

pub(super) fn draw(frame: &mut Frame, model: &Model, area: Rect) {
    let mut lines = Vec::new();
    match model.selected_namespace() {
        None => lines.push(Line::from("no namespace is selected")),
        Some(name) => {
            lines.push(Line::from(format!("namespace \"{name}\"")));
            lines.extend(placeholder(&model.namespace).unwrap_or_default());
        }
    }
    if let Some(spec) = model.namespace_spec() {
        lines.push(header(row(&[("MODE", 8), ("RULE", 32), ("TARGET", 24)])));
        let keys = model.rule_keys();
        let visible = model.rule_selection.visible(&keys);
        let index = model.rule_selection.index(&visible);
        let height = usize::from(area.height)
            .saturating_sub(4 + usize::from(model.rule_selection.filter().is_some()));
        if visible.is_empty() {
            lines.push(Line::from(
                "  no rules — nothing in this namespace resolves",
            ));
        }
        for position in window(visible.len(), index, height) {
            let key = visible[position];
            // By the whole key, path and match: two rules on one directory differ only
            // in the match.
            let Some(rule) = spec
                .rules
                .iter()
                .find(|rule| rule.key().to_string() == key.as_str())
            else {
                continue;
            };
            let text = row(&[
                (&rule.mode.to_string(), 8),
                (key.as_str(), 32),
                (rule.target.as_deref().unwrap_or("—"), 24),
            ]);
            lines.push(if Some(position) == index {
                selected(text)
            } else {
                Line::from(text)
            });
        }
    }
    if let Some(line) = filter_line(
        model.rule_selection.filter(),
        model.rule_selection.is_filtering(),
    ) {
        lines.push(line);
    }

    frame.render_widget(
        Paragraph::new(lines).block(panel(" Rules — a: add, d: remove ")),
        area,
    );
}
