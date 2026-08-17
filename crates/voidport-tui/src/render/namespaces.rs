//! The namespace list.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use super::{filter_line, header, panel, placeholder, row, selected};
use crate::model::Model;
use crate::model::list::window;

/// Draws the namespace list.
pub(super) fn draw(frame: &mut Frame, model: &Model, area: Rect) {
    let mut lines = placeholder(&model.namespaces).unwrap_or_default();
    if let Some(namespaces) = model.namespaces.ready() {
        lines.push(header(row(&[
            ("NAME", 24),
            ("OWNERSHIP", 12),
            ("PERMISSION", 12),
            ("AUTH", 6),
            ("RULES", 5),
        ])));
        let keys = model.namespace_keys();
        let visible = model.namespace_selection.visible(&keys);
        let index = model.namespace_selection.index(&visible);
        // Two border rows, one header, and the filter line when there is one.
        let height = usize::from(area.height)
            .saturating_sub(3 + usize::from(model.namespace_selection.filter().is_some()));
        if visible.is_empty() {
            lines.push(Line::from("  no namespaces"));
        }
        for position in window(visible.len(), index, height) {
            let key = visible[position];
            let Some(summary) = namespaces
                .iter()
                .find(|summary| summary.name.as_str() == key)
            else {
                continue;
            };
            let text = row(&[
                (summary.name.as_str(), 24),
                (&summary.ownership.to_string(), 12),
                (&summary.permission.to_string(), 12),
                (&summary.auth.to_string(), 6),
                (&summary.rules.to_string(), 5),
            ]);
            lines.push(if Some(position) == index {
                selected(text)
            } else {
                Line::from(text)
            });
        }
    }
    if let Some(line) = filter_line(
        model.namespace_selection.filter(),
        model.namespace_selection.is_filtering(),
    ) {
        lines.push(line);
    }

    frame.render_widget(
        Paragraph::new(lines).block(panel(" Namespaces — n: create, d: delete, Enter: rules ")),
        area,
    );
}
