use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use super::{header, panel, placeholder, row, selected};
use crate::model::Model;

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
        lines.push(header(row(&[
            ("SETTING", 12),
            ("SERVER", 16),
            ("TO APPLY", 16),
        ])));
        for (index, (label, server, chosen)) in [
            (
                "permission",
                spec.permission.to_string(),
                model.modes.permission.clone(),
            ),
            ("auth", spec.auth.to_string(), model.modes.auth.clone()),
        ]
        .into_iter()
        .enumerate()
        {
            let text = row(&[(label, 12), (&server, 16), (&chosen, 16)]);
            lines.push(if index == model.modes.row {
                selected(text)
            } else {
                Line::from(text)
            });
        }
    }
    frame.render_widget(
        Paragraph::new(lines).block(panel(" Permission / Auth — Space: change, Enter: apply ")),
        area,
    );
}
