use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use super::{filter_line, header, panel, placeholder, row, selected};
use crate::model::Model;
use crate::model::list::window;

pub(super) fn draw(frame: &mut Frame, model: &Model, area: Rect) {
    let mut lines = placeholder(&model.sessions).unwrap_or_default();
    if let Some(sessions) = model.sessions.ready() {
        lines.push(header(row(&[
            ("ID", 6),
            ("NAMESPACE", 16),
            ("SUBPATH", 20),
            ("VIA", 5),
            ("PEER", 20),
            ("CONNS", 5),
            ("NODES", 6),
            ("HANDLES", 7),
            ("SUBSCR", 6),
        ])));
        let keys = model.session_keys();
        let visible = model.session_selection.visible(&keys);
        let index = model.session_selection.index(&visible);
        let height = usize::from(area.height)
            .saturating_sub(3 + usize::from(model.session_selection.filter().is_some()));
        if visible.is_empty() {
            lines.push(Line::from("  no sessions — nothing is mounted"));
        }
        for position in window(visible.len(), index, height) {
            let key = visible[position];
            let Some(session) = sessions
                .iter()
                .find(|session| session.id.to_string() == *key)
            else {
                continue;
            };
            let text = row(&[
                (&session.id.to_string(), 6),
                (session.namespace.as_str(), 16),
                (&session.subpath, 20),
                (&session.transport, 5),
                (&session.peer, 20),
                (&session.connections.to_string(), 5),
                (&session.nodes.to_string(), 6),
                (&session.handles.to_string(), 7),
                (if session.subscribed { "yes" } else { "no" }, 6),
            ]);
            lines.push(if Some(position) == index {
                selected(text)
            } else {
                Line::from(text)
            });
        }
    }
    if let Some(line) = filter_line(
        model.session_selection.filter(),
        model.session_selection.is_filtering(),
    ) {
        lines.push(line);
    }

    frame.render_widget(
        Paragraph::new(lines).block(panel(" Sessions — refreshed every tick ")),
        area,
    );
}
