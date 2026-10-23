use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use super::{header, panel, placeholder};
use crate::model::{Mode, Model};

pub(super) fn draw(frame: &mut Frame, model: &Model, area: Rect) {
    let mut lines = placeholder(&model.server).unwrap_or_default();
    if let Some(facts) = model.server.ready() {
        lines.push(header("Server".to_owned()));
        lines.push(Line::from(format!("  version         {}", facts.version)));
        lines.push(Line::from(format!(
            "  state file      {}",
            facts.state_file
        )));
        lines.push(Line::from(format!(
            "  control socket  {}",
            facts.control_socket
        )));
        lines.push(Line::from(format!(
            "  namespaces      {}",
            facts.namespaces
        )));
        lines.push(Line::from(format!("  sessions        {}", sessions(model))));
        lines.push(Line::from(""));

        // The set is live: `voidport-ctl listener add` and `listener remove` change
        // it while the server runs, and the refresh tick re-reads it.
        lines.push(header("Bound endpoints".to_owned()));
        if facts.listeners.is_empty() {
            lines.push(Line::from(
                "  none — this server serves only its control socket",
            ));
        } else {
            // `voidport-ctl` prints the same `Display` of `ListenerInfo`, so a
            // field added to it shows in both.
            for listener in &facts.listeners {
                lines.push(Line::from(format!("  {listener}")));
            }
        }
    }

    if let Some(notes) = &model.notes {
        lines.push(Line::from(""));
        lines.push(header(format!(
            "Namespace \"{}\" is being served",
            notes.namespace
        )));
        lines.push(Line::from("  Mount it from the guest:"));
        for mount in &notes.mounts {
            lines.push(Line::from(Span::styled(
                format!("    {mount}"),
                Style::default().fg(Color::Cyan),
            )));
        }
        lines.push(Line::from("  Reconfigure it from this machine:"));
        lines.push(Line::from(Span::styled(
            format!("    {}", notes.control_command),
            Style::default().fg(Color::Cyan),
        )));
        if let Some(note) = &notes.auth_note {
            lines.push(Line::from(Span::styled(
                format!("  {note}"),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(match model.mode {
        Mode::Attach => "Attached: quitting leaves this server serving.",
        Mode::Serving => "Serving: quitting shuts this server down.",
    }));

    frame.render_widget(
        Paragraph::new(lines)
            .block(panel(" Overview "))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn sessions(model: &Model) -> String {
    model
        .sessions
        .ready()
        .map_or_else(|| "?".to_owned(), |sessions| sessions.len().to_string())
}
