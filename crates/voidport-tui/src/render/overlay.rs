//! What sits on top: the Help overlay, a form, a confirmation.
//!
//! Help is rendered straight from the keybinding table, so it is the canonical
//! list by construction, not by upkeep.

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Wrap};

use super::panel;
use crate::keys::{Binding, HELP_ORDER, bindings, help_rows};
use crate::model::{Dialog, Model};

/// Draws whichever overlay is up, if any.
pub(super) fn draw(frame: &mut Frame, model: &Model, area: Rect) {
    if model.help {
        // Nearly the whole frame, not a comfortable 72%: at the supported
        // minimum width a narrower box wraps the longest binding rows, and a
        // canonical list that folds "suspend to the shell" onto two lines is
        // harder to read than one that uses the terminal it was given.
        let area = centered(area, 90, 90);
        frame.render_widget(Clear, area);
        // The list is longer than any supported terminal — about 60 rows
        // against the 16 the minimum size allows — so it scrolls, and the
        // title says where in it the operator is. A clipped canonical list
        // would be a binding that exists and cannot be read about.
        let rows = help_rows();
        let scroll = model.help_scroll.min(rows.saturating_sub(1));
        frame.render_widget(
            Paragraph::new(help_lines())
                .scroll((u16::try_from(scroll).unwrap_or(u16::MAX), 0))
                .block(panel(format!(
                    " Help — every binding, line {} of {rows}, j/k to scroll, ? or Esc to close ",
                    scroll + 1,
                )))
                .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    match &model.dialog {
        None => {}
        Some(Dialog::Confirm(confirm)) => {
            let area = centered(area, 60, 30);
            frame.render_widget(Clear, area);
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(confirm.prompt.clone()),
                    Line::from(""),
                    Line::from(Span::styled(
                        "y: yes    n: no",
                        Style::default().add_modifier(Modifier::BOLD),
                    )),
                ])
                .block(panel(" Confirm "))
                .wrap(Wrap { trim: false }),
                area,
            );
        }
        Some(Dialog::Form(form)) => {
            let area = centered(area, 72, 70);
            frame.render_widget(Clear, area);
            let mut lines = Vec::new();
            for (index, field) in form.fields.iter().enumerate() {
                let marker = if index == form.focus { ">" } else { " " };
                let value = if index == form.focus && !field.is_choice() {
                    format!("{}_", field.value)
                } else {
                    field.value.clone()
                };
                let text = format!("{marker} {:<12} {value}", field.label);
                lines.push(if index == form.focus {
                    Line::from(Span::styled(
                        text,
                        Style::default().add_modifier(Modifier::BOLD),
                    ))
                } else {
                    Line::from(text)
                });
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("  {}", form.focused().hint),
                Style::default().fg(Color::Gray),
            )));
            if let Some(error) = &form.error {
                lines.push(Line::from(Span::styled(
                    format!("  {error}"),
                    Style::default().fg(Color::Red),
                )));
            }
            lines.push(Line::from(
                "  Tab/Shift-Tab: fields   Enter: submit   Esc: cancel",
            ));
            frame.render_widget(
                Paragraph::new(lines)
                    .block(panel(format!(" {} ", form.title())))
                    .wrap(Wrap { trim: false }),
                area,
            );
        }
    }
}

/// Every binding, grouped by context, exactly as the table holds them.
fn help_lines() -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for context in HELP_ORDER {
        lines.push(Line::from(Span::styled(
            context.title(),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for binding in bindings(*context) {
            lines.push(Line::from(format!(
                "  {:<22} {}",
                chords(binding),
                binding.action.label()
            )));
        }
    }
    lines
}

/// How one binding's keys read.
fn chords(binding: &Binding) -> String {
    if binding.keys.is_empty() {
        // The text-entry binding: no chord of its own, every printable key.
        return "any character".to_owned();
    }
    binding
        .keys
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" / ")
}

/// A centred rectangle, as a percentage of the frame.
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let [area] = Layout::horizontal([Constraint::Percentage(width)])
        .flex(Flex::Center)
        .areas(area);
    let [area] = Layout::vertical([Constraint::Percentage(height)])
        .flex(Flex::Center)
        .areas(area);
    area
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scroll bound the model enforces is counted from the table; the rows
    /// drawn are built from the same table. This is the only place the two
    /// could drift apart.
    #[test]
    fn the_counted_rows_are_the_rows_that_are_drawn() {
        assert_eq!(help_lines().len(), help_rows());
    }
}
