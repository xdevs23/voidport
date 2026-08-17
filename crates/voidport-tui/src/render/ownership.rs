//! The ownership policy of the selected namespace.
//!
//! Rendered in the vocabulary of the state file — mode, unmapped policy,
//! squash ids, `host -> guest` tables — so what an operator reads here and
//! what they would write in the file are the same words. Sentinels are shown
//! as sentinels: a policy written as `uid` is not resolved for display, since
//! that is precisely the fact that makes it portable.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use voidport_control::{IdMapping, OwnershipSpec};

use super::{header, panel, placeholder};
use crate::model::Model;

/// Draws the ownership policy.
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
        lines.push(header("Ownership".to_owned()));
        lines.push(Line::from(format!(
            "  mode        {}",
            spec.ownership.mode()
        )));
        match &spec.ownership {
            OwnershipSpec::Passthrough {} => {
                lines.push(Line::from("  host ids are presented as-is, both ways"));
            }
            OwnershipSpec::Static { uid, gid } => {
                lines.push(Line::from(format!("  static      uid {uid}, gid {gid}")));
            }
            OwnershipSpec::Map {
                unmapped,
                squash_uid,
                squash_gid,
                uid_map,
                gid_map,
            } => {
                lines.push(Line::from(format!("  unmapped    {unmapped}")));
                lines.push(Line::from(format!(
                    "  squash      uid {squash_uid}, gid {squash_gid}"
                )));
                lines.push(Line::from(format!("  uid map     {}", table(uid_map))));
                lines.push(Line::from(format!("  gid map     {}", table(gid_map))));
            }
        }
    }
    frame.render_widget(
        Paragraph::new(lines).block(panel(" Ownership — e: edit the whole policy ")),
        area,
    );
}

/// One id table, in the spelling the editor parses back.
fn table(mappings: &[IdMapping]) -> String {
    if mappings.is_empty() {
        return "empty".to_owned();
    }
    mappings
        .iter()
        .map(|mapping| format!("{}->{}", mapping.host, mapping.guest))
        .collect::<Vec<_>>()
        .join(", ")
}
