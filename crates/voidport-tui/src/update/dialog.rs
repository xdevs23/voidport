//! Dialogs: the form and the confirmation.
//!
//! Both are modal on purpose. A destructive operation asks first (design:
//! "delete behind a confirmation"), and a form composes one whole operation
//! before anything is sent — the protocol applies ownership and namespace
//! creation whole, so composing them piecemeal against a live server would
//! invent intermediate policies nobody asked for.

use crossterm::event::KeyEvent;

use super::input;
use crate::event::Effect;
use crate::keys::{self, Action, Context};
use crate::model::{Dialog, Model, Status};

/// Folds a key press into whichever dialog is open.
pub(super) fn key(model: &mut Model, key: KeyEvent) -> Vec<Effect> {
    match model.dialog.take() {
        Some(Dialog::Confirm(confirm)) => match keys::action(Context::Confirm, key) {
            Some(Action::Confirm) => input::submit(model, confirm.request, confirm.description),
            Some(Action::Cancel) => {
                model.status = Status::info(format!("{} — cancelled", confirm.description));
                Vec::new()
            }
            _ => {
                model.dialog = Some(Dialog::Confirm(confirm));
                Vec::new()
            }
        },
        Some(Dialog::Form(mut form)) => {
            match keys::action(Context::Form, key) {
                Some(Action::Submit) => match form.request() {
                    Ok(request) => {
                        let description = describe(&form);
                        return input::submit(model, request, description);
                    }
                    // A local validation failure keeps the form exactly as it
                    // is: the operator sees what to fix, and nothing was sent.
                    Err(reason) => {
                        model.status = Status::failure(reason.clone());
                        form.error = Some(reason);
                    }
                },
                Some(Action::Cancel) => {
                    model.status = Status::info("cancelled");
                    return Vec::new();
                }
                Some(Action::NextField) => form.focus_next(true),
                Some(Action::PreviousField) => form.focus_next(false),
                Some(Action::CycleValue) => form.cycle(true),
                Some(Action::Backspace) => form.backspace(),
                _ => {
                    if let Some(character) = input::typed(key) {
                        form.type_character(character);
                    }
                }
            }
            model.dialog = Some(Dialog::Form(form));
            Vec::new()
        }
        None => Vec::new(),
    }
}

/// What the status line calls a submitted form.
fn describe(form: &crate::model::Form) -> String {
    match &form.kind {
        crate::model::FormKind::NamespaceCreate => {
            format!("create namespace \"{}\"", form.fields[0].value.trim())
        }
        crate::model::FormKind::RuleAdd(namespace) => format!(
            "add rule {} to \"{namespace}\"",
            form.fields[0].value.trim()
        ),
        crate::model::FormKind::Ownership(namespace) => {
            format!("set ownership of \"{namespace}\"")
        }
    }
}
