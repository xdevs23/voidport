use crossterm::event::KeyEvent;

use super::input;
use crate::event::Effect;
use crate::keys::{self, Action, Context};
use crate::model::{Dialog, Model, Status};

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
