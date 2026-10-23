use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use voidport_control::{AuthMode, PermissionMode, Request};

use super::dialog;
use crate::event::{Effect, Fetch};
use crate::keys::{self, Action, Context};
use crate::model::form::{AUTH_MODES, PERMISSION_MODES};
use crate::model::{Confirm, Dialog, Form, Model, Pending, Screen, Selection, Status};

pub(super) const PAGE: isize = 10;

pub(super) fn key(model: &mut Model, key: KeyEvent) -> Vec<Effect> {
    // Quit and suspend come first in every state: in raw mode no signal exists
    // to fall back on if a form swallowed them.
    if let Some(action) = keys::action(Context::Anywhere, key) {
        return act(model, action);
    }
    if model.help {
        return help(model, key);
    }
    if model.dialog.is_some() {
        return dialog::key(model, key);
    }
    if model.selection().is_some_and(Selection::is_filtering) {
        return filter(model, key);
    }
    match resolve(model, key) {
        Some(action) => act(model, action),
        None => Vec::new(),
    }
}

fn help(model: &mut Model, key: KeyEvent) -> Vec<Effect> {
    match keys::action(Context::Help, key) {
        Some(Action::Cancel) => model.help = false,
        Some(Action::SelectNext) => model.scroll_help(1),
        Some(Action::SelectPrevious) => model.scroll_help(-1),
        Some(Action::PageDown) => model.scroll_help(PAGE),
        Some(Action::PageUp) => model.scroll_help(-PAGE),
        Some(Action::SelectFirst) => model.help_scroll = 0,
        Some(Action::SelectLast) => model.scroll_help(isize::MAX),
        _ => {}
    }
    Vec::new()
}

fn resolve(model: &Model, key: KeyEvent) -> Option<Action> {
    keys::action(Context::of(model.screen), key)
        .or_else(|| {
            model
                .screen
                .is_list()
                .then(|| keys::action(Context::List, key))
                .flatten()
        })
        .or_else(|| keys::action(Context::Global, key))
}

fn act(model: &mut Model, action: Action) -> Vec<Effect> {
    match action {
        Action::Quit => super::quit(model),
        Action::ToggleHelp => {
            model.help = true;
            model.help_scroll = 0;
            Vec::new()
        }
        Action::NextScreen => focus(model, model.screen.step(true)),
        Action::PreviousScreen => focus(model, model.screen.step(false)),
        Action::Focus(screen) => focus(model, screen),
        Action::Refresh => {
            model.status = Status::info("refreshing");
            super::refresh(model)
        }
        Action::Suspend => vec![Effect::Suspend],
        Action::SelectNext => step(model, 1),
        Action::SelectPrevious => step(model, -1),
        Action::PageDown => step(model, PAGE),
        Action::PageUp => step(model, -PAGE),
        Action::SelectFirst => jump(model, false),
        Action::SelectLast => jump(model, true),
        Action::StartFilter => {
            if let Some(selection) = model.selection_mut() {
                selection.start_filter();
            }
            Vec::new()
        }
        Action::Cancel => {
            if let Some(selection) = model.selection_mut() {
                selection.stop_filter();
            }
            Vec::new()
        }
        Action::OpenNamespace => focus(model, Screen::Rules),
        Action::CreateNamespace => open(model, Dialog::Form(Form::namespace_create())),
        Action::DeleteNamespace => delete_namespace(model),
        Action::AddRule => add_rule(model),
        Action::RemoveRule => remove_rule(model),
        Action::EditOwnership => edit_ownership(model),
        Action::CycleValue => cycle_mode(model),
        Action::ApplyMode => apply_mode(model),
        Action::Follow => {
            model.logs.follow();
            Vec::new()
        }
        Action::CycleLevel => {
            model.logs.cycle_level();
            Vec::new()
        }
        // Reachable only inside a dialog or a filter, both handled above.
        Action::Confirm
        | Action::NextField
        | Action::PreviousField
        | Action::Submit
        | Action::Backspace
        | Action::TypeText => Vec::new(),
    }
}

fn focus(model: &mut Model, screen: Screen) -> Vec<Effect> {
    model.screen = screen;
    super::refresh(model)
}

fn step(model: &mut Model, delta: isize) -> Vec<Effect> {
    if model.screen == Screen::Modes {
        model.modes.row = usize::from(delta > 0);
        return Vec::new();
    }
    if model.screen == Screen::Logs {
        // Down is towards the newest line, a smaller distance from the bottom of the
        // view.
        model.logs.scroll(-delta);
        return Vec::new();
    }
    let keys = model.keys();
    let before = selected_namespace(model);
    if let Some(selection) = model.selection_mut() {
        selection.step(&keys, delta);
    }
    followed(model, before)
}

fn jump(model: &mut Model, to_end: bool) -> Vec<Effect> {
    if model.screen == Screen::Logs {
        if to_end {
            model.logs.follow();
        } else {
            model.logs.to_oldest();
        }
        return Vec::new();
    }
    let keys = model.keys();
    let before = selected_namespace(model);
    if let Some(selection) = model.selection_mut() {
        selection.jump(&keys, to_end);
    }
    followed(model, before)
}

fn selected_namespace(model: &Model) -> Option<String> {
    model
        .namespace_selection
        .selected()
        .map(std::borrow::ToOwned::to_owned)
}

fn followed(model: &mut Model, before: Option<String>) -> Vec<Effect> {
    if before == selected_namespace(model) {
        return Vec::new();
    }
    model.namespace.invalidate();
    model.rule_selection.clear();
    match model.selected_namespace() {
        Some(name) => {
            model.namespace.requested();
            vec![Effect::Fetch(Fetch::Namespace(name))]
        }
        None => Vec::new(),
    }
}

fn open(model: &mut Model, dialog: Dialog) -> Vec<Effect> {
    model.dialog = Some(dialog);
    Vec::new()
}

fn delete_namespace(model: &mut Model) -> Vec<Effect> {
    let Some(name) = model.selected_namespace() else {
        model.status = Status::failure("no namespace is selected");
        return Vec::new();
    };
    open(
        model,
        Dialog::Confirm(Confirm {
            prompt: format!(
                "Delete namespace \"{name}\"? Sessions already mounted keep serving until they \
                 disconnect; new mounts fail."
            ),
            description: format!("delete namespace \"{name}\""),
            request: Request::NamespaceDelete { name },
        }),
    )
}

fn add_rule(model: &mut Model) -> Vec<Effect> {
    let Some(name) = model.selected_namespace() else {
        model.status = Status::failure("no namespace is selected");
        return Vec::new();
    };
    open(model, Dialog::Form(Form::rule_add(name)))
}

/// The request contains the path and, for a pattern rule, the match of the
/// selected rule: the path alone would identify another rule where a directory
/// has both kinds.
fn remove_rule(model: &mut Model) -> Vec<Effect> {
    // Read off the rule before the dialog, which borrows the model mutably.
    let selected = model.selected_rule().map(|rule| {
        (
            rule.key().to_string(),
            rule.path.clone(),
            rule.r#match.clone(),
        )
    });
    let (Some(namespace), Some((key, path, matches))) = (model.selected_namespace(), selected)
    else {
        model.status = Status::failure("no rule is selected");
        return Vec::new();
    };
    open(
        model,
        Dialog::Confirm(Confirm {
            prompt: format!("Remove rule {key} from \"{namespace}\"?"),
            description: format!("remove rule {key}"),
            request: Request::RuleRemove {
                namespace,
                path,
                r#match: matches,
            },
        }),
    )
}

fn edit_ownership(model: &mut Model) -> Vec<Effect> {
    let Some(spec) = model.namespace_spec() else {
        model.status = Status::failure("the namespace has not been read yet");
        return Vec::new();
    };
    let form = Form::ownership(spec.name.clone(), &spec.ownership);
    open(model, Dialog::Form(form))
}

fn cycle_mode(model: &mut Model) -> Vec<Effect> {
    let (choices, current) = if model.modes.row == 0 {
        (PERMISSION_MODES, &mut model.modes.permission)
    } else {
        (AUTH_MODES, &mut model.modes.auth)
    };
    let index = choices
        .iter()
        .position(|choice| choice == current)
        .unwrap_or(0);
    *current = choices[(index + 1) % choices.len()].to_owned();
    model.modes.edit();
    Vec::new()
}

/// The request contains the value that the screen shows, parsed back through
/// the protocol type, because a hardcoded variant would send a value nobody
/// chose once a second variant exists.
fn apply_mode(model: &mut Model) -> Vec<Effect> {
    let Some(namespace) = model.selected_namespace() else {
        model.status = Status::failure("no namespace is selected");
        return Vec::new();
    };
    let (request, description) = if model.modes.row == 0 {
        let mode = match model.modes.permission.parse::<PermissionMode>() {
            Ok(mode) => mode,
            Err(error) => {
                model.status = Status::failure(error.to_string());
                return Vec::new();
            }
        };
        (
            Request::PermissionSet {
                namespace: namespace.clone(),
                mode,
            },
            format!("set permission of \"{namespace}\" to {mode}"),
        )
    } else {
        let mode = match model.modes.auth.parse::<AuthMode>() {
            Ok(mode) => mode,
            Err(error) => {
                model.status = Status::failure(error.to_string());
                return Vec::new();
            }
        };
        (
            Request::AuthSet {
                namespace: namespace.clone(),
                mode,
            },
            format!("set auth of \"{namespace}\" to {mode}"),
        )
    };
    submit(model, request, description)
}

/// One at a time: a second mutation before the first is answered is rejected
/// with a plain message.
pub(super) fn submit(model: &mut Model, request: Request, description: String) -> Vec<Effect> {
    if let Some(pending) = &model.pending {
        model.status = Status::failure(format!("{} is still in flight", pending.description));
        return Vec::new();
    }
    let correlation = model.correlate();
    model.pending = Some(Pending {
        correlation,
        description: description.clone(),
        origin: model.screen,
    });
    model.status = Status::pending(description);
    vec![Effect::Mutate {
        correlation,
        request,
    }]
}

fn filter(model: &mut Model, key: KeyEvent) -> Vec<Effect> {
    let keys = model.keys();
    let Some(selection) = model.selection_mut() else {
        return Vec::new();
    };
    match keys::action(Context::Filter, key) {
        Some(Action::Backspace) => selection.pop_filter(),
        Some(Action::Confirm) => selection.accept_filter(),
        Some(Action::Cancel) => selection.stop_filter(),
        _ => match typed(key) {
            Some(character) => selection.push_filter(character),
            None => return Vec::new(),
        },
    }
    selection.follow_filter(&keys);
    Vec::new()
}

/// A control or alt chord never types: a terminal that reports `Ctrl-N` as
/// the character `n` would otherwise put an `n` in a form.
pub(super) fn typed(key: KeyEvent) -> Option<char> {
    match key.code {
        KeyCode::Char(character)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            Some(character)
        }
        _ => None,
    }
}
