//! Keys, resolved through the canonical table and turned into model changes.
//!
//! The table ([`crate::keys`]) decides *what* a key means; this module decides
//! what that means for the model. Nothing here matches on a raw key except the
//! two places the table itself delegates to text entry — a form field and a
//! filter — so the Help overlay cannot fall out of step with the keyboard.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use voidport_control::{AuthMode, PermissionMode, Request};

use super::dialog;
use crate::event::{Effect, Fetch};
use crate::keys::{self, Action, Context};
use crate::model::form::{AUTH_MODES, PERMISSION_MODES};
use crate::model::{Confirm, Dialog, Form, Model, Pending, Screen, Selection, Status};

/// How far a page key moves a selection, or scrolls the Help overlay.
pub(super) const PAGE: isize = 10;

/// Folds one key press into the model.
pub(super) fn key(model: &mut Model, key: KeyEvent) -> Vec<Effect> {
    // Quit and suspend first, and in every state: Help lists them as available
    // anywhere, and in raw mode there is no signal an operator could fall back
    // on if a form swallowed them. They are control chords, so nothing that is
    // being typed can reach this.
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

/// Drives the Help overlay: it swallows the rest of the keyboard, scrolls, and
/// closes.
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

/// Resolves a key against the focused screen, then the shared list bindings,
/// then the global ones.
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

/// Applies an action.
fn act(model: &mut Model, action: Action) -> Vec<Effect> {
    match action {
        Action::Quit => super::quit(model),
        Action::ToggleHelp => {
            model.help = true;
            // Opened at the top: the overlay is read from its first line, and
            // where it was left last time is not where the operator is looking
            // now.
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
            // Outside a dialog, the only thing to dismiss is an accepted
            // filter.
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

/// Focuses a screen, re-reading what it shows.
fn focus(model: &mut Model, screen: Screen) -> Vec<Effect> {
    model.screen = screen;
    super::refresh(model)
}

/// Moves the selection, the mode cursor, or the log view — whichever the
/// focused screen moves.
fn step(model: &mut Model, delta: isize) -> Vec<Effect> {
    if model.screen == Screen::Modes {
        model.modes.row = usize::from(delta > 0);
        return Vec::new();
    }
    if model.screen == Screen::Logs {
        // Down is towards the newest line, which is the bottom of the view, so
        // it is a *smaller* distance from it.
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

/// Selects the first or last row — on the Logs screen, the oldest line the
/// ring still holds or the newest one, which is following again.
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

/// The selected namespace as a plain string, for comparing before and after.
fn selected_namespace(model: &Model) -> Option<String> {
    model
        .namespace_selection
        .selected()
        .map(std::borrow::ToOwned::to_owned)
}

/// Re-reads the per-namespace views when the selected namespace changed.
///
/// The Rules, Ownership and Permission/Auth screens all show *the selected
/// namespace*, so moving the cursor in the namespace list is a change of
/// subject: what they hold no longer describes what is selected, and keeping
/// it on screen would be the stale-data lie.
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

/// Puts a dialog on top.
fn open(model: &mut Model, dialog: Dialog) -> Vec<Effect> {
    model.dialog = Some(dialog);
    Vec::new()
}

/// Asks before deleting a namespace.
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

/// Opens the rule form for the selected namespace.
fn add_rule(model: &mut Model) -> Vec<Effect> {
    let Some(name) = model.selected_namespace() else {
        model.status = Status::failure("no namespace is selected");
        return Vec::new();
    };
    open(model, Dialog::Form(Form::rule_add(name)))
}

/// Asks before removing the selected rule.
///
/// The request carries the *pair* that keys the selected rule — its path and,
/// where it is a pattern rule, its match — read off the rule the row stands
/// for. Sending the path alone would name a different rule than the one under
/// the cursor wherever a directory carries both kinds.
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

/// Opens the ownership editor, pre-filled with the policy the server holds.
fn edit_ownership(model: &mut Model) -> Vec<Effect> {
    let Some(spec) = model.namespace_spec() else {
        model.status = Status::failure("the namespace has not been read yet");
        return Vec::new();
    };
    let form = Form::ownership(spec.name.clone(), &spec.ownership);
    open(model, Dialog::Form(form))
}

/// Changes the value of the selected mode setter, locally.
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

/// Applies the selected mode setter to the server.
///
/// The request carries the value the screen is showing, parsed back through the
/// protocol's own type. v1 defines one mode for each setter, so sending a
/// hardcoded variant would look right today and send a value the operator never
/// chose the day a second one exists.
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

/// Issues one mutation, under a fresh correlation id.
///
/// One at a time: a second mutation before the first is answered would leave
/// the operator reasoning about a state neither end can name, so it is refused
/// with a plain message instead.
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

/// Edits a list filter.
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
    // The selection has to stay on something the filter still shows.
    selection.follow_filter(&keys);
    Vec::new()
}

/// The character a key types, if it types one.
///
/// A control or alt chord never types: those are bindings, and a terminal that
/// reports `Ctrl-N` as the character `n` would otherwise put an `n` in a form.
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
