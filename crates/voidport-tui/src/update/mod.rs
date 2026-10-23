mod dialog;
mod input;

use voidport_control::Reply;

use crate::event::{Correlation, Effect, Event, Failure, Fetch};
use crate::model::{Connection, Model, Reconciled, Screen, ServerFacts, Status, View};
use crate::tail::LogRead;

pub fn update(model: &mut Model, event: Event) -> Vec<Effect> {
    match event {
        Event::Key(key) => input::key(model, key),
        Event::Resize { width, height } => {
            model.size = (width, height);
            Vec::new()
        }
        Event::Tick => refresh(model),
        Event::Fetched { fetch, result } => {
            fetched(model, &fetch, result);
            Vec::new()
        }
        Event::LogRead(read) => {
            tailed(model, read);
            Vec::new()
        }
        Event::Answered {
            correlation,
            result,
        } => answered(model, correlation, result),
        Event::Connected => connected(model),
        Event::Disconnected { reason, attempt } => {
            model.status = Status::failure(format!("connection lost: {reason}"));
            model.connection = Connection::Lost { reason, attempt };
            Vec::new()
        }
        Event::ServerStopped { reason } => {
            model.finished = true;
            model.status = match &reason {
                Some(reason) => Status::failure(format!("the server stopped: {reason}")),
                None => Status::info("the server stopped"),
            };
            Vec::new()
        }
        Event::Stop => quit(model),
    }
}

pub(crate) fn quit(model: &mut Model) -> Vec<Effect> {
    model.finished = true;
    vec![Effect::Quit]
}

pub(crate) fn views(model: &Model, screen: Screen) -> Vec<Fetch> {
    match screen {
        Screen::Overview => vec![Fetch::ServerInfo, Fetch::Sessions],
        Screen::Namespaces => vec![Fetch::Namespaces],
        Screen::Rules | Screen::Ownership | Screen::Modes => {
            let mut fetches = vec![Fetch::Namespaces];
            if let Some(name) = model.selected_namespace() {
                fetches.push(Fetch::Namespace(name));
            }
            fetches
        }
        Screen::Sessions => vec![Fetch::Sessions],
        Screen::Logs => vec![Fetch::ServerInfo],
    }
}

fn tail(model: &Model) -> Vec<Effect> {
    if model.screen != Screen::Logs {
        return Vec::new();
    }
    model
        .log_file()
        .map(|path| {
            vec![Effect::ReadLog {
                path: std::path::PathBuf::from(path),
            }]
        })
        .unwrap_or_default()
}

fn tailed(model: &mut Model, read: LogRead) {
    let path = read.path.display().to_string();
    // Another file is the history of another server, so the old lines are not
    // kept under the new path.
    if model.logs.source.as_deref() != Some(path.as_str()) {
        model.logs.restart(path);
    }
    model.logs.trouble = read.trouble;
    model.logs.append(read.lines);
}

fn every_view(model: &Model) -> Vec<Fetch> {
    let mut fetches = vec![Fetch::ServerInfo, Fetch::Namespaces, Fetch::Sessions];
    if let Some(name) = model.selected_namespace() {
        fetches.push(Fetch::Namespace(name));
    }
    fetches
}

pub(crate) fn refresh(model: &mut Model) -> Vec<Effect> {
    let mut effects = fetch_all(model, views(model, model.screen));
    effects.extend(tail(model));
    effects
}

fn refresh_both(model: &mut Model, origin: Screen) -> Vec<Effect> {
    let mut fetches = views(model, origin);
    for fetch in views(model, model.screen) {
        if !fetches.contains(&fetch) {
            fetches.push(fetch);
        }
    }
    let mut effects = fetch_all(model, fetches);
    effects.extend(tail(model));
    effects
}

fn fetch_all(model: &mut Model, fetches: Vec<Fetch>) -> Vec<Effect> {
    for fetch in &fetches {
        match fetch {
            Fetch::ServerInfo => model.server.requested(),
            Fetch::Namespaces => model.namespaces.requested(),
            Fetch::Namespace(_) => model.namespace.requested(),
            Fetch::Sessions => model.sessions.requested(),
        }
    }
    fetches.into_iter().map(Effect::Fetch).collect()
}

/// A failed re-read replaces the view with the failure instead of drawing
/// old rows as current.
fn fetched(model: &mut Model, fetch: &Fetch, result: Result<Reply, Failure>) {
    let result = match result {
        Ok(reply) => reply,
        Err(failure) => {
            fail(model, fetch, &failure);
            return;
        }
    };
    match (fetch, result) {
        (
            Fetch::ServerInfo,
            // The descriptor-cache counters are diagnostic fields that the overview does
            // not render.
            Reply::ServerInfo {
                version,
                state_file,
                control_socket,
                namespaces,
                listeners,
                log_file,
                ..
            },
        ) => {
            model.version = Some(version.clone());
            model.server = View::Ready(ServerFacts {
                version,
                state_file,
                control_socket,
                namespaces,
                listeners,
                log_file,
            });
        }
        (Fetch::Namespaces, Reply::NamespaceList { namespaces }) => {
            model.namespaces = View::Ready(namespaces);
            let keys = model.namespace_keys();
            if let Reconciled::Dropped(gone) = model.namespace_selection.reconcile(&keys) {
                model.status = Status::info(format!("namespace \"{gone}\" is gone"));
                model.namespace.invalidate();
            }
        }
        (Fetch::Namespace(name), Reply::Namespace { namespace }) => {
            if Some(name) == model.selected_namespace().as_ref() {
                model.adopt_namespace(namespace);
                let keys = model.rule_keys();
                if let Reconciled::Dropped(gone) = model.rule_selection.reconcile(&keys) {
                    model.status = Status::info(format!("rule {gone} is gone"));
                }
            }
        }
        (Fetch::Sessions, Reply::SessionList { sessions }) => {
            model.sessions = View::Ready(sessions);
            let keys = model.session_keys();
            if let Reconciled::Dropped(gone) = model.session_selection.reconcile(&keys) {
                model.status = Status::info(format!("session {gone} ended"));
            }
        }
        (fetch, reply) => fail(
            model,
            fetch,
            &Failure::Unexpected(format!("the server answered {reply:?} to {fetch:?}")),
        ),
    }
}

fn fail(model: &mut Model, fetch: &Fetch, failure: &Failure) {
    let message = failure.to_string();
    match fetch {
        Fetch::ServerInfo => model.server = View::Failed(message),
        Fetch::Namespaces => model.namespaces = View::Failed(message),
        Fetch::Namespace(_) => model.namespace = View::Failed(message),
        Fetch::Sessions => model.sessions = View::Failed(message),
    }
}

/// An answer whose correlation no longer matches the pending mutation
/// belongs to something the model has moved on from, and is dropped.
fn answered(
    model: &mut Model,
    correlation: Correlation,
    result: Result<Reply, Failure>,
) -> Vec<Effect> {
    let Some(pending) = model.pending.as_ref() else {
        return Vec::new();
    };
    if pending.correlation != correlation {
        return Vec::new();
    }
    let pending = model.pending.take().expect("just checked");
    match result {
        Ok(_) => {
            model.status = Status::success(format!("{} — done", pending.description));
            if pending.origin == Screen::Modes {
                model.modes.applied();
            }
            refresh_both(model, pending.origin)
        }
        // A rejection changes nothing else: no view is invalidated, no selection
        // moves, no form reopens.
        Err(failure) => {
            model.status = Status::failure(format!("{}: {failure}", pending.description));
            Vec::new()
        }
    }
}

/// Every view is invalidated first, because the server may be a different
/// one after a restart. Every view is then re-read, so no view stays invalid
/// until its screen is entered.
fn connected(model: &mut Model) -> Vec<Effect> {
    model.connection = Connection::Connected;
    model.status = Status::info("connected");
    model.server.invalidate();
    model.namespaces.invalidate();
    model.namespace.invalidate();
    model.sessions.invalidate();
    let fetches = every_view(model);
    fetch_all(model, fetches)
}

#[cfg(test)]
mod tests;
