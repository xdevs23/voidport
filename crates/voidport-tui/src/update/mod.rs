//! The reducer: `(model, event) -> (model, effects)`, and nothing else.
//!
//! Every rule the design states about behaviour lives here, and lives here
//! *only*: freshness, correlation, what a rejection may and may not change,
//! what a reconnect invalidates. No function in this module tree performs I/O,
//! reads a clock or touches a terminal — the tick arrives as an event and the
//! socket answers as an event, so each rule is a test of the form "feed these
//! events, assert this model and these effects".

mod dialog;
mod input;

use voidport_control::Reply;

use crate::event::{Correlation, Effect, Event, Failure, Fetch};
use crate::model::{Connection, Model, Reconciled, Screen, ServerFacts, Status, View};
use crate::tail::LogRead;

/// Folds one event into the model, returning what the outside world must do.
pub fn update(model: &mut Model, event: Event) -> Vec<Effect> {
    match event {
        Event::Key(key) => input::key(model, key),
        Event::Resize { width, height } => {
            model.size = (width, height);
            Vec::new()
        }
        // The shared freshness tick: every *visible* view re-reads, so another
        // operator's `voidport-ctl` mutation shows up within one tick.
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

/// Ends the session: quitting disconnects in attach mode and shuts the server
/// down in serve-and-present, which is the effect runner's business, not the
/// reducer's.
pub(crate) fn quit(model: &mut Model) -> Vec<Effect> {
    model.finished = true;
    vec![Effect::Quit]
}

/// The views the focused screen shows.
///
/// The per-namespace screens read two: the list, because it is what a
/// selection means, and the namespace itself.
pub(crate) fn views(model: &Model, screen: Screen) -> Vec<Fetch> {
    match screen {
        // The Overview reports a session count, so it reads the session list
        // too: the count is the server's, not one the interface keeps.
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
        // The Logs screen reads no rows from the server at all — only where
        // the file is, which is a field of `server-info`.
        Screen::Logs => vec![Fetch::ServerInfo],
    }
}

/// The read the Logs screen wants, when it is the focused screen and the
/// server has said where its log file is.
///
/// Off-screen it wants none: a log nobody is looking at is a file this process
/// has no reason to keep opening, and the ring would only hold the tail of it
/// anyway.
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

/// Applies one read of the log file.
fn tailed(model: &mut Model, read: LogRead) {
    let path = read.path.display().to_string();
    // Another file is another server's history — a reconnect to a restarted
    // server, or a server that now logs elsewhere. Keeping the old lines under
    // the new path would be the stale-data lie in its plainest form.
    if model.logs.source.as_deref() != Some(path.as_str()) {
        model.logs.restart(path);
    }
    model.logs.trouble = read.trouble;
    model.logs.append(read.lines);
}

/// Every view the model holds, whatever screen is focused.
///
/// Used where the model's *whole* picture is worthless — a reconnect — not
/// where only what is on screen has aged.
fn every_view(model: &Model) -> Vec<Fetch> {
    let mut fetches = vec![Fetch::ServerInfo, Fetch::Namespaces, Fetch::Sessions];
    if let Some(name) = model.selected_namespace() {
        fetches.push(Fetch::Namespace(name));
    }
    fetches
}

/// Re-reads everything the focused screen shows.
pub(crate) fn refresh(model: &mut Model) -> Vec<Effect> {
    let mut effects = fetch_all(model, views(model, model.screen));
    effects.extend(tail(model));
    effects
}

/// Re-reads the views of two screens — the one that issued a mutation and the
/// one the operator is looking at, which are not always the same.
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

/// Marks each view as being read and asks for it.
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

/// Applies one view's answer.
///
/// A failed re-read **replaces** the view with the failure. Keeping the old
/// rows and drawing them as if they were current is the one thing a
/// deterministic-state interface may never do.
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
            // The descriptor-cache counters are operator-diagnostic fields the
            // overview does not render; a screen for them is its own change.
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
                // The per-namespace views belonged to it and no longer mean
                // anything.
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
        // A reply of the wrong shape for the request is the answer this view
        // cannot use, which is exactly what `Failure::Unexpected` names.
        (fetch, reply) => fail(
            model,
            fetch,
            &Failure::Unexpected(format!("the server answered {reply:?} to {fetch:?}")),
        ),
    }
}

/// Replaces one view with the failure that stopped it being read.
fn fail(model: &mut Model, fetch: &Fetch, failure: &Failure) {
    let message = failure.to_string();
    match fetch {
        Fetch::ServerInfo => model.server = View::Failed(message),
        Fetch::Namespaces => model.namespaces = View::Failed(message),
        Fetch::Namespace(_) => model.namespace = View::Failed(message),
        Fetch::Sessions => model.sessions = View::Failed(message),
    }
}

/// Applies a mutation's answer to the view that issued it.
///
/// An answer whose correlation no longer matches the pending mutation is
/// dropped: it belongs to something the model has moved on from, and reporting
/// it as the outcome of the current operation would be a lie.
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
                // The buffer the operator edited is now the server's own value,
                // so it goes back to following the server.
                model.modes.applied();
            }
            refresh_both(model, pending.origin)
        }
        // A rejection changes nothing else: no view is invalidated, no
        // selection moves, no form reopens. The server refused; the interface
        // says so and stays exactly as it was.
        Err(failure) => {
            model.status = Status::failure(format!("{}: {failure}", pending.description));
            Vec::new()
        }
    }
}

/// Adopts a fresh connection.
///
/// Every view is invalidated first: the server may be a *different* server —
/// a restart while the TUI was retrying — so nothing read before the drop is
/// evidence of anything now. Every view is then re-read, not only the focused
/// one: the design rules that a reconnect re-fetches everything, and a view
/// left invalid until its screen is next entered would be a hole the operator
/// finds by walking into it.
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
