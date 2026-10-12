//! The control-plane service: what a request actually does.
//!
//! The service is deliberately synchronous and transport-free — it takes a
//! [`Request`] and returns a [`Response`] — so the whole of the state machine
//! is testable without a socket, and the async layer above it
//! ([`super::listener`]) is only framing.
//!
//! # The mutation contract
//!
//! Every mutation is **serialized, and ordered validate → persist → swap**:
//!
//! 1. one mutation lock is held across the entire sequence, so mutations
//!    linearize and a read-modify-write cannot interleave;
//! 2. the edit is applied to a *copy* of the source document and the affected
//!    namespace is rebuilt through the engine's build boundary — a rejected
//!    mutation therefore touches neither memory nor file;
//! 3. the new document is persisted durably;
//! 4. only then is the new snapshot published.
//!
//! Publishing last is what removes the rollback path entirely: if the persist
//! fails, nothing was ever published, so memory and disk cannot diverge. The
//! reverse order (swap then persist) has no correct recovery — the operator
//! would have been told "done" about a change the disk does not hold.
//!
//! One persist failure is not a "nothing happened" failure: the one that comes
//! *after* the rename that replaced the state file
//! ([`PersistError::Committed`]). The file already holds the change, so the
//! snapshot is published, the operation reports success, and the daemon logs a
//! durability warning. Refusing to publish there would be the very divergence
//! this ordering exists to prevent — memory would keep serving a document the file
//! no longer holds, and a restart would silently adopt the change.
//!
//! Reads take the published snapshot behind a short read lock and never wait
//! for a mutation to finish.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};

use voidport_control::{
    ControlError, ErrorCode, Listener, ListenerInfo, NamespaceName, NamespaceSpec,
    NamespaceSummary, PathResolution, Reply, Request, Response, Rule, ShareMode, XattrRule,
};

use crate::data::listener::{BoundListener, DataListeners, ListenerError};
use crate::data::pin::{DescriptorBudget, DescriptorLimit};
use crate::data::sessions::Sessions;
use crate::data::subscribe::{NotificationQueue, Subscribers};
use crate::error::render;
use crate::namespace::Namespace;
use crate::records::{RecordHome, RecordStore};
use crate::registry::{Registry, summarize};
use crate::rules::{
    EffectiveMode, HostBacking, NamespacePath, Resolution, TableError, XattrRulesError,
};
use crate::state::{
    Environment, Limits, LoadedState, PersistError, StateDocument, build_namespace, persist,
};

/// A consistent view of the server's state: the source document and the built
/// namespaces that came from it, always swapped together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The source of truth, exactly as the state file holds it.
    pub document: StateDocument,
    /// The built namespaces.
    pub registry: Registry,
}

/// The published snapshot, shared by everything that reads it.
///
/// It is a handle of its own, not a private field of [`Service`], because
/// the data plane reads it constantly: every path-resolving operation of every
/// session consults the *current* registry for its namespace name, so a rule
/// added through the control plane is visible to the very next lookup (design:
/// "Session lifecycle"). Handing sessions the whole service instead would close
/// an `Arc` cycle, since the service owns the live-session list.
///
/// Only this module can publish into it; everyone else reads.
///
/// It also owns the **share subscriber registry**, and that is not an accident
/// of convenience: the subscription contract requires registration and
/// publication to linearize, so both run under this very write lock. A
/// subscriber therefore captures a snapshot and joins the fan-out atomically —
/// every delta it receives postdates its snapshot, and none falls between.
#[derive(Debug)]
pub struct Published {
    snapshot: RwLock<Arc<Snapshot>>,
    subscribers: Subscribers,
}

impl Published {
    /// A cell holding `snapshot`, with nobody subscribed.
    #[must_use]
    pub fn new(snapshot: Snapshot) -> Arc<Self> {
        Arc::new(Self {
            snapshot: RwLock::new(Arc::new(snapshot)),
            subscribers: Subscribers::new(),
        })
    }

    /// The currently published snapshot.
    ///
    /// The read lock is held only long enough to clone the handle, so a read
    /// never queues behind a mutation's persist.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(
            &self
                .snapshot
                .read()
                .unwrap_or_else(|poison| poison.into_inner()),
        )
    }

    /// The namespace of that name, as the server currently publishes it.
    ///
    /// `None` means the registry no longer holds the name — the namespace was
    /// deleted — which is what sends a session back to its tombstone.
    #[must_use]
    pub fn namespace(&self, name: &NamespaceName) -> Option<Arc<Namespace>> {
        self.snapshot().registry.get(name)
    }

    /// The namespace of that name and the record store that goes with it,
    /// taken from **one** snapshot read.
    ///
    /// The handshake takes both together on purpose: a session captures its
    /// store handle beside its namespace resolution, so a namespace deleted
    /// while it is serving does not take the store from underneath it.
    #[must_use]
    pub fn mount_of(
        &self,
        name: &NamespaceName,
    ) -> Option<(Arc<Namespace>, Option<Arc<RecordStore>>)> {
        let snapshot = self.snapshot();
        let namespace = snapshot.registry.get(name)?;
        Some((namespace, snapshot.registry.records(name)))
    }

    /// Starts — or restarts — a session's share subscription.
    ///
    /// Taken under the **write** lock even though nothing is published: that is
    /// the whole point. Capturing the table the snapshot describes and joining
    /// the fan-out cannot be two steps, or a publish landing between them would
    /// be reported neither in the snapshot nor as a delta.
    pub fn subscribe(
        &self,
        session: u64,
        name: &NamespaceName,
        subpath: &NamespacePath,
        queue: &Arc<NotificationQueue>,
    ) {
        let published = self
            .snapshot
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        self.subscribers
            .register(session, name, subpath, queue, &published.registry);
    }

    /// Ends a session's share subscription. A session that has none is
    /// untouched, which is what makes the operation a plain success.
    pub fn unsubscribe(&self, session: u64) {
        self.subscribers.unregister(session);
    }

    /// Sends a lapsed subscriber the fresh snapshot it is owed.
    ///
    /// Under the write lock for the same reason [`Self::subscribe`] is: the
    /// resnapshot replaces the subscriber's recorded set, and a publish
    /// interleaving with that would diff against a set nobody holds.
    pub fn refresh_subscription(&self, session: u64) {
        let published = self
            .snapshot
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        self.subscribers.refresh(session, &published.registry);
    }

    /// Whether a session is subscribed, for the operator's session list.
    #[must_use]
    pub fn is_subscribed(&self, session: u64) -> bool {
        self.subscribers.is_subscribed(session)
    }

    /// Replaces the published snapshot and fans the change out to subscribers.
    ///
    /// The fan-out runs **inside** the write lock, on the installed snapshot,
    /// which is what linearizes it against registration. It cannot block: a
    /// subscriber's queue either takes a frame or lapses.
    fn publish(&self, snapshot: Snapshot) {
        let mut published = self
            .snapshot
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        *published = Arc::new(snapshot);
        self.subscribers.republish(&published.registry);
    }
}

/// The control-plane service.
#[derive(Debug)]
pub struct Service {
    state_file: PathBuf,
    control_socket: PathBuf,
    environment: Environment,
    /// Where each namespace's record sidecar lives, derived from the state file
    /// once: a namespace-create opens a store there, and a removal deletes it.
    records: RecordHome,
    /// Held across a whole mutation; nothing else takes it.
    mutations: Mutex<()>,
    /// The published snapshot. Readers clone the `Arc` and let go.
    published: Arc<Published>,
    /// The live data-plane sessions. The data plane registers into it; the
    /// control plane only reads it, which is what `session list` is.
    sessions: Arc<Sessions>,
    /// The live data listeners, attached once by startup.
    ///
    /// A cell, not a constructor argument, because of the order startup
    /// runs in: the service exists before the listeners bind, since the data
    /// plane is built around it. What is written once is the *registry*; the
    /// set of listeners inside it is exactly what `listener-add` and
    /// `listener-remove` change, so every read of it is a fresh read.
    listeners: OnceLock<Arc<DataListeners>>,
    /// The bound on cache-resident node descriptors, shared with every session
    /// the data plane builds and reported read-only by `server info`.
    ///
    /// Sized once, at startup, from the configured budget or from the
    /// descriptor limit the raise reached: startup-only, like the listeners.
    descriptor_budget: Arc<DescriptorBudget>,
    /// The file this process's tracing is written to, when it is written to
    /// one. Reported read-only by `server info`; nothing here opens it.
    log_file: Option<PathBuf>,
}

impl Service {
    /// Builds the service around freshly loaded state.
    ///
    /// `descriptors` is the soft descriptor limit the server runs under, which
    /// an unconfigured node descriptor budget is derived from. It is passed in
    /// because startup has just *raised* it and therefore already knows it.
    ///
    /// `log_file` is where the *process* sends its tracing, which the service
    /// only repeats: the subscriber and its destination are the binary's, and
    /// were settled before any of this existed.
    #[must_use]
    pub fn new(
        state_file: impl Into<PathBuf>,
        control_socket: impl Into<PathBuf>,
        environment: Environment,
        loaded: LoadedState,
        descriptors: DescriptorLimit,
        log_file: Option<PathBuf>,
    ) -> Self {
        let limits = loaded.document.server.limits;
        let descriptor_budget =
            DescriptorBudget::sized(loaded.document.server.node_descriptor_budget, descriptors);
        let state_file = state_file.into();
        let records = RecordHome::for_state_file(&state_file);
        Self {
            state_file,
            control_socket: control_socket.into(),
            environment,
            records,
            mutations: Mutex::new(()),
            published: Published::new(Snapshot {
                document: loaded.document,
                registry: loaded.registry,
            }),
            sessions: Sessions::new(limits.max_sessions),
            listeners: OnceLock::new(),
            descriptor_budget,
            log_file,
        }
    }

    /// The node descriptor cache every session pins through.
    ///
    /// Server-global because the descriptor table it bounds is, and read at
    /// startup because it is startup-only: nothing in the control protocol
    /// changes it.
    #[must_use]
    pub fn descriptor_budget(&self) -> Arc<DescriptorBudget> {
        Arc::clone(&self.descriptor_budget)
    }

    /// Hands the service the registry of live data listeners, so `server info`
    /// can report where guests connect and the listener operations have
    /// something to operate on.
    ///
    /// Called once, by startup, after binding. A second call is ignored: a
    /// server has one data plane.
    pub fn attach_listeners(&self, listeners: Arc<DataListeners>) {
        let _ = self.listeners.set(listeners);
    }

    /// The endpoints the data listeners are bound to right now; empty for a
    /// server that has none, and before startup attaches the registry.
    #[must_use]
    pub fn listeners(&self) -> Vec<ListenerInfo> {
        self.listeners
            .get()
            .map(|listeners| listeners.info())
            .unwrap_or_default()
    }

    /// The listener registry, or the error for a service that has no data
    /// plane attached — which only startup could cause, and does not.
    fn data_listeners(&self) -> Result<&Arc<DataListeners>, ControlError> {
        self.listeners
            .get()
            .ok_or_else(|| internal("the data plane is not attached"))
    }

    /// The live-session registry the data plane publishes into.
    ///
    /// The caps are read once, at startup: the session registry is built with
    /// the state file's `max_sessions`, and changing it takes a restart (v1).
    #[must_use]
    pub fn sessions(&self) -> Arc<Sessions> {
        Arc::clone(&self.sessions)
    }

    /// The resource caps the server was started with.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.snapshot().document.server.limits
    }

    /// The state file the server owns.
    #[must_use]
    pub fn state_file(&self) -> &Path {
        &self.state_file
    }

    /// The control socket the server serves.
    #[must_use]
    pub fn control_socket(&self) -> &Path {
        &self.control_socket
    }

    /// The currently published snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.published.snapshot()
    }

    /// The published-snapshot handle, for readers that outlive a single read.
    ///
    /// The data plane holds it: a session resolves against the *current*
    /// registry on every path-resolving operation, and this is the handle it
    /// resolves through.
    #[must_use]
    pub fn published(&self) -> Arc<Published> {
        Arc::clone(&self.published)
    }

    /// Answers one request line, classifying every parse failure.
    #[must_use]
    pub fn handle_line(&self, line: &[u8]) -> Response {
        match voidport_control::parse_request(line) {
            Ok(request) => self.handle(request),
            Err(error) => Response::error(error),
        }
    }

    /// Answers one request.
    #[must_use]
    pub fn handle(&self, request: Request) -> Response {
        let result = match request {
            Request::ServerInfo {} => Ok(self.server_info()),
            Request::NamespaceList {} => Ok(self.namespace_list()),
            Request::NamespaceShow { name } => self.namespace_show(&name),
            Request::NamespaceCreate { namespace } => self.namespace_create(namespace),
            Request::NamespaceDelete { name } => self.namespace_delete(&name),
            Request::RuleAdd { namespace, rule } => self.rule_add(&namespace, rule),
            Request::RuleRemove {
                namespace,
                path,
                r#match,
            } => self.rule_remove(&namespace, &path, r#match.as_deref()),
            Request::XattrAdd { namespace, rule } => self.xattr_add(&namespace, rule),
            Request::XattrRemove { namespace, r#match } => self.xattr_remove(&namespace, &r#match),
            Request::OwnershipSet {
                namespace,
                ownership,
            } => self.mutate_namespace(&namespace, |spec| {
                spec.ownership = ownership;
                Ok(())
            }),
            Request::PermissionSet { namespace, mode } => {
                self.mutate_namespace(&namespace, |spec| {
                    spec.permission = mode;
                    Ok(())
                })
            }
            Request::DirectIoSet { namespace, posture } => {
                self.mutate_namespace(&namespace, |spec| {
                    spec.direct_io = posture;
                    Ok(())
                })
            }
            Request::PrivilegedBitsSet { namespace, enabled } => {
                self.mutate_namespace(&namespace, |spec| {
                    spec.privileged_bits = enabled;
                    Ok(())
                })
            }
            Request::AuthSet { namespace, mode } => self.mutate_namespace(&namespace, |spec| {
                spec.auth = mode;
                Ok(())
            }),
            Request::SessionList {} => Ok(self.session_list()),
            Request::ListenerAdd { listener } => self.listener_add(listener),
            Request::ListenerRemove { endpoint } => self.listener_remove(&endpoint),
            Request::Resolve { namespace, path } => self.resolve(&namespace, &path),
        };
        match result {
            Ok(reply) => Response::ok(reply),
            Err(error) => Response::error(error),
        }
    }

    /// Facts about the running server.
    fn server_info(&self) -> Reply {
        Reply::ServerInfo {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            state_file: self.state_file.display().to_string(),
            control_socket: self.control_socket.display().to_string(),
            namespaces: self.snapshot().registry.len(),
            listeners: self.listeners(),
            node_descriptors: self.descriptor_budget.resident(),
            node_descriptor_budget: self.descriptor_budget.budget(),
            log_file: self
                .log_file
                .as_ref()
                .map(|path| path.display().to_string()),
        }
    }

    /// Every namespace, summarized in name order.
    fn namespace_list(&self) -> Reply {
        let snapshot = self.snapshot();
        let mut namespaces: Vec<NamespaceSummary> = snapshot
            .document
            .namespaces
            .iter()
            .filter_map(|spec| {
                let namespace = snapshot.registry.get(&spec.name)?;
                Some(summarize(
                    &namespace,
                    spec.ownership.mode(),
                    spec.rules.len(),
                ))
            })
            .collect();
        namespaces.sort_by(|left, right| left.name.cmp(&right.name));
        Reply::NamespaceList { namespaces }
    }

    /// Every live data-plane session, in session-id order.
    fn session_list(&self) -> Reply {
        Reply::SessionList {
            sessions: self.sessions.list(),
        }
    }

    /// One namespace, in the source form the file holds.
    fn namespace_show(&self, name: &NamespaceName) -> Result<Reply, ControlError> {
        self.snapshot()
            .document
            .namespace(name)
            .map(|namespace| Reply::Namespace {
                namespace: namespace.clone(),
            })
            .ok_or_else(|| not_found(name))
    }

    /// How one path resolves against the published rules of a namespace.
    fn resolve(&self, name: &NamespaceName, path: &str) -> Result<Reply, ControlError> {
        let namespace = self
            .published
            .namespace(name)
            .ok_or_else(|| not_found(name))?;
        let path = NamespacePath::parse(path).map_err(|source| {
            ControlError::new(ErrorCode::InvalidRequest, format!("{path:?}: {source}"))
        })?;
        Ok(Reply::Resolution {
            resolution: path_resolution(namespace.rules().resolve_path(&path)),
        })
    }

    /// Adds a whole namespace.
    fn namespace_create(&self, namespace: NamespaceSpec) -> Result<Reply, ControlError> {
        let name = namespace.name.clone();
        self.mutate(|document| {
            if document.namespace(&name).is_some() {
                return Err(ControlError::new(
                    ErrorCode::AlreadyExists,
                    format!("namespace {:?} already exists", name.as_str()),
                ));
            }
            document.namespaces.push(namespace);
            Ok(Change::Upsert(name.clone()))
        })
    }

    /// Removes a namespace. Existing holders keep their snapshot.
    fn namespace_delete(&self, name: &NamespaceName) -> Result<Reply, ControlError> {
        self.mutate(|document| {
            let Some(index) = document
                .namespaces
                .iter()
                .position(|namespace| &namespace.name == name)
            else {
                return Err(not_found(name));
            };
            document.namespaces.remove(index);
            Ok(Change::Remove(name.clone()))
        })
    }

    /// Adds one rule to a namespace.
    fn rule_add(&self, name: &NamespaceName, rule: Rule) -> Result<Reply, ControlError> {
        self.mutate_namespace(name, |spec| {
            spec.rules.push(rule);
            Ok(())
        })
    }

    /// Removes the rule keyed by a path and, for a pattern rule, a match.
    /// There is no modify operation: a change is a remove followed by an add.
    ///
    /// The key is the pair, so removing a pattern names its match and removing
    /// a literal or wildcard rule names none — a directory carrying two pattern
    /// rules is otherwise ambiguous about which one was meant.
    fn rule_remove(
        &self,
        name: &NamespaceName,
        path: &str,
        matches: Option<&str>,
    ) -> Result<Reply, ControlError> {
        self.mutate_namespace(name, |spec| {
            let Some(index) = spec
                .rules
                .iter()
                .position(|rule| rule.keyed_by(path, matches))
            else {
                let rule = match matches {
                    Some(matches) => format!("{path:?} with match {matches:?}"),
                    None => format!("{path:?}"),
                };
                return Err(ControlError::new(
                    ErrorCode::NotFound,
                    format!("namespace {:?} has no rule at {rule}", spec.name.as_str()),
                ));
            };
            spec.rules.remove(index);
            Ok(())
        })
    }

    /// Adds one extended-attribute rule to a namespace.
    ///
    /// A duplicate match is refused by the engine's build boundary, so `xattr
    /// add` and a state file holding the same pair twice fail identically.
    fn xattr_add(&self, name: &NamespaceName, rule: XattrRule) -> Result<Reply, ControlError> {
        self.mutate_namespace(name, |spec| {
            spec.xattr.push(rule);
            Ok(())
        })
    }

    /// Removes the extended-attribute rule keyed by a match. There is no modify
    /// operation here either: a change is a remove followed by an add.
    fn xattr_remove(&self, name: &NamespaceName, matches: &str) -> Result<Reply, ControlError> {
        self.mutate_namespace(name, |spec| {
            let Some(index) = spec.xattr.iter().position(|rule| rule.r#match == matches) else {
                return Err(ControlError::new(
                    ErrorCode::NotFound,
                    format!(
                        "namespace {:?} has no attribute rule matching {matches:?}",
                        spec.name.as_str()
                    ),
                ));
            };
            spec.xattr.remove(index);
            Ok(())
        })
    }

    /// Binds one data listener, persists it, and only then serves it.
    ///
    /// The ordering is the one this operation forces, and it is not the
    /// ordinary validate → persist → swap: a listener cannot be persisted
    /// before it is bound, because a bind is the only thing that can say
    /// whether the endpoint is available at all *and* what port a `:0`
    /// configuration actually got. So it is **bind-unserved → persist →
    /// serve**, and each step's failure is clean because of it:
    ///
    /// * a bind failure carries the operating system's own answer and nothing
    ///   is written;
    /// * a persist failure drops the just-bound socket — which never accepted
    ///   a connection and, for a unix path, unlinks itself on the way out — so
    ///   there is nothing to roll back and nothing was published;
    /// * the accept loop starts last, so a listener the state file does not
    ///   hold has never served a single connection.
    ///
    /// What runs *before* the bind is validation: the settings check the loader
    /// runs, on the document this addition would make, plus the duplicate
    /// refusal — so a second `listener add` of the same thing is answered as a
    /// duplicate, not as a confusing `EADDRINUSE` against this server's
    /// own socket.
    fn listener_add(&self, listener: Listener) -> Result<Reply, ControlError> {
        let _guard = self.mutation_lock();
        let live = self.data_listeners()?;
        let runtime = live
            .runtime()
            .ok_or_else(|| internal("the data plane is not serving"))?;

        let current = self.snapshot();
        let mut document = current.document.clone();
        document.server.listeners.push(listener.clone());
        document.server.validate().map_err(|source| {
            ControlError::new(ErrorCode::InvalidConfiguration, render(&source))
        })?;
        if let Some(held) = live.duplicate(&listener) {
            return Err(ControlError::new(
                ErrorCode::AlreadyExists,
                format!(
                    "this server already serves {} (bound at {})",
                    describe(&listener),
                    held.endpoint
                ),
            ));
        }

        let bound = BoundListener::bind(&listener).map_err(|source| bind_error(&source))?;
        let result = persist(&document, &self.state_file);
        // `bound` is dropped with this frame if the persist failed: the socket
        // closes, and a unix path this call created is unlinked.
        self.commit(document, current.registry.clone(), result)?;
        Ok(Reply::Listener {
            listener: live.publish(&runtime, listener, bound),
        })
    }

    /// Closes one data listener, named by the endpoint it bound.
    ///
    /// The ordinary validate → persist → swap, where **closing the listener is
    /// the swap**: a persist failure publishes nothing and leaves it serving,
    /// and when this answers, no further connection can land on that endpoint.
    ///
    /// Sessions already accepted on it are untouched and keep serving until
    /// their connections die by the ordinary rules. Removal is not an eviction:
    /// an accepted connection has nothing left to do with the listener that
    /// accepted it.
    fn listener_remove(&self, endpoint: &str) -> Result<Reply, ControlError> {
        let _guard = self.mutation_lock();
        let live = self.data_listeners()?;
        let Some(config) = live.configured(endpoint) else {
            return Err(ControlError::new(
                ErrorCode::NotFound,
                format!("no data listener at {endpoint:?}"),
            ));
        };

        let current = self.snapshot();
        let mut document = current.document.clone();
        // The first entry with that source form. Two entries can only be
        // identical here — a runtime addition of a form the server already
        // holds is refused — so which of them goes is not a question.
        let Some(index) = document
            .server
            .listeners
            .iter()
            .position(|held| *held == config)
        else {
            return Err(internal(
                "a bound listener has no entry in the state document",
            ));
        };
        document.server.listeners.remove(index);

        let result = persist(&document, &self.state_file);
        self.commit(document, current.registry.clone(), result)?;
        live.close_blocking(endpoint);
        Ok(Reply::Done {})
    }

    /// Edits one existing namespace's source form and rebuilds it.
    fn mutate_namespace<F>(&self, name: &NamespaceName, edit: F) -> Result<Reply, ControlError>
    where
        F: FnOnce(&mut NamespaceSpec) -> Result<(), ControlError>,
    {
        self.mutate(|document| {
            let spec = document
                .namespace_mut(name)
                .ok_or_else(|| not_found(name))?;
            edit(spec)?;
            Ok(Change::Upsert(name.clone()))
        })
    }

    /// The mutation sequence: validate, persist, then swap.
    fn mutate<F>(&self, edit: F) -> Result<Reply, ControlError>
    where
        F: FnOnce(&mut StateDocument) -> Result<Change, ControlError>,
    {
        let _guard = self.mutation_lock();
        let current = self.snapshot();
        let mut document = current.document.clone();
        let change = edit(&mut document)?;

        let mut registry = current.registry.clone();
        // A removal's store, kept live across the persist: retiring it deletes
        // the sidecar, and recorded truth may not be destroyed for a mutation
        // the disk never took.
        let mut retiring = None;
        match &change {
            Change::Upsert(name) => {
                let spec = document
                    .namespace(name)
                    .ok_or_else(|| internal("the edited namespace vanished from the document"))?;
                let namespace = build_namespace(spec, &self.environment).map_err(|source| {
                    let code = if matches!(
                        source,
                        crate::state::NamespaceError::Rules(TableError::DuplicatePath { .. })
                            | crate::state::NamespaceError::XattrRules(
                                XattrRulesError::DuplicateMatch { .. }
                            )
                    ) {
                        ErrorCode::AlreadyExists
                    } else {
                        ErrorCode::InvalidConfiguration
                    };
                    ControlError::new(code, format!("namespace {:?}: {source}", name.as_str()))
                })?;
                // A name the registry already holds keeps the very store its
                // sessions are writing to; only a namespace-create opens one,
                // and only there can reading a sidecar fail.
                registry
                    .insert(namespace, &self.records)
                    .map_err(|source| {
                        ControlError::new(
                            ErrorCode::InvalidConfiguration,
                            format!("namespace {:?}: {}", name.as_str(), render(&source)),
                        )
                    })?;
            }
            Change::Remove(name) => {
                retiring = registry.remove(name).and_then(|removed| removed.records);
            }
        }

        let result = persist(&document, &self.state_file);
        self.commit(document, registry, result)?;
        // The removal is durable now, so the namespace's recorded truth goes
        // with it: the store takes no further writes and its sidecar is
        // deleted. A re-created name starts empty.
        if let Some(records) = retiring {
            records.retire();
        }
        Ok(Reply::Done {})
    }

    /// Applies the persist commit-point decision: publish, or report failure
    /// having published nothing.
    fn commit(
        &self,
        document: StateDocument,
        registry: Registry,
        result: Result<(), PersistError>,
    ) -> Result<(), ControlError> {
        match result {
            Ok(()) => {
                self.publish(document, registry);
                Ok(())
            }
            // Rename is the commit point. The change is already real, so publish
            // it and report success; only crash durability is unconfirmed.
            Err(PersistError::Committed { path, source }) => {
                self.publish(document, registry);
                tracing::warn!(
                    directory = %path.display(),
                    %source,
                    "state mutation committed, but directory durability could not be confirmed"
                );
                Ok(())
            }
            Err(source) => Err(persist_error(ErrorCode::PersistFailed, &source)),
        }
    }

    /// Publishes a snapshot for every later read to see.
    fn publish(&self, document: StateDocument, registry: Registry) {
        self.published.publish(Snapshot { document, registry });
    }

    /// Takes the mutation lock, ignoring poisoning: a panicking mutation
    /// publishes nothing, so the state a later mutation reads is still whole.
    fn mutation_lock(&self) -> MutexGuard<'_, ()> {
        self.mutations
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// Which namespace a mutation touched, and how.
enum Change {
    /// The namespace must be (re)built and published.
    Upsert(NamespaceName),
    /// The namespace must leave the registry.
    Remove(NamespaceName),
}

/// The error for an operation naming a namespace that does not exist.
fn not_found(name: &NamespaceName) -> ControlError {
    ControlError::new(
        ErrorCode::NotFound,
        format!("no namespace {:?}", name.as_str()),
    )
}

/// A persist failure, rendered with the whole cause chain the operator needs.
fn persist_error(code: ErrorCode, source: &PersistError) -> ControlError {
    ControlError::new(code, render(source))
}

/// A bind failure, rendered with the whole cause chain — which is where the
/// operating system's own answer (`Address already in use`, and the rest) is.
fn bind_error(source: &ListenerError) -> ControlError {
    ControlError::new(ErrorCode::BindFailed, render(source))
}

/// How a listener's source form reads in a message: what the operator asked
/// for, not where it landed.
fn describe(listener: &Listener) -> String {
    match listener {
        Listener::Tcp { addr } => format!("tcp {addr}"),
        Listener::Unix { path } => format!("unix {}", path.display()),
        Listener::Vsock { cid, port } if *cid == voidport_control::ANY_CID => {
            format!("vsock any:{port}")
        }
        Listener::Vsock { cid, port } => format!("vsock {cid}:{port}"),
    }
}

/// A resolution in the vocabulary of the control plane.
fn path_resolution(resolution: Resolution) -> PathResolution {
    match resolution {
        Resolution::HostBacked { backing, mode } => PathResolution::Host {
            mode: match mode {
                EffectiveMode::Rw => ShareMode::Rw,
                EffectiveMode::Ro => ShareMode::Ro,
            },
            host_path: host_path(&backing),
        },
        Resolution::SynthesizedDir => PathResolution::Synthesized {},
        Resolution::Nonexistent => PathResolution::Absent {},
    }
}

/// The graft target and the components beneath it, joined for a reader.
fn host_path(backing: &HostBacking) -> String {
    let graft = backing.graft().as_str().trim_end_matches('/');
    let path = backing
        .relative()
        .iter()
        .fold(graft.to_owned(), |path, name| format!("{path}/{name}"));
    if path.is_empty() {
        "/".to_owned()
    } else {
        path
    }
}

/// The error for a condition the server believes impossible.
fn internal(message: &str) -> ControlError {
    ControlError::new(ErrorCode::Internal, message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use voidport_control::NamespaceName;

    fn service() -> Service {
        let document = StateDocument::default();
        Service::new(
            "state.toml",
            "control.sock",
            Environment::new(1, 2, "."),
            LoadedState {
                registry: Registry::new(),
                document,
            },
            DescriptorLimit::current(),
            None,
        )
    }

    fn changed() -> (StateDocument, Registry) {
        let mut document = StateDocument::default();
        let name = NamespaceName::new("landed").expect("valid name");
        document.namespaces.push(NamespaceSpec::new(name));
        (document, Registry::new())
    }

    #[test]
    fn a_pre_rename_failure_publishes_nothing_and_reports_failure() {
        let service = service();
        let (document, registry) = changed();
        let response = service.commit(
            document,
            registry,
            Err(PersistError::NotCommitted {
                path: PathBuf::from("state.toml"),
                source: io::Error::from(io::ErrorKind::PermissionDenied),
            }),
        );
        assert_eq!(
            response.expect_err("the mutation failed").code,
            ErrorCode::PersistFailed
        );
        assert!(service.snapshot().document.namespaces.is_empty());
    }

    #[test]
    fn a_post_rename_failure_publishes_and_reports_success() {
        let service = service();
        let (document, registry) = changed();
        let response = service.commit(
            document,
            registry,
            Err(PersistError::Committed {
                path: PathBuf::from("."),
                source: io::Error::from(io::ErrorKind::PermissionDenied),
            }),
        );
        assert_eq!(response, Ok(()), "the landed mutation succeeds");
        assert_eq!(
            service.snapshot().document.namespaces[0].name.as_str(),
            "landed"
        );
    }

    /// A service with no data plane attached — which only a half-built startup
    /// could produce — refuses the listener operations instead of panicking,
    /// and reports no listeners instead of pretending to none.
    #[test]
    fn the_listener_operations_need_a_data_plane() {
        let service = service();
        assert!(service.listeners().is_empty());
        for request in [
            Request::ListenerAdd {
                listener: Listener::vsock(1024),
            },
            Request::ListenerRemove {
                endpoint: "any:1024".to_owned(),
            },
        ] {
            let Response::Error { error } = service.handle(request) else {
                panic!("a service with no data plane cannot serve a listener operation");
            };
            assert_eq!(error.code, ErrorCode::Internal);
        }
    }

    #[test]
    fn resolve_in_an_unknown_namespace_is_not_found() {
        let service = service();
        let Response::Error { error } = service.handle(Request::Resolve {
            namespace: NamespaceName::new("missing").expect("valid name"),
            path: "/a".to_owned(),
        }) else {
            panic!("an unknown namespace cannot resolve");
        };
        assert_eq!(error.code, ErrorCode::NotFound);
    }

    #[test]
    fn a_resolution_reports_the_host_path_behind_it() {
        use crate::rules::{HostTarget, Name};
        let name = |raw: &str| Name::new(raw).expect("valid name");
        let backing = HostBacking::graft_root(HostTarget::new("/srv/project/"))
            .extend(&[name("src"), name("main.rs")]);
        assert_eq!(
            path_resolution(Resolution::HostBacked {
                backing,
                mode: EffectiveMode::Ro,
            }),
            PathResolution::Host {
                mode: ShareMode::Ro,
                host_path: "/srv/project/src/main.rs".to_owned(),
            }
        );
        assert_eq!(
            host_path(&HostBacking::graft_root(HostTarget::new("/"))),
            "/"
        );
        assert_eq!(
            host_path(&HostBacking::graft_root(HostTarget::new("/")).child(&name("etc"))),
            "/etc"
        );
        assert_eq!(
            path_resolution(Resolution::Nonexistent),
            PathResolution::Absent {}
        );
    }

    /// The message an operator reads names what they asked for, in the
    /// vocabulary they asked for it in.
    #[test]
    fn a_listener_describes_itself_as_it_was_configured() {
        assert_eq!(
            describe(&Listener::Tcp {
                addr: "127.0.0.1:9000".parse().expect("valid address")
            }),
            "tcp 127.0.0.1:9000"
        );
        assert_eq!(
            describe(&Listener::Unix {
                path: PathBuf::from("/run/data.sock")
            }),
            "unix /run/data.sock"
        );
        assert_eq!(describe(&Listener::vsock(1024)), "vsock any:1024");
        assert_eq!(
            describe(&Listener::Vsock { cid: 3, port: 1024 }),
            "vsock 3:1024"
        );
    }
}
