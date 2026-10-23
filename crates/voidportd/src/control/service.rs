use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};

use voidport_control::{
    AdmittedMode, ControlError, ErrorCode, Listener, ListenerInfo, NamespaceName, NamespaceSpec,
    NamespaceSummary, PathResolution, Reply, Request, Response, Rule, XattrRule,
};

use crate::data::descriptor_budget::{DescriptorBudget, DescriptorLimit};
use crate::data::listener::{BoundListener, DataListeners, ListenerError};
use crate::data::sessions::Sessions;
use crate::data::subscribe::{NotificationQueue, Subscribers};
use crate::error::render;
use crate::namespace::Namespace;
use crate::records::{HostLocator, RecordHome, RecordStore};
use crate::registry::{Registry, summarize};
use crate::rules::{EffectiveMode, NamespacePath, Resolution, TableError, XattrRulesError};
use crate::state::{
    Environment, LoadedState, PersistError, StateDocument, build_namespace, persist,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub document: StateDocument,
    pub registry: Registry,
}

/// Registration and publication of share subscribers run under the same write
/// lock, so a subscriber captures a snapshot and joins the fan-out atomically:
/// every delta it receives postdates its snapshot.
#[derive(Debug)]
pub struct Published {
    snapshot: RwLock<Arc<Snapshot>>,
    subscribers: Subscribers,
}

impl Published {
    #[must_use]
    pub fn new(snapshot: Snapshot) -> Arc<Self> {
        Arc::new(Self {
            snapshot: RwLock::new(Arc::new(snapshot)),
            subscribers: Subscribers::new(),
        })
    }

    /// The read lock lasts only for the clone, so a read never queues behind the
    /// persist of a mutation.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(
            &self
                .snapshot
                .read()
                .unwrap_or_else(|poison| poison.into_inner()),
        )
    }

    /// `None` means the namespace was deleted, which sends a session back to its
    /// tombstone.
    #[must_use]
    pub fn namespace(&self, name: &NamespaceName) -> Option<Arc<Namespace>> {
        self.snapshot().registry.get(name)
    }

    #[must_use]
    pub fn longest_name(&self) -> usize {
        let published = self
            .snapshot
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        published
            .registry
            .iter()
            .map(|namespace| namespace.name().as_str().len())
            .max()
            .unwrap_or(0)
    }

    /// Both come from one snapshot read, so a namespace deleted while a session
    /// serves does not take its store from underneath it.
    #[must_use]
    pub fn mount_of(
        &self,
        name: &NamespaceName,
    ) -> Option<(Arc<Namespace>, Option<Arc<RecordStore>>)> {
        let snapshot = self.snapshot();
        let namespace = snapshot.registry.get(name)?;
        Some((namespace, snapshot.registry.records(name)))
    }

    /// Takes the write lock although nothing is published: capturing the table
    /// and joining the fan-out must be one step, or a publish between them
    /// would be reported neither in the snapshot nor as a delta.
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

    pub fn unsubscribe(&self, session: u64) {
        self.subscribers.unregister(session);
    }

    /// Under the write lock like [`Self::subscribe`]: a publish interleaving
    /// with the resnapshot would diff against a set no consumer has.
    pub fn refresh_subscription(&self, session: u64) {
        let published = self
            .snapshot
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        self.subscribers.refresh(session, &published.registry);
    }

    #[must_use]
    pub fn is_subscribed(&self, session: u64) -> bool {
        self.subscribers.is_subscribed(session)
    }

    /// The fan-out runs inside the write lock, which linearizes it against
    /// registration. It cannot block: the queue of a subscriber accepts a frame
    /// or lapses.
    fn publish(&self, snapshot: Snapshot) {
        let mut published = self
            .snapshot
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        *published = Arc::new(snapshot);
        self.subscribers.republish(&published.registry);
    }
}

#[derive(Debug)]
pub struct Service {
    state_file: PathBuf,
    control_socket: PathBuf,
    environment: Environment,
    records: RecordHome,
    /// Held across a whole mutation; nothing else takes it.
    mutations: Mutex<()>,
    published: Arc<Published>,
    sessions: Arc<Sessions>,
    /// A cell because the service exists before the listeners bind. The set of
    /// listeners inside changes at runtime, so every read is a fresh read.
    listeners: OnceLock<Arc<DataListeners>>,
    descriptor_budget: Arc<DescriptorBudget>,
    log_file: Option<PathBuf>,
}

impl Service {
    #[must_use]
    pub fn new(
        state_file: impl Into<PathBuf>,
        control_socket: impl Into<PathBuf>,
        environment: Environment,
        loaded: LoadedState,
        descriptors: DescriptorLimit,
        log_file: Option<PathBuf>,
    ) -> Self {
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
            sessions: Sessions::new(),
            listeners: OnceLock::new(),
            descriptor_budget,
            log_file,
        }
    }

    #[must_use]
    pub fn descriptor_budget(&self) -> Arc<DescriptorBudget> {
        Arc::clone(&self.descriptor_budget)
    }

    /// A second call is ignored: a server has one data plane.
    pub fn attach_listeners(&self, listeners: Arc<DataListeners>) {
        let _ = self.listeners.set(listeners);
    }

    #[must_use]
    pub fn listeners(&self) -> Vec<ListenerInfo> {
        self.listeners
            .get()
            .map(|listeners| listeners.info())
            .unwrap_or_default()
    }

    fn data_listeners(&self) -> Result<&Arc<DataListeners>, ControlError> {
        self.listeners
            .get()
            .ok_or_else(|| internal("the data plane is not attached"))
    }

    #[must_use]
    pub fn sessions(&self) -> Arc<Sessions> {
        Arc::clone(&self.sessions)
    }

    #[must_use]
    pub fn state_file(&self) -> &Path {
        &self.state_file
    }

    #[must_use]
    pub fn control_socket(&self) -> &Path {
        &self.control_socket
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.published.snapshot()
    }

    #[must_use]
    pub fn published(&self) -> Arc<Published> {
        Arc::clone(&self.published)
    }

    #[must_use]
    pub fn handle_line(&self, line: &[u8]) -> Response {
        match voidport_control::parse_request(line) {
            Ok(request) => self.handle(request),
            Err(error) => Response::error(error),
        }
    }

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

    fn session_list(&self) -> Reply {
        Reply::SessionList {
            sessions: self.sessions.list(),
        }
    }

    fn namespace_show(&self, name: &NamespaceName) -> Result<Reply, ControlError> {
        self.snapshot()
            .document
            .namespace(name)
            .map(|namespace| Reply::Namespace {
                namespace: namespace.clone(),
            })
            .ok_or_else(|| not_found(name))
    }

    fn resolve(&self, name: &NamespaceName, path: &str) -> Result<Reply, ControlError> {
        let namespace = self
            .published
            .namespace(name)
            .ok_or_else(|| not_found(name))?;
        let path = NamespacePath::parse_bounded(path).map_err(|source| {
            ControlError::new(ErrorCode::InvalidRequest, format!("{path:?}: {source}"))
        })?;
        Ok(Reply::Resolution {
            resolution: path_resolution(namespace.rules().resolve_path(&path)),
        })
    }

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

    fn rule_add(&self, name: &NamespaceName, rule: Rule) -> Result<Reply, ControlError> {
        self.mutate_namespace(name, |spec| {
            spec.rules.push(rule);
            Ok(())
        })
    }

    /// The key is the path plus, for a pattern rule, its match: a directory can
    /// carry two pattern rules.
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

    /// A duplicate match is refused by the build, as it is when loading a state
    /// file.
    fn xattr_add(&self, name: &NamespaceName, rule: XattrRule) -> Result<Reply, ControlError> {
        self.mutate_namespace(name, |spec| {
            spec.xattr.push(rule);
            Ok(())
        })
    }

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

    /// The order is bind unserved, persist, then serve. A listener cannot be
    /// persisted before it is bound, because only a bind shows whether the
    /// endpoint is available and which port `:0` got. A failed persist drops the
    /// bound socket, so nothing is rolled back. Serving starts last, so a
    /// listener the state file lacks never serves a connection.
    ///
    /// Validation and the duplicate refusal run before the bind, so a duplicate
    /// is not reported as `EADDRINUSE` against the socket of this server.
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
        self.commit(document, current.registry.clone(), result)?;
        Ok(Reply::Listener {
            listener: live.publish(&runtime, listener, bound),
        })
    }

    /// Closing the listener is the swap. Sessions already accepted on it keep
    /// serving until their connections end.
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
        // Two entries can only be identical here, so which of them goes does
        // not matter.
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

    /// Edits a copy of the document, rebuilds the affected namespace, persists,
    /// and only then publishes, so a rejected or failed mutation changes neither
    /// memory nor the file.
    fn mutate<F>(&self, edit: F) -> Result<Reply, ControlError>
    where
        F: FnOnce(&mut StateDocument) -> Result<Change, ControlError>,
    {
        let _guard = self.mutation_lock();
        let current = self.snapshot();
        let mut document = current.document.clone();
        let change = edit(&mut document)?;

        let mut registry = current.registry.clone();
        // The retiring store is live across the persist: retiring it deletes
        // the sidecar, which must not happen for a mutation that never reached
        // the disk.
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
                // A name already in the registry reuses the store its sessions
                // write to. Only a namespace-create opens one.
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
        // The removal is durable, so the store takes no more writes and its
        // sidecar is deleted. A re-created name starts empty.
        if let Some(records) = retiring {
            records.retire();
        }
        Ok(Reply::Done {})
    }

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

enum Change {
    Upsert(NamespaceName),
    Remove(NamespaceName),
}

fn not_found(name: &NamespaceName) -> ControlError {
    ControlError::new(
        ErrorCode::NotFound,
        format!("no namespace {:?}", name.as_str()),
    )
}

fn persist_error(code: ErrorCode, source: &PersistError) -> ControlError {
    ControlError::new(code, render(source))
}

fn bind_error(source: &ListenerError) -> ControlError {
    ControlError::new(ErrorCode::BindFailed, render(source))
}

fn describe(listener: &Listener) -> String {
    match listener {
        Listener::Tcp { addr } => format!("tcp {addr}"),
        Listener::Unix { path } => format!("unix {}", path.display()),
        Listener::Vsock { cid, port } if *cid == voidport_control::ANY_CID => {
            format!("vsock any:{port}")
        }
        Listener::Vsock { cid, port } => format!("vsock {cid}:{port}"),
        Listener::VhostUser { path } => format!("vhost-user {}", path.display()),
    }
}

impl From<EffectiveMode> for AdmittedMode {
    fn from(mode: EffectiveMode) -> Self {
        match mode {
            EffectiveMode::Rw => Self::Rw,
            EffectiveMode::Ro => Self::Ro,
        }
    }
}

fn path_resolution(resolution: Resolution) -> PathResolution {
    match resolution {
        Resolution::HostBacked { backing, mode } => PathResolution::Host {
            mode: mode.into(),
            host_path: HostLocator::of(&backing)
                .path()
                .components()
                .collect::<PathBuf>()
                .to_string_lossy()
                .into_owned(),
        },
        Resolution::SynthesizedDir => PathResolution::Synthesized {},
        Resolution::Nonexistent => PathResolution::Absent {},
    }
}

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
            DescriptorLimit::reached(u64::MAX),
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
    fn a_host_backed_resolution_reports_its_mode_and_host_path() {
        use crate::rules::{HostBacking, HostTarget, Name};
        let name = |raw: &str| Name::new(raw).expect("valid name");
        let graft = |target: &str| HostBacking::graft_root(HostTarget::new(target));
        let resolved = |backing, mode| path_resolution(Resolution::HostBacked { backing, mode });
        let host = |mode, host_path: &str| PathResolution::Host {
            mode,
            host_path: host_path.to_owned(),
        };

        assert_eq!(
            resolved(
                graft("/srv/project/").extend(&[name("src"), name("main.rs")]),
                EffectiveMode::Ro
            ),
            host(AdmittedMode::Ro, "/srv/project/src/main.rs")
        );
        assert_eq!(
            resolved(graft("/srv/project/"), EffectiveMode::Rw),
            host(AdmittedMode::Rw, "/srv/project")
        );
        assert_eq!(
            resolved(graft("/"), EffectiveMode::Rw),
            host(AdmittedMode::Rw, "/")
        );
        assert_eq!(
            resolved(graft("/").child(&name("etc")), EffectiveMode::Rw),
            host(AdmittedMode::Rw, "/etc")
        );
    }

    #[test]
    fn a_resolution_without_a_host_entry_maps_to_its_own_kind() {
        assert_eq!(
            path_resolution(Resolution::SynthesizedDir),
            PathResolution::Synthesized {}
        );
        assert_eq!(
            path_resolution(Resolution::Nonexistent),
            PathResolution::Absent {}
        );
    }

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
            describe(&Listener::Vsock {
                cid: 3,
                port: 1024.into()
            }),
            "vsock 3:1024"
        );
        assert_eq!(
            describe(&Listener::VhostUser {
                path: PathBuf::from("/run/vhost-user.sock")
            }),
            "vhost-user /run/vhost-user.sock"
        );
    }
}
