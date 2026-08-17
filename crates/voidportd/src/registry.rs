//! The namespace registry.
//!
//! The registry maps a name to a shared, immutable [`Namespace`]. Mutations do
//! not edit a namespace in place: they build a replacement and swap the
//! registry entry, so a holder of an `Arc<Namespace>` keeps serving the
//! snapshot it resolved against until it lets go. Deleting a namespace removes
//! the entry — new handshakes fail, existing holders are untouched (design:
//! "Namespace lifecycle").
//!
//! It maps a name to one more thing, and that one is **not** a snapshot: the
//! [`RecordStore`] holding the namespace's recorded metadata. A namespace
//! snapshot is replaced on every control mutation, and recorded truth may not
//! be — so the store is owned per *name*, one instance across every republish,
//! and a rebuild carries the very store the displaced snapshot's sessions are
//! writing to. That is also why its sidecar is read exactly once, when the
//! store is created: no two tables ever race one file.

use std::collections::BTreeMap;
use std::sync::Arc;

use voidport_control::{NamespaceName, NamespaceSummary, OwnershipMode};

use crate::namespace::Namespace;
use crate::records::{RecordError, RecordHome, RecordStore};

/// Name-keyed namespaces, shared by reference.
///
/// Cloning a registry clones the map but shares every namespace, which is what
/// makes publishing a new registry cheap.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    namespaces: BTreeMap<NamespaceName, Arc<Namespace>>,
    records: BTreeMap<NamespaceName, Arc<RecordStore>>,
}

impl Registry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces a namespace, returning the snapshot it displaced.
    ///
    /// The name's record store is opened the first time the name appears and
    /// carried over on every republish after that, so a session writing through
    /// it never finds the store swapped underneath it.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError`] where the name is new and its sidecar cannot be
    /// read or does not parse — the state file's refusal posture, applied to
    /// the file that holds the namespace's recorded truth.
    pub fn insert(
        &mut self,
        namespace: Namespace,
        home: &RecordHome,
    ) -> Result<Option<Arc<Namespace>>, RecordError> {
        let name = namespace.name().clone();
        if !self.records.contains_key(&name) {
            self.records
                .insert(name.clone(), RecordStore::open(&name, home)?);
        }
        Ok(self.namespaces.insert(name, Arc::new(namespace)))
    }

    /// Removes a namespace, returning the snapshot it held and the record store
    /// that went with it.
    ///
    /// The store comes back **live**: retiring it deletes the sidecar, and that
    /// must not happen until the removal is durable, so the caller retires it
    /// after the mutation commits.
    pub fn remove(&mut self, name: &NamespaceName) -> Option<Removed> {
        let namespace = self.namespaces.remove(name)?;
        Some(Removed {
            namespace,
            records: self.records.remove(name),
        })
    }

    /// The record store of that name.
    #[must_use]
    pub fn records(&self, name: &NamespaceName) -> Option<Arc<RecordStore>> {
        self.records.get(name).cloned()
    }

    /// Every record store, for the teardown flush.
    pub fn stores(&self) -> impl Iterator<Item = &Arc<RecordStore>> {
        self.records.values()
    }

    /// The namespace of that name.
    #[must_use]
    pub fn get(&self, name: &NamespaceName) -> Option<Arc<Namespace>> {
        self.namespaces.get(name).cloned()
    }

    /// Whether the registry holds that name.
    #[must_use]
    pub fn contains(&self, name: &NamespaceName) -> bool {
        self.namespaces.contains_key(name)
    }

    /// How many namespaces the registry holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.namespaces.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.namespaces.is_empty()
    }

    /// Every namespace, in name order.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<Namespace>> {
        self.namespaces.values()
    }
}

impl<'a> IntoIterator for &'a Registry {
    type Item = &'a Arc<Namespace>;
    type IntoIter = std::collections::btree_map::Values<'a, NamespaceName, Arc<Namespace>>;

    fn into_iter(self) -> Self::IntoIter {
        self.namespaces.values()
    }
}

/// What removing a namespace hands back.
#[derive(Clone, Debug)]
pub struct Removed {
    /// The snapshot the registry held. Sessions that resolved against it keep
    /// serving it.
    pub namespace: Arc<Namespace>,
    /// Its record store, still live. The caller retires it once the removal is
    /// durable, which is what deletes the sidecar.
    pub records: Option<Arc<RecordStore>>,
}

/// Summarizes a namespace for `namespace list`.
///
/// The summary is derived from the built form, so it describes what the server
/// is actually serving, not what the file says.
#[must_use]
pub fn summarize(
    namespace: &Namespace,
    ownership_mode: OwnershipMode,
    rules: usize,
) -> NamespaceSummary {
    NamespaceSummary {
        name: namespace.name().clone(),
        ownership: ownership_mode,
        permission: namespace.permission(),
        direct_io: namespace.direct_io(),
        auth: namespace.auth(),
        rules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Environment, build_namespace};
    use crate::testing::Scratch;
    use voidport_control::{NamespaceSpec, OwnershipSpec, Rule, ShareMode};

    fn name(raw: &str) -> NamespaceName {
        NamespaceName::new(raw).expect("valid namespace name")
    }

    /// Sidecars beside a state file of this test module's own, so nothing here
    /// reads or writes another suite's recorded truth.
    fn home(scratch: &Scratch) -> RecordHome {
        RecordHome::for_state_file(&scratch.join("state.toml"))
    }

    fn namespace(raw: &str, rules: Vec<Rule>) -> Namespace {
        let spec = NamespaceSpec {
            rules,
            ..NamespaceSpec::new(name(raw))
        };
        // A built namespace pins its grafts, so the rules below name a real
        // directory: the scratch space this test module runs in.
        build_namespace(&spec, &Environment::new(1000, 100, std::env::temp_dir()))
            .expect("valid namespace")
    }

    #[test]
    fn namespaces_are_keyed_by_name_in_order() {
        let scratch = Scratch::new("registry-order");
        let home = home(&scratch);
        let mut registry = Registry::new();
        assert!(registry.is_empty());
        assert!(
            registry
                .insert(namespace("second", Vec::new()), &home)
                .expect("a fresh store")
                .is_none()
        );
        assert!(
            registry
                .insert(namespace("first", Vec::new()), &home)
                .expect("a fresh store")
                .is_none()
        );
        assert_eq!(registry.len(), 2);
        assert!(registry.contains(&name("first")));
        assert!(!registry.contains(&name("third")));
        let names: Vec<&str> = registry
            .iter()
            .map(|namespace| namespace.name().as_str())
            .collect();
        assert_eq!(names, ["first", "second"]);
        assert_eq!((&registry).into_iter().count(), 2);
    }

    #[test]
    fn a_replaced_namespace_leaves_its_snapshot_intact() {
        let mut registry = Registry::new();
        let scratch = Scratch::new("registry");
        let home = home(&scratch);
        registry
            .insert(
                namespace(
                    "project",
                    vec![Rule::new("/a", ShareMode::Rw).with_target(scratch.as_target())],
                ),
                &home,
            )
            .expect("a fresh store");
        let held = registry.get(&name("project")).expect("present");
        let store = registry.records(&name("project")).expect("a store");

        let displaced = registry
            .insert(namespace("project", Vec::new()), &home)
            .expect("a store the name already has")
            .expect("replaced");
        assert_eq!(displaced, held);
        // One store across every republish: the rebuilt namespace writes to the
        // very store the displaced snapshot's sessions hold.
        assert!(Arc::ptr_eq(
            &store,
            &registry.records(&name("project")).expect("a store")
        ));
        // The holder still sees the policy it resolved against.
        assert_eq!(
            held.rules().structural_children(&Default::default()).len(),
            1
        );
        assert_eq!(
            registry
                .get(&name("project"))
                .expect("present")
                .rules()
                .structural_children(&Default::default())
                .len(),
            0
        );
    }

    #[test]
    fn deleting_a_namespace_removes_only_the_entry() {
        let scratch = Scratch::new("registry-delete");
        let home = home(&scratch);
        let mut registry = Registry::new();
        registry
            .insert(namespace("project", Vec::new()), &home)
            .expect("a fresh store");
        let held = registry.get(&name("project")).expect("present");
        let removed = registry.remove(&name("project")).expect("removed");
        assert_eq!(removed.namespace, held);
        // The store comes back live, for the caller to retire once the removal
        // is durable.
        let records = removed.records.expect("a store went with it");
        assert!(!records.is_retired());
        records.retire();
        assert!(registry.get(&name("project")).is_none());
        assert!(registry.records(&name("project")).is_none());
        assert!(registry.remove(&name("project")).is_none());
        assert!(registry.is_empty());
        // The holder is unaffected: its snapshot is frozen, not borrowed.
        assert_eq!(held.name().as_str(), "project");
    }

    #[test]
    fn a_summary_describes_the_built_namespace() {
        let namespace = namespace("project", Vec::new());
        let summary = summarize(&namespace, OwnershipSpec::default().mode(), 0);
        assert_eq!(summary.name, name("project"));
        assert_eq!(summary.ownership, OwnershipMode::Passthrough);
        assert_eq!(summary.rules, 0);
    }
}
