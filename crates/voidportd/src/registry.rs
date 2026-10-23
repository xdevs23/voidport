use std::collections::BTreeMap;
use std::sync::Arc;

use voidport_control::{NamespaceName, NamespaceSummary, OwnershipMode};

use crate::namespace::Namespace;
use crate::records::{RecordError, RecordHome, RecordStore};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    namespaces: BTreeMap<NamespaceName, Arc<Namespace>>,
    records: BTreeMap<NamespaceName, Arc<RecordStore>>,
}

impl Registry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The record store of the name is opened the first time it appears and
    /// carried over on every republish, so a session writing through it never
    /// finds it swapped.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError`] where the name is new and its sidecar cannot be
    /// read or parsed.
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

    /// The record store comes back live: retiring it deletes the sidecar, which
    /// must wait until the removal is durable.
    pub fn remove(&mut self, name: &NamespaceName) -> Option<Removed> {
        let namespace = self.namespaces.remove(name)?;
        Some(Removed {
            namespace,
            records: self.records.remove(name),
        })
    }

    #[must_use]
    pub fn records(&self, name: &NamespaceName) -> Option<Arc<RecordStore>> {
        self.records.get(name).cloned()
    }

    pub fn stores(&self) -> impl Iterator<Item = &Arc<RecordStore>> {
        self.records.values()
    }

    #[must_use]
    pub fn get(&self, name: &NamespaceName) -> Option<Arc<Namespace>> {
        self.namespaces.get(name).cloned()
    }

    #[must_use]
    pub fn contains(&self, name: &NamespaceName) -> bool {
        self.namespaces.contains_key(name)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.namespaces.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.namespaces.is_empty()
    }

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

#[derive(Clone, Debug)]
pub struct Removed {
    pub namespace: Arc<Namespace>,
    pub records: Option<Arc<RecordStore>>,
}

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
    use voidport_control::{NamespaceSpec, OwnershipSpec, Rule, ShareMode};
    use voidport_test_host::Scratch;

    fn name(raw: &str) -> NamespaceName {
        NamespaceName::new(raw).expect("valid namespace name")
    }

    fn home(scratch: &Scratch) -> RecordHome {
        RecordHome::for_state_file(&scratch.join("state.toml"))
    }

    fn namespace(raw: &str, rules: Vec<Rule>) -> Namespace {
        let spec = NamespaceSpec {
            rules,
            ..NamespaceSpec::new(name(raw))
        };
        // A built namespace opens its grafts, so the rules name a real directory.
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
        assert!(Arc::ptr_eq(
            &store,
            &registry.records(&name("project")).expect("a store")
        ));
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
        let records = removed.records.expect("a store went with it");
        assert!(!records.is_retired());
        records.retire();
        assert!(registry.get(&name("project")).is_none());
        assert!(registry.records(&name("project")).is_none());
        assert!(registry.remove(&name("project")).is_none());
        assert!(registry.is_empty());
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
