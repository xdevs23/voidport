//! The namespace registry.
//!
//! The registry maps a name to a shared, immutable [`Namespace`]. Mutations do
//! not edit a namespace in place: they build a replacement and swap the
//! registry entry, so a holder of an `Arc<Namespace>` keeps serving the
//! snapshot it resolved against until it lets go. Deleting a namespace removes
//! the entry — new handshakes fail, existing holders are untouched (design:
//! "Namespace lifecycle").

use std::collections::BTreeMap;
use std::sync::Arc;

use voidport_control::{NamespaceName, NamespaceSummary};

use crate::namespace::Namespace;

/// Name-keyed namespaces, shared by reference.
///
/// Cloning a registry clones the map but shares every namespace, which is what
/// makes publishing a new registry cheap.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    namespaces: BTreeMap<NamespaceName, Arc<Namespace>>,
}

impl Registry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces a namespace, returning the snapshot it displaced.
    pub fn insert(&mut self, namespace: Namespace) -> Option<Arc<Namespace>> {
        self.namespaces
            .insert(namespace.name().clone(), Arc::new(namespace))
    }

    /// Removes a namespace, returning the snapshot it held.
    pub fn remove(&mut self, name: &NamespaceName) -> Option<Arc<Namespace>> {
        self.namespaces.remove(name)
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

/// Summarizes a namespace for `namespace list`.
///
/// The summary is derived from the built form, so it describes what the server
/// is actually serving, not what the file says.
#[must_use]
pub fn summarize(namespace: &Namespace, ownership_mode: &str, rules: usize) -> NamespaceSummary {
    NamespaceSummary {
        name: namespace.name().clone(),
        ownership: ownership_mode.to_owned(),
        permission: namespace.permission(),
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
        let mut registry = Registry::new();
        assert!(registry.is_empty());
        assert!(registry.insert(namespace("second", Vec::new())).is_none());
        assert!(registry.insert(namespace("first", Vec::new())).is_none());
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
        registry.insert(namespace(
            "project",
            vec![Rule::new("/a", ShareMode::Rw).with_target(scratch.as_target())],
        ));
        let held = registry.get(&name("project")).expect("present");

        let displaced = registry
            .insert(namespace("project", Vec::new()))
            .expect("replaced");
        assert_eq!(displaced, held);
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
        let mut registry = Registry::new();
        registry.insert(namespace("project", Vec::new()));
        let held = registry.get(&name("project")).expect("present");
        let removed = registry.remove(&name("project")).expect("removed");
        assert_eq!(removed, held);
        assert!(registry.get(&name("project")).is_none());
        assert!(registry.remove(&name("project")).is_none());
        assert!(registry.is_empty());
        // The holder is unaffected: its snapshot is frozen, not borrowed.
        assert_eq!(held.name().as_str(), "project");
    }

    #[test]
    fn a_summary_describes_the_built_namespace() {
        let namespace = namespace("project", Vec::new());
        let summary = summarize(&namespace, OwnershipSpec::default().mode_name(), 0);
        assert_eq!(summary.name, name("project"));
        assert_eq!(summary.ownership, "passthrough");
        assert_eq!(summary.rules, 0);
    }
}
