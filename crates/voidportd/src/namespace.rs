//! Runtime namespace state.
//!
//! A [`Namespace`] is the *built* form of one entry of the state document: the
//! validated rule table and ownership algebra, plus the policy modes, frozen
//! together. It is immutable by construction — reconfiguration builds a new one
//! and publishes it — so one operation can take a snapshot and be sure the
//! policy it resolves against does not shift underneath it. The *next*
//! operation takes the snapshot again, which is how a control-plane mutation
//! reaches a mounted guest (design: "Session lifecycle", "Policy binds at
//! lookup").

use std::sync::Arc;

use voidport_control::{AuthMode, HostDirectIo, NamespaceName, PermissionMode};

use crate::host::Grafts;
use crate::rules::{Ownership, RuleTable, XattrRules};

/// The policy modes a namespace carries, one value instead of a run of
/// same-shaped constructor arguments.
///
/// They belong together: each is a single scalar of one state-file entry, none
/// of them is built or validated (a mode either parses or the document does
/// not load), and they are read one at a time by the operation that cares.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolicyModes {
    /// How host permission bits present.
    pub permission: PermissionMode,
    /// Where backing I/O sits with respect to the host page cache.
    pub direct_io: HostDirectIo,
    /// How clients authenticate.
    pub auth: AuthMode,
}

/// One namespace, built and immutable.
///
/// It carries its own pinned graft descriptors: a session resolving against
/// this snapshot descends from *these* descriptors, so a namespace that has
/// been reconfigured or deleted while an operation is in flight cannot change
/// where that operation lands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Namespace {
    name: NamespaceName,
    modes: PolicyModes,
    ownership: Ownership,
    rules: RuleTable,
    xattr: XattrRules,
    grafts: Arc<Grafts>,
}

impl Namespace {
    /// Freezes validated policy and its pinned grafts into a namespace.
    ///
    /// Everything arrives already validated: this constructor cannot fail,
    /// because every way a namespace can be invalid — the rule table, the
    /// ownership algebra, an unopenable graft target — is a build boundary in
    /// [`crate::state::build`].
    #[must_use]
    pub fn new(
        name: NamespaceName,
        modes: PolicyModes,
        ownership: Ownership,
        rules: RuleTable,
        xattr: XattrRules,
        grafts: Grafts,
    ) -> Self {
        Self {
            name,
            modes,
            ownership,
            rules,
            xattr,
            grafts: Arc::new(grafts),
        }
    }

    /// The pinned graft descriptors every host lookup starts from.
    #[must_use]
    pub fn grafts(&self) -> &Grafts {
        &self.grafts
    }

    /// The namespace name.
    #[must_use]
    pub fn name(&self) -> &NamespaceName {
        &self.name
    }

    /// How host permission bits present.
    #[must_use]
    pub fn permission(&self) -> PermissionMode {
        self.modes.permission
    }

    /// Where this namespace's backing I/O sits with respect to the host page
    /// cache.
    ///
    /// Read at the open that derives a backing description's flags, so a
    /// posture changed through the control plane is live at the next open and
    /// leaves open descriptions alone — the same rule a share-mode change
    /// follows.
    #[must_use]
    pub fn direct_io(&self) -> HostDirectIo {
        self.modes.direct_io
    }

    /// How clients authenticate.
    #[must_use]
    pub fn auth(&self) -> AuthMode {
        self.modes.auth
    }

    /// The ownership algebra, with its environmental inputs already injected.
    #[must_use]
    pub fn ownership(&self) -> &Ownership {
        &self.ownership
    }

    /// The validated rule table.
    #[must_use]
    pub fn rules(&self) -> &RuleTable {
        &self.rules
    }

    /// The validated extended-attribute rules.
    ///
    /// Per namespace, like everything else here: a rule added through the
    /// control plane reaches a mounted guest by the same snapshot swap that
    /// carries a share-mode change, and is live at the next operation.
    #[must_use]
    pub fn xattr(&self) -> &XattrRules {
        &self.xattr
    }
}
