use std::sync::Arc;

use voidport_control::{AuthMode, HostDirectIo, NamespaceName, PermissionMode};

use crate::host::Grafts;
use crate::rules::{Ownership, RuleTable, XattrRules};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolicyModes {
    pub permission: PermissionMode,
    pub direct_io: HostDirectIo,
    pub auth: AuthMode,
}

/// Contains the open graft descriptors: a session descends from these, so
/// reconfiguring or deleting the namespace mid-operation cannot change where
/// the operation goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Namespace {
    name: NamespaceName,
    modes: PolicyModes,
    ownership: Ownership,
    rules: RuleTable,
    xattr: XattrRules,
    privileged_bits: bool,
    grafts: Arc<Grafts>,
}

impl Namespace {
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "a namespace is the whole of one entry of the state document, frozen; grouping its parts into a struct would only move the same list one layer out"
    )]
    pub fn new(
        name: NamespaceName,
        modes: PolicyModes,
        ownership: Ownership,
        rules: RuleTable,
        xattr: XattrRules,
        privileged_bits: bool,
        grafts: Grafts,
    ) -> Self {
        Self {
            name,
            modes,
            ownership,
            rules,
            xattr,
            privileged_bits,
            grafts: Arc::new(grafts),
        }
    }

    /// When disabled, presentation masks setuid and setgid, a chmod setting them is
    /// refused, and a delivered mode neither records nor deletes them.
    #[must_use]
    pub fn privileged_bits(&self) -> bool {
        self.privileged_bits
    }

    #[must_use]
    pub fn grafts(&self) -> &Grafts {
        &self.grafts
    }

    #[must_use]
    pub fn name(&self) -> &NamespaceName {
        &self.name
    }

    #[must_use]
    pub fn permission(&self) -> PermissionMode {
        self.modes.permission
    }

    /// Read at the open that derives the flags of a backing description, so open
    /// descriptions are left alone by a change.
    #[must_use]
    pub fn direct_io(&self) -> HostDirectIo {
        self.modes.direct_io
    }

    #[must_use]
    pub fn auth(&self) -> AuthMode {
        self.modes.auth
    }

    #[must_use]
    pub fn ownership(&self) -> &Ownership {
        &self.ownership
    }

    #[must_use]
    pub fn rules(&self) -> &RuleTable {
        &self.rules
    }

    #[must_use]
    pub fn xattr(&self) -> &XattrRules {
        &self.xattr
    }
}
