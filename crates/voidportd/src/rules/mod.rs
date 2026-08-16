//! The namespace rule engine.
//!
//! A namespace is a virtual root plus policy: what of the host filesystem is
//! grafted where, under which share mode, and how host ownership presents to
//! the guest. This module is the whole of that policy as **pure logic** — no
//! syscalls, no I/O, no clock. Everything environmental (the server identity,
//! the squash ids, the host directory listings) is injected by the caller, so
//! every decision the server makes about a namespace is reproducible in a unit
//! test.
//!
//! The engine is normatively specified by `docs/DESIGN.md` ("Rule table and
//! resolution", "Namespace policy", "Rule engine contract"); this module tree
//! mirrors that structure:
//!
//! * [`table`] — the rule domain types and the build boundary. Building a
//!   [`RuleTable`] validates the configuration and returns typed errors; a
//!   built table is immutable, and runtime reconfiguration builds a new one.
//! * [`resolve`] — the six-step, component-wise resolution, the directory
//!   context it runs against, and enumeration of both synthesized and
//!   host-backed directories.
//! * [`ownership`] — the bidirectional uid/gid algebra.
//! * [`permissions`] — presented permission bits.
//! * [`path`] and [`name`] — canonical namespace paths and their components.
//! * [`pattern`] — the glob a pattern rule matches child names with, and the
//!   automata product that refuses two patterns covering one name.
//! * [`xattr`] — the per-namespace extended-attribute rules: the same `*`
//!   engine under its own parse, specificity with deny-wins ties, and the
//!   unconditional ACL guard.
//! * [`mode`] — the share modes, split into what a rule states and what an
//!   admitted entry carries.
//!
//! # Shape of a lookup
//!
//! ```
//! use voidportd::rules::{
//!     DirContext, EffectiveMode, Name, NamespacePath, Resolution, RuleSpec, RuleTable, ShareMode,
//! };
//!
//! // Graft a project read-write, default its children to hidden, and admit
//! // one entry explicitly.
//! let table = RuleTable::build([
//!     RuleSpec::new("/project", ShareMode::Rw).with_target("/srv/project"),
//!     RuleSpec::new("/project/*", ShareMode::Hidden),
//!     RuleSpec::new("/project/notes.txt", ShareMode::Ro),
//! ])?;
//!
//! let project = table.walk(&NamespacePath::parse("/project")?).expect("reachable");
//! let notes = table.resolve(&project, &Name::new("notes.txt")?);
//! assert_eq!(notes.mode(), Some(EffectiveMode::Ro));
//! let backing = notes.backing().unwrap();
//! assert_eq!(backing.graft().as_str(), "/srv/project");
//! assert_eq!(backing.relative()[0].as_bytes(), b"notes.txt");
//!
//! // Everything else under the project is hidden: no lookup, no listing.
//! let secret = table.resolve(&project, &Name::new("secret")?);
//! assert_eq!(secret, Resolution::Nonexistent);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod mode;
pub mod name;
pub mod ownership;
pub mod path;
pub mod pattern;
pub mod permissions;
pub mod resolve;
pub mod table;
pub mod xattr;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

pub use mode::{EffectiveMode, ShareMode};
pub use name::{Name, NameError};
pub use ownership::{
    ChownDenied, DEFAULT_SQUASH_ID, GuestIds, HostIds, IdMap, IdMapError, IdMapping,
    OwnerPresentation, Ownership, OwnershipError, OwnershipMode, ServerIdentity, SquashIds,
    UnmappedPolicy,
};
pub use path::{MAX_RULE_PATH_LEN, NamespacePath, PathError, PatternKey, RulePath};
pub use pattern::{Pattern, PatternError};
pub use permissions::{SYNTHESIZED_DIR_PERMISSIONS, WRITE_BITS, presented_mode};
pub use resolve::{DirContext, DirEntry, DirState, Resolution};
pub use table::{HostBacking, HostTarget, LiteralRule, RuleSpec, RuleTable, TableError};
pub use xattr::{
    MAX_XATTR_GLOB_LEN, USER_PREFIX, XattrAccess, XattrGlob, XattrGlobError, XattrRules,
    XattrRulesError, XattrSpec, XattrVerdict,
};
