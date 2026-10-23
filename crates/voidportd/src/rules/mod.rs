//! Pure logic: no syscalls, no I/O, no clock. The server identity, the squash ids
//! and the host directory listings are injected by the caller.
//!
//! ```
//! use voidportd::rules::{
//!     DirContext, EffectiveMode, Name, NamespacePath, Resolution, RuleSpec, RuleTable, ShareMode,
//! };
//!
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
//! let secret = table.resolve(&project, &Name::new("secret")?);
//! assert_eq!(secret, Resolution::Nonexistent);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod glob;
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
    USER_PREFIX, XattrAccess, XattrGlob, XattrGlobError, XattrRules, XattrRulesError, XattrSpec,
    XattrVerdict,
};
