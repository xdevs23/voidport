//! Every syscall that resolves a host name is issued here, under one containment
//! discipline. [`grafts`] opens every graft target as an `O_PATH` descriptor when
//! a namespace is built, and [`open`] is the only way below a graft: `openat2`
//! with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS` and `O_NOFOLLOW` on the final
//! component, so a symlink pointing out of the graft is never followed.
//!
//! The syscalls that the data plane issues on a descriptor it already has
//! (`mkdirat`, `unlinkat`, `renameat` and the like) take no resolution flags and
//! cannot be given a path, so the descriptor already settles containment.

pub mod attr;
pub mod closes;
pub mod direct;
pub mod grafts;
pub mod lease;
pub mod lock;
pub mod open;
pub mod xattr;

pub use attr::{
    FileKind, HostAttr, HostIdentity, NodeIdentity, SynthesizedTimes, synthesized_attr,
};
pub use direct::{Description, Io, Transfer};
pub use grafts::{GraftError, Grafts};
pub use open::{CONTAINMENT, dup, pin_child, pin_relative, reopen};
