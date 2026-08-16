//! Host filesystem I/O.
//!
//! Nothing outside this module tree decides *where* on the host filesystem the
//! server may reach, and nothing inside it decides *policy*. That is the split:
//! the rule engine is pure logic, the data plane is wire framing plus
//! bookkeeping, and every syscall that **resolves a host name** — the only kind
//! that can leave a graft — is issued here, under one containment discipline:
//!
//! * [`grafts`] pins every graft target as an `O_PATH` descriptor when a
//!   namespace is built. The descriptor is the truth afterwards, so a host-side
//!   rename of a grafted tree does not break the graft.
//! * [`open`] is the only way to reach anything below a graft: `openat2` with
//!   `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`, final component `O_NOFOLLOW`,
//!   whether the entry is being pinned, created or reopened. A symlink pointing
//!   out of the graft can therefore never be followed out — the hard security
//!   invariant of the design.
//! * [`attr`] turns host metadata into the wire's presented attributes, through
//!   the namespace's ownership algebra and presented-bits function.
//! * [`xattr`] is the `user.*` passthrough; [`lock`] is byte-range OFD locking.
//!
//! What is deliberately **not** here: the syscalls the data plane issues on a
//! descriptor it already holds, plus a single component of it — `mkdirat`,
//! `unlinkat`, `renameat`, `linkat`, `symlinkat`, `chmodat`, `chownat`,
//! `utimensat`, `readlinkat`, `fstatfs`, `ftruncate`, `pread`/`pwrite`,
//! `fsync`. They take no resolution flags and cannot be given a path, so
//! containment is already settled by the descriptor they are handed; they live
//! next to the wire operation that means them, where the enforcement they
//! follow can be read in one place.
//!
//! Host errors are `rustix::io::Errno` throughout and reach the wire as the
//! negated errno the design's response contract asks for; nothing here invents
//! an errno the kernel did not produce, except where the design rules one
//! (share-mode enforcement, reserved xattr namespaces).

pub mod attr;
pub mod grafts;
pub mod lock;
pub mod open;
pub mod xattr;

pub use attr::{
    FileKind, HostAttr, HostIdentity, NodeIdentity, SynthesizedTimes, synthesized_attr,
};
pub use grafts::{GraftError, Grafts};
pub use open::{CONTAINMENT, create_child, dup, pin_child, pin_relative, reopen};
