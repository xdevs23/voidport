//! The node descriptor cache: a bounded pool of `O_PATH` pins, and the
//! identity-verified re-pin that makes evicting one safe.
//!
//! **A descriptor is a cache slot, not a lifetime pin.** That is the whole of
//! this module, and it is the answer to a field failure: a node used to hold
//! its `O_PATH` descriptor for as long as the guest kernel remembered the
//! lookup, and a kernel under no memory pressure remembers a cold dentry
//! forever — so the server's descriptor table filled at the rate of *names ever
//! resolved*, and a source-tree walk the size of an AOSP checkout exhausted it.
//! The same walk over the host, or through a bind mount, costs nothing: a
//! dentry cache is not a process's descriptor table. voidport must not turn the
//! guest's caching into a server resource a guest can exhaust.
//!
//! The pieces:
//!
//! * [`DescriptorBudget`] — the server-global ledger. At most `budget` pins are
//!   **cache-resident** at once, in least-recently-used order, across every
//!   session (the descriptor table is process-wide, so the bound must be too).
//! * [`NodePin`] — one node's slot: the cache's own reference to the
//!   descriptor, the **recipe** for pinning it again, and the
//!   [`NodeIdentity`] that proves a re-pin found the
//!   same file.
//!
//! **A recipe is a whole host path, from a graft root down.** One
//! [`HostBacking`] — the graft the entry belongs to plus its components below it
//! — and nothing else: every node re-pins by itself, from a descriptor the
//! namespace snapshot already holds, so no node's slot depends on another's.
//! That is what a fresh resolution of the entry would walk, which is the
//! governing principle of the whole reopen. The price is that an entry the
//! server *moves* must have the recorded paths of its whole subtree rewritten
//! ([`NodeTable::rebind_moved`](crate::data::node::NodeTable::rebind_moved)) —
//! the same per-session pass the cross-session rebind already makes, paid by
//! directory renames only.
//!
//! **What the budget bounds is what the cache itself holds.** Eviction drops
//! the cache's reference and is therefore *always possible*; the descriptor
//! closes when its last holder lets go. A descriptor kept alive past eviction
//! belongs to that holder — an in-flight operation, or an open handle, which
//! keeps its node's pin for its lock descriptions — and those stay unbudgeted
//! by the unbounded-caps decision. The process total decomposes as
//! cache-resident (≤ budget) + in-flight checkouts + handle-retained pins +
//! graft pins + the startup reserve.
//!
//! **Lock discipline**, which is what keeps a process-global ledger off the
//! critical path: the ledger lock is never held across a host syscall and never
//! across a session's table lock. Eviction takes descriptors *out* of their
//! slots under the ledger lock and closes them after releasing it; a re-pin
//! does its `openat2` and its `statx` holding nothing but its own single-flight
//! lock, so a thousand threads meeting the same evicted node perform one
//! re-pin.

use std::collections::BTreeMap;
use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use rustix::io::Errno;

use crate::host::attr::{HostAttr, NodeIdentity};
use crate::host::open::pin_relative;
use crate::namespace::Namespace;
use crate::rules::{HostBacking, NamespacePath};

/// The cache slot of one host-backed node.
///
/// Shared by every clone of the node, because the slot is the node's — a node
/// taken out of the table to be worked on and the entry left behind must agree
/// about whether the descriptor is still there.
#[derive(Debug)]
pub struct NodePin {
    /// The ledger this slot belongs to.
    budget: Arc<DescriptorBudget>,
    /// The namespace path the node this slot belongs to was reached by.
    ///
    /// The name the *guest* is holding, which is why it is the fallback when
    /// the recorded recipe answers `ENOENT`: a recipe is one way back, not the
    /// only one, and one recipe cannot represent two live names of an inode.
    path: NamespacePath,
    /// Where the namespace said this entry lived when it was pinned.
    ///
    /// A record of what the *policy* said, never a statement about where the
    /// entry is now: the re-target check compares it against where the
    /// namespace says the directory is *now*, and it is frozen at pin time
    /// exactly as the node's namespace path is — a rename through the mount
    /// moves neither, so the two keep agreeing. The recipe below is the moving
    /// part.
    backing: HostBacking,
    /// What was found at pin time, so a re-pin can prove it found it again.
    identity: NodeIdentity,
    /// How to pin it again: the entry's whole host path, from its graft root
    /// down, as it stands **now**.
    recipe: Mutex<HostBacking>,
    /// The cache's own reference, and the ledger tick it is filed under.
    state: Mutex<Slot>,
    /// Single-flight: one re-pin per node, however many threads want it.
    repin: Mutex<()>,
}

/// Everything the cache records about an entry as it takes it in.
///
/// One struct, not five arguments, because the five belong together and
/// are easy to transpose: two of them are host locations and two are ways back
/// to the same file.
#[derive(Debug)]
pub struct Pinned {
    /// The `O_PATH` descriptor the caller has just opened under containment.
    pub fd: OwnedFd,
    /// The namespace path the node was reached by, which is the fallback way
    /// back when the recipe's name is gone.
    pub path: NamespacePath,
    /// Where the namespace said the entry lived at pin time.
    pub backing: HostBacking,
    /// What was found there, so a re-pin can prove it found it again.
    pub identity: NodeIdentity,
    /// The way back: the entry's whole host path from its graft root. Equal to
    /// `backing` for everything a fresh resolution pinned; they part company
    /// only where the server has since moved the entry, or where the entry was
    /// reached through a parent the server had moved.
    pub recipe: HostBacking,
}

/// The cache's reference to one descriptor.
#[derive(Debug)]
struct Slot {
    /// `None` once the budget has evicted it. The descriptor itself lives on
    /// for as long as any holder keeps its own reference.
    fd: Option<Arc<OwnedFd>>,
    /// The ledger tick this slot is filed under while it is resident.
    tick: u64,
}

impl NodePin {
    /// The descriptor, re-pinning the entry if the budget has evicted it.
    ///
    /// A resident slot costs one mutex and one ledger touch. An evicted one
    /// costs the re-pin — a contained descent and a `statx` — and answers
    /// `ESTALE` where the entry the node names is no longer at the end of it.
    ///
    /// # Errors
    ///
    /// `ESTALE` for a re-pin that cannot find the same file: a missing entry,
    /// an identity mismatch, a containment refusal (`EXDEV`, `ELOOP` — a
    /// symlink planted since the original pin is *refused*, which is a
    /// security-positive re-check), or a namespace that no longer grafts the
    /// path. Every other host errno propagates unchanged, so honest exhaustion
    /// stays honest.
    pub fn descriptor(self: &Arc<Self>, namespace: &Namespace) -> Result<Arc<OwnedFd>, Errno> {
        if let Some(fd) = self.resident() {
            self.budget.touch(self);
            return Ok(fd);
        }
        self.repin(namespace)
    }

    /// The descriptor if it is resident, without re-pinning anything.
    ///
    /// This is what the accounting is stated in terms of, and what a test that
    /// wants to observe eviction instead of causing it asks.
    #[must_use]
    pub fn resident(&self) -> Option<Arc<OwnedFd>> {
        self.state().fd.clone()
    }

    /// Where the namespace said this entry lived when it was pinned.
    #[must_use]
    pub fn backing(&self) -> &HostBacking {
        &self.backing
    }

    /// What was found at pin time.
    #[must_use]
    pub fn identity(&self) -> NodeIdentity {
        self.identity
    }

    /// The host path this node re-pins by, as it stands now.
    ///
    /// A snapshot, not a borrow: the recipe is behind a lock, and a
    /// caller pinning a child from it must not hold that lock across the
    /// syscall it is about to make.
    #[must_use]
    pub fn recipe(&self) -> HostBacking {
        self.recorded().clone()
    }

    /// Re-points the recipe at where the server has just moved this entry.
    ///
    /// The server never stales what it renamed itself: a rename, a
    /// `RENAME_EXCHANGE` or a link performed *through the mount* moves the host
    /// entry a node names, and the recorded path follows it here. A renamed
    /// directory's descendants are re-pointed the same way, one call each —
    /// their recorded paths carry the directory's old path as a prefix, and
    /// [`NodeTable::rebind_moved`](crate::data::node::NodeTable::rebind_moved)
    /// swaps it for the new one.
    pub fn rebind(&self, recipe: HostBacking) {
        *self.recorded() = recipe;
    }

    /// Pins the entry again and proves it is the same file.
    fn repin(self: &Arc<Self>, namespace: &Namespace) -> Result<Arc<OwnedFd>, Errno> {
        // The single-flight gate. Whoever holds it does the work; everyone else
        // waits and then finds the slot filled by the check below.
        let _flight = self
            .repin
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(fd) = self.resident() {
            self.budget.touch(self);
            return Ok(fd);
        }
        // No ledger lock and no session table lock is held here: this is the
        // syscall half, and it is the reason both are dropped before it.
        let fd = Arc::new(self.pin_again(namespace)?);
        self.state().fd = Some(Arc::clone(&fd));
        self.budget.admit(self);
        Ok(fd)
    }

    /// The contained descent that re-pins the entry, with the identity check
    /// the design puts between an old node id and an impostor's bytes.
    ///
    /// **A recipe is one way back, not the only way.** A recipe that answers
    /// `ENOENT` has lost the name it recorded, which is not the same thing as
    /// the node having lost its file: an inode the guest linked under a second
    /// name and then unlinked under the first is still exactly the file this
    /// node names. So the node's own namespace path — the name the guest is
    /// actually holding — is re-resolved under the **current** rules before the
    /// node is given up on, and a match rebinds the recipe there.
    fn pin_again(&self, namespace: &Namespace) -> Result<OwnedFd, Errno> {
        // Cloned out: the recipe lock is not held across the syscalls below.
        let recipe = self.recipe();
        match self.walk_to(&recipe, namespace) {
            Ok(fd) => self.verified(fd),
            Err(Errno::NOENT) => {
                let backing = backing_at(namespace, &self.path).ok_or(Errno::STALE)?;
                let fd = self.walk_to(&backing, namespace).map_err(gone_is_stale)?;
                let fd = self.verified(fd)?;
                *self.recorded() = backing;
                Ok(fd)
            }
            Err(error) => Err(gone_is_stale(error)),
        }
    }

    /// Walks one whole host path from its graft's pinned root, without judging
    /// what it found.
    ///
    /// The graft descriptor comes from the **currently published** namespace
    /// snapshot, so a rule removed at the control plane leaves nothing to
    /// descend from and the node answers `ESTALE` on its next use. This is the
    /// descent a *fresh* resolution would make, which is the governing
    /// principle of the whole reopen: an evicted node's operation behaves as it
    /// would after a fresh resolution of its namespace path.
    fn walk_to(&self, backing: &HostBacking, namespace: &Namespace) -> Result<OwnedFd, Errno> {
        let graft = namespace.grafts().graft_of(backing).ok_or(Errno::STALE)?;
        pin_relative(graft, backing.relative())
    }

    /// Accepts a freshly pinned descriptor only if it is the same file.
    ///
    /// This is what stands between an old node id and an impostor's bytes, and
    /// it is applied to every way back — the recorded recipe and the namespace
    /// path alike.
    fn verified(&self, fd: OwnedFd) -> Result<OwnedFd, Errno> {
        let found = HostAttr::of(fd.as_fd())?.node_identity();
        if !self.identity.matches(&found) {
            return Err(Errno::STALE);
        }
        Ok(fd)
    }

    /// The slot, ignoring poisoning: a panicking holder can leave a descriptor
    /// filed, which the ledger closes on its next eviction.
    fn state(&self) -> MutexGuard<'_, Slot> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// The recorded recipe, ignoring poisoning for the same reason.
    fn recorded(&self) -> MutexGuard<'_, HostBacking> {
        self.recipe
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

impl Drop for NodePin {
    /// Gives the cache slot back before the descriptor closes.
    ///
    /// A node the guest forgot, or a session torn down, must leave the resident
    /// count where it found it — the counter is what the criteria and the
    /// torture harness read, so an unreturned slot would be a lie that
    /// eventually starves the cache.
    fn drop(&mut self) {
        let resident = self
            .state
            .get_mut()
            .unwrap_or_else(|poison| poison.into_inner());
        if resident.fd.is_some() {
            let tick = resident.tick;
            self.budget.retire(tick);
        }
        // The descriptor closes as this struct's fields drop, which is after
        // this body has released the ledger lock.
    }
}

/// The server-global bound on cache-resident node descriptors.
#[derive(Debug)]
pub struct DescriptorBudget {
    /// How many pins the cache may hold at once.
    budget: usize,
    ledger: Mutex<Ledger>,
}

/// The least-recently-used order, and the count that is bounded.
#[derive(Debug, Default)]
struct Ledger {
    /// Resident slots by tick, which is least-recently-used order: a
    /// `BTreeMap` gives the oldest in one step and re-files a touched slot in
    /// logarithmic time, with no intrusive list to get wrong.
    order: BTreeMap<u64, Weak<NodePin>>,
    /// The monotonic tick a touch or an admission files a slot under.
    tick: u64,
    /// How many slots the cache holds. Kept beside `order`, not derived
    /// from it because a slot popped for a pin that has since been dropped
    /// still has to be counted out.
    resident: usize,
}

impl Ledger {
    /// The next tick, which no slot has ever been filed under.
    fn next(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Evicts least-recently-used slots until the count is within `budget`,
    /// handing back the descriptors to close **outside** the ledger lock.
    fn trim(&mut self, budget: usize) -> Vec<Arc<OwnedFd>> {
        let mut evicted = Vec::new();
        while self.resident > budget {
            let Some((_, slot)) = self.order.pop_first() else {
                break;
            };
            self.resident -= 1;
            // A slot whose pin has already been dropped counts out and closes
            // nothing: its descriptor went with the node.
            if let Some(pin) = slot.upgrade()
                && let Some(fd) = pin.state().fd.take()
            {
                evicted.push(fd);
            }
        }
        evicted
    }
}

/// What the server needs descriptors for beyond the node cache: the listeners,
/// the control socket and its connections, the state file, the pinned graft
/// targets, and the reopens an operation does while it runs.
///
/// A round thousand, deliberately generous: this is a limit, not an
/// allocation, and being a thousand descriptors too generous costs nothing
/// while being one too tight costs an `EMFILE` in a place nobody would look.
pub const DESCRIPTOR_RESERVE: u64 = 1024;

/// The smallest budget the server derives for itself.
///
/// A machine with a small descriptor limit still gets a usable cache; an
/// operator who wants less says so, and is taken at their word.
const DERIVED_FLOOR: u64 = 4096;

/// The largest budget the server derives for itself.
///
/// The startup raise can reach `fs.nr_open` — 2.1 billion on the probed
/// machine, where half would be 267 GiB of unswappable slab at the measured
/// 267.8 bytes per `O_PATH` descriptor. 262,144 resident pins cost a measured
/// ~70 MiB, which is ample for any working set and harmless to the machine.
const DERIVED_CEILING: u64 = 262_144;

/// The soft `RLIMIT_NOFILE` the server runs under.
///
/// A value, not a `getrlimit` call, because the number has an owner:
/// startup raises the limit towards the OS maximum and reports what it reached,
/// and the derived budget is a fraction of *that*. Reading the limit a second
/// time where the budget is sized would be a second source of the same truth,
/// and the two could disagree about which number the operator was told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorLimit(u64);

impl DescriptorLimit {
    /// The limit a startup raise reached.
    #[must_use]
    pub fn reached(soft: u64) -> Self {
        Self(soft)
    }

    /// The limit as it stands, for a server built without the startup raise —
    /// a test harness, or anything embedding the service directly.
    #[must_use]
    pub fn current() -> Self {
        Self(
            rustix::process::getrlimit(rustix::process::Resource::Nofile)
                .current
                .unwrap_or(u64::MAX),
        )
    }

    /// The soft limit itself.
    #[must_use]
    pub fn soft(self) -> u64 {
        self.0
    }
}

impl DescriptorBudget {
    /// A ledger holding at most `budget` cache-resident descriptors.
    #[must_use]
    pub fn new(budget: usize) -> Arc<Self> {
        Arc::new(Self {
            budget,
            ledger: Mutex::new(Ledger::default()),
        })
    }

    /// The budget a server runs with: what the operator configured, or half of
    /// the descriptor limit startup reached, less the reserve, clamped.
    ///
    /// A configured number is taken **as written** — no floor, no ceiling: an
    /// operator who says 200 means 200, and the tests say hundreds. The derived
    /// number is clamped at both ends for the reasons the constants state.
    ///
    /// The limit is passed in, not read here, because startup has
    /// already *raised* it and therefore already knows what it reached: one
    /// truth, recorded once, and no chance of sizing the budget from a number
    /// other than the one the operator log reports.
    #[must_use]
    pub fn sized(configured: Option<usize>, limit: DescriptorLimit) -> Arc<Self> {
        if let Some(budget) = configured {
            return Self::new(budget);
        }
        let derived = (limit.soft() / 2)
            .saturating_sub(DESCRIPTOR_RESERVE)
            .clamp(DERIVED_FLOOR, DERIVED_CEILING);
        Self::new(usize::try_from(derived).unwrap_or(usize::MAX))
    }

    /// How many cache-resident descriptors the budget allows.
    #[must_use]
    pub fn budget(&self) -> usize {
        self.budget
    }

    /// How many the cache holds right now.
    ///
    /// This is the counter the control plane publishes and the criteria assert
    /// on: `/proc/self/fd` counts descriptors but cannot say which of them is a
    /// node's cache slot and which is an open handle's.
    #[must_use]
    pub fn resident(&self) -> usize {
        self.ledger().resident
    }

    /// Files a freshly pinned descriptor as a cache slot.
    ///
    /// The caller must not hold a session's node table: admitting one slot may
    /// evict another, and closing the evicted descriptor is a host syscall.
    #[must_use]
    pub fn pin(self: &Arc<Self>, entry: Pinned) -> Arc<NodePin> {
        let Pinned {
            fd,
            path,
            backing,
            identity,
            recipe,
        } = entry;
        let pin = Arc::new(NodePin {
            budget: Arc::clone(self),
            path,
            backing,
            identity,
            recipe: Mutex::new(recipe),
            state: Mutex::new(Slot {
                fd: Some(Arc::new(fd)),
                tick: 0,
            }),
            repin: Mutex::new(()),
        });
        self.admit(&pin);
        pin
    }

    /// Files a slot whose descriptor has just been (re-)pinned, evicting the
    /// least recently used ones until the budget holds again.
    fn admit(&self, pin: &Arc<NodePin>) {
        let evicted = {
            let mut ledger = self.ledger();
            let tick = ledger.next();
            {
                let mut slot = pin.state();
                slot.tick = tick;
            }
            ledger.order.insert(tick, Arc::downgrade(pin));
            ledger.resident += 1;
            ledger.trim(self.budget)
        };
        // Outside the ledger lock: closing a descriptor is a host syscall.
        drop(evicted);
    }

    /// Re-files a slot as the most recently used one.
    fn touch(&self, pin: &Arc<NodePin>) {
        let mut ledger = self.ledger();
        let mut slot = pin.state();
        // The slot may have been evicted between the read that found it
        // resident and this line; the ledger is the authority on whether it is
        // still filed.
        if ledger.order.remove(&slot.tick).is_none() {
            return;
        }
        slot.tick = ledger.next();
        ledger.order.insert(slot.tick, Arc::downgrade(pin));
    }

    /// Gives a slot back, for a pin that is going away with its node.
    fn retire(&self, tick: u64) {
        let mut ledger = self.ledger();
        if ledger.order.remove(&tick).is_some() {
            ledger.resident -= 1;
        }
    }

    /// The ledger, ignoring poisoning: the worst a panicking holder leaves is
    /// a slot to reclaim.
    fn ledger(&self) -> MutexGuard<'_, Ledger> {
        self.ledger
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// The re-pin failures that mean "this is no longer the file this node names".
///
/// `ENOENT` is the entry gone; `EXDEV` and `ELOOP` are the containment flags
/// refusing an escape that was not there when the node was first pinned. All
/// three answer `ESTALE` — the node cannot be re-pinned, and a path-addressed
/// retry re-resolves and succeeds. Everything else is the machine talking, and
/// is passed through untouched.
fn gone_is_stale(error: Errno) -> Errno {
    match error {
        Errno::NOENT | Errno::XDEV | Errno::LOOP => Errno::STALE,
        other => other,
    }
}

/// Where the namespace's rules put `path` **now**, or `None` where they no
/// longer admit a host entry there.
///
/// The walk and the single-component resolve below are the engine's own — the
/// very two calls [`Session::lookup`](crate::data::session::Session::lookup)
/// makes — so re-pinning by namespace path is the existing resolution path
/// replayed, never a second one written beside it.
///
/// A path is resolved as a *name inside its parent*, because that is the shape
/// the engine decides in. The namespace root has no parent and is synthesized
/// by definition, so it never holds a pin to re-pin.
fn backing_at(namespace: &Namespace, path: &NamespacePath) -> Option<HostBacking> {
    let rules = namespace.rules();
    let context = rules.walk(&path.parent()?)?;
    rules.resolve(&context, path.last()?).backing().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{FileKind, Grafts};
    use crate::rules::{
        HostTarget, Name, Ownership, OwnershipMode, RuleSpec, RuleTable, ServerIdentity, ShareMode,
        SquashIds,
    };
    use crate::testing::Scratch;
    use std::path::Path;

    /// A namespace grafting one directory read-write at `/g`, which is all a
    /// re-pin needs: a graft descriptor to descend from.
    fn namespace_grafting(root: &Path) -> Namespace {
        let table = RuleTable::build([
            RuleSpec::new("/g", ShareMode::Rw).with_target(root.display().to_string())
        ])
        .expect("valid table");
        let grafts = Grafts::pin(&table).expect("the target exists");
        Namespace::new(
            voidport_control::NamespaceName::new("pin").expect("valid name"),
            voidport_control::PermissionMode::Passthrough,
            voidport_control::AuthMode::None,
            Ownership::new(
                OwnershipMode::Passthrough,
                ServerIdentity::new(1000, 100),
                SquashIds::default(),
            )
            .expect("valid ownership"),
            table,
            crate::rules::XattrRules::default(),
            grafts,
        )
    }

    fn open_path(path: &Path) -> OwnedFd {
        rustix::fs::openat(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .expect("the entry pins")
    }

    fn identity(path: &Path) -> NodeIdentity {
        let fd = open_path(path);
        HostAttr::of(fd.as_fd()).expect("stattable").node_identity()
    }

    fn backing(root: &Path, name: &str) -> HostBacking {
        HostBacking::graft_root(HostTarget::new(root.display().to_string()))
            .child(&Name::new(name).expect("valid name"))
    }

    /// Everything the cache records about one entry of the grafted scratch
    /// directory, which [`namespace_grafting`] puts at `/g`.
    fn entry(scratch: &Scratch, name: &str) -> Pinned {
        let path = scratch.join(name);
        Pinned {
            fd: open_path(&path),
            path: NamespacePath::parse(&format!("/g/{name}")).expect("valid namespace path"),
            backing: backing(scratch.path(), name),
            identity: identity(&path),
            recipe: backing(scratch.path(), name),
        }
    }

    /// One slot per file, filed and given back.
    #[test]
    fn a_pin_is_resident_until_the_budget_needs_its_slot() {
        let scratch = Scratch::new("pin");
        let budget = DescriptorBudget::new(2);
        assert_eq!(budget.budget(), 2);
        assert_eq!(budget.resident(), 0);

        let mut pins = Vec::new();
        for index in 0..3 {
            let name = format!("file-{index}");
            scratch.file(&name, b"x");
            pins.push(budget.pin(entry(&scratch, &name)));
        }
        // The third admission evicted the first, and never more than the
        // budget is resident.
        assert_eq!(budget.resident(), 2);
        assert!(pins[0].resident().is_none(), "the oldest slot went first");
        assert!(pins[1].resident().is_some());
        assert!(pins[2].resident().is_some());

        // A node that goes away gives its slot back.
        pins.pop();
        assert_eq!(budget.resident(), 1);
        pins.clear();
        assert_eq!(budget.resident(), 0);
    }

    /// Use is what keeps a slot: the least *recently used* one is evicted, not
    /// the oldest one.
    #[test]
    fn touching_a_slot_moves_it_out_of_the_way_of_eviction() {
        let scratch = Scratch::new("pin-lru");
        let namespace = namespace_grafting(scratch.path());
        let budget = DescriptorBudget::new(2);
        let names = ["a", "b", "c"];
        let pins: Vec<Arc<NodePin>> = names
            .iter()
            .map(|name| {
                scratch.file(name, b"x");
                budget.pin(entry(&scratch, name))
            })
            .collect();
        // `a` was evicted by `c`; using it brings it back and costs `b` its
        // slot, because `b` is now the least recently used.
        assert!(pins[0].resident().is_none());
        assert!(pins[0].descriptor(&namespace).is_ok());
        assert_eq!(budget.resident(), 2);
        assert!(pins[1].resident().is_none(), "b was the oldest use");
        assert!(pins[2].resident().is_some());
    }

    /// The whole point of the identity record: after eviction, a file replaced
    /// at the same path must not be served through the old node.
    #[test]
    fn a_replaced_entry_answers_stale_rather_than_serving_the_impostor() {
        let scratch = Scratch::new("pin-identity");
        let namespace = namespace_grafting(scratch.path());
        let budget = DescriptorBudget::new(1);
        let path = scratch.file("victim", b"original");
        let pin = budget.pin(entry(&scratch, "victim"));
        // A resident pin answers from the slot, whatever the host does.
        assert!(pin.descriptor(&namespace).is_ok());

        // Evict it, then replace the file behind its back.
        scratch.file("other", b"x");
        let _filler = budget.pin(entry(&scratch, "other"));
        assert!(pin.resident().is_none());
        std::fs::remove_file(&path).expect("removable");
        std::fs::write(&path, b"impostor").expect("writable");
        assert_eq!(
            pin.descriptor(&namespace).expect_err("a different file"),
            Errno::STALE
        );

        // And a path that is simply gone is stale too.
        std::fs::remove_file(&path).expect("removable");
        assert_eq!(
            pin.descriptor(&namespace).expect_err("nothing there"),
            Errno::STALE
        );
    }

    /// A recipe is one way back, not the only one: a node whose recorded name
    /// has gone re-resolves its own namespace path, which is the name the guest
    /// is holding.
    #[test]
    fn a_recipe_that_lost_its_name_falls_back_to_the_namespace_path() {
        let scratch = Scratch::new("pin-fallback");
        let namespace = namespace_grafting(scratch.path());
        let budget = DescriptorBudget::new(1);
        let original = scratch.file("original", b"contents");
        std::fs::hard_link(&original, scratch.join("copy")).expect("linkable");

        // The node was reached at `/g/original`; its recipe names the second
        // link the guest made, exactly as adopting a `link` leaves it.
        let mut pinned = entry(&scratch, "original");
        pinned.recipe = backing(scratch.path(), "copy");
        let pin = budget.pin(pinned);

        // Evict it, then unlink the name its recipe holds.
        scratch.file("filler", b"x");
        let filler = budget.pin(entry(&scratch, "filler"));
        assert!(pin.resident().is_none());
        std::fs::remove_file(scratch.join("copy")).expect("removable");

        // One live name is enough: the node is not stale, and the re-pin
        // adopted the name that answered — proven by evicting it again, since a
        // recipe still naming `copy` could not survive a second round.
        assert!(pin.descriptor(&namespace).is_ok());
        drop(filler);
        let filler = budget.pin(entry(&scratch, "filler"));
        assert!(pin.resident().is_none());
        assert!(pin.descriptor(&namespace).is_ok(), "the recipe was rebound");

        // And when the namespace path goes too, there is no way back.
        drop(filler);
        let _filler = budget.pin(entry(&scratch, "filler"));
        std::fs::remove_file(&original).expect("removable");
        assert_eq!(
            pin.descriptor(&namespace).expect_err("both names are gone"),
            Errno::STALE
        );
    }

    /// The derived budget is a fraction of the limit **it is handed**, clamped
    /// at both ends; a configured one is taken as written.
    #[test]
    fn the_budget_is_derived_from_the_limit_startup_reached() {
        let budget = |configured, soft| {
            DescriptorBudget::sized(configured, DescriptorLimit::reached(soft)).budget()
        };
        assert_eq!(budget(Some(200), 1_048_576), 200, "taken as written");
        assert_eq!(
            budget(None, 65_536),
            65_536 / 2 - DESCRIPTOR_RESERVE as usize
        );
        assert_eq!(budget(None, 1024), DERIVED_FLOOR as usize, "the floor");
        assert_eq!(
            budget(None, u64::MAX),
            DERIVED_CEILING as usize,
            "the ceiling"
        );
        // The limit this process actually runs under is a limit like any other.
        assert!(DescriptorLimit::current().soft() > 0);
    }

    /// A birth time on both sides has to agree; a filesystem that records none
    /// falls back to the triple, and says so.
    #[test]
    fn identity_compares_birth_time_where_there_is_one() {
        let base = NodeIdentity {
            device: 1,
            inode: 2,
            kind: FileKind::Regular,
            birth: Some((100, 7)),
        };
        assert!(base.matches(&base));
        assert!(!base.matches(&NodeIdentity {
            birth: Some((100, 8)),
            ..base
        }));
        assert!(!base.matches(&NodeIdentity { inode: 3, ..base }));
        assert!(!base.matches(&NodeIdentity {
            kind: FileKind::Directory,
            ..base
        }));
        // Best-effort where the filesystem records no birth time.
        assert!(base.matches(&NodeIdentity {
            birth: None,
            ..base
        }));
    }
}
