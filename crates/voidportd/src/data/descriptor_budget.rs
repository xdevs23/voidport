//! A node has its `O_PATH` descriptor as a cache slot only: a guest kernel
//! without memory pressure never drops a dentry, so a descriptor per lookup it
//! remembers would fill the descriptor table. The budget is server-global,
//! because the descriptor table is process-wide.
//!
//! Every node reopens by itself, from a descriptor the namespace snapshot
//! already has, so no slot depends on another.
//!
//! The budget bounds the descriptors in the cache only. Eviction drops the
//! reference of the cache, and the descriptor closes with its last reference.
//! A descriptor used past eviction by an operation or an open handle is not
//! counted.
//!
//! The ledger lock is never held across a host syscall and never across the
//! table lock of a session. Eviction takes descriptors out of their slots under
//! the ledger lock and closes them after releasing it. A reopen takes only the
//! single-flight lock of its node, so a thousand threads meeting the same
//! evicted node perform one reopen.

use std::collections::BTreeMap;
use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use rustix::io::Errno;

use crate::host::attr::{HostAttr, NodeIdentity};
use crate::host::open::pin_relative;
use crate::namespace::Namespace;
use crate::rules::{HostBacking, NamespacePath};

/// Shared by every clone of the node: a node taken out of the table to be worked
/// on and the entry left behind must agree about whether the descriptor is still
/// there.
#[derive(Debug)]
pub struct NodePin {
    budget: Arc<DescriptorBudget>,
    /// The name used by the guest, which is why it is the fallback when the
    /// recorded recipe fails with `ENOENT`: one recipe cannot represent two live
    /// names of an inode.
    path: NamespacePath,
    /// The backing chosen by the rules when the node was first opened, never
    /// where the entry is now: the re-target check compares it against where the
    /// namespace puts the directory now.
    backing: HostBacking,
    identity: NodeIdentity,
    recipe: Mutex<HostBacking>,
    state: Mutex<Slot>,
    /// Single-flight: one reopen per node, however many threads wait for it.
    repin: Mutex<()>,
}

/// One struct, because the five belong together and are easy to transpose: two
/// of them are host locations and two are ways back to the same file.
#[derive(Debug)]
pub struct Pinned {
    pub fd: OwnedFd,
    /// The fallback when the name recorded in the recipe is gone.
    pub path: NamespacePath,
    pub backing: HostBacking,
    pub identity: NodeIdentity,
    /// Equal to `backing` for everything a fresh resolution opened; they part
    /// company where the server has since moved the entry, or where the entry
    /// was reached through a parent the server had moved.
    pub recipe: HostBacking,
}

#[derive(Debug)]
struct Slot {
    /// `None` once the budget has evicted it. The descriptor lives on for as
    /// long as another reference to it exists.
    fd: Option<Arc<OwnedFd>>,
    tick: u64,
}

impl NodePin {
    /// # Errors
    ///
    /// `ESTALE` for a reopen that cannot find the same file: a missing entry, an
    /// identity mismatch, a containment refusal (`EXDEV`, `ELOOP`: a symlink
    /// planted since the node was first opened), or a namespace that no longer
    /// grafts the path. Every other host errno propagates unchanged.
    pub fn descriptor(self: &Arc<Self>, namespace: &Namespace) -> Result<Arc<OwnedFd>, Errno> {
        if let Some(fd) = self.resident() {
            self.budget.touch(self);
            return Ok(fd);
        }
        self.repin(namespace)
    }

    #[must_use]
    pub fn resident(&self) -> Option<Arc<OwnedFd>> {
        self.state().fd.clone()
    }

    #[must_use]
    pub fn backing(&self) -> &HostBacking {
        &self.backing
    }

    #[must_use]
    pub fn identity(&self) -> NodeIdentity {
        self.identity
    }

    /// A snapshot, because a caller opening a child from it must not hold the
    /// lock across the syscall it is about to make.
    #[must_use]
    pub fn recipe(&self) -> HostBacking {
        self.recorded().clone()
    }

    /// A rename, a `RENAME_EXCHANGE` or a link through the mount moves the host
    /// entry of a node, and the recorded path follows it here.
    pub fn rebind(&self, recipe: HostBacking) {
        *self.recorded() = recipe;
    }

    fn repin(self: &Arc<Self>, namespace: &Namespace) -> Result<Arc<OwnedFd>, Errno> {
        // The thread that takes this lock reopens. Every other thread waits and
        // then finds the slot filled by the check below.
        let _flight = self
            .repin
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(fd) = self.resident() {
            self.budget.touch(self);
            return Ok(fd);
        }
        // No ledger lock and no session table lock is held here.
        let fd = Arc::new(self.pin_again(namespace)?);
        self.state().fd = Some(Arc::clone(&fd));
        self.budget.admit(self);
        Ok(fd)
    }

    /// A recipe that fails with `ENOENT` has lost the name it recorded, but an
    /// inode linked under a second name and then unlinked under the first is
    /// still the file of this node. So the namespace path of the node is
    /// resolved again under the current rules before the node is given up, and
    /// a match rebinds the recipe there.
    fn pin_again(&self, namespace: &Namespace) -> Result<OwnedFd, Errno> {
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

    /// The graft descriptor comes from the currently published namespace
    /// snapshot, so a rule removed at the control plane leaves nothing to
    /// descend from and the node fails with `ESTALE` on its next use.
    fn walk_to(&self, backing: &HostBacking, namespace: &Namespace) -> Result<OwnedFd, Errno> {
        let graft = namespace.grafts().graft_of(backing).ok_or(Errno::STALE)?;
        pin_relative(graft, backing.relative())
    }

    /// Applies to every way back, so an old node id never serves another file.
    fn verified(&self, fd: OwnedFd) -> Result<OwnedFd, Errno> {
        let found = HostAttr::of(fd.as_fd())?.node_identity();
        if !self.identity.matches(&found) {
            return Err(Errno::STALE);
        }
        Ok(fd)
    }

    /// Ignores poisoning: a panicking holder can leave a descriptor filed, which
    /// the ledger closes on its next eviction.
    fn state(&self) -> MutexGuard<'_, Slot> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn recorded(&self) -> MutexGuard<'_, HostBacking> {
        self.recipe
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

impl Drop for NodePin {
    /// A node the guest forgot, or a session torn down, must leave the resident
    /// count where it found it, or an unreturned slot would eventually starve
    /// the cache.
    fn drop(&mut self) {
        let resident = self
            .state
            .get_mut()
            .unwrap_or_else(|poison| poison.into_inner());
        if resident.fd.is_some() {
            let tick = resident.tick;
            self.budget.retire(tick);
        }
    }
}

#[derive(Debug)]
pub struct DescriptorBudget {
    budget: usize,
    ledger: Mutex<Ledger>,
}

#[derive(Debug, Default)]
struct Ledger {
    /// A `BTreeMap` gives the oldest in one step and re-files a touched slot in
    /// logarithmic time.
    order: BTreeMap<u64, Weak<NodePin>>,
    tick: u64,
    /// Kept beside `order`, not derived from it, because a slot popped for a node
    /// that has since been dropped still has to be counted out.
    resident: usize,
    idle: BTreeMap<u64, Weak<dyn LeaseHolder>>,
    /// A lease asked back has its slot until its holder has given it up, so
    /// the total may stand above the budget meanwhile.
    leased: usize,
}

impl Ledger {
    fn next(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Where leases fill the budget, the last cached descriptor remains and the
    /// least recently used idle lease is handed back instead, to be asked back
    /// outside the lock; the count stands above the budget by that descriptor
    /// until the lease is given up. With no idle lease, the last cached
    /// descriptor goes too.
    fn trim(&mut self, budget: usize) -> (Vec<Arc<OwnedFd>>, Option<Arc<dyn LeaseHolder>>) {
        let mut evicted = Vec::new();
        while self.resident + self.leased > budget {
            if self.resident <= 1
                && let Some(holder) = self.oldest_idle()
            {
                return (evicted, Some(holder));
            }
            match self.evict_pin() {
                Some(fd) => evicted.extend(fd),
                None => break,
            }
        }
        (evicted, None)
    }

    /// The inner `None` is a slot dropped already, whose descriptor went with its
    /// node.
    fn evict_pin(&mut self) -> Option<Option<Arc<OwnedFd>>> {
        let (_, slot) = self.order.pop_first()?;
        self.resident -= 1;
        Some(slot.upgrade().and_then(|pin| pin.state().fd.take()))
    }

    /// It returns to the order once it is idle again.
    fn oldest_idle(&mut self) -> Option<Arc<dyn LeaseHolder>> {
        while let Some((_, holder)) = self.idle.pop_first() {
            if let Some(holder) = holder.upgrade() {
                return Some(holder);
            }
        }
        None
    }
}

pub trait LeaseHolder: Send + Sync + std::fmt::Debug {
    fn give_back(self: Arc<Self>);
}

#[derive(Debug)]
pub struct LeaseSlot {
    budget: Arc<DescriptorBudget>,
    holder: Weak<dyn LeaseHolder>,
    idle: Mutex<Option<u64>>,
}

impl LeaseSlot {
    pub fn idle(&self) {
        let mut ledger = self.budget.ledger();
        let mut idle = self.filed();
        if let Some(tick) = idle.take() {
            ledger.idle.remove(&tick);
        }
        let tick = ledger.next();
        ledger.idle.insert(tick, Weak::clone(&self.holder));
        *idle = Some(tick);
    }

    pub fn busy(&self) {
        let mut ledger = self.budget.ledger();
        if let Some(tick) = self.filed().take() {
            ledger.idle.remove(&tick);
        }
    }

    fn filed(&self) -> MutexGuard<'_, Option<u64>> {
        self.idle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

impl Drop for LeaseSlot {
    fn drop(&mut self) {
        let idle = self
            .idle
            .get_mut()
            .unwrap_or_else(|poison| poison.into_inner())
            .take();
        let mut ledger = self.budget.ledger();
        if let Some(tick) = idle {
            ledger.idle.remove(&tick);
        }
        ledger.leased -= 1;
    }
}

/// The listeners, the control socket and its connections, the state file, the
/// open graft targets, and the reopens an operation does while it runs. A
/// limit, not an allocation: being too generous costs nothing, while being one
/// too tight costs an `EMFILE` in a place nobody would look.
pub const DESCRIPTOR_RESERVE: u64 = 1024;

/// A machine with a small descriptor limit still gets a usable cache.
const DERIVED_FLOOR: u64 = 4096;

/// The startup raise can reach `fs.nr_open`, and half of that would be
/// unswappable slab.
const DERIVED_CEILING: u64 = 262_144;

/// A value, not a `getrlimit` call: startup raises the limit towards the OS
/// maximum and reports what it reached, and the derived budget is a fraction of
/// that.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorLimit(u64);

impl DescriptorLimit {
    #[must_use]
    pub fn reached(soft: u64) -> Self {
        Self(soft)
    }

    #[must_use]
    pub fn soft(self) -> u64 {
        self.0
    }
}

impl DescriptorBudget {
    #[must_use]
    pub fn new(budget: usize) -> Arc<Self> {
        Arc::new(Self {
            budget,
            ledger: Mutex::new(Ledger::default()),
        })
    }

    /// A configured number is used as written. The derived number is clamped at
    /// both ends.
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

    #[must_use]
    pub fn budget(&self) -> usize {
        self.budget
    }

    /// Published by the control plane: `/proc/self/fd` counts descriptors but
    /// does not tell a cache slot of a node from an open handle.
    #[must_use]
    pub fn resident(&self) -> usize {
        self.ledger().resident
    }

    /// The caller must not hold the node table of a session: admitting one slot
    /// may evict another, and closing the evicted descriptor is a host syscall.
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

    fn admit(&self, pin: &Arc<NodePin>) {
        let (evicted, asked) = {
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
        // Outside the ledger lock: closing a descriptor is a host syscall, and
        // giving a lease back takes the lock of its holder.
        drop(evicted);
        if let Some(holder) = asked {
            holder.give_back();
        }
    }

    /// A full budget makes room by evicting its least recently used node slot.
    /// Once it contains only leases, the file gets no slot: the error is the
    /// least recently used idle lease, which the caller asks back
    /// ([`LeaseHolder::give_back`]) outside every lock of its own, or `None`
    /// when every lease is relied on.
    pub fn lease_slot(
        self: &Arc<Self>,
        holder: Weak<dyn LeaseHolder>,
    ) -> Result<LeaseSlot, Option<Arc<dyn LeaseHolder>>> {
        let evicted = {
            let mut ledger = self.ledger();
            let evicted = if ledger.resident + ledger.leased >= self.budget {
                ledger.evict_pin().ok_or_else(|| ledger.oldest_idle())?
            } else {
                None
            };
            ledger.leased += 1;
            evicted
        };
        drop(evicted);
        Ok(LeaseSlot {
            budget: Arc::clone(self),
            holder,
            idle: Mutex::new(None),
        })
    }

    fn touch(&self, pin: &Arc<NodePin>) {
        let mut ledger = self.ledger();
        let mut slot = pin.state();
        // The slot may have been evicted between the read that found it resident
        // and this line; the ledger is the authority on whether it is still
        // filed.
        if ledger.order.remove(&slot.tick).is_none() {
            return;
        }
        slot.tick = ledger.next();
        ledger.order.insert(slot.tick, Arc::downgrade(pin));
    }

    fn retire(&self, tick: u64) {
        let mut ledger = self.ledger();
        if ledger.order.remove(&tick).is_some() {
            ledger.resident -= 1;
        }
    }

    /// Ignores poisoning: the worst a panicking holder leaves is a slot to
    /// reclaim.
    fn ledger(&self) -> MutexGuard<'_, Ledger> {
        self.ledger
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// `ENOENT` is the entry gone; `EXDEV` and `ELOOP` are the containment flags
/// refusing an escape that was not there when the node was first opened.
fn gone_is_stale(error: Errno) -> Errno {
    match error {
        Errno::NOENT | Errno::XDEV | Errno::LOOP => Errno::STALE,
        other => other,
    }
}

/// The namespace root is synthesized, so it never has a host entry to look up
/// again.
fn backing_at(namespace: &Namespace, path: &NamespacePath) -> Option<HostBacking> {
    namespace.rules().resolve_path(path).backing().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{FileKind, Grafts};
    use crate::rules::{
        HostTarget, Name, Ownership, OwnershipMode, RuleSpec, RuleTable, ServerIdentity, ShareMode,
        SquashIds,
    };
    use std::path::Path;
    use voidport_test_host::Scratch;

    fn namespace_grafting(root: &Path) -> Namespace {
        let table = RuleTable::build([
            RuleSpec::new("/g", ShareMode::Rw).with_target(root.display().to_string())
        ])
        .expect("valid table");
        let grafts = Grafts::pin(&table).expect("the target exists");
        Namespace::new(
            voidport_control::NamespaceName::new("pin").expect("valid name"),
            crate::namespace::PolicyModes::default(),
            Ownership::new(
                OwnershipMode::Passthrough,
                ServerIdentity::new(1000, 100),
                SquashIds::default(),
            )
            .expect("valid ownership"),
            table,
            crate::rules::XattrRules::default(),
            true,
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
        assert_eq!(budget.resident(), 2);
        assert!(pins[0].resident().is_none(), "the oldest slot went first");
        assert!(pins[1].resident().is_some());
        assert!(pins[2].resident().is_some());

        pins.pop();
        assert_eq!(budget.resident(), 1);
        pins.clear();
        assert_eq!(budget.resident(), 0);
    }

    /// The least recently used slot is evicted, not the oldest one.
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
        assert!(pins[0].resident().is_none());
        assert!(pins[0].descriptor(&namespace).is_ok());
        assert_eq!(budget.resident(), 2);
        assert!(pins[1].resident().is_none(), "b was the oldest use");
        assert!(pins[2].resident().is_some());
    }

    #[derive(Debug, Default)]
    struct Holder {
        asked: std::sync::atomic::AtomicUsize,
    }

    impl LeaseHolder for Holder {
        fn give_back(self: Arc<Self>) {
            self.asked
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    impl Holder {
        fn asked(&self) -> usize {
            self.asked.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    fn holder() -> Arc<Holder> {
        Arc::default()
    }

    fn weak(holder: &Arc<Holder>) -> Weak<dyn LeaseHolder> {
        let holder: Arc<dyn LeaseHolder> = Arc::clone(holder) as Arc<dyn LeaseHolder>;
        Arc::downgrade(&holder)
    }

    #[test]
    fn a_lease_slot_counts_against_the_budget_and_evicts_a_pin() {
        let scratch = Scratch::new("pin-lease");
        let budget = DescriptorBudget::new(2);
        let pins: Vec<Arc<NodePin>> = ["a", "b"]
            .iter()
            .map(|name| {
                scratch.file(name, b"x");
                budget.pin(entry(&scratch, name))
            })
            .collect();

        let first = holder();
        let slot = budget.lease_slot(weak(&first)).expect("a pin makes room");
        assert_eq!(budget.resident(), 1, "the oldest pin made room");
        assert!(pins[0].resident().is_none());

        drop(slot);
        scratch.file("c", b"x");
        let _third = budget.pin(entry(&scratch, "c"));
        assert_eq!(budget.resident(), 2, "the lease gave its slot back");
        assert!(pins[1].resident().is_some());
    }

    #[test]
    fn a_full_budget_asks_the_least_recently_used_idle_lease_back() {
        let budget = DescriptorBudget::new(2);
        let (first, second) = (holder(), holder());
        let first_slot = budget.lease_slot(weak(&first)).expect("room");
        let second_slot = budget.lease_slot(weak(&second)).expect("room");

        let refused = budget.lease_slot(weak(&holder()));
        assert!(
            matches!(refused, Err(None)),
            "busy leases are never asked back"
        );

        second_slot.idle();
        first_slot.idle();
        let Err(Some(asked)) = budget.lease_slot(weak(&holder())) else {
            panic!("a full budget has no slot");
        };
        asked.give_back();
        assert_eq!((first.asked(), second.asked()), (0, 1));

        let scratch = Scratch::new("pin-lease-full");
        scratch.file("a", b"x");
        let pin = budget.pin(entry(&scratch, "a"));
        assert_eq!(first.asked(), 1);
        assert!(
            pin.resident().is_some(),
            "the pin stays while the lease goes"
        );

        drop((first_slot, second_slot));
        assert!(budget.lease_slot(weak(&holder())).is_ok());
    }

    /// After eviction, a file replaced at the same path must not be served
    /// through the old node.
    #[test]
    fn a_replaced_entry_answers_stale_instead_of_serving_the_impostor() {
        let scratch = Scratch::new("pin-identity");
        let namespace = namespace_grafting(scratch.path());
        let budget = DescriptorBudget::new(1);
        let path = scratch.file("victim", b"original");
        let pin = budget.pin(entry(&scratch, "victim"));
        assert!(pin.descriptor(&namespace).is_ok());

        scratch.file("other", b"x");
        let _filler = budget.pin(entry(&scratch, "other"));
        assert!(pin.resident().is_none());
        std::fs::remove_file(&path).expect("removable");
        std::fs::write(&path, b"impostor").expect("writable");
        assert_eq!(
            pin.descriptor(&namespace).expect_err("a different file"),
            Errno::STALE
        );

        std::fs::remove_file(&path).expect("removable");
        assert_eq!(
            pin.descriptor(&namespace).expect_err("nothing there"),
            Errno::STALE
        );
    }

    #[test]
    fn a_recipe_that_lost_its_name_falls_back_to_the_namespace_path() {
        let scratch = Scratch::new("pin-fallback");
        let namespace = namespace_grafting(scratch.path());
        let budget = DescriptorBudget::new(1);
        let original = scratch.file("original", b"contents");
        std::fs::hard_link(&original, scratch.join("copy")).expect("linkable");

        // The node was reached at `/g/original`; its recipe names the second
        // link the guest made, as adopting a `link` leaves it.
        let mut pinned = entry(&scratch, "original");
        pinned.recipe = backing(scratch.path(), "copy");
        let pin = budget.pin(pinned);

        scratch.file("filler", b"x");
        let filler = budget.pin(entry(&scratch, "filler"));
        assert!(pin.resident().is_none());
        std::fs::remove_file(scratch.join("copy")).expect("removable");

        // One live name is enough, and the reopen adopted the name that
        // answered, proven by evicting it again, since a recipe still naming
        // `copy` could not survive a second round.
        assert!(pin.descriptor(&namespace).is_ok());
        drop(filler);
        let filler = budget.pin(entry(&scratch, "filler"));
        assert!(pin.resident().is_none());
        assert!(pin.descriptor(&namespace).is_ok(), "the recipe was rebound");

        drop(filler);
        let _filler = budget.pin(entry(&scratch, "filler"));
        std::fs::remove_file(&original).expect("removable");
        assert_eq!(
            pin.descriptor(&namespace).expect_err("both names are gone"),
            Errno::STALE
        );
    }

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
    }

    /// A filesystem that records no birth time falls back to the triple.
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
        assert!(base.matches(&NodeIdentity {
            birth: None,
            ..base
        }));
    }
}
