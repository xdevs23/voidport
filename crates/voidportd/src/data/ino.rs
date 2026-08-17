//! Server-global inode-number allocation.
//!
//! The guest-visible `ino` is not the host's. Host inode numbers collide across
//! devices, so the server allocates its own, monotonically, and remembers the
//! mapping:
//!
//! * **Host-backed entries** are keyed by `(host_dev, host_ino)`. Identity is
//!   therefore stable across sessions, and every hardlink alias of one host
//!   inode presents the same `ino` — which is the point of allocating at all.
//! * **Synthesized directories** have no host inode. They are keyed by
//!   `(namespace name, namespace path)` in a disjoint number space tagged by
//!   the top bit, so a synthetic ino can never be confused with a real one.
//!
//! Both tables are **server-global and survive snapshot swaps and namespace
//! deletion**. A table owned by a namespace snapshot would renumber every
//! unchanged directory on every mutation, which a guest holding cached
//! attributes would read as "every directory was replaced".
//!
//! Accepted v1 limitations, both dated in the design: inos are not stable
//! across server restarts, and host `(dev, ino)` recycling after a deletion can
//! alias a stale table entry.

use std::collections::HashMap;
use std::sync::Mutex;

use voidport_control::NamespaceName;

use crate::host::HostIdentity;
use crate::rules::NamespacePath;

/// The bit that marks an ino as belonging to the synthesized-directory space.
///
/// Allocation is monotonic in the low 63 bits, so the tag partitions the space
/// exactly: a real entry never carries it, a synthesized directory always does.
pub const SYNTHETIC_INO_TAG: u64 = 1 << 63;

/// The server's inode-number allocator.
#[derive(Debug, Default)]
pub struct InoAllocator {
    state: Mutex<State>,
}

/// The allocator's tables, behind one lock.
#[derive(Debug, Default)]
struct State {
    /// The last number handed out. Monotonic, never reused within a server
    /// lifetime.
    allocated: u64,
    /// `(host_dev, host_ino)` to ino.
    host: HashMap<(u64, u64), u64>,
    /// `(namespace, namespace path)` to synthetic ino.
    synthesized: HashMap<(NamespaceName, NamespacePath), u64>,
}

impl InoAllocator {
    /// A fresh allocator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The ino of a host entry, allocating one on first sight.
    ///
    /// Keyed by the entry's device and inode and not by its kind, which a host
    /// inode fixes when it is created: the pair is the whole of the identity
    /// this table has to hold apart.
    #[must_use]
    pub fn host(&self, entry: HostIdentity) -> u64 {
        let key = (entry.device, entry.inode);
        let mut state = self.locked();
        if let Some(ino) = state.host.get(&key) {
            return *ino;
        }
        let ino = state.allocate();
        state.host.insert(key, ino);
        ino
    }

    /// The ino of a synthesized directory, allocating one on first sight.
    ///
    /// Keyed by namespace *and* path: one host directory grafted at two
    /// namespace paths is two directories with different children, and a
    /// synthesized directory has no host identity to share anyway.
    #[must_use]
    pub fn synthesized(&self, namespace: &NamespaceName, path: &NamespacePath) -> u64 {
        let mut state = self.locked();
        let key = (namespace.clone(), path.clone());
        if let Some(ino) = state.synthesized.get(&key) {
            return *ino;
        }
        let ino = state.allocate() | SYNTHETIC_INO_TAG;
        state.synthesized.insert(key, ino);
        ino
    }

    /// How many inos have been handed out.
    #[must_use]
    pub fn allocated(&self) -> u64 {
        self.locked().allocated
    }

    /// Takes the lock, ignoring poisoning: the allocator holds no invariant a
    /// panicking caller could have broken beyond the counter it was about to
    /// increment.
    fn locked(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

impl State {
    /// The next number, monotonic and never reused.
    fn allocate(&mut self) -> u64 {
        self.allocated += 1;
        assert!(
            self.allocated & SYNTHETIC_INO_TAG == 0,
            "the ino space is exhausted"
        );
        self.allocated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::FileKind;

    fn namespace(raw: &str) -> NamespaceName {
        NamespaceName::new(raw).expect("valid namespace name")
    }

    fn path(raw: &str) -> NamespacePath {
        NamespacePath::parse(raw).expect("valid namespace path")
    }

    /// A host entry with that device and inode. The kind is not part of the
    /// key, so any one will do.
    fn entry(device: u64, inode: u64) -> HostIdentity {
        HostIdentity {
            device,
            inode,
            kind: FileKind::Regular,
        }
    }

    #[test]
    fn a_host_inode_keeps_its_number() {
        let allocator = InoAllocator::new();
        let first = allocator.host(entry(7, 11));
        assert_eq!(allocator.host(entry(7, 11)), first);
        // A hardlink alias is the same host inode, so the same ino.
        assert_eq!(allocator.host(entry(7, 11)), first);
        // Same inode number on another device is another file.
        assert_ne!(allocator.host(entry(8, 11)), first);
        assert_eq!(allocator.allocated(), 2);
    }

    #[test]
    fn synthesized_directories_live_in_a_disjoint_space() {
        let allocator = InoAllocator::new();
        let host = allocator.host(entry(7, 11));
        let synthetic = allocator.synthesized(&namespace("p"), &path("/a"));
        assert_eq!(host & SYNTHETIC_INO_TAG, 0);
        assert_eq!(synthetic & SYNTHETIC_INO_TAG, SYNTHETIC_INO_TAG);
        assert_eq!(
            allocator.synthesized(&namespace("p"), &path("/a")),
            synthetic
        );
        // Keyed by namespace and by path.
        assert_ne!(
            allocator.synthesized(&namespace("other"), &path("/a")),
            synthetic
        );
        assert_ne!(
            allocator.synthesized(&namespace("p"), &path("/b")),
            synthetic
        );
    }

    #[test]
    fn allocation_is_monotonic_across_both_spaces() {
        let allocator = InoAllocator::new();
        let mut seen = Vec::new();
        for index in 0..4u64 {
            seen.push(allocator.host(entry(1, index)));
            seen.push(allocator.synthesized(&namespace("p"), &path(&format!("/{index}"))));
        }
        let low_bits: Vec<u64> = seen.iter().map(|ino| ino & !SYNTHETIC_INO_TAG).collect();
        assert_eq!(low_bits, (1..=8).collect::<Vec<u64>>());
    }
}
