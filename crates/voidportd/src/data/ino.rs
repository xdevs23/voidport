use std::collections::HashMap;
use std::sync::Mutex;

use voidport_control::NamespaceName;

use crate::host::HostIdentity;
use crate::rules::NamespacePath;

/// Allocation is monotonic in the low 63 bits, so a real entry never has
/// the tag that marks the synthesized-directory space.
pub const SYNTHETIC_INO_TAG: u64 = 1 << 63;

/// Server-global: a table in a namespace snapshot would renumber every
/// unchanged directory on each mutation.
///
/// An ino is not stable across server restarts, and a host `(dev, ino)` reused
/// after a deletion maps to the ino of the deleted entry.
#[derive(Debug, Default)]
pub struct InoAllocator {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    allocated: u64,
    host: HashMap<(u64, u64), u64>,
    synthesized: HashMap<(NamespaceName, NamespacePath), u64>,
}

impl InoAllocator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

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

    /// Keyed by namespace and path: one host directory grafted at two
    /// namespace paths is two directories with different children.
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

    #[must_use]
    pub fn allocated(&self) -> u64 {
        self.locked().allocated
    }

    /// Ignores poisoning: a panicking caller can only have left the counter
    /// unincremented.
    fn locked(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

impl State {
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
        assert_eq!(allocator.host(entry(7, 11)), first);
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
