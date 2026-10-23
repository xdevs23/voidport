use std::sync::{Arc, MutexGuard};

use rustix::io::Errno;

use super::Session;
use crate::data::handle::HandleTable;
use crate::data::locks::LockSets;
use crate::data::node::{Node, NodeTable};
use crate::data::recall::Recalls;

impl Session {
    pub fn nodes(&self) -> MutexGuard<'_, NodeTable> {
        self.nodes
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn handles(&self) -> MutexGuard<'_, HandleTable> {
        self.handles
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn recalls(&self) -> &Arc<Recalls> {
        &self.recalls
    }

    pub fn locks(&self) -> &Arc<LockSets> {
        &self.locks
    }

    pub fn node(&self, id: u64) -> Result<Node, Errno> {
        self.nodes().get(id).ok_or(Errno::STALE)
    }

    pub fn directory(&self, id: u64) -> Result<Node, Errno> {
        let node = self.node(id)?;
        if node.is_directory() {
            Ok(node)
        } else {
            Err(Errno::NOTDIR)
        }
    }
}
