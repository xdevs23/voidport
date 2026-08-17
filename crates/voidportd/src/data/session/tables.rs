//! Reaching the session's two tables, and what an id names.
//!
//! The plain accessors, with no policy of their own: they hand out the guard
//! and turn an id into a node, so every other concern of the session — and
//! every wire operation — takes the tables one way. The one decision made here
//! is that an id the session never handed out, or has already forgotten, is
//! `ESTALE` and not a panic.

use std::sync::MutexGuard;

use rustix::io::Errno;

use super::Session;
use crate::data::handle::HandleTable;
use crate::data::node::{Node, NodeTable};

impl Session {
    /// The node table.
    pub fn nodes(&self) -> MutexGuard<'_, NodeTable> {
        self.nodes
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// The handle table.
    pub fn handles(&self) -> MutexGuard<'_, HandleTable> {
        self.handles
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// The node an id names.
    ///
    /// # Errors
    ///
    /// Returns `ESTALE` for an id this session never handed out or has already
    /// forgotten — the node is gone, which is exactly what stale means.
    pub fn node(&self, id: u64) -> Result<Node, Errno> {
        self.nodes().get(id).ok_or(Errno::STALE)
    }

    /// The node an id names, required to be a directory.
    ///
    /// # Errors
    ///
    /// As [`Self::node`], plus `ENOTDIR`.
    pub fn directory(&self, id: u64) -> Result<Node, Errno> {
        let node = self.node(id)?;
        if node.is_directory() {
            Ok(node)
        } else {
            Err(Errno::NOTDIR)
        }
    }
}
