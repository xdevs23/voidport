//! Telling the guest kernel to drop the pages it caches for a file.
//!
//! What keeps those pages fresh is described at [`DataCaching::Page`]; this
//! module is the part of it that the adapter sends to the kernel itself.
//!
//! [`DataCaching::Page`]: super::DataCaching::Page

use std::collections::HashSet;
use std::io;
use std::sync::{Mutex, MutexGuard, OnceLock};

use fuser::{INodeNo, Notifier};

/// Drops the cached pages of a file through the session's notifier.
///
/// The notifier belongs to the session, and the session does not exist until
/// the filesystem is handed to it. The adapter therefore stores this, and the
/// mount attaches the notifier before the first dispatch loop starts.
#[derive(Debug, Default)]
pub struct PageInvalidator {
    notifier: OnceLock<Notifier>,
    /// The open handles a lock has dropped the pages through since they were
    /// opened.
    locked: Mutex<HashSet<u64>>,
}

impl PageInvalidator {
    /// Attaches the session's notifier.
    pub fn attach(&self, notifier: Notifier) {
        if self.notifier.set(notifier).is_err() {
            tracing::error!("a second session notifier was attached and is ignored");
        }
    }

    /// Drops every cached page of a file, and its cached attributes with them,
    /// and returns once the kernel has done so.
    ///
    /// The notification goes out from a blocking thread. The kernel waits for
    /// the lock of every page it drops, and a locked page can be waiting for a
    /// reply that a task of this runtime has to send, so a runtime worker that
    /// waited here could be the one that never sends it.
    ///
    /// The kernel must not be in the middle of a size change of the file: it
    /// sends no write of a dirty page until the reply to that change, and
    /// dropping a dirty page waits for its write.
    ///
    /// A notification that fails is logged. The pages it should have dropped
    /// are then stale until the size or the modification time of the file
    /// changes again.
    pub async fn drop_pages(&self, node_id: u64) {
        let Some(notifier) = self.notifier.get().cloned() else {
            tracing::error!(
                node_id,
                "no session notifier is attached to drop the pages of a file"
            );
            return;
        };
        let sent =
            tokio::task::spawn_blocking(move || notifier.inval_inode(INodeNo(node_id), 0, 0))
                .await
                .unwrap_or_else(|failed| Err(io::Error::other(failed)));
        if let Err(error) = sent {
            tracing::warn!(
                node_id,
                %error,
                "the kernel did not drop the cached pages of a file, which stay stale until the \
                 file changes again"
            );
        }
    }

    /// Drops the cached pages of a file for the first lock granted through an
    /// open handle, which is when an open used to drop them.
    pub async fn drop_pages_for_lock(&self, node_id: u64, handle: u64) {
        let first = self.locked_handles().insert(handle);
        if first {
            self.drop_pages(node_id).await;
        }
    }

    /// Forgets an open handle once it is released.
    pub fn release(&self, handle: u64) {
        self.locked_handles().remove(&handle);
    }

    fn locked_handles(&self) -> MutexGuard<'_, HashSet<u64>> {
        self.locked
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}
