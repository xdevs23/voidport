// SPDX-License-Identifier: GPL-2.0

use kernel::prelude::*;
use kernel::sync::Arc;
use voidport_session::cleanup::WorkerStep;
use voidport_session::time::{deadline_verdict, DeadlineVerdict};

use super::Session;
use crate::cleanup::{Connections, Written};
use crate::clock::{now, timeout_of};
use crate::connection::{Connection, Death};
use crate::thread::Thread;

impl Session {
    pub(crate) fn start_cleanup(self: &Arc<Self>) -> Result {
        let session = self.clone();
        let cancellation = self.clone();
        *self.cleanup.lock() = Some(Thread::spawn(
            c"voidport-cleanup",
            move || cleanup(&session),
            move || {
                cancellation.begin_close();
                cancellation.records.lock().close();
                cancellation.cleanup_ready.notify_all();
            },
        )?);
        Ok(())
    }

    /// Ends the cleanup worker once the mount closed: closes the records,
    /// which has the worker run a last pass over them and return, and joins
    /// it. A stop can end the worker before it ever ran, so this task runs the
    /// last pass too, which finds nothing left after a worker that ran it.
    /// The closed mount sends nothing, so the pass does not wait.
    pub(super) fn end_cleanup(&self) {
        self.records.lock().close();
        self.cleanup_ready.notify_all();
        let thread = self.cleanup.lock().take();
        if let Some(thread) = thread {
            thread.stop();
        }
        cleanup(self);
    }
}

/// The one teardown-owned cleanup worker. A detached batch is reversed to
/// process oldest first; arrivals cannot indefinitely postpone an older batch.
fn cleanup(session: &Session) {
    let _scope = crate::helpers::NoFsScope::enter();
    loop {
        let mut records = session.records.lock();
        let (refused, arrived) = match records.step(now()) {
            WorkerStep::Pass { refused, arrived } => (refused, arrived),
            WorkerStep::Retry { deadline } => {
                if let DeadlineVerdict::Wait(remaining) = deadline_verdict(deadline, now()) {
                    let _ = session
                        .cleanup_ready
                        .wait_interruptible_timeout(&mut records, timeout_of(remaining));
                }
                continue;
            }
            WorkerStep::Sleep => {
                // An idle worker sleeps interruptibly: an uninterruptible sleep
                // counts toward the load average and trips the hung task check
                // on a mount that is idle for a long time. This thread does not
                // receive signals, so nothing is pending.
                let _ = session.cleanup_ready.wait_interruptible(&mut records);
                continue;
            }
            WorkerStep::Exit => return,
        };
        drop(records);
        for cleanup in Iterator::chain(refused.oldest_first(), arrived.oldest_first()) {
            if let Some(cleanup) = crate::cleanup::discharge(cleanup, session) {
                session.records.lock().finish_cleanup(cleanup);
            }
        }
    }
}

impl Connections for Session {
    fn lasts(&self, generation: u64) -> bool {
        self.serving(generation).is_some()
    }

    /// Uses a connection of the pool of that session for the frame, and
    /// another one while a connection died before it took the frame.
    fn write_cleanup(
        &self,
        generation: u64,
        write: &mut dyn FnMut(&Arc<Connection>) -> Result<bool>,
    ) -> Written {
        let Some(pool) = self.serving(generation) else {
            return Written::Ended;
        };
        loop {
            let lent = match pool.take(self) {
                Ok(Some(lent)) => lent,
                Ok(None) => return Written::Ended,
                Err(_) => return Written::Later,
            };
            match write(lent.connection()) {
                Ok(owed) => {
                    // A reply owed on the connection leaves it to its
                    // thread, which gives it back after that reply.
                    if owed {
                        lent.leave_to_thread();
                    }
                    return Written::Sent;
                }
                Err(error) if error == EIO => {}
                Err(error) => {
                    // A frame that cannot be written ends its connection,
                    // unless memory was refused.
                    if error != ENOMEM {
                        lent.connection().bury(Death::Transport(error));
                    }
                    return Written::Later;
                }
            }
        }
    }
}
