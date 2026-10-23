// SPDX-License-Identifier: GPL-2.0

use core::time::Duration;

use kernel::bindings;
use kernel::prelude::*;
use kernel::sync::atomic::{Acquire, Atomic, Release};
use kernel::sync::Arc;

use crate::handshake::Server;
use crate::session::Session;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Options {
    pub(crate) server: Server,
    /// How long attributes may be believed, as a jiffies span.
    pub(crate) attr_timeout: c_ulong,
    /// How long a name may resolve without another lookup, as a jiffies span.
    pub(crate) entry_timeout: c_ulong,
    /// How long requests stall on a lost server before failing.
    pub(crate) stall: Duration,
    pub(crate) mask_privileged: bool,
}

pub(crate) struct Mount {
    pub(crate) session: Arc<Session>,
    options: Options,
    /// How many writes this mount applied: the count the session core places
    /// replies with attributes by.
    writes: Atomic<u64>,
    lock_key: bindings::siphash_key_t,
}

impl Mount {
    pub(crate) fn new(session: Arc<Session>, options: Options) -> Self {
        Self {
            session,
            options,
            writes: Atomic::new(0),
            // SAFETY: calls into the kernel's random source, which needs no
            // context.
            lock_key: unsafe {
                bindings::siphash_key_t {
                    key: [bindings::get_random_u64(), bindings::get_random_u64()],
                }
            },
        }
    }

    pub(crate) fn options(&self) -> Options {
        self.options
    }

    pub(crate) fn attr_timeout(&self) -> c_ulong {
        self.options.attr_timeout
    }

    pub(crate) fn entry_timeout(&self) -> c_ulong {
        self.options.entry_timeout
    }

    pub(crate) fn mask_privileged(&self) -> bool {
        self.options.mask_privileged
    }

    /// A caller reads it before it sends a request whose reply includes
    /// attributes.
    pub(crate) fn writes(&self) -> u64 {
        self.writes.load(Acquire)
    }

    pub(crate) fn count_write(&self) -> u64 {
        self.writes.fetch_add(1, Release) + 1
    }

    /// A hash keyed for this mount, so no kernel address is sent to the
    /// server.
    pub(crate) fn lock_owner(&self, owner: bindings::fl_owner_t) -> u64 {
        // SAFETY: hashing reads only the key and the value.
        unsafe { bindings::siphash_1u64(owner as usize as u64, &self.lock_key) }
    }
}
