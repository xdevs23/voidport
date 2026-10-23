// SPDX-License-Identifier: GPL-2.0

//! A filesystem that mounts a voidport namespace over a TCP or unix stream
//! socket, or over a virtio filesystem device whose tag starts with `voidport-`.

// The wire dependency is distinct from any crate exported by the kernel.
extern crate wire_zerocopy as zerocopy;

use kernel::prelude::*;

mod aops;
mod buffer;
mod cleanup;
mod connection;
mod diag;
mod direct;
mod division;
mod file_ops;
mod folio;
mod fs;
mod handle;
mod helpers;
mod inode_kind;
mod inode_ops;
mod integer;
mod lock;
mod mount;
mod namespace;
mod node;
mod ops;
mod parts;
mod pool;
mod session;
mod setattr;
mod settle;
mod splice;
mod stats;
mod superblock;
mod vfs;
mod vtable;
mod write;
mod writeback;
mod xattr;

use voidport_transport::{clock, compat, errno, handshake, part, socket, thread, virtio, wire};

module! {
    type: Voidport,
    name: "voidport",
    authors: ["voidport"],
    description: "voidport native filesystem over a kernel TCP or unix stream or a virtio device",
    license: "GPL",
}

/// A mount lasts as long as its superblock, so unloading the module only
/// unregisters the filesystem type, which fails while a mount exists, and then
/// the driver.
struct Voidport {
    _stats: stats::Published,
    _driver: virtio::Driver,
}

impl kernel::Module for Voidport {
    fn init(module: &'static ThisModule) -> Result<Self> {
        let published = stats::publish()?;
        // SAFETY: called once at module load, with the module being loaded.
        let driver = unsafe { virtio::Driver::register(module.as_ptr())? };
        // SAFETY: called once at module load, before any mount, with the
        // module being loaded, stored in the type's `owner` field.
        unsafe { fs::register(module.as_ptr())? };
        Ok(Voidport {
            _stats: published,
            _driver: driver,
        })
    }
}

impl Drop for Voidport {
    fn drop(&mut self) {
        // SAFETY: called once at module unload; the kernel guarantees no mount
        // of this type remains, because it refuses to unload a filesystem
        // module with a live superblock.
        unsafe { fs::unregister() };
    }
}
