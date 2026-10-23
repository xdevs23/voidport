// SPDX-License-Identifier: GPL-2.0
//! Kernel stream I/O, virtio filesystem devices, cancellable handshakes and
//! their task ownership.
//! The filesystem module links this kbuild crate.

#![no_std]
#![feature(allocator_api, arbitrary_self_types)]

const __LOG_PREFIX: &[u8] = b"voidport\0";

pub mod clock;
pub mod errno;
pub mod handshake;
pub mod part;
pub mod socket;
pub mod thread;
pub mod virtio;
pub mod wire;

#[path = "../compat.rs"]
pub mod compat;
#[path = "transport_helpers.rs"]
pub mod helpers;
