//! The parts of the virtio device of voidport that the server and the keeper
//! share.

#![forbid(unsafe_code)]

pub mod backend;
pub mod device;
mod error;
pub mod eventfd;
pub mod inflight;
pub mod memory;
pub mod queue;

pub use error::{Error, Unmappable};
