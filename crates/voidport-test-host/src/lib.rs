#![forbid(unsafe_code)]

mod scratch;
pub mod vsock;

pub use scratch::{Scratch, create_directory, scratch_root};
