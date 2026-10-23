#![forbid(unsafe_code)]

mod scratch;
mod test_name;
pub mod vsock;

pub use scratch::{Scratch, create_directory, scratch_root};
#[doc(hidden)]
pub use test_name::test_name_in;
