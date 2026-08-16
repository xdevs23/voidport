//! Renders `voidportd.1` from the command-line definition.
//!
//! The manual page is generated, not written, so it cannot say something
//! `--help` does not: `src/cli.rs` is compiled twice, once into the binary and
//! once here, and `clap_mangen` turns that same definition into roff. The page
//! lands in `OUT_DIR`; the flake installs it into `$out/share/man/man1`.

use std::path::PathBuf;

use clap::CommandFactory as _;

#[allow(
    dead_code,
    reason = "the build script needs only the command definition, not the parsed values"
)]
#[path = "src/cli.rs"]
mod cli;

fn main() -> std::io::Result<()> {
    println!("cargo::rerun-if-changed=src/cli.rs");
    println!("cargo::rerun-if-changed=build.rs");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    clap_mangen::generate_to(cli::Args::command(), &out)?;
    Ok(())
}
