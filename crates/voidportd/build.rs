//! `src/cli.rs` is compiled twice, once into the binary and once here, so the
//! manual page and `--help` come from one definition.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::CommandFactory as _;

#[path = "src/cli.rs"]
mod cli;

fn main() -> std::io::Result<()> {
    println!("cargo::rerun-if-changed=src/cli.rs");
    println!("cargo::rerun-if-changed=build.rs");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    clap_mangen::generate_to(cli::Args::command(), &out)?;
    Ok(())
}
