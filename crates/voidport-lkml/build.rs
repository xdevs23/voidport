#![forbid(unsafe_code)]
use clap::CommandFactory as _;
fn main() -> std::io::Result<()> {
    println!("cargo::rerun-if-changed=build.rs");
    clap_mangen::generate_to(
        voidport_lkml_cli::Cli::command(),
        std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"),
    )
}
