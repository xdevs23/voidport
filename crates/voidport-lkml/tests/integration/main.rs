#![forbid(unsafe_code)]

mod acquisition;
mod cli;
#[path = "support/collector.rs"]
mod collector;
#[path = "support/corpus.rs"]
mod corpus;
mod errors;
mod faulty_filesystem;
mod harness;
mod interpretation;
mod persistence;
