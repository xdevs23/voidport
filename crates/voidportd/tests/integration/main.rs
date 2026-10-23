// The leases module needs unsafe code, so every other module forbids it itself.

mod connections;
mod control;
mod create;
mod data;
mod data_limits;
mod direct_io;
#[path = "../frontend/mod.rs"]
mod frontend;
mod inline;
mod leases;
mod listeners;
mod privileged_bits;
mod reclaim;
mod startup;
mod state;
mod subscribe;
mod virtio;
