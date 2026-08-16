//! voidport guest client: mounts a namespace over the data plane through FUSE.
//!
//! The binary is a thin shell around this library, exactly as `voidportd` is:
//! everything a mount does lives here so it can be driven from tests without a
//! command line.
//!
//! The layering follows the request as it travels:
//!
//! * [`url`] — the mount URL grammar. Pure parsing: it decides which endpoint
//!   to dial, which namespace to ask for and which subpath to mount, and it
//!   rejects every malformed spelling with its own error, without a server.
//! * [`client`] — the data-plane client. One connection per mount, many
//!   requests in flight, replies matched by request id, and a single
//!   serialization point for everything written. It speaks `voidport-proto` and
//!   nothing else: no framing is hand-assembled here.
//! * [`fuse`] — the adapter: a `fuser` [`Filesystem`](fuser::Filesystem) that
//!   translates kernel callbacks into wire operations. Callbacks never block
//!   the dispatch loop — each hands its work to the mount's runtime and replies
//!   from there.
//! * [`mount`] — assembly: negotiate the capabilities the contract requires,
//!   mount, and tear down in the required order.
//! * [`subscribe`] — listening to what the namespace shares, over the same
//!   data plane, so a guest can mount and unmount directories as the operator
//!   changes them. The `voidport subscribe` command is written on this module,
//!   so there is one stream implementation and not two.
//!
//! See `docs/DESIGN.md` ("FUSE client contract") for the authoritative model.

#![deny(missing_docs)]

pub mod client;
pub mod fuse;
pub mod mount;
pub mod subscribe;
pub mod url;
