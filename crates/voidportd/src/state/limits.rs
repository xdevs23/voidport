//! The configured resource caps.
//!
//! These are server settings — part of the state file's schema, sitting beside
//! [`Listener`](super::Listener) under `[server]` — so they live in the state
//! layer with the rest of the source document, and the data plane consumes
//! them. What each cap *does* is documented where it is enforced
//! ([`crate::data::caps`]); what a cap *is* is documented here.
//!
//! **Every cap is opt-in.** An absent setting is not a number, it is no cap at
//! all (decided 2026-08-14: a limit nobody chose is a bug report waiting, after
//! sized defaults twice refused a real source-tree walk that the host
//! filesystem carries without complaint). A cap exists only where an operator
//! wrote one,
//! which is the throttle a multi-tenant posture wants and nothing a single
//! trusted guest ever meets.
//!
//! What bounds a server that configured nothing is the OS, and — for
//! descriptors — the node descriptor budget. **A node no longer costs a
//! descriptor for its lifetime** (retracted 2026-08-15, after an AOSP walk
//! exhausted the table at the rate of names ever resolved): a node's `O_PATH`
//! pin is a slot in a bounded, least-recently-used cache
//! ([`crate::data::pin`]), so `max_nodes` bounds table *entries* and nothing
//! else. A handle still holds an open file for as long as the guest keeps it
//! open, and that is the cap that still speaks in descriptors. The daemon
//! raises `RLIMIT_NOFILE` to the OS maximum at startup (see
//! [`raise_descriptor_limit`](crate::daemon)); when that ceiling genuinely
//! binds, the OS's own errno surfaces: a fact, not a policy.

use serde::{Deserialize, Serialize};

/// The smallest configurable node descriptor budget.
///
/// One operation's simultaneous working set: a rename holds both parents and
/// both entries, so a budget below this could evict a descriptor the very
/// operation that pinned it still needs. Everything above it is the operator's
/// business — the tests configure hundreds.
pub const MIN_NODE_DESCRIPTOR_BUDGET: usize = 16;

/// The per-session and per-server resource caps.
///
/// Every field is optional in both senses: absent from the state file, and
/// `None` — unbounded — when absent. The whole table may therefore be omitted,
/// and a state file that omits it persists without it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// How many sessions the server serves at once. An excess connection gets
    /// an error response to its handshake and is closed. `None`: any number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_sessions: Option<usize>,
    /// How many requests one session may have in flight. Reaching it pauses
    /// that connection's read loop — backpressure, not an error. `None`: the
    /// data plane's own run-ahead bound applies, which pauses the same way and
    /// refuses nothing either ([`crate::data::caps`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_inflight: Option<usize>,
    /// How many nodes one session's node table may hold. The lookup that would
    /// exceed it fails with `ENFILE`. `None`: as many as the guest asks for —
    /// entries, not descriptors, since a node's pin is a cache slot, not
    /// a lifetime hold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_nodes: Option<usize>,
    /// How many handles one session may hold open. The open that would exceed
    /// it fails with `EMFILE`. `None`: as many as the process can hold
    /// descriptors for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_handles: Option<usize>,
    /// How many entries one materialized directory listing may hold. A larger
    /// directory fails to open with `EOVERFLOW`. `None`: the listing is as
    /// large as the directory is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_listing_entries: Option<usize>,
}

impl Limits {
    /// Whether nothing is configured — the default, unbounded posture.
    ///
    /// Persistence skips the table when it is, so a state file that never
    /// mentioned caps does not grow a block of numbers the operator did not
    /// write.
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Checks that every configured cap can mean what it says.
    ///
    /// `max_inflight = 0` is the one value the data plane cannot honour: a
    /// connection that may have no request in flight can serve nothing, and the
    /// reply channel it feeds cannot have zero capacity, so the number would
    /// have to be quietly raised to 1 — a stated cap that is not the enforced
    /// cap. It is refused at load instead, where an operator gets an error
    /// naming the field. The other caps at zero are unhelpful but honest: they
    /// refuse every session, node, handle or non-empty listing exactly as they
    /// say, so they are left to the operator. An *absent* cap is not zero and
    /// is not a refusal: it is no cap at all.
    ///
    /// # Errors
    ///
    /// Returns [`LimitsError`] naming the offending setting.
    pub fn validate(&self) -> Result<(), LimitsError> {
        if self.max_inflight == Some(0) {
            return Err(LimitsError::Zero {
                setting: "max_inflight",
            });
        }
        Ok(())
    }
}

/// Why a configured cap is not usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LimitsError {
    /// A cap that must be positive was configured as zero.
    #[error("server.limits.{setting} must be at least 1")]
    Zero {
        /// The setting at fault.
        setting: &'static str,
    },
    /// A setting was configured below the smallest value it can mean.
    #[error("server.{setting} must be at least {minimum}")]
    TooSmall {
        /// The setting at fault.
        setting: &'static str,
        /// The smallest value it may take.
        minimum: usize,
    },
    /// A vsock listener named a port outside the range a mount URL can carry.
    #[error(
        "vsock listener cid {cid} port {port}: a vsock port must be 1..=65535, \
         because a mount URL's port is the URL standard's 16-bit one"
    )]
    VsockPort {
        /// The cid the listener binds, which is how the operator finds the
        /// entry in the file.
        cid: u32,
        /// The port as configured.
        port: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_capped_until_an_operator_says_so() {
        let limits = Limits::default();
        assert_eq!(limits.max_sessions, None);
        assert_eq!(limits.max_inflight, None);
        assert_eq!(limits.max_nodes, None);
        assert_eq!(limits.max_handles, None);
        assert_eq!(limits.max_listing_entries, None);
        assert!(limits.is_default());
        assert_eq!(limits.validate(), Ok(()));
        // An empty table is the same as no table: an operator who wrote the
        // header and no settings configured no caps.
        assert_eq!(toml::from_str::<Limits>("").expect("parses"), limits);
    }

    #[test]
    fn every_cap_is_configurable_on_its_own() {
        let limits: Limits = toml::from_str("max_nodes = 8").expect("parses");
        assert_eq!(limits.max_nodes, Some(8));
        // The rest stay unbounded: configuring one cap does not conjure others.
        assert_eq!(limits.max_sessions, None);
        assert_eq!(limits.max_handles, None);
        assert!(!limits.is_default());
        assert!(toml::from_str::<Limits>("max_node = 8").is_err());
    }

    #[test]
    fn only_the_configured_caps_are_written_back() {
        let limits: Limits = toml::from_str("max_handles = 4").expect("parses");
        let text = toml::to_string(&limits).expect("serializes");
        assert_eq!(text.trim(), "max_handles = 4");
    }

    #[test]
    fn a_cap_the_server_would_have_to_raise_is_refused() {
        let limits: Limits = toml::from_str("max_inflight = 0").expect("parses");
        assert_eq!(
            limits.validate().expect_err("zero is not a cap"),
            LimitsError::Zero {
                setting: "max_inflight"
            }
        );
        assert!(
            limits
                .validate()
                .expect_err("zero")
                .to_string()
                .contains("max_inflight"),
            "the operator is told which setting to fix"
        );
        // A cap of one is a real cap, and is honoured as written.
        let one: Limits = toml::from_str("max_inflight = 1").expect("parses");
        assert_eq!(one.validate(), Ok(()));
    }
}
