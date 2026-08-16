//! Ownership mapping between host and guest id space.
//!
//! Three modes, per the design's "Ownership" section:
//!
//! * **map** — translate host ids to guest ids through explicit tables, and
//!   apply the inverse for guest-created files.
//! * **passthrough** — host ids shown as-is, both directions.
//! * **static** — everything presented as one configured id.
//!
//! Precise semantics this module implements:
//!
//! * uid and gid tables are separate, and each must be **injective in both
//!   directions**; a duplicate host id or guest id is rejected at map-table
//!   construction ([`IdMapError`]), and a mapped guest id equal to the squash id
//!   is rejected at ownership construction ([`OwnershipError`]).
//! * `unmapped: hide` hides a file when **either** its uid or its gid is
//!   unmapped; `squash` replaces only the unmapped component; `passthrough`
//!   passes the unmapped component through. The squash target is numeric and
//!   configurable ([`DEFAULT_SQUASH_ID`]) — there are no NSS lookups anywhere
//!   in this engine.
//! * **Reverse application:** map uses the inverse tables; passthrough is
//!   identity; static cannot express a reverse. For a guest id with no reverse
//!   mapping — and for static in every case — a create lands as the server
//!   identity, while an explicit chown/chgrp is denied ([`ChownDenied`], which
//!   the server answers with `EPERM` instead of lying about the result).
//!
//! **Privilege reality.** Applying a reverse-mapped host id other than the
//! server's own requires `CAP_CHOWN` and a backing filesystem that permits it.
//! Without that, creates simply land owned by the server identity; the guest's
//! view stays consistent either way, because presentation forward-maps
//! whatever the host actually recorded. This module computes the *intended*
//! host ids; whether they can be applied is increment 5's business.
//!
//! The module is pure: the server identity and the squash ids are injected at
//! construction, never read through `std::env` or any syscall.

use std::collections::BTreeMap;

/// The default squash target: the conventional `nobody`/`nogroup` id, used
/// numerically and never resolved through NSS.
pub const DEFAULT_SQUASH_ID: u32 = 65534;

/// An owner in host id space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostIds {
    /// Host uid.
    pub uid: u32,
    /// Host gid.
    pub gid: u32,
}

impl HostIds {
    /// Builds a host owner.
    #[must_use]
    pub fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

/// An owner in guest id space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuestIds {
    /// Guest uid.
    pub uid: u32,
    /// Guest gid.
    pub gid: u32,
}

impl GuestIds {
    /// Builds a guest owner.
    #[must_use]
    pub fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

/// The server's own identity, injected at construction.
///
/// It is the fallback owner for guest-created files whose guest owner has no
/// reverse mapping, and the owner synthesized directories present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerIdentity {
    /// The uid the server runs as.
    pub uid: u32,
    /// The gid the server runs as.
    pub gid: u32,
}

impl ServerIdentity {
    /// Builds a server identity.
    #[must_use]
    pub fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }

    /// The server identity as a host owner.
    #[must_use]
    pub fn as_host_ids(self) -> HostIds {
        HostIds::new(self.uid, self.gid)
    }
}

/// The numeric ids `unmapped: squash` presents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SquashIds {
    /// The uid unmapped host uids are squashed to.
    pub uid: u32,
    /// The gid unmapped host gids are squashed to.
    pub gid: u32,
}

impl SquashIds {
    /// Builds a squash target.
    #[must_use]
    pub fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

impl Default for SquashIds {
    /// [`DEFAULT_SQUASH_ID`] for both components.
    fn default() -> Self {
        Self::new(DEFAULT_SQUASH_ID, DEFAULT_SQUASH_ID)
    }
}

/// One entry of an id map table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdMapping {
    /// The id on the host. Configuration may write this as the enum value
    /// `uid`, meaning the invoking user; that resolves to a number at state
    /// load, before it reaches this engine.
    pub host_id: u32,
    /// The id the guest sees.
    pub guest_id: u32,
}

impl IdMapping {
    /// Builds a mapping.
    #[must_use]
    pub fn new(host_id: u32, guest_id: u32) -> Self {
        Self { host_id, guest_id }
    }
}

/// A bijective id table: host ids to guest ids and back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdMap {
    forward: BTreeMap<u32, u32>,
    reverse: BTreeMap<u32, u32>,
}

impl IdMap {
    /// Builds a table from mappings.
    ///
    /// # Errors
    ///
    /// Returns [`IdMapError`] if the mappings are not injective in both
    /// directions. A repeated host id makes presentation ambiguous, a repeated
    /// guest id makes reverse mapping ambiguous; both are configuration
    /// defects, not runtime conditions.
    pub fn new(mappings: impl IntoIterator<Item = IdMapping>) -> Result<Self, IdMapError> {
        let mut map = Self::default();
        for IdMapping { host_id, guest_id } in mappings {
            if map.forward.insert(host_id, guest_id).is_some() {
                return Err(IdMapError::DuplicateHostId { id: host_id });
            }
            if map.reverse.insert(guest_id, host_id).is_some() {
                return Err(IdMapError::DuplicateGuestId { id: guest_id });
            }
        }
        Ok(map)
    }

    /// The guest id a host id presents as, if the table maps it.
    #[must_use]
    pub fn forward(&self, host_id: u32) -> Option<u32> {
        self.forward.get(&host_id).copied()
    }

    /// The host id a guest id maps back to, if the table maps it.
    #[must_use]
    pub fn reverse(&self, guest_id: u32) -> Option<u32> {
        self.reverse.get(&guest_id).copied()
    }
}

/// Why a set of id mappings is not a valid table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdMapError {
    /// Two mappings share a host id, so presentation would be ambiguous.
    #[error("host id {id} is mapped twice")]
    DuplicateHostId {
        /// The repeated host id.
        id: u32,
    },
    /// Two mappings share a guest id, so the reverse mapping would be
    /// ambiguous.
    #[error("guest id {id} is mapped twice")]
    DuplicateGuestId {
        /// The repeated guest id.
        id: u32,
    },
}

/// What to do with a host id the map table does not cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmappedPolicy {
    /// Present the configured squash id instead. Only the unmapped component
    /// is replaced.
    Squash,
    /// Hide the file entirely — triggered by either component being unmapped.
    Hide,
    /// Present the raw host id.
    Passthrough,
}

/// The ownership mode a namespace is configured with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnershipMode {
    /// Translate through explicit, separate uid and gid tables.
    Map {
        /// The uid table.
        uid: IdMap,
        /// The gid table.
        gid: IdMap,
        /// What to do with host ids no table entry covers.
        unmapped: UnmappedPolicy,
    },
    /// Show host ids as-is.
    Passthrough,
    /// Present everything as one configured owner.
    Static {
        /// The uid every file presents.
        uid: u32,
        /// The gid every file presents.
        gid: u32,
    },
}

/// The ownership algebra of one namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ownership {
    mode: OwnershipMode,
    identity: ServerIdentity,
    squash: SquashIds,
}

impl Ownership {
    /// Builds the mapping with its environmental inputs injected.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError`] if a mapped guest uid or gid equals that
    /// component's squash id. Such a collision would make mapped and unmapped
    /// host owners present identically.
    pub fn new(
        mode: OwnershipMode,
        identity: ServerIdentity,
        squash: SquashIds,
    ) -> Result<Self, OwnershipError> {
        if let OwnershipMode::Map { uid, gid, .. } = &mode {
            if uid.reverse(squash.uid).is_some() {
                return Err(OwnershipError::GuestUidEqualsSquash { id: squash.uid });
            }
            if gid.reverse(squash.gid).is_some() {
                return Err(OwnershipError::GuestGidEqualsSquash { id: squash.gid });
            }
        }
        Ok(Self {
            mode,
            identity,
            squash,
        })
    }

    /// The configured mode.
    #[must_use]
    pub fn mode(&self) -> &OwnershipMode {
        &self.mode
    }

    /// The injected server identity.
    #[must_use]
    pub fn identity(&self) -> ServerIdentity {
        self.identity
    }

    /// The injected squash ids.
    #[must_use]
    pub fn squash(&self) -> SquashIds {
        self.squash
    }

    /// Maps a host owner into guest id space for presentation.
    #[must_use]
    pub fn forward(&self, host: HostIds) -> OwnerPresentation {
        match &self.mode {
            OwnershipMode::Passthrough => {
                OwnerPresentation::Visible(GuestIds::new(host.uid, host.gid))
            }
            OwnershipMode::Static { uid, gid } => {
                OwnerPresentation::Visible(GuestIds::new(*uid, *gid))
            }
            OwnershipMode::Map { uid, gid, unmapped } => {
                let mapped_uid =
                    forward_component(uid.forward(host.uid), host.uid, self.squash.uid, *unmapped);
                let mapped_gid =
                    forward_component(gid.forward(host.gid), host.gid, self.squash.gid, *unmapped);
                match (mapped_uid, mapped_gid) {
                    (Some(uid), Some(gid)) => OwnerPresentation::Visible(GuestIds::new(uid, gid)),
                    // `hide` triggers on either component.
                    _ => OwnerPresentation::Hidden,
                }
            }
        }
    }

    /// The host owner a guest-created file should land with.
    ///
    /// Never fails: where no reverse mapping exists — and always under static
    /// ownership — the file lands as the server identity, which is also what
    /// happens when the server lacks the privilege to apply another id.
    #[must_use]
    pub fn reverse_for_create(&self, guest: GuestIds) -> HostIds {
        match &self.mode {
            OwnershipMode::Passthrough => HostIds::new(guest.uid, guest.gid),
            OwnershipMode::Static { .. } => self.identity.as_host_ids(),
            OwnershipMode::Map { uid, gid, .. } => HostIds::new(
                uid.reverse(guest.uid).unwrap_or(self.identity.uid),
                gid.reverse(guest.gid).unwrap_or(self.identity.gid),
            ),
        }
    }

    /// The host uid an explicit `chown` to `guest_uid` must apply.
    ///
    /// # Errors
    ///
    /// Returns [`ChownDenied`] when the request cannot be expressed as a host
    /// id: under static ownership, which has no reverse, and for a guest id
    /// the table does not map back. The server answers `EPERM`; silently
    /// applying a different owner would lie to the guest.
    pub fn reverse_uid_for_chown(&self, guest_uid: u32) -> Result<u32, ChownDenied> {
        match &self.mode {
            OwnershipMode::Passthrough => Ok(guest_uid),
            OwnershipMode::Static { .. } => Err(ChownDenied::StaticOwnership),
            OwnershipMode::Map { uid, .. } => uid.reverse(guest_uid).ok_or(ChownDenied::Unmapped {
                guest_id: guest_uid,
            }),
        }
    }

    /// The host gid an explicit `chgrp` to `guest_gid` must apply.
    ///
    /// # Errors
    ///
    /// As [`Self::reverse_uid_for_chown`], for the gid table.
    pub fn reverse_gid_for_chown(&self, guest_gid: u32) -> Result<u32, ChownDenied> {
        match &self.mode {
            OwnershipMode::Passthrough => Ok(guest_gid),
            OwnershipMode::Static { .. } => Err(ChownDenied::StaticOwnership),
            OwnershipMode::Map { gid, .. } => gid.reverse(guest_gid).ok_or(ChownDenied::Unmapped {
                guest_id: guest_gid,
            }),
        }
    }
}

/// Why ownership policy construction failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OwnershipError {
    /// A mapped guest uid equals the uid used to present unmapped host owners.
    #[error("guest uid {id} is also the squash uid")]
    GuestUidEqualsSquash {
        /// The colliding guest and squash uid.
        id: u32,
    },
    /// A mapped guest gid equals the gid used to present unmapped host owners.
    #[error("guest gid {id} is also the squash gid")]
    GuestGidEqualsSquash {
        /// The colliding guest and squash gid.
        id: u32,
    },
}

/// How a host owner presents to the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerPresentation {
    /// The file is visible, owned by these guest ids.
    Visible(GuestIds),
    /// `unmapped: hide` applies: the file must not surface at all, exactly as
    /// if a rule hid it.
    Hidden,
}

/// Why an explicit ownership change cannot be carried out.
///
/// The server answers `EPERM`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChownDenied {
    /// The guest id has no reverse mapping.
    #[error("guest id {guest_id} has no host id to map back to")]
    Unmapped {
        /// The requested guest id.
        guest_id: u32,
    },
    /// Static ownership presents one id for everything and therefore has no
    /// reverse to apply.
    #[error("static ownership cannot express a reverse mapping")]
    StaticOwnership,
}

/// Applies the unmapped policy to one component of a host owner.
///
/// `None` means the file must be hidden.
fn forward_component(
    mapped: Option<u32>,
    raw: u32,
    squash: u32,
    policy: UnmappedPolicy,
) -> Option<u32> {
    match (mapped, policy) {
        (Some(id), _) => Some(id),
        (None, UnmappedPolicy::Squash) => Some(squash),
        (None, UnmappedPolicy::Passthrough) => Some(raw),
        (None, UnmappedPolicy::Hide) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server runs as this identity in every test below.
    const SERVER: ServerIdentity = ServerIdentity {
        uid: 1000,
        gid: 100,
    };

    fn id_map(mappings: [(u32, u32); 1]) -> IdMap {
        IdMap::new(mappings.map(|(host, guest)| IdMapping::new(host, guest))).expect("injective")
    }

    /// The common single-user map: the server's own ids present as guest root.
    fn single_user(unmapped: UnmappedPolicy) -> Ownership {
        Ownership::new(
            OwnershipMode::Map {
                uid: id_map([(SERVER.uid, 0)]),
                gid: id_map([(SERVER.gid, 0)]),
                unmapped,
            },
            SERVER,
            SquashIds::default(),
        )
        .expect("valid ownership")
    }

    fn passthrough() -> Ownership {
        Ownership::new(OwnershipMode::Passthrough, SERVER, SquashIds::default())
            .expect("valid ownership")
    }

    fn statically(uid: u32, gid: u32) -> Ownership {
        Ownership::new(
            OwnershipMode::Static { uid, gid },
            SERVER,
            SquashIds::default(),
        )
        .expect("valid ownership")
    }

    #[test]
    fn id_tables_must_be_injective_in_both_directions() {
        let duplicate_host =
            IdMap::new([IdMapping::new(1000, 0), IdMapping::new(1000, 1)]).expect_err("ambiguous");
        assert_eq!(duplicate_host, IdMapError::DuplicateHostId { id: 1000 });

        let duplicate_guest =
            IdMap::new([IdMapping::new(1000, 0), IdMapping::new(1001, 0)]).expect_err("ambiguous");
        assert_eq!(duplicate_guest, IdMapError::DuplicateGuestId { id: 0 });

        let repeated =
            IdMap::new([IdMapping::new(1000, 0), IdMapping::new(1000, 0)]).expect_err("ambiguous");
        assert_eq!(repeated, IdMapError::DuplicateHostId { id: 1000 });

        let injective =
            IdMap::new([IdMapping::new(1000, 0), IdMapping::new(1001, 1)]).expect("injective");
        assert_eq!(injective.forward(1000), Some(0));
        assert_eq!(injective.reverse(1), Some(1001));
        assert_eq!(injective.forward(7), None);
        assert_eq!(injective.reverse(7), None);
        assert_eq!(
            IdMap::default(),
            IdMap::new([]).expect("an empty table is injective")
        );
    }

    #[test]
    fn map_mode_translates_both_directions() {
        let ownership = single_user(UnmappedPolicy::Squash);
        assert_eq!(
            ownership.forward(HostIds::new(SERVER.uid, SERVER.gid)),
            OwnerPresentation::Visible(GuestIds::new(0, 0))
        );
        assert_eq!(
            ownership.reverse_for_create(GuestIds::new(0, 0)),
            HostIds::new(SERVER.uid, SERVER.gid)
        );
        assert_eq!(ownership.reverse_uid_for_chown(0), Ok(SERVER.uid));
        assert_eq!(ownership.reverse_gid_for_chown(0), Ok(SERVER.gid));
    }

    #[test]
    fn unmapped_squash_replaces_only_the_unmapped_component() {
        let ownership = single_user(UnmappedPolicy::Squash);
        assert_eq!(
            ownership.forward(HostIds::new(4242, SERVER.gid)),
            OwnerPresentation::Visible(GuestIds::new(DEFAULT_SQUASH_ID, 0))
        );
        assert_eq!(
            ownership.forward(HostIds::new(SERVER.uid, 4242)),
            OwnerPresentation::Visible(GuestIds::new(0, DEFAULT_SQUASH_ID))
        );
        assert_eq!(
            ownership.forward(HostIds::new(4242, 4242)),
            OwnerPresentation::Visible(GuestIds::new(DEFAULT_SQUASH_ID, DEFAULT_SQUASH_ID))
        );
    }

    #[test]
    fn mapped_guest_ids_must_not_equal_their_squash_ids() {
        let uid_collision = Ownership::new(
            OwnershipMode::Map {
                uid: id_map([(SERVER.uid, 7)]),
                gid: id_map([(SERVER.gid, 0)]),
                unmapped: UnmappedPolicy::Squash,
            },
            SERVER,
            SquashIds::new(7, 8),
        )
        .expect_err("mapped and squashed uids must be distinguishable");
        assert_eq!(
            uid_collision,
            OwnershipError::GuestUidEqualsSquash { id: 7 }
        );

        let gid_collision = Ownership::new(
            OwnershipMode::Map {
                uid: id_map([(SERVER.uid, 0)]),
                gid: id_map([(SERVER.gid, 8)]),
                unmapped: UnmappedPolicy::Squash,
            },
            SERVER,
            SquashIds::new(7, 8),
        )
        .expect_err("mapped and squashed gids must be distinguishable");
        assert_eq!(
            gid_collision,
            OwnershipError::GuestGidEqualsSquash { id: 8 }
        );
    }

    #[test]
    fn the_squash_target_is_numeric_and_configurable() {
        assert_eq!(
            SquashIds::default(),
            SquashIds::new(DEFAULT_SQUASH_ID, DEFAULT_SQUASH_ID)
        );
        let ownership = Ownership::new(
            OwnershipMode::Map {
                uid: id_map([(SERVER.uid, 0)]),
                gid: id_map([(SERVER.gid, 0)]),
                unmapped: UnmappedPolicy::Squash,
            },
            SERVER,
            SquashIds::new(7, 8),
        )
        .expect("mapped ids do not collide with squash ids");
        assert_eq!(ownership.squash(), SquashIds::new(7, 8));
        assert_eq!(
            ownership.forward(HostIds::new(4242, 4243)),
            OwnerPresentation::Visible(GuestIds::new(7, 8))
        );
    }

    #[test]
    fn unmapped_hide_triggers_on_either_component() {
        let ownership = single_user(UnmappedPolicy::Hide);
        assert_eq!(
            ownership.forward(HostIds::new(4242, SERVER.gid)),
            OwnerPresentation::Hidden
        );
        assert_eq!(
            ownership.forward(HostIds::new(SERVER.uid, 4242)),
            OwnerPresentation::Hidden
        );
        assert_eq!(
            ownership.forward(HostIds::new(4242, 4242)),
            OwnerPresentation::Hidden
        );
        assert_eq!(
            ownership.forward(HostIds::new(SERVER.uid, SERVER.gid)),
            OwnerPresentation::Visible(GuestIds::new(0, 0))
        );
    }

    #[test]
    fn unmapped_passthrough_presents_the_raw_component() {
        let ownership = single_user(UnmappedPolicy::Passthrough);
        assert_eq!(
            ownership.forward(HostIds::new(4242, SERVER.gid)),
            OwnerPresentation::Visible(GuestIds::new(4242, 0))
        );
    }

    #[test]
    fn reverse_unmapped_create_fallback_is_per_component() {
        let ownership = Ownership::new(
            OwnershipMode::Map {
                uid: id_map([(2000, 0)]),
                gid: id_map([(200, 0)]),
                unmapped: UnmappedPolicy::Squash,
            },
            SERVER,
            SquashIds::default(),
        )
        .expect("valid ownership");
        // The mapped uid survives even though the gid falls back, and vice
        // versa: fallback is not applied to the whole identity.
        assert_eq!(
            ownership.reverse_for_create(GuestIds::new(0, 4242)),
            HostIds::new(2000, SERVER.gid)
        );
        assert_eq!(
            ownership.reverse_for_create(GuestIds::new(4242, 0)),
            HostIds::new(SERVER.uid, 200)
        );
        // An explicit chown is denied instead of silently applying another id.
        assert_eq!(
            ownership.reverse_uid_for_chown(4242),
            Err(ChownDenied::Unmapped { guest_id: 4242 })
        );
        assert_eq!(
            ownership.reverse_gid_for_chown(4242),
            Err(ChownDenied::Unmapped { guest_id: 4242 })
        );
    }

    #[test]
    fn passthrough_mode_is_the_identity_in_both_directions() {
        let ownership = passthrough();
        assert_eq!(
            ownership.forward(HostIds::new(4242, 4243)),
            OwnerPresentation::Visible(GuestIds::new(4242, 4243))
        );
        assert_eq!(
            ownership.reverse_for_create(GuestIds::new(4242, 4243)),
            HostIds::new(4242, 4243)
        );
        assert_eq!(ownership.reverse_uid_for_chown(4242), Ok(4242));
        assert_eq!(ownership.reverse_gid_for_chown(4243), Ok(4243));
    }

    #[test]
    fn static_mode_presents_one_owner_and_has_no_reverse() {
        let ownership = statically(0, 0);
        assert_eq!(
            ownership.forward(HostIds::new(4242, 4243)),
            OwnerPresentation::Visible(GuestIds::new(0, 0))
        );
        // Creates land as the server identity, whatever the guest asked for.
        assert_eq!(
            ownership.reverse_for_create(GuestIds::new(0, 0)),
            HostIds::new(SERVER.uid, SERVER.gid)
        );
        assert_eq!(
            ownership.reverse_for_create(GuestIds::new(4242, 4243)),
            HostIds::new(SERVER.uid, SERVER.gid)
        );
        assert_eq!(
            ownership.reverse_uid_for_chown(0),
            Err(ChownDenied::StaticOwnership)
        );
        assert_eq!(
            ownership.reverse_gid_for_chown(0),
            Err(ChownDenied::StaticOwnership)
        );
    }

    #[test]
    fn the_environment_is_injected_not_discovered() {
        let ownership = single_user(UnmappedPolicy::Hide);
        assert_eq!(ownership.identity(), SERVER);
        assert_eq!(
            ownership.identity().as_host_ids(),
            HostIds::new(SERVER.uid, SERVER.gid)
        );
        assert_eq!(ownership.squash(), SquashIds::default());
        assert!(matches!(ownership.mode(), OwnershipMode::Map { .. }));
        assert_eq!(ServerIdentity::new(1, 2), ServerIdentity { uid: 1, gid: 2 });
        assert_eq!(
            IdMapping::new(1, 2),
            IdMapping {
                host_id: 1,
                guest_id: 2
            }
        );
    }

    #[test]
    fn mapping_is_a_pure_function_of_its_inputs() {
        let ownership = single_user(UnmappedPolicy::Squash);
        let host = HostIds::new(SERVER.uid, 4242);
        assert_eq!(ownership.forward(host), ownership.forward(host));
        assert_eq!(
            ownership.reverse_for_create(GuestIds::new(0, 0)),
            ownership.reverse_for_create(GuestIds::new(0, 0))
        );
    }
}
