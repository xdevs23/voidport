//! A host id is translated to a guest id through explicit tables (map), shown
//! as it is (passthrough), or presented as one configured id (static). The uid
//! and gid tables are separate, and each must be injective in both directions.
//! `unmapped: hide` hides a file when either its uid or its gid is unmapped,
//! `squash` replaces only the unmapped component, and `passthrough` passes it
//! through.
//!
//! For a guest id with no reverse mapping, and for static in every case, a
//! created file gets the ids of the server identity, while an explicit chown is
//! denied ([`ChownDenied`]). Applying a reverse-mapped host id other than the
//! server identity requires `CAP_CHOWN`: this module computes the intended host
//! ids only.
//!
//! The module is pure: the server identity and the squash ids are injected.

use std::collections::BTreeMap;

/// Used numerically, never resolved through NSS.
pub const DEFAULT_SQUASH_ID: u32 = 65534;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostIds {
    pub uid: u32,
    pub gid: u32,
}

impl HostIds {
    #[must_use]
    pub fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuestIds {
    pub uid: u32,
    pub gid: u32,
}

impl GuestIds {
    #[must_use]
    pub fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

/// The fallback identity for guest-created files whose guest ids have no reverse
/// mapping, and the identity presented by synthesized directories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerIdentity {
    pub uid: u32,
    pub gid: u32,
}

impl ServerIdentity {
    #[must_use]
    pub fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }

    #[must_use]
    pub fn as_host_ids(self) -> HostIds {
        HostIds::new(self.uid, self.gid)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SquashIds {
    pub uid: u32,
    pub gid: u32,
}

impl SquashIds {
    #[must_use]
    pub fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

impl Default for SquashIds {
    fn default() -> Self {
        Self::new(DEFAULT_SQUASH_ID, DEFAULT_SQUASH_ID)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdMapping {
    /// The id on the host. Configuration may write the enum value `uid`; that
    /// resolves to a number at state load, before it reaches this engine.
    pub host_id: u32,
    pub guest_id: u32,
}

impl IdMapping {
    #[must_use]
    pub fn new(host_id: u32, guest_id: u32) -> Self {
        Self { host_id, guest_id }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdMap {
    forward: BTreeMap<u32, u32>,
    reverse: BTreeMap<u32, u32>,
}

impl IdMap {
    /// # Errors
    ///
    /// Returns [`IdMapError`] if the mappings are not injective in both directions.
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

    #[must_use]
    pub fn forward(&self, host_id: u32) -> Option<u32> {
        self.forward.get(&host_id).copied()
    }

    #[must_use]
    pub fn reverse(&self, guest_id: u32) -> Option<u32> {
        self.reverse.get(&guest_id).copied()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdMapError {
    #[error("host id {id} is mapped twice")]
    DuplicateHostId { id: u32 },
    #[error("guest id {id} is mapped twice")]
    DuplicateGuestId { id: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmappedPolicy {
    /// Only the unmapped component is replaced.
    Squash,
    /// Triggered by either component being unmapped.
    Hide,
    Passthrough,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnershipMode {
    Map {
        uid: IdMap,
        gid: IdMap,
        unmapped: UnmappedPolicy,
    },
    Passthrough,
    Static {
        uid: u32,
        gid: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ownership {
    mode: OwnershipMode,
    identity: ServerIdentity,
    squash: SquashIds,
}

impl Ownership {
    /// # Errors
    ///
    /// Returns [`OwnershipError`] if a mapped guest uid or gid equals the squash id
    /// of that component.
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

    #[must_use]
    pub fn mode(&self) -> &OwnershipMode {
        &self.mode
    }

    #[must_use]
    pub fn identity(&self) -> ServerIdentity {
        self.identity
    }

    #[must_use]
    pub fn squash(&self) -> SquashIds {
        self.squash
    }

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
                    _ => OwnerPresentation::Hidden,
                }
            }
        }
    }

    /// Never fails: where no reverse mapping exists, and always under static
    /// ownership, the file gets the ids of the server identity.
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

    /// # Errors
    ///
    /// Returns [`ChownDenied`] under static ownership and for a guest id the
    /// table does not map back. The server returns `EPERM`, because applying a
    /// different id would lie to the guest.
    pub fn reverse_uid_for_chown(&self, guest_uid: u32) -> Result<u32, ChownDenied> {
        match &self.mode {
            OwnershipMode::Passthrough => Ok(guest_uid),
            OwnershipMode::Static { .. } => Err(ChownDenied::StaticOwnership),
            OwnershipMode::Map { uid, .. } => uid.reverse(guest_uid).ok_or(ChownDenied::Unmapped {
                guest_id: guest_uid,
            }),
        }
    }

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OwnershipError {
    #[error("guest uid {id} is also the squash uid")]
    GuestUidEqualsSquash { id: u32 },
    #[error("guest gid {id} is also the squash gid")]
    GuestGidEqualsSquash { id: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerPresentation {
    Visible(GuestIds),
    Hidden,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChownDenied {
    #[error("guest id {guest_id} has no host id to map back to")]
    Unmapped { guest_id: u32 },
    #[error("static ownership cannot express a reverse mapping")]
    StaticOwnership,
}

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

    const SERVER: ServerIdentity = ServerIdentity {
        uid: 1000,
        gid: 100,
    };

    fn id_map(mappings: [(u32, u32); 1]) -> IdMap {
        IdMap::new(mappings.map(|(host, guest)| IdMapping::new(host, guest))).expect("injective")
    }

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
        // Fallback applies per component, not to the whole identity.
        assert_eq!(
            ownership.reverse_for_create(GuestIds::new(0, 4242)),
            HostIds::new(2000, SERVER.gid)
        );
        assert_eq!(
            ownership.reverse_for_create(GuestIds::new(4242, 0)),
            HostIds::new(SERVER.uid, 200)
        );
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
