use voidport_proto::ops::dir::EntryType;

/// `S_ISUID | S_ISGID`.
pub const PRIVILEGED: u32 = 0o6000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct MaskedChmod {
    requested: u32,
}

impl MaskedChmod {
    /// The server takes the privileged bits of the received mode as their new
    /// value. The mount shows the file without them, so sending the bits `held`
    /// by the server leaves them as they are.
    #[must_use]
    pub fn mode(self, held: u32) -> u32 {
        self.requested | (held & PRIVILEGED)
    }
}

/// `None` when the mount rejects the chmod with `EPERM` before any request: a
/// mount that shows no privileged bits sets none either.
pub fn chmod_mode(requested: u32) -> Option<MaskedChmod> {
    (requested & PRIVILEGED == 0).then_some(MaskedChmod { requested })
}

/// `None` when the client rejects the mknod with `EPERM` before any request.
#[must_use]
pub fn mknod_kind(mode: u32) -> Option<EntryType> {
    EntryType::of_mode(mode).filter(|kind| matches!(kind, EntryType::Fifo | EntryType::Socket))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_masked_mount_refuses_a_chmod_that_sets_a_privileged_bit() {
        for privileged in [0o4755, 0o2755, 0o6755] {
            assert_eq!(chmod_mode(privileged), None, "{privileged:o}");
        }
    }

    #[test]
    fn a_masked_chmod_sends_the_privileged_bits_the_server_has() {
        let chmod = chmod_mode(0o755).expect("no privileged bit is requested");
        assert_eq!(chmod.mode(0o104_644), 0o4755);
        assert_eq!(chmod.mode(0o102_600), 0o2755);
        assert_eq!(chmod.mode(0o100_644), 0o755);
    }

    #[test]
    fn only_a_fifo_or_a_socket_is_created_by_mknod() {
        assert_eq!(mknod_kind(0o010_644), Some(EntryType::Fifo));
        assert_eq!(mknod_kind(0o140_644), Some(EntryType::Socket));
        for refused in [0o020_644, 0o060_644, 0o100_644, 0o040_755, 0o644] {
            assert_eq!(mknod_kind(refused), None, "{refused:o}");
        }
    }
}
