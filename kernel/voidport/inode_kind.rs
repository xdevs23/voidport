// SPDX-License-Identifier: GPL-2.0

use voidport_proto::ops::dir::EntryType;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SupportedKind {
    Directory,
    Symlink,
    Regular,
    Fifo,
    Socket,
    CharDevice,
    BlockDevice,
}

impl SupportedKind {
    pub(crate) fn of_mode(mode: u32) -> Option<Self> {
        EntryType::of_mode(mode).and_then(Self::of_entry_type)
    }

    pub(crate) fn of_entry_type(entry_type: EntryType) -> Option<Self> {
        match entry_type {
            EntryType::Directory => Some(Self::Directory),
            EntryType::Symlink => Some(Self::Symlink),
            EntryType::Regular => Some(Self::Regular),
            EntryType::Fifo => Some(Self::Fifo),
            EntryType::Socket => Some(Self::Socket),
            EntryType::Character => Some(Self::CharDevice),
            EntryType::Block => Some(Self::BlockDevice),
            EntryType::Unknown => None,
        }
    }
}
