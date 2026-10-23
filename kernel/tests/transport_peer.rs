// SPDX-License-Identifier: GPL-2.0

use std::io::Read;
use std::process::Command;

use voidport_proto::attr::Attr;
use voidport_proto::frame::{FRAME_HEADER_LEN, Frame, FrameWriter, Parsed};
use voidport_proto::limits::Limits;
use voidport_proto::message::ResponseBody;
use voidport_proto::ops::file::ReadResponse;
use voidport_proto::ops::handshake::HelloReply;
use voidport_proto::piece::{self, Closing};
use zerocopy::FromZeros;
use zerocopy::byteorder::little_endian::{U32, U64};

pub(crate) const LIMITS: Limits = Limits {
    name_max: 255,
    path_max: 4096,
    xattr_name_max: 255,
    xattr_size_max: 65536,
    xattr_list_max: 65536,
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn load_module() -> Result {
    let status = Command::new("/bin/insmod").arg("/voidport.ko").status()?;
    if status.success() {
        Ok(())
    } else {
        Err("the module refused to load".into())
    }
}

fn unload_module() -> Result {
    if Command::new("/bin/rmmod")
        .arg("voidport")
        .status()?
        .success()
    {
        Ok(())
    } else {
        Err("the module refused to unload".into())
    }
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut bytes = vec![0; FRAME_HEADER_LEN];
    stream.read_exact(&mut bytes)?;
    loop {
        match Frame::parse_prefix(&bytes, &LIMITS)? {
            Parsed::Frame(_) => return Ok(bytes),
            Parsed::Need(needed) => {
                let have = bytes.len();
                bytes.resize(needed, 0);
                stream.read_exact(&mut bytes[have..])?;
            }
        }
    }
}

fn response<R: ResponseBody>(id: u64, body: &R, payload: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = vec![0; 4096];
    let mut frame = FrameWriter::response(&mut bytes, &LIMITS, id, body)?;
    frame.payload(payload)?;
    Ok(frame.finish()?.to_vec())
}

fn piece_of(bytes: &[u8]) -> Vec<u8> {
    let mut out = piece::length(bytes.len()).expect("a piece length").to_vec();
    out.extend_from_slice(bytes);
    out
}

fn read_reply(id: u64, parts: &[&[u8]], status: i32, exhausted: bool) -> Result<Vec<u8>> {
    let mut bytes = response(id, &ReadResponse, &[])?;
    for part in parts {
        bytes.extend(piece_of(part));
    }
    bytes.extend_from_slice(&Closing { status, exhausted }.encode());
    Ok(bytes)
}

fn accepting_reply(
    id: u64,
    protocol_version: u32,
    connection_id: u64,
    token: &[u8],
) -> Result<Vec<u8>> {
    response(
        id,
        &HelloReply {
            root_node_id: U64::new(1),
            protocol_version: U32::new(protocol_version),
            flags: U32::ZERO,
            connection_id: U64::new(connection_id),
            token_len: U32::new(u32::try_from(token.len())?),
            reserved: U32::ZERO,
        },
        token,
    )
}

fn hello_reply(id: u64, protocol_version: u32) -> Result<Vec<u8>> {
    accepting_reply(id, protocol_version, 1, b"unjoined")
}

fn eof(stream: &mut (impl Read + ?Sized)) -> Result {
    let mut byte = [0];
    assert_eq!(stream.read(&mut byte)?, 0, "unexpected request bytes");
    Ok(())
}

fn attr(id: u64, size: u64) -> Attr {
    let mut attr = Attr::new_zeroed();
    attr.ino = U64::new(id);
    attr.size = U64::new(size);
    attr.mode = U32::new(libc::S_IFREG | 0o444);
    attr.nlink = U32::new(1);
    attr.blksize = U32::new(4096);
    attr
}

mod supervision;
mod vfs_peer;

use vfs_peer::{Cleanup, JoinCase, SettleCase, SignalCase, SignalOperation, StoppedPeerCase};

enum Mode {
    AllocationFaults,
    Concurrency,
    Transitions,
    StallExpiry,
    Flaps,
    SharedNode,
    ConnectionThreads,
    ConnectionsParallel,
    Settle(SettleCase),
    Join(JoinCase),
    CleanupSendFailure(vfs_peer::Cleanup),
    Signal(vfs_peer::SignalCase),
    SignalAnswered,
    StoppedPeer(StoppedPeerCase),
    Diagnostics,
    AddressFamily,
    Lifecycle,
    Retry,
    NegativeLifetime,
    Vfs,
    Unix,
    UnixChroot,
    Netns,
    NetnsReference,
    PeerFailure,
    DecoyFailure,
    UnmountWait,
    Writes,
    Direct,
    DirectMount,
    MappedWrites,
    Setattr,
    OrphanedCreate,
    RecordLocks,
}

impl std::str::FromStr for Mode {
    type Err = String;

    fn from_str(argument: &str) -> std::result::Result<Self, String> {
        Ok(match argument {
            "--allocation-faults" => Self::AllocationFaults,
            "--concurrency" => Self::Concurrency,
            "--transitions" => Self::Transitions,
            "--stall-expiry" => Self::StallExpiry,
            "--flaps" => Self::Flaps,
            "--sessions-share-node" => Self::SharedNode,
            "--connection-threads" => Self::ConnectionThreads,
            "--connections-parallel" => Self::ConnectionsParallel,
            "--settle-not-started" => Self::Settle(SettleCase::NotStarted),
            "--settle-applied-forget" => Self::Settle(SettleCase::AppliedForget),
            "--settle-departed-lookup" => Self::Settle(SettleCase::DepartedLookup),
            "--settle-signalled-outcome" => Self::Settle(SettleCase::SignalledOutcome),
            "--settle-signalled-mkdir" => Self::Settle(SettleCase::SignalledMkdir),
            "--join-silent" => Self::Join(JoinCase::Silent),
            "--join-teardown" => Self::Join(JoinCase::Teardown),
            "--join-refused" => Self::Join(JoinCase::Refused),
            "--ownership-cleanup-forget" => Self::CleanupSendFailure(Cleanup::Forget),
            "--ownership-cleanup-release" => Self::CleanupSendFailure(Cleanup::Release),
            "--signal-queued" => Self::Signal(SignalCase::Queued),
            "--signal-transmitted" => Self::Signal(SignalCase::Transmitted),
            "--signal-answered" => Self::SignalAnswered,
            "--ownership-signal-node" => Self::Signal(SignalCase::Killed(SignalOperation::Node)),
            "--ownership-signal-open" => Self::Signal(SignalCase::Killed(SignalOperation::Open)),
            "--ownership-signal-dir" => {
                Self::Signal(SignalCase::Killed(SignalOperation::Directory))
            }
            "--signal-partial" => Self::StoppedPeer(StoppedPeerCase::SignalPartial),
            "--kill-partial" => Self::StoppedPeer(StoppedPeerCase::KillPartial),
            "--frame-in-parts" => Self::StoppedPeer(StoppedPeerCase::FrameInParts),
            "--close-frame" => Self::StoppedPeer(StoppedPeerCase::CloseFrame),
            "--diagnostics" => Self::Diagnostics,
            "--address-family" => Self::AddressFamily,
            "--lifecycle" => Self::Lifecycle,
            "--retry" => Self::Retry,
            "--negative-lifetime" => Self::NegativeLifetime,
            "--vfs" => Self::Vfs,
            "--unix" => Self::Unix,
            "--unix-chroot" => Self::UnixChroot,
            "--netns" => Self::Netns,
            "--netns-reference" => Self::NetnsReference,
            "--peer-failure" => Self::PeerFailure,
            "--decoy-failure" => Self::DecoyFailure,
            "--unmount-wait" => Self::UnmountWait,
            "--write" => Self::Writes,
            "--direct" => Self::Direct,
            "--direct-mount" => Self::DirectMount,
            "--mapped-writes" => Self::MappedWrites,
            "--setattr" => Self::Setattr,
            "--namespace" => Self::OrphanedCreate,
            "--record-locks" => Self::RecordLocks,
            _ => return Err(format!("unknown argument {argument}")),
        })
    }
}

fn main() -> Result {
    let argument = std::env::args().nth(1).ok_or("a case to run")?;
    match argument.parse::<Mode>()? {
        Mode::AllocationFaults => vfs_peer::allocation_faults(),
        Mode::Concurrency => vfs_peer::concurrency(),
        Mode::Transitions => vfs_peer::transitions(),
        Mode::StallExpiry => vfs_peer::stall_expiry(),
        Mode::Flaps => vfs_peer::flaps(),
        Mode::SharedNode => vfs_peer::shared_node(),
        Mode::ConnectionThreads => vfs_peer::connection_threads(),
        Mode::ConnectionsParallel => vfs_peer::connections_parallel(),
        Mode::Settle(case) => vfs_peer::settle(case),
        Mode::Join(case) => vfs_peer::joins(case),
        Mode::CleanupSendFailure(cleanup) => vfs_peer::cleanup_send_failure(cleanup),
        Mode::Signal(case) => vfs_peer::signals(case),
        Mode::SignalAnswered => vfs_peer::signal_answered(),
        Mode::StoppedPeer(case) => vfs_peer::stopped_peer(case),
        Mode::Diagnostics => vfs_peer::diagnostics(),
        Mode::AddressFamily => vfs_peer::address_family(),
        Mode::Lifecycle => vfs_peer::lifecycle(),
        Mode::Retry => vfs_peer::retry(),
        Mode::NegativeLifetime => vfs_peer::negative_lifetime(),
        Mode::Vfs => vfs_peer::run(),
        Mode::Unix => vfs_peer::unix(),
        Mode::UnixChroot => vfs_peer::unix_chroot(),
        Mode::Netns => vfs_peer::netns(),
        Mode::NetnsReference => vfs_peer::netns_reference(),
        Mode::PeerFailure => vfs_peer::peer_failure(),
        Mode::DecoyFailure => supervision::decoy_failure(),
        Mode::UnmountWait => vfs_peer::unmount_wait(),
        Mode::Writes => vfs_peer::writes(),
        Mode::Direct => vfs_peer::direct(),
        Mode::DirectMount => vfs_peer::direct_mount(),
        Mode::MappedWrites => vfs_peer::mapped_writes(),
        Mode::Setattr => vfs_peer::setattr(),
        Mode::OrphanedCreate => vfs_peer::orphaned_create(),
        Mode::RecordLocks => vfs_peer::record_locks(),
    }
}
