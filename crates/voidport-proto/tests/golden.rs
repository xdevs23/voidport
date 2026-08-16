//! Golden byte vectors: the ABI lock.
//!
//! Every wire struct and every message type is encoded, compared against a
//! literal byte vector, decoded back and compared for equality. A layout,
//! ordering or endianness change cannot land without breaking these vectors —
//! which per the wire contract requires a `PROTOCOL_VERSION` bump.
//!
//! Golden values follow one rule: the k-th distinct value in a struct is the
//! integer whose little-endian bytes are `k*0x10+1, k*0x10+2, ...`. Every
//! field of a struct therefore has its own byte signature, so a swapped pair
//! of fields shows up immediately.

use core::fmt::Debug;

use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::attr::{Attr, EntryOut, Timespec, file_type};
use voidport_proto::frame::{
    FLAG_RESPONSE, Frame, FrameHeader, FrameKind, FrameWriter, MAX_HELLO_FRAME_LEN,
};
use voidport_proto::message::{
    NotificationBody, RequestHead, ResponseHead, ResponseOutcome, WireMessage, WireStruct,
};
use voidport_proto::opcode::{NotificationOpcode, Opcode, notifications, values};
use voidport_proto::ops::dir::{
    DirEntryHeader, DirEntryWriter, LinkRequest, LinkResponse, MkdirRequest, MkdirResponse,
    MknodRequest, MknodResponse, ReaddirplusRequest, ReaddirplusResponse, RenameRequest,
    RenameResponse, RmdirRequest, RmdirResponse, SymlinkRequest, SymlinkResponse, UnlinkRequest,
    UnlinkResponse,
};
use voidport_proto::ops::file::{
    CreateRequest, CreateResponse, FileLock, FlushRequest, FlushResponse, FsyncRequest,
    FsyncResponse, GetlkRequest, GetlkResponse, OpenRequest, OpenResponse, ReadRequest,
    ReadResponse, ReleaseRequest, ReleaseResponse, SetlkRequest, SetlkResponse, WriteRequest,
    WriteResponse,
};
use voidport_proto::ops::handshake::{HelloReply, HelloRequest};
use voidport_proto::ops::node::{
    ForgetRequest, GetattrRequest, GetattrResponse, LookupRequest, LookupResponse, ReadlinkRequest,
    ReadlinkResponse, SetattrRequest, SetattrResponse, StatfsRequest, StatfsResponse,
};
use voidport_proto::ops::share::{
    SHARE_KIND_DIRECTORY, SHARE_KIND_FILE, SHARE_MODE_RO, SHARE_MODE_RW, ShareAdded, ShareChanged,
    ShareEnded, ShareEntryHeader, ShareEntryWriter, ShareRemoved, ShareSnapshotBegin,
    ShareSnapshotEnd, ShareSnapshotPart,
};
use voidport_proto::ops::subscribe::{
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, UnsubscribeResponse,
};
use voidport_proto::ops::xattr::{
    GetxattrRequest, GetxattrResponse, ListxattrRequest, ListxattrResponse, RemovexattrRequest,
    RemovexattrResponse, SetxattrRequest, SetxattrResponse, XattrNameHeader, XattrNameIter,
    XattrNameWriter, guest_list_size,
};
use zerocopy::byteorder::little_endian::{I32, I64, U16, U32, U64};

/// The k-th 64-bit golden value.
const V: [u64; 8] = [
    0x0807_0605_0403_0201,
    0x1817_1615_1413_1211,
    0x2827_2625_2423_2221,
    0x3837_3635_3433_3231,
    0x4847_4645_4443_4241,
    0x5857_5655_5453_5251,
    0x6867_6665_6463_6261,
    0x7877_7675_7473_7271,
];

/// Little-endian bytes of [`V`].
const VB: [[u8; 8]; 8] = [
    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
    [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28],
    [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38],
    [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48],
    [0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58],
    [0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68],
    [0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78],
];

/// The k-th 32-bit golden value.
const W: [u32; 10] = [
    0x0403_0201,
    0x1413_1211,
    0x2423_2221,
    0x3433_3231,
    0x4443_4241,
    0x5453_5251,
    0x6463_6261,
    0x7473_7271,
    0x8483_8281,
    0x9493_9291,
];

/// Little-endian bytes of [`W`].
const WB: [[u8; 4]; 10] = [
    [0x01, 0x02, 0x03, 0x04],
    [0x11, 0x12, 0x13, 0x14],
    [0x21, 0x22, 0x23, 0x24],
    [0x31, 0x32, 0x33, 0x34],
    [0x41, 0x42, 0x43, 0x44],
    [0x51, 0x52, 0x53, 0x54],
    [0x61, 0x62, 0x63, 0x64],
    [0x71, 0x72, 0x73, 0x74],
    [0x81, 0x82, 0x83, 0x84],
    [0x91, 0x92, 0x93, 0x94],
];

/// Concatenates literal byte pieces into an expected vector.
macro_rules! bytes {
    ($($piece:expr),* $(,)?) => {{
        let mut out: Vec<u8> = Vec::new();
        $(out.extend_from_slice(&$piece);)*
        out
    }};
}

/// Encode, compare against the golden bytes, decode, compare for equality.
#[track_caller]
fn golden<T: WireStruct + Debug + PartialEq>(value: &T, expected: &[u8]) {
    assert_eq!(
        size_of::<T>(),
        expected.len(),
        "{}: size does not match its golden vector",
        core::any::type_name::<T>()
    );
    assert_eq!(
        value.as_bytes(),
        expected,
        "{}: encoding drifted from its golden vector",
        core::any::type_name::<T>()
    );
    assert_eq!(
        &T::read_from_bytes(expected).expect("golden vector must decode"),
        value,
        "{}: decoding drifted from its golden vector",
        core::any::type_name::<T>()
    );
}

/// Encode, compare, decode, compare — and check the opcode assignment the
/// message type is bound to.
#[track_caller]
fn golden_message<T: WireMessage + Debug + PartialEq>(value: &T, opcode: u16, expected: &[u8]) {
    golden(value, expected);
    assert_eq!(
        T::OPCODE.as_u16(),
        opcode,
        "{}: opcode assignment drifted",
        core::any::type_name::<T>()
    );
}

/// The same, for a notification body, whose opcode comes from the other
/// registry.
#[track_caller]
fn golden_notification<T: NotificationBody + Debug + PartialEq>(
    value: &T,
    opcode: u16,
    expected: &[u8],
) {
    golden(value, expected);
    assert_eq!(
        T::OPCODE.as_u16(),
        opcode,
        "{}: notification opcode assignment drifted",
        core::any::type_name::<T>()
    );
}

fn golden_timespec(sec: usize, nsec: usize) -> Timespec {
    Timespec {
        sec: I64::new(V[sec] as i64),
        nsec: U32::new(W[nsec]),
    }
}

fn golden_attr() -> Attr {
    Attr {
        ino: U64::new(V[0]),
        size: U64::new(V[1]),
        blocks: U64::new(V[2]),
        atime: golden_timespec(3, 0),
        mtime: golden_timespec(4, 1),
        ctime: golden_timespec(5, 2),
        mode: U32::new(W[3]),
        nlink: U32::new(W[4]),
        uid: U32::new(W[5]),
        gid: U32::new(W[6]),
        rdev: U32::new(W[7]),
        blksize: U32::new(W[8]),
    }
}

fn golden_attr_bytes() -> Vec<u8> {
    bytes![
        VB[0], VB[1], VB[2], VB[3], WB[0], VB[4], WB[1], VB[5], WB[2], WB[3], WB[4], WB[5], WB[6],
        WB[7], WB[8],
    ]
}

fn golden_entry() -> EntryOut {
    EntryOut {
        node_id: U64::new(V[6]),
        generation: U64::new(V[7]),
        attr: golden_attr(),
    }
}

fn golden_entry_bytes() -> Vec<u8> {
    bytes![VB[6], VB[7], golden_attr_bytes()]
}

#[test]
fn components() {
    golden(
        &FrameHeader {
            len: U32::new(W[0]),
            opcode: U16::new(0x1211),
            flags: U16::new(0x2221),
            request_id: U64::new(V[3]),
        },
        &bytes![WB[0], [0x11, 0x12], [0x21, 0x22], VB[3]],
    );
    golden(
        &RequestHead {
            node_id: U64::new(V[0]),
            uid: U32::new(W[1]),
            gid: U32::new(W[2]),
            pid: U32::new(W[3]),
            reserved: U32::ZERO,
        },
        &bytes![VB[0], WB[1], WB[2], WB[3], [0, 0, 0, 0]],
    );
    golden(
        &ResponseHead {
            status: I32::new(-2),
        },
        &[0xFE, 0xFF, 0xFF, 0xFF],
    );
    golden(&golden_timespec(0, 1), &bytes![VB[0], WB[1]]);
    golden(&golden_attr(), &golden_attr_bytes());
    golden(&golden_entry(), &golden_entry_bytes());
    golden(
        &FileLock {
            start: U64::new(V[0]),
            end: U64::new(V[1]),
            owner: U64::new(V[2]),
            pid: U32::new(W[0]),
            lock_type: U32::new(W[1]),
        },
        &bytes![VB[0], VB[1], VB[2], WB[0], WB[1]],
    );
    golden(
        &DirEntryHeader::new(golden_entry(), V[0], W[0], W[1]),
        &bytes![golden_entry_bytes(), VB[0], WB[0], WB[1]],
    );
    golden(&XattrNameHeader::new(W[0]), &WB[0]);
}

#[test]
fn handshake_messages() {
    golden_message(
        &HelloRequest {
            protocol_version: U32::new(W[0]),
            flags: U32::new(W[1]),
            namespace_len: U32::new(W[2]),
            subpath_len: U32::new(W[3]),
            auth_len: U32::new(W[4]),
        },
        values::HELLO,
        &bytes![WB[0], WB[1], WB[2], WB[3], WB[4]],
    );
    golden_message(
        &HelloReply {
            root_node_id: U64::new(V[0]),
            protocol_version: U32::new(W[0]),
            flags: U32::new(W[1]),
            max_frame_len: U32::new(W[2]),
            reserved: U32::ZERO,
        },
        values::HELLO,
        &bytes![VB[0], WB[0], WB[1], WB[2], [0, 0, 0, 0]],
    );
}

#[test]
fn node_messages() {
    golden_message(
        &LookupRequest {
            name_len: U32::new(W[0]),
        },
        values::LOOKUP,
        &WB[0],
    );
    golden_message(
        &LookupResponse {
            entry: golden_entry(),
        },
        values::LOOKUP,
        &golden_entry_bytes(),
    );
    golden_message(
        &ForgetRequest {
            nlookup: U64::new(V[0]),
        },
        values::FORGET,
        &VB[0],
    );
    golden_message(
        &GetattrRequest {
            handle: U64::new(V[0]),
            flags: U32::new(W[0]),
            reserved: U32::ZERO,
        },
        values::GETATTR,
        &bytes![VB[0], WB[0], [0, 0, 0, 0]],
    );
    golden_message(
        &GetattrResponse {
            attr: golden_attr(),
        },
        values::GETATTR,
        &golden_attr_bytes(),
    );
    golden_message(
        &SetattrRequest {
            valid: U32::new(W[0]),
            reserved: U32::ZERO,
            handle: U64::new(V[0]),
            size: U64::new(V[1]),
            mode: U32::new(W[1]),
            uid: U32::new(W[2]),
            gid: U32::new(W[3]),
            reserved2: U32::ZERO,
            atime: golden_timespec(2, 4),
            mtime: golden_timespec(3, 5),
            ctime: golden_timespec(4, 6),
        },
        values::SETATTR,
        &bytes![
            WB[0],
            [0, 0, 0, 0],
            VB[0],
            VB[1],
            WB[1],
            WB[2],
            WB[3],
            [0, 0, 0, 0],
            VB[2],
            WB[4],
            VB[3],
            WB[5],
            VB[4],
            WB[6],
        ],
    );
    golden_message(
        &SetattrResponse {
            attr: golden_attr(),
        },
        values::SETATTR,
        &golden_attr_bytes(),
    );
    golden_message(&ReadlinkRequest, values::READLINK, &[]);
    golden_message(
        &ReadlinkResponse {
            target_len: U32::new(W[0]),
        },
        values::READLINK,
        &WB[0],
    );
    golden_message(&StatfsRequest, values::STATFS, &[]);
    golden_message(
        &StatfsResponse {
            blocks: U64::new(V[0]),
            bfree: U64::new(V[1]),
            bavail: U64::new(V[2]),
            files: U64::new(V[3]),
            ffree: U64::new(V[4]),
            bsize: U32::new(W[0]),
            namelen: U32::new(W[1]),
            frsize: U32::new(W[2]),
            reserved: U32::ZERO,
        },
        values::STATFS,
        &bytes![
            VB[0],
            VB[1],
            VB[2],
            VB[3],
            VB[4],
            WB[0],
            WB[1],
            WB[2],
            [0, 0, 0, 0],
        ],
    );
}

#[test]
fn directory_messages() {
    golden_message(
        &MkdirRequest {
            mode: U32::new(W[0]),
            umask: U32::new(W[1]),
            name_len: U32::new(W[2]),
            reserved: U32::ZERO,
        },
        values::MKDIR,
        &bytes![WB[0], WB[1], WB[2], [0, 0, 0, 0]],
    );
    golden_message(
        &MkdirResponse {
            entry: golden_entry(),
        },
        values::MKDIR,
        &golden_entry_bytes(),
    );
    golden_message(
        &MknodRequest {
            mode: U32::new(W[0]),
            umask: U32::new(W[1]),
            rdev: U32::new(W[2]),
            name_len: U32::new(W[3]),
        },
        values::MKNOD,
        &bytes![WB[0], WB[1], WB[2], WB[3]],
    );
    golden_message(
        &MknodResponse {
            entry: golden_entry(),
        },
        values::MKNOD,
        &golden_entry_bytes(),
    );
    golden_message(
        &UnlinkRequest {
            name_len: U32::new(W[0]),
        },
        values::UNLINK,
        &WB[0],
    );
    golden_message(&UnlinkResponse, values::UNLINK, &[]);
    golden_message(
        &RmdirRequest {
            name_len: U32::new(W[0]),
        },
        values::RMDIR,
        &WB[0],
    );
    golden_message(&RmdirResponse, values::RMDIR, &[]);
    golden_message(
        &RenameRequest {
            new_parent_node_id: U64::new(V[0]),
            flags: U32::new(W[0]),
            old_name_len: U32::new(W[1]),
            new_name_len: U32::new(W[2]),
            reserved: U32::ZERO,
        },
        values::RENAME,
        &bytes![VB[0], WB[0], WB[1], WB[2], [0, 0, 0, 0]],
    );
    golden_message(&RenameResponse, values::RENAME, &[]);
    golden_message(
        &LinkRequest {
            target_node_id: U64::new(V[0]),
            name_len: U32::new(W[0]),
            reserved: U32::ZERO,
        },
        values::LINK,
        &bytes![VB[0], WB[0], [0, 0, 0, 0]],
    );
    golden_message(
        &LinkResponse {
            entry: golden_entry(),
        },
        values::LINK,
        &golden_entry_bytes(),
    );
    golden_message(
        &SymlinkRequest {
            name_len: U32::new(W[0]),
            target_len: U32::new(W[1]),
        },
        values::SYMLINK,
        &bytes![WB[0], WB[1]],
    );
    golden_message(
        &SymlinkResponse {
            entry: golden_entry(),
        },
        values::SYMLINK,
        &golden_entry_bytes(),
    );
    golden_message(
        &ReaddirplusRequest {
            handle: U64::new(V[0]),
            cookie: U64::new(V[1]),
            size: U32::new(W[0]),
            reserved: U32::ZERO,
        },
        values::READDIRPLUS,
        &bytes![VB[0], VB[1], WB[0], [0, 0, 0, 0]],
    );
    golden_message(
        &ReaddirplusResponse {
            entries_len: U32::new(W[0]),
        },
        values::READDIRPLUS,
        &WB[0],
    );
}

#[test]
fn file_messages() {
    golden_message(
        &OpenRequest {
            flags: U32::new(W[0]),
            reserved: U32::ZERO,
        },
        values::OPEN,
        &bytes![WB[0], [0, 0, 0, 0]],
    );
    golden_message(
        &OpenResponse {
            handle: U64::new(V[0]),
            flags: U32::new(W[0]),
            reserved: U32::ZERO,
        },
        values::OPEN,
        &bytes![VB[0], WB[0], [0, 0, 0, 0]],
    );
    golden_message(
        &CreateRequest {
            flags: U32::new(W[0]),
            mode: U32::new(W[1]),
            umask: U32::new(W[2]),
            name_len: U32::new(W[3]),
        },
        values::CREATE,
        &bytes![WB[0], WB[1], WB[2], WB[3]],
    );
    golden_message(
        &CreateResponse {
            entry: golden_entry(),
            handle: U64::new(V[0]),
            flags: U32::new(W[0]),
            reserved: U32::ZERO,
        },
        values::CREATE,
        &bytes![golden_entry_bytes(), VB[0], WB[0], [0, 0, 0, 0]],
    );
    golden_message(
        &ReleaseRequest {
            handle: U64::new(V[0]),
            lock_owner: U64::new(V[1]),
            flags: U32::new(W[0]),
            release_flags: U32::new(W[1]),
        },
        values::RELEASE,
        &bytes![VB[0], VB[1], WB[0], WB[1]],
    );
    golden_message(&ReleaseResponse, values::RELEASE, &[]);
    golden_message(
        &ReadRequest {
            handle: U64::new(V[0]),
            offset: U64::new(V[1]),
            size: U32::new(W[0]),
            flags: U32::new(W[1]),
        },
        values::READ,
        &bytes![VB[0], VB[1], WB[0], WB[1]],
    );
    golden_message(
        &ReadResponse {
            data_len: U32::new(W[0]),
        },
        values::READ,
        &WB[0],
    );
    golden_message(
        &WriteRequest {
            handle: U64::new(V[0]),
            offset: U64::new(V[1]),
            data_len: U32::new(W[0]),
            flags: U32::new(W[1]),
            write_flags: U32::new(W[2]),
            reserved: U32::ZERO,
        },
        values::WRITE,
        &bytes![VB[0], VB[1], WB[0], WB[1], WB[2], [0, 0, 0, 0]],
    );
    golden_message(
        &WriteResponse {
            written: U32::new(W[0]),
        },
        values::WRITE,
        &WB[0],
    );
    golden_message(
        &FlushRequest {
            handle: U64::new(V[0]),
            lock_owner: U64::new(V[1]),
        },
        values::FLUSH,
        &bytes![VB[0], VB[1]],
    );
    golden_message(&FlushResponse, values::FLUSH, &[]);
    golden_message(
        &FsyncRequest {
            handle: U64::new(V[0]),
            flags: U32::new(W[0]),
            reserved: U32::ZERO,
        },
        values::FSYNC,
        &bytes![VB[0], WB[0], [0, 0, 0, 0]],
    );
    golden_message(&FsyncResponse, values::FSYNC, &[]);

    let lock = FileLock {
        start: U64::new(V[0]),
        end: U64::new(V[1]),
        owner: U64::new(V[2]),
        pid: U32::new(W[0]),
        lock_type: U32::new(W[1]),
    };
    let lock_bytes = bytes![VB[0], VB[1], VB[2], WB[0], WB[1]];
    golden_message(
        &GetlkRequest {
            handle: U64::new(V[3]),
            lock,
        },
        values::GETLK,
        &bytes![VB[3], lock_bytes],
    );
    golden_message(&GetlkResponse { lock }, values::GETLK, &lock_bytes);
    golden_message(
        &SetlkRequest {
            handle: U64::new(V[3]),
            lock,
            flags: U32::new(W[2]),
            reserved: U32::ZERO,
        },
        values::SETLK,
        &bytes![VB[3], lock_bytes, WB[2], [0, 0, 0, 0]],
    );
    golden_message(&SetlkResponse, values::SETLK, &[]);
}

#[test]
fn xattr_messages() {
    golden_message(
        &SetxattrRequest {
            flags: U32::new(W[0]),
            name_len: U32::new(W[1]),
            value_len: U32::new(W[2]),
            reserved: U32::ZERO,
        },
        values::SETXATTR,
        &bytes![WB[0], WB[1], WB[2], [0, 0, 0, 0]],
    );
    golden_message(&SetxattrResponse, values::SETXATTR, &[]);
    golden_message(
        &GetxattrRequest {
            size: U32::new(W[0]),
            name_len: U32::new(W[1]),
        },
        values::GETXATTR,
        &bytes![WB[0], WB[1]],
    );
    golden_message(
        &GetxattrResponse {
            size: U32::new(W[0]),
            value_len: U32::new(W[1]),
        },
        values::GETXATTR,
        &bytes![WB[0], WB[1]],
    );
    golden_message(
        &ListxattrRequest {
            size: U32::new(W[0]),
            reserved: U32::ZERO,
        },
        values::LISTXATTR,
        &bytes![WB[0], [0, 0, 0, 0]],
    );
    golden_message(
        &ListxattrResponse {
            size: U32::new(W[0]),
            list_len: U32::new(W[1]),
        },
        values::LISTXATTR,
        &bytes![WB[0], WB[1]],
    );
    golden_message(
        &RemovexattrRequest {
            name_len: U32::new(W[0]),
        },
        values::REMOVEXATTR,
        &WB[0],
    );
    golden_message(&RemovexattrResponse, values::REMOVEXATTR, &[]);
}

#[test]
fn subscription_messages() {
    golden_message(
        &SubscribeRequest {
            reserved: U32::ZERO,
        },
        values::SUBSCRIBE,
        &[0, 0, 0, 0],
    );
    golden_message(
        &SubscribeResponse {
            reserved: U32::ZERO,
        },
        values::SUBSCRIBE,
        &[0, 0, 0, 0],
    );
    golden_message(
        &UnsubscribeRequest {
            reserved: U32::ZERO,
        },
        values::UNSUBSCRIBE,
        &[0, 0, 0, 0],
    );
    golden_message(
        &UnsubscribeResponse {
            reserved: U32::ZERO,
        },
        values::UNSUBSCRIBE,
        &[0, 0, 0, 0],
    );
}

#[test]
fn share_notification_messages() {
    golden(
        &ShareEntryHeader::new(W[0] as u16, W[1] as u16, W[2]),
        &bytes![[0x01, 0x02], [0x11, 0x12], WB[2]],
    );
    golden_notification(
        &ShareSnapshotBegin {
            entries: U32::new(W[0]),
            reserved: U32::ZERO,
        },
        notifications::SHARE_SNAPSHOT_BEGIN,
        &bytes![WB[0], [0, 0, 0, 0]],
    );
    golden_notification(
        &ShareSnapshotPart {
            entries: U32::new(W[0]),
            entries_len: U32::new(W[1]),
        },
        notifications::SHARE_SNAPSHOT_PART,
        &bytes![WB[0], WB[1]],
    );
    golden_notification(
        &ShareSnapshotEnd {
            reserved: U32::ZERO,
        },
        notifications::SHARE_SNAPSHOT_END,
        &[0, 0, 0, 0],
    );
    golden_notification(
        &ShareAdded {
            mode: U16::new(W[0] as u16),
            kind: U16::new(W[1] as u16),
            path_len: U32::new(W[2]),
        },
        notifications::SHARE_ADDED,
        &bytes![[0x01, 0x02], [0x11, 0x12], WB[2]],
    );
    golden_notification(
        &ShareChanged {
            mode: U16::new(W[0] as u16),
            kind: U16::new(W[1] as u16),
            path_len: U32::new(W[2]),
        },
        notifications::SHARE_CHANGED,
        &bytes![[0x01, 0x02], [0x11, 0x12], WB[2]],
    );
    golden_notification(
        &ShareRemoved {
            path_len: U32::new(W[0]),
        },
        notifications::SHARE_REMOVED,
        &WB[0],
    );
    golden_notification(
        &ShareEnded {
            reason: U32::new(W[0]),
        },
        notifications::SHARE_ENDED,
        &WB[0],
    );
}

/// A whole snapshot part frame, pinned: the notification taxonomy on the wire.
///
/// It is the one frame shape nothing else in this file covers — no request
/// head, no response head, `request_id` 0 and the response flag clear — so the
/// bytes are asserted, not only round-tripped.
#[test]
fn share_snapshot_part_frame_is_pinned() {
    let mut stream = [0u8; 64];
    let mut entries = ShareEntryWriter::new(&mut stream);
    entries
        .push(
            &ShareEntryHeader::new(SHARE_MODE_RW, SHARE_KIND_DIRECTORY, 5),
            b"/docs",
        )
        .expect("the buffer holds one entry");
    entries
        .push(
            &ShareEntryHeader::new(SHARE_MODE_RO, SHARE_KIND_FILE, 9),
            b"/read.txt",
        )
        .expect("the buffer holds two");
    let stream = entries.finish();

    let body = ShareSnapshotPart {
        entries: U32::new(2),
        entries_len: U32::new(stream.len() as u32),
    };
    let mut buffer = [0u8; 128];
    let mut writer =
        FrameWriter::notification(&mut buffer, MAX_HELLO_FRAME_LEN, &body).expect("encodable");
    writer.payload(stream).expect("the declared payload");
    let frame_bytes = writer.finish().expect("complete").to_vec();

    let expected = bytes![
        // header: len, opcode, flags (RESPONSE clear), request_id 0
        (16u32 + 8 + stream.len() as u32).to_le_bytes(),
        notifications::SHARE_SNAPSHOT_PART.to_le_bytes(),
        0u16.to_le_bytes(),
        0u64.to_le_bytes(),
        // body
        2u32.to_le_bytes(),
        (stream.len() as u32).to_le_bytes(),
        // payload: two entries
        SHARE_MODE_RW.to_le_bytes(),
        SHARE_KIND_DIRECTORY.to_le_bytes(),
        5u32.to_le_bytes(),
        *b"/docs",
        SHARE_MODE_RO.to_le_bytes(),
        SHARE_KIND_FILE.to_le_bytes(),
        9u32.to_le_bytes(),
        *b"/read.txt",
    ];
    assert_eq!(frame_bytes, expected);

    let frame = Frame::parse(&frame_bytes, MAX_HELLO_FRAME_LEN).expect("a legal frame");
    assert_eq!(frame.kind(), FrameKind::Notification);
    assert_eq!(frame.request_id(), 0);
    assert_eq!(
        frame.notification_opcode(),
        Ok(NotificationOpcode::ShareSnapshotPart)
    );
    let part = frame
        .notification::<ShareSnapshotPart>()
        .expect("a snapshot part");
    let decoded: Vec<(u16, u16, Vec<u8>)> = part
        .entries()
        .map(|entry| {
            let entry = entry.expect("a well-formed entry");
            (
                entry.header.mode.get(),
                entry.header.kind.get(),
                entry.tail.to_vec(),
            )
        })
        .collect();
    assert_eq!(
        decoded,
        vec![
            (SHARE_MODE_RW, SHARE_KIND_DIRECTORY, b"/docs".to_vec()),
            (SHARE_MODE_RO, SHARE_KIND_FILE, b"/read.txt".to_vec()),
        ]
    );
}

/// A delta frame carries its path in the payload and nothing else.
#[test]
fn share_delta_frames_round_trip() {
    let path = b"/project/docs";
    let body = ShareAdded {
        mode: U16::new(SHARE_MODE_RO),
        kind: U16::new(SHARE_KIND_DIRECTORY),
        path_len: U32::new(path.len() as u32),
    };
    let mut buffer = [0u8; 64];
    let mut writer =
        FrameWriter::notification(&mut buffer, MAX_HELLO_FRAME_LEN, &body).expect("encodable");
    writer.payload(path).expect("the declared payload");
    let bytes = writer.finish().expect("complete").to_vec();

    let frame = Frame::parse(&bytes, MAX_HELLO_FRAME_LEN).expect("a legal frame");
    let event = frame.notification::<ShareAdded>().expect("an added event");
    assert_eq!(event.path(), path);
    assert_eq!(event.body().mode.get(), SHARE_MODE_RO);
    // A notification is not a response, whatever its body says.
    assert!(frame.response::<SubscribeResponse>().is_err());
    assert!(frame.notification::<ShareRemoved>().is_err());
}

#[test]
fn hello_frame_is_pinned() {
    let namespace = b"ns";
    let subpath = b"/proj";
    let body = HelloRequest {
        protocol_version: U32::new(PROTOCOL_VERSION),
        flags: U32::ZERO,
        namespace_len: U32::new(namespace.len() as u32),
        subpath_len: U32::new(subpath.len() as u32),
        auth_len: U32::ZERO,
    };

    let mut buf = [0u8; 128];
    let mut writer = FrameWriter::request(
        &mut buf,
        MAX_HELLO_FRAME_LEN,
        1,
        &RequestHead::default(),
        &body,
    )
    .unwrap();
    writer.payload(namespace).unwrap();
    writer.payload(subpath).unwrap();
    let frame_bytes = writer.finish().unwrap();

    let expected: Vec<u8> = bytes![
        // header: len = 67, opcode = HELLO, flags = 0, request_id = 1
        [67, 0, 0, 0],
        [0x01, 0x00],
        [0x00, 0x00],
        [1, 0, 0, 0, 0, 0, 0, 0],
        // request head: all zero, the handshake targets no node
        [0u8; 24],
        // body: version 1, flags 0, lengths 2 / 5 / 0
        [1, 0, 0, 0],
        [0, 0, 0, 0],
        [2, 0, 0, 0],
        [5, 0, 0, 0],
        [0, 0, 0, 0],
        // payload
        *namespace,
        *subpath,
    ];
    assert_eq!(frame_bytes, expected.as_slice());

    let frame = Frame::parse(&expected, MAX_HELLO_FRAME_LEN).unwrap();
    assert_eq!(frame.opcode(), Ok(Opcode::Hello));
    let request = frame.request::<HelloRequest>().unwrap();
    assert_eq!(request.body(), &body);
    assert_eq!(request.namespace(), namespace);
    assert_eq!(request.subpath(), subpath);
    assert_eq!(request.auth(), b"");
}

#[test]
fn hello_reply_frame_is_pinned() {
    let body = HelloReply {
        root_node_id: U64::new(1),
        protocol_version: U32::new(PROTOCOL_VERSION),
        flags: U32::ZERO,
        max_frame_len: U32::new(0x0010_0000),
        reserved: U32::ZERO,
    };

    let mut buf = [0u8; 128];
    let frame_bytes = FrameWriter::response(&mut buf, MAX_HELLO_FRAME_LEN, 1, &body)
        .unwrap()
        .finish()
        .unwrap();

    let expected: Vec<u8> = bytes![
        // header: len = 44, opcode = HELLO, flags = RESPONSE, request_id = 1
        [44, 0, 0, 0],
        [0x01, 0x00],
        [0x01, 0x00],
        [1, 0, 0, 0, 0, 0, 0, 0],
        // status 0
        [0, 0, 0, 0],
        // root node id 1, version 1, flags 0, max_frame_len 1 MiB, reserved 0
        [1, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0],
        [0, 0, 0, 0],
        [0x00, 0x00, 0x10, 0x00],
        [0, 0, 0, 0],
    ];
    assert_eq!(frame_bytes, expected.as_slice());

    let frame = Frame::parse(&expected, MAX_HELLO_FRAME_LEN).unwrap();
    let response = frame.response::<HelloReply>().unwrap().success().unwrap();
    assert_eq!(response.body(), &body);
}

#[test]
fn lookup_frames_are_pinned() {
    let name = b"project";
    let body = LookupRequest {
        name_len: U32::new(name.len() as u32),
    };

    let mut buf = [0u8; 128];
    let mut writer = FrameWriter::request(
        &mut buf,
        MAX_HELLO_FRAME_LEN,
        7,
        &RequestHead::new(1, 1000, 1000, 42),
        &body,
    )
    .unwrap();
    writer.payload(name).unwrap();
    let frame_bytes = writer.finish().unwrap();

    let expected: Vec<u8> = bytes![
        // header: len = 51, opcode = LOOKUP, flags = 0, request_id = 7
        [51, 0, 0, 0],
        [0x02, 0x00],
        [0x00, 0x00],
        [7, 0, 0, 0, 0, 0, 0, 0],
        // request head: node 1, uid 1000, gid 1000, pid 42, reserved 0
        [1, 0, 0, 0, 0, 0, 0, 0],
        [0xE8, 0x03, 0, 0],
        [0xE8, 0x03, 0, 0],
        [42, 0, 0, 0],
        [0, 0, 0, 0],
        // name_len 7 and the name
        [7, 0, 0, 0],
        *name,
    ];
    assert_eq!(frame_bytes, expected.as_slice());

    let frame = Frame::parse(&expected, MAX_HELLO_FRAME_LEN).unwrap();
    let request = frame.request::<LookupRequest>().unwrap();
    assert_eq!(request.head().uid.get(), 1000);
    assert_eq!(request.name(), name);
}

#[test]
fn error_response_frame_is_pinned() {
    let mut buf = [0u8; 32];
    let frame_bytes =
        FrameWriter::error_response(&mut buf, MAX_HELLO_FRAME_LEN, 7, Opcode::Lookup, -2).unwrap();

    let expected: Vec<u8> = bytes![
        // header: len = 20, opcode = LOOKUP, flags = RESPONSE, request_id = 7
        [20, 0, 0, 0],
        [0x02, 0x00],
        [0x01, 0x00],
        [7, 0, 0, 0, 0, 0, 0, 0],
        // status = -ENOENT, and nothing else
        [0xFE, 0xFF, 0xFF, 0xFF],
    ];
    assert_eq!(frame_bytes, expected.as_slice());

    let frame = Frame::parse(&expected, MAX_HELLO_FRAME_LEN).unwrap();
    assert_eq!(frame.header().flags.get(), FLAG_RESPONSE);
    assert_eq!(
        frame.response::<LookupResponse>().unwrap(),
        ResponseOutcome::Error(-2)
    );
}

#[test]
fn readdirplus_frame_round_trips() {
    let entry = golden_entry();
    let mut stream_buf = [0u8; 512];
    let mut stream = DirEntryWriter::new(&mut stream_buf);
    stream
        .push(&DirEntryHeader::new(entry, 1, file_type::DIR, 3), b"foo")
        .unwrap();
    stream
        .push(
            &DirEntryHeader::new(entry, 2, file_type::REG, 7),
            b"bar.txt",
        )
        .unwrap();
    let entries = stream.finish();

    let expected_entries: Vec<u8> = bytes![
        golden_entry_bytes(),
        [1, 0, 0, 0, 0, 0, 0, 0],
        [4, 0, 0, 0],
        [3, 0, 0, 0],
        *b"foo",
        golden_entry_bytes(),
        [2, 0, 0, 0, 0, 0, 0, 0],
        [8, 0, 0, 0],
        [7, 0, 0, 0],
        *b"bar.txt",
    ];
    assert_eq!(entries, expected_entries.as_slice());

    let body = ReaddirplusResponse {
        entries_len: U32::new(entries.len() as u32),
    };
    let mut buf = [0u8; 1024];
    let mut writer = FrameWriter::response(&mut buf, MAX_HELLO_FRAME_LEN, 9, &body).unwrap();
    writer.payload(entries).unwrap();
    let frame_bytes = writer.finish().unwrap();

    let frame = Frame::parse(frame_bytes, 4096).unwrap();
    let response = frame
        .response::<ReaddirplusResponse>()
        .unwrap()
        .success()
        .unwrap();
    let walked: Vec<(Vec<u8>, u64, u32)> = response
        .entries()
        .map(|item| {
            let item = item.unwrap();
            (
                item.tail.to_vec(),
                item.header.next_cookie.get(),
                item.header.entry_type.get(),
            )
        })
        .collect();
    assert_eq!(
        walked,
        vec![
            (b"foo".to_vec(), 1, file_type::DIR),
            (b"bar.txt".to_vec(), 2, file_type::REG),
        ]
    );
}

#[test]
fn listxattr_frame_round_trips() {
    let mut stream_buf = [0u8; 128];
    let mut stream = XattrNameWriter::new(&mut stream_buf);
    stream.push(&XattrNameHeader::new(8), b"user.foo").unwrap();
    stream
        .push(&XattrNameHeader::new(10), b"user.other")
        .unwrap();
    let list = stream.finish();

    let expected_list: Vec<u8> = bytes![[8, 0, 0, 0], *b"user.foo", [10, 0, 0, 0], *b"user.other",];
    assert_eq!(list, expected_list.as_slice());

    // `size` is the guest-visible NUL-separated list (8+1 + 10+1 = 20 bytes),
    // `list_len` the wire stream (4+8 + 4+10 = 26). They differ whenever the
    // list is nonempty, and a guest buffer of 20 bytes is sufficient.
    let size = guest_list_size(XattrNameIter::new(list)).unwrap();
    assert_eq!(size, 20);
    assert_eq!(list.len(), 26);

    let body = ListxattrResponse {
        size: U32::new(size),
        list_len: U32::new(list.len() as u32),
    };
    let mut buf = [0u8; 256];
    let mut writer = FrameWriter::response(&mut buf, MAX_HELLO_FRAME_LEN, 3, &body).unwrap();
    writer.payload(list).unwrap();
    let frame_bytes = writer.finish().unwrap();

    let frame = Frame::parse(frame_bytes, 4096).unwrap();
    let response = frame
        .response::<ListxattrResponse>()
        .unwrap()
        .success()
        .unwrap();
    assert_eq!(response.body().size.get(), 20);
    assert_eq!(response.body().list_len.get(), 26);
    assert_eq!(guest_list_size(response.names()), Ok(20));
    let names: Vec<Vec<u8>> = response
        .names()
        .map(|item| item.unwrap().tail.to_vec())
        .collect();
    assert_eq!(names, vec![b"user.foo".to_vec(), b"user.other".to_vec()]);
}

#[test]
fn multi_region_payloads_round_trip() {
    let old_name = b"before";
    let new_name = b"after";
    let body = RenameRequest {
        new_parent_node_id: U64::new(9),
        flags: U32::ZERO,
        old_name_len: U32::new(old_name.len() as u32),
        new_name_len: U32::new(new_name.len() as u32),
        reserved: U32::ZERO,
    };
    let mut buf = [0u8; 128];
    let mut writer = FrameWriter::request(
        &mut buf,
        MAX_HELLO_FRAME_LEN,
        4,
        &RequestHead::new(2, 0, 0, 0),
        &body,
    )
    .unwrap();
    writer.payload(old_name).unwrap();
    writer.payload(new_name).unwrap();
    let frame_bytes = writer.finish().unwrap();

    let frame = Frame::parse(frame_bytes, 4096).unwrap();
    let request = frame.request::<RenameRequest>().unwrap();
    assert_eq!(request.old_name(), old_name);
    assert_eq!(request.new_name(), new_name);

    let target = b"../elsewhere";
    let body = SymlinkRequest {
        name_len: U32::new(4),
        target_len: U32::new(target.len() as u32),
    };
    let mut writer = FrameWriter::request(
        &mut buf,
        MAX_HELLO_FRAME_LEN,
        5,
        &RequestHead::new(2, 0, 0, 0),
        &body,
    )
    .unwrap();
    writer.payload(b"link").unwrap();
    writer.payload(target).unwrap();
    let frame_bytes = writer.finish().unwrap();
    let frame = Frame::parse(frame_bytes, 4096).unwrap();
    let request = frame.request::<SymlinkRequest>().unwrap();
    assert_eq!(request.name(), b"link");
    assert_eq!(request.target(), target);

    let value = b"value-bytes";
    let body = SetxattrRequest {
        flags: U32::ZERO,
        name_len: U32::new(8),
        value_len: U32::new(value.len() as u32),
        reserved: U32::ZERO,
    };
    let mut writer = FrameWriter::request(
        &mut buf,
        MAX_HELLO_FRAME_LEN,
        6,
        &RequestHead::new(2, 0, 0, 0),
        &body,
    )
    .unwrap();
    writer.payload(b"user.foo").unwrap();
    writer.payload(value).unwrap();
    let frame_bytes = writer.finish().unwrap();
    let frame = Frame::parse(frame_bytes, 4096).unwrap();
    let request = frame.request::<SetxattrRequest>().unwrap();
    assert_eq!(request.name(), b"user.foo");
    assert_eq!(request.value(), value);
}

#[test]
fn payload_can_be_filled_in_place() {
    let body = ReadResponse {
        data_len: U32::new(4),
    };
    let mut buf = [0u8; 64];
    let mut writer = FrameWriter::response(&mut buf, MAX_HELLO_FRAME_LEN, 11, &body).unwrap();
    writer.payload_buf(4).unwrap().copy_from_slice(b"data");
    let frame_bytes = writer.finish().unwrap();

    let frame = Frame::parse(frame_bytes, 4096).unwrap();
    let response = frame.response::<ReadResponse>().unwrap().success().unwrap();
    assert_eq!(response.data(), b"data");
}
