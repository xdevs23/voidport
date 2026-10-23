//! Golden values follow one rule: the k-th distinct value in a struct is the
//! integer whose little-endian bytes are `k*0x10+1, k*0x10+2, ...`. Every
//! field of a struct therefore has its own byte signature, so a swapped pair
//! of fields shows up immediately.

use core::fmt::Debug;
use voidport_proto::ops::dir::EntryType;

use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::attr::{Attr, EntryOut, Timespec, file_type};
use voidport_proto::frame::{FLAG_RESPONSE, Frame, FrameHeader, FrameKind, FrameWriter, Parsed};
use voidport_proto::limits::Limits;
use voidport_proto::message::{
    NotificationBody, RequestHead, ResponseHead, ResponseOutcome, WireMessage, WireStruct,
};
use voidport_proto::opcode::{NotificationOpcode, Opcode, notifications, values};
use voidport_proto::ops::connection::{
    CancelRequest, OutcomeRequest, OutcomeResponse, RetireRequest, RetireResponse, outcome_state,
};
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
use voidport_proto::ops::handshake::{HelloReply, HelloRequest, hello_flags};
use voidport_proto::ops::node::{
    ForgetRequest, GetattrRequest, GetattrResponse, LookupRequest, LookupResponse, ReadlinkRequest,
    ReadlinkResponse, SetattrRequest, SetattrResponse, StatfsRequest, StatfsResponse,
};
use voidport_proto::ops::recall::{
    Recall, RecalledRequest, RecalledResponse, RelinquishRequest, RelinquishResponse, RenewRequest,
    RenewResponse,
};
use voidport_proto::ops::share::{
    SHARE_KIND_DIRECTORY, SHARE_KIND_FILE, SHARE_MODE_RO, SHARE_MODE_RW, ShareAdded, ShareChanged,
    ShareEnded, ShareEntryHeader, ShareRemoved, ShareSnapshotBegin, ShareSnapshotEnd,
    ShareSnapshotPart,
};
use voidport_proto::ops::subscribe::{
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, UnsubscribeResponse,
};
use voidport_proto::ops::xattr::{
    GetxattrRequest, GetxattrResponse, ListxattrRequest, ListxattrResponse, RemovexattrRequest,
    RemovexattrResponse, SetxattrRequest, SetxattrResponse, XattrNameHeader, XattrNameIter,
    XattrNameWriter, guest_list_size,
};
use voidport_proto::piece::{self, Closing, ClosingBody, PIECE_LEN_LEN, Stream};
use zerocopy::IntoBytes as _;
use zerocopy::byteorder::little_endian::{I32, I64, U16, U32, U64};

const LIMITS: Limits = Limits {
    name_max: linux_raw_sys::general::NAME_MAX,
    path_max: linux_raw_sys::general::PATH_MAX,
    xattr_name_max: linux_raw_sys::general::XATTR_NAME_MAX,
    xattr_size_max: linux_raw_sys::general::XATTR_SIZE_MAX,
    xattr_list_max: linux_raw_sys::general::XATTR_LIST_MAX,
};

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

macro_rules! bytes {
    ($($piece:expr),* $(,)?) => {{
        let mut out: Vec<u8> = Vec::new();
        $(out.extend_from_slice(&$piece);)*
        out
    }};
}

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
            opcode: U16::new(0x1211),
            flags: U16::new(0x2221),
            request_id: U64::new(V[3]),
        },
        &bytes![[0x11, 0x12], [0x21, 0x22], VB[3]],
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
        &DirEntryHeader::new(golden_entry(), V[0], EntryType::Regular, W[1]),
        &bytes![golden_entry_bytes(), VB[0], [8, 0, 0, 0], WB[1]],
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
            token_len: U32::new(W[5]),
        },
        values::HELLO,
        &bytes![WB[0], WB[1], WB[2], WB[3], WB[4], WB[5]],
    );
    golden_message(
        &HelloReply {
            root_node_id: U64::new(V[0]),
            protocol_version: U32::new(W[0]),
            flags: U32::new(W[1]),
            connection_id: U64::new(V[1]),
            token_len: U32::new(W[2]),
            reserved: U32::ZERO,
        },
        values::HELLO,
        &bytes![VB[0], WB[0], WB[1], VB[1], WB[2], [0, 0, 0, 0]],
    );
}

#[test]
fn connection_messages() {
    golden_message(
        &OutcomeRequest {
            connection_id: U64::new(V[0]),
            request_id: U64::new(V[1]),
        },
        values::OUTCOME,
        &bytes![VB[0], VB[1]],
    );
    golden_message(
        &OutcomeResponse {
            state: U32::new(W[0]),
            reserved: U32::ZERO,
        },
        values::OUTCOME,
        &bytes![WB[0], [0, 0, 0, 0]],
    );
    golden_message(
        &RetireRequest {
            connection_id: U64::new(V[0]),
        },
        values::RETIRE,
        &VB[0],
    );
    golden_message(
        &RetireResponse {
            reserved: U32::ZERO,
        },
        values::RETIRE,
        &[0, 0, 0, 0],
    );
    golden_message(
        &CancelRequest {
            request_id: U64::new(V[0]),
        },
        values::CANCEL,
        &VB[0],
    );
    golden_message(
        &RecalledRequest {
            recall: U64::new(V[0]),
        },
        values::RECALLED,
        &VB[0],
    );
    golden_message(
        &RecalledResponse {
            reserved: U32::ZERO,
        },
        values::RECALLED,
        &[0, 0, 0, 0],
    );
    golden_message(
        &RenewRequest {
            reserved: U32::ZERO,
        },
        values::RENEW,
        &[0, 0, 0, 0],
    );
    golden_message(
        &RenewResponse {
            window_ns: U64::new(V[0]),
            period_ns: U64::new(V[1]),
        },
        values::RENEW,
        &bytes![VB[0], VB[1]],
    );
    golden_message(
        &RelinquishRequest {
            reserved: U32::ZERO,
        },
        values::RELINQUISH,
        &[0, 0, 0, 0],
    );
    golden_message(
        &RelinquishResponse {
            reserved: U32::ZERO,
        },
        values::RELINQUISH,
        &[0, 0, 0, 0],
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
    golden_message(&ReaddirplusResponse, values::READDIRPLUS, &[]);
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
    golden_message(&ReadResponse, values::READ, &[]);
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
    golden_notification(&ShareSnapshotPart, notifications::SHARE_SNAPSHOT_PART, &[]);
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
    golden_notification(
        &Recall {
            node_id: U64::new(V[0]),
            recall: U64::new(V[1]),
        },
        notifications::RECALL,
        &bytes![VB[0], VB[1]],
    );
}

#[track_caller]
fn parsed(bytes: &[u8]) -> Frame<'_> {
    Frame::parse(bytes, &LIMITS).expect("a legal frame")
}

#[track_caller]
fn pieces(mut rest: &[u8], stream: Stream) -> (Vec<Vec<u8>>, Closing) {
    let bound = stream.piece_bound(&LIMITS).map_or(u64::MAX, u64::from);
    let mut out = Vec::new();
    loop {
        let (length, tail) = rest.split_at(PIECE_LEN_LEN);
        let len = piece::read_length(length.try_into().expect("a length word"));
        if len == 0 {
            let (closing, tail) = tail.split_at(8);
            assert!(tail.is_empty(), "nothing follows the closing piece");
            let closing = ClosingBody::parse(closing.try_into().expect("a closing body"))
                .expect("a legal closing piece");
            return (out, closing);
        }
        piece::check(len, bound).expect("a piece within its bound");
        let (bytes, tail) = tail.split_at(len as usize);
        out.push(bytes.to_vec());
        rest = tail;
    }
}

fn encode_pieces(pieces: &[Vec<u8>], closing: Closing) -> Vec<u8> {
    let mut out = Vec::new();
    for bytes in pieces {
        out.extend_from_slice(&piece::length(bytes.len()).expect("a 32-bit length"));
        out.extend_from_slice(bytes);
    }
    out.extend_from_slice(&closing.encode());
    out
}

#[test]
fn share_snapshot_part_is_pinned() {
    let expected = bytes![
        // header: opcode, flags (RESPONSE clear), request_id 0; no body
        notifications::SHARE_SNAPSHOT_PART.to_le_bytes(),
        0u16.to_le_bytes(),
        0u64.to_le_bytes(),
        // one entry per piece
        13u32.to_le_bytes(),
        SHARE_MODE_RW.to_le_bytes(),
        SHARE_KIND_DIRECTORY.to_le_bytes(),
        5u32.to_le_bytes(),
        *b"/docs",
        17u32.to_le_bytes(),
        SHARE_MODE_RO.to_le_bytes(),
        SHARE_KIND_FILE.to_le_bytes(),
        9u32.to_le_bytes(),
        *b"/read.txt",
        // closing piece: status 0, flags 0
        [0u8; 12],
    ];

    let Parsed::Frame(frame) = Frame::parse_prefix(&expected, &LIMITS).expect("legal") else {
        panic!("the message is all there");
    };
    assert_eq!(frame.len(), 12, "the part itself is a bare header");
    assert_eq!(frame.kind(), FrameKind::Notification);
    assert_eq!(frame.request_id(), 0);
    assert_eq!(
        frame.notification_opcode(),
        Ok(NotificationOpcode::ShareSnapshotPart)
    );
    assert_eq!(
        frame.follows(),
        voidport_proto::message::Follows::Pieces(Stream::ShareEntries)
    );
    frame
        .notification::<ShareSnapshotPart>()
        .expect("a snapshot part");
    let (entries, closing) = pieces(&expected[frame.len()..], Stream::ShareEntries);
    assert_eq!(closing, Closing::done(false));
    let decoded: Vec<(u16, u16, Vec<u8>)> = entries
        .iter()
        .map(|bytes| {
            let entry = piece::entry::<ShareEntryHeader>(bytes, LIMITS.path_max - 1)
                .expect("one entry per piece");
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

    let mut buffer = [0u8; 16];
    let mut encoded = FrameWriter::notification(&mut buffer, &LIMITS, &ShareSnapshotPart)
        .and_then(FrameWriter::finish)
        .expect("encodable")
        .to_vec();
    let reencoded: Vec<Vec<u8>> = decoded
        .iter()
        .map(|(mode, kind, path)| {
            let mut entry = ShareEntryHeader::new(*mode, *kind, path.len() as u32)
                .as_bytes()
                .to_vec();
            entry.extend_from_slice(path);
            entry
        })
        .collect();
    encoded.extend_from_slice(&encode_pieces(&reencoded, closing));
    assert_eq!(encoded, expected);
}

#[test]
fn share_delta_frames_round_trip() {
    let path = b"/project/docs";
    let body = ShareAdded {
        mode: U16::new(SHARE_MODE_RO),
        kind: U16::new(SHARE_KIND_DIRECTORY),
        path_len: U32::new(path.len() as u32),
    };
    let mut buffer = [0u8; 64];
    let mut writer = FrameWriter::notification(&mut buffer, &LIMITS, &body).expect("encodable");
    writer.payload(path).expect("the declared payload");
    let bytes = writer.finish().expect("complete").to_vec();

    let frame = parsed(&bytes);
    let event = frame.notification::<ShareAdded>().expect("an added event");
    assert_eq!(event.path(), path);
    assert_eq!(event.body().mode.get(), SHARE_MODE_RO);
    assert!(frame.response::<SubscribeResponse>().is_err());
    assert!(frame.notification::<ShareRemoved>().is_err());
}

#[test]
fn hello_frame_is_pinned() {
    let namespace = b"ns";
    let subpath = b"/proj";
    let expected: Vec<u8> = bytes![
        // header: opcode = HELLO, flags = 0, request_id = 1
        [0x01, 0x00],
        [0x00, 0x00],
        [1, 0, 0, 0, 0, 0, 0, 0],
        // request head: all zero, the handshake targets no node
        [0u8; 24],
        // body: version 4, flags 0, lengths 2 / 5 / 0 / 0
        [4, 0, 0, 0],
        [0, 0, 0, 0],
        [2, 0, 0, 0],
        [5, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        // payload
        *namespace,
        *subpath,
    ];
    assert_eq!(PROTOCOL_VERSION, 4);

    let frame = parsed(&expected);
    assert_eq!(frame.opcode(), Ok(Opcode::Hello));
    let request = frame.request::<HelloRequest>().unwrap();
    assert_eq!(request.namespace(), namespace);
    assert_eq!(request.subpath(), subpath);
    assert_eq!(request.auth(), b"");
    assert_eq!(request.token(), b"");
    assert!(!request.body().joins());

    let mut buf = [0u8; 128];
    let mut writer = FrameWriter::request(
        &mut buf,
        &LIMITS,
        frame.request_id(),
        request.head(),
        request.body(),
    )
    .unwrap();
    writer.payload(request.namespace()).unwrap();
    writer.payload(request.subpath()).unwrap();
    assert_eq!(writer.finish().unwrap(), expected.as_slice());
    assert_eq!(
        HelloRequest::new(2, 5),
        *request.body(),
        "the builder a client opens a session with"
    );
}

#[test]
fn a_joining_hello_frame_is_exact() {
    let token = b"a.b.c";
    let expected: Vec<u8> = bytes![
        // header: opcode = HELLO, flags = 0, request_id = 1
        [0x01, 0x00],
        [0x00, 0x00],
        [1, 0, 0, 0, 0, 0, 0, 0],
        // request head: all zero
        [0u8; 24],
        // body: version 4, the join flag, lengths 0 / 0 / 0 / 5
        [4, 0, 0, 0],
        [1, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [5, 0, 0, 0],
        // payload: the token alone
        *token,
    ];
    assert_eq!(hello_flags::JOIN, 1);

    let frame = parsed(&expected);
    let request = frame.request::<HelloRequest>().unwrap();
    assert!(request.body().joins());
    assert_eq!(request.namespace(), b"");
    assert_eq!(request.subpath(), b"");
    assert_eq!(request.auth(), b"");
    assert_eq!(request.token(), token);
    assert_eq!(*request.body(), HelloRequest::join(5));

    let mut buf = [0u8; 128];
    let mut writer = FrameWriter::request(
        &mut buf,
        &LIMITS,
        frame.request_id(),
        request.head(),
        request.body(),
    )
    .unwrap();
    writer.payload(request.token()).unwrap();
    assert_eq!(writer.finish().unwrap(), expected.as_slice());
}

#[test]
fn hello_reply_frame_is_pinned() {
    let token = b"a.b.c";
    let expected: Vec<u8> = bytes![
        // header: opcode = HELLO, flags = RESPONSE, request_id = 1
        [0x01, 0x00],
        [0x01, 0x00],
        [1, 0, 0, 0, 0, 0, 0, 0],
        // status 0
        [0, 0, 0, 0],
        // root node id 1, version 4, flags 0, connection id 2, token length
        // 5, reserved 0
        [1, 0, 0, 0, 0, 0, 0, 0],
        [4, 0, 0, 0],
        [0, 0, 0, 0],
        [2, 0, 0, 0, 0, 0, 0, 0],
        [5, 0, 0, 0],
        [0, 0, 0, 0],
        // payload: the session token
        *token,
    ];

    let frame = parsed(&expected);
    let response = frame.response::<HelloReply>().unwrap().success().unwrap();
    assert_eq!(response.body().root_node_id.get(), 1);
    assert_eq!(response.body().protocol_version.get(), PROTOCOL_VERSION);
    assert_eq!(response.body().connection_id.get(), 2);
    assert_eq!(response.token(), token);

    let mut buf = [0u8; 64];
    let mut writer =
        FrameWriter::response(&mut buf, &LIMITS, frame.request_id(), response.body()).unwrap();
    writer.payload(response.token()).unwrap();
    assert_eq!(writer.finish().unwrap(), expected.as_slice());
}

#[test]
fn a_joined_hello_reply_names_its_own_connection() {
    let token = b"a.b.c";
    let reply = HelloReply {
        root_node_id: U64::new(1),
        protocol_version: U32::new(PROTOCOL_VERSION),
        flags: U32::ZERO,
        connection_id: U64::new(7),
        token_len: U32::new(token.len() as u32),
        reserved: U32::ZERO,
    };
    let mut buf = [0u8; 64];
    let mut writer = FrameWriter::response(&mut buf, &LIMITS, 1, &reply).unwrap();
    writer.payload(token).unwrap();
    let bytes = writer.finish().unwrap().to_vec();
    let frame = parsed(&bytes);
    let response = frame.response::<HelloReply>().unwrap().success().unwrap();
    assert_eq!(response.body().connection_id.get(), 7);
    assert_eq!(response.token(), token);
}

#[test]
fn outcome_frames_are_exact() {
    let expected: Vec<u8> = bytes![
        // header: opcode = OUTCOME, flags = 0, request_id = 4
        values::OUTCOME.to_le_bytes(),
        [0x00, 0x00],
        [4, 0, 0, 0, 0, 0, 0, 0],
        // request head: all zero
        [0u8; 24],
        // body: connection id 2, request id 9
        [2, 0, 0, 0, 0, 0, 0, 0],
        [9, 0, 0, 0, 0, 0, 0, 0],
    ];
    assert_eq!(values::OUTCOME, 0x001F);
    let frame = parsed(&expected);
    assert_eq!(frame.opcode(), Ok(Opcode::Outcome));
    let request = frame.request::<OutcomeRequest>().unwrap();
    assert_eq!(request.body().connection_id.get(), 2);
    assert_eq!(request.body().request_id.get(), 9);
    let mut buf = [0u8; 64];
    let encoded = FrameWriter::request(&mut buf, &LIMITS, 4, request.head(), request.body())
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(encoded, expected.as_slice());

    // The kept reply: a write answered with 3 bytes written, to request 9.
    let mut kept = [0u8; 64];
    let kept = FrameWriter::response(
        &mut kept,
        &LIMITS,
        9,
        &WriteResponse {
            written: U32::new(3),
        },
    )
    .unwrap()
    .finish()
    .unwrap()
    .to_vec();
    let answer: Vec<u8> = bytes![
        // header: opcode = OUTCOME, flags = RESPONSE, request_id = 4
        values::OUTCOME.to_le_bytes(),
        [0x01, 0x00],
        [4, 0, 0, 0, 0, 0, 0, 0],
        // status 0; state REPLIED, reserved 0
        [0, 0, 0, 0],
        [2, 0, 0, 0],
        [0, 0, 0, 0],
    ];
    assert_eq!(outcome_state::REPLIED, 2);
    let mut wire = answer.clone();
    wire.extend(encode_pieces(
        std::slice::from_ref(&kept),
        Closing::done(false),
    ));

    let (message, rest) = match Frame::parse_prefix(&wire, &LIMITS).unwrap() {
        Parsed::Frame(frame) => (frame, &wire[answer.len()..]),
        Parsed::Need(needed) => panic!("the answer is whole, the parser asks for {needed}"),
    };
    assert_eq!(
        message.follows(),
        voidport_proto::message::Follows::Pieces(Stream::Data)
    );
    let response = message
        .response::<OutcomeResponse>()
        .unwrap()
        .success()
        .unwrap();
    assert_eq!(response.body().state.get(), outcome_state::REPLIED);
    let (carried, closing) = pieces(rest, Stream::Data);
    assert_eq!(carried, vec![kept.clone()]);
    assert_eq!(closing, Closing::done(false));
    let reply = parsed(&kept);
    assert_eq!(reply.request_id(), 9);
    let written = reply
        .response::<WriteResponse>()
        .unwrap()
        .success()
        .unwrap();
    assert_eq!(written.body().written.get(), 3);
}

#[test]
fn lookup_frames_are_pinned() {
    let name = b"project";
    let expected: Vec<u8> = bytes![
        // header: opcode = LOOKUP, flags = 0, request_id = 7
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

    let frame = parsed(&expected);
    let request = frame.request::<LookupRequest>().unwrap();
    assert_eq!(request.head().uid.get(), 1000);
    assert_eq!(request.name(), name);

    let mut buf = [0u8; 128];
    let mut writer = FrameWriter::request(
        &mut buf,
        &LIMITS,
        frame.request_id(),
        request.head(),
        request.body(),
    )
    .unwrap();
    writer.payload(request.name()).unwrap();
    assert_eq!(writer.finish().unwrap(), expected.as_slice());
}

#[test]
fn error_response_frame_is_pinned() {
    let expected: Vec<u8> = bytes![
        // header: opcode = LOOKUP, flags = RESPONSE, request_id = 7
        [0x02, 0x00],
        [0x01, 0x00],
        [7, 0, 0, 0, 0, 0, 0, 0],
        // status = -ENOENT, and nothing else
        [0xFE, 0xFF, 0xFF, 0xFF],
    ];

    let frame = parsed(&expected);
    assert_eq!(frame.header().flags.get(), FLAG_RESPONSE);
    assert_eq!(
        frame.response::<LookupResponse>().unwrap(),
        ResponseOutcome::Error(-2)
    );

    let mut buf = [0u8; 32];
    let encoded = FrameWriter::error_response(
        &mut buf,
        frame.request_id(),
        frame.opcode().unwrap(),
        frame.status().unwrap(),
    )
    .unwrap();
    assert_eq!(encoded, expected.as_slice());
}

#[test]
fn read_reply_envelope_is_pinned() {
    let expected: Vec<u8> = bytes![
        // header: opcode = READ, flags = RESPONSE, request_id = 11
        [0x0E, 0x00],
        [0x01, 0x00],
        [11, 0, 0, 0, 0, 0, 0, 0],
        // status 0; the fixed body is empty
        [0, 0, 0, 0],
        // two pieces
        [4, 0, 0, 0],
        *b"abcd",
        [2, 0, 0, 0],
        *b"ef",
        // closing piece: status -EIO, flags 0
        [0, 0, 0, 0],
        [0xFB, 0xFF, 0xFF, 0xFF],
        [0, 0, 0, 0],
    ];
    let Parsed::Frame(frame) = Frame::parse_prefix(&expected, &LIMITS).unwrap() else {
        panic!("the head is all there");
    };
    assert_eq!(frame.len(), 16);
    assert_eq!(
        frame.follows(),
        voidport_proto::message::Follows::Pieces(Stream::Data)
    );
    let response = frame.response::<ReadResponse>().unwrap().success().unwrap();
    let (data, closing) = pieces(&expected[frame.len()..], Stream::Data);
    assert_eq!(data, vec![b"abcd".to_vec(), b"ef".to_vec()]);
    assert_eq!(
        closing,
        Closing {
            status: -5,
            exhausted: false,
        }
    );

    let mut buf = [0u8; 32];
    let mut encoded = FrameWriter::response(&mut buf, &LIMITS, frame.request_id(), response.body())
        .unwrap()
        .finish()
        .unwrap()
        .to_vec();
    encoded.extend_from_slice(&encode_pieces(&data, closing));
    assert_eq!(encoded, expected);

    let exhausted: Vec<u8> = bytes![
        [0x0E, 0x00],
        [0x01, 0x00],
        [11, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [1, 0, 0, 0],
    ];
    let frame = Frame::parse_prefix(&exhausted, &LIMITS).unwrap();
    let Parsed::Frame(frame) = frame else {
        panic!("the head is all there");
    };
    let (data, closing) = pieces(&exhausted[frame.len()..], Stream::Data);
    assert!(data.is_empty());
    assert_eq!(closing, Closing::done(true));
}

#[test]
fn readdirplus_reply_streams_one_entry_per_piece() {
    let entry = golden_entry();
    let expected: Vec<u8> = bytes![
        // header: opcode = READDIRPLUS, flags = RESPONSE, request_id = 9
        [0x18, 0x00],
        [0x01, 0x00],
        [9, 0, 0, 0, 0, 0, 0, 0],
        // status 0; the fixed body is empty
        [0, 0, 0, 0],
        // one entry per piece: 116 bytes of header and the name
        (116u32 + 3).to_le_bytes(),
        golden_entry_bytes(),
        [1, 0, 0, 0, 0, 0, 0, 0],
        [4, 0, 0, 0],
        [3, 0, 0, 0],
        *b"foo",
        (116u32 + 7).to_le_bytes(),
        golden_entry_bytes(),
        [2, 0, 0, 0, 0, 0, 0, 0],
        [8, 0, 0, 0],
        [7, 0, 0, 0],
        *b"bar.txt",
        // closing piece: status 0, the directory is exhausted
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [1, 0, 0, 0],
    ];
    assert_eq!(size_of::<DirEntryHeader>(), 116);

    let Parsed::Frame(frame) = Frame::parse_prefix(&expected, &LIMITS).unwrap() else {
        panic!("the head is all there");
    };
    let response = frame
        .response::<ReaddirplusResponse>()
        .unwrap()
        .success()
        .unwrap();
    let (entries, closing) = pieces(&expected[frame.len()..], Stream::DirEntries);
    assert_eq!(closing, Closing::done(true));
    let walked: Vec<(Vec<u8>, u64, u32)> = entries
        .iter()
        .map(|bytes| {
            let item = piece::entry::<DirEntryHeader>(bytes, LIMITS.name_max).unwrap();
            assert_eq!(item.header.entry, entry);
            (
                item.tail.to_vec(),
                item.header.next_cookie.get(),
                item.header.entry_type().unwrap() as u32,
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

    let mut buf = [0u8; 32];
    let mut encoded = FrameWriter::response(&mut buf, &LIMITS, frame.request_id(), response.body())
        .unwrap()
        .finish()
        .unwrap()
        .to_vec();
    let reencoded: Vec<Vec<u8>> = [
        (b"foo".as_slice(), 1, EntryType::Directory),
        (b"bar.txt".as_slice(), 2, EntryType::Regular),
    ]
    .iter()
    .map(|(name, cookie, kind)| {
        let mut stream_buf = [0u8; 256];
        let mut stream = DirEntryWriter::new(&mut stream_buf);
        stream
            .push(
                &DirEntryHeader::new(entry, *cookie, *kind, name.len() as u32),
                name,
            )
            .unwrap();
        stream.finish().to_vec()
    })
    .collect();
    encoded.extend_from_slice(&encode_pieces(&reencoded, closing));
    assert_eq!(encoded, expected);
}

#[test]
fn write_data_follows_the_message() {
    let message: Vec<u8> = bytes![
        // header: opcode = WRITE, flags = 0, request_id = 5
        [0x0F, 0x00],
        [0x00, 0x00],
        [5, 0, 0, 0, 0, 0, 0, 0],
        // request head: node 2, uid 0, gid 0, pid 0, reserved 0
        [2, 0, 0, 0, 0, 0, 0, 0],
        [0u8; 16],
        // handle 3, offset 4, data_len 6, flags 0, write_flags 0, reserved 0
        [3, 0, 0, 0, 0, 0, 0, 0],
        [4, 0, 0, 0, 0, 0, 0, 0],
        [6, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
    ];
    let mut stream = message.clone();
    stream.extend_from_slice(b"123456");

    let Parsed::Frame(frame) = Frame::parse_prefix(&stream, &LIMITS).unwrap() else {
        panic!("the message is all there");
    };
    assert_eq!(frame.len(), message.len());
    assert_eq!(frame.follows(), voidport_proto::message::Follows::Data(6));
    let request = frame.request::<WriteRequest>().unwrap();
    assert!(request.payload().is_empty());
    assert!(matches!(
        Frame::parse(&stream, &LIMITS),
        Err(voidport_proto::error::FramingError::TrailingBytes { extra: 6 })
    ));

    let mut buf = [0u8; 128];
    let encoded = FrameWriter::request(
        &mut buf,
        &LIMITS,
        frame.request_id(),
        request.head(),
        request.body(),
    )
    .unwrap()
    .finish()
    .unwrap();
    assert_eq!(encoded, message.as_slice());
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
    let mut writer = FrameWriter::response(&mut buf, &LIMITS, 3, &body).unwrap();
    writer.payload(list).unwrap();
    let frame_bytes = writer.finish().unwrap();

    let frame = parsed(frame_bytes);
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
    let mut writer =
        FrameWriter::request(&mut buf, &LIMITS, 4, &RequestHead::new(2, 0, 0, 0), &body).unwrap();
    writer.payload(old_name).unwrap();
    writer.payload(new_name).unwrap();
    let frame_bytes = writer.finish().unwrap();

    let frame = parsed(frame_bytes);
    let request = frame.request::<RenameRequest>().unwrap();
    assert_eq!(request.old_name(), old_name);
    assert_eq!(request.new_name(), new_name);

    let target = b"../elsewhere";
    let body = SymlinkRequest {
        name_len: U32::new(4),
        target_len: U32::new(target.len() as u32),
    };
    let mut writer =
        FrameWriter::request(&mut buf, &LIMITS, 5, &RequestHead::new(2, 0, 0, 0), &body).unwrap();
    writer.payload(b"link").unwrap();
    writer.payload(target).unwrap();
    let frame_bytes = writer.finish().unwrap();
    let frame = parsed(frame_bytes);
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
    let mut writer =
        FrameWriter::request(&mut buf, &LIMITS, 6, &RequestHead::new(2, 0, 0, 0), &body).unwrap();
    writer.payload(b"user.foo").unwrap();
    writer.payload(value).unwrap();
    let frame_bytes = writer.finish().unwrap();
    let frame = parsed(frame_bytes);
    let request = frame.request::<SetxattrRequest>().unwrap();
    assert_eq!(request.name(), b"user.foo");
    assert_eq!(request.value(), value);
}

#[test]
fn payload_can_be_filled_in_place() {
    let body = ReadlinkResponse {
        target_len: U32::new(4),
    };
    let mut buf = [0u8; 64];
    let mut writer = FrameWriter::response(&mut buf, &LIMITS, 11, &body).unwrap();
    writer.payload_buf(4).unwrap().copy_from_slice(b"data");
    let frame_bytes = writer.finish().unwrap();

    let frame = parsed(frame_bytes);
    let response = frame
        .response::<ReadlinkResponse>()
        .unwrap()
        .success()
        .unwrap();
    assert_eq!(response.target(), b"data");
}

#[test]
fn the_write_privileged_strip_flag_is_pinned_to_its_bit() {
    use voidport_proto::ops::file::write_flags;

    assert_eq!(write_flags::PRIVILEGED_STRIP, 1);
    golden_message(
        &WriteRequest {
            handle: U64::new(V[0]),
            offset: U64::new(V[1]),
            data_len: U32::new(W[0]),
            flags: U32::ZERO,
            write_flags: U32::new(write_flags::PRIVILEGED_STRIP),
            reserved: U32::ZERO,
        },
        values::WRITE,
        &bytes![
            VB[0],
            VB[1],
            WB[0],
            [0, 0, 0, 0],
            [1, 0, 0, 0],
            [0, 0, 0, 0]
        ],
    );

    golden_message(
        &WriteRequest {
            handle: U64::new(V[0]),
            offset: U64::new(V[1]),
            data_len: U32::new(W[0]),
            flags: U32::ZERO,
            write_flags: U32::ZERO,
            reserved: U32::ZERO,
        },
        values::WRITE,
        &bytes![
            VB[0],
            VB[1],
            WB[0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0]
        ],
    );
}

#[test]
fn the_open_reply_caching_flags_are_pinned_to_their_bits() {
    use voidport_proto::ops::file::open_flags;

    for (flag, byte) in [(open_flags::KEEP_CACHE, 1), (open_flags::UNCACHED, 2)] {
        golden_message(
            &OpenResponse {
                handle: U64::new(V[0]),
                flags: U32::new(flag),
                reserved: U32::ZERO,
            },
            values::OPEN,
            &bytes![VB[0], [byte, 0, 0, 0], [0, 0, 0, 0]],
        );
    }
}
