//! Hostile input: what the wire layer may never *accept*.
//!
//! Every byte this crate parses arrived from the network, so a parse either
//! refuses or produces something internally consistent. `tests/fuzz.rs` pins
//! the weaker half of that contract — nothing panics. This suite pins the
//! stronger half: no accepted result may be absurd. Concretely, an accepted
//! frame is never longer than the buffer it was parsed from, a declared length
//! always agrees with the bytes it describes, and no payload or region slice
//! ever points outside the input, whatever the length fields say.
//!
//! Three generators, all deterministic:
//!
//! 1. **Pure noise** — seeded random buffers of random length, from empty to
//!    twice the maximum frame length, through every public parse entry point,
//!    under both the pre-handshake bound and an unbounded one.
//! 2. **Structure-aware mutation** — a valid frame for every opcode, every
//!    request, response and notification body among them, then every byte
//!    position rewritten and every header bit flipped, one at a time.
//! 3. **Truncation sweep** — every valid frame cut at every length: the parser
//!    must ask for more bytes than are buffered, or refuse.
//!
//! # Reproducing a failure
//!
//! Every assertion prints the frame label, the case index and the generator
//! seed. The seeds are constants in this file and the case order is fixed, so
//! a reported case is the same case on the next run.
//!
//! # Case count
//!
//! The defaults are sized to add about a second to the suite: roughly 130k
//! noise buffers, 150k mutations and 3.9k truncations of 68 sample frames.
//! `VOIDPORT_HOSTILE_ROUNDS=<n>` multiplies the case count of the two
//! randomized generators by `n` for a long run; the seed is unchanged, so a
//! larger `n` extends the same stream instead of replacing it. The truncation
//! sweep is exhaustive over its samples and therefore ignores the variable.

use core::fmt;

use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::attr::{Attr, EntryOut, Timespec, file_type};
use voidport_proto::error::FramingError;
use voidport_proto::frame::{FRAME_HEADER_LEN, Frame, FrameKind, FrameWriter, MAX_HELLO_FRAME_LEN};
use voidport_proto::message::{
    Notification, NotificationBody, REQUEST_HEAD_LEN, RESPONSE_HEAD_LEN, Request, RequestBody,
    RequestHead, Response, ResponseBody, ResponseOutcome, WirePayload, is_error_status,
};
use voidport_proto::opcode::{Opcode, is_notification_opcode};
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
    SHARE_END_NAMESPACE_REMOVED, SHARE_KIND_DIRECTORY, SHARE_KIND_FILE, SHARE_MODE_RO,
    SHARE_MODE_RW, ShareAdded, ShareChanged, ShareEnded, ShareEntryHeader, ShareEntryWriter,
    ShareRemoved, ShareSnapshotBegin, ShareSnapshotEnd, ShareSnapshotPart,
};
use voidport_proto::ops::subscribe::{
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, UnsubscribeResponse,
};
use voidport_proto::ops::xattr::{
    GetxattrRequest, GetxattrResponse, ListxattrRequest, ListxattrResponse, RemovexattrRequest,
    RemovexattrResponse, SetxattrRequest, SetxattrResponse, XattrNameHeader, XattrNameWriter,
    guest_list_size,
};
use voidport_proto::stream::{StreamEntry, StreamIter};
use zerocopy::byteorder::little_endian::{U16, U32, U64};

/// The pre-handshake frame bound, which is the bound these generators parse
/// under unless they are explicitly proving the unbounded case.
const MAX: u32 = MAX_HELLO_FRAME_LEN;

/// `ENOSYS`, negated: the status a receiver owes a well-framed request whose
/// opcode it cannot name.
const ENOSYS: i32 = -38;

/// Buffer every sample frame is encoded into. The largest sample is the
/// readdirplus response, whose two entries carry a 100-byte entry reply each.
const SCRATCH: usize = 512;

/// Base case count of the noise generator.
const NOISE_CASES: usize = 65_536;

/// How many times the mutation generator sweeps every sample frame. Each pass
/// rewrites the same positions with fresh values, so more passes mean more
/// distinct byte values at every offset.
const MUTATION_PASSES: usize = 12;

/// Seed of the noise generator.
const NOISE_SEED: u64 = 0x5EED_0000_0000_0001;

/// Seed of the mutation generator.
const MUTATION_SEED: u64 = 0x5EED_0000_0000_0002;

/// Environment variable multiplying the randomized generators' case counts.
const ROUNDS_VAR: &str = "VOIDPORT_HOSTILE_ROUNDS";

/// How many times the randomized generators run their base case count.
fn rounds() -> usize {
    std::env::var(ROUNDS_VAR)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(1)
}

/// Deterministic xorshift64* generator: a few lines, no dependency, and a
/// failure reproduces from the seed alone.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    /// A value in `0..bound`; `bound` must be nonzero.
    fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    /// `len` random bytes, drawn eight at a time so a long buffer costs one
    /// step per eight bytes.
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

/// Which case a failure came from: enough to rerun exactly that case.
#[derive(Clone, Copy)]
struct Case {
    /// The frame the case was derived from, or the generator's name.
    label: &'static str,
    /// Index of the case within its generator, in generation order.
    index: usize,
    /// Seed of the generator, or 0 when the sweep is exhaustive.
    seed: u64,
}

impl Case {
    fn seeded(label: &'static str, index: usize, seed: u64) -> Self {
        Self { label, index, seed }
    }

    /// A case of a sweep that enumerates every possibility and so draws no
    /// random values.
    fn exhaustive(label: &'static str, index: usize) -> Self {
        Self {
            label,
            index,
            seed: 0,
        }
    }
}

impl fmt::Display for Case {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { label, index, seed } = self;
        if *seed == 0 {
            write!(f, "[{label}] case {index} (exhaustive sweep)")
        } else {
            write!(f, "[{label}] case {index} of seed {seed:#018x}")
        }
    }
}

/// Whether `inner` borrows from `outer`'s bytes.
///
/// An empty slice borrows nothing — it can escape nothing, and the crate
/// legitimately hands back the empty literal for an empty region — so it counts
/// as contained.
fn inside(outer: &[u8], inner: &[u8]) -> bool {
    if inner.is_empty() {
        return true;
    }
    let start = outer.as_ptr() as usize;
    let at = inner.as_ptr() as usize;
    at >= start && at + inner.len() <= start + outer.len()
}

/// Every public parse entry point, applied to one buffer, with every accepted
/// result checked for internal consistency.
fn check_buffer(buf: &[u8], max: u32, case: Case) {
    match Frame::peek_len(buf, max) {
        Ok(None) => assert!(
            buf.len() < FRAME_HEADER_LEN,
            "{case}: peek_len asked for more bytes with a whole header buffered"
        ),
        Ok(Some(len)) => {
            assert!(
                buf.len() >= FRAME_HEADER_LEN,
                "{case}: peek_len produced a length from less than a header"
            );
            assert!(
                (FRAME_HEADER_LEN as u32..=max).contains(&len),
                "{case}: peeked length {len} is outside the legal range"
            );
        }
        Err(_) => {}
    }

    let whole = Frame::parse(buf, max);
    let Ok((frame, tail)) = Frame::parse_prefix(buf, max) else {
        assert!(
            whole.is_err(),
            "{case}: parse accepted a buffer parse_prefix refused"
        );
        return;
    };

    check_frame(buf, max, &frame, tail, case);
    assert_eq!(
        whole.is_ok(),
        tail.is_empty(),
        "{case}: parse and parse_prefix disagree about the trailing bytes"
    );
    assert_eq!(
        Frame::peek_len(buf, max),
        Ok(Some(frame.header().len.get())),
        "{case}: peek_len disagrees with the frame parse_prefix produced"
    );
    check_every_body(buf, max, &frame, case);
}

/// Frame-level invariants of an accepted parse: the declared length accounts
/// for exactly the bytes handed back, and every slice stays in the input.
fn check_frame(buf: &[u8], max: u32, frame: &Frame<'_>, tail: &[u8], case: Case) {
    let body = frame.body();
    let declared = frame.header().len.get() as usize;

    assert!(
        inside(buf, body),
        "{case}: the frame body escaped the input buffer"
    );
    assert!(
        inside(buf, tail),
        "{case}: the trailing bytes escaped the input buffer"
    );
    assert!(
        declared <= buf.len(),
        "{case}: accepted a frame of {declared} bytes from a {}-byte buffer",
        buf.len()
    );
    assert_eq!(
        declared,
        FRAME_HEADER_LEN + body.len(),
        "{case}: the declared length disagrees with the body handed back"
    );
    assert_eq!(
        declared + tail.len(),
        buf.len(),
        "{case}: the frame and its tail do not account for the buffer"
    );
    assert!(
        (FRAME_HEADER_LEN..=max as usize).contains(&declared),
        "{case}: the declared length {declared} is outside the legal range"
    );
    assert_eq!(
        frame.header().validate(max),
        Ok(()),
        "{case}: an accepted frame carries a header that does not validate"
    );

    // The taxonomy is a header-only decision, and each class fixes the id.
    let notification = is_notification_opcode(frame.raw_opcode());
    assert_eq!(
        frame.kind() == FrameKind::Notification,
        notification,
        "{case}: the frame class disagrees with the opcode range"
    );
    if notification {
        assert_eq!(
            frame.request_id(),
            0,
            "{case}: an accepted notification carries a request id"
        );
        assert!(
            frame.opcode().is_err(),
            "{case}: a notification opcode answered the request registry"
        );
    } else {
        assert_ne!(
            frame.request_id(),
            0,
            "{case}: an accepted request or response carries the reserved id 0"
        );
        assert!(
            frame.notification_opcode().is_err(),
            "{case}: a request opcode answered the notification registry"
        );
    }
}

/// Body-level invariants of an accepted typed parse: the fixed structs and the
/// declared payload account for the frame body exactly, and the payload lies
/// inside the input.
fn check_payload<M: WirePayload>(
    buf: &[u8],
    body_len: usize,
    head_len: usize,
    body: &M,
    payload: &[u8],
    case: Case,
) {
    assert!(
        inside(buf, payload),
        "{case}: a payload slice escaped the input buffer"
    );
    let declared = match body.payload_len() {
        Ok(declared) => declared,
        Err(error) => panic!("{case}: an accepted body's declared lengths do not sum: {error}"),
    };
    assert_eq!(
        declared as usize,
        payload.len(),
        "{case}: the declared payload length disagrees with the payload"
    );
    assert_eq!(
        head_len + size_of::<M>() + payload.len(),
        body_len,
        "{case}: the fixed structs and the payload do not account for the body"
    );
}

/// Parses one request body and checks it, handing back the accepted view so a
/// caller can follow up on its accessors.
fn checked_request<'a, M: RequestBody>(
    buf: &[u8],
    frame: &Frame<'a>,
    case: Case,
) -> Option<Request<'a, M>> {
    let request = frame.request::<M>().ok()?;
    check_payload(
        buf,
        frame.body().len(),
        REQUEST_HEAD_LEN,
        request.body(),
        request.payload(),
        case,
    );
    Some(request)
}

/// The same for a message that carries no payload regions to follow up on.
fn check_request<M: RequestBody>(buf: &[u8], frame: &Frame<'_>, case: Case) {
    let _ = checked_request::<M>(buf, frame, case);
}

/// Parses one response body and checks it. An error outcome is checked too: it
/// must carry a real errno and nothing after it.
fn checked_response<'a, M: ResponseBody>(
    buf: &[u8],
    frame: &Frame<'a>,
    case: Case,
) -> Option<Response<'a, M>> {
    match frame.response::<M>().ok()? {
        ResponseOutcome::Error(status) => {
            assert!(
                is_error_status(status),
                "{case}: an accepted error response carries status {status}"
            );
            assert_eq!(
                frame.body().len(),
                RESPONSE_HEAD_LEN,
                "{case}: an accepted error response carries bytes after its status"
            );
            None
        }
        ResponseOutcome::Success(response) => {
            check_payload(
                buf,
                frame.body().len(),
                RESPONSE_HEAD_LEN,
                response.body(),
                response.payload(),
                case,
            );
            Some(response)
        }
    }
}

/// The same for a response with no payload regions to follow up on.
fn check_response<M: ResponseBody>(buf: &[u8], frame: &Frame<'_>, case: Case) {
    let _ = checked_response::<M>(buf, frame, case);
}

/// Parses one notification body and checks it. A notification has no head, so
/// its fixed struct starts at the frame body.
fn checked_notification<'a, M: NotificationBody>(
    buf: &[u8],
    frame: &Frame<'a>,
    case: Case,
) -> Option<Notification<'a, M>> {
    let notification = frame.notification::<M>().ok()?;
    check_payload(
        buf,
        frame.body().len(),
        0,
        notification.body(),
        notification.payload(),
        case,
    );
    Some(notification)
}

/// The same for a notification with no payload regions to follow up on.
fn check_notification<M: NotificationBody>(buf: &[u8], frame: &Frame<'_>, case: Case) {
    let _ = checked_notification::<M>(buf, frame, case);
}

/// The regions an accessor split out of a payload: each inside the input, and
/// together covering the payload exactly. A length field that lied can neither
/// hand out bytes from outside the frame nor leave bytes unaccounted for.
fn check_regions(buf: &[u8], payload: &[u8], regions: &[&[u8]], case: Case) {
    let mut total = 0;
    for region in regions {
        assert!(
            inside(buf, region),
            "{case}: a payload region escaped the input buffer"
        );
        assert!(
            inside(payload, region),
            "{case}: a payload region escaped the payload it was split from"
        );
        total += region.len();
    }
    assert_eq!(
        total,
        payload.len(),
        "{case}: the payload regions do not cover the payload exactly"
    );
}

/// Walks a length-prefixed entry stream: every entry accepted must sit inside
/// the payload with the length its header declared, and a stream that failed
/// once must stop instead of resynchronizing.
fn check_stream<H: StreamEntry>(payload: &[u8], entries: StreamIter<'_, H>, case: Case) {
    let mut failed = false;
    for item in entries {
        assert!(
            !failed,
            "{case}: an entry stream kept walking after it failed"
        );
        match item {
            Ok(item) => {
                assert!(
                    inside(payload, item.tail),
                    "{case}: a stream entry tail escaped the payload"
                );
                assert_eq!(
                    item.header.tail_len() as usize,
                    item.tail.len(),
                    "{case}: a stream entry tail disagrees with its declared length"
                );
            }
            Err(_) => failed = true,
        }
    }
}

/// Every message body the crate can parse, applied to one frame.
///
/// A type whose opcode or class the frame does not carry refuses at once; the
/// one that matches is checked in full, accessors and entry streams included.
/// Listing every type here is what makes "every opcode" a property of this
/// file instead of the frames the generators happen to produce.
fn check_every_body(buf: &[u8], max: u32, frame: &Frame<'_>, case: Case) {
    // The envelope check the unknown-opcode path owes, before any opcode is
    // known.
    let _ = frame.request_head();

    if let Some(request) = checked_request::<HelloRequest>(buf, frame, case) {
        check_regions(
            buf,
            request.payload(),
            &[request.namespace(), request.subpath(), request.auth()],
            case,
        );
    }
    check_response::<HelloReply>(buf, frame, case);

    if let Some(request) = checked_request::<LookupRequest>(buf, frame, case) {
        check_regions(buf, request.payload(), &[request.name()], case);
    }
    check_response::<LookupResponse>(buf, frame, case);
    check_request::<ForgetRequest>(buf, frame, case);
    check_request::<GetattrRequest>(buf, frame, case);
    check_response::<GetattrResponse>(buf, frame, case);
    check_request::<SetattrRequest>(buf, frame, case);
    check_response::<SetattrResponse>(buf, frame, case);
    check_request::<ReadlinkRequest>(buf, frame, case);
    if let Some(response) = checked_response::<ReadlinkResponse>(buf, frame, case) {
        check_regions(buf, response.payload(), &[response.target()], case);
    }
    check_request::<StatfsRequest>(buf, frame, case);
    check_response::<StatfsResponse>(buf, frame, case);

    if let Some(request) = checked_request::<SymlinkRequest>(buf, frame, case) {
        check_regions(
            buf,
            request.payload(),
            &[request.name(), request.target()],
            case,
        );
    }
    check_response::<SymlinkResponse>(buf, frame, case);
    if let Some(request) = checked_request::<MkdirRequest>(buf, frame, case) {
        check_regions(buf, request.payload(), &[request.name()], case);
    }
    check_response::<MkdirResponse>(buf, frame, case);
    if let Some(request) = checked_request::<MknodRequest>(buf, frame, case) {
        check_regions(buf, request.payload(), &[request.name()], case);
    }
    check_response::<MknodResponse>(buf, frame, case);
    if let Some(request) = checked_request::<UnlinkRequest>(buf, frame, case) {
        check_regions(buf, request.payload(), &[request.name()], case);
    }
    check_response::<UnlinkResponse>(buf, frame, case);
    if let Some(request) = checked_request::<RmdirRequest>(buf, frame, case) {
        check_regions(buf, request.payload(), &[request.name()], case);
    }
    check_response::<RmdirResponse>(buf, frame, case);
    if let Some(request) = checked_request::<RenameRequest>(buf, frame, case) {
        check_regions(
            buf,
            request.payload(),
            &[request.old_name(), request.new_name()],
            case,
        );
    }
    check_response::<RenameResponse>(buf, frame, case);
    if let Some(request) = checked_request::<LinkRequest>(buf, frame, case) {
        check_regions(buf, request.payload(), &[request.name()], case);
    }
    check_response::<LinkResponse>(buf, frame, case);
    check_request::<ReaddirplusRequest>(buf, frame, case);
    if let Some(response) = checked_response::<ReaddirplusResponse>(buf, frame, case) {
        check_stream(response.payload(), response.entries(), case);
    }

    check_request::<OpenRequest>(buf, frame, case);
    check_response::<OpenResponse>(buf, frame, case);
    if let Some(request) = checked_request::<CreateRequest>(buf, frame, case) {
        check_regions(buf, request.payload(), &[request.name()], case);
    }
    check_response::<CreateResponse>(buf, frame, case);
    check_request::<ReadRequest>(buf, frame, case);
    if let Some(response) = checked_response::<ReadResponse>(buf, frame, case) {
        check_regions(buf, response.payload(), &[response.data()], case);
    }
    if let Some(request) = checked_request::<WriteRequest>(buf, frame, case) {
        check_regions(buf, request.payload(), &[request.data()], case);
    }
    check_response::<WriteResponse>(buf, frame, case);
    check_request::<ReleaseRequest>(buf, frame, case);
    check_response::<ReleaseResponse>(buf, frame, case);
    check_request::<FlushRequest>(buf, frame, case);
    check_response::<FlushResponse>(buf, frame, case);
    check_request::<FsyncRequest>(buf, frame, case);
    check_response::<FsyncResponse>(buf, frame, case);
    check_request::<GetlkRequest>(buf, frame, case);
    check_response::<GetlkResponse>(buf, frame, case);
    check_request::<SetlkRequest>(buf, frame, case);
    check_response::<SetlkResponse>(buf, frame, case);

    if let Some(request) = checked_request::<SetxattrRequest>(buf, frame, case) {
        check_regions(
            buf,
            request.payload(),
            &[request.name(), request.value()],
            case,
        );
    }
    check_response::<SetxattrResponse>(buf, frame, case);
    if let Some(request) = checked_request::<GetxattrRequest>(buf, frame, case) {
        check_regions(buf, request.payload(), &[request.name()], case);
    }
    if let Some(response) = checked_response::<GetxattrResponse>(buf, frame, case) {
        check_regions(buf, response.payload(), &[response.value()], case);
    }
    check_request::<ListxattrRequest>(buf, frame, case);
    if let Some(response) = checked_response::<ListxattrResponse>(buf, frame, case) {
        check_stream(response.payload(), response.names(), case);
        let _ = guest_list_size(response.names());
    }
    if let Some(request) = checked_request::<RemovexattrRequest>(buf, frame, case) {
        check_regions(buf, request.payload(), &[request.name()], case);
    }
    check_response::<RemovexattrResponse>(buf, frame, case);

    check_request::<SubscribeRequest>(buf, frame, case);
    check_response::<SubscribeResponse>(buf, frame, case);
    check_request::<UnsubscribeRequest>(buf, frame, case);
    check_response::<UnsubscribeResponse>(buf, frame, case);

    check_notification::<ShareSnapshotBegin>(buf, frame, case);
    if let Some(part) = checked_notification::<ShareSnapshotPart>(buf, frame, case) {
        check_stream(part.payload(), part.entries(), case);
    }
    check_notification::<ShareSnapshotEnd>(buf, frame, case);
    if let Some(event) = checked_notification::<ShareAdded>(buf, frame, case) {
        check_regions(buf, event.payload(), &[event.path()], case);
    }
    if let Some(event) = checked_notification::<ShareRemoved>(buf, frame, case) {
        check_regions(buf, event.payload(), &[event.path()], case);
    }
    if let Some(event) = checked_notification::<ShareChanged>(buf, frame, case) {
        check_regions(buf, event.payload(), &[event.path()], case);
    }
    check_notification::<ShareEnded>(buf, frame, case);

    // The encode side meets hostile values too: a well-framed request this
    // build cannot name is answered with ENOSYS echoing its id and opcode,
    // both of which came straight from the mutated bytes.
    if frame.kind() == FrameKind::Request && frame.request_head().is_ok() {
        let mut out = [0u8; FRAME_HEADER_LEN + RESPONSE_HEAD_LEN];
        if let Ok(reply) = FrameWriter::error_response_raw(
            &mut out,
            max,
            frame.request_id(),
            frame.raw_opcode(),
            ENOSYS,
        ) {
            let parsed = match Frame::parse(reply, max) {
                Ok(parsed) => parsed,
                Err(error) => panic!("{case}: an emitted error response does not parse: {error}"),
            };
            assert_eq!(
                parsed.kind(),
                FrameKind::Response,
                "{case}: an error response is not a response"
            );
            assert_eq!(
                parsed.request_id(),
                frame.request_id(),
                "{case}: an error response lost the request id it answers"
            );
            assert_eq!(
                parsed.raw_opcode(),
                frame.raw_opcode(),
                "{case}: an error response lost the opcode it echoes"
            );
        }
    }
}

/// A valid frame and the label it is reported under.
struct Sample {
    label: &'static str,
    bytes: Vec<u8>,
}

/// Encodes a valid request frame. The body must declare exactly `payload`.
fn request_sample<M: RequestBody>(label: &'static str, body: &M, payload: &[u8]) -> Sample {
    let mut buf = [0u8; SCRATCH];
    let head = RequestHead::new(1, 1000, 1000, 42);
    let mut writer = FrameWriter::request(&mut buf, MAX, 7, &head, body)
        .unwrap_or_else(|error| panic!("{label}: the sample request must encode: {error}"));
    writer
        .payload(payload)
        .unwrap_or_else(|error| panic!("{label}: the sample payload must fit: {error}"));
    let bytes = writer
        .finish()
        .unwrap_or_else(|error| panic!("{label}: the sample request must finish: {error}"))
        .to_vec();
    Sample { label, bytes }
}

/// Encodes a valid successful response frame.
fn response_sample<M: ResponseBody>(label: &'static str, body: &M, payload: &[u8]) -> Sample {
    let mut buf = [0u8; SCRATCH];
    let mut writer = FrameWriter::response(&mut buf, MAX, 7, body)
        .unwrap_or_else(|error| panic!("{label}: the sample response must encode: {error}"));
    writer
        .payload(payload)
        .unwrap_or_else(|error| panic!("{label}: the sample payload must fit: {error}"));
    let bytes = writer
        .finish()
        .unwrap_or_else(|error| panic!("{label}: the sample response must finish: {error}"))
        .to_vec();
    Sample { label, bytes }
}

/// Encodes a valid notification frame.
fn notification_sample<M: NotificationBody>(
    label: &'static str,
    body: &M,
    payload: &[u8],
) -> Sample {
    let mut buf = [0u8; SCRATCH];
    let mut writer = FrameWriter::notification(&mut buf, MAX, body)
        .unwrap_or_else(|error| panic!("{label}: the sample notification must encode: {error}"));
    writer
        .payload(payload)
        .unwrap_or_else(|error| panic!("{label}: the sample payload must fit: {error}"));
    let bytes = writer
        .finish()
        .unwrap_or_else(|error| panic!("{label}: the sample notification must finish: {error}"))
        .to_vec();
    Sample { label, bytes }
}

/// Encodes a valid error response frame.
fn error_sample(label: &'static str, opcode: Opcode, status: i32) -> Sample {
    let mut buf = [0u8; SCRATCH];
    let bytes = FrameWriter::error_response(&mut buf, MAX, 7, opcode, status)
        .unwrap_or_else(|error| panic!("{label}: the sample error response must encode: {error}"))
        .to_vec();
    Sample { label, bytes }
}

fn sample_attr() -> Attr {
    Attr {
        ino: U64::new(0x1234),
        size: U64::new(8192),
        blocks: U64::new(16),
        atime: Timespec::new(1_700_000_000, 123),
        mtime: Timespec::new(1_700_000_001, 456),
        ctime: Timespec::new(1_700_000_002, 789),
        mode: U32::new(0o100_644),
        nlink: U32::new(1),
        uid: U32::new(1000),
        gid: U32::new(1000),
        rdev: U32::ZERO,
        blksize: U32::new(4096),
    }
}

fn sample_entry() -> EntryOut {
    EntryOut {
        node_id: U64::new(9),
        generation: U64::new(1),
        attr: sample_attr(),
    }
}

fn sample_lock() -> FileLock {
    FileLock {
        start: U64::new(0),
        end: U64::new(4096),
        owner: U64::new(0x4242),
        pid: U32::new(42),
        lock_type: U32::new(1),
    }
}

/// One valid frame per request opcode, with a plausible body and the payload
/// that body declares.
fn request_samples() -> Vec<Sample> {
    vec![
        request_sample(
            "hello request",
            &HelloRequest {
                protocol_version: U32::new(PROTOCOL_VERSION),
                flags: U32::ZERO,
                namespace_len: U32::new(2),
                subpath_len: U32::new(5),
                auth_len: U32::ZERO,
            },
            b"ns/proj",
        ),
        request_sample(
            "lookup request",
            &LookupRequest {
                name_len: U32::new(7),
            },
            b"project",
        ),
        request_sample(
            "forget request",
            &ForgetRequest {
                nlookup: U64::new(3),
            },
            &[],
        ),
        request_sample(
            "getattr request",
            &GetattrRequest {
                handle: U64::new(4),
                flags: U32::new(1),
                reserved: U32::ZERO,
            },
            &[],
        ),
        request_sample(
            "setattr request",
            &SetattrRequest {
                valid: U32::new(0b0000_0111),
                handle: U64::new(4),
                size: U64::new(1024),
                mode: U32::new(0o644),
                uid: U32::new(1000),
                gid: U32::new(1000),
                atime: Timespec::new(1_700_000_000, 0),
                mtime: Timespec::new(1_700_000_001, 0),
                ctime: Timespec::new(1_700_000_002, 0),
                ..SetattrRequest::default()
            },
            &[],
        ),
        request_sample("readlink request", &ReadlinkRequest, &[]),
        request_sample(
            "symlink request",
            &SymlinkRequest {
                name_len: U32::new(4),
                target_len: U32::new(6),
            },
            b"link../tgt",
        ),
        request_sample(
            "mkdir request",
            &MkdirRequest {
                mode: U32::new(0o755),
                umask: U32::new(0o022),
                name_len: U32::new(3),
                reserved: U32::ZERO,
            },
            b"dir",
        ),
        request_sample(
            "mknod request",
            &MknodRequest {
                mode: U32::new(0o010_644),
                umask: U32::new(0o022),
                rdev: U32::ZERO,
                name_len: U32::new(4),
            },
            b"fifo",
        ),
        request_sample(
            "unlink request",
            &UnlinkRequest {
                name_len: U32::new(5),
            },
            b"a.txt",
        ),
        request_sample(
            "rmdir request",
            &RmdirRequest {
                name_len: U32::new(3),
            },
            b"dir",
        ),
        request_sample(
            "rename request",
            &RenameRequest {
                new_parent_node_id: U64::new(2),
                flags: U32::ZERO,
                old_name_len: U32::new(3),
                new_name_len: U32::new(3),
                reserved: U32::ZERO,
            },
            b"oldnew",
        ),
        request_sample(
            "link request",
            &LinkRequest {
                target_node_id: U64::new(3),
                name_len: U32::new(4),
                reserved: U32::ZERO,
            },
            b"hard",
        ),
        request_sample(
            "open request",
            &OpenRequest {
                flags: U32::new(2),
                reserved: U32::ZERO,
            },
            &[],
        ),
        request_sample(
            "read request",
            &ReadRequest {
                handle: U64::new(4),
                offset: U64::new(4096),
                size: U32::new(4096),
                flags: U32::ZERO,
            },
            &[],
        ),
        request_sample(
            "write request",
            &WriteRequest {
                handle: U64::new(4),
                offset: U64::new(0),
                data_len: U32::new(5),
                flags: U32::ZERO,
                write_flags: U32::ZERO,
                reserved: U32::ZERO,
            },
            b"bytes",
        ),
        request_sample("statfs request", &StatfsRequest, &[]),
        request_sample(
            "release request",
            &ReleaseRequest {
                handle: U64::new(4),
                lock_owner: U64::new(0x4242),
                flags: U32::ZERO,
                release_flags: U32::ZERO,
            },
            &[],
        ),
        request_sample(
            "fsync request",
            &FsyncRequest {
                handle: U64::new(4),
                flags: U32::new(1),
                reserved: U32::ZERO,
            },
            &[],
        ),
        request_sample(
            "setxattr request",
            &SetxattrRequest {
                flags: U32::ZERO,
                name_len: U32::new(8),
                value_len: U32::new(3),
                reserved: U32::ZERO,
            },
            b"user.fooval",
        ),
        request_sample(
            "getxattr request",
            &GetxattrRequest {
                size: U32::new(64),
                name_len: U32::new(8),
            },
            b"user.foo",
        ),
        request_sample(
            "listxattr request",
            &ListxattrRequest {
                size: U32::new(128),
                reserved: U32::ZERO,
            },
            &[],
        ),
        request_sample(
            "removexattr request",
            &RemovexattrRequest {
                name_len: U32::new(8),
            },
            b"user.foo",
        ),
        request_sample(
            "flush request",
            &FlushRequest {
                handle: U64::new(4),
                lock_owner: U64::new(0x4242),
            },
            &[],
        ),
        request_sample(
            "readdirplus request",
            &ReaddirplusRequest {
                handle: U64::new(4),
                cookie: U64::new(0),
                size: U32::new(4096),
                reserved: U32::ZERO,
            },
            &[],
        ),
        request_sample(
            "create request",
            &CreateRequest {
                flags: U32::new(0o101),
                mode: U32::new(0o644),
                umask: U32::new(0o022),
                name_len: U32::new(5),
            },
            b"a.txt",
        ),
        request_sample(
            "getlk request",
            &GetlkRequest {
                handle: U64::new(4),
                lock: sample_lock(),
            },
            &[],
        ),
        request_sample(
            "setlk request",
            &SetlkRequest {
                handle: U64::new(4),
                lock: sample_lock(),
                flags: U32::ZERO,
                reserved: U32::ZERO,
            },
            &[],
        ),
        request_sample(
            "subscribe request",
            &SubscribeRequest {
                reserved: U32::ZERO,
            },
            &[],
        ),
        request_sample(
            "unsubscribe request",
            &UnsubscribeRequest {
                reserved: U32::ZERO,
            },
            &[],
        ),
    ]
}

/// One valid frame per response opcode, plus the error-response shape. Only
/// `forget` is missing, because it is the one request nothing answers.
fn response_samples() -> Vec<Sample> {
    let mut entry_buf = [0u8; 256];
    let mut entries = DirEntryWriter::new(&mut entry_buf);
    entries
        .push(
            &DirEntryHeader::new(sample_entry(), 1, file_type::DIR, 3),
            b"foo",
        )
        .expect("the entry buffer holds one entry");
    entries
        .push(
            &DirEntryHeader::new(sample_entry(), 2, file_type::REG, 5),
            b"a.txt",
        )
        .expect("the entry buffer holds two entries");
    let entries = entries.finish().to_vec();

    let mut name_buf = [0u8; 64];
    let mut names = XattrNameWriter::new(&mut name_buf);
    names
        .push(&XattrNameHeader::new(8), b"user.foo")
        .expect("the name buffer holds one name");
    names
        .push(&XattrNameHeader::new(10), b"user.other")
        .expect("the name buffer holds two names");
    let names = names.finish().to_vec();

    vec![
        response_sample(
            "hello reply",
            &HelloReply {
                root_node_id: U64::new(1),
                protocol_version: U32::new(PROTOCOL_VERSION),
                flags: U32::ZERO,
                max_frame_len: U32::new(0x0010_0000),
                reserved: U32::ZERO,
            },
            &[],
        ),
        response_sample(
            "lookup response",
            &LookupResponse {
                entry: sample_entry(),
            },
            &[],
        ),
        response_sample(
            "getattr response",
            &GetattrResponse {
                attr: sample_attr(),
            },
            &[],
        ),
        response_sample(
            "setattr response",
            &SetattrResponse {
                attr: sample_attr(),
            },
            &[],
        ),
        response_sample(
            "readlink response",
            &ReadlinkResponse {
                target_len: U32::new(6),
            },
            b"../tgt",
        ),
        response_sample(
            "symlink response",
            &SymlinkResponse {
                entry: sample_entry(),
            },
            &[],
        ),
        response_sample(
            "mkdir response",
            &MkdirResponse {
                entry: sample_entry(),
            },
            &[],
        ),
        response_sample(
            "mknod response",
            &MknodResponse {
                entry: sample_entry(),
            },
            &[],
        ),
        response_sample("unlink response", &UnlinkResponse, &[]),
        response_sample("rmdir response", &RmdirResponse, &[]),
        response_sample("rename response", &RenameResponse, &[]),
        response_sample(
            "link response",
            &LinkResponse {
                entry: sample_entry(),
            },
            &[],
        ),
        response_sample(
            "open response",
            &OpenResponse {
                handle: U64::new(4),
                flags: U32::ZERO,
                reserved: U32::ZERO,
            },
            &[],
        ),
        response_sample(
            "read response",
            &ReadResponse {
                data_len: U32::new(9),
            },
            b"file data",
        ),
        response_sample(
            "write response",
            &WriteResponse {
                written: U32::new(5),
            },
            &[],
        ),
        response_sample(
            "statfs response",
            &StatfsResponse {
                blocks: U64::new(1024),
                bfree: U64::new(512),
                bavail: U64::new(256),
                files: U64::new(64),
                ffree: U64::new(32),
                bsize: U32::new(4096),
                namelen: U32::new(255),
                frsize: U32::new(4096),
                reserved: U32::ZERO,
            },
            &[],
        ),
        response_sample("release response", &ReleaseResponse, &[]),
        response_sample("fsync response", &FsyncResponse, &[]),
        response_sample("setxattr response", &SetxattrResponse, &[]),
        response_sample(
            "getxattr response",
            &GetxattrResponse {
                size: U32::new(3),
                value_len: U32::new(3),
            },
            b"val",
        ),
        response_sample(
            "listxattr response",
            &ListxattrResponse {
                size: U32::new(20),
                list_len: U32::new(names.len() as u32),
            },
            &names,
        ),
        response_sample("removexattr response", &RemovexattrResponse, &[]),
        response_sample("flush response", &FlushResponse, &[]),
        response_sample(
            "readdirplus response",
            &ReaddirplusResponse {
                entries_len: U32::new(entries.len() as u32),
            },
            &entries,
        ),
        response_sample(
            "create response",
            &CreateResponse {
                entry: sample_entry(),
                handle: U64::new(4),
                flags: U32::ZERO,
                reserved: U32::ZERO,
            },
            &[],
        ),
        response_sample(
            "getlk response",
            &GetlkResponse {
                lock: sample_lock(),
            },
            &[],
        ),
        response_sample("setlk response", &SetlkResponse, &[]),
        response_sample(
            "subscribe response",
            &SubscribeResponse {
                reserved: U32::ZERO,
            },
            &[],
        ),
        response_sample(
            "unsubscribe response",
            &UnsubscribeResponse {
                reserved: U32::ZERO,
            },
            &[],
        ),
        error_sample("lookup error response", Opcode::Lookup, -2),
        error_sample("read error response", Opcode::Read, ENOSYS),
    ]
}

/// One valid frame per notification opcode.
fn notification_samples() -> Vec<Sample> {
    let mut entry_buf = [0u8; 128];
    let mut entries = ShareEntryWriter::new(&mut entry_buf);
    entries
        .push(
            &ShareEntryHeader::new(SHARE_MODE_RW, SHARE_KIND_DIRECTORY, 5),
            b"/docs",
        )
        .expect("the entry buffer holds one entry");
    entries
        .push(
            &ShareEntryHeader::new(SHARE_MODE_RO, SHARE_KIND_FILE, 9),
            b"/read.txt",
        )
        .expect("the entry buffer holds two entries");
    let entries = entries.finish().to_vec();

    vec![
        notification_sample(
            "share snapshot begin",
            &ShareSnapshotBegin {
                entries: U32::new(2),
                reserved: U32::ZERO,
            },
            &[],
        ),
        notification_sample(
            "share snapshot part",
            &ShareSnapshotPart {
                entries: U32::new(2),
                entries_len: U32::new(entries.len() as u32),
            },
            &entries,
        ),
        notification_sample(
            "share snapshot end",
            &ShareSnapshotEnd {
                reserved: U32::ZERO,
            },
            &[],
        ),
        notification_sample(
            "share added",
            &ShareAdded {
                mode: U16::new(SHARE_MODE_RW),
                kind: U16::new(SHARE_KIND_DIRECTORY),
                path_len: U32::new(5),
            },
            b"/docs",
        ),
        notification_sample(
            "share removed",
            &ShareRemoved {
                path_len: U32::new(9),
            },
            b"/read.txt",
        ),
        notification_sample(
            "share changed",
            &ShareChanged {
                mode: U16::new(SHARE_MODE_RO),
                kind: U16::new(SHARE_KIND_FILE),
                path_len: U32::new(9),
            },
            b"/read.txt",
        ),
        notification_sample(
            "share ended",
            &ShareEnded {
                reason: U32::new(SHARE_END_NAMESPACE_REMOVED),
            },
            &[],
        ),
    ]
}

/// Every valid frame the mutation and truncation generators start from.
fn valid_frames() -> Vec<Sample> {
    let mut samples = request_samples();
    samples.extend(response_samples());
    samples.extend(notification_samples());
    samples
}

/// Generator 1: arbitrary bytes are refused, or accepted as something whose
/// own lengths and slices hold up.
///
/// A random 32-bit length practically never describes the buffer it sits in,
/// so what this generator proves in practice is the refusal side: every entry
/// point answers, `peek_len` never reports a length outside the legal range,
/// and the two parse entry points never disagree. The acceptance checks run
/// all the same and are what would catch a length field that stopped being
/// checked — generators 2 and 3 are what exercise them frame after frame.
#[test]
fn noise_is_refused_or_self_consistent() {
    let mut rng = Rng(NOISE_SEED);
    for index in 0..NOISE_CASES * rounds() {
        // Mostly frame-sized buffers, where a random header has a real chance
        // of describing the bytes that follow; sometimes up to twice the
        // maximum frame length, which is the largest a reader ever holds.
        let len = if rng.below(4) == 0 {
            rng.below(2 * MAX as usize + 1)
        } else {
            rng.below(193)
        };
        let buf = rng.bytes(len);
        // Both bounds: the pre-handshake one, and one that cannot save a
        // parse, so the length checks stand on their own.
        check_buffer(&buf, MAX, Case::seeded("noise", index, NOISE_SEED));
        check_buffer(&buf, u32::MAX, Case::seeded("noise", index, NOISE_SEED));
    }
}

/// Generator 2: a valid frame with one byte rewritten, or one header bit
/// flipped, is either refused or still self-consistent. A length field that a
/// mutation made larger can never make a payload slice escape the buffer.
#[test]
fn single_change_mutations_stay_self_consistent() {
    let samples = valid_frames();
    let mut rng = Rng(MUTATION_SEED);
    let mut index = 0;
    for _ in 0..MUTATION_PASSES * rounds() {
        for sample in &samples {
            for at in 0..sample.bytes.len() {
                let mut mutated = sample.bytes.clone();
                // A nonzero mask, so every case really is a changed frame.
                mutated[at] ^= rng.next_u8() | 1;
                check_buffer(
                    &mutated,
                    MAX,
                    Case::seeded(sample.label, index, MUTATION_SEED),
                );
                index += 1;
            }
            for bit in 0..FRAME_HEADER_LEN * 8 {
                let mut mutated = sample.bytes.clone();
                mutated[bit / 8] ^= 1 << (bit % 8);
                check_buffer(
                    &mutated,
                    MAX,
                    Case::seeded(sample.label, index, MUTATION_SEED),
                );
                index += 1;
            }
        }
    }
}

/// Generator 3: a valid frame cut short is never accepted. The parser either
/// asks for more bytes than are buffered, or refuses outright — it never
/// reports a frame that ends inside the data it has.
#[test]
fn truncations_never_succeed_past_the_data() {
    for sample in valid_frames() {
        let full = &sample.bytes;
        for cut in 0..full.len() {
            let case = Case::exhaustive(sample.label, cut);
            let prefix = &full[..cut];

            match Frame::peek_len(prefix, MAX) {
                Ok(None) => assert!(
                    cut < FRAME_HEADER_LEN,
                    "{case}: peek_len asked for a header it already has"
                ),
                Ok(Some(len)) => assert!(
                    len as usize > cut,
                    "{case}: peek_len claims a {len}-byte frame ends inside {cut} buffered bytes"
                ),
                Err(error) => panic!("{case}: the header of a valid frame must peek: {error}"),
            }

            match Frame::parse_prefix(prefix, MAX) {
                Err(FramingError::Incomplete { needed }) => assert!(
                    needed > cut,
                    "{case}: the parser asked for {needed} bytes, no more than the {cut} buffered"
                ),
                Err(error) => {
                    panic!("{case}: a truncated valid frame must be incomplete, got {error}")
                }
                Ok(_) => panic!("{case}: parse_prefix accepted a frame past the end of the data"),
            }
            assert!(
                Frame::parse(prefix, MAX).is_err(),
                "{case}: parse accepted a truncated frame"
            );
        }

        // The uncut frame is the control: it parses, and everything it hands
        // back holds up.
        let case = Case::exhaustive(sample.label, full.len());
        assert!(
            Frame::parse(full, MAX).is_ok(),
            "{case}: the sample frame itself must parse"
        );
        check_buffer(full, MAX, case);
    }
}
