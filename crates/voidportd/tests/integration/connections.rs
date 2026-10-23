#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rustix::fs::OFlags;
use support::fixture::Fixture;
use support::wire::{DirEntry, ROOT, Settled, WireClient, status};
use support::{Dial as _, TempDir};
use voidport_control::{
    NamespaceName, OwnershipSpec, Request, Rule, SessionSummary, ShareMode, UnmappedPolicy,
};
use voidport_proto::frame::{FRAME_HEADER_LEN, Frame};
use voidport_proto::limits::LIMITS;
use voidport_proto::message::{REQUEST_HEAD_LEN, ResponseOutcome};
use voidport_proto::ops::connection::{OutcomeRequest, RetireRequest};
use voidport_proto::ops::dir::{DirEntryHeader, ReaddirplusRequest, ReaddirplusResponse};
use voidport_proto::ops::file::{
    FileLock, SetlkRequest, SetlkResponse, WriteResponse, lock_type, setlk_flags,
};
use voidport_proto::ops::handshake::{HelloReply, HelloRequest};
use voidport_proto::ops::node::{ForgetRequest, LookupResponse};
use voidport_proto::piece::PIECE_LEN_LEN;
use zerocopy::byteorder::little_endian::{U32, U64};

fn sessions(fixture: &Fixture) -> Vec<SessionSummary> {
    fixture.server.service().sessions().list()
}

fn session(fixture: &Fixture) -> SessionSummary {
    let mut sessions = sessions(fixture);
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    sessions.remove(0)
}

fn join(fixture: &Fixture, first: &WireClient) -> WireClient {
    let mut joined = fixture.server.dial();
    joined
        .join(first.token())
        .unwrap_or_else(|status| panic!("the join was refused with {status}"));
    joined
}

fn key_file(directory: &TempDir, name: &str) -> (std::path::PathBuf, SigningKey) {
    let mut seed = [0u8; 32];
    rustix::rand::getrandom(&mut seed, rustix::rand::GetRandomFlags::empty()).expect("random");
    let key = SigningKey::from_bytes(&seed);
    let pem = key.to_pkcs8_pem(LineEnding::LF).expect("an encodable key");
    (directory.write(name, &pem), key)
}

fn signing_key(path: &Path) -> String {
    format!("signing_key = \"{}\"", path.display())
}

fn claims(token: &[u8]) -> serde_json::Value {
    jsonwebtoken::dangerous::insecure_decode::<serde_json::Value>(token)
        .expect("a token")
        .claims
}

#[test]
fn a_join_attaches_a_second_connection_to_the_live_session() {
    let fixture = Fixture::start("join-attaches");
    let mut first = fixture.server.mount("plain", "/tree");
    assert!(
        !first.token().is_empty(),
        "the reply carries the session's token"
    );
    let data = first.lookup(ROOT, "data.bin").expect("a file");

    let mut second = fixture.server.dial();
    let reply = second.join(first.token()).expect("joined");
    assert_eq!(reply.root_node_id.get(), ROOT);
    assert_eq!(
        second.token(),
        first.token(),
        "every connection gets the same token"
    );
    assert_ne!(second.connection_id(), first.connection_id());
    assert_eq!(session(&fixture).connections, 2);
    assert_eq!(
        second
            .getattr(data.node_id)
            .expect("the same node")
            .size
            .get(),
        10
    );
}

#[test]
fn a_join_with_a_token_that_does_not_verify_is_refused_with_eacces() {
    let fixture = Fixture::start("join-unverified");
    let first = fixture.server.mount("plain", "/tree");
    let token = first.token().to_vec();

    let mut changed = token.clone();
    let last = changed.len() - 2;
    changed[last] = if changed[last] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        fixture.server.dial().join(&changed).err(),
        Some(status::ACCESS)
    );

    let (_, other) = key_file(&fixture.directory, "other.pem");
    let other = jsonwebtoken::encode(
        &Header::new(Algorithm::EdDSA),
        &claims(&token),
        &EncodingKey::from_ed_der(other.to_pkcs8_der().expect("encodable").as_bytes()),
    )
    .expect("signed");
    assert_eq!(
        fixture.server.dial().join(other.as_bytes()).err(),
        Some(status::ACCESS)
    );

    let hmac = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims(&token),
        &EncodingKey::from_secret(b"a shared secret"),
    )
    .expect("signed");
    // The token fits the length bound, so the refusal comes from the signature.
    assert!(hmac.len() <= token.len(), "the token fits the length bound");
    assert_eq!(
        fixture.server.dial().join(hmac.as_bytes()).err(),
        Some(status::ACCESS)
    );
    assert_eq!(session(&fixture).connections, 1);
}

#[test]
fn a_join_with_the_token_of_an_ended_session_is_refused_with_enoent() {
    let fixture = Fixture::start("join-ended");
    let first = fixture.server.mount("plain", "/tree");
    let token = first.token().to_vec();
    first.disconnect(&fixture.server);
    assert!(sessions(&fixture).is_empty());
    assert_eq!(
        fixture.server.dial().join(&token).err(),
        Some(status::NOENT)
    );
}

#[test]
fn a_join_carrying_a_namespace_or_a_subpath_is_refused() {
    let fixture = Fixture::start("join-namespace");
    let first = fixture.server.mount("plain", "/tree");
    assert_eq!(
        fixture
            .server
            .dial()
            .join_with(first.token(), b"plain", b"")
            .err(),
        Some(status::INVAL)
    );
    assert_eq!(
        fixture
            .server
            .dial()
            .join_with(first.token(), b"", b"/tree")
            .err(),
        Some(status::INVAL)
    );
    assert_eq!(session(&fixture).connections, 1);
}

/// The length of the longest token in the format of the server: the token of the
/// largest session id, with the process id `token` names and a signature of
/// the one length Ed25519 signatures have.
fn longest_token(token: &[u8]) -> usize {
    let (_, key) = key_file(&TempDir::new("longest-token-key"), "key.pem");
    let claims = serde_json::json!({
        "sub": u64::MAX.to_string(),
        "iss": claims(token)["iss"],
    });
    jsonwebtoken::encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &EncodingKey::from_ed_der(key.to_pkcs8_der().expect("encodable").as_bytes()),
    )
    .expect("signed")
    .len()
}

fn join_hello_head(client: &mut WireClient, token_len: usize) -> Vec<u8> {
    let body = HelloRequest::join(u32::try_from(token_len).expect("a token length"));
    let (_, mut bytes) = client.encoded(0, &body, &vec![b'x'; token_len]);
    bytes.truncate(FRAME_HEADER_LEN + REQUEST_HEAD_LEN + size_of::<HelloRequest>());
    bytes
}

#[test]
fn a_join_stating_a_token_longer_than_the_format_is_refused_unread() {
    let fixture = Fixture::start("join-too-long");
    let first = fixture.server.mount("plain", "/tree");
    let longest = longest_token(first.token());
    assert!(first.token().len() <= longest);

    let mut joining = fixture.server.dial();
    let head = join_hello_head(&mut joining, longest + 1);
    joining.send_bytes(&head);
    let (_, status) = joining.receive_status::<HelloReply>();
    assert_eq!(status, status::NOENT);
    assert!(joining.receive().is_none(), "the connection ends");
    assert_eq!(session(&fixture).connections, 1);
}

#[test]
fn a_join_to_a_server_with_no_session_is_judged_by_its_token() {
    let directory = TempDir::new("join-no-session-key");
    let (path, _) = key_file(&directory, "signing.pem");
    let minting = Fixture::start_with("join-no-session-minting", &signing_key(&path));
    let empty = Fixture::start_with("join-no-session-empty", &signing_key(&path));
    let token = minting.server.mount("plain", "/tree").token().to_vec();
    assert!(sessions(&empty).is_empty());

    let mut changed = token.clone();
    let last = changed.len() - 2;
    changed[last] = if changed[last] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        empty.server.dial().join(&changed).err(),
        Some(status::ACCESS)
    );
    assert_eq!(empty.server.dial().join(&token).err(), Some(status::NOENT));
    assert!(sessions(&empty).is_empty());
}

#[test]
fn the_session_ends_with_its_last_connection_and_not_before() {
    let fixture = Fixture::start("session-last");
    let mut first = fixture.server.mount("plain", "/tree");
    first.lookup(ROOT, "data.bin").expect("a file");
    let mut second = join(&fixture, &first);
    let nodes = session(&fixture).nodes;
    drop(first);
    // A request answered after the other connection left is answered in the same
    // session.
    fixture.server.until(|| session(&fixture).connections == 1);
    second.getattr(ROOT).expect("the session serves on");
    assert_eq!(session(&fixture).nodes, nodes, "nothing was torn down");
    second.disconnect(&fixture.server);
    assert!(
        sessions(&fixture).is_empty(),
        "the last connection ended it"
    );
}

#[test]
fn a_server_signs_with_the_key_it_generated_or_was_given() {
    let fixture = Fixture::start("key-generated");
    let first = fixture.server.mount("plain", "/tree");
    let header = jsonwebtoken::decode_header(first.token()).expect("a token");
    assert_eq!(header.alg, Algorithm::EdDSA);
    let generated = claims(first.token());
    assert!(generated.get("exp").is_none(), "no expiry: {generated}");
    assert!(generated["sub"].is_string() && generated["iss"].is_string());

    let directory = TempDir::new("key-given-file");
    let (path, key) = key_file(&directory, "signing.pem");
    let given = Fixture::start_with("key-given", &signing_key(&path));
    let mounted = given.server.mount("plain", "/tree");
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.required_spec_claims = ["sub", "iss"].map(str::to_owned).into();
    validation.validate_exp = false;
    let verified = jsonwebtoken::decode::<serde_json::Value>(
        mounted.token(),
        &DecodingKey::from_ed_der(key.verifying_key().as_bytes()),
        &validation,
    )
    .expect("the file's key signed it");
    assert_eq!(
        verified.claims["sub"],
        session(&given).id.to_string(),
        "it names the session"
    );
}

#[test]
fn a_token_of_another_server_sharing_the_key_is_refused_with_enoent() {
    let directory = TempDir::new("key-shared-file");
    let (path, _) = key_file(&directory, "signing.pem");
    let one = Fixture::start_with("key-shared-one", &signing_key(&path));
    let two = Fixture::start_with("key-shared-two", &signing_key(&path));
    let mounted = one.server.mount("plain", "/tree");
    assert_eq!(
        two.server.dial().join(mounted.token()).err(),
        Some(status::NOENT)
    );
    join(&one, &mounted);
}

#[test]
fn a_join_after_a_restart_is_refused() {
    let directory = TempDir::new("key-restart-file");
    let (path, _) = key_file(&directory, "signing.pem");
    let mut fixture = Fixture::start_with("key-restart", &signing_key(&path));
    let token = fixture.server.mount("plain", "/tree").token().to_vec();
    fixture.server.stop();
    let config = voidport_test_support::daemon_config(&fixture.join("state.toml"));
    fixture.server = support::RunningServer::start(&config).expect("the server starts again");
    assert_eq!(
        fixture.server.dial().join(&token).err(),
        Some(status::NOENT)
    );
}

#[test]
fn a_key_file_that_is_missing_or_malformed_stops_the_server() {
    let directory = TempDir::new("key-refused");
    let missing = directory.join("absent.pem");
    let malformed = directory.write("malformed.pem", "not a key\n");
    for path in [missing, malformed] {
        let state = directory.write("state.toml", &format!("[server]\n{}\n", signing_key(&path)));
        let config = voidport_test_support::daemon_config(&state);
        let error = support::RunningServer::start(&config)
            .expect_err("a key the server cannot use stops it")
            .to_string();
        assert!(error.contains("server.signing_key"), "{error}");
        assert!(error.contains(&path.display().to_string()), "{error}");
    }
}

#[test]
fn an_outcome_closes_the_connection_it_names_and_answers_the_kept_reply() {
    let fixture = Fixture::start("outcome-kept");
    let mut first = fixture.server.mount("plain", "/tree");
    let (lookup, bytes) = first.encoded(ROOT, &lookup_request(), b"data.bin");
    first.send_bytes(&bytes);
    let answered = first.receive().expect("answered");

    let mut second = join(&fixture, &first);
    let mut asking = join(&fixture, &first);
    let (_, bytes) = asking.encoded(0, &outcome_request(first.connection_id(), lookup), &[]);
    asking.send_bytes(&bytes);
    drop(asking);

    let Settled::Replied(kept) = second
        .outcome(first.connection_id(), lookup)
        .expect("an answer")
    else {
        panic!("the lookup finished");
    };
    assert_eq!(kept, answered, "the kept reply is the reply");
    let frame = Frame::parse(&kept, &LIMITS).expect("a reply");
    assert!(matches!(
        frame.response::<LookupResponse>(),
        Ok(ResponseOutcome::Success(_))
    ));
    assert_eq!(
        second.outcome(first.connection_id(), lookup),
        Ok(Settled::Replied(kept)),
        "asked twice, the same answer"
    );
    assert!(first.receive().is_none(), "the named connection was closed");
    assert_eq!(
        second.outcome(first.connection_id(), lookup + 1),
        Ok(Settled::NotStarted),
        "a request never read"
    );
    assert_eq!(
        second.outcome(99, 1).err(),
        Some(status::NOENT),
        "an id the session never gave out"
    );
    assert_eq!(second.outcome(0, 1).err(), Some(status::NOENT), "zero");
    let own = second.connection_id();
    assert_eq!(
        second.outcome(own, 1).err(),
        Some(status::INVAL),
        "a connection cannot wait for itself"
    );
}

#[test]
fn retiring_a_connection_closes_it_and_drops_its_records() {
    let fixture = Fixture::start("retire");
    let mut first = fixture.server.mount("plain", "/tree");
    first.lookup(ROOT, "data.bin").expect("a file");
    let mut second = join(&fixture, &first);
    second.retire(first.connection_id()).expect("retired");
    assert!(
        first.receive().is_none(),
        "the open connection was closed first"
    );
    assert_eq!(
        second.outcome(first.connection_id(), 2).err(),
        Some(status::STALE)
    );
    second
        .retire(first.connection_id())
        .expect("retiring again is answered the same");
    assert_eq!(session(&fixture).connections, 1);
    assert_eq!(second.retire(0).err(), Some(status::NOENT), "zero");
    assert_eq!(
        second.retire(99).err(),
        Some(status::NOENT),
        "an id the session never gave out"
    );
    let own = second.connection_id();
    assert_eq!(
        second.retire(own).err(),
        Some(status::INVAL),
        "a connection cannot wait for itself"
    );
}

#[test]
fn joins_dropped_before_a_request_leave_nothing_held() {
    let fixture = Fixture::start("join-dropped");
    let mut first = fixture.server.mount("plain", "/tree");

    let joined = join(&fixture, &first);
    let joined_id = joined.connection_id();
    assert_eq!(session(&fixture).connections, 2);
    drop(joined);
    fixture.server.until(|| session(&fixture).connections == 1);

    // The server answered this hello, so it attached the connection, and the
    // end of the stream closes it; the reply is never read.
    let mut unread = fixture.server.dial();
    let token = first.token().to_vec();
    let (_, hello) = unread.encoded(0, &HelloRequest::join(token.len() as u32), &token);
    unread.send_bytes(&hello);
    unread.shutdown_write();
    fixture.server.until(|| unread.unread() > 0);
    fixture.server.until(|| session(&fixture).connections == 1);
    let reply = unread.receive().expect("the hello reply");
    let Ok(ResponseOutcome::Success(reply)) = Frame::parse(&reply, &LIMITS)
        .expect("a reply")
        .response::<HelloReply>()
    else {
        panic!("the join was answered");
    };
    let unread_id = reply.body().connection_id.get();
    for id in [joined_id, unread_id] {
        assert_eq!(
            first.outcome(id, 1).err(),
            Some(status::STALE),
            "nothing is held for connection {id}"
        );
    }
}

#[test]
fn an_outcome_for_a_connection_that_read_nothing_is_stale() {
    let fixture = Fixture::start("outcome-nothing-read");
    let mut first = fixture.server.mount("plain", "/tree");
    let mut idle = join(&fixture, &first);
    let id = idle.connection_id();
    assert_eq!(first.outcome(id, 1).err(), Some(status::STALE));
    assert!(idle.receive().is_none(), "it was closed first");
    first.retire(id).expect("answered as retired");
}

// Whichever request the server reads first, both connections get a reply or
// end.
#[test]
fn settlement_requests_naming_each_other_both_end() {
    let fixture = Fixture::start("settle-each-other");
    let third = fixture.server.mount("plain", "/tree");
    let mut asking = join(&fixture, &third);
    let mut retiring = join(&fixture, &third);

    let (_, outcome) = asking.encoded(0, &outcome_request(retiring.connection_id(), 1), &[]);
    let retire = RetireRequest {
        connection_id: U64::new(asking.connection_id()),
    };
    let (_, retire) = retiring.encoded(0, &retire, &[]);
    asking.send_bytes(&outcome);
    retiring.send_bytes(&retire);

    asking.receive();
    retiring.receive();
}

#[test]
fn a_forget_read_before_the_connection_closed_is_applied() {
    let fixture = Fixture::start("outcome-forget");
    let mut first = fixture.server.mount("plain", "/tree");
    let base = session(&fixture).nodes;
    let node = first.lookup(ROOT, "data.bin").expect("a file").node_id;
    assert_eq!(session(&fixture).nodes, base + 1);
    let forget = first.forget_counted(node, 1);
    first.fence();
    let mut second = join(&fixture, &first);
    assert_eq!(
        second.outcome(first.connection_id(), forget),
        Ok(Settled::Applied)
    );
    assert_eq!(session(&fixture).nodes, base, "applied once");
}

#[test]
fn a_write_cut_off_answers_a_short_count_or_never_started() {
    let fixture = Fixture::start("outcome-write");
    let host = fixture.tree("data.bin");
    let piece = fs::metadata(&host).expect("stat").blksize() as usize;
    let data = vec![b'w'; 3 * piece];

    let cut = |through: usize, flags: OFlags| {
        let mut first = fixture.server.mount("plain", "/tree");
        let asking = join(&fixture, &first);
        let node = first.lookup(ROOT, "data.bin").expect("a file").node_id;
        let handle = first.open(node, flags).expect("opens");
        let (write, bytes) = first.write_request(handle, 0, &data);
        let frame = bytes.len() - data.len();
        first.send_bytes(&bytes[..frame + through]);
        first.shutdown_write();
        (first, asking, write)
    };

    fs::write(&host, b"").expect("an empty file");
    let (first, mut asking, write) = cut(piece + piece / 2, OFlags::RDWR);
    // The first piece reaches the file before the question is asked: asking
    // closes the connection, and a write it closed first never started.
    fixture
        .server
        .until(|| fs::read(&host).expect("host").len() >= piece);
    let Settled::Replied(kept) = asking
        .outcome(first.connection_id(), write)
        .expect("an answer")
    else {
        panic!("some of the write was written");
    };
    let frame = Frame::parse(&kept, &LIMITS).expect("a reply");
    let Ok(ResponseOutcome::Success(reply)) = frame.response::<WriteResponse>() else {
        panic!("a short write");
    };
    assert_eq!(reply.body().written.get() as usize, piece);
    drop((first, asking));

    let (first, mut asking, write) = cut(0, OFlags::RDWR);
    assert_eq!(
        asking.outcome(first.connection_id(), write),
        Ok(Settled::NotStarted)
    );
    drop((first, asking));

    let appending = OFlags::RDWR | OFlags::APPEND;
    let before = fs::read(&host).expect("host");
    let (first, mut asking, write) = cut(piece, appending);
    assert_eq!(
        asking.outcome(first.connection_id(), write),
        Ok(Settled::NotStarted)
    );
    assert_eq!(
        fs::read(&host).expect("host"),
        before,
        "nothing was appended"
    );
}

/// The smallest offset at which a one-byte write fails, with `EFBIG` or `EINVAL`.
/// Found by writing into a probe file beside `path`, which is removed after.
fn refused_from(path: &Path) -> u64 {
    use std::os::unix::fs::FileExt as _;

    let probe_path = path.with_extension("probe");
    let probe = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&probe_path)
        .expect("a probe file");
    let refused = |offset: u64| match probe.write_at(b"p", offset) {
        Ok(_) => false,
        Err(error) if matches!(error.raw_os_error(), Some(27 | 22)) => true,
        Err(error) => panic!("a probe write at {offset} failed: {error}"),
    };
    let (mut low, mut high) = (0u64, i64::MAX as u64);
    assert!(!refused(low) && refused(high));
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if refused(middle) {
            high = middle;
        } else {
            low = middle;
        }
    }
    drop(probe);
    fs::remove_file(&probe_path).expect("the probe goes");
    high
}

#[test]
fn a_write_refused_part_way_by_its_host_keeps_its_short_count_through_the_drain() {
    let fixture = Fixture::start("outcome-write-refused");
    let host = fixture.tree("data.bin");
    let piece = fs::metadata(&host).expect("stat").blksize();
    let offset = refused_from(&host) - piece;
    let data = vec![b'r'; 4 * usize::try_from(piece).expect("a piece")];

    let mut first = fixture.server.mount("plain", "/tree");
    let mut asking = join(&fixture, &first);
    let node = first.lookup(ROOT, "data.bin").expect("a file").node_id;
    let handle = first.open(node, OFlags::RDWR).expect("opens");
    let (write, bytes) = first.write_request(handle, offset, &data);
    let frame = bytes.len() - data.len();
    first.send_bytes(&bytes[..frame + data.len() * 3 / 4]);
    first.shutdown_write();
    fixture.server.until(|| session(&fixture).connections == 1);

    let Settled::Replied(kept) = asking
        .outcome(first.connection_id(), write)
        .expect("an answer")
    else {
        panic!("the host took the first piece");
    };
    let frame = Frame::parse(&kept, &LIMITS).expect("a reply");
    let Ok(ResponseOutcome::Success(reply)) = frame.response::<WriteResponse>() else {
        panic!("a short write");
    };
    assert_eq!(u64::from(reply.body().written.get()), piece);
    assert_eq!(fs::metadata(&host).expect("stat").len(), offset + piece);
}

fn lock_holder(fixture: &Fixture) -> (WireClient, u64) {
    let mut holder = fixture.server.mount("plain", "/tree");
    let node = holder.lookup(ROOT, "data.bin").expect("a file").node_id;
    let handle = holder.open(node, OFlags::RDWR).expect("opens");
    holder
        .setlk(handle, whole(1, lock_type::WRITE), false)
        .expect("the first lock holder locks");
    (holder, handle)
}

#[test]
fn a_lock_request_on_a_held_range_whose_connection_closes_never_started() {
    let fixture = Fixture::start("outcome-lock");
    let mut first = fixture.server.mount("plain", "/tree");
    let node = first.lookup(ROOT, "data.bin").expect("a file").node_id;
    let handle = first.open(node, OFlags::RDWR).expect("opens");
    let mut asking = join(&fixture, &first);
    let _holder = lock_holder(&fixture);
    let waiting = first.send(
        0,
        &SetlkRequest {
            handle: U64::new(handle),
            lock: whole(2, lock_type::WRITE),
            flags: U32::new(setlk_flags::WAIT),
            reserved: U32::ZERO,
        },
        &[],
    );
    // A reply to a later request shows the server has read the lock request.
    first.fence();
    assert_eq!(
        asking.outcome(first.connection_id(), waiting),
        Ok(Settled::NotStarted)
    );
    assert_eq!(
        asking
            .getlk(handle, whole(3, lock_type::WRITE))
            .expect("tested")
            .lock_type
            .get(),
        lock_type::WRITE,
        "the lock is still held by its holder"
    );
}

#[test]
fn a_lock_granted_as_its_connection_closes_is_cancelled_or_kept() {
    let fixture = Fixture::start("outcome-lock-grant");
    let mut first = fixture.server.mount("plain", "/tree");
    let node = first.lookup(ROOT, "data.bin").expect("a file").node_id;
    let handle = first.open(node, OFlags::RDWR).expect("opens");
    let mut asking = join(&fixture, &first);
    let (mut holder, held) = lock_holder(&fixture);
    let waiting = first.send(
        0,
        &SetlkRequest {
            handle: U64::new(handle),
            lock: whole(2, lock_type::WRITE),
            flags: U32::new(setlk_flags::WAIT),
            reserved: U32::ZERO,
        },
        &[],
    );
    // A reply to a later request shows the server has read the lock request.
    first.fence();

    let unlock = SetlkRequest {
        handle: U64::new(held),
        lock: whole(1, lock_type::UNLOCK),
        flags: U32::ZERO,
        reserved: U32::ZERO,
    };
    holder.send(0, &unlock, &[]);
    let answer = asking
        .outcome(first.connection_id(), waiting)
        .expect("an answer");
    holder.receive().expect("the unlock is answered");
    let conflict = |client: &mut WireClient| {
        client
            .getlk(handle, whole(3, lock_type::WRITE))
            .expect("tested")
            .lock_type
            .get()
    };
    match answer {
        Settled::NotStarted => {
            assert_eq!(
                conflict(&mut asking),
                lock_type::UNLOCK,
                "a cancelled request took nothing"
            );
            asking
                .setlk(handle, whole(2, lock_type::WRITE), true)
                .expect("sent again, it takes the lock");
            assert_eq!(conflict(&mut asking), lock_type::WRITE);
        }
        Settled::Replied(kept) => {
            let frame = Frame::parse(&kept, &LIMITS).expect("a reply");
            assert!(
                matches!(
                    frame.response::<SetlkResponse>(),
                    Ok(ResponseOutcome::Success(_))
                ),
                "the kept reply grants the lock"
            );
            assert_eq!(conflict(&mut asking), lock_type::WRITE, "and it is held");
        }
        Settled::Applied => panic!("a lock request is never answered as applied"),
    }
}

#[test]
fn a_cancelled_lock_wait_ends_with_eintr_and_takes_nothing() {
    let fixture = Fixture::start("cancel-lock");
    let mut first = fixture.server.mount("plain", "/tree");
    let node = first.lookup(ROOT, "data.bin").expect("a file").node_id;
    let handle = first.open(node, OFlags::RDWR).expect("opens");
    let (mut holder, held) = lock_holder(&fixture);
    let waiting = first.send(
        0,
        &SetlkRequest {
            handle: U64::new(handle),
            lock: whole(2, lock_type::WRITE),
            flags: U32::new(setlk_flags::WAIT),
            reserved: U32::ZERO,
        },
        &[],
    );
    first.cancel(waiting);
    assert_eq!(
        first.receive_status::<SetlkResponse>(),
        (waiting, status::INTR)
    );

    holder
        .setlk(held, whole(1, lock_type::UNLOCK), false)
        .expect("the holder lets go");
    let mut asking = join(&fixture, &first);
    let Ok(Settled::Replied(kept)) = asking.outcome(first.connection_id(), waiting) else {
        panic!("the session stores the reply of the cancelled request");
    };
    let frame = Frame::parse(&kept, &LIMITS).expect("a reply");
    assert!(matches!(
        frame.response::<SetlkResponse>(),
        Ok(ResponseOutcome::Error(status::INTR))
    ));
    assert_eq!(
        asking
            .getlk(handle, whole(3, lock_type::WRITE))
            .expect("tested")
            .lock_type
            .get(),
        lock_type::UNLOCK,
        "the cancelled request placed no lock"
    );
}

#[test]
fn a_cancel_of_a_request_that_does_not_wait_has_no_effect() {
    let fixture = Fixture::start("cancel-unwaited");
    let mut client = fixture.server.mount("plain", "/tree");
    let node = client.lookup(ROOT, "data.bin").expect("a file").node_id;
    let handle = client.open(node, OFlags::RDWR).expect("opens");
    let (write, bytes) = client.write_request(handle, 0, b"written");
    client.send_bytes(&bytes);
    client.cancel(write);
    assert_eq!(client.receive_written(), (write, Ok(7)));
    assert_eq!(
        &fs::read(fixture.tree("data.bin")).expect("readable")[..7],
        b"written"
    );
}

#[test]
fn a_listing_is_kept_whole_and_counted_once() {
    let fixture = Fixture::start("outcome-listing");
    let many = fixture.tree("many");
    voidport_test_support::create_directory(&many);
    for index in 0..30 {
        fs::write(many.join(format!("f{index:02}")), b"x").expect("a file");
    }
    let mut first = fixture.server.mount("plain", "/tree");
    let directory = first.lookup(ROOT, "many").expect("a directory").node_id;
    let handle = first.open(directory, OFlags::RDONLY).expect("opens");
    let base = session(&fixture).nodes;
    let listing = first.send(
        directory,
        &ReaddirplusRequest {
            handle: U64::new(handle),
            cookie: U64::ZERO,
            size: U32::new(65536),
            reserved: U32::ZERO,
        },
        &[],
    );
    let received = first.receive_message().expect("the listing");
    let mut asking = join(&fixture, &first);
    let Settled::Replied(kept) = asking
        .outcome(first.connection_id(), listing)
        .expect("an answer")
    else {
        panic!("the listing finished");
    };
    let mut wire = received.frame.clone();
    for piece in &received.pieces {
        wire.extend_from_slice(&voidport_proto::piece::length(piece.len()).expect("a length"));
        wire.extend_from_slice(piece);
    }
    wire.extend_from_slice(&received.closing.expect("a closing piece").encode());
    assert_eq!(
        kept, wire,
        "the kept reply is the reply, as it went on the wire"
    );
    assert_eq!(received.pieces.len(), 30);
    assert!(kept.len() > PIECE_LEN_LEN * 30);
    assert_eq!(
        session(&fixture).nodes,
        base + 30,
        "each entry counted once"
    );
}

#[test]
fn a_listing_admits_only_the_entries_that_fit() {
    let fixture = Fixture::start("listing-fits");
    let five = fixture.tree("five");
    voidport_test_support::create_directory(&five);
    for index in 0..5 {
        fs::write(five.join(format!("f{index}")), b"x").expect("a file");
    }
    let mut first = fixture.server.mount("plain", "/tree");
    let directory = first.lookup(ROOT, "five").expect("a directory").node_id;
    let handle = first.open(directory, OFlags::RDONLY).expect("opens");
    let base = session(&fixture).nodes;
    let entry = size_of::<DirEntryHeader>() + "f0".len();

    let (entries, exhausted) = first
        .readdirplus_page(
            directory,
            handle,
            0,
            u32::try_from(4 * entry - 1).expect("small"),
        )
        .expect("the listing");
    assert_eq!(entries.len(), 3);
    assert!(!exhausted, "the directory has more");
    assert_eq!(session(&fixture).nodes, base + 3, "each entry sent counted");

    assert_eq!(
        first
            .readdirplus_page(
                directory,
                handle,
                0,
                u32::try_from(entry - 1).expect("small")
            )
            .err(),
        Some(status::OVERFLOW)
    );
    assert_eq!(
        session(&fixture).nodes,
        base + 3,
        "a refused listing counts none"
    );
}

const LONG_NAME: &str = "an-entry-whose-name-is-longer-than-the-room-left";

fn page_for_s(client: &mut WireClient, directory: u64, handle: u64) -> (Vec<String>, bool) {
    let room = size_of::<DirEntryHeader>() + "s".len();
    let (entries, exhausted) = client
        .readdirplus_page(directory, handle, 0, u32::try_from(room).expect("small"))
        .expect("the listing");
    (entries.iter().map(DirEntry::name).collect(), exhausted)
}

#[test]
fn a_listing_skips_a_removed_entry_too_long_for_the_room_left() {
    let fixture = Fixture::start("listing-removed-unfit");
    let removed = fixture.tree("removed");
    voidport_test_support::create_directory(&removed);
    fs::write(removed.join(LONG_NAME), b"x").expect("a file");
    fs::write(removed.join("s"), b"x").expect("a file");
    let mut first = fixture.server.mount("plain", "/tree");
    let directory = first.lookup(ROOT, "removed").expect("a directory").node_id;
    let handle = first.open(directory, OFlags::RDONLY).expect("opens");
    fs::remove_file(removed.join(LONG_NAME)).expect("removed on the host");
    let base = session(&fixture).nodes;

    let (names, exhausted) = page_for_s(&mut first, directory, handle);
    assert_eq!(names, ["s"]);
    assert!(exhausted, "the removed entry does not end the reply");
    assert_eq!(
        session(&fixture).nodes,
        base + 1,
        "only the listed entry counted"
    );
}

/// Mounted at the namespace root, whose entries come from the rules: every rule
/// that grafts a host directory is hidden once the policy hides every user that
/// owns files on the host, and `s`, a directory that exists only on the way to
/// a rule, is the one entry no ownership hides.
#[test]
fn a_listing_skips_a_hidden_entry_too_long_for_the_room_left() {
    let fixture = Fixture::start("listing-hidden-unfit");
    let mut control = fixture.server.connect();
    let external = fixture
        .join("external")
        .to_str()
        .expect("a utf-8 fixture path")
        .to_owned();
    for path in [format!("/{LONG_NAME}"), "/s/inside".to_owned()] {
        control.expect_ok(&Request::RuleAdd {
            namespace: NamespaceName::new("plain").expect("a valid namespace name"),
            rule: Rule::new(path, ShareMode::Ro).with_target(external.clone()),
        });
    }
    let mut first = fixture.server.mount("plain", "/");
    let handle = first.open(ROOT, OFlags::RDONLY).expect("the root opens");
    control.expect_ok(&Request::OwnershipSet {
        namespace: NamespaceName::new("plain").expect("a valid namespace name"),
        ownership: OwnershipSpec::Map {
            unmapped: UnmappedPolicy::Hide,
            squash_uid: 65534,
            squash_gid: 65534,
            uid_map: Vec::new(),
            gid_map: Vec::new(),
        },
    });
    let base = session(&fixture).nodes;

    let (names, exhausted) = page_for_s(&mut first, ROOT, handle);
    assert_eq!(names, ["s"]);
    assert!(exhausted, "the hidden entries do not end the reply");
    assert_eq!(
        session(&fixture).nodes,
        base + 1,
        "only the listed entry counted"
    );
}

#[test]
fn a_listing_followed_by_a_forget_of_its_directory_still_lists_it() {
    let fixture = Fixture::start("listing-then-forget");
    let few = fixture.tree("few");
    voidport_test_support::create_directory(&few);
    for index in 0..3 {
        fs::write(few.join(format!("f{index}")), b"x").expect("a file");
    }
    let mut first = fixture.server.mount("plain", "/tree");
    let directory = first.lookup(ROOT, "few").expect("a directory").node_id;
    let handle = first.open(directory, OFlags::RDONLY).expect("opens");
    let (_, listing) = first.encoded(
        directory,
        &ReaddirplusRequest {
            handle: U64::new(handle),
            cookie: U64::ZERO,
            size: U32::new(65536),
            reserved: U32::ZERO,
        },
        &[],
    );
    let (_, forget) = first.encoded(
        directory,
        &ForgetRequest {
            nlookup: U64::new(1),
        },
        &[],
    );
    first.send_bytes(&[listing, forget].concat());

    let received = first.receive_message().expect("the listing");
    assert!(
        matches!(
            received.parsed().response::<ReaddirplusResponse>(),
            Ok(ResponseOutcome::Success(_))
        ),
        "the listing is answered"
    );
    assert_eq!(received.pieces.len(), 3, "it lists the directory");
    assert_eq!(received.closing.map(|closing| closing.status), Some(0));
}

#[test]
fn a_kept_reply_goes_when_the_next_request_arrives() {
    let fixture = Fixture::start("outcome-next");
    let mut first = fixture.server.mount("plain", "/tree");
    let (lookup, bytes) = first.encoded(ROOT, &lookup_request(), b"data.bin");
    first.send_bytes(&bytes);
    first.receive().expect("answered");
    first.getattr(ROOT).expect("the next request");
    let mut asking = join(&fixture, &first);
    assert_eq!(
        asking.outcome(first.connection_id(), lookup),
        Ok(Settled::Applied),
        "read, and nothing kept for it any more"
    );
}

fn lookup_request() -> voidport_proto::ops::node::LookupRequest {
    voidport_proto::ops::node::LookupRequest {
        name_len: U32::new(8),
    }
}

fn outcome_request(connection_id: u64, request_id: u64) -> OutcomeRequest {
    OutcomeRequest {
        connection_id: U64::new(connection_id),
        request_id: U64::new(request_id),
    }
}

fn whole(owner: u64, kind: u32) -> FileLock {
    FileLock {
        start: U64::ZERO,
        end: U64::new(u64::MAX),
        owner: U64::new(owner),
        pid: U32::new(1),
        lock_type: U32::new(kind),
    }
}
