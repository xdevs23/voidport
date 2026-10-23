use super::*;
use std::path::PathBuf;

use tokio::io::AsyncWriteExt as _;
use voidport_proto::frame::FrameWriter;
use voidport_proto::limits::LIMITS;
use voidport_proto::ops::share::ShareSnapshotPart;
use voidport_proto::piece::Closing;
use zerocopy::byteorder::little_endian::U64;

use crate::client::connection::Notice;
use crate::client::connection::tests::over_pair;
use crate::url::Endpoint;

impl Pool {
    fn is_ended(&self) -> bool {
        self.lock().is_ended()
    }
}

fn join(pool: &Pool, connection: &Arc<Connection>) -> Placed {
    let joined = pool.lock().join(connection.id(), Arc::clone(connection));
    let Ok(Joined::Added(place)) = joined else {
        panic!("room for the connection, not {joined:?}");
    };
    Placed {
        connection: Arc::clone(connection),
        place,
    }
}

fn add(pool: &Arc<Pool>, established: Established) -> Placed {
    let Established { connection, reader } = established;
    let placed = join(pool, &Arc::new(connection));
    assert_eq!(pool.lock().give_back(placed.place), Ok(None));
    pool.watch(placed.clone(), reader);
    placed
}

fn install_subscribed(pool: &Arc<Pool>, connection: &Arc<Connection>) {
    let placed = join(pool, connection);
    assert_eq!(pool.lock().install(placed.place), Ok(Install::Installed));
}

async fn pool_at(path: &std::path::Path, first: Established) -> Arc<Pool> {
    let memory = Memory::host();
    let target = Target {
        endpoint: Endpoint::Unix {
            path: path.to_path_buf(),
        },
        namespace: String::new(),
        subpath: Vec::new(),
    };
    let token = memory.buffer(1, 1).await;
    let (pool, first) = Pool::open(
        Weak::new(),
        target,
        1,
        token,
        Arc::clone(&memory),
        tokio::runtime::Handle::current(),
        First::new(first, &memory).await,
    );
    first.watch();
    pool
}

pub(crate) fn endpoint_path(name: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("voidport-pool-{}-{name}.sock", std::process::id()));
    let _absent_on_a_fresh_run = std::fs::remove_file(&path);
    path
}

async fn poll_once<F: Future>(future: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
    let mut future = Some(future);
    std::future::poll_fn(|cx| {
        let polled = future.take().expect("polled once").poll(cx);
        std::task::Poll::Ready(polled)
    })
    .await
}

fn dialed(listener: &std::os::unix::net::UnixListener) -> Option<std::os::unix::net::UnixStream> {
    match listener.accept() {
        Ok((stream, _)) => Some(stream),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
        Err(error) => panic!("the listener failed: {error}"),
    }
}

#[tokio::test]
async fn a_failed_dial_waits_for_an_idle_connection_without_dialing_again() {
    let path = endpoint_path("dial-wait");
    let (only, _only_server) = over_pair(1);
    let pool = pool_at(&path, only).await;
    let busy = pool.take().await.expect("the idle connection");

    // Nothing listens yet, so the dial fails at once, inside this poll.
    let mut taking = std::pin::pin!(pool.take());
    assert!(poll_once(taking.as_mut()).await.is_pending(), "it waits");

    // From now on a dial would reach the listener's queue.
    let listener = std::os::unix::net::UnixListener::bind(&path).expect("a listener");
    listener.set_nonblocking(true).expect("non-blocking");
    pool.changed.notify_waiters();
    assert!(
        poll_once(taking.as_mut()).await.is_pending(),
        "it still waits"
    );
    assert!(dialed(&listener).is_none(), "and dials nothing");

    let busy = busy.give_back();
    let std::task::Poll::Ready(Ok(taken)) = poll_once(taking.as_mut()).await else {
        panic!("the idle connection is taken");
    };
    assert!(
        Arc::ptr_eq(&taken.connection, &busy),
        "it runs on the connection that went idle"
    );
    assert!(dialed(&listener).is_none(), "no dial was made");
    assert_eq!(
        pool.connections(),
        Connections {
            pooled: 1,
            subscribed: false,
        }
    );
    let _absent_on_a_fresh_run = std::fs::remove_file(&path);
}

/// The clock is paused and only the test moves it, so the delay between two
/// dials is measured on that clock.
#[tokio::test(start_paused = true)]
async fn a_waiting_request_whose_pool_loses_its_last_connection_dials_until_one_joins() {
    let path = endpoint_path("dial-again");
    let (only, _only_server) = over_pair(1);
    let (subscribed, _subscribed_server) = over_pair(2);
    let pool = pool_at(&path, only).await;
    let subscribed = Arc::new(subscribed.connection);
    install_subscribed(&pool, &subscribed);
    let busy = pool.take().await.expect("the idle connection");

    let mut taking = std::pin::pin!(pool.take());
    assert!(poll_once(taking.as_mut()).await.is_pending(), "it waits");
    let listener = std::os::unix::net::UnixListener::bind(&path).expect("a listener");
    listener.set_nonblocking(true).expect("non-blocking");

    busy.lost();
    assert!(!pool.is_ended());
    // Two dials fail, and the third joins. The clock moves by one tick
    // after each poll that brought no dial, so each dial is seen at the
    // time it was made. The request takes in a failure at the time the
    // failed dial was seen, so the time between two sightings is the
    // delay the request waited out after the failure between them.
    let mut dials = Vec::new();
    let accepted = loop {
        let Some(accepted) = dial_after_a_poll(taking.as_mut(), &listener).await else {
            tokio::time::advance(TICK).await;
            continue;
        };
        dials.push(tokio::time::Instant::now());
        if dials.len() == 3 {
            break accepted;
        }
        failing(taking.as_mut(), accepted).await;
    };
    // The shortest delay of the stall schedule its jitter leaves.
    let shortest = voidport_session::backoff::STALL_INITIAL * 3 / 4;
    assert!(
        dials[1] - dials[0] >= shortest,
        "the second dial waits out a delay after the first failed: {:?}",
        dials[1] - dials[0]
    );
    assert!(
        dials[2] - dials[1] >= shortest,
        "the third dial waits out a delay after the second failed: {:?}",
        dials[2] - dials[1]
    );
    assert!(!pool.is_ended(), "the session lives on");
    assert!(
        subscribed.death().is_none(),
        "the subscribed connection is kept"
    );

    let (taken, _joined) = joining(taking.as_mut(), accepted, 9).await;
    let taken = taken.expect("the session lives");
    assert_eq!(taken.id(), 9, "it runs on the connection that joined");
    assert_eq!(
        pool.connections(),
        Connections {
            pooled: 1,
            subscribed: true,
        }
    );
    assert!(!pool.is_ended());
    let _absent_on_a_fresh_run = std::fs::remove_file(&path);
}

#[tokio::test]
async fn a_subscription_installed_meanwhile_is_not_used_once_its_connection_is_lost() {
    let path = endpoint_path("installed-meanwhile");
    let (only, _only_server) = over_pair(1);
    let (other, _other_server) = over_pair(2);
    let pool = pool_at(&path, only).await;
    let _busy = pool.take().await.expect("the idle connection");
    let listener = std::os::unix::net::UnixListener::bind(&path).expect("a listener");
    listener.set_nonblocking(true).expect("non-blocking");

    let mut subscribing = std::pin::pin!(pool.subscription());
    assert!(poll_once(subscribing.as_mut()).await.is_pending());
    let other = Arc::new(other.connection);
    install_subscribed(&pool, &other);
    other.bury(Death::Transport("lost after it was installed".to_owned()));

    let (installed, _joined) = answering_a_join(subscribing.as_mut(), &listener, 7).await;
    let installed = installed.expect("the session lives");
    assert_eq!(
        installed.id(),
        7,
        "the dialed connection holds the subscription"
    );
    assert_eq!(pool.subscribed_id(), Some(7));
    assert_eq!(
        pool.connections(),
        Connections {
            pooled: 1,
            subscribed: true,
        },
        "the dead subscription's connection left the session"
    );
    assert!(!pool.is_ended());
    let _absent_on_a_fresh_run = std::fs::remove_file(&path);
}

async fn dial_after_a_poll<F: Future>(
    future: std::pin::Pin<&mut F>,
    listener: &std::os::unix::net::UnixListener,
) -> Option<std::os::unix::net::UnixStream> {
    assert!(
        poll_once(future).await.is_pending(),
        "the request waits for a connection"
    );
    let stream = dialed(listener)?;
    stream.set_nonblocking(true).expect("non-blocking");
    Some(stream)
}

/// It moves no clock. A dial that never comes hangs the test, which is the
/// failure.
async fn next_dial<F: Future>(
    mut future: std::pin::Pin<&mut F>,
    listener: &std::os::unix::net::UnixListener,
) -> std::os::unix::net::UnixStream {
    loop {
        if let Some(stream) = dial_after_a_poll(future.as_mut(), listener).await {
            return stream;
        }
        tokio::task::yield_now().await;
    }
}

/// The join reads the end of the stream where the reply belongs, fails and
/// closes the dialed socket in the same poll in which the request takes in the
/// failure. The clock does not move meanwhile, so the request takes in the
/// failure at the time the dial was seen, however many polls that takes.
async fn failing<F: Future>(
    mut future: std::pin::Pin<&mut F>,
    mut accepted: std::os::unix::net::UnixStream,
) {
    use std::io::Read as _;

    accepted
        .shutdown(std::net::Shutdown::Write)
        .expect("the reply side closed");
    let mut chunk = [0u8; 256];
    loop {
        assert!(
            poll_once(future.as_mut()).await.is_pending(),
            "the request waits while its dials fail"
        );
        match accepted.read(&mut chunk) {
            Ok(0) => return,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("the dial could not be read: {error}"),
        }
        tokio::task::yield_now().await;
    }
}

async fn answering_a_join<F: Future>(
    mut future: std::pin::Pin<&mut F>,
    listener: &std::os::unix::net::UnixListener,
    connection_id: u64,
) -> (F::Output, std::os::unix::net::UnixStream) {
    let accepted = next_dial(future.as_mut(), listener).await;
    joining(future, accepted, connection_id).await
}

/// Each step of the join is waited for with no deadline: a step that never
/// happens hangs the test, which is the failure.
async fn joining<F: Future>(
    mut future: std::pin::Pin<&mut F>,
    mut accepted: std::os::unix::net::UnixStream,
    connection_id: u64,
) -> (F::Output, std::os::unix::net::UnixStream) {
    use std::io::{Read as _, Write as _};

    let token = [0u8; 1];
    let expected = voidport_session::handshake::join_request_len(&token);
    let mut hello = Vec::new();
    let mut reply: Vec<u8> = Vec::new();
    let mut replied = 0;
    loop {
        if let std::task::Poll::Ready(output) = poll_once(future.as_mut()).await {
            return (output, accepted);
        }
        if hello.len() < expected {
            let mut chunk = [0u8; 256];
            match accepted.read(&mut chunk) {
                Ok(read) => hello.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("the hello could not be read: {error}"),
            }
            if hello.len() >= expected {
                let request_id = voidport_proto::frame::FrameHeader::parse(&hello)
                    .expect("a hello")
                    .request_id
                    .get();
                reply = join_reply(request_id, connection_id, &token);
            }
        } else if replied < reply.len() {
            match accepted.write(&reply[replied..]) {
                Ok(written) => replied += written,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("the reply could not be written: {error}"),
            }
        }
        tokio::task::yield_now().await;
    }
}

/// The millisecond resolution of Tokio's timer, so no deadline of a dial delay
/// is passed by more than one step.
const TICK: std::time::Duration = std::time::Duration::from_millis(1);

pub(crate) fn join_reply(request_id: u64, connection_id: u64, token: &[u8]) -> Vec<u8> {
    use voidport_proto::ops::handshake::HelloReply;
    use zerocopy::byteorder::little_endian::U32;

    let mut buffer = vec![0u8; FrameWriter::response_len::<HelloReply>(token.len())];
    let mut writer = FrameWriter::response(
        &mut buffer,
        &LIMITS,
        request_id,
        &HelloReply {
            root_node_id: U64::new(1),
            protocol_version: U32::new(voidport_proto::PROTOCOL_VERSION),
            flags: U32::ZERO,
            connection_id: U64::new(connection_id),
            token_len: U32::new(token.len() as u32),
            reserved: U32::ZERO,
        },
    )
    .expect("encodable");
    writer.payload(token).expect("fits");
    let len = writer.finish().expect("whole").len();
    buffer.truncate(len);
    buffer
}

/// The test runs on one thread, so no reader task runs between the death
/// recorded below and the subscription: the connection taken first is one whose
/// death is recorded and whose loss is not yet handled.
#[tokio::test]
async fn a_connection_lost_while_taken_for_the_subscription_is_never_installed() {
    let memory = Memory::host();
    let (spare, _spare_server) = over_pair(1);
    let (living, mut living_server) = over_pair(2);
    let (dying, _dying_server) = over_pair(3);
    let target = Target {
        endpoint: Endpoint::Unix {
            path: PathBuf::from("/nonexistent/voidport.sock"),
        },
        namespace: String::new(),
        subpath: Vec::new(),
    };
    let token = memory.buffer(1, 1).await;
    let (pool, spare) = Pool::open(
        Weak::new(),
        target,
        1,
        token,
        Arc::clone(&memory),
        tokio::runtime::Handle::current(),
        First::new(spare, &memory).await,
    );
    spare.watch();
    let living = add(&pool, living);
    // Idle last, so it is the one taken first.
    let dying = add(&pool, dying);

    dying.bury(Death::Transport("lost while taken".to_owned()));
    let subscribed = pool.subscription().await.expect("the session lives");
    assert_eq!(subscribed.id(), living.id());
    assert_eq!(pool.subscribed_id(), Some(living.id()));

    let (sink, mut notices) = tokio::sync::mpsc::unbounded_channel();
    subscribed.route_notifications(sink);
    let mut buffer = [0u8; 32];
    let part = FrameWriter::notification(&mut buffer, &LIMITS, &ShareSnapshotPart)
        .and_then(FrameWriter::finish)
        .expect("encodable")
        .to_vec();
    let mut sent = part.clone();
    sent.extend(
        Closing {
            status: 0,
            exhausted: false,
        }
        .encode(),
    );
    living_server.write_all(&sent).await.expect("sent");
    let Some(Notice::Message(message)) = notices.recv().await else {
        panic!("the notification arrives");
    };
    assert_eq!(message, part);

    let handled = Connections {
        pooled: 1,
        subscribed: true,
    };
    loop {
        let changed = pool.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if pool.connections() == handled {
            break;
        }
        changed.await;
    }
    assert_eq!(pool.subscribed_id(), Some(living.id()));
    assert!(!pool.is_ended());
}

#[tokio::test]
async fn connections_announced_with_the_same_id_are_told_apart() {
    let (first, _first_server) = over_pair(5);
    let (twin, _twin_server) = over_pair(5);
    let pool = pool_at(&endpoint_path("same-id"), first).await;
    let twin = add(&pool, twin);
    let lost = pool.take().await.expect("the connection given back last");
    assert!(Arc::ptr_eq(&lost.connection, &twin.connection));
    let other = pool.take().await.expect("the first connection");
    assert!(!Arc::ptr_eq(&other.connection, &twin.connection));

    lost.lost();
    lost.give_back();
    assert_eq!(
        pool.connections(),
        Connections {
            pooled: 1,
            subscribed: false,
        }
    );
    assert!(other.death().is_none(), "the other one lives");
    let other = other.give_back();
    let again = pool.take().await.expect("the first connection, idle");
    assert!(Arc::ptr_eq(&again.connection, &other));
    assert!(!pool.is_ended());
}

#[tokio::test]
async fn after_the_last_connection_is_lost_neither_a_waiter_nor_a_join_is_served() {
    use std::io::Read as _;

    let path = endpoint_path("ended-join");
    let (only, _only_server) = over_pair(1);
    let pool = pool_at(&path, only).await;
    let busy = pool.take().await.expect("the idle connection");

    let mut waiting = std::pin::pin!(pool.take());
    assert!(poll_once(waiting.as_mut()).await.is_pending(), "it waits");
    let listener = std::os::unix::net::UnixListener::bind(&path).expect("a listener");
    listener.set_nonblocking(true).expect("non-blocking");
    let mut dialing = std::pin::pin!(pool.take());
    let accepted = next_dial(dialing.as_mut(), &listener).await;

    busy.lost();
    assert!(pool.is_ended());
    let std::task::Poll::Ready(waited) = poll_once(waiting.as_mut()).await else {
        panic!("the waiting request is woken");
    };
    assert_eq!(waited.err(), Some(Ended));
    let (joined, mut accepted) = joining(dialing.as_mut(), accepted, 2).await;
    assert_eq!(
        joined.err(),
        Some(Ended),
        "the join finds the session ended"
    );
    assert_eq!(
        pool.connections(),
        Connections {
            pooled: 0,
            subscribed: false,
        }
    );
    accepted.set_nonblocking(false).expect("blocking");
    let mut rest = Vec::new();
    accepted
        .read_to_end(&mut rest)
        .expect("the joined socket is closed");
    let _absent_on_a_fresh_run = std::fs::remove_file(&path);
}

/// The pool is closed as the end of its session closes it before that end is
/// reported to the mount, and the test reports nothing. A request that asked
/// the mount again at once would be handed the ended session for ever and never
/// return from its first poll, which hangs the test.
#[tokio::test]
async fn a_request_that_finds_its_session_ended_waits_for_the_mount() {
    use crate::client::{Origin, ROOT_NODE_ID};

    let path = endpoint_path("unreported-end");
    let listener = tokio::net::UnixListener::bind(&path).expect("a listener");
    let serving = async {
        let (mut accepted, _) = listener.accept().await.expect("the mount dials");
        let reply = join_reply(voidport_session::handshake::HELLO_REQUEST_ID, 1, b"t");
        accepted.write_all(&reply).await.expect("the reply");
        accepted
    };
    let endpoint = Endpoint::Unix { path: path.clone() };
    let (client, _accepted) = tokio::join!(Client::mount(&endpoint, "", b""), serving);
    let client = client.expect("the mount");

    client.current().expect("the session").close(Death::Closed);
    let mut request = std::pin::pin!(client.statfs(Origin::default(), ROOT_NODE_ID));
    assert!(
        poll_once(request.as_mut()).await.is_pending(),
        "it waits for the mount"
    );

    client.close();
    assert_eq!(request.await.err(), Some(rustix::io::Errno::IO));
    let _absent_on_a_fresh_run = std::fs::remove_file(&path);
}

#[test]
fn counted_references_fit_only_what_the_session_core_owes() {
    use voidport_proto::opcode::Opcode;
    use voidport_session::owed;

    let looked_up = Counted {
        lookups: vec![7],
        handle: None,
    };
    assert!(looked_up.fits(owed::of(Opcode::Lookup)));
    assert!(
        !looked_up.fits(owed::of(Opcode::Create)),
        "a create opens a handle too"
    );
    assert!(!looked_up.fits(owed::of(Opcode::Getattr)));
    assert!(!Counted::default().fits(owed::of(Opcode::Open)));
    let listed = Counted {
        lookups: vec![7, 7, 9],
        handle: None,
    };
    assert!(listed.fits(owed::of(Opcode::Readdirplus)));
}
