// SPDX-License-Identifier: GPL-2.0

//! Phase one of the voidport kernel client: one real wire frame over vsock.
//!
//! The module opens a kernel-owned vsock stream to the voidport server on its
//! hypervisor host, sends a `Hello` encoded by the workspace's wire crate,
//! reads the answer, and validates it with the same crate. Every step it takes
//! is reported to the kernel log, because the log is this probe's product: it
//! converts the transport from something that compiles into something that has
//! run.
//!
//! The exchange runs on a workqueue, not on the loading task's stack, because
//! the socket calls sleep and the client's I/O is designed to live off the
//! caller's task. Module init waits for the verdict, so a failed exchange is a
//! failed load and the loader sees it. That wait is not a stall: every wait
//! the worker makes on the peer carries a deadline, so the worker always
//! finishes. Waiting is also all init may do — the kernel's Rust workqueue
//! offers no synchronous cancel, and returning while a worker still runs this
//! module's code would leave that code to be unloaded under it.
//!
//! The accepted session is then the module's, held until the module is
//! unloaded: a session that ended with its handshake would not be one, and the
//! server's view of it is what the harness checks the host side against.
//!
//! Load parameters: `port` names the server's vsock port and `cid` its address
//! — `VMADDR_CID_HOST` by default, which is what a guest calls its host.

use kernel::prelude::*;
use kernel::sync::{new_mutex, Arc, Completion, Mutex, SetOnce};
use kernel::workqueue::{self, impl_has_work, new_work, Work, WorkItem};

mod exchange;
mod vsock;

/// The namespace the probe asks its session for.
///
/// The handshake needs a namespace name and module parameters carry integers
/// only, so the name is fixed here and the harness configures the server to
/// serve it.
const NAMESPACE: &[u8] = b"probe";

module! {
    type: Probe,
    name: "voidport_probe",
    authors: ["voidport"],
    description: "voidport session handshake over a kernel-owned vsock stream",
    license: "GPL",
    params: {
        cid: u32 {
            default: 2,
            description: "vsock cid of the voidport server; 2 is the host",
        },
        port: u32 {
            default: 0,
            description: "vsock port the voidport server listens on",
        },
    },
}

/// The module, holding the session its handshake opened.
///
/// Nothing here is an explicit teardown step: dropping this drops the last
/// reference to the handshake, which drops the stream, which releases the
/// socket. Unload closes the session by structure.
struct Probe {
    _handshake: Arc<Handshake>,
}

impl kernel::Module for Probe {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let cid = *module_parameters::cid.value();
        let port = *module_parameters::port.value();
        if port == 0 {
            pr_err!("voidport probe: load with port=<the server's vsock port>\n");
            return Err(EINVAL);
        }
        Ok(Probe {
            _handshake: Handshake::open(cid, port)?,
        })
    }
}

/// One handshake attempt, queued as a work item so it runs in a worker's task
/// context, and joined by the task that queued it.
#[pin_data]
struct Handshake {
    #[pin]
    work: Work<Handshake>,
    #[pin]
    done: Completion,
    /// The session the handshake opened, empty until the worker opens it.
    ///
    /// Nothing ever empties it again: the session ends when this whole value
    /// is dropped. The lock is what a shared handshake needs to hold a stream
    /// at all, since a stream is `Send` and not `Sync`.
    #[pin]
    session: Mutex<Option<vsock::Stream>>,
    /// The verdict as an errno, published before `done` is signalled.
    verdict: SetOnce<c_int>,
    cid: u32,
    port: u32,
}

impl_has_work! {
    impl HasWork<Self> for Handshake { self.work }
}

impl Handshake {
    /// Runs the handshake and answers the session it opened.
    fn open(cid: u32, port: u32) -> Result<Arc<Self>> {
        let handshake = Arc::pin_init(
            pin_init!(Handshake {
                work <- new_work!("voidport_probe::handshake"),
                done <- Completion::new(),
                session <- new_mutex!(None, "voidport_probe::session"),
                verdict: SetOnce::new(),
                cid,
                port,
            }),
            GFP_KERNEL,
        )?;
        // The unbound queue, not the system one: this item waits on a remote
        // peer for as long as its deadline allows, and the system queue's
        // users expect items that finish quickly.
        //
        // The enqueue is refused only for an item that is already queued, and
        // this one was built here and is queued once.
        if workqueue::system_unbound()
            .enqueue(handshake.clone())
            .is_err()
        {
            return Err(EAGAIN);
        }
        handshake.done.wait_for_completion();
        // The verdict is published before the completion is signalled, so it
        // is there. An absent one could only mean the worker never reached its
        // publication, which is a failed load like any other.
        kernel::error::to_result(handshake.verdict.copy().unwrap_or(EIO.to_errno()))?;
        Ok(handshake)
    }

    /// The exchange itself, on the worker's stack.
    fn exchange(&self) -> Result<vsock::Stream> {
        let mut request = KVec::from_elem(0u8, exchange::BUFFER_LEN, GFP_KERNEL)?;
        let mut reply = KVec::from_elem(0u8, exchange::BUFFER_LEN, GFP_KERNEL)?;

        let stream = vsock::Stream::open()?;
        pr_info!("voidport probe: created a kernel-owned vsock socket\n");

        stream.connect(self.cid, self.port)?;
        pr_info!(
            "voidport probe: connected to cid {} port {}\n",
            self.cid,
            self.port
        );

        let frame = exchange::encode_hello(&mut request, NAMESPACE)?;
        let sent = stream.send_all(frame)?;
        pr_info!("voidport probe: sent {} bytes of hello\n", sent);

        let (outcome, received) =
            exchange::read_reply(&mut reply, |slice| stream.receive_exact(slice))?;
        pr_info!("voidport probe: received {} bytes of reply\n", received);

        match outcome {
            exchange::Outcome::Accepted {
                root_node_id,
                protocol_version,
                max_frame_len,
            } => {
                pr_info!(
                    "voidport probe: hello accepted: root node {} protocol {} max frame {}\n",
                    root_node_id,
                    protocol_version,
                    max_frame_len
                );
                Ok(stream)
            }
            exchange::Outcome::Refused(status) => {
                let refusal = Error::from_errno(status);
                pr_info!(
                    "voidport probe: hello refused: status {} ({})\n",
                    status,
                    refusal.name().unwrap_or(c"unnamed")
                );
                Err(refusal)
            }
        }
    }
}

impl WorkItem for Handshake {
    type Pointer = Arc<Handshake>;

    fn run(this: Arc<Handshake>) {
        let verdict = match this.exchange() {
            Ok(stream) => {
                *this.session.lock() = Some(stream);
                0
            }
            Err(error) => {
                pr_err!(
                    "voidport probe: the exchange failed: {}\n",
                    error.name().unwrap_or(c"unnamed")
                );
                error.to_errno()
            }
        };
        // Publish before signalling: the waiter reads the session and the
        // verdict only after the completion, and the completion is what orders
        // the two against this store.
        this.verdict.populate(verdict);
        this.done.complete_all();
    }
}
