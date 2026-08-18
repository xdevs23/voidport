# Write streaming

The authority document for v2 write streaming. Written 2026-08-18
from the consolidated research record — the NFS, SMB and FUSE
write-pipelining contracts, the bandwidth-delay arithmetic, and
this project's own measurements and parked contract — under the
evidence classes KERNEL.md defines: **measured**, **proven by
source**, **decided**, **open** (with the settling experiment
named). This document decides the design and implements nothing.

The problem, measured: writes through the share reach 172 MB/s
because the write path pipelines nothing — every write is a full
round trip, the mirror image of what readahead fixed on reads.
The arithmetic is unforgiving: a serialized protocol moves exactly
one chunk per round trip, which caps a 1 MiB chunk at 1 GiB/s at
one millisecond of latency and at 20 MiB/s at fifty — no link
speed changes that. Saturation needs in-flight data equal to the
bandwidth-delay product, and the fleet decision has put
arbitrary-latency constellations in scope.

## The decision that shapes everything: no early acknowledgment

The parked v1 contract bought throughput by acknowledging a write
once its frame was queued, and then had to carry the consequences:
a poisoned-handle failure mode with no external precedent, drains
in front of node operations, an mmap invalidation split between
acknowledgment and confirmation, and a direct contradiction of the
live resilience rule that a written-but-unanswered write fails
with EIO. Each was a fence around a hazard the early
acknowledgment itself created.

Decided: **streaming never acknowledges early.** A guest write
returns only when every chunk of it has been answered by the
server, exactly as today. What changes is only what happens
*inside* the request: a large write splits at the frame bound and
its chunks are sent concurrently under a bounded window, answers
gathered, the syscall completing on the last one. Concurrent
writers and asynchronous guest I/O pipeline naturally on top,
because parallel direct writes already ship.

Everything the parked contract fenced then never happens. A stat
cannot observe a size the server has not applied, because nothing
was acknowledged before apply. An mmap fault cannot cache
pre-write bytes inside an acknowledgment window, because there is
no such window. No handle is ever poisoned. No drain rule exists.
Barriers keep their v1 meaning without amendment: by the time
fsync can be issued on a handle, its writes have returned, and
returned means answered. The hazards are not mitigated — they are
unconstructable.

## The contract

- **Scope.** Offset-addressed data writes on non-append handles.
  Append handles, O_SYNC and O_DSYNC handles, and guest-side
  O_DIRECT handles stream nothing and behave exactly as v1 —
  append is not offset-addressed, and the sync flags promise
  per-write durability ordering that concurrency would blur. The
  kernel already serializes append and size-extending writes under
  its exclusive lock, so the exclusion costs what it already cost.
- **Chunking.** A write larger than the negotiated frame bound
  splits into chunks at that bound, each an ordinary WriteRequest
  carrying its own absolute offset — the wire is unchanged, and
  every mature protocol's recurring lesson (the unit carries its
  offset; short writes are first-class) is already this wire's
  shape. Chunks of one write never overlap, so their apply order
  is immaterial and the server needs no new rule. A short chunk
  answer resumes from where the server stopped, as a local write
  would.
- **The window.** In-flight chunks are bounded in count and bytes,
  two levels — per handle and per mount — the measured shape the
  readahead engine already ships. Defaults sized from the
  bandwidth-delay table and the run-ahead evidence (the server's
  own bound is 64 in flight, and 1024 measured 19% worse, so depth
  is not free); both levels configurable per mount for the WAN
  constellations, negotiation with the server not required because
  the server's run-ahead bound already backpressures the wire by
  pausing the read loop. A full window backpressures the writer;
  it never errors. **Open**: the default depth and whether
  per-handle 8 matches the write side as it does the read side —
  settled by the phase W2 measurements on unix, vsock and TCP with
  injected latency.
- **Failure.** The first failed chunk fails the write: its errno
  is the syscall's errno, delivered once; chunks not yet sent are
  abandoned; chunks in flight are awaited and their answers
  discarded. The handle remains healthy — the guest sees exactly
  what a local short-or-failed write shows.
- **Retention and replay.** Every unanswered chunk is retained by
  the client engine for the life of the request — the window
  bounds this by construction, so retention is fixed-capacity in
  the kernel core's terms, no overflow class. On reconnect inside
  the stall window, retained chunks replay: an offset-addressed
  data write applying twice writes the same bytes to the same
  place, which is the idempotence the replay set requires. The
  resilience contract's replay set is therefore **amended, not
  overridden**: offset-addressed non-append data writes join the
  idempotent class, with their retention the streaming window
  itself; the EIO rule keeps governing everything the class
  excludes, append above all. One recorded sharpening: replay is
  per chunk against absolute offsets, so a partially answered
  write replays only its unanswered chunks.
- **Ordering.** All chunks of one handle's writes travel one
  connection (handle affinity), so the per-connection serialized
  frame stream orders whatever needed ordering; no sequence
  numbers, no stream ids, no new wire surface — the taxonomy that
  refused a smuggled stream id stays untouched. A future
  multi-connection session streams different handles over
  different connections and loses nothing, because nothing
  cross-handle was ever ordered.

## What this does not fix, stated honestly

A single-threaded writer issuing small writes gains nothing: each
syscall still spans a round trip, because completing it early is
exactly the early acknowledgment this design refuses. Measured
today that costs two round trips per write on FUSE mounts (the
capability probe preceding each write); the kernel client halves
that by never issuing the probe. The structural answer for the
small-write single-thread case is the v4 caching layer, whose
design opens with the durability contract such absorption
requires — recorded there, not smuggled in here. The bulk cases —
large writes, parallel writers, asynchronous I/O — are the cases
the 172 MB/s number measured, and they are what this contract
accelerates.

## Interaction with the data plane

None by design. The window is read-only toward the guest and the
wire is the write path on every transport (DATAPLANE.md); the
streaming engine lives in the client's write path on both clients
— the userspace engine beside readahead, the kernel client inside
its provider's write-through path — below the syscall boundary
and above the transport seam, so it rides vsock, TCP, unix and
the virtio queue identically.

## Phasing

1. **W1 — the client engine.** Chunked concurrent submission,
   window accounting, retention, failure gathering; the userspace
   client first, behind the existing write path; the replay-set
   amendment lands in the shared session logic with its golden
   tests. Criteria: byte-identical outcomes versus v1 under the
   full v1 write suite, fault injection on every chunk position,
   reconnect mid-write replaying exactly the unanswered chunks.
2. **W2 — measurement.** Throughput versus v1 on unix, vsock and
   TCP with injected latency across the BDP table's points;
   window defaults set from the numbers; the open depth question
   closed. The 172 MB/s number is the baseline the report leads
   with.
3. **W3 — the kernel client's engine.** The same contract inside
   the kernel provider when the kernel client's write phase
   arrives, sharing the session core's replay machinery; the
   ring-2 torture arm gains a streamed-write storm.

## Acceptance criteria — for this specification

1. No clause weakens a durability or ordering promise v1 makes:
   acknowledgment semantics, barrier semantics and error delivery
   are v1's exactly.
2. The replay-set amendment is stated as an amendment with its
   idempotence argument, and everything outside the amended class
   still follows the unmodified resilience contract.
3. The window is fixed-capacity with backpressure and no error
   path, satisfying the kernel core's constraints verbatim.
4. The wire is unchanged: no new opcodes, fields, or flags, and
   golden vectors stay green.
5. Every open question names its settling experiment and phase,
   and the stated non-goal (small serialized writes) is recorded
   with its future home.
