# Write streaming

The authority document for v2 write streaming. First written
2026-08-18; rewritten the same day after its unbriefed review,
which found the first draft's chunking inert on the client it
shipped to first, its replay amendment unexecutable, and its
failure clause false — the corrections are folded in below.
Evidence classes are KERNEL.md's: **measured**, **proven by
source**, **decided**, **open** (with the settling experiment
named). The design was affirmed 2026-08-18, and implementation is
open from that affirmation.

The problem, measured: the write path pipelines nothing — every
write is one full round trip. The rig's paired baseline is
369–410 MiB/s sequential; the field report saw 172 MB/s on a busy
host. The arithmetic that bounds any serialized design: one chunk
per round trip means a 1 MiB chunk caps at 1 GiB/s at one
millisecond of effective latency and 20 MiB/s at fifty — no link
speed changes it — and saturation requires in-flight data equal to
the bandwidth-delay product, with arbitrary-latency constellations
decided in scope. The in-document table (derivable arithmetic):

| link, latency | in-flight needed | depth at 128 KiB | at 1 MiB |
|---|---|---|---|
| 10 Gb/s, 1 ms | 1.25 MB | 10 | 2 |
| 10 Gb/s, 10 ms | 12.5 MB | 96 | 12 |
| 1 Gb/s, 50 ms | 6.25 MB | 48 | 6 |
| 40 Gb/s, 20 ms | 100 MB | 763 | 96 |

## The decision that shapes everything: no early acknowledgment

The parked v1 contract bought throughput by acknowledging a write
once its frame was queued, and every fence it carried — the
poisoned-handle failure mode, the drains in front of node
operations, the split mmap invalidation — fenced a hazard the
early acknowledgment itself created. Decided: **streaming never
acknowledges early.** A guest write returns only when every chunk
of it has been answered, exactly as today. The hazards are not
mitigated; they are unconstructable, because the window in which
they lived does not exist.

## Where the concurrency comes from — stated per client

**Proven by source, and decisive for the shape:** the userspace
client cannot receive a large write. It announces its write budget
to the FUSE kernel as max_write, the kernel splits every syscall
to that size before the client sees it, and the kernel's own
ceiling is 1 MiB — so a split at the frame bound never fires
there, and a per-request mechanism keyed to "writes larger than a
frame" would be inert on the client that ships first. The
mechanism is therefore **sub-frame chunking with a concurrent
window**:

- **The kernel client** owns its write-through path and streams
  its batches whole — a write's full extent, a memory-map
  writeback's page batch — chunked at the frame bound and below,
  so one large write fills the window by itself.
- **The userspace client** receives at most max_write per request
  and chunks *below* the frame bound (a 1 MiB request becoming,
  for example, eight 128 KiB chunks in flight at once), which
  overlaps the per-chunk fixed costs and the round trips inside
  one request. The chunk unit is a mount option with a measured
  default — **measured, 256 KiB** (the W2 matrix, 2026-08-18; the
  record is the "What W2 measured" section below). The matrix
  answered the question this clause left open both ways at once:
  sub-frame chunking beats the single frame by 7–31% where the
  round trip is cheap — the win is the transfer of one chunk
  overlapping the server's apply of the last — and merely equals
  it, never beats it, where the round trip is the cost, because
  the request boundary is a barrier either way and one request is
  one round trip on both paths.
- **Concurrent writers and asynchronous guest I/O** pipeline
  naturally on both clients through parallel direct writes, with
  that capability's honest bound restated, not dropped: the guest
  kernel still serializes append, size-extending, and ever-mmap'd
  files under its exclusive lock, so the archetypal growing bulk
  write is serialized at the source and gains only what
  intra-request chunking gives it.

**What no clause fixes, stated honestly**: a single-threaded
writer issuing small writes still spans one round trip per
syscall, because completing it early is exactly the early
acknowledgment this design refuses. The only structural remover
of that round trip is a guest-side writeback cache, which the
decided coherence contract refuses; this stays out of scope with
no future home claimed for it.

## The contract

- **Scope.** Offset-addressed data writes on direct-io mounts
  (off by default on the userspace client, and the posture the
  measured deployments run; a page-cached mount keeps v1's path
  byte-identical). On the kernel client the same contract applies
  to the provider's write-through path: the unit is the
  provider's batch — the syscall's extent for a write, the page
  batch for the memory-map writeback hook — chunked at and below
  the frame bound under the same window. Excluded and unchanged
  from v1: append handles (not offset-addressed), O_SYNC and
  O_DSYNC handles (per-write durability ordering), and guest
  O_DIRECT handles — excluded on their own semantics: a guest
  choosing O_DIRECT asked for unbuffered, uncoalesced submission,
  and that path is already served by parallel direct writes
  exactly as shipped.
- **Chunking.** Each chunk is an ordinary WriteRequest carrying
  its own absolute offset and the full write_flags of its parent
  — PRIVILEGED_STRIP rides **every** chunk, as the shipped rule
  requires. Chunks of one write never overlap. If the frame bound
  renegotiates downward mid-write, unsent chunks re-slice at the
  new bound, as the shipped client already does per attempt.
- **The window.** In-flight chunks are bounded in count and
  bytes, per handle and per mount — the byte level held by
  construction, not by a second counter (stated 2026-08-18):
  every chunk is cut at or below the fixed unit, so the count
  bound times the unit is the byte bound, and a live byte counter
  could never fire. The reservation is one mount slot only a
  handle's first chunk may take (restated 2026-08-18 to the built
  shape, same effect as first worded), so a saturated window
  always has room for another handle's progress and one large
  write cannot starve it. Both levels are sized at mount and
  fixed thereafter,
  the retention they imply is the window itself — fixed-capacity,
  allocation-free steady state, no overflow class, satisfying the
  kernel core's constraints by construction and sized within the
  request-table capacity that bounds the mount's concurrency. The
  server's per-connection bound of 64 in-flight requests is a
  shared budget — readahead's chunks, metadata traffic and write
  chunks all draw on it — so the write window's default leaves
  the other classes their measured shares (eight chunks per
  handle and thirty-two per mount — first provisional, then kept
  by the W2 matrix, which measured the cliff below cover and
  nothing above it; both counts are mount options now, the
  operator-facing surface that was owed with the numbers),
  and a window that met the ceiling would stall the connection's
  read loop for everyone. The operator's existing per-session
  in-flight override is the WAN dial; the mount's window option
  matching it is operator coordination, stated plainly — nothing
  is negotiated, because the handshake carries no in-flight field
  and this contract adds no wire surface. A full window
  backpressures the writer; it never errors.
- **The send path.** Chunks are independent requests, so the
  client's single serialization point releases between frames.
  The rule that keeps metadata prompt lives at that serialization
  point (restated 2026-08-18 to the shape actually built, same
  effect as first worded): frames carry one of two classes, a
  bulk-class frame takes a single turn before it may queue for
  the writer and holds it until its frame is written, so at most
  one chunk ever waits at the writer and a prompt-class request
  is passed by that one chunk at most, never by the window behind
  it — the request-direction analog of the server's two reply
  classes. Bulk is not starved: the writer is fair, so a waiting
  chunk is passed only by prompt frames already waiting.
  One ordering assumption is stated the way the fsync one is:
  a release, flush or forget naming the same handle or node
  cannot be issued while the write is in flight, because the
  guest kernel holds the file reference across the syscall — the
  kernel client's provider re-establishes this itself.
- **Failure, stated without pretense.** Chunks apply
  concurrently, so a failed chunk does not stop later chunks that
  were already in flight from applying: the bytes-on-disk state
  of a failed streamed write is *some subset of its chunks'
  byte ranges*, not the prefix a serial loop leaves. Error
  delivery stays v1's: the syscall reports the first failed
  chunk's errno, exactly as the serial loop reports its errno
  after a partial apply. The one semantic change this contract
  makes is therefore the failure-time file state — a byte-range
  subset instead of a prefix — confined to writes that fail
  partway, absent entirely on the success path, and priced by the
  W2 matrix: at the shipped defaults the divergence buys 7–31%
  at native latency and costs nothing at any measured latency —
  the cells that measured below serial are windows sized under
  cover, which the defaults are not. One further answer state
  is named for completeness (added 2026-08-18): a chunk answered
  zero bytes without an error ends the write as a short success
  at the answered prefix, exactly as the serial loop breaks on a
  zero answer, and chunks at higher offsets may already have
  applied — the byte-range-subset state on a nominally successful
  return, practically unreachable for a regular-file write and
  recorded so the wording claims nothing it cannot hold. A chunk answered short
  while the write is otherwise healthy resumes from the answered
  byte with a follow-up chunk; once any chunk has failed, no
  resume is attempted. Unsent chunks are abandoned; in-flight
  chunks are awaited before the syscall returns, so nothing of
  the request outlives it.
- **Connection loss.** The resilience contract applies verbatim
  and unamended: a written-but-unanswered chunk fails the write
  with EIO; queued-never-written chunks are sent as they are and
  receive their honest stale answer from the new generation,
  which fails the write the same way — so the all-queued case
  fails too, never a false success — and nothing replays: a
  replayed chunk would address a handle whose id died with the
  generation, and the review record shows replay without a
  fencing surface is a stale-write hazard besides. If session
  continuity ever arrives (the parked attach-connection surface
  is the only candidate), streamed-write replay may be revisited
  in its terms; until then the contract's honest answer is v1's.
- **Barriers and teardown.** fsync, fdatasync, flush and release
  keep v1 semantics with nothing to add: a returned write is an
  answered write. The concurrent-fsync case rests on the guest
  kernel's inode locking (fsync excludes in-flight writers on the
  same inode), an assumption stated here because the kernel
  client's provider must re-establish it itself. Signalled
  teardown owes the kernel only answered operations, and a
  window of in-flight chunks drains inside the bounded settle or
  fails with the teardown's rules — the window depth must be
  sized so a full window can drain inside that bound at the
  mount's measured throughput. The recorded check: the default
  window's ceiling is 8 MiB in flight (thirty-two chunks at the
  256 KiB unit), the slowest measured point moved 9.4 MiB/s, and
  a full window at that pace drains in under a second against a
  two-second settle bound. The bound binds only below ~4 MiB/s of
  effective throughput, where the sizing rule above is the
  operator's — window bytes at most the settle bound times the
  link's pace.
- **Invalidation.** The readahead contract's write-wise bracket
  survives untouched: the client invalidates the file's cached
  blocks around the whole write — all chunks — never per chunk,
  so no prefetch can cache bytes a later chunk is still
  overwriting.
- **Short chunks.** A short chunk answer resumes from where the
  server stopped. The server's apply is a single unlooped pwrite,
  so short answers are real host behavior — probed, then
  asserted, on ext4 and btrfs both, per the standing rule that
  filesystem-behavior assertions are exercised on more than one
  filesystem.

## Interaction with the data plane

None by design: the window is read-only toward the guest
(DATAPLANE.md), the wire is the write path on every transport,
and the streaming engine sits below the syscall boundary and
above the transport seam on both clients, riding vsock, TCP, unix
and the virtio queue identically. A writable arena, if D3 ever
opens one, would be specified in that document against this one's
contract.

## What W2 measured

The matrix, run 2026-08-18 on the development guest (32 vCPUs,
tmpfs-backed server so the disk never enters the numbers):
sequential 1 MiB write syscalls through a direct mount, every
streamed cell against the serial baseline of the same transport,
latency and syscall size; latency injected with netem on the
loopback device (round trip = twice the one-way delay; queue
limit raised so drops never masquerade as transport behaviour);
eight repetitions after the first pass showed native-latency
throughput lands in one of two modes per run and three could not
say which mode a number was from — medians of eight, with the
spread kept in the raw records.

**The unit sweep** (window 8×32, ratios are streamed p50 against
the paired serial p50):

| unit    | unix native | vsock native | tcp native | tcp 1–50 ms RTT |
|---------|-------------|--------------|------------|-----------------|
| 64 KiB  | 1.18×       | 1.19×        | 0.64×      | 0.68–0.70×      |
| 128 KiB | 1.15×       | 1.22×        | 1.11×      | 1.00–1.01×      |
| 256 KiB | 1.13×       | 1.31×        | 1.07×      | 0.97–1.01×      |
| 512 KiB | 1.11×       | 1.27×        | 1.07×      | 0.98–1.00×      |
| 1 MiB   | 0.99×       | 1.01×        | 0.98×      | 0.94–1.00×      |

The shape, stated plainly:

- **The win is real and it lives at native latency**: 7–31% at
  units of 128–512 KiB on every transport, strongest on vsock.
  It is the transfer/apply overlap, not round-trip hiding — under
  injected latency every covered unit measured exactly even,
  because a request is one round trip on both paths and the
  syscall boundary is a barrier on both paths. The serial
  round-trip floor for a single-threaded writer stands exactly as
  the opening section states it.
- **The one cliff is a window smaller than the request**: under
  injected latency, the depth sweep at 128 KiB measured 0.42×
  serial at a quarter of the request covered (2×8), 0.68× at half
  (4×16), and even at cover (8×32) — and nothing above cover, to
  the server's whole budget (16×48 and 32×64 measured identical
  to 8×32). At native latency an under-covered window still wins
  (1.17× at 2×8 on unix), because the cliff is round trips
  multiplied and the round trip there is cheap — the rule guards
  the deployments with distance in them. The
  per-handle depth rule is therefore *cover the request*:
  unit × depth at least max_write. Sixty-four KiB units sit
  under the fixed-cost break-even on tcp (0.64× native) and
  under cover at depth eight (0.68× at latency), which is why
  the default unit is not the smallest one measured.
- **A unit at the request bound is even everywhere** (0.94–1.01×):
  one chunk per request, and the engine's own path — the copy,
  the task, the send-class turn — costs nothing the medians can
  see. The same holds for writes of one chunk or less (the
  128 KiB-syscall pair: 0.96–1.00×), so streaming-on does not tax
  the writes it cannot help.
- **The defaults**: unit 256 KiB, window 8 per handle and 32 per
  mount, streaming on by default on the mounts it applies to at
  all (direct-io stays opt-in). 256 is vsock's measured best and
  within a few points of the best unit on unix and tcp
  (128 KiB leads both by 0.02–0.04×), it is the furthest covered
  unit from the fixed-cost cliff below 128, and it
  covers the request at depth eight with
  a factor-two margin against a frame bound renegotiated down,
  and leaves the per-mount window at 8 MiB in flight. The serial
  path stays one flag away (`--write-stream 0`) and byte for
  byte what it was, and `./check` now runs the write suites both
  ways with the polarity the default implies: the ordinary run
  tests the shipped posture, the pinned run tests serial.
- **Methodology note, recorded so nobody re-derives it**: at
  native latency this guest's throughput is bimodal per run
  (roughly 500 against 900 MiB/s modes, reps within a run tight);
  three-rep cells sampled single modes and first read as a unix
  regression and a vsock unit-bound anomaly — both vanished at
  eight reps. Native-latency medians below eight repetitions are
  not to be trusted on this rig.

The deferred simplification is **decided — the tail-slicing
machinery stays**. The measurements kept multi-chunk windows as
the shipped default (four chunks per request at the default
unit), short answers remain real host behaviour the resume path
serves, and the reduction's price — the first-failed-by-offset
assertion going timing-dependent — is a contract clause's test
losing its determinism. Seventy-three lines do not buy that.

## Phasing

1. **W1 — the userspace engine. DONE 2026-08-18.**
   Sub-frame chunking behind the
   existing write path, window accounting with the per-handle
   reservation, the send-queue class rule, failure gathering with
   the documented partial-application semantics. Criteria: the
   full v1 write suite green with streaming on and off;
   fault-injection arms per chunk position asserting the
   documented failure state (not v1's, and stated as such);
   streaming ships off by default until W2 sets the defaults, and
   a W2 verdict of no sub-frame win sets the chunk unit to the
   frame bound, which makes the engine chunk nothing and the
   failure-state divergence vanish with it; the
   probe-then-assert short-write arm on ext4 and btrfs; the
   torture harness gains a streamed-write storm arm here, not
   later.
2. **W2 — measurement. DONE 2026-08-18.** The chunk-unit and
   depth matrix on unix, vsock and TCP with injected latency
   across the table's points, against the paired serial baseline
   — run, and recorded in "What W2 measured" above: the sub-frame
   win stated plainly (real at native latency, exactly even under
   it), the defaults set from the numbers (256 KiB, 8×32,
   streaming on where it applies), the window counts opened as
   mount options, the teardown-drain check recorded in the
   barriers clause, and the deferred tail-slicing simplification
   decided — the machinery stays, for the reasons recorded with
   the matrix.
3. **W3 — the kernel client's engine.** The same contract inside
   the kernel provider's write path, chunking at and below the
   frame bound from whole syscalls, sharing the session core's
   accounting; the ring-2 torture arm extends to it.

## Acceptance criteria — for this specification

1. The success path weakens nothing: acknowledgment, barrier and
   durability semantics are v1's exactly, and the single
   documented divergence (the failure-state subset) is stated
   with its bound and its test arm.
2. The resilience contract applies unamended, and the document
   contains no replay clause.
3. The window is fixed-capacity with backpressure, a per-handle
   reservation, and no error path, and its sizing names both the
   server's depth ceiling and the teardown-drain bound.
4. The wire is unchanged: no new opcodes, fields or flags, and
   the per-chunk write_flags rule is restated.
5. Every open question names its settling experiment and phase;
   every claim the first draft overstated (the client that never
   sees large writes, the failure prefix, the two-round-trip
   figure, the 172 MB/s workload shape) is corrected against its
   authority.
