# FUSE-over-io_uring — evaluation and decision

Written 2026-08-13. This is the evaluation the roadmap (item 7) gates any
kernel-module work on. It rests on two probing research passes run against
kernel 6.18 sources, the libfuse and fuser trees, and — decisively — a real
A/B experiment executed on the reference VM: a null filesystem served by
fuser's classic `/dev/fuse` loop against the same filesystem served over a
working ring implementation. Raw artifacts kept out of tree.

**Decision: do not adopt a ring path now.** The measured single-request win
is ~5 µs against a 75–95 µs voidport operation, the concurrency win is real
but mostly reachable today through fuser configuration we do not yet use,
every adoption path carries a material cost, and the kernel interface is
still moving. The cheap levers come first; the ring re-enters consideration
only if the residual still dominates after them. A kernel module is even
further out than the ring on this evidence.

## The kernel mechanism (6.14+, verified in the 6.18 source)

- Gated twice: `CONFIG_FUSE_IO_URING=y` at build time (set here) **and** the
  `fuse.enable_uring` module parameter, which defaults to **off**
  (`/sys/module/fuse/parameters/enable_uring`, root-writable at runtime,
  reverts on reboot). The kernel only offers `FUSE_OVER_IO_URING` (flag
  bit 41, requires `FUSE_INIT_EXT`) in the INIT handshake when the parameter
  is on. Any future measurement must record this knob.
- The daemon registers per-queue ring entries with `IORING_OP_URING_CMD`
  SQEs on the `/dev/fuse` fd (ring created with `IORING_SETUP_SQE128`);
  there is one queue per possible CPU (32 on the test kernel) and **every queue
  needs at least one registered entry before the ring goes ready**. Each
  entry carries a 288-byte header buffer plus a payload buffer sized to
  `max(8 KiB, max_write, max_pages × page)` — up to 1 MiB per entry at our
  defaults, which is the memory-sizing concern raised at LSFMM 2026.
- Lifecycle: `FUSE_IO_URING_CMD_REGISTER` parks an entry; the CQE **is** the
  request delivery (no read syscall); the daemon writes results into the
  entry's buffers and submits `FUSE_IO_URING_CMD_COMMIT_AND_FETCH`, which
  commits the reply and fetches the next request in one step. Requests are
  routed to the queue of the CPU the calling task runs on.
- Still on classic `/dev/fuse` even with the ring active: INIT itself,
  FORGET batches, INTERRUPT, and notifications — a ring server keeps both
  paths alive (libfuse multiplexes them with a poll SQE per queue).
- The uapi is explicitly documented as unstable, and a kernel-managed
  buffer-ring / zero-copy series that touches `uapi/linux/fuse.h` was in
  review as of late 2025 — coding against today's interface risks a moving
  target.

## Ecosystem state (verified in the trees, not release notes)

- **libfuse**: full support merged (PR #1177) and shipped in 3.18.0; the
  entire userspace shape is ~1 000 lines of C (`lib/fuse_uring.c`). Off by
  default; teardown/lifecycle fixes were still landing as of days ago.
- **fuser 0.18 (what voidport ships)**: defines the flag bit and *actively
  refuses it* — `FUSE_OVER_IO_URING` is in `UNSUPPORTED_CAPABILITIES`, so
  `add_capabilities` rejects it. No ring code, no PR, one dormant
  auto-filed issue (#380) asking only for the ABI constants. Upstream ETA:
  none in evidence.
- **fractal-fuse 0.6**: a working Rust FUSE-over-io_uring library exists
  (verified by mounting and serving on the reference VM). ~3 500 lines, compio
  thread-per-core runtime, op coverage comparable to ours. Frictions:
  single-vendor and five months old with breaking changes every minor
  release; `async` + `!Send` filesystem trait (a tokio↔compio bridge would
  preserve exactly the thread handoff the ring is meant to remove); mounts
  through a `fusermount3` binary on `$PATH`; its ring internals are
  `mmap` + raw pointers, i.e. the kind of code our workspace-wide
  `deny(unsafe_code)` exists to exclude.

## The measurements

Published upstream numbers (pre-merge RFC tables; the author states the
merged code is expected slower): direct-IO reads up to 3.58×, file creates
2.57× at low thread counts, paged reads 1.2–1.8×, gains shrinking at ≥8
cores. No independent post-merge benchmark exists.

Local A/B on the reference VM (null filesystem, TTL 0, 20 000 ops per phase, client
pinned, three alternating repetitions, p50):

| Phase | classic fuser, 1 thread | ring, 32 per-core queues | delta |
|---|---|---|---|
| stat (1 wire op) | 32.6 µs | 27.7 µs | −5 µs (−15%) |
| open+close (2 ops) | 44.5 µs | 43.5 µs | −1.2 µs (−3%) |
| read after seek | 11.1 µs | 19.2 µs | confounded¹ |

¹ The two servers negotiated different INIT flags (`FUSE_AUTO_INVAL_DATA`
only on the ring side), so the read row compares different revalidation
protocols, not transports. Re-run with matched flags before citing.

With 8 concurrent clients (5 000 stats each, p50 per client):

| Server | stat p50 |
|---|---|
| classic, 1 dispatch thread (voidport's current configuration) | ~110 µs |
| classic, `n_threads = 8` + `clone_fd` | ~59 µs |
| ring | ~39 µs |

## What this means for voidport

1. **The single-request win is ~5 µs**, i.e. 5–7% of the 75–95 µs voidport
   operation — not the 25–35% PERFORMANCE.md projected from "halving the
   residual". The projection over-attributed the residual to the
   `/dev/fuse` syscall pair: the *entire* classic null round trip is only
   ~33 µs on this hardware, so most of voidport's 45–70 µs residual lives
   elsewhere (the client's own tokio handoff among the suspects) and no
   transport change touches it.
2. **The ring's genuine advantage is concurrency** (2.8× over a
   single-loop null filesystem at 8 clients). *Retracted 2026-08-13, same
   day:* the follow-up predicted that fuser's `n_threads` + `clone_fd`
   would recover most of that for voidport. It was landed and measured, and
   it does not — every thread count above one measured *worse* (3–12%
   degradation, wider tails), because voidport is not dispatch-bound: its
   callbacks hand off to the runtime immediately, and the ceiling is
   per-connection, downstream of the event loop. Proof: 16 clients over
   four separate mounts reach 40 943 ops/s where one mount caps at
   ~25 000, whatever the loop count. The null filesystem was
   dispatch-bound because it answered inline on the loop thread — the A/B
   generalized to voidport exactly where voidport differs from it. The
   knob ships (`--dispatch-threads`, default 1, chosen by measurement);
   the concurrency story moves to the client's connection path. A ring
   would not lift this ceiling either: it accelerates kernel↔daemon
   delivery, and the bound is behind the daemon's single wire connection.
3. **Every adoption path is expensive right now**: waiting on fuser has no
   ETA; patching fuser means carrying a fork of a 12 400-line crate whose
   private `ll` module and iovec-shaped reply surface fight the ring's
   buffer model; adopting fractal-fuse means an adapter rewrite plus a
   second async runtime (or a bridge that gives back the affinity win) on
   a young single-vendor crate; a bespoke loop is ~2 700 lines including
   exactly the unsafe memory-mapping code our workspace policy denies —
   against an interface still being reshaped upstream.

## The sequence, in order

1. ~~Land the fuser concurrency configuration and re-run the matrix.~~
   **Done 2026-08-13, negative result** (see the retraction above): the
   knob ships with default 1; voidport is connection-bound, not
   dispatch-bound. The measurement is recorded in PERFORMANCE.md ("The
   FUSE dispatch configuration").
2. **Find the per-connection ceiling** — ~25 000 ops/s per mount (~40 µs
   serialized somewhere on the mount's single wire connection) against
   ~41 000 over four mounts. Candidates: the client's single reader task,
   the write serialization point, the server's per-connection read loop
   and in-flight accounting. This is now the top profiling target: it
   bounds every concurrent workload, and neither dispatch threads nor a
   ring touches it.
3. **Re-run the null-fs A/B with matched INIT flags** to resolve the
   read-path confound (raw artifacts kept out of tree).
4. **Profile where the single-request residual lives** (client tokio
   handoff vs FUSE upcall vs server scheduling) — the null-fs numbers say
   the syscall pair is the smaller share.
5. **Only if FUSE delivery still dominates after 2–4**: a bounded ring
   prototype — fractal-fuse behind the existing adapter serving the
   existing client over a tokio bridge, measured on `open-close-loop` and
   `rand-read-4k`. No compio port of the client unless that prototype
   shows a win that justifies it.
6. **Kernel module**: stays gated. On this evidence the per-op floor is
   not set by the FUSE transport, so a kernel client attacks the wrong
   term until proven otherwise.

Sibling finding, for completeness: `CONFIG_FUSE_PASSTHROUGH` (also enabled
here) does not apply to voidport — it requires the daemon to register a
guest-local backing descriptor, and voidport's data lives behind a socket on
the host by design.

## Reproduction

The A/B recipe that produced the tables: two null filesystems with the same
tree, TTL 0 and identical negotiated INIT flags, one on fuser and one on a
ring library; measure stat / open+close / read, 20 000 ops with 1 000
warmup, `taskset` the client, alternate A/B for ≥3 reps, report p50; then
repeat with 8 concurrent clients — the concurrency arm is the one that
separates the paths. Record `enable_uring`, `n_threads`, `clone_fd`,
`max_background`, and the negotiated INIT flag word in every result line
(the flag word is the only proof the ring was in use).
