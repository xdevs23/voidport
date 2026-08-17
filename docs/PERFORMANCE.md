# voidport — Performance

First measurement pass, taken after v1 (increment 6) landed. It answers three
questions: how much a voidport mount costs against the filesystem it proxies,
how it compares to the incumbent this project exists to beat, and which
workloads the next optimisation — FUSE-over-io_uring — could plausibly move.

Everything below was measured on the date and machine named in *Environment*.
Nothing is extrapolated; where a number is derived from other numbers it says
so.

## Summary

Primary metric per scenario, mean over five measured repetitions. Higher is
better except for the last row.

| Scenario (parameters) | Metric | tmpfs | voidport unix | voidport tcp | 9p |
|---|---|---|---|---|---|
| seq-write (256 MiB, 128 KiB writes, fsync) | MiB/s | 2978 | 369 | 302 | 66 |
| seq-read (256 MiB, 128 KiB reads) | MiB/s | 7499 | 1255 | 970 | 105 |
| rand-read-4k (20 000 × 4 KiB) | ops/s | 903 021 | 14 720 | 10 920 | 12 791 |
| small-files (1000 × 4 KiB, fsync each) | files/s | 104 262 | 1 279 | 1 168 | 359 |
| stat-loop (20 000 stats, 512 files) | ops/s | 585 471 | 201 509 | 190 542 | 1 101 |
| readdir-loop (200 × 1000-entry listings) | listings/s | 6 581 | 60.1 | 52.7 | 47.3 |
| open-close-loop (20 000 open+close) | ops/s | 305 331 | 5 344 | 4 694 | 961 |
| parallel-rw (8 threads × 500 × 64 KiB rw) | ops/s | 218 292 | 9 300 | 7 672 | 3 789 |
| one-writer-many-readers (4 readers) | visibility µs | 53 | 383 | 425 | 57 |

Ratios from the same table:

| Scenario | tmpfs ÷ voidport-unix | voidport-unix ÷ 9p | voidport-unix ÷ voidport-tcp |
|---|---|---|---|
| seq-write | 8.1× | 5.60× | 1.22× |
| seq-read | 6.0× | 11.95× | 1.29× |
| rand-read-4k | 61.3× | 1.15× | 1.35× |
| small-files | 81.5× | 3.57× | 1.10× |
| stat-loop | 2.9× | 182.97× | 1.06× |
| readdir-loop | 109.6× | 1.27× | 1.14× |
| open-close-loop | 57.1× | 5.56× | 1.14× |
| parallel-rw | 23.5× | 2.45× | 1.21× |

Read the `stat-loop` row as a caching comparison, not a protocol comparison:
the voidport client caches attributes and names for one second, the 9p mount is
`cache=none`. The rest of this document says where each number comes from.

## Environment

| Item | Value |
|---|---|
| Date | 2026-08-13 |
| Kernel | Linux 6.18.43, x86\_64, `CONFIG_FUSE_IO_URING=y`, `CONFIG_FUSE_PASSTHROUGH=y` |
| Machine | KVM guest, 32 vCPUs on a 16-core consumer x86-64 host, ~120 GiB RAM |
| Guest root | tmpfs (the VM has no local disk for the workloads) |
| Build | `cargo build --release` (default release profile: opt-level 3, no LTO, 16 codegen units), rustc 1.97.1 |
| Revision | `858b4df` plus the uncommitted `voidport-bench` crate |
| Binaries | `voidportd`, `voidport`, `voidport-bench`, all 0.1.0 |
| FUSE library | `fuser` 0.18; the mount carries `default_permissions`, `fsname=voidport`, no `max_read` override |
| FUSE connection | `max_background=16`, `congestion_threshold=12` (kernel defaults, read from `/sys/fs/fuse/connections`) |
| Client timeouts | attr and entry TTL 1 s (the product defaults) |
| 9p mount | `trans=virtio, msize=512000, access=client`, no `cache=` option — i.e. `cache=none` |

The VM is not otherwise idle-guaranteed: it is a guest on a shared host, so
steal time and host jitter are present. The repetition spread reported with
each scenario is the honest bound on that.

## Method

### The harness

`voidport-bench` is a workspace-member binary (`publish = false`), one
subcommand per scenario. It knows nothing about voidport: it is handed a
directory with `--dir` and measures what that directory does, which is exactly
what makes one command comparable across four backends. Timing is
`std::time::Instant` throughout; there are no dependencies beyond what the
workspace already carries (`clap`, `serde`, `serde_json`, `anyhow`, and
`rustix` for `sync(2)`).

Every run emits one JSON object per line on stdout — scenario, backend label,
directory, parameters, warmup and repetition counts, every measured
repetition, and the derived summary — and a human summary on stderr. Raw records for this pass (36 matrix runs
and a 14-run chunk sweep) and the driver that produced them are kept out of
tree.

### Discipline

- One unmeasured warmup repetition, then five measured repetitions, for every
  backend × scenario cell.
- `sync(2)` followed by `echo 3 > /proc/sys/vm/drop_caches` before **every**
  repetition, warmup included. This drops the guest page, dentry and inode
  caches. It does not evict tmpfs contents — tmpfs pages *are* the storage —
  and it cannot reach the host's page cache behind the 9p mount.
- Preparation (creating the file a read scenario reads, the file set a stat
  loop stats) happens once, before the repetitions and therefore before the
  cache drops, so it is neither timed nor warm.
- Percentiles are nearest-rank. `p50`/`p99` on a per-operation latency are
  computed over every sampled operation of all five repetitions pooled
  (100 000 samples for the 20 000-op loops, 5000 for `small-files`); `p99` on
  a wall time is over the five repetitions and is therefore just the worst
  one.
- Every scenario works in its own subdirectory, removed and recreated at
  start, so one backend's leftovers cannot be another's warm cache.

### The backends

| Label | What it is |
|---|---|
| `tmpfs` | A fresh `mount -t tmpfs` created by the driver. The baseline: the same kernel, no proxy. |
| `voidport-unix` | A `voidport` FUSE mount over a unix socket, served by `voidportd`, whose single rw graft is a directory **on that same tmpfs**. The difference from the baseline is the whole proxy and nothing else. |
| `voidport-tcp` | The same server, the same graft, mounted over tcp on `127.0.0.1`. The difference from `voidport-unix` is the tcp stack. |
| `9p` | A subdirectory of the project's own 9p mount (`trans=virtio`), i.e. the incumbent, as the rig is actually configured. |

The server ran one namespace with `ownership.mode = "passthrough"`,
`permission = "passthrough"`, `auth = "none"` and one rw graft, with both
listeners active. Backends were run sequentially, never concurrently.

### The scenarios

Each names one operation, and the per-operation latency columns are that
operation timed individually.

| Scenario | What one operation is | Timed window |
|---|---|---|
| `seq-write` | one `write(2)` of the chunk size | create → write the whole file → `fsync` → close |
| `seq-read` | one `read(2)` of the chunk size | open → read to EOF |
| `rand-read-4k` | one `pread(2)` of 4 KiB at a pseudorandom block offset | the whole loop; the open is outside it |
| `small-files` | one file's whole life: create, write, `fsync`, close | the whole batch |
| `stat-loop` | one `stat(2)` by path (path resolution included) | the whole loop |
| `readdir-loop` | one complete listing: opendir, all readdir calls, closedir — names only, no per-entry stat | the whole loop |
| `open-close-loop` | one `open(2)` + `close(2)` of an existing file | the whole loop |
| `one-writer-many-readers` | one record becoming visible | see below |
| `parallel-rw` | one 64 KiB `pwrite` + one 64 KiB `pread` at pseudorandom offsets, per thread | from the start barrier to the last thread's join |

`one-writer-many-readers` needs its own paragraph. A writer appends 40 records
of 4 KiB to one file, pacing itself 100 ms apart, and timestamps each append
the instant `write(2)` returns. Four reader threads hold their own descriptors
open and poll with `pread(2)` every 50 µs for the next record; when a reader
reads record *i* intact it records the delta from the writer's timestamp. That
delta is the reported visibility latency. Pacing is what makes it a visibility
latency, not a queue depth. Two consequences to keep in mind when
reading the numbers: the poll interval puts a sampling floor of roughly 25 µs
(half a poll period) under the measurement, and four readers polling every
50 µs offer up to ~80 000 requests/s to the mount's single connection, so both
the visibility latency and the writer's append latency in that scenario are
measured *under load*, not on an idle path. The pattern is identical on all
four backends, so the comparison holds.

### Notes on these numbers

1. **The 9p tree is not memory-backed and is shared with a live host.** The
   tmpfs and both voidport backends read and write RAM. The 9p mount's backing
   store is the host's real filesystem, on a host that is doing other things.
   For the write-and-fsync scenarios (`seq-write`, `small-files`) this
   flatters voidport by an unknown amount: 9p is paying for real durability.
   For the read scenarios the host's page cache almost certainly holds the
   freshly written file, so those comparisons are closer to protocol-versus-
   protocol. No 9p number here should be read as "9p on this hardware would be
   X on a tmpfs".
2. **The tmpfs baseline cannot be made cold.** `drop_caches` does not evict
   tmpfs. The baseline is therefore a memory-speed floor, which is the right
   reference for "what does the proxy add" and the wrong one for "what would
   this cost on a disk".
3. **VM jitter.** Repetition-to-repetition spread (max−min over the mean) was
   under 11% for every cell except three: `seq-write` on 9p (18.7%),
   `seq-write` on `voidport-unix` (16.7%), and `rand-read-4k` on
   `voidport-unix` (11.2%). The two writes are the largest single transfers
   in the matrix; treat their means as ±10%.
4. **Both voidport backends shared one server process and one graft
   directory**, run sequentially. The tcp and unix listeners were both bound
   throughout, but only one was in use at a time.
5. Percentile counts differ by scenario (see *Discipline*); a `p99` over five
   wall times is the worst repetition, not a tail estimate.

## Results

Wall times are per repetition. Latency columns are per-operation, pooled over
all five repetitions, in microseconds.

### seq-write — 256 MiB, 128 KiB writes, fsync and close inside the window

| Backend | MiB/s mean | MiB/s worst rep | wall mean (s) | wall p99 (s) |
|---|---|---|---|---|
| tmpfs | 2978.4 | 2941.2 | 0.086 | 0.087 |
| voidport-unix | 369.1 | 329.2 | 0.696 | 0.778 |
| voidport-tcp | 301.5 | 291.8 | 0.850 | 0.877 |
| 9p | 65.9 | 62.6 | 3.903 | 4.087 |

### seq-read — 256 MiB, 128 KiB reads, cold guest cache

| Backend | MiB/s mean | MiB/s worst rep | wall mean (s) | wall p99 (s) |
|---|---|---|---|---|
| tmpfs | 7498.5 | 7282.6 | 0.034 | 0.035 |
| voidport-unix | 1255.0 | 1209.9 | 0.204 | 0.212 |
| voidport-tcp | 969.5 | 951.2 | 0.264 | 0.269 |
| 9p | 105.1 | 103.3 | 2.437 | 2.478 |

### rand-read-4k — 20 000 × 4 KiB preads over a 256 MiB file

| Backend | ops/s | MiB/s | lat mean | lat p50 | lat p99 | lat max |
|---|---|---|---|---|---|---|
| tmpfs | 903 021 | 3527.4 | 1.1 | 1.0 | 1.5 | 20.6 |
| voidport-unix | 14 720 | 57.5 | 68.0 | 75.1 | 119.0 | 1796.7 |
| voidport-tcp | 10 920 | 42.7 | 91.6 | 101.2 | 164.9 | 954.3 |
| 9p | 12 791 | 50.0 | 78.2 | 75.7 | 111.0 | 1150.5 |

On both voidport backends the mean sits *below* the median, which it does not
on 9p. The fast cluster is the guest page cache: a fraction of the 4 KiB reads
land in a page some earlier read pulled in. `p50` is the figure to read as the
round trip. `cache=none` gives 9p no such cluster, and tmpfs is all cache.

### small-files — 1000 files, 4 KiB each, create + write + fsync + close

| Backend | files/s | lat mean | lat p50 | lat p99 | lat max |
|---|---|---|---|---|---|
| tmpfs | 104 262 | 9.4 | 8.3 | 18.2 | 642.6 |
| voidport-unix | 1 279 | 781.7 | 773.0 | 1068.8 | 1664.6 |
| voidport-tcp | 1 168 | 856.2 | 842.4 | 1185.9 | 1982.3 |
| 9p | 359 | 2789.7 | 2749.3 | 3415.5 | 34 298.1 |

### stat-loop — 20 000 `stat(2)` by path over 512 files

| Backend | ops/s | lat mean | lat p50 | lat p99 | lat max |
|---|---|---|---|---|---|
| tmpfs | 585 471 | 1.7 | 1.6 | 2.0 | 31.4 |
| voidport-unix | 201 509 | 4.9 | 1.8 | 112.9 | 5345.9 |
| voidport-tcp | 190 542 | 5.2 | 1.9 | 122.8 | 5803.1 |
| 9p | 1 101 | 908.0 | 896.0 | 1123.0 | 3309.5 |

The bimodal voidport distribution is the client's 1-second TTL: `p50` is a
guest cache hit at 1.8 µs, `p99` is the round trip taken when the TTL expires.

### readdir-loop — 200 complete listings of a 1000-entry directory

| Backend | listings/s | entries/s | lat mean (µs) | lat p50 | lat p99 | lat max |
|---|---|---|---|---|---|---|
| tmpfs | 6 581 | 6 581 241 | 151.9 | 148.7 | 181.8 | 296.9 |
| voidport-unix | 60.1 | 60 071 | 16 647.5 | 16 329.6 | 19 698.7 | 26 631.5 |
| voidport-tcp | 52.7 | 52 712 | 18 971.0 | 18 846.0 | 23 484.6 | 26 576.0 |
| 9p | 47.3 | 47 252 | 21 163.1 | 20 859.5 | 24 450.4 | 24 873.1 |

### open-close-loop — 20 000 open + close over 64 existing files

| Backend | ops/s | lat mean | lat p50 | lat p99 | lat max |
|---|---|---|---|---|---|
| tmpfs | 305 331 | 3.2 | 3.2 | 4.3 | 58.8 |
| voidport-unix | 5 344 | 187.1 | 181.8 | 295.0 | 2834.9 |
| voidport-tcp | 4 694 | 213.1 | 207.1 | 335.8 | 3031.1 |
| 9p | 961 | 1041.8 | 1021.8 | 1325.9 | 2779.6 |

### parallel-rw — 8 threads × 500 × (64 KiB pwrite + 64 KiB pread)

| Backend | ops/s | MiB/s | lat mean | lat p50 | lat p99 | lat max |
|---|---|---|---|---|---|---|
| tmpfs | 218 292 | 27 286.5 | 33.1 | 33.8 | 55.6 | 619.6 |
| voidport-unix | 9 300 | 1162.5 | 855.3 | 845.9 | 1155.3 | 1659.4 |
| voidport-tcp | 7 672 | 959.0 | 1037.0 | 1029.8 | 1381.2 | 1756.3 |
| 9p | 3 789 | 473.7 | 2106.7 | 2076.2 | 2601.3 | 3187.7 |

### one-writer-many-readers — 1 writer (40 × 4 KiB, 100 ms apart), 4 polling readers

| Backend | visibility mean | p50 | p99 | max | append mean | append p99 (worst rep) | timeouts |
|---|---|---|---|---|---|---|---|
| tmpfs | 53.0 | 52.9 | 108.1 | 133.4 | 13.4 | 38.3 | 0 |
| voidport-unix | 382.8 | 378.0 | 683.1 | 727.2 | 502.6 | 745.1 | 0 |
| voidport-tcp | 425.3 | 426.3 | 740.8 | 780.8 | 537.2 | 828.8 | 0 |
| 9p | 56.8 | 47.4 | 172.2 | 312.8 | 178.2 | 272.4 | 0 |

All values in microseconds. No record ever failed to become visible within the
5-second per-record timeout on any backend. The append latency is measured
under the readers' polling load, as described in *The scenarios*.

Two things need stating plainly here. First, voidport's visibility latency
is **not** TTL-bounded even though the entry/attr TTL is 1 second: the client
negotiates `FUSE_AUTO_INVAL_DATA`, so the kernel revalidates size before
serving a read, and a new record is seen within a few hundred microseconds
instead of within a second. Second, 9p is the faster of the two here (57 µs vs
383 µs), because `cache=none` means the reader's poll is an unconditional
round trip with no revalidation step, and because the voidport numbers include
queueing behind the polling load on the mount's single connection.

### Supplementary probe — request size sweep

Not part of the matrix. 64 MiB file, three measured repetitions, run to
separate the fixed per-request cost from the per-byte cost. `µs/call` is the
window divided by the number of `read`/`write` calls the harness issued.

| Backend | Scenario | chunk | MiB/s | µs/call |
|---|---|---|---|---|
| voidport-unix | seq-write | 4 KiB | 28.9 | 135 |
| voidport-unix | seq-write | 32 KiB | 174.1 | 180 |
| voidport-unix | seq-write | 128 KiB | 412.3 | 303 |
| voidport-unix | seq-write | 1 MiB | 600.1 | 1667 |
| voidport-unix | seq-read | 4 KiB | 1173.1 | 3 |
| voidport-unix | seq-read | 128 KiB | 1247.7 | 100 |
| voidport-unix | seq-read | 1 MiB | 1161.4 | 863 |
| tmpfs | seq-write | 4 KiB | 1841.2 | 2 |
| tmpfs | seq-write | 128 KiB | 3113.6 | 40 |
| tmpfs | seq-write | 1 MiB | 3088.8 | 324 |
| tmpfs | seq-read | 4 KiB | 4062.6 | 1 |
| tmpfs | seq-read | 128 KiB | 7760.6 | 16 |
| tmpfs | seq-read | 1 MiB | 7949.6 | 126 |

A straight line through the voidport-unix write points gives a fixed cost of
about **110–130 µs per write request** and a marginal cost of about
**1.5 µs/KiB (≈650 MiB/s)**. The read points are flat in the application's
read size — 4 KiB reads go as fast as 1 MiB reads — which is the kernel page
cache plus readahead absorbing the request size entirely.

## Analysis

### Where the overhead sits

The per-operation floor is the whole story for everything except bulk reads.
Against the tmpfs baseline, a single wire operation costs:

| Measurement | tmpfs | voidport-unix | difference |
|---|---|---|---|
| 4 KiB random read (1 wire op), p50 | 1.0 µs | 75.1 µs | +74 µs |
| open + close (2 wire ops), mean | 3.2 µs | 187.1 µs | +184 µs |
| stat with the TTL expired (1 wire op), p99 | 2.0 µs | 112.9 µs | +111 µs |
| create+write+fsync+close (~5 wire ops), mean | 9.4 µs | 781.7 µs | +772 µs |

The two cleanest measurements — a 4 KiB random read (one wire operation) and
an open+close pair (two) — both put one wire operation at **75–95 µs**. The
composite rows are consistent with that once their round trips are counted,
though the exact count is not observable from the guest. That per-operation
figure is the number to attack.

Decomposing it with the evidence available here instead of with a profiler:

- **The host syscall itself is ~1–3 µs** — that is the tmpfs column. It is
  under 5% of the cost. The server's work (rule resolution, `openat2` under
  `RESOLVE_BENEATH`, attribute mapping) is not what is being paid for.
- **Serialization is not the cost either.** The wire is fixed-layout zerocopy
  structs; payloads are never re-encoded. The per-byte behaviour confirms it:
  the marginal write cost of 1.5 µs/KiB is ~650 MiB/s, which is memcpy-class
  for the several copies the path makes (guest page → FUSE device → client
  buffer → socket → server buffer → host `pwrite`), not parse-class.
- **The transport is 13–26 µs of it.** The tcp-minus-unix delta is 23.6 µs on
  `rand-read-4k`, 26.0 µs on `open-close-loop`, and 74.5 µs on `small-files`
  (which is ~5 operations, so ~15 µs each). Loopback tcp adds roughly a fifth
  to a third of the per-op cost. This is the cost of `voidport://` over
  `voidport+unix://` and is the argument for vsock over tcp for VM guests on
  latency grounds as well as on the security grounds already in the threat
  model.
- **The remaining 45–70 µs is the FUSE upcall plus scheduling.** Every request
  crosses: guest syscall → `/dev/fuse` → the client's fuser dispatch thread →
  a handoff to the client's async runtime (the contract forbids blocking the
  dispatch loop) → socket write → server reader task → tokio blocking pool for
  the host syscall → reply → writer task → socket → `/dev/fuse` write → the
  waiting guest thread wakes. That is on the order of six to eight context
  switches and two thread handoffs per operation, none of which the tmpfs
  baseline pays.

Bulk reads are the exception at the application level: readahead and the page
cache absorb the request size entirely — 4 KiB reads run as fast as 1 MiB
reads (the sweep above) — and throughput settles at ~1.25 GiB/s regardless.
But 1.25 GiB/s is 100 µs per 128 KiB, which is what *one* 128 KiB wire read
costs. The read stream therefore appears to run about one request deep, not
deeply pipelined. Two candidate levers, neither tested: the negotiated
`max_readahead` and the resulting readahead window, and `max_background=16`,
which caps how many asynchronous requests the kernel will have outstanding.
The client sets neither today.

Bulk writes are per-op bound because they are meant to be. The design rules
writethrough with no writeback cache, so every `write(2)` is a synchronous
round trip; the 4 KiB row of the sweep (28.9 MiB/s) is what that costs a guest
that writes in small chunks. This is a deliberate coherence trade, not a
defect, but it is the single largest gap to the baseline in the whole matrix
and the thing to know is that it lives entirely in the client's caching policy.

> **Superseded 2026-08-14 by *The optimisation pass* at the end of this
> document.** The instrumented attribution settled the split this paragraph
> leaves open, and it is not the one the paragraph guesses at: the client
> side is 1.0% of the cost, server materialisation 23%, and the *second*
> pass over the same entries inside `readdirplus` a larger 39%. The pass
> that followed cut the listing to 4.9 µs per entry. The paragraph is kept
> as the question that was asked.

The `readdir-loop` row is the weakest result in the matrix and is not
explained by the per-op floor: 16.6 ms for a 1000-entry listing is 16.6 µs per
entry, about 110× the tmpfs cost per entry and only 1.27× better than 9p.
The data-plane contract has `opendir` materialise the entire merged,
policy-filtered listing with attributes resolved, which is a rule lookup and a
stat per entry before the first entry is returned; the client then does
per-entry lookup-count accounting on the way out. That is the chosen design (it
buys stable cookies over the merged view), and 16.6 µs per entry is far above
both the host's stat cost (1.7 µs) and any plausible per-entry share of a
batched transfer. Which of the three — server materialisation, per-entry
client accounting, or the kernel's dentry instantiation — dominates is not
resolved by this pass. It deserves its own profiling pass before anything else
in the optimisation queue.

### Against 9p, per workload class

- **Bulk transfer: voidport wins decisively.** 5.6× on writes, 12× on reads.
  Both are inflated by the backing-store difference (note 1), so treat the
  direction as solid and the magnitude as an upper bound.
- **Small random reads: a tie.** 14 720 vs 12 791 ops/s, 68 µs vs 78 µs. Both
  are one round trip per read; 9p over virtio and voidport over a unix socket
  cost about the same per round trip. voidport does not win this class on
  protocol design; it wins it on caching policy when the workload allows
  caching at all.
- **Metadata under a cache: voidport wins by two orders of magnitude** (183× on
  `stat-loop`) purely because the client caches attributes and names for a
  second and this 9p mount does not cache. A `cache=loose` 9p mount would
  close most of that; the comparison as configured is the honest one for
  *this* VM, not a protocol claim.
- **Metadata without a cache: voidport wins by ~5×** (`open-close-loop`,
  `small-files`). Opens and creates are never served from a guest cache on
  either filesystem, so this is protocol against protocol: 187 µs vs 1042 µs
  per open/close, 782 µs vs 2790 µs per created file.
- **Directory listing: voidport barely wins** (1.27×), for the reasons above.
- **Parallel mixed I/O: voidport wins 2.45×**, and scales better — 8 threads
  reach 1.16 GiB/s through one mount.
- **Cross-mount visibility: 9p wins** (57 µs vs 383 µs). A `cache=none`
  filesystem has nothing to revalidate. voidport's 383 µs is still three orders
  of magnitude below the 1-second TTL a reader would suffer without
  `FUSE_AUTO_INVAL_DATA`, which is the capability the increment-6 spec review
  made the client negotiate.

Summary judgement: voidport beats 9p everywhere the workload is bulk or
cacheable, beats it by ~5× on uncacheable metadata, ties on small random
reads, and loses on immediate cross-mount visibility. The one place it is
uncomfortably close to 9p — directory listings — is a server-side
materialisation cost, not a transport cost.

### What FUSE-over-io_uring could plausibly improve

> **Superseded 2026-08-13 by docs/IO_URING.md.** A measured A/B (null
> filesystem, classic loop vs a real ring) put the single-request ring win
> at ~5 µs — 5–7% of a voidport operation, not the 25–35% projected below.
> The projection over-attributed the residual to the `/dev/fuse` syscall
> pair; the whole classic null round trip is only ~33 µs on this hardware.
> The ring's genuine advantage is concurrency, and most of that is
> reachable by configuring fuser's `n_threads` + `clone_fd`, which the
> mount currently leaves at the single-thread default. The ranking below
> stands as a description of which workloads are residual-bound; the
> magnitudes do not.
>
> That last expectation was itself measured on 2026-08-13 — see *The FUSE
> dispatch configuration* at the end of this document. Against voidport the
> loop count changes nothing for the better: a mount's concurrency ceiling
> is on the client's per-connection path, not in the FUSE event loop.

The kernel here is built with `CONFIG_FUSE_IO_URING=y` (6.14+ feature). The
mechanism removes the `read`/`write` syscall pair on `/dev/fuse` and its
context switches, replacing them with shared ring buffers and per-core queues.
It therefore attacks precisely the 45–70 µs residual identified above, and
nothing else: it does not change the wire protocol, the transport, the host
syscall, or any copy.

Ranked by how much of each scenario's cost is that residual:

1. **`open-close-loop`, `small-files`, `stat-loop` on TTL expiry** — pure
   per-op round trips with no payload. If the residual is halved these move by
   roughly 25–35%. These are also the workloads that make a source tree feel
   slow, so the user-visible effect is larger than the percentage suggests.
2. **`rand-read-4k`** — one round trip per 4 KiB, 68 µs today with a ~1 µs
   host read underneath. Same reasoning.
3. **`seq-write` at small chunk sizes** — the fixed 110–130 µs per write
   request is the whole cost below 32 KiB. At 128 KiB and above the marginal
   copy cost dominates and the gain tapers.
4. **`one-writer-many-readers`** — the visibility path is a getattr plus a
   read, under polling load; lower per-request cost both shortens the path and
   raises the ceiling the polling saturates.
5. **`parallel-rw`** — helps, but this workload is already partly
   throughput-bound.

Where it will *not* help: `readdir-loop`, whose cost is per-entry listing work
on the server and the client, which no transport change touches. `seq-read` is
uncertain — the application sees a page cache, but the stream underneath runs
about one 128 KiB request deep at ~100 µs each, so a cheaper request would
raise the ceiling unless the readahead window is what binds first.

Two prerequisites need recording now. `fuser` 0.18 defines the
`FUSE_OVER_IO_URING` capability bit but implements no ring, so adopting it
means library work or a bespoke `/dev/fuse` path. And two cheaper experiments
should be run first, because they are configuration, not architecture:
raising `max_background` above 16 (bulk read ceiling), and profiling the
`opendir` materialisation (listing cost). Both are measurable with this
harness as it stands.

## Anomalies observed

- **Every one of the 36 matrix runs and 14 probe runs completed.** No run
  stalled, timed out, or produced a short read. No visibility record ever hit
  its 5-second timeout on any backend.
- **No unmount needed a retry.** The driver retries `voidport umount` on EBUSY
  up to 20 times and logs every retry; the log is empty across all six driver
  invocations.
- **`fuser` logs `Unmount failed: Invalid argument (os error 22)` at teardown**
  in the foreground `voidport mount` process, once per mount, every time. It is
  benign and expected in this arrangement: the driver unmounts with
  `voidport umount` from another process, the foreground mount's session loop
  ends and `serve_until_signalled` then returns,
  and the session's own drop attempts a second unmount of a mountpoint that is
  already gone. Know this before someone reports it as a teardown bug; the
  message is a warning from the library, not a failure of the unmount.
- **`seq-write` is the noisiest cell** (18.7% spread on 9p, 16.7% on
  `voidport-unix` between the best and worst of five repetitions). The only
  other cell above 11% is `rand-read-4k` on `voidport-unix` at 11.2%.
- **`small-files` on 9p has a 34 ms outlier** against a 2.7 ms median — one
  file in 5000 took twelve times the median. Consistent with the host's own
  writeback; not reproduced on any memory-backed backend.

## What was not measured

- **vsock.** The transport is served (2026-08-15), but no benchmark was run
  over it: the numbers in this document predate it, so tcp is still the only
  network-transport figure here. Given the 13–26 µs loopback-tcp delta,
  vsock is expected to land between unix and tcp, but that is a prediction,
  not a measurement.
- **Multi-VM contention.** Everything ran in one guest. One server serving
  several guests concurrently — the product's actual deployment — is
  unmeasured, as is contention between namespaces.
- **Real durable storage.** No workload here touched a disk from the guest
  side. Fsync costs are tmpfs fsync costs (near zero) on three of the four
  backends.
- **Session and connection scaling.** One mount, one connection, one
  namespace, one graft. The resource caps (`max_sessions`, `max_inflight`,
  node and handle caps) were unconfigured and never approached.
- **Policy-resolution cost under a large rule table.** The namespace had one
  rule. Wildcards, deep literal chains and hidden entries all add per-lookup
  work that this pass cannot see.
- **The control plane.** No mutation traffic ran during the benchmarks, so the
  cost of a rule change against a live mount is unmeasured.
- **Memory and CPU consumption.** Only latency and throughput were recorded.
  The server's residency under load, and the client's, are unknown.
- **A profiler breakdown.** The decomposition in *Where the overhead sits* is
  built from differences between measured configurations. It is consistent,
  but no `perf` run was taken to confirm the split between context switches,
  scheduling and copying.

## Reproducing

The harness is the `voidport-bench` crate and is part of the tree. The matrix
driver and the raw records are not — they are scratch artifacts kept out of
tree — so a reader reproduces by running the harness directly (example below).

```
nix develop path:. -c cargo build --release -p voidportd -p voidport -p voidport-bench
```

The out-of-tree driver mounts a tmpfs, starts `voidportd`, mounts the client
twice, runs every scenario against every backend, and unmounts everything on
every exit path including failure. It needs root (page-cache drops, mounting)
and `/dev/fuse`, and it appends one JSON line per run plus a human summary.

A single measurement, without the driver:

```
voidport-bench --dir /some/directory --label whatever --reps 5 --warmup 1 \
    --drop-caches rand-read-4k --size-mib 256 --ops 20000
```

## 2026-08-13 — the FUSE dispatch configuration

This section is the measurement pass behind item 1 of `docs/IO_URING.md`'s
sequence: land fuser's `n_threads` + `clone_fd` on the client's session and
re-measure. The configuration landed as `MountOptions::dispatch_threads` and
the `voidport mount --dispatch-threads` flag; `clone_fd` rides with it
unconditionally, so above one loop each loop reads its own `/dev/fuse`
descriptor.

**The chosen default is one event loop**, because one measured best on every
scenario and at every client count tried. The rest of this section is why.

Same machine and method as the pass above, except where a table says
otherwise. Kernel 6.18.43, 32 vCPUs, `cargo build --release`, revision
`e875298` plus the uncommitted dispatch-threads change,
`/sys/module/fuse/parameters/enable_uring` = `Y` (left on by the io_uring
experiment; irrelevant here — fuser 0.18 lists `FUSE_OVER_IO_URING` in its
unsupported capabilities and refuses it, so no voidport mount can use the
ring), `max_background` at the kernel default of 16.

### The sweep — one client, `voidport-unix`, three measured repetitions

Warmup 1, cache drops before every repetition, exactly the matrix's discipline
and parameters. Only the loop count differs between rows.

| Event loops | stat-loop ops/s | open-close-loop ops/s | parallel-rw ops/s | parallel-rw MiB/s | one-writer-many-readers visibility mean µs |
|---|---|---|---|---|---|
| 1 | 215 805 | 5 574 | 9 977 | 1247 | 351 |
| 4 | 207 109 | 4 844 | 9 806 | 1226 | 397 |
| 8 | 205 935 | 4 697 | 9 768 | 1221 | 419 |
| 16 | 206 199 | 4 619 | 9 631 | 1204 | 413 |

Repetition spread was under 3.1% in every cell except `stat-loop` at one loop
(12.3%, the TTL-hit scenario's usual noise). `parallel-rw` is the matrix's only
multi-threaded scenario — eight guest threads through one mount — and it is
the one row where extra loops were expected to pay. They do not: every count
above one is slower, monotonically, by 1.7% to 3.5%.

### The concurrency probe — several client processes, one mount

The matrix has no many-clients cell, and many clients is the arm
`docs/IO_URING.md` measured (8 clients, ~110 µs → ~59 µs on a *null*
filesystem). An out-of-tree concurrency driver reproduces that shape against
voidport: N `voidport-bench open-close-loop` processes started together on one
mount, each in its own subdirectory, three repetitions, warmup 1. Cache drops
are off here — several clients dropping the guest cache under each other would
measure the drops. Aggregate is the sum of the per-client means; latency is
the mean over clients of each client's pooled per-operation latency.

| Clients | Mounts | Event loops | aggregate ops/s | per client | lat mean µs | lat p99 µs |
|---|---|---|---|---|---|---|
| 8 | 1 | 1 | 23 063 | 2 883 | 347 | 613 |
| 8 | 1 | 4 | 22 295 | 2 787 | 359 | 646 |
| 8 | 1 | 8 | 20 912 | 2 614 | 382 | 742 |
| 8 | 1 | 16 | 20 603 | 2 575 | 388 | 764 |
| 16 | 1 | 1 | 25 082 | 1 568 | 638 | 981 |
| 16 | 1 | 8 | 22 510 | 1 407 | 711 | 1324 |
| 32 | 1 | 1 | 24 548 | 767 | 1304 | 1976 |
| 32 | 1 | 4 | 23 720 | 741 | 1349 | 2166 |
| 32 | 1 | 8 | 22 565 | 705 | 1418 | 2432 |
| 32 | 1 | 16 | 21 574 | 674 | 1483 | 2710 |
| 16 | 4 | 1 | 40 943 | 2 559 | 391 | 1155 |
| 16 | 4 | 8 | 39 503 | 2 469 | 405 | 1193 |

Repetition spread was 2.4–7.0% throughout. Three things fall out of this
table, and the third is the load-bearing one.

1. **One mount saturates at ~23–25 000 open+close per second** no matter how
   many clients push at it: 8, 16 and 32 clients all land in that band, and
   the extra clients buy latency, not throughput.
2. **More event loops never raise that ceiling.** They lower it, by 3% to 12%,
   monotonically in the loop count, and they widen the tail (p99 at 32 clients
   goes 1976 µs → 2710 µs from 1 loop to 16). Extra loops add cross-loop
   wakeups and a second set of parked reader threads with their own
   megabyte-class request buffers, against a queue that was not the
   constraint.
3. **The ceiling is per-mount, not per-machine and not per-loop.** The same 16
   clients spread over four mounts of the same namespace on the same server
   reach 40 943 ops/s — 1.63× the one-mount figure — with each mount running a
   single loop. If the loop were the bottleneck, one loop per mount would have
   capped each mount near its own saturation point; instead four mounts scale
   most of the way and one mount does not.

So a voidport mount's concurrency limit lives downstream of the FUSE event
loop, on the client's per-connection path (one socket, one writer, one reader
task demultiplexing every response). Adding loops in front of that queue
cannot help, and the measurement says it mildly hurts.

This is the honest answer to `docs/IO_URING.md`'s expectation that the fuser
configuration would take "1.87× of [the ring's concurrency advantage] off the
table": **not reproduced for voidport.** That figure came from a null
filesystem whose whole round trip is ~33 µs, where the dispatch loop really is
the busiest thing in the path. At voidport's 180–350 µs per open+close the loop
is nowhere near saturated, and the ring would be attacking the same
non-bottleneck. Whether that changes the ring's ranking in the roadmap is a
decision, not a measurement, and is left to the document that owns it.

### The default, and what it is not

`DEFAULT_DISPATCH_THREADS` is 1. That reproduces fuser's own default exactly —
at one loop fuser clones no descriptor, so `clone_fd` has no effect either —
which means **the shipped default is behaviourally identical to the
configuration every number in the first pass was taken under.**

The knob still earns its place: the ceiling above is a property of *this*
client's per-connection path, not of FUSE. A deployment whose per-operation
cost is far below voidport's 75–95 µs, or a future client that lifts the
per-connection limit, reaches the point where one loop binds — and the
adapter is already sound under parallel dispatch. `fuser::Filesystem` is
declared `Send + Sync + 'static` and fuser shares one `Arc` of it across the
loops; the only two `&mut self` callbacks are outside the parallel window by
construction (`init` runs during `Session::new`'s handshake, before any loop
exists; `destroy` runs after all of them are joined); every other callback
takes `&self`, and the adapter holds nothing mutable — an `Arc<Client>`, a
runtime handle and two durations. The state that does mutate is the client's,
behind its own locks, and the tokio runtime already reached it concurrently
under a single loop. The mount assembly records this at the site.

Live check on the rig: `voidport mount --dispatch-threads 8` shows eight
`fuser-N` threads and eight distinct `/dev/fuse` descriptors in the mount
process; at 1 it shows one of each. The e2e suite passes unchanged at the
default, and `./check` is green.

### Matrix re-run

The full matrix as it then stood — nine scenarios; `walk` is the tenth, added
by the descriptor-budget increment — was re-run at the shipped default over `tmpfs`,
`voidport-unix` and `voidport-tcp`; 9p was re-run for the two concurrent
scenarios only, since the client configuration cannot touch it (its two rows
below, unchanged to within 1.4%, are the check on that). Because the default
is behaviourally identical to the first pass's configuration, this is a
**reproducibility check, not a before/after**: every difference is run-to-run
drift on a shared host, and the size of it is the useful result.

| Scenario | Metric | voidport-unix before | after | voidport-tcp before | after |
|---|---|---|---|---|---|
| seq-write | MiB/s | 369.1 | 409.5 | 301.5 | 357.1 |
| seq-read | MiB/s | 1255.0 | 1349.0 | 969.5 | 1094.9 |
| rand-read-4k | ops/s | 14 720 | 14 857 | 10 920 | 12 743 |
| small-files | files/s | 1 279 | 1 470 | 1 168 | 1 327 |
| stat-loop | ops/s | 201 509 | 225 188 | 190 542 | 205 119 |
| readdir-loop | listings/s | 60.1 | 60.7 | 52.7 | 58.6 |
| open-close-loop | ops/s | 5 344 | 5 479 | 4 694 | 4 865 |
| parallel-rw | ops/s | 9 300 | 9 862 | 7 672 | 7 730 |
| one-writer-many-readers | visibility µs | 382.8 | 370.0 | 425.3 | 413.0 |

The baseline drifted the same way: `tmpfs` moved +0.6% to +5.4% on seven
scenarios and −8.5% on `parallel-rw` (whose repetition spread was 19.3% in the
second pass — the noisiest cell in either). Read the table as **±5% typical,
±17% worst (`voidport-tcp` on `rand-read-4k`) between passes days apart on this
VM**, and treat any single-figure claim in this document accordingly. Nothing
regressed.

**The single-client per-operation floor is unchanged, and was expected to
be.** `open-close-loop` p50 is 178 µs against 182 µs before, `rand-read-4k`
p50 is 74 µs against 75 µs; the 75–95 µs per wire operation from *Where the
overhead sits* stands untouched. No dispatch configuration could have moved
it: one client doing one thing at a time keeps exactly one loop busy, and the
cost it is waiting on is the round trip, not the queue in front of it.

### Raw records

Raw records kept out of tree: the one-client loop sweep (16 runs), the
many-clients probes (8 and 32 clients × 4 loop counts, and 16 clients over one
and over four mounts), and the re-run matrix (29 runs). The matrix driver
gained a `DISPATCH_THREADS` variable (it passes the flag through and tags the
label `-tN`); the many-clients probe takes a loop-count list, a client count
and a scenario, with `MOUNTS` spreading the clients over several mounts.

## 2026-08-14 — the optimisation pass

This section is the before/after of the optimisation pass the profiling
report (kept out of tree) proposed and the design's
"Acceptance criteria — optimisation pass" settled. It changes two things: how a
connection reads frames, and what a directory listing costs per entry.

Same machine and method as every pass above. Kernel 6.18.43, 32 vCPUs,
`cargo build --release`, `--dispatch-threads 1`, `max_background` 16, attr and
entry TTL 1 s — the shipped defaults. The **before** arm is the pass's base
revision, `ada2fcd`, taken with `git archive` into its own target directory and
built there; the **after** arm is that base plus this pass, which is `fc98288`.
Both arms therefore run on this machine, on this day, through the same driver.
(The first write-up of this section named `1e77a36`, an ancestor: what was
measured is what `git archive HEAD` produced while the pass was uncommitted,
and that is `ada2fcd`.)

### What landed

| | Change |
|---|---|
| Stream splitting | `tokio::io::split` — one `std::sync::Mutex` shared by both halves of a connection — replaced by the transport's own `into_split`, on both ends |
| Frame reading | a bounded (64 KiB) reusable read buffer per connection on both ends, so a header and the body that arrived with it cost one `read(2)` between them |
| Listing materialisation | the visibility filter stats each entry by name against the pinned parent (`AT_SYMLINK_NOFOLLOW`, one component) instead of opening a descriptor it immediately closes |
| Entry replies | a listed entry the session already has a node for is named from the identity that stat reported — no `openat2`, no second stat |
| Readdirplus batching | the client asks for as much of the entry stream as the negotiated frame bound allows, capped at 64 KiB, and holds the surplus per directory handle instead of giving it back and fetching it again |

The wire contract is unchanged: the batch is the `size` field the
`readdirplus` request has always carried, and every other message is
byte-identical.

### Frames per read syscall

The ceiling the profiling pass attributed was two `read(2)` calls per wire
frame on each end. Counted with `strace -c -e trace=read,recvfrom` over a
20 000-operation `open-close-loop` (≈60 000 request frames, one connection):

| Successful socket reads | before | after |
|---|---|---|
| server, total | 125 252 | 50 075 |
| server, per wire frame | 2.09 | **0.83** |
| mount, total | 125 122 | 54 787 |
| mount, per wire frame | 2.09 | **0.91** |

Below one per frame, because a saturated connection sometimes has the next
frame already in the socket. The `EAGAIN` returns disappear with them
(server 42 779 → 61).

### The per-connection ceiling — criterion 2

The many-clients probe, 16 `voidport-bench` clients over **one** mount,
`open-close-loop --files 64 --ops 3000`, three measured repetitions per
client, aggregate of the per-client means. Six before/after pairs were run
**alternating**, because a single pair of runs on the rig says less than the
drift between them.

| Pair | before ops/s | after ops/s | ratio |
|---|---|---|---|
| 1 | 21 751 | 30 417 | 1.40 |
| 2 | 22 718 | 29 254 | 1.29 |
| 3 | 23 110 | 28 653 | 1.24 |
| 4 | 20 771 | 26 378 | 1.27 |
| 5 | 25 086 | 29 544 | 1.18 |
| 6 | 24 241 | 27 316 | 1.13 |
| **mean** | **22 946** | **28 594** | **1.25** |

Every after run beats every before run; the run-to-run spread is 19% on the
before arm and 14% on the after arm, which is wider than this document's usual
±5–17% and is the reason for pairing.

**Measured +25%, against the predicted +60% (buffering alone) and +110%
(buffering with the lock-free split).** The prediction was arithmetic on the
profiled reader cycle: 13.63 µs per frame less the 5.21 µs of the second read
and the ~2.5 µs of split-mutex contention. Both costs are gone — the syscall
count above is direct evidence — so the honest reading is that the cycle does
not shrink by the whole of what was removed from it: the remaining terms
(wakeup, the delivery step, the reply channel and writer task the report
measured at 0.5 occupancy) take up part of the room. The ceiling moved, by a
quarter, and it is no longer two reads per frame; what binds it now has not
been re-attributed and would need another instrumented pass.

The four-mount arm — the same 16 clients spread over four connections — is
unchanged within noise (40 957 → 39 617 ops/s, one run each), as expected: it
was never bound by one connection's read loop. One mount now reaches 72% of
what four reach, against 56% before.

### The affected scenarios — criterion 9

`voidport-unix`, one client, five measured repetitions, cache drops before
every repetition — the matrix's own discipline and parameters. The figure is
the mean of the per-run means; three runs per cell for the two headline
scenarios, one for the rest.

| Scenario | Metric | before | after | change |
|---|---|---|---|---|
| readdir-loop (200 × 1000-entry listings) | listings/s | 60.2 | **204.7** | **+240%** |
| readdir-loop | µs per entry | 16.8 | **4.9** | −71% |
| open-close-loop (20 000 open+close) | ops/s | 4 826 | 4 948 | +2.5% |
| stat-loop (20 000 stats) | ops/s | 215 267 | 224 795 | +4.4% |
| small-files (1000 × 4 KiB) | files/s | 1 347 | 1 386 | +2.9% |
| rand-read-4k (20 000 × 4 KiB) | ops/s | 13 088 | 13 985 | +6.9% |
| seq-read (256 MiB) | MiB/s | 1164.6 | 1130.3 | −2.9% |
| seq-write (256 MiB) | MiB/s | 337.8 | 371.0 | +9.8% |
| parallel-rw (8 threads) | ops/s | 10 137 | 9 468 | −6.6% |
| one-writer-many-readers | visibility µs | 361 | 365 | +1% |

`voidport-tcp` moves the same way on the row that matters: 62.7 → 193.1
listings/s (+208%).

Everything except `readdir-loop` is inside this document's stated run-to-run
drift and should be read as "unchanged", including the two negative rows —
`parallel-rw`'s own repetition spread has been as high as 19% between passes.
**The single-client per-operation floor is unchanged and was expected to be**:
one client doing one thing at a time never had two frames in flight, so
neither the lock nor the second read syscall was ever on its critical path.
The pass moves a *ceiling* and a *per-entry* cost, and those are the two rows
that moved.

`readdir-loop` at 204.7 listings/s is **3.4× the incumbent-beating figure this
document opened with** (9p: 47.3) and takes the weakest row in the matrix off
that list. Against the profiling report's per-entry attribution, the 11.9 µs
per entry that went away is the readdirplus pin (2.15) and its stat (0.71),
the opendir pin (2.08), the node-table lock traffic and the per-entry
allocations of `admit` (up to 3.0 between them), and 30 of the 32 round trips
(3.1) — i.e. the predicted terms, and slightly more of them than the ~40%
band the report predicted for the server-side items alone.

### A decided shape the measurement refused

The profiling report proposed carrying the attributes of the materialisation
stat into the entry reply, and the disposition accepted it with the argument
that they are "as-of materialisation, inside the same 1 s attr-TTL coherence
envelope". **Built that way, it is a data-visibility defect, and it was
measured, not argued.** A guest caches what an entry reply says about a file
for the entry timeout and then serves reads by that size: a listing taken
while another writer is extending a file made a following read of that file
return the old length — empty, or half the file. Eight concurrent writers
through one mount reproduced it within four rounds, every time.

What landed instead keeps the goal and drops the staleness: the
materialisation stat is kept only as the entry's **identity**, which is what
names its node, and the reply's attributes are read when the reply is built.
The `openat2` — the expensive primitive, 2.1 µs against the stat's 0.7 — is
what a repeated listing now avoids entirely, and the measured result is above
the band the original shape was predicted to reach. The end-to-end suite
carries the regression as `a_listing_describes_its_entries_as_of_the_reply`,
which fails on the decided shape and passes on this one.

### The descriptor-per-node lifecycle — criterion 6

(Refined 2026-08-17: this section measured the PRE-budget lifecycle,
where a node held its pin for life — one descriptor per node. The
descriptor budget has since landed: descriptors are evictable cache
slots reopened from full-path recipes, and the current-stack
re-measure above observed 0.33 per node at an 801k-name peak. The
numbers below stand as the record of what was measured before that
decision.)

The question the field-use disposition left open: whether a node should keep
its `O_PATH` pin for its lifetime, or whether descriptors should be evicted
and reopened on demand. Measured before deciding, on a synthetic source tree
of 320 000 files in 400 directories under a two-level package hierarchy —
the scale the AOSP walk that raised the question ran at — walked whole with
`find` through one mount at the defaults of the time (sized caps, since made
unbounded — the walk was well inside them, so the numbers stand unchanged for
a server that configures none):

| | Measured |
|---|---|
| `RLIMIT_NOFILE` after the startup raise | 1 065 984 (soft and hard) |
| server descriptors, idle | 18 |
| server descriptors, after the walk | 320 438 |
| session nodes, after the walk | 320 421 |
| **descriptors per node** | **1.00** |
| server RSS after the walk | 254 MiB (≈790 bytes per node) |
| walk through the mount | 320 000 files in 3.8 s, no error |
| the same walk on the host tree | 320 000 files in 0.1 s |

**Recommendation: keep the pin. No lifecycle change is proposed.** Three
measured reasons, in the order they bind:

1. **The scale is carried.** The walk that produced `ENFILE` in the field
   completes with 30% of the raised descriptor limit spent and a quarter of a
   gigabyte of server memory. The bar — it works on the host
   filesystem, so it must work through the mount — is met, which is the
   condition the disposition set for not revising the refusal. (Met twice
   over since: with the caps now unbounded there is no refusal left on that
   path at all, only the descriptor table.)
2. **Dropping the pin does not save the open, it adds one.** The pin is taken
   once per node and reused by every later operation on it; on-demand
   reopening pays a fresh `openat2` per operation instead — and a multi-
   component one, walked from the graft, not one component from a
   pinned parent. That is *more* host work per operation, not less, and it
   lands on the getattr path this pass has just made cheaper. (An earlier
   draft of this section put a figure on how much more — "2.42 µs against
   2.34" for the two `openat2` shapes. **It is struck: no harness or raw
   record was kept for it**, and this document does not carry numbers it
   cannot reproduce. The count argument above needs none: one open per node
   against one open per operation is arithmetic.)
3. **The invariants do not survive it.** The pin is what makes a node an
   inode, not a name: the design requires a reopen after a rename-over
   to serve the pinned inode, and requires every descent to run from a
   descriptor obtained under containment. A node that re-resolves its path on
   demand serves whatever now answers to that name, and re-resolution through
   a re-targeted or removed graft has nothing to resolve from. Criterion 6
   admits a change "only if the containment invariants provably hold through
   it"; they provably do not.

One limit is recorded here instead of fixed, because it is a
configuration question and not a lifecycle one — and the caps decision of
2026-08-14 has since changed which number it is about. Every per-session cap
now defaults to unbounded, so nothing sizes `RLIMIT_NOFILE` down: startup
raises it to the OS maximum (`/proc/sys/fs/nr_open`, 1 048 576 on the measured
machine, which is where the 1 065 984 above came from) whatever the caps say,
and the descriptor table is the only ceiling a default server has.

That ceiling is process-wide and shared by every session. The measured walk
holds 320 438 descriptors, so **three** source-tree-scale guests fit inside a
1 048 576 limit (~961 k) and a **fourth** does not. Past it, the pin that would
exceed the limit fails with the host's `EMFILE` — the machine's own answer,
which under the new posture is the honest one, not a cap's `ENFILE`
standing in for it. Those thresholds are arithmetic on the one walk that was
measured, not four measured walks.

The measured unit cost — 1 descriptor and ~790 bytes of server memory per held
node — is what an operator sizes with, in either direction: raise the hard
limit (`LimitNOFILE=`, `ulimit -n`) for more concurrent large guests, or
configure `max_nodes`/`max_handles` as opt-in throttles where guests are not
trusted to be reasonable. Where both are configured the server checks
`max_nodes + max_handles + 1024` against the limit it reached and warns when
the caps promise more than the process can back. The sizing note in
`docs/state.example.toml` carries the same arithmetic for operators.

### Raw records

Raw records kept out of tree: the paired single-client scenario runs, the full
matrix (one run per arm), the six alternating ceiling pairs, the `strace -c`
syscall counts, and the 320 000-entry descriptor measurement. The before arm is
built from `git archive` of the base revision into a separate target directory,
and the drivers take it through `CARGO_TARGET_DIR`.

## 2026-08-14 — the optimisation boundary patch

The boundary rulings on the pass above changed three things that the pass had
measured, so the three measurements are taken again. Same machine and method,
same day. The **before** arm here is the pass as it landed (`fc98288`), built
with `git archive` into its own target directory; the **after** arm is that
plus the boundary patch. Every pair below was run **alternating**, because the
run-to-run drift on the rig is wider than most of what is being compared.

| | Change | What it could cost |
|---|---|---|
| Held surplus is TTL-bounded | the mount serves an entry from held surplus only within the attr TTL of the fetch that brought it; older surplus is given back with its compensating `forget`s and refetched | a refetch per slow walker, and nothing at all for a walk that outpaces the timeout |
| Host syscalls left the node-table guard | readdirplus takes and drops the session's node table per entry — a hash lookup or an insertion — instead of holding it across a batch of pins and stats | more lock acquisitions, each of them short |
| Both hand-rolled frame readers are gone | the buffering is `tokio::io::BufReader` (64 KiB, unchanged) around each end's read half, with the pre-pass `read_frame` shape on top | the one-read-per-frame property, if `BufReader` had not carried it |

### One read per frame, re-proven — criterion 1

The property the deleted readers existed for, counted the way the pass counted
it: `strace -c -e trace=read,recvfrom` over a 20 000-operation
`open-close-loop` on one connection (≈60 000 wire frames), successful socket
reads only.

| Successful socket reads | pre-pass | the pass (`fc98288`) | with `BufReader` |
|---|---|---|---|
| server, total | 125 252 | 49 787 | 49 995 |
| server, per wire frame | 2.09 | **0.83** | **0.83** |
| mount, total | 125 122 | 55 113 | 55 500 |
| mount, per wire frame | 2.09 | **0.92** | **0.93** |

The pre-pass column is the pass's own record; the other two were measured
today, one after the other. **`BufReader` holds the property exactly** — the
0.01 difference on the mount side is 400 syscalls in 55 000. Two ~300-line
readers and their test suites are gone for it.

### The per-connection ceiling is unmoved

The framing change is the one that could have moved it, so it was checked:
The many-clients probe, 16 clients over **one** mount,
`open-close-loop --files 64 --ops 3000`, three measured repetitions per client,
aggregate of the per-client means, three alternating pairs.

| Pair | the pass ops/s | with the patch ops/s | ratio |
|---|---|---|---|
| 1 | 52 009 | 50 761 | 0.98 |
| 2 | 51 595 | 56 237 | 1.09 |
| 3 | 54 085 | 51 372 | 0.95 |
| **mean** | **52 563** | **52 790** | **1.00** |

Unchanged, inside a ±9% pair spread. (The absolute level is well above the
28 594 ops/s the pass recorded for the same probe; that is the rig on a
different day, and is exactly why only same-day alternating pairs are compared
here.)

### readdir-loop keeps the +240% — criteria 5 and 9

Both the TTL bound and the per-entry locking land on this scenario:
200 listings of a 1000-entry directory through `voidport-unix`, one client, five
measured repetitions with a cache drop before each, three alternating pairs.

| Pair | the pass listings/s | with the patch listings/s |
|---|---|---|
| 1 | 216.9 | 225.0 |
| 2 | 208.1 | 215.5 |
| 3 | 206.8 | 211.5 |
| **mean** | **210.6** | **217.3** |

**The patch costs nothing measurable, and the pass's headline survives it**:
217.3 listings/s against the pre-pass baseline of 60.2 is **+261%**, and 4.6 µs
per entry against 16.8. The after arm was ahead in all three pairs, which is
drift, not a claim of improvement — the honest reading is "unchanged".

Two things the numbers say about the rulings themselves:

* **The TTL bound is free for a fast consumer.** A listing here takes 4.6 ms,
  three orders of magnitude inside the 1 s attr TTL, so no surplus in this
  scenario ever expires. What the bound costs is paid only by a walker slower
  than the timeout, which is the walker that was being served stale attributes
  before.
* **The batching win was never the lock.** Taking the node table per entry
  instead of per batch left the scenario where it was, which places the pass's
  +240% where its attribution already put it: the `openat2` a repeated listing
  no longer pays, and the 30 of 32 round trips the batch bound removed.

That the guard is now short is asserted, not left to a benchmark:
the server data-plane suite carries
`a_lookup_is_not_queued_behind_a_large_listing_batch`, which puts a lookup
behind a 5000-entry batch on the same session and requires it to be answered in
under a quarter of the batch's own time. Measured, the lookup takes ~0.3 ms of
the batch's ~160 ms with the guard short, and ~88 ms of ~90 ms with the batch
holding the table — the shape this patch removed.

### Raw records

Raw records kept out of tree: the three alternating readdir-loop pairs, the
three alternating ceiling pairs, the `strace -c` syscall counts with the runs
they were taken over, and the syscall-count harness as the pass left it.

## 2026-08-15 — `--direct-io`: what the guest page cache costs, and what dropping it costs

The client gained `--direct-io`: with it, every `open` and `create` reply
carries `FOPEN_DIRECT_IO`, and the mount negotiates
`FUSE_DIRECT_IO_ALLOW_MMAP` in the FUSE handshake so that shared mappings keep
working. File data then never enters the guest page cache — except for the
pages of ranges a process has actually mapped — while attribute and entry
caching, which is where voidport wins 7–11× over 9p, is untouched.

Two questions, both measured here: how much guest memory the option gives back,
and what it costs in re-read throughput.

### Environment

Same rig as every section above: KVM guest, 32 vCPUs on a 16-core consumer
x86-64 host, ~120 GiB RAM, Linux 6.18.43, guest root on tmpfs. Release build
(`cargo build --release`), `voidportd` and `voidport` 0.1.0, unix-socket
transport, product-default timeouts (attr and entry TTL 1 s). Runs serialized
so no other heavy workload overlapped. Harnesses kept out of tree.

**Read the throughput numbers with the machine in mind.** This host's *wire* is
a unix socket to a server whose backing store is tmpfs — RAM on both ends of it
— so "going to the server" here is far cheaper than it is for the deployment
the option exists for, where the wire is vsock or TCP to a real host
filesystem. The memory numbers transfer; the throughput numbers are this
machine's floor on the cost, not a general one.

### One mount, 2048 MiB read twice

32 files × 64 MiB, read end to end with `dd bs=1M`, then read again. `Cached:`
from `/proc/meminfo` before and after the first read; caches dropped before
each arm. Three repetitions, all three shown because they barely move.

| Arm | `Cached:` growth over the first read | First read | Re-read |
|---|---|---|---|
| default (page cache) | 2 101 096 / 2 100 992 / 2 101 308 kB (~2052 MiB) | 1.461 / 1.411 / 1.429 s | 1.660 / 1.656 / 1.654 s |
| `--direct-io` | 3 136 / 3 108 / 3 184 kB (~3 MiB) | 1.272 / 1.254 / 1.262 s | 1.209 / 1.292 / 1.255 s |

Reading 2048 MiB through a default mount grows the guest page cache by
2052 MiB: the whole file set, duplicated into the guest on top of the copy the
host already holds. Through a `--direct-io` mount it grows by ~3 MiB — the
mount's own metadata and nothing else. **The duplication is removed entirely,
which is what the option is for.**

The re-read is where the cost was expected, and on this machine it does not
appear: 1234–1238 MiB/s cached against 1585–1694 MiB/s direct. Two things
explain that and neither generalises. The server's data is in tmpfs and the
transport is a unix socket, so a "wire" read is a RAM-to-RAM copy over a local
socket; and the cached arm still pays a copy out of the guest page cache into
`dd`'s buffer, plus the attribute revalidation `FUSE_AUTO_INVAL_DATA` asks for
once per file per TTL. On a guest whose host is across vsock and whose backing
store is a real disk, the cached re-read is the one that would win, and by a
lot. What this measurement does establish is the shape of the trade: the
re-read cost is bounded by wire speed, and wire speed here is 1.6 GiB/s.

### Four mounts, one host tree — the case the option exists for

Four simultaneous mounts of the same namespace, each reading all 1024 MiB of
it. Four FUSE mounts are four superblocks with four sets of inodes, which is
what four guests of one host tree are. Two repetitions.

| Arm | `Cached:` growth across all four mounts |
|---|---|
| default (page cache) | 4 197 836 kB / 4 197 848 kB (4099 MiB) |
| `--direct-io` | 636 kB / 644 kB (0 MiB) |

One host copy of 1024 MiB, read by four guests, costs 4099 MiB of *additional*
guest memory by default and nothing at all under the option. That is the
N-guests-share-one-host-copy claim, measured: the growth is linear in the
number of guests without the option and flat with it.

### What was not measured

* Nothing under memory pressure. Every run here had ample free memory, so no
  arm
  was ever reclaiming; a guest tight on memory is the case the option helps
  most and it is not measured.
* No mapped-file workload's memory. `mmap` still caches the pages of mapped
  ranges under the option by design, so a workload that maps most of what it
  reads gives back less. The direct-io suite proves such a workload still
  *works*; how much memory it keeps is unmeasured.
* No unsupported-kernel arm: this kernel offers `FUSE_DIRECT_IO_ALLOW_MMAP`, so
  the fallback to ordinary caching is unit-tested, not measured.

## 2026-08-15 — the direct-io memory claim, consolidated

The section above was re-measured after a field report of a `--direct-io`
mount whose guest `Cached:` still grew 1:1 with bytes read. The claim stands,
and the field observation is explained; all three facts belong together,
because reading any one of them alone leads to the wrong conclusion. Full
method and logs kept out of tree.

* **On an isolated rig the option does what this document says.** 3.00 GiB
  read through one mount, backing on a *non-caching* filesystem so that only
  the guest's own caching is visible: `Cached:` grows **+3 146 736 kB
  (1.000× bytes read)** through a default mount and **+1 008 kB (0.0003×)**
  through `--direct-io`. First-read throughput is equal (~330 MB/s both arms).
  The bypass is proven functionally as well as by counter: with 1 h TTLs and
  one open descriptor, a host-side rewrite between two reads at offset 0 is
  invisible to the cached arm and visible to the direct arm.
* **The field observation reproduces exactly — as a property of the
  topology, not of the option.** Put the server in the *same kernel* as the
  observer with its backing on a caching filesystem, and the `--direct-io`
  arm grows that kernel's `Cached:` by **1.000× bytes read** while the
  default arm grows it by **2.000×**. Nothing is wrong with the mount: the
  server's own `pread`s of the backing populate the same page cache being
  watched. That growth is the host's ordinary, reclaimable file cache, and in
  a split host/guest deployment it is invisible to guest `meminfo`
  altogether. **A guest-side `Cached:` measurement of a co-located server
  measures both sides at once, and cannot be read as the mount's caching.**
* **`O_DIRECT` in the reader is a third variable, and must not be conflated
  with `--direct-io`.** `dd iflag=direct` bypasses the guest page cache on a
  voidport mount in *either* caching mode (1 GiB read, `Cached:` +3.2 MB).
  An A/B whose reader opens `O_DIRECT` therefore shows "no caching" in both
  arms and proves nothing about the option.

One product change came out of it, and it is in the log, not in the
data path: **every mount now states its resolved data-caching mode**
(the FUSE adapter's `DataCaching::resolve`) — at info for the
two `--direct-io` outcomes, at debug for a plain mount. Silence used to mean
either "no `--direct-io`" or "a build older than the confirmation line", which
is precisely the ambiguity the field case turned on.

## 2026-08-15 — returning a drained node table to the host

The RAM attribution pass measured the sharper half of the entry-memory
problem: an 800 809-name walk grew the server to ~1.4 GiB, a guest
`drop_caches` drained the session to one node within five seconds — every
descriptor closed, every entry freed — and **the host got none of the memory
back**, then or after the unmount. Nothing leaked; glibc keeps freed memory in
its arenas. This section is what landed against that, and what it measures.

Same rig as every section above. Server-side numbers are `VmRSS` from
`/proc/<pid>/status`; the allocator probe and the mounted-walk harness are kept
out of tree, and the server reclaim suite is the suite-scale
regression.

### Choosing the mechanism

A standalone probe allocating a node-table-shaped 467 MiB (400 000 entries of
several small strings each), freeing all of it, and calling `malloc_trim(0)`,
across 16 allocating threads — the server's shape, since requests are served
on a thread pool:

| `MALLOC_ARENA_MAX` | returned by free + trim | fill time |
|---|---|---|
| default (8 × cores = 256) | 98 MiB — **21%** | 0.19 s |
| 8 | 294–355 MiB (63–76%) | 0.19 s |
| 4 | 378–429 MiB (81–92%) | 0.31–0.41 s |
| **2** | **462–467 MiB (99%)** | 0.85–0.99 s |
| 1 | 467 MiB (100%) | 2.13 s |

**Neither half works alone.** Without a trim the memory stays whatever the
arena count is; with a trim but default arenas, four fifths of it stays
anyway, because entries scatter across dozens of arenas and each is left
holding fragments that pin whole heaps. Two arenas returns what one does at a
third of one's allocation cost. The fill column is a pure `malloc` loop and is
therefore the *worst* case for the bound: the server's per-entry work is
dominated by `openat2` and `statx`, and the end-to-end walk benchmark below
moves by less than the run-to-run drift.

An allocator swap (jemalloc/mimalloc) was **rejected**: it is a dependency and
a build change, and the two glibc mechanisms above measurably reach the goal.

### What landed

* The reclaim module — the arena bound, set once at startup
  beside the descriptor-limit raise, and a reclaimer thread that trims when a
  drain has freed enough to justify it: the live entry count has halved since
  the last trim and fallen by at least 4096 entries. Never on the request
  path, never per FORGET.
* **Two trims per drain**, because a drain becomes returnable in two stages.
  The threads that freed the entries hold per-thread allocator caches, and a
  page under one cached chunk cannot be handed back however free the rest of
  it is; those caches return to the arena when the thread retires, which the
  request pool does ten seconds after it goes idle. Measured on the
  60 000-entry drain: the first trim left 43 MiB of a 70 MiB growth resident,
  and the second — 15 s later — took it to 6 MiB.
* The node table gives back its *own*
  storage once it is a quarter full. Removing entries frees the entries, never
  the table, and a table sized for a source-tree walk is a large single
  allocation: 13.8 MiB behind 60 000 entries, held until the session
  disconnected. This one needs no trim at all — it is one `free` big enough to
  go straight back to the kernel.

### Suite scale — 60 000 entries, in-process server

The server reclaim suite walks a 60 000-entry directory over the
wire, forgets every node as a guest under memory pressure does, and asserts
that at least half the growth comes back. The same suite run against the
pre-change tree is the control:

| | growth | returned | settled |
|---|---|---|---|
| before (`522c3c7`) | 70 724 KiB | **0 KiB** after 90 s | 87 312 KiB |
| after | 70 692 KiB | **64 560 KiB (91%)** | 16 296 KiB |

### Full scale — 200 206 entries, real mount, `drop_caches`

The RAM report's M2 method, re-run with the patched release build: a
200 000-file tree walked whole through a mount, drained by
`echo 2 > /proc/sys/vm/drop_caches` in the guest.

| point | before (report M2, same shape) | after |
|---|---|---|
| server start | 6 720 kB | 6 696 kB |
| post-walk | 296 944 kB | 297 024 kB |
| drained, settled | 270 228 kB — **9%** returned | 77 964 kB — **76%** returned |
| post-umount, settled | 232 844 kB — 22% | 73 740 kB — **77%** |

A second run of the same script settled at 58 968 kB after the drain (82%), so
read the return as 76–82% run to run. The peak is unchanged, which is the
point: this pass returns memory, it does not shrink an entry (that is the
decided entry-diet follow-up). Descriptors behave as the budget already
promised — 200 217 open during the walk, 16 after the drain.

**The residue is not a fixed high-water mark, and that needs stating
plainly.** Walking and draining the same tree a second time in that server
settled at 108 112 kB against the first cycle's 58 968 kB: each cycle returns
~80% and leaves fragmentation the trim cannot reach. Two contributors are identified —
allocator fragmentation around the live data, and one structure that is
per-entry and *permanent by design*: the ino allocator's `(host_dev, host_ino)`
table, which never forgets an entry it has numbered (~13 MiB at this scale) and
is what keeps a guest-visible inode stable across sessions. Against the
measured baseline — where the whole 290 MiB stayed for the life of the process,
every cycle — this is the difference between a server that grows without bound
and one that gives back four fifths of every drain.

### The walk benchmark, before and after

The arena bound is the change that could cost throughput, so the walk scenario
was run alternating between arms, five repetitions each, `tmpfs` alongside as
the drift control.

| arm | `voidport-unix` walk (entries/s) | `tmpfs` control (entries/s) |
|---|---|---|
| before, round 1 | 16 752 | 404 696 |
| after, round 1 | 16 627 | 399 945 |
| before, round 2 | 16 433 | 412 529 |
| after, round 2 | 16 282 | 404 400 |

Means: 16 593 before, 16 455 after — **−0.8%**, against a control that moved
−1.6% the same way. Inside the drift this document has measured on the rig
(±5% typical), and far inside the ±10% band the change was held to.

### Raw records

Raw records kept out of tree: the arena/trim probe and its sweeps, the mounted
200 206-entry walk with two drain cycles, the alternating walk benchmark, and
the pre-change RAM measurement this pass answers.

## 2026-08-15 — `--direct-io` wall-clock, measured in the field

Measured on a separate deployment (vsock transport, ext4-on-virtio-blk
guest): the wall-clock counterpart of the memory numbers above, against
that guest's native filesystem. Reproduced numbers only — the environment
differs from this document's rig and that is its value.

| workload, warm | native | voidport `--direct-io` | ratio |
|---|---|---|---|
| walk+stat, 2000 files | 12 ms | ~75 ms | ~6x |
| grep -r, 2000 files | 17 ms | ~880 ms | ~52x |
| 200 MiB sequential re-read | 5 ms | ~250 ms | ~50x |
| grep -r vs COLD native disk | 233 ms | ~890 ms | ~4x |

The readings that matter:

- **Metadata is ~6x native** — attr/entry caching is untouched by
  the data-path mode, and that number is what makes a tree feel
  responsive either way.
- **The ~50x data ratios compare a wire round trip against a
  page-cache hit**; against a filesystem genuinely fetching bytes
  the gap is ~4x.
- **The direct-io cost is entirely workload-shaped.** Many small
  files (grep over a source tree): free — 880 ms direct vs 973 ms
  cached, the round trips dominate and metadata caching serves both
  modes. Bulk re-reads of the same data: ~50x — 250 ms direct vs
  3 ms cached per 200 MiB, where the cached mount is native-parity
  because the second read never leaves the guest.

The mode choice this prices: `--direct-io` for large working sets
(a big build out-reads what the guest could ever cache, and the
memory stays flat per the sections above); the default cached mode
for small projects whose hot files are re-read constantly, where
the cache repays its bounded cost with native-speed re-reads.


## 2026-08-17 — what the attribution bought: four landings

The attribution section below ranked the safe reductions; all four
landed the same day, each proven by paired interleaved A/B on the
rig (pre arm built from the unchanged source, same session):

- **Serve replies from the blocking closure** — the per-request
  outer task and its join are gone (~5 us of server CPU per wire
  round trip): create+close 336.6 to 308.8 us, write 4 KiB 150.8 to
  143.1, getattr 59.6 to 57.4. The full-queue case falls back to a
  task so a stalled peer can never park the shared blocking pool.
- **Run-ahead bound for uncapped connections** (64, measured — 1024
  measured worse on the 16-client ceiling): the forget-flood drain
  transient fell from +36.8% RSS over plateau to +1.3-2.8%, peak
  threads from the 512-pool ceiling to 171-388, post-drain RSS from
  124 to 49 MiB, walk and 16-client aggregate at parity.
- **One allocation per reply, no per-mutation dup, repeat-lookup
  stat reuse** (inode-keyed nodes only): lookup -5.9%, unlink -4.6%,
  create -4.0%, getattr -3.4%, readdirplus -4.4% per entry.
- **Signalled teardown settles what the kernel is owed** (a
  correctness landing found by the same measurements): the teardown
  race reproduced five of five with a frozen server and five in
  fifty-four full-suite runs, and zero of 288 after.

Raw records for every arm kept out of tree.

## 2026-08-17 — the round trip dissected, and what each guest op pays

A full attribution pass on the current stack (release builds, unix
socket, tmpfs backing, single client; one vsock confirmation arm).
This updates the earlier ~40 us/op attribution: the wire round trip
is 50-56 us on unix, 83.9 us on vsock, and the dominant component is
scheduling, not I/O or serialization.

One getattr round trip, 50 us wall, 62 us CPU across both processes:
scheduling/wakeup/futex/runtime 64.3%, syscall entry/exit 7%,
socket 6%, allocation 4%, operation code 4%, framing 3%, the host
filesystem syscall itself 2%. About ten voluntary context switches
per round trip, five on each side; zero involuntary.

What each guest operation costs in wire round trips (measured by
opcode census on the live socket): create+close 5 (lookup, getattr,
create, flush, release); unlink 3 plus a fire-and-forget forget;
open+close 3; every write 2 — the guest kernel precedes each write
with a security.capability getxattr probe FUSE cannot suppress
without the handle-killpriv negotiation, so the fixed cost of a
guest write is ~116 us of which the two round trips are 101-112;
readdirplus on 1000 entries 6. Bulk-loop taxes are guest-cache
effects: each unlink dirties the parent's attributes, so the next
iteration re-fetches them (a permanent one-round-trip tax on serial
unlink loops), and rm -rf avoids the lookup round trip because
readdirplus primed the entries.

The FORGET-flood drain transient is attributed and bounded: with no
configured in-flight cap the read loop spawns one task per FORGET
frame as fast as they arrive and the blocking pool runs to its
512-thread ceiling — at 200k names the transient is +35% RSS over
plateau and 546 threads. An internal run-ahead bound of 64 measured
the transient down to +1.9% and peak threads to 245, at parity
throughput on both the single-walk and the 16-client ceiling (a
bound of 1024 measured 19% WORSE on the 16-client ceiling than no
bound — the value is load-bearing, measured, not chosen round).

Raw records and harness scripts kept out of tree.

## 2026-08-17 — the host-direct-io postures: what the bounce costs, and where the bound moved

The two uncached postures (`direct_io = "passthrough"` and
`"always"`) put `O_DIRECT` on the backing description, and direct
I/O refuses a buffer that is not aligned to what the backing file
demands. The server's own buffers never are — a read payload sits
behind a fixed response head, a write is a slice of the request
frame — so an uncached description serves through an aligned bounce
buffer, one allocation and one copy per request. This section is
what that costs and what changes underneath it.

### Environment

Same machine as the sections above. Backing store `/tmp` on ext4 on
`/dev/vdb`; kernel 6.18.43. `STATX_DIOALIGN` is answered on this
filesystem: memory alignment 512, offset alignment 512 — so the
`statx` path is what supplies the number here and the logical-block
fallback is not exercised.

In-process server, tcp data listener on loopback, one 256 MiB file
per namespace, sequential 128 KiB reads. The cached arm is measured
page-cache-hot, which is the posture's whole claim; the uncached arm
cannot be, by construction. Two runs, five repetitions each.

### The bound moves from the wire to the storage — criterion 3

| arm | GiB/s, five repetitions (run 1 / run 2) |
|---|---|
| `cached` (host page cache) | 1.63 1.66 1.72 1.75 1.63 / 1.67 1.46 2.01 1.87 1.75 |
| `always` (uncached) | 0.47 0.50 0.53 0.75 0.67 / 0.34 0.53 0.53 0.71 0.71 |

**The uncached posture reads at 0.34-0.75 GiB/s against the cached
default's 1.46-2.01 GiB/s — 2.4x to 3.5x slower, and no longer
bounded by the same thing.** The cached arm is bounded by the wire
and the copy, as every earlier section measured; the uncached arm is
bounded by `/dev/vdb` answering 128 KiB serial reads with no
readahead behind them, which is why its repetitions climb as the
device's own queue warms while the cached arm's stay flat. That is
the trade the posture exists to make, stated at its own numbers: an
operator who chooses `always` is choosing the storage as the bound.

### The bounce itself — the same syscall, once through an aligned buffer

Isolated from the storage: the same page-cache-hot description, read
straight into the server's buffer, then read through the aligned
bounce and copied out. Only the allocation and the copy differ.

| request | plain us/req | bounced us/req | added |
|---|---|---|---|
| read 4 KiB | 0.708-0.771 | 0.918-0.964 | +0.21-0.19 us (+25-30%) |
| read 64 KiB | 3.66-4.14 | 4.82-6.00 | +1.17-1.86 us (+32-45%) |
| read 128 KiB | 6.47-9.22 | 9.39-12.56 | +2.92-3.34 us (+36-45%) |
| write 4 KiB | 1.13-1.25 | 1.29-1.30 | +0.05-0.16 us (+4-15%) |
| write 64 KiB | 9.96-11.57 | 10.96-11.36 | -0.61-+1.40 us (within noise) |
| write 128 KiB | 18.27-18.37 | 20.66-21.20 | +2.39-2.83 us (+13-15%) |

**The bounce costs about 3 us on a 128 KiB read and about 0.2 us on
a 4 KiB one** — a memory copy at roughly 40 GiB/s plus one
allocation, which is what those figures work out to. It is the
smaller of the two costs by a wide margin: 3 us of copy against the
~180 us a 128 KiB uncached read spends waiting for the device at the
0.7 GiB/s measured above. On the write side it is within noise below
64 KiB, because the syscall dominates.

Two bounds on these numbers, stated: the bounce arm here runs
against a *cached* description, so it measures the copy and the
allocation and nothing about `O_DIRECT` itself; and the allocation
is a fresh `Vec` per request, so an allocator under memory pressure
would pay more than this warm one did.

## 2026-08-17 — per-entry cost re-measured on the current stack

The entry-cost and reclaim numbers above predate the descriptor
budget, the full-path reopen recipes, and the memory-reclaim landing.
Re-measured end to end: 801 042 names (40 x 25 x 800 empty files plus
1 040 directories, the established tree shape), one fresh server per
run, six runs across three mount arms, real VmRSS from the server's
proc status at idle, post-walk plateau, drain, and settle.

| arm, two runs each | peak KiB/name | return % after drain | post-drain KiB/name |
|---|---|---|---|
| default (page-cached) | 1.0875 / 1.0872 | 77.3 / 73.2 | 0.25 / 0.29 |
| direct-io, readahead 256 MiB | 1.0874 / 1.0876 | 76.6 / 75.5 | 0.25 / 0.27 |
| direct-io, readahead 0 | 1.0874 / 1.0873 | 65.7 / 72.3 | 0.37 / 0.30 |

The verdicts against the sections above:

- **Peak per-entry cost improved ~39%**: 1.087 KiB/name against the
  1.79-1.83 the earlier pass measured (the ~1.4 GiB / 800 809-name
  figure derives to 1.83). Spread across all six runs is
  0.0004 KiB/name. The landed work is the difference; nothing else
  changed the entry path.
- **Descriptors: 0.33 per node at peak** (262 161 against 801 042
  nodes — the budget cap plus infrastructure), no longer the 1.00
  per node the pre-budget lifecycle measured. After a drain: 16.
- **Reclaim return holds**: default-mount runs at 77.3% and 73.2%
  against the documented 76-82% band — one inside, one three points
  below; residue is not a fixed high-water mark (197-299 MiB across
  identical runs), as the reclaim section already states.
- **Readahead adds nothing to server memory**: peak per-name
  identical to four decimals with the engine at 256 MiB and at 0.
  The pool is a ceiling, not an allocation, and it lives in the
  client. Bounded claim: an empty-file walk issues no reads, so
  this proves the engine's idle cost is zero, not the cost of a
  full pool.
- **The true RSS high-water mark is during the drain, not the
  walk**: the FORGET flood transiently adds ~18% over the post-walk
  plateau (1.27-1.32 KiB/name at that moment) in every run. Sizing
  memory off the plateau under-states the peak; recorded here so
  capacity math uses the right number.

Two mount-behavior findings from the same runs. The zero-inode df
output is per node kind, not a defect (refined 2026-08-17 after the
behavior was pinned by test): synthesized directories answer all-zero
statfs, host-backed nodes pass the backing filesystem's counts
through — a mount rooted on a synthesized directory therefore shows
zero inodes at the mountpoint while a host-backed subpath reports
real numbers. (Refined 2026-08-17 by controlled measurement: the
3.4x unlink-vs-create figure this note first carried compared a
serial rm -rf against a 16-worker parallel create and does not
survive a same-shape comparison — bulk unlink is in fact 1.35-1.5x
FASTER than bulk create through the mount, because create+close is
five wire round trips and unlink is three plus a fire-and-forget;
the attribution section below carries the full census. The mutation
path is round-trip-bound either way.) The client also logged a
spurious unmount warning after every successful unmount; fixed
since.

## 2026-08-16 — readahead in the field, post-integration

Measured on the same separate deployment as the direct-io section
above, after its migration to a build carrying the readahead engine.
Reproduced numbers; conditions stated as reported.

- **Sequential reads 1.66x**: 609/668 MB/s with `--readahead 0`
  against 1043/1096 MB/s at the 256 MiB default — same binary, same
  transport, same 512 MiB file, two mounts of the same namespace.
  Engine-off is effectively the pre-readahead behaviour, so this A/B
  is a controlled before/after; both halves ran minutes apart under
  identical load. Because readahead applies under `--direct-io`,
  that deployment's default for every share, every mount gets it
  without a flag.
- **Metadata unchanged**: cold `grep -r` 928-949 ms against
  867-924 ms before, warm walk+stat 65-73 ms against 70-71 ms.
  Within noise, and the halves are not load-matched (the host ran
  one other VM then, four plus a large build now). Readahead does
  not touch the per-file round-trip path, so unchanged is the
  expected result.
- **Distance from native**: the share reads at 1.04-1.25 GB/s
  against 5.3-5.5 GB/s from the local overlay — about 20%. The
  local reference is itself host-page-cache-backed through
  virtio-blk, so its figure is memory speed, not disk.
- **Writes through the share: 172 MB/s.** The weakest number in the
  report. The write path pipelines nothing — every write is a full
  round trip — making it the mirror image of what readahead fixed
  on reads. **OPEN**: whether and how to improve it is undecided;
  any buffering trades durability semantics and needs a decision
  before a contract.
- **Interactive latency under a never-pausing bulk reader**:
  49-60 ms idle to 72-85 ms loaded, ~1.5x, degrading gracefully
  without stalls. This is the harshest case the two-class reply
  writer faces.

Every absolute figure above was taken on a host running four VMs and
a large build concurrently — a busy-host floor. The 1.66x A/B is the
trustworthy comparison; both halves shared conditions.

## 2026-08-16 — readahead: what pipelining a direct mount buys, and where the wire stops it

The readahead increment's criterion 1 and criterion 3 measurements, and the
numbers the flag is documented with. A direct mount has no guest page cache
and therefore no kernel readahead in front of it, so before this every read
was a round trip the reader waited out; the engine puts a window of 128 KiB
reads on the wire ahead of a sequential reader and answers out of its own
pool.

The headline is that the gain is bounded by the transport, not by the engine:
on the rig the unix transport doubles and vsock reaches 93% of its own
measured ceiling without doubling, because that ceiling is only 1.95x the
unpipelined baseline. Both halves are measured below, not argued.

### Environment

Same rig as the sections above (32-vCPU KVM guest, kernel 6.18.43, guest root
on tmpfs), with the differences that matter stated, not implied:

| Item | Value |
|---|---|
| Date | 2026-08-16 |
| Baseline revision | `94981d0`, built in a read-only worktree — the pre-change commit |
| Measured revision | the readahead increment's working tree |
| Backing store | a directory on the guest root (tmpfs), host-cache-warm; **`--drop-caches` off** |
| Mount | `--direct-io`, defaults otherwise (256 MiB pool, 1 s TTLs, one dispatch loop) |
| Transports | unix socket and vsock loopback (cid 1), one mount each, same server |
| Scenarios | `seq-read --size-mib 512 --chunk-kib 128` and `rand-read-4k --size-mib 256 --ops 20000`, both `--warmup 1 --reps 5` |
| Method | **paired rounds**: baseline and measured runs alternate, and only numbers from the same round are compared |

The pairing is not ceremony. An unpaired first pass measured the two builds
minutes apart and produced a 43% *regression* on one random-read case that the
paired repeats put at parity — both builds had lost a third of their
throughput to whatever else the shared host was doing at the time. Only
same-round pairs are reported.

`--drop-caches` is deliberately off: the criterion is about round trips
between the guest and the server, and dropping the host's cache would measure
the host's disk instead. Both arms are warm.

**The backing store is on the guest root, not in the project tree.** An
earlier pass ran with the backing directory inside a checkout that is itself a
network mount, which measures a filesystem through a filesystem; those numbers
are reported separately at the end as the slow-backing-store case they
actually are, never as the rig's.

### seq-read, 128 KiB read discipline — criterion 1

Eight consecutive paired rounds, machine otherwise idle:

| Round | Transport | Baseline MiB/s (p50) | Readahead MiB/s (p50) | Ratio |
|---|---|---|---|---|
| 30 | unix | 1276.0 | 2572.7 | **2.02x** |
| 31 | unix | 1260.5 | 2582.3 | **2.05x** |
| 32 | unix | 1287.9 | 2604.5 | **2.02x** |
| 33 | unix | 1270.6 | 2604.0 | **2.05x** |
| 34 | unix | 1267.6 | 2592.3 | **2.05x** |
| 35 | unix | 1269.5 | 2542.7 | **2.00x** |
| 36 | unix | 1114.6 | 2527.9 | **2.27x** |
| 37 | unix | 1268.0 | 2577.0 | **2.03x** |
| 30 | vsock | 945.2 | 1711.7 | 1.81x |
| 31 | vsock | 988.1 | 1717.9 | 1.74x |
| 32 | vsock | 1000.3 | 1735.0 | 1.73x |
| 33 | vsock | 840.1 | 1716.1 | 2.04x |
| 34 | vsock | 952.3 | 1682.9 | 1.77x |
| 35 | vsock | 931.3 | 1696.3 | 1.82x |
| 36 | vsock | 994.3 | 1744.4 | 1.75x |
| 37 | vsock | 930.3 | 1723.0 | 1.85x |

Unix: median 2.04x, worst round 2.00x — the criterion's doubling, on every
one of eight rounds. Vsock: median 1.79x, range 1.73–2.04x — **short of the
doubling**, and the next section is why.

The spread is small enough to trust: the worst single repetition of any
measured unix run is 2346.5 MiB/s against a best baseline repetition of
1287.9, and the worst measured vsock repetition is 1619.6 against a best
baseline of 1000.3. Nothing here rests on a lucky pass.

### Why vsock does not double: the transport's ceiling, measured

The obvious suspicion about a transport that stops at 1.7 GB/s is that the
engine's own window is what stops it — 8 chunks of 128 KiB in flight per
handle, 16 per mount. It is not. Concurrent readers on the same mount saturate
the mount-wide cap at two handles and go on adding readers past it:

| Transport | 1 reader | 2 readers | 4 readers |
|---|---|---|---|
| unix | 2726.0 MiB/s | 2630.4 MiB/s | 3474.9 MiB/s |
| vsock | 1663.5 MiB/s | 1849.8 MiB/s | 1850.2 MiB/s |

(aggregate p50 across the readers, readahead build, same server and mounts.)

Unix keeps climbing to 3474.9 MiB/s with four readers. Vsock flattens at
1850 MiB/s and does not move between two readers and four: **that is the
transport, not the client.** One sequential reader already reaches 1663.5 of
those 1850 MiB/s — 90% of the wire's aggregate ceiling from a single handle.

The arithmetic that follows is the whole finding. The vsock baseline on this
rig is ~950 MiB/s and the vsock ceiling is ~1850 MiB/s, so the most any
client-side pipelining can win on this transport is **1.95x**, and the engine
delivers 1.79x of a possible 1.95x. A doubling is not available to be won. The
unix transport has 2.7x of headroom between its baseline (1276 MiB/s) and its
ceiling (3475 MiB/s), which is why the same build doubles there.

This is the same shape the contract's 2026-08-16 amendment already recognised
for the 1 MiB read discipline, arriving one discipline earlier because the
backing store is tmpfs: with the server side nearly free, the wire is the
whole cost and the baseline already sits at half the wire. Measured at
1 MiB reads on this rig for completeness: unix 1473.1 → 2579.5 (1.75x), vsock
960.7 → 1490.3 (1.55x).

### rand-read-4k — criterion 3

Random access must not pay for sequential access. It does not: the detector
opens no window without two consecutive reads at the expected offset, so the
engine issues nothing at all here.

| Round | Transport | Baseline ops/s (p50) | Readahead ops/s (p50) | Ratio |
|---|---|---|---|---|
| 40 | unix | 18731.7 | 18248.8 | 0.97x |
| 41 | unix | 18634.1 | 18758.4 | 1.01x |
| 42 | unix | 18715.0 | 18502.1 | 0.99x |
| 43 | unix | 18634.1 | 17147.7 | 0.92x |
| 44 | unix | 18552.8 | 18214.4 | 0.98x |
| 40 | vsock | 13423.2 | 13244.4 | 0.99x |
| 41 | vsock | 14165.6 | 13254.9 | 0.94x |
| 42 | vsock | 13949.4 | 13732.2 | 0.98x |
| 43 | vsock | 13368.6 | 13062.9 | 0.98x |
| 44 | vsock | 12786.3 | 13579.2 | 1.06x |

Median 0.98x on both legs; the worst pair of ten is 0.92x, an 8.0% shortfall
against a 15% tolerance and inside the scenario's own documented 11.2%
repetition spread. **Criterion 3 passes.**

### The slow-backing-store case

The same two builds, with the backing directory on a network-backed
filesystem instead of the guest root — a per-read cost far above tmpfs's,
which is the deployment `--direct-io` exists for and the case where the round
trip, not the wire, is what a reader waits on:

| Round | Transport | Baseline MiB/s (p50) | Readahead MiB/s (p50) | Ratio |
|---|---|---|---|---|
| A | unix | 251.3 | 861.7 | 3.43x |
| A | vsock | 241.5 | 804.1 | 3.33x |
| B | unix | 281.5 | 889.4 | 3.16x |
| B | vsock | 255.2 | 795.2 | 3.12x |
| C | unix | 189.1 | 819.6 | 4.33x |
| C | vsock | 218.5 | 512.7 | 2.35x |
| D | unix | 250.9 | 858.5 | 3.42x |
| D | vsock | 185.5 | 702.5 | 3.79x |

Every case doubles and most triple, on both transports, because the baseline
is nowhere near the wire's ceiling. Random access in the same environment is
unmoved (unix 0.96x and 0.99x, vsock 0.99x and 1.03x over two paired rounds).
These runs are not the rig's headline numbers — the environment is not the
one the rest of this document uses — but they are the honest answer to what
the engine buys where a read costs more than a memcpy.

### What the numbers say about the design

* The pinned 128 KiB chunk and the depth-8 per-handle in-flight cap are not
  what limits either transport. One reader reaches 90% of the vsock transport's
  aggregate ceiling and 78% of the unix transport's, and adding readers past
  the mount-wide cap of 16 in-flight moves vsock not at all.
* The remaining unix headroom is the reader's own serialization: one kernel
  read is answered, then the window is topped up. Closing it is a larger
  change (a negotiated stream) that the design defers on arithmetic, not on
  appetite.
* The pool never had to be large: these runs peak far below the 256 MiB
  ceiling, because a window is 4 MiB of coverage per handle and one reader was
  running. The ceiling exists for the many-reader case.

### Cross-version interoperability — criterion 7

No frame changed, and both directions were run to prove it, not
asserted: a pre-change server serving a post-change client, and a post-change
server serving a pre-change client, each mounting over a unix socket and
reading a 4 MiB file back byte-identically (`cmp`, no difference). The two
reply classes are scheduling inside one server's writer task; a peer cannot
observe them except as lower latency.

### Raw records

Raw records kept out of tree: the paired-round driver and its bench wrapper,
the concurrent-reader ceiling probe, the cross-version interop runs, and the
per-round JSON lines for the sequential and random legs.

## 2026-08-17 — the privileged-bits table costs the server no host work

The privileged-bits increment's sixth acceptance criterion asks for a
syscall census: presentation is an in-memory merge at the one attribute
funnel, so a server carrying the feature must issue exactly the host
syscalls a server without it issues, on every attribute path including
the pinless listing walk. The claim is about the enabled-and-empty
state — the table present, the lookup taken, no record to find — which
is what every namespace looks like until a guest sets a bit.

Two arms, identical in everything but the namespace's
`privileged_bits` switch, each `strace -f -c` from launch to `SIGTERM`.
The workloads are this document's own attribute scenarios, driven
through a real mount with both metadata timeouts at zero so that every
guest `stat`, listing and walk step reaches the server instead of the
guest's attribute cache: `stat-loop` (512 files), `readdir-loop` (1000
entries) and `walk` (depth 3, fanout 8, 8 files per directory — 5264
entries), one warmup and three measured repetitions each. Nothing in
any run sets a privileged bit, so the table stays empty throughout.
Kernel 6.18.43, dev-profile binaries, backing tree and mountpoint on
ext4.

### The counts

Every syscall that touches the host filesystem, both arms of the full
run:

| syscall | enabled (no records) | control (feature off) |
|---|---|---|
| statx | 1 460 118 | 1 460 117 |
| openat2 | 270 437 | 270 437 |
| close | 266 217 | 266 217 |
| fcntl | 266 208 | 266 208 |
| fchownat | 6 782 | 6 782 |
| fchmodat | 6 782 | 6 782 |
| getdents64 | 6 082 | 6 082 |
| open | 2 540 | 2 540 |
| fsync | 1 512 | 1 512 |
| mkdirat | 590 | 590 |
| pwrite64 | 512 | 512 |
| getxattr | 512 | 512 |
| newfstatat | 8 | 8 |
| unlink | 2 | 2 |

Thirteen of the fourteen match exactly. `statx` differs by one call in
1.46 million, which is one part in 1.5 million and cannot be a
per-operation cost — a per-operation cost would show up as a multiple
of the 1 460 117 attribute operations, not as a single call.

A second pair of runs settles that directly, at a twenty-fifth of the
scale (200 stats, 2 listings, a depth-1 walk): if the difference were
per-operation it would shrink with the workload, and if it were a
fixed startup or teardown cost it would stay at one. It is neither —
it is zero:

| syscall | enabled (no records) | control (feature off) |
|---|---|---|
| statx | 57 749 | 57 749 |
| openat2 | 13 221 | 13 221 |
| close | 11 689 | 11 689 |
| fcntl | 11 680 | 11 680 |
| fchownat | 1 598 | 1 598 |
| fchmodat | 1 598 | 1 598 |
| fsync | 1 512 | 1 512 |
| pwrite64 | 512 | 512 |
| getxattr | 512 | 512 |
| getdents64 | 130 | 130 |
| open | 44 | 44 |
| mkdirat | 14 | 14 |
| newfstatat | 8 | 8 |
| unlink | 2 | 2 |

Every filesystem syscall identical, the single `statx` included. The
one-call difference in the large run is run-to-run jitter, not the
feature.

**Criterion 6's census clause passes: zero added host syscalls on the
attribute paths, the listing walk included.** What the feature costs
is what the design said it costs — an atomic-load lookup in memory,
which issues no syscall and therefore appears nowhere in a census.

### What this does not measure

Wall-clock throughput. The two arms ran under `strace`, which
multiplies the cost of every syscall by a large constant, so the
scenario timings from these runs are a tracer's numbers and are not
comparable with anything else in this document. The census counts
calls, and calls are what the criterion is about; the latency of the
in-memory lookup is measured nowhere here because there is no syscall
to attribute it to.

The arms also differ in the non-filesystem syscalls a scheduler
decides — `futex`, `epoll_wait`, `mmap`, `clone3` — by fractions of a
percent in both directions. Those are thread timing, not host work,
and no claim is made about them.

### Raw records

Raw records kept out of tree: the two-arm census driver, the four
`strace -c` summaries, and the per-scenario JSON lines.
