# The shared-memory data plane

The authority document for v2's shared-memory data plane. Written
2026-08-18 from the consolidated research record: the virtio-fs DAX
window end to end (spec, guest implementation, the never-upstreamed
QEMU side, and the generic mechanism that superseded it), the
kernel's own statement of what may back guest memory, and this
project's binding contracts. This document decides the design and
implements nothing. Evidence classes are KERNEL.md's: **measured**,
**compile-proven**, **proven by source**, **decided**, **open**
(with the settling experiment named).

The decided v2 shape this document refines: a virtio device with a
DAX-style shared-memory window — host page cache mapped into the
guest, bulk data as zero-copy memory reads, control on a queue.
The refinement below keeps that shape and decides what the
precedent left broken.

## What the precedent proves

Proven by source, from the research record. Mapping a host file's
page cache into a guest is real and sanctioned: the kernel states
that any object may back a guest memory slot, ordinary files
included, with backing changes reflected immediately. The generic
mechanism exists upstream since QEMU 11.1: a vhost-user device
declares shared-memory regions, and the backend asks the VMM to map
any mmap-able descriptor into one at a given offset. A custom
device with a window plus queues is a precedented shape (virtio-fs,
virtio-gpu's host-visible blobs, virtio-pmem).

And the precedent's failure record, equally proven, is the design
input: the virtio-fs DAX window performs well only while the data
fits the window, and collapses under mapping churn; window-full is
a hard stall in the guest fault path; reclaim is synchronous
writeback plus a device round trip per fixed-size range; a host
truncate under a live mapping has no error channel to the guest,
which can spin in an infinite fault loop — the authors' own
conclusion was that the mechanism suits non-shared filesystems
only; each mapping under the generic mechanism costs a KVM memory
slot, with the practical ceiling in the low hundreds; any device
with a shared-memory region blocks VM migration today; and
virtio-fs never shipped its cross-guest coherence half. Three of
those — stall on full, spin on truncate, breakage under the
concurrent host modification this project declares an expected
workload — are impossible under this project's survival bar as
shipped upstream. The design below removes them structurally.

## The law of the window

**The window is an accelerator over the wire, never the truth.**
Every operation has a wire path; the window only ever short-cuts
reads whose bytes are already proven reachable that way. Losing
the window — absence, fullness, revocation, device reset, session
migration, an unsupported transport — degrades the affected reads
to the wire and nothing else. A full window therefore never
stalls a fault and never errors: the read that finds no mapping
takes the wire, exactly as every read did before the window
existed. This single rule is what makes the window compatible at
once with the survival bar, the fleet decision, VM migration, and
transports that have no shared memory at all.

Consequences, stated so they cannot be unstated: the wire remains
the semantic carrier of the protocol on every transport; the
window carries no protocol state; no correctness property anywhere
may depend on a mapping existing; and a member of the fleet with
no window serves identically, only slower. Session migration
needs no window handoff — mappings die with the device connection
and the next member rebuilds them on demand or not at all.

## The device

One virtio device, PCI and MMIO transports (the CCW transport has
no shared-memory regions — proven by spec — and simply serves
wire-only). The device carries two things and decides nothing:

1. **A frame transport.** One virtqueue pair carrying the
   existing wire protocol, unchanged — the session core already
   takes its transport as data, and this queue is handed to it
   exactly as vsock is today. Control of the data plane rides the
   wire as ordinary requests; the device has no control registers
   and puts nothing but mapped file bytes in the window, which is
   also what the virtio spec's normative clause demands of
   shared-memory regions.
2. **The window.** One shared-memory region, read-only toward the
   guest in this document's scope. Its size is fixed for the
   device's lifetime (the transport rule), negotiated at VM
   configuration; the guest learns it by enumeration.

The choice that the mapping lifecycle is wire requests — new
request opcodes in the unassigned range, additive by the recorded
ABI rules — and not a device-private protocol keeps one protocol
authority. A server that does not know the opcodes answers ENOSYS
and the client runs wire-only: discovery for free, skew-safe by
the same rule every addition uses.

## Mappings — leased, bounded, revocable

A mapping is a whole-file range of the server's backing file
placed into the window. Decided rules:

- **Mappings are established only under a host lease.** The
  server takes a read lease on the backing file before mapping
  it; a file whose lease cannot be taken (a concurrent host
  writer holds it open) is served over the wire. When the lease
  breaks — a host writer opens or truncates — the server revokes
  the guest's mapping first (an invalidation notification on the
  wire, an unmap toward the VMM), releases the lease, and the
  host writer proceeds. The truncate-spin hazard is thereby
  removed by construction: no live mapping can outlive the
  server's right to the bytes under it. **Open**: whether a hole
  punch breaks a read lease on the supported filesystems — the
  settling experiment is a probe on ext4 and btrfs, run before
  phase D2 closes, and a filesystem where it does not means hole
  punching joins truncation in the class of operations the server
  performs only through its own lease discipline.
- **Mappings are few, large, and bounded.** One mapping per file,
  whole-file, only for files past a size floor; the concurrent
  mapping count is bounded well inside the memory-slot budget
  (the practical ceiling is in the low hundreds — proven by the
  maintainers' own statements — and the bound leaves at least
  half of it free for the rest of the machine). Eviction is
  LRU by mapping, asynchronous, and never on a fault path: the
  read that misses takes the wire while eviction and mapping
  proceed in the background. The size floor and the bound are
  set by measurement in phase D3, not chosen here.
- **Mappings are per session and policy-checked.** The server
  maps only nodes the session's namespace policy admits reading;
  the window is private to one guest's device, so the unit of
  exposure equals the unit the wire already exposes. A policy or
  posture change revokes affected mappings at the next
  invalidation, exactly as it invalidates wire caches.
- **Writes do not ride the window here.** The window is read-only
  toward the guest in this document's scope; the write path is
  WRITESTREAM.md's, on the wire, on every transport. A writable
  window is recorded **open**, revisited only after the D3
  measurements and the write-streaming contract are both facts —
  the upstream record (extending writes deliberately routed away
  from the mapped path; size growth not atomic with the write) is
  the reason for the caution, and the wire write path keeps
  invalidation coherent meanwhile: a write through any handle
  drops the file's guest cache and its mapping revalidates
  through the same attribute discipline as everything else.

## Coherence

Unchanged, and that is the point. Attribute and entry lifetimes,
the auto-invalidation analog, writethrough writes, and the
drop-on-change rules all keep governing; a mapped read serves
bytes from the host page cache, which is the same cache the wire
read serves from, so the window narrows the staleness story
instead of widening it: for mapped ranges the guest reads the
truth directly, and revocation covers the transitions the
attribute discipline cannot see. Cross-member coherence stays a
backend obligation per the fleet decision; the window never
spans members.

## The kernel client's seams, satisfied

The provider boundary takes a second provider: the interim wire
provider stands; the window provider serves a read by consuming a
mapped range where one exists and delegating to the wire provider
otherwise. Nothing above the boundary changes — criterion 3 of
the kernel specification holds by construction. The transport
seam takes the device's virtqueue as one more frame transport.
The FUSE client gains nothing here (a userspace mount has no
guest physical address space); the window is the kernel client's
and the built-image case's.

## Deployment envelope, stated honestly

Proven by source: the generic mapping mechanism needs QEMU 11.1;
devices with shared-memory regions block migration today; the
vhost-user model shares all guest memory with the backend; and
confidential-VM compatibility is not determinable from the public
record. None of these bind correctness — wire-only is always
whole — but they bound where the accelerator may be turned on,
and the flake's guest images pin the QEMU they were proven
against. **Open**: whether the guest's mapped-range faults
resolve to huge-page mappings against a file-backed host window —
the settling experiment is a phase D3 measurement on the KVM
ring; nothing in this design depends on the answer.

## Phasing

1. **D1 — the device as transport.** The virtio device with its
   queue pair carries the wire; the kernel client mounts over it
   in the KVM ring alongside vsock. No window use. Proves the
   transport seam with a second real transport.
2. **D2 — the read-only window.** Region enumeration, the mapping
   opcodes, the lease discipline, revocation, the eviction rule;
   the KVM ring proves mapped reads byte-identical to wire reads
   under concurrent host modification, lease breaks, revocation
   storms, and window exhaustion — the survival arms.
3. **D3 — measurement.** Mapped versus wire reads across sizes
   and patterns; the size floor and mapping bound set from the
   numbers; the huge-page question answered; the writable-window
   question opened or closed on evidence.

## Acceptance criteria — for this specification

1. Every capability claim carries its evidence class, and the
   upstream failure record it designs against is cited, not
   assumed away.
2. The window is provably optional: every operation's wire path
   is stated or inherited, and no clause makes a mapping
   necessary for correctness.
3. The three upstream failure modes — stall on full, spin on
   truncate, churn collapse — each have a structural answer in
   the design, not a mitigation.
4. The design contradicts no decided contract: coherence,
   resilience, fleet topology, policy enforcement, the kernel
   client's provider and transport seams, and the ABI rules.
5. Every open question names its settling experiment and the
   phase that runs it.
