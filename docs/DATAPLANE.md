# The shared-memory data plane

The authority document for v2's shared-memory data plane. First
written 2026-08-18 from the consolidated research record; rewritten
the same day after its unbriefed review, which measured the first
draft's lease-and-map discipline false eleven ways and is the
evidence set behind the rejected alternative recorded below.
Evidence classes are KERNEL.md's: **proven by source**,
**decided**, **open** (with the settling experiment named) —
measured claims arrive with phase D3, and none is made here. This
document decides the design and implements nothing.

## The shape, and what it replaced

**Decided: the window is a server-owned arena, not a view of
backing files.** A sealed memory object created by the server
(shrink-sealed — proven by source, the seal class exists exactly
for a peer that must not shrink a shared object — so nothing can
pull pages out from under a mapping), exposed to the guest as one
virtio shared-memory region, mapped **once** at device setup and
never remapped. Inside it the server manages fixed-size slots in
software: a small index table at the arena's start carries one
sequence word per slot, and the slots follow. A slot holds a copy
of a file range, placed there by the server through its ordinary
read path, and the guest serves reads from granted slots at memory
speed with no device exit and no round trip. The arena is a cache
— exactly the readahead block cache's discipline, promoted into
shared memory — and every rule about staleness, invalidation and
loss is inherited from contracts that already exist instead of
being invented here.

**The rejected alternative, recorded with its evidence.** The
first draft mapped backing files themselves into the window (the
DAX shape the original v2 decision sketched), fenced by host file
leases. The review retired it on the record: leases are
uid-scoped, so an ordinary-user server could map only files it
owns; the kernel force-breaks a lease on a timer, so
revocation-before-truncate is not race-free; the notification
class carries no acknowledgment, so no quiesce protocol fits the
wire's taxonomy; guest-pinned pages cannot be revoked on demand;
the server's own truncate path never breaks its own lease; a
lease is host-local while the fleet's ordinary deployment is a
shared backend a thousand members write; two decided host-I/O
postures bypass the host page cache the shape claimed to serve
from; and the mapping mechanism rejects files whose size is not
page-aligned. Each defect was structural. The direct-mapped shape
also could not keep the one-cache property it existed for without
per-inode divergence above the kernel client's provider boundary,
which that document's own criterion forbids. **The one-cache
property is therefore not achieved by this design and is not
claimed**: the arena is a third copy beside the host page cache
and the guest's own caching. What the window buys — decided, and
what D3 must prove — is the removal of the per-read round trip
and the device exit: a granted read costs a guest-local memory
copy, nothing else.

## The law of the window

**The window is an accelerator over the wire, never the truth.**
Every read has a wire path; a granted slot only short-cuts reads
the wire already serves. Absence, fullness, revocation, staleness,
device reset, reconnection, or a transport with no shared memory
at all each degrade the affected reads to the wire and nothing
else. A miss never stalls on the window: the read that finds no
valid grant takes the wire while the server fills a slot in the
background, or does not. No correctness property anywhere may
depend on a grant existing. A wire-only member, transport, or
deployment is whole, only slower.

Against the direct-mapped precedent's three recorded failure
modes, each impossible here by construction: **stall on full** —
a full arena refuses grants and the read takes the wire, there is
no fault path to stall; **spin on truncate** — the arena is a
sealed copy the server owns, no host file operation can invalidate
its pages; **churn collapse** — there is exactly one mapping for
the device's lifetime, so the per-mapping machinery whose churn
collapsed upstream is never exercised at all.

## The device

One virtio device **per mount**, PCI and MMIO transports (the CCW
transport has no shared-memory regions — proven by spec — and
serves wire-only). It carries two things and decides nothing:

1. **A frame transport.** One virtqueue pair carrying the wire
   protocol, handed to the session core as its transport exactly
   as vsock is. Framing on a descriptor queue is decided here,
   not assumed: one wire frame per descriptor chain, chains
   bounded by the negotiated frame bound, and the resilience
   contract's linearization point re-derived as *the complete
   frame made available to the device* — the queue analog of the
   complete frame on the socket. Device→driver buffers are
   pre-posted at the frame bound so notifications and replies
   always have a landing place. A device-transport mount dials one member — the
   backend its VMM was configured with — so "reconnect" on this
   transport always means the same member, and fleet migration is
   a wire-transport property; stated plainly, not implied.
2. **The window.** One shared-memory region, read-only toward the
   guest, write-back cacheable — decided, and stated to the guest
   the way the precedent that negotiates cache attributes does —
   size fixed at VM configuration. Region enumeration on the PCI
   and MMIO transports is the virtio spec's own machinery, proven
   by source in the research record. The guest maps the region
   once; there is no per-slot mapping, no memory-slot churn, and
   the memory-slot budget question the direct-mapped shape had is
   moot at exactly one slot for the region.

The mapping-free design keeps all slot management in software:
grants and invalidations are wire messages, the arena's contents
are the server's memcpy, and no VMM interaction exists after
setup. Contents of ungranted slots are undefined toward the guest
and never read — the guest reads only through grants it holds.

## Grants — the slot lifecycle

A grant names (slot, node, range, generation, expiry). Decided
rules:

- **Granted on demand, once per range.** A guest read that misses
  asks for a grant with an ordinary request (new opcodes in the
  unassigned range — additive by the recorded ABI rules; a server
  answering ENOSYS makes the mount wire-only, which is the
  discovery story every addition uses). The reply carries the
  grant or a wire-fallback refusal; the read itself proceeds on
  the wire either way, so the grant round trip is never on a
  read's critical path — it accelerates the next read, not this
  one.
- **Grants expire like attributes.** A grant's validity is the
  attribute lifetime the mount already runs, and the renewal rule
  is stated: an attribute revalidation that observes unchanged
  size and mtime extends the file's grants to a fresh lifetime —
  a client-side rule over traffic that already flows, no new
  timer, no field added to any message. A mount running a zero
  attribute TTL therefore holds only expired grants and is
  wire-only in effect, stated so the relation is never
  rediscovered. A policy, posture or rule change bounds exposure
  by the same TTL that already bounds every cache the client
  holds, with the invalidation notification (below) as the
  accelerator of that bound, not its guarantee. The mount gains
  an off switch for the window mirroring the readahead engine's,
  for the operator whose posture intent excludes serving reads
  from any TTL-bounded copy.
- **Invalidation inherits the client's own cache discipline.**
  On the userspace client that is the readahead contract's rules;
  on the page-cached kernel client it is the attribute-driven
  drop rules its specification states — in both, the client drops
  its own file's grants on a local write, and staleness from
  host-side change is bounded by the attribute TTL, which the
  main design already records as the bound for every client
  cache. The server refreshes or invalidates a slot when it
  applies a write to the range and when the attributes it serves
  change size or mtime; no host-change watcher exists or is
  assumed. Invalidation notifications ride the existing
  reserved-notification class fire-and-forget — safe precisely
  because a stale slot is a stale *cache*, bounded by the TTL
  like every other cache, never a fault and never undefined
  memory. The quiesce protocol the direct-mapped shape needed
  does not exist because nothing needs quiescing.
- **Slots are fixed-size, the tables fixed-capacity.** Slot size
  and count are set at mount from the arena size; the guest's
  grant table is sized at mount and allocation-free in steady
  state per the kernel core's constraints. Eviction is
  server-driven (the server owns the arena), least-recently
  granted first, revocation by notification. The race between a
  refill or revocation and an in-flight guest copy is closed by
  the index table's sequence words, the classic sequence-lock
  discipline: the server makes the slot's word odd before
  touching its bytes and even-and-advanced after (each store
  released), and the guest reads the word before and after its
  copy (each load acquired) — a copy whose two reads disagree,
  observe an odd value, or observe a sequence other than its
  grant's is discarded and the read taken on the wire. A torn
  mid-refill copy is thereby detected, never served; this is the
  one check the accelerator needs, and its two memory-ordering
  rules are stated here so no implementation rediscovers them.
- **Reconnection invalidates everything.** Grants are
  generation-tagged; a new session generation invalidates every
  grant the guest holds (ids die with the generation — the
  resilience contract's rule, inherited). The arena mapping
  itself survives, because it belongs to the device, not the
  session; the slots refill on demand.

## What fills a slot

The server, through its ordinary read path: policy checked at the
funnel every read passes, posture respected (an uncached-posture
namespace fills slots through the same aligned-bounce site its
wire reads use), and any future transform stage sits upstream of
the copy exactly as it sits upstream of a wire reply — the v3
hint stays alive with no further provision. The fill is the one
host-side memory copy this design pays, and D3 measures what it
buys against the round trip it replaces.

## The kernel client's seams, satisfied

The provider boundary takes the window provider: it fills guest
pages (or direct-io read buffers) from granted slots by memory
copy, and delegates to the wire provider on any miss — the same
fill-shaped contract the interim provider has, strictly below the
boundary, no per-inode divergence, no new memory model in the
guest. mmap needs nothing: mapped pages are ordinary guest page
cache filled by the provider, whichever source filled them. The
transport seam takes the device queue as one more frame
transport. The FUSE client can consume the same grants through a
userspace mapping of the region — recorded **open**, settled by a
D3 experiment on whether the userspace copy path beats the wire
enough to carry its complexity; nothing in the design depends on
the answer.

## Deployment envelope, stated honestly

Proven by source: the generic shared-memory plumbing this rides
(region declaration and one fd-backed map at setup) is in QEMU
from 11.1; the flake's current QEMU is older, so **the QEMU floor
is a named precondition of phase D2**, checked by the ladder, not
assumed. Any device with a shared-memory region blocks VM
migration today — the blocker attaches to the device, so a
migratable VM runs wire-only mounts; stated as the deployment
rule. The vhost-user model shares all guest memory with the
backend, which places the server inside that VM's trust boundary
— THREAT-MODEL is owed a line for the device-transport deployment
when implementation opens. One item is not determinable from the
public record and is marked exactly that, not proven:
confidential-VM compatibility; wire-only serves there too.

## Phasing

1. **D1 — the device as transport.** The virtio device with its
   queue pair carries the wire; the kernel client mounts over it
   in the KVM ring beside vsock; the prototype rides the generic
   test device upstream provides for exactly this, and a proper
   device identity is this phase's deliverable. No window use.
2. **D2 — the arena.** Region setup, seals, the grant opcodes,
   TTL expiry, invalidation and revocation, generation checks;
   the KVM ring proves granted reads byte-identical to wire reads
   under concurrent host modification, revocation storms, slot
   exhaustion, reconnection, and device reset — the survival
   arms. Provisional slot size and count are set here from the
   readahead engine's measured shape and marked as provisional.
3. **D3 — measurement.** Granted versus wire reads across sizes,
   patterns and postures; slot size, count and the size floor set
   from the numbers (the floor — the file size below which a
   grant is never asked for because the wire read is already
   cheap — runs provisionally at one slot's size until then);
   the userspace-mapping question answered; a writable arena for
   the write path opened or closed on evidence, in
   WRITESTREAM.md's terms.

## Acceptance criteria — for this specification

1. Every capability claim carries its evidence class, and the
   rejected direct-mapped shape is recorded with the evidence
   that retired it.
2. The window is provably optional: every read's wire path is
   stated or inherited, no clause makes a grant necessary for
   correctness, and a wire-only deployment satisfies every other
   contract untouched.
3. The three failure modes of the direct-mapped precedent —
   stall on full, spin on truncate, churn collapse — are
   structurally impossible in the granted-arena shape, each shown
   by construction, not mitigated.
4. The design contradicts no decided contract: coherence and
   invalidation, resilience and generations, fleet topology,
   policy enforcement, the postures, the kernel client's provider
   and transport seams, the kernel core's fixed-capacity rules,
   and the ABI rules.
5. Every open question names its settling experiment and phase,
   and every deferred number (slot size, count, size floor) has a
   provisional value with the phase that replaces it.
