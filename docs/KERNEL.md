# The kernel client

The authority document for voidport's in-kernel client. First
written 2026-08-17 at the close of v1; rewritten the same day after
its probing spec review, which measured two claims false, disproved
one enumeration with a live probe, and rebuilt the compile probes
against the newest kernel — every correction is folded in below,
and the review's probes are part of this document's evidence.
Amended the same day after the follow-up review, which verified the
closures and returned fifteen findings, four of them contradictions
of decided contracts — the coherence carry-over, the write-path
wording, the unnamed kernel attribute, and the shared core's
license — all fifteen folded in below. This document
decides the design and implements nothing: implementation begins
when it is opened, separately.

Standing context: the userspace FUSE client remains the client for
userspace mounts, permanently. The kernel client exists for the
built-image virtual machine case, where the guest image is
constructed wholesale and a module in it costs nothing to deliver.

## The law before the design

Everything here is designed robustly from the start: a hazard is
fixed through architecture, never through imperative code layered
on top, and a shape that accumulates guards is reconsidered instead
of patched. Where this document cannot decide something without an
experiment, it names the experiment, and each
implementation phase gates on the experiments before it.

## The quality and survival bars (decided 2026-08-18)

Implementation is open. The bar is set explicitly: the in-tree
Rust code of the pinned kernel is the floor, the asahi GPU driver
is the external reference, and this module aims a level above
both. The shapes that reach that level are the recorded
architecture law's — hollow-lattice structure, asynchronous and
event-driven design where the problem is a stream of events,
actor-shaped ownership where state wants exactly one owner — and
when a new requirement does not slot in, the structure is
refactored until it does. Calling a requirement too hard or too
involved is not an outcome this project recognizes; shipping v1
is the standing proof of what the process can build.

Survival is an acceptance criterion, not an aspiration: the
module withstands everything thrown at it short of memory
corruption or broken hardware, and attempts best-effort survival
even then. The host's resources are the only limit — a test run
where voidport yields before the hardware does is a failed run,
and the ring-2 torture and fault arms encode exactly that
criterion.

Maintainer approval is checked, not assumed. The C file passes
the kernel tree's own checkpatch and coding style; the Rust
passes the kernel tree's rustfmt and clippy configuration; and
every kernel increment's review includes an upstream-maintainer
pass — a reviewer judging the change as a subsystem maintainer
would, returning "would this survive list review" as a named
verdict. These checks live beside the module and run with its
ladder.

Evidence classes used throughout: **measured** (a probe ran and its
result is stated), **compile-proven** (it builds and links; it has
never executed), **proven by source** (read in the named kernel
version), **decided** (a recorded project decision), **open** (the
settling experiment is named). The review that shaped this rewrite
exists because the first draft blurred the first two classes; they
are never blurred below.

## Purpose, scope, non-goals

**Purpose.** A guest kernel module that mounts a voidport namespace
as a real filesystem — registered with the VFS, mounted by
`mount(2)`, no userspace helper in the data path — speaking the
existing wire protocol over vsock to the unmodified v1 server.

**Scope.** The client only: session handshake, the full operation
set the wire defines, per-namespace mounts, reconnect semantics
matching the mount-resilience contract, and the guest-side
postures v1 defines where they are meaningful in kernel space.

**Non-goals, stated hard.** The v2 shared-memory data plane is the
successor data path: out of scope, and the seam it slots into is
named in the caching section. No server changes. No upstreaming
attempt now (kept possible; constraints recorded). The retired
io_uring evaluation stays retired by the recorded decision.

## The shape: a real filesystem, three layers

1. **The protocol and session core — pure Rust, no kernel types.**
   The wire crate compiles under kbuild as a kernel crate with zero
   source changes (**compile-proven**, and re-proven against the
   newest kernel during the review). The session logic — handshake
   validation with its distinct error classes, request tracking,
   reconnect with replay — is **extracted from the existing
   userspace client into a shared no_std core crate**, not written
   twice: one authority for the resilience contract, consumed by
   both clients, tested by the existing suites through the
   userspace client and by ring-1 tests directly. The core speaks
   through a frame transport handed to it as data — vsock now, the
   v2 window's control queue later — so the decided v2 shape's
   control half has its seam here, beside the data-provider
   boundary named in the caching section. The extraction is
   its own implementation phase with its own review, because it
   refactors shipped v1 code. Kernel-space constraints the core
   must meet, decided here: replay retention and the request table
   are **fixed-capacity**, sized at mount from the mount's
   concurrency bound, and a full table backpressures the caller
   exactly as the v1 run-ahead bound backpressures the wire —
   allocation-free steady state, no overflow class. The jittered
   backoff takes its randomness from a seed the mount supplies (the
   kernel's random bytes at mount time), threaded as data.
2. **The kernel-Rust layer.** Everything upstream's kernel crate
   offers is used from it: allocation, synchronization, workqueues,
   module plumbing — and, decisively, the kernel's **generated
   bindings crate**, through which the filesystem registration
   types are reachable from Rust without hand-written C (the
   registration structures resolve through the bindings,
   **compile-proven by the review**; every registration and
   super-block symbol the client needs is a plain export in both
   probed kernels, **proven by source**). What the bindings cannot
   express — static inline helpers and macros, which the generator
   cannot call — is the true C surface, enumerated below. This layer owns the one
   auditable unsafe boundary.
3. **The C helper file — one, enumerated, logic-free.** The
   surfaces that genuinely need C on the probed kernels: the
   static-inline VFS helpers the registration path uses (the
   review's probe names the class; the exact list is a phase-3
   deliverable pinned by its gate), and the five kernel-socket
   calls (**compile-proven**, with the newest-kernel signature
   drift already found and fixed one-line in the probes). A helper
   that starts deciding things moves up a layer. When the upstream
   VFS or socket abstraction series merge, the corresponding
   helpers retire by swap.

## The wire crate under kbuild — compile-proven ground

The build recipe is a project artifact, not a memory: one rustc
rule per external crate using the kernel build's own flag set,
three products per invocation so metadata and object agree, crate
objects listed as module objects, direct dependencies injected per
object, host proc macros built by cargo with the same rustc. Five
sharp edges, each failing with an error that does not name its
cause, are constraints on the module's code: the tree-wide 2021
edition is filtered per crate (the module's own Rust is 2021,
always; the wire crate is 2024, which also sets the true rustc
floor — newer than the kernel's own — on any pinned-fallback
kernel); the kernel core's stripped float formatting is a
configuration flag the build passes through, which the derive
dependency already supports first-class; the tree-wide non-ASCII
identifier lint is allowed for the derive dependency's expansion;
extern declarations cover direct dependencies only, with
transitive resolution on the search path; and a crate's object
must come from the invocation that produced its metadata.

**One wire truth, mechanically.** The module consumes the
workspace's protocol crate **by path** — never a vendored copy
(the review found the probe's vendored copy already stale against
a landing from the same day, which is the whole argument). The
full crate chain is stated, not waved at: the wire crate, the
derive dependency, and the derive's own host-side chain, all
resolved from the workspace's lockfile; the module build derivation
reads the same sources the workspace builds, and a drift test in
the gate fails if the module's crate inputs and the workspace's
disagree.

## Transport — kernel-owned vsock

**Proven by source and compile-proven; never yet executed.** The
kernel-socket constructor is family-agnostic; the vsock family
threads the kernel flag through its allocation; the send and
receive calls carry kernel buffers. Every needed symbol is a plain
export — moot for licensing, since the Rust runtime's exports force
GPL-2.0 regardless, consistent with the recorded license split. The
newest-kernel signature drift in the connect call is found and
fixed in the probes. Two source-proven preconditions: the vsock
transport module is ensured by the guest image's module
configuration (a soft dependency declared by the module, and the
built-image case controls its image — a mount-time preflight
answers a typed error when the transport is absent anyway), and
socket calls run in task context: the client's I/O lives on its
own kernel threads.

**The first implementation phase is the load test this document is
not allowed to assume**: a module exchanging one real frame with
the running v1 server over vsock. No published precedent exists
anywhere for kernel-space Rust over vsock; this is the highest
information per hour in the plan, and nothing in this document
claims it has happened.

## The data path and the caching decision

The review proved the first draft's posture impossible: a native
filesystem without a guest page cache cannot serve shared mappings,
and mmap — exec from the mount above all — is inviolable by
recorded decision. So the decision, stated plainly:

**The kernel client uses the guest page cache for file data.** The
standard native shape: read and write paths through the page cache
against the wire, shared mappings served the way every real
filesystem serves them. This deliberately gives up, for the interim,
the one-cache property the userspace direct mode bought — a
built-image guest running the kernel client caches file data twice,
guest and host — and says so instead of pretending otherwise.

**The v2 seam is exactly here, and it is why the trade is
acceptable.** The data path sits behind one provider boundary in
the kernel-Rust layer: the interim provider fills pages from the
wire and writes through them to the wire — writethrough, no
writeback cache, per the decided coherence contract, with fsync
and flush passing through as in v1, and memory-map writeback
riding the same path: dirty pages a shared mapping produces reach
the wire through the provider's page-writing hook, ported in the
full-operation phase with the rest of the write set; the v2
provider maps the shared-memory window so the same page cache
pages ARE host memory — the DAX shape, which
removes the duplication the interim accepts. Nothing above the
boundary changes when the provider does. That boundary is the
criterion-3 answer: the successor data plane slots in as a provider
swap, and this document forecloses nothing it needs.

Attribute and entry caching mirror the v1 mount options and their
bounded lifetimes. Cached file data is dropped when attribute
revalidation observes a size or modification-time change — the
in-kernel analog of the auto-invalidation capability the userspace
mount negotiates — so data staleness stays bounded by the attribute
lifetime, exactly the v1 coherence bound; without this rule a held
page would stay stale indefinitely, which the decided contract
forbids. Directory entry revalidation is the module's own
(the machinery FUSE supplied for free is rebuilt: a revalidation
hook honoring the entry lifetime, with the stale-answer retry
behavior of the kernel's path walk **open** until the path-walk
retry experiment in phase 3 proves it). Readahead needs no port: the page cache's own
readahead drives the read path, and the measurement phase compares
it against the userspace engine before anything more is built.

## Node lifecycle — the FORGET mapping

The wire's node lifecycle assumes the client counts lookups and
forgets nodes; FUSE supplied that accounting and a native
filesystem has none. Decided: the module keeps its own per-inode
lookup count — incremented where the wire operations that admit
nodes return them, decremented to a wire FORGET from the inode
eviction callback, exactly one forget per admission — and the
directory-listing path owes the same compensating forget v1 states
for entries counted but never delivered to the caller. Eviction
under guest memory pressure therefore drives the server's node
table down the same way FUSE clients do and the descriptor-budget
contract holds unchanged. No forget flush is owed at unmount: the
server clears the session's nodes at teardown, per the decided
lifecycle. The mapping is pinned in ring 2 by the same
node-accounting assertions the v1 suites run.

## Security posture

Stated, because a native filesystem changes the defaults FUSE
imposed: mounting requires system administrator capability in the
initial namespace (the standard bar for a network filesystem
module); the mount is visible guest-wide like any mount — the
userspace client's allow-other flag was a FUSE artifact and has no
analog here — THREAT-MODEL is owed a line for this when
implementation opens; per-request credentials are the calling
task's at call time, matching the
request head's semantics; permission checking stays exactly v1's
default-permissions model — the guest kernel checks against
presented attributes, the server enforces its own rules regardless.
Idmapped mounts and user-namespace mounting are **open**, with the
experiment named: a phase-4 probe of the mapped-credential path
before any support is claimed.

## Teardown and failure

The module is unloadable only with no mounts; a mount holds the
module. Unmount answers what the kernel is owed before it
disconnects — the v1 signalled-teardown contract's shape, with the
same bounded settle and the same refusal to lazy-unmount. Stall
waits on a dead server are killable: every wire wait is
interruptible, a killed task's operation fails with the interrupt
error, and the mount degrades per the resilience contract instead
of wedging the guest's task state. Each hello refusal class maps
to a distinct mount error, inherited from the shared session core.
The client's kernel threads are bounded per mount and join at
unmount, pinned by a ring-2 teardown test.

## I/O contract

Reads and writes chunk at the negotiated frame bound. Buffers:
one bounce per in-flight operation, owned by the operation,
allocated under the no-filesystem-reclaim discipline so memory
pressure cannot recurse into the mount. Frame transmission is
serialized per connection — the resilience contract's linearization
point is the complete frame on the socket, so partial sends are
completed under the send lock before any other frame may start.
Concurrency is bounded per mount by the same run-ahead shape the
server itself adopted, and the bound is the request table's
capacity from the core section.

## Mount surface

`mount -t voidport` with a source naming the vsock endpoint and
namespace and options parsed by the kernel's own filesystem
parameter machinery — the in-kernel analog of the no-manual-parsers
law; the userspace URL grammar is not reused (its parser cannot
exist in kernel space, and mount sources have their own
convention). Options mirror the v1 mount options that survive the
kernel context — read-only, the attribute and entry lifetimes, the
privileged-bits opt-out, and the reconnect stall window with its
zero-means-fail-fast semantic — each mapping to its v1 semantic;
unknown options refuse the mount with the parameter machinery's own
error. The userspace `voidport mount` tool gains nothing here;
whether it ever fronts the kernel mount is a later product
decision — settled by decision when it arises, not by an
experiment.

## Build integration and version policy

The module builds out of tree with kbuild against the kernel dev
output nix provides, as a flake output. **The supported kernels
are a named set of three** (decided 2026-08-18, superseding the
single pin): the latest longterm release, the current stable
release, and mainline — tracked through their nixpkgs unstable
attributes (at this writing 6.18.44, 7.1.8, and the 7.2 release
candidates). Every member already carries Rust on this
architecture. The rule that makes loading sound is unchanged and
now holds per member: **the module is only ever loaded on the
kernel it was built against**; ring 3 is available only while the
development machine boots one of the set's exact derivations,
otherwise ring 2 is the only loading ring, and the ladder checks
the equality instead of assuming it. The review measured both
mismatch scales this rule exists for: the running kernel one
patch level behind one member, and a full major version behind
another.

Version drift across the set is an architecture obligation, not
a porting chore. The kernel-Rust API is unstable between releases
— the connect-call signature drift the review found is the
recorded example — so every difference the set exposes is
absorbed in **one compatibility surface** beside the C helpers,
one place that answers what this kernel offers; a capability an
older member lacks degrades by structure, decided and recorded
per capability, never by conditionals scattered through the
layers. Supporting the whole set from one tree is deliberately
part of the architecture test: a version difference that cannot
be absorbed at the compatibility surface is a finding against
the shape, not a reason for a special case.

Chase-newest comes with its protocol, per set member: every
kernel bump runs the revalidation ladder — crate compile, helper
compile, the frame round-trip probe in a KVM guest, then the
module suite — and a bump that breaks the module is fixed forward
promptly or the flake pins that member's previous kernel until it
is (a pinned fallback must still meet the wire crate's rustc
floor, which is newer than the kernel's own — stated above). The
ladder's build rungs are derivations; its guest rungs are not
(next section), so the ladder is a gate script over both, run by
the same entry point as the other gates.

## Testing architecture

Three rings, cheapest first, plus the debug arm the review found
missing:

1. **Userspace tests of the shared core.** The extracted session
   core and the wire crate run in the ordinary workspace suite:
   golden vectors, rejection tables, handshake classes, replay and
   backoff behavior against mock transports — the same assertions
   that already pin the userspace client, now pinning the shared
   authority.
2. **KVM guests, nix-built, driven from the devshell.** The real
   ring: a minimal guest image carrying the module boots under KVM
   on the development machine, mounts a namespace served by the
   host-side v1 server over vsock, and the v1 end-to-end semantics
   — POSIX continuity including exec from the mount, policy
   enforcement, coherence, reconnect, teardown, node accounting —
   re-run through a guest-driving harness with the same
   skip-is-a-failure law every v1 suite carries. Production
   contract, stated because the review demanded it: this ring runs
   **outside the nix build sandbox** (the sandbox exposes neither
   the vsock host device nor stable guest addressing), driven by
   the gate script from the devshell; guest addresses are
   allocated per run from the ladder's own registry so concurrent
   runs cannot collide; and the ring's cost is bounded by reusing
   the flake's already-built kernel and image outputs. This ring
   is a **ladder gate only**: the workspace check and the flake
   package build stay unchanged and sandbox-clean, and neither
   ever boots a guest. The torture harness gains a kernel-mount
   arm in the same ring.
3. **The development machine**, where loading is sanctioned, under
   the built-equals-loaded rule — fast iteration, with the KVM
   ring as the place anything dangerous goes instead.
4. **The debug arm**: ring 2 runs its suite additionally against a
   debug kernel — address and undefined-behavior sanitizers, lock
   dependency validation, sleep-in-atomic checks, leak detection —
   on every ladder run, because hand-written unsafe against kernel
   internals is exactly what those tools exist for. Each set
   member stays singular in **source**: one kernel, two
   configurations. The production configuration is the cached
   upstream build; the debug configuration enables facilities the
   production kernel ships disabled, so it is built locally once
   per kernel bump and cached across ladder runs, with the module
   built once per configuration under the built-equals-loaded
   rule. The full matrix is three members by two configurations;
   the ladder runs the debug configuration on the member that
   changed and cycles the rest.

## Layout, licensing, evidence durability

The module lives in this repository under a kernel directory:
its kbuild files, the C helper file, its nix expressions, and the
probe modules — which graduate from development scratch into the
tree when implementation opens, so the authority document's
evidence stops living in throwaway space (the review's durability
finding; until implementation opens, the probe records remain
development artifacts and every load-bearing claim above is marked
compile-proven or open accordingly — the phases re-prove each at
its gate). The module's own crates stay outside the cargo
workspace — kbuild builds them, and the workspace-wide denial of
unsafe code is untouched; the shared session core joins the
workspace as an ordinary member and stays unsafe-free, since every
unsafe boundary lives in the kernel-Rust layer.

Licensing, stated per crate because two copyleft versions do not
combine: the module is GPL-2.0-only, forced by the Rust runtime's
exports and consistent with the recorded split; the wire crate's
permissive license is what makes the by-path consumption clean;
and the **extracted session core carries the wire crate's
permissive license too** — it cannot inherit the workspace's
GPL-3.0-only and remain consumable by a GPL-2.0-only module, which
is the same reasoning already recorded for the wire crate. The
extraction phase owes the license table this entry.

## Upstreaming — possible, not pursued

Unchanged by decision: no effort now, nothing foreclosing later.
Constraints on record: the derive dependency's non-ASCII expansion
against the tree-wide lint; the in-tree third-party crate policy;
the C helpers becoming or awaiting upstream abstractions; and the
calibration that the reference project's flagship driver remains
out of tree after three years.

## Phasing

Each phase gates the next; none is started by this document.

1. **Frame over vsock, executed**: the probe module exchanges one
   real frame with the v1 server at runtime — in a minimal probe
   guest first (the full ring-2 harness comes later), then ring 3.
   Runs on the stable member of the kernel set first; the other
   members join the ladder with the phase-3 harness. Converts the
   transport from compile-proven to measured; no precedent exists.
2. **The shared core extraction**: the session logic leaves the
   userspace client for the no_std core crate, with the fixed-
   capacity replay design and the permissive license entry owed to
   the license table, under the full increment pipeline (it
   refactors shipped code); the userspace client consumes it and
   the v1 suites prove nothing moved.
3. **Read-only mount**: registration through the bindings and
   helpers, lookup, getattr, open, read, readdir, entry
   revalidation, the FORGET mapping; the full ring-2 harness comes
   up with this phase; the static-inline helper list is pinned by
   this phase's gate, and so is the **path-walk retry experiment**:
   prove the kernel's walk retries the lookup after a stale answer
   from entry revalidation, which the resilience contract's healing
   depends on.
4. **The full operation set**: writes through the page-cache
   provider, mutations, locks, xattrs, special files, recorded
   privileged bits, the credential-path probe; each ported with
   its v1 semantics tests.
5. **Resilience and torture**: reconnect through the shared core,
   the kernel-mount torture arm, teardown under fault.
6. **Measurement**: paired comparisons against the userspace
   client — including whether the page cache's own readahead
   makes the userspace engine's port unnecessary, and the numbers
   that inform the v2 window's design.

## Acceptance criteria — for this specification

1. Every capability claim carries its evidence class, no claim
   states execution that never ran, and the compile-proven and
   measured classes are never conflated — checkable by reading,
   and the review that enforced it is part of the record.
2. Every open question is named with the experiment that settles
   it — except a question marked a product decision, which is
   settled by decision and carries no experiment — and every
   phase's unknowns are listed in that phase or an earlier one.
3. The v2 data plane slots in at the named provider boundary
   without restructuring the layers — checkable against the v2
   mandate's decided shape.
4. The spec contradicts no decided contract of the main design
   document: wire rules, coherence model, resilience contract
   (including replay and its linearization point), node lifecycle,
   the license split, mmap inviolability, and the architecture
   law.
