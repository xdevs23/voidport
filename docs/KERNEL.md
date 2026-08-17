# The kernel client

The authority document for voidport's in-kernel client. Written
2026-08-17, at the close of v1, from the research pass and the
compile probes that preceded it; every claim below carries its
evidence class — measured, proven by source, or open with the
experiment that settles it named. This document decides the design.
It deliberately implements nothing: implementation begins when it is
opened, separately.

Renamed context: the userspace FUSE client remains the client for
userspace mounts, permanently. The kernel client exists for the
built-image virtual machine case, where the guest image is
constructed wholesale anyway and a module in it costs nothing to
deliver.

## The law before the design

Everything here is designed robustly from the start: a hazard is
fixed through architecture, never through imperative code layered on
top, and a shape that accumulates guards is reconsidered instead of
patched. The v1 record shows the method — three rejected shapes are
recorded beside the one that shipped for the recorded-metadata
design, each with its measured reason — and the kernel client is
built the same way. Where this document cannot decide something
without an experiment, it names the experiment instead of guessing.

## Purpose, scope, non-goals

**Purpose.** A guest kernel module that mounts a voidport namespace
as a real filesystem — registered with the VFS, mounted by
`mount(2)`, no userspace helper in the data path — speaking the
existing wire protocol over vsock to the unmodified v1 server.

**Scope.** The client only: session handshake, the full operation
set the wire defines, per-namespace mounts, reconnect semantics
matching the mount-resilience contract, and the guest-side
enforcement postures v1 defines (presented attributes, recorded
privileged bits, the mount options that exist today where they are
meaningful in kernel space).

**Non-goals, stated hard.** The v2 shared-memory data plane — the
virtio device with a DAX-style window — is the successor data path
and is out of scope here; nothing in this design may foreclose it,
and its host-side component makes it a different project. No server
changes: the module speaks to the v1 server as any client does. No
upstreaming attempt now (kept possible; see the constraints
section). The retired io_uring evaluation stays retired: the
earlier roadmap gate was superseded by decision when the kernel
direction was chosen on its own merits, and the round-trip
attribution showed the dominant cost is scheduling that a ring only
partly addresses.

## The shape: a real filesystem, three layers

The decided ideal is a filesystem the guest kernel treats as native.
On the kernels the module targets, the Rust surface for that does
not exist upstream — the kernel's Rust filesystem types cover file
handles and I/O control blocks, not registration — so the shape is
three layers, each with one job:

1. **The protocol core, pure Rust, no kernel types.** The wire
   crate itself — no_std, allocation-free, every multi-byte field a
   byteorder type — compiled as a kernel crate. This is measured
   fact, not plan: the crate and its one derive dependency build
   under kbuild against a Rust-enabled kernel with zero source
   changes, and a probe module has round-tripped a frame in kernel
   space. The session state machine (handshake, request tracking,
   reconnect) lives here too, as plain Rust over abstract transport
   and timer traits, so it is testable in userspace by the existing
   suite patterns before it ever runs in a kernel.
2. **The kernel-Rust layer.** Everything the upstream kernel crate
   already offers is used from it — allocation, synchronization,
   workqueues, module plumbing. What it does not offer for this
   module's needs is written as this project's own Rust
   abstractions over the C shim below, following the practice the
   reference Rust-driver project demonstrated at scale: wrap what
   upstream lacks, keep the unsafe boundary in one auditable
   place, and expect to own those wrappers for years.
3. **The C shim, small and enumerated.** Two surfaces need C on
   the target kernels, and only two. Filesystem registration: the
   registration structures and their operation tables are filled
   with `extern "C"` functions exported by the Rust side; the shim
   owns only the structure definitions and the register/unregister
   calls. Sockets: kernel-owned socket creation and the send and
   receive calls, five functions, compile-proven against the
   running kernel. The shim never contains logic — a function that
   starts deciding things moves up a layer. Both upstream gaps
   have RFC series that would close them; when either merges, the
   corresponding shim retires, and the layering exists exactly so
   that retirement is a swap, not a rewrite.

## The wire client in kernel space — proven ground

The protocol crate builds under kbuild as a real extern crate. The
build recipe is recorded with the probe records: one rustc rule per
external crate using the kernel build's own flag set, three products
from one invocation so metadata and object agree, crate objects
listed as module objects, direct dependencies injected per object.
Five sharp edges were found and cleared, each with a misleading
error, and they are constraints on the module's code:

- the kernel build pins the 2021 edition tree-wide; external crates
  filter it out and set their own, and the module's own Rust is
  2021-edition, always;
- the kernel's core strips float formatting behind a configuration
  flag that out-of-tree builds do not inherit; the derive
  dependency already supports exactly that configuration and the
  build passes the flag through;
- the kernel denies non-ASCII identifiers tree-wide and the derive
  dependency emits them; the module build allows the lint for
  those crates — this is also the single hardest obstacle if
  upstreaming is ever attempted;
- extern declarations cover direct dependencies only; transitive
  resolution rides the library search path with exact file names;
- a crate's code reaches the module only when its object is
  emitted from the same invocation as its metadata.

## Transport — kernel-owned vsock, compile-proven, load-untested

Kernel-owned vsock is first-class on the target kernels: the
kernel-socket constructor is family-agnostic by source, the vsock
family threads the kernel flag through its socket allocation, and
the send and receive calls carry kernel-space buffers with no
userspace assumption. Every symbol the client needs is a plain
export — none is GPL-gated, though the question is moot because
every Rust runtime export is GPL-only and the module is GPL-2.0 by
construction. A five-function shim compiles and links in the probe
module. Two preconditions are recorded from source: the vsock
transport module must be ensured explicitly (the module alias for
the protocol family belongs to the wrong transport in a QEMU
guest), and socket calls assume a task context — the client's I/O
runs on kernel threads or workqueues, never in atomic context.

What no one has published anywhere is vsock from kernel-space Rust
at runtime. The first implementation phase therefore begins with
the load test this document is not allowed to assume: a module that
exchanges one real frame with the running v1 server over vsock.
Loading probe modules on the development machine is sanctioned.

## Caching — the interim posture

The shared network-filesystem caching library is deliberately not
used: it has no Rust bindings, its integration is the largest C
surface on the map, and the decided v2 data plane routes around it
entirely for bulk data. Until that data plane exists, the kernel
client's caching posture mirrors the userspace client's direct
mode: attribute and entry caching with the same bounded lifetimes
the v1 mount options define, no guest page cache for file data,
reads and writes as wire round trips. This keeps the one-cache
model — the host's page cache is the cache — and keeps every v1
coherence contract intact. The parallel-writes capability the FUSE
client announces has a natural analog: the module imposes no
serialization of its own on concurrent direct I/O to one file
beyond what the wire contract requires. Readahead as the v1 client
implements it is explicitly deferred to measurement: the module
lands correct first, and the streaming engine is ported only where
the same paired A/B that justified it in userspace justifies it
again in kernel space.

## Build integration and version policy

The module builds out of tree with kbuild against the kernel dev
output nixpkgs provides. On the development machine this is proven
with zero toolchain skew: the running kernel is the nixpkgs kernel
with Rust enabled, its dev output substitutes from the cache in
seconds, and the module builds in seconds against it. The `nix`
expressions for the module build live beside it under the module
directory; the flake gains a kernel-module output gated on the
kernel offering Rust, so the module is built by the same entry
point as everything else.

The version policy is decided: **chase newest** — the module tracks
whatever kernel nixpkgs unstable carries. The kernel's Rust
internals are explicitly unstable, so the policy comes with its
protocol: every kernel bump runs the revalidation ladder — the
crate compile, the shim compile against the new dev output, the
frame round-trip probe, then the module's own suite — and a bump
that breaks the module is fixed forward the same day it is noticed
or the flake pins the previous kernel until it is. The ladder is
automation, not discipline: it is a derivation that fails loudly,
not a checklist.

## Testing architecture

Three rings, cheapest first:

1. **Userspace tests of the pure core.** The protocol and session
   state machine are plain Rust; their tests run in the ordinary
   workspace suite against mock transports, and every wire-level
   behavior the v1 suites pin — golden vectors, rejection tables,
   handshake semantics — applies to the kernel client's core
   verbatim because it is the same crate.
2. **KVM guests, built by nix.** The real ring: a minimal NixOS
   guest image carrying the module, booted under KVM on the
   development machine (KVM access is available), mounting a
   namespace served by the host-side v1 server over vsock. The v1
   end-to-end suites' semantics — POSIX continuity, policy
   enforcement, coherence across mounts, reconnect, teardown — are
   re-exercised against the kernel mount through the same
   assertions, ported to drive a guest. The torture harness gains a
   kernel-mount arm the same way. Guest kernels for this ring come
   from the same nixpkgs revision as the module build, which makes
   the ring the revalidation ladder's last rung.
3. **The development machine itself**, where loading is sanctioned:
   fast iteration on probe modules against the running kernel, with
   the stated risk that a bad module halts the machine — the KVM
   ring exists so this ring is optional for anything dangerous.

## Layout and licensing

The module lives in this repository under a kernel directory, with
its own build files and its vendored crate references pointing at
the workspace's protocol crate — one wire truth, no copy. The
license is GPL-2.0-only, forced by the kernel's Rust runtime
exports independent of preference and consistent with the recorded
license split; the protocol crate's permissive license is what
makes the vendoring clean.

## Upstreaming — possible, not pursued

The decision stands: no upstreaming effort now, and nothing that
forecloses it. The recorded constraints if it is ever attempted:
the derive dependency's non-ASCII identifiers collide with a
tree-wide lint; the in-tree third-party crate policy would make
that dependency someone's maintenance duty; the C shim would need
to become or await the upstream abstractions; and the reference
project's calibration is sobering — its flagship Rust driver
remains out of tree after three years. The layering above is the
whole preparation: the pure core is upstream-agnostic, the shim is
disposable, and only the middle layer would be negotiated.

## Phasing

The implementation order, when opened — each phase a gate for the
next, none started here:

1. **Frame over vsock**: the probe module exchanges one real frame
   with the v1 server at runtime. Highest information per hour; no
   published precedent exists.
2. **Session core in kernel space**: handshake and request
   tracking on kernel threads, still no VFS — proven by an
   in-kernel functional test against the real server.
3. **Read-only mount**: registration through the shim, lookup,
   getattr, open, read, readdir against the wire; the KVM ring
   comes up with it.
4. **The full operation set**: writes, mutations, locks, xattrs,
   special files, recorded privileged bits — each ported with its
   v1 semantics tests.
5. **Resilience and torture**: reconnect semantics and the
   kernel-mount torture arm.
6. **Measurement**: the paired comparisons against the userspace
   client, which decide whether readahead's port is justified and
   inform the v2 data plane's design with kernel-side numbers.

## Acceptance criteria — for this specification

1. Every capability claim in this document carries its evidence
   class, and every proven claim traces to a probe or measurement
   in the research records; a reader can distinguish measured fact
   from decision from open question in every section.
2. Every open question is named with the experiment that settles
   it, and no phase depends on an unnamed unknown.
3. The design forecloses nothing the v2 mandate requires: the
   shared-memory data plane slots in as the data path without
   restructuring the three layers.
4. The spec review finds no contradiction with the main design
   document's decided contracts — the wire protocol rules, the
   coherence model, the mount-resilience contract, the recorded
   license split, and the architecture law.
