# voidport — Design

Renamed from sharefs to voidport (2026-08-16); the design predates the name.

voidport is a network file server that exposes **namespaces**: virtual,
policy-defined projections of the host filesystem, mounted by guests (VMs
first, but nothing is VM-specific) through a FUSE client now and possibly a
kernel client later.

The core inversion versus virtiofs/9p/NFS: **you don't export a directory,
you compose a view.** A namespace starts as a completely empty root — zero
inodes, zero free space, nothing resolvable — and the operator grafts host
paths into it at runtime, each with its own policy.

## Problem

Existing host-to-VM sharing mechanisms each fail in a different way:

- **NFS** — uid/gid mapping is miserable (idmapd, squash options), export
  granularity is coarse, no per-path policy composition.
- **9p** — slow, weak caching, historically shaky xattr/attr semantics.
- **virtiofs** — fast but rigid: one virtiofsd per shared tree, configured at
  VM boot, tied to the VMM. No runtime "now also share this one file
  read-only into that running VM", no hiding entries within a tree.

voidport is a single long-running, VM-agnostic server: namespaces are created
and mutated on demand while guests are mounted, and one server serves many
namespaces to many clients over pluggable transports (TCP, unix socket,
vsock).

## Example

Host structure:

```
/path/to/project/
  foo/        → shared read-write
  bar/        → shared read-only
  secret/     → not shared, invisible to the guest
  file.txt    → shared read-write
```

Guest:

```
mount voidport://10.0.2.2/@my-namespace/path/to/project /mnt/project
ls -la /mnt/project
  rwx------ foo/
  r-x------ bar/
  rw------- file.txt        # secret/ does not exist as far as the guest can tell
```

## Goals

- Per-path share modes: **rw**, **ro**, **hidden** — hidden means the entry
  does not resolve, does not stat, does not appear in readdir.
- Deny-by-default: what is not grafted does not exist.
- Runtime reconfiguration of namespaces while clients are mounted.
- Ownership and permission mapping that solves the NFS uid problem.
- Real daily-driver semantics: xattrs, symlinks, hardlink identity, mmap
  (via read/write paths), locking, rename-while-open, unlink-while-open.
- Performance: the server is a multithreaded, highly parallel passthrough
  proxy; reads and writes go straight to the host filesystem.
- Coherence: multiple guests may share a tree (one writer / many readers);
  the server is the single point of truth.

## Non-goals (v1)

- Authentication (`auth.mode: none` only; the field exists so modes can be
  added without a protocol break).
- Client cache invalidation pushes (the protocol reserves a server-initiated
  message class for this; v1 clients just use conservative caching).
- Reconnect/resume of a dropped session (handshake carries a version field
  so this can be added).
- Watching the state file for external edits (server memory is authoritative
  after startup).
- Kernel client (the wire protocol is designed so one stays feasible).
- Recursive `**` wildcards, full glob syntax.
- Forced revocation of open handles on policy change.

## Concepts

- **Server (`voidportd`)** — owns all namespaces, serves the data plane and
  the control plane.
- **Namespace** — a named virtual root plus policy: ownership mapping,
  permission mode, auth mode, and a rule table.
- **Rule (graft)** — maps a namespace path to a host path with a share mode.
  Literal rules graft a specific file/dir; wildcard rules set a per-directory
  fallback.
- **Session** — one data-plane connection = one mount of one namespace
  subpath by one client.

## Namespace policy

### Ownership

```
ownership:
  mode: map            # map | passthrough | static
  map:
    - host_uid: uid    # "uid" = the server's invoking uid, resolved at load
      guest_uid: 0
  unmapped: squash     # squash (→ nobody) | hide | passthrough
```

- **map** — translate host uids/gids to guest uids/gids through an explicit
  table. The table is applied in reverse for guest-created files: a guest
  writing as uid 0 produces host files owned by the server operator.
- **passthrough** — host ids shown as-is.
- **static** — everything squashed to one configured id.
- `host_uid: uid` is an enum value meaning "the invoking user's uid",
  resolved once at state load. This keeps configs shareable between users
  with different uids.
- `unmapped` decides the fate of files whose host owner has no map entry:
  squash to nobody, hide the file entirely, or pass the raw id through.

Precise semantics (decided 2026-08-12 after the rule-engine spec review):

- uid and gid tables are separate; each map table must be **injective in
  both directions** — a duplicate host id or duplicate guest id in a table
  is rejected at load (non-invertible maps make reverse mapping
  nondeterministic).
- `unmapped: hide` hides a file when EITHER its uid or its gid is unmapped;
  `squash` replaces only the unmapped component; `passthrough` passes the
  unmapped component through. The squash target is numeric and configurable,
  default 65534 (no NSS lookups anywhere).
- **Reverse application per mode:** map uses the inverse table; passthrough
  is identity; static cannot express a reverse — creates land as the server
  identity and explicit chown/chgrp is EPERM. Reverse-unmapped guest ids:
  creates fall back to the server identity, explicit chown/chgrp is EPERM
  (decided earlier, unchanged).
- **Privilege reality:** applying a reverse-mapped host id other than the
  server's own requires CAP_CHOWN, and the backing filesystem must permit
  it. Without that, creates succeed owned by the server identity — the
  guest's view stays consistent regardless, because presentation
  forward-maps whatever the host actually records. An explicit chown to an
  id the server cannot apply fails with EPERM instead of lying. Multi-uid
  maps are therefore faithful only on a CAP_CHOWN server; the common
  single-user map (`host_uid: uid` ↔ guest 0) is exact everywhere.
- The engine is pure: the server identity (`uid`/`gid`) and the squash ids
  are injected as explicit inputs at construction, never read via syscalls.

### Permissions

- **passthrough** (v1): host permission bits shown as-is, except that a
  read-only graft strips write bits from the *presented* mode (`r-x` in the
  example above).
- Future: mask / synthetic modes.

Presentation is UX only. **Enforcement is server-side, always**: guest root
is untrusted, and a write through a ro graft fails at the server regardless
of what bits were displayed.

## Rule table and resolution

Revised 2026-08-12 after the rule-engine spec review: the earlier
whole-path precedence list (exact > longest prefix > wildcard > nonexistent)
was retracted — two independent probes proved it contradicts the
component-wise API for hidden ancestors and makes wildcards dead below
grafted parents, the opposite of the decided intent: a fallback `*` set to
not shared must have the same effect as adding the files individually.

**Resolution is component-wise, and policy context lives in the parent
directory.** Every directory the walk reaches is in one of two states:
*host-backed* (at or inside a graft; has a host directory behind it) or
*synthesized* (exists only because reachable grafts lie beneath it). The
namespace root starts synthesized. Resolving name `N` under directory `D`:

1. A **literal rule** at `D/N` wins: rw/ro admits `N` with that mode and its
   host target; hidden makes `N` nonexistent.
2. Otherwise a **pattern rule** at `D` whose match covers `N` applies to
   the host child `N` of `D`'s backing: rw/ro admits it with that mode,
   hidden makes it nonexistent. (Step added 2026-08-15 with the
   pattern-rules contract; at most one pattern can cover `N`, because
   overlapping patterns at one level are refused at the table boundary.)
3. Otherwise a **wildcard rule** `D/*` applies to the host child `N` of
   `D`'s backing: rw/ro admits it with that mode, hidden makes it
   nonexistent.
4. Otherwise, if `D` is **host-backed** with effective mode `M`, the child
   exists per the host with inherited mode `M` (a graft is a subtree).
5. Otherwise, if `N` is the next component of some reachable non-hidden
   literal rule beneath `D`, it is a **synthesized directory**.
6. Otherwise `N` does not exist. Empty-by-default falls out here.

Consequences, all deliberate:

- A wildcard is the **per-directory default for entries with no literal
  or pattern rule** — patterns and wildcards both beat subtree
  inheritance (steps 2 and 3 before step 4), which is what makes "graft
  the project rw, default `*` to hidden, admit entries explicitly or by
  family" work. (Renumbered 2026-08-15 when the pattern step landed.)
- Deeper literal rules **override** the subtree they sit in (step 1 before
  step 4), including upgrading (ro parent, rw child) and hiding.
- `hidden` is a first-class mode and terminates the walk; nothing beneath a
  hidden entry is reachable through it.
- Readdir of a host-backed directory enumerates host children and applies
  steps 1–4 per entry, filtering hidden ones (a rule lookup per dirent —
  accepted; that is the product). Readdir of a synthesized directory lists
  exactly its visible immediate children per step 5 plus literal-rule
  children per step 1.
- Mounting a namespace subpath is an ordinary component walk at handshake
  time.

**Table validation (rejected at build, typed errors — increment 4 calls
this boundary):** duplicate rule keys (a literal's path, a wildcard's
directory, a pattern's `(path, match)` pair — amended 2026-08-15: two
patterns may share a path with different matches, subject to the overlap
refusal); non-absolute or non-canonical paths
(`.`/`..` components rejected; separators canonicalized); a rule strictly
beneath a hidden literal rule, or beneath a hidden wildcard or hidden
pattern without an admitting chain (unreachable = dead config —
reachability reuses per-component resolution, so an admitting pattern
keeps a deeper rule alive and hidden patterns cut exactly as hidden
wildcards do; extended 2026-08-15 with the pattern-rules contract); a
wildcard or pattern rule whose directory is not structurally host-backed
(no graft chain admits it — nothing to enumerate or match under a
synthesized directory); a pattern rule carrying a target, a match of only
`*`s, or a match overlapping another pattern at the same level (typed
error naming both rules); rw/ro literal rules missing a host target.
Wildcard, pattern and hidden rules carry **no host target** (their
entries' backing is the parent's backing plus the name; hidden needs
none). A deeper literal rule may omit its target (derived: enclosing
backing plus relative path) or state one (re-target / translation).

Because precedence is structural and duplicates are rejected, resolution is
deterministic and insertion-order-independent by construction.

### Rule engine contract (normative for increment 3)

- The engine is **pure logic**: no syscalls, no I/O, no clock. It lives in
  `voidportd` as its own module tree and owns its domain types; serde and the
  state file bind to it in increment 4, host fds in increment 5. Everything
  environmental — the server identity, the squash ids — is injected at
  construction.
- **Build boundary:** `RuleTable` construction validates per "Table
  validation" above and returns typed errors; increment 4 calls this
  boundary. A built table is immutable; runtime mutation builds a new table
  (deterministic, reloadable state).
- **Component-wise API**, mirroring how the server resolves FUSE-shaped
  lookups. The parent context is a directory state (namespace path +
  host-backed-or-synthesized + effective mode); the engine resolves one
  name under it per the numbered steps above (six since the 2026-08-15
  pattern amendment), yielding *host-backed* (relative
  host target, effective share mode), *synthesized directory*, or
  *nonexistent* (which covers hidden). It also enumerates: the visible
  child set of a synthesized directory (structural), and the per-entry
  decision for each name of a host-backed directory listing (the caller
  supplies the host names; the engine decides admit/mode/hide per entry).
- Lookup components are single names, never containing `/`, `.` or `..`
  (the server rejects those before the engine sees them — stated here so
  the engine may assume it).
- **Ownership mapping** per the "Ownership" section's precise semantics:
  separate injective uid/gid tables, forward and reverse application,
  per-direction unmapped policies, injected server identity and squash ids.
- **Presented permission bits** are a pure function of host mode and
  effective share mode: ro clears the write bits (mask `0o222`) and
  preserves everything else; rw passes through; hidden never surfaces.

### Acceptance criteria — increment 3 (rule engine)

Revised 2026-08-12 after the spec review; the earlier criterion set is
retracted.

1. Rule table supports literal rules (rw/ro with required-or-derived host
   target, hidden with none) and single-level `*` wildcard rules
   (mode-only). Table build enforces every "Table validation" rejection
   with typed errors, each with a test: duplicate paths, non-canonical
   paths, rules shadowed by hidden ancestors, wildcards on
   non-host-backed directories, targetless rw/ro roots.
2. Resolution implements the component-wise steps exactly (five when
   this increment landed; six since the 2026-08-15 pattern amendment);
   each step
   and each documented consequence has a test, including: wildcard beats
   subtree inheritance, literal beats wildcard, deeper literal overrides
   (upgrade and hide), hidden terminating the walk, and descent inside a
   wildcard-admitted directory (inherits the wildcard's mode as subtree
   mode).
3. A property-style test proves insertion-order independence over valid
   tables (permuting rule insertion never changes any decision), and the
   alias case is tested: one host directory grafted at two namespace paths
   with divergent child policy resolves independently per path.
4. The worked example from this document (foo rw, bar ro, file.txt rw,
   `*` hidden) is a test, including the invisibility of `secret/` in both
   lookup and enumeration.
5. Ownership mapping implements map / passthrough / static per the precise
   semantics: separate injective tables (collisions rejected with typed
   errors), forward and reverse application for all three modes, the three
   forward unmapped policies (hide triggering on either id), reverse
   unmapped and static-reverse rules (server identity for creates, EPERM
   for chown), numeric squash ids. All tested.
6. Presented-bits computation is a pure function with tests (ro clears
   exactly `0o222`; rw preserves; synthesized directories present 0555).
7. The engine performs no I/O (no rustix/tokio/fs imports in its modules),
   takes identity inputs by injection, and is deterministic.
8. `./check` passes.

## Graft pinning and host-side security

Grafts are **fd-pinned, not path-pinned**: at graft time the server opens the
host path with `O_PATH` and keeps the fd. Consequences:

- A host-side rename of the grafted tree does not break the graft.
- All resolution below a graft uses `openat2` with
  `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS` from the pinned fd (harmonized
  2026-08-12 with the data-plane contract; the bare-`RESOLVE_BENEATH`
  wording is retracted). A guest-created symlink pointing outside the
  graft (e.g. `→ /etc/shadow`) can never be followed out by the server.
  This is a hard invariant, independent of auth mode (virtiofsd learned
  this the hard way — CVE-class bug otherwise).

Relative host paths in the state file resolve against the state file's
directory, once, at load time; the fd is the truth afterwards.

## Inode identity and node ids

Two distinct identifiers, deliberately separated (disposition 2026-08-12,
below):

- **Inode number (`ino`)** — the guest-visible file identity carried in
  attributes. The server allocates synthetic inos keyed by
  `(host_dev, host_ino)` in a server-global table, so identity is stable
  across sessions and hardlink identity within a graft is preserved. Raw
  host inos are never exposed (they collide across devices).
- **Node id** — the handle a session uses to name a resolved file in wire
  operations. Node ids are **session-scoped** (every session's mount root
  is node id 1, which is what lets one server serve many different roots)
  and are allocated on first lookup, keyed by
  `(host_dev, host_ino, effective_share_mode)` within the session.

Keying node ids by effective mode resolves the alias-policy conflict: when
one host inode is reachable through rules with different share modes
(hardlinks crossing rule boundaries), each mode surfaces as its own node id
with its own enforcement and presented bits, while all aliases share one
`ino`. Enforcement always uses the node's mode — the policy of the path
that admitted it.

Node lifecycle follows FUSE: lookup and readdirplus entries increment a
per-node lookup count; FORGET (carrying a count) decrements it, and the
server drops the node entry at zero. Entry replies carry a `u64`
generation, so a reused node id is distinguishable from its previous life.
Session teardown drops the session's entire node table.

Accepted v1 limitation (2026-08-12, source: fuser 0.18.0 `reply.rs` couples
the FUSE kernel node id to `attr.ino` in entry replies): the v1 FUSE client
presents the session node id as `st_ino`,
so guest `st_ino` equality across hardlink aliases holds only among aliases
with the same effective share mode. The wire protocol carries the true
global `ino` in attributes, so a client without this coupling (a future
kernel client) presents full hardlink identity.

Refinements from the rule-engine spec review (decided 2026-08-12):

- **Directory nodes carry namespace-path context.** Child resolution is
  always evaluated from the parent node's namespace path, and a host
  directory grafted at two namespace paths is two distinct directory nodes
  — required, because their children may differ by policy. Directories
  cannot be hardlinked on the host, so this costs no identity. The
  `(host_dev, host_ino, mode)` node key applies to non-directories.
- **Synthesized directories** have no host backing: their inos come from a
  disjoint synthetic ino space (tag bit), allocated per namespace path,
  stable for the server's lifetime. Their attributes are fixed: directory,
  permission bits 0555 through the presented-bits function, ownership =
  the forward-mapped server identity, nlink 2, timestamps an injected
  constant — decided 2026-08-16 to be **the server's start time**,
  injected once at startup (the original implementation injected
  zero, which presents as 1970 and reads as breakage to users and
  tools; start time keeps the same stability property — the
  skeleton never appears to change under an attribute-caching
  guest — while presenting a plausible clock).
- **Ino allocation** is a monotonic u64, never reused within a server
  lifetime. The synthesized-directory ino table is **server-global, keyed
  by (namespace name, namespace path), and survives snapshot swaps and
  namespace deletion** (decided 2026-08-12 — a snapshot-owned table would
  renumber unchanged directories on every mutation). Accepted v1
  limitations (dated 2026-08-12): inos are not stable across server
  restarts, and host `(dev, ino)` recycling after deletion can alias a
  stale table entry. Both revisit with the kernel-client work.
- **Node ids are monotonic per session and never reused** (decided
  2026-08-12); the wire generation field is reserved and carries 0 in v1.
  The earlier "generations distinguish recycled nodes" framing is
  retracted — with never-reused ids there is nothing to distinguish, and
  the ABI field stays for a future client that does reuse ids.
  (Amended 2026-09-22, release 1.0.1: "never reused" means **never given
  to another file**. The userspace client presents the node id as
  `st_ino`, so an id that changed when the guest kernel forgot a file and
  looked it up again changed the file's inode number under tools that
  identify a file by device and inode; a compiler read one `#pragma once`
  header twice in one compile that way. The node table now remembers the
  id of a forgotten node with its key and its identity and gives that id
  back when the same file is looked up again. A file that was replaced
  in between gets a fresh id, and a retired id is never given out again,
  so there is still nothing for a generation to distinguish. An id comes
  back only where both identities carry a birth time and agree, or where
  neither side has an identity, as for a synthesized directory: on a
  filesystem that reports no birth time a recycled inode number could pass
  for the forgotten file, so there a forgotten file gets a fresh id as it
  did in 1.0.0, and no entry is kept for it, since none could ever be
  used. The price is one small entry per forgotten file that carries a
  birth time, and per forgotten synthesized directory, for the life of
  the session. Where the operator configured `max_nodes`, the
  remembered entries are kept to that same number, the oldest going first,
  and a file whose entry went gets a fresh id at its next lookup; where no
  cap is configured nothing bounds them but the session's end.
  Presenting the host's inode number instead was set aside for this
  release because the FUSE library takes an entry's node id from the inode
  field of its attributes.)

## Policy changes vs. open handles

Same semantics as local filesystems, where permissions are checked at
`open()`:

- Downgrading a graft rw→ro, or removing/hiding it, does **not** affect
  existing open handles — they keep working until close (like an
  unlinked-but-open file).
- **Policy binds at lookup** (refined 2026-08-12): a node's effective mode
  is fixed when the lookup admits it, and an open through that node uses
  the node's mode. "New opens see the new policy" therefore means opens
  that follow a fresh lookup; a client's entry-cache TTL bounds how long a
  stale-mode node can be opened. This is the FUSE-native shape of the
  chmod analogy, and the future invalidation notification tightens the
  bound to immediate.
- Consequence the operator must know: "hidden" does not cut off a guest that
  already holds a handle. A forced-revoke operation (server invalidates
  handles, guest sees EBADF/ESTALE) is a future explicit operator action.

## Coherence and caching

The server passes reads and writes through to the host filesystem and is the
single point of truth; host-side and guest-side concurrent modification is an
expected workload (one writer / many readers across VMs).

v1 client caching is conservative: writethrough, short FUSE attr/entry
timeouts. The protocol reserves a server-initiated notification message
class so cache invalidation pushes can be added later **without a protocol
redesign** — this door must not be welded shut, it is where 9p died and
virtiofs wins.

## Wire protocol (data plane)

A bespoke binary protocol shaped like the FUSE operation set: lookup,
forget, getattr/setattr, open/create/release, read, write, readdirplus,
mkdir, unlink, rmdir, rename, link, symlink, readlink, xattr
get/set/list/remove, flush, fsync, statfs, lock ops.

- **Encoding:** little-endian fixed-layout structs via `zerocopy` derives
  (`FromBytes`/`IntoBytes`/`KnownLayout`/`Immutable`) — compile-time-checked
  reinterpretation, no hand-written encode/decode, no offset arithmetic.
- **Framing:** fixed header `{len, opcode, request_id, flags}` + op-specific
  struct + raw trailing payload (file data, xattr blobs, dirents). Payload
  bytes are never re-serialized — zero-copy on the hot path.
- **Concurrency:** many requests in flight per connection; out-of-order
  replies matched by `request_id`.
- **Reserved:** a message class for server-initiated notifications.
  (Amended 2026-08-15, retracting "unused in v1": the share
  subscription increment activates this class at protocol version 1 —
  opcode addition is not an ABI change per the amended stability rule.)
- **Handshake:** protocol version, namespace name, subpath, auth blob (empty
  for `auth: none`). Server resolves the subpath through the rule table;
  failure → mount error.
- **Sessions/handles:** open files live in a per-session handle table;
  connection drop tears down handles and the mount goes EIO.
- **Transports:** the framing is byte-stream-agnostic — TCP, unix socket,
  vsock behind one interface.

Guest UX:

```
voidport mount voidport://10.0.2.2:1234/@my-namespace/path/to/project /mnt/project
```

### Wire contract (normative for `voidport-proto`)

Revised 2026-08-12 after the spec review (see Dispositions below); the
earlier, looser wording of this section is retracted.

**Crate discipline**

- The crate is `#![no_std]` (core only). Frame and message parsing works over
  caller-provided byte slices and performs no allocation.
- All multi-byte integers on the wire use zerocopy's little-endian byteorder
  types (`U16`/`U32`/`U64`/`I32`/`I64` over `LE`). This makes every wire
  struct alignment-1, so any struct is safely viewable at any offset of a
  byte buffer.
- No hand-written integer encoding/decoding exists. Variable-length payload
  regions (dirent streams, xattr lists) are walked as per-entry fixed
  structs via zerocopy prefix parsing plus explicit length fields — that
  walking logic is expected and is not "manual byte juggling".

**Framing**

- **Frame header** — exactly 16 bytes:

  ```
  len:        U32<LE>   total frame length in bytes, including this header
  opcode:     U16<LE>
  flags:      U16<LE>   bit 0 = RESPONSE; other bits reserved, must be zero
  request_id: U64<LE>
  ```

- **Frame taxonomy.** Requests: RESPONSE clear, request opcode
  (`0x0001..=0x7FFF`). Responses: RESPONSE set, opcode echoing the request.
  Notifications (server→client only): opcode with the top bit set
  (`0x8000..=0xFFFF`), `request_id` 0, RESPONSE clear, no reply expected.
  (Amended 2026-08-15, retracting "v1 defines the notification range
  but no notification messages": the share subscription increment
  defines the first notification messages, still at version 1.)
- **Request ids.** Chosen by the client, echoed verbatim; replies may arrive
  out of order. Id 0 is reserved for notifications and must not be used by a
  request. An id must be unique among the client's outstanding
  response-expecting requests and may be reused once its response has
  arrived. FORGET is the single request that receives no response (FUSE
  semantics); a no-response request's id retires the moment its frame is
  fully accepted in stream order, so it is immediately reusable and
  duplicate-id detection applies only among response-expecting requests
  (clarified 2026-08-12 — the earlier wording left FORGET ids outstanding
  forever).
- **Strict framing.** Every byte of a frame must be accounted for: fixed
  structs plus declared variable-length regions must sum exactly to `len`.
  Trailing unaccounted bytes, overlapping or payload-exceeding declared
  lengths, and arithmetic overflow in length sums are framing errors.
- **Opcode registry.** Numeric opcode values are explicitly assigned,
  stable, documented constants; the crate exposes a total
  known/unknown-opcode classification (enum with fallible conversion).
- **ABI stability rule.** Any change to an existing opcode's assignment,
  struct layout, or field meaning requires a `PROTOCOL_VERSION` bump.
  (Amended 2026-08-15, retracting the original blanket "any change to an
  opcode assignment": **adding** a request opcode in the unassigned
  range, or activating a reserved notification opcode, with every
  existing message untouched, is not an ABI change and does not bump
  the version — the unknown-opcode `ENOSYS` answer is the discovery
  mechanism, and older clients never see the new frames. The blanket
  form made the subscription increment's byte-compatibility criterion
  self-contradictory.) (Amended 2026-08-17, second additive case, for
  the privileged-bits increment: a **reserved must-be-zero flags
  field acquiring its first flag** is likewise additive when the zero
  value preserves the old behavior exactly — reserved flag space is
  the wire's own forward-compatibility mechanism, an elder peer
  ignores the bit per the flags rule, and every existing frame is
  byte-identical. The skew posture such a flag creates is stated at
  the feature that adds it, never hidden.) Golden byte-vector tests
  pin the ABI of every message type.

**Requests and responses**

- **Request head.** Every request body begins with a fixed 24-byte head:

  ```
  node_id:  U64<LE>   the node the operation targets (0 where meaningless)
  uid:      U32<LE>   guest caller uid
  gid:      U32<LE>   guest caller gid
  pid:      U32<LE>   guest caller pid (informational)
  reserved: U32<LE>   must be zero
  ```

  Ownership mapping and server-side permission enforcement key on the
  per-request caller identity — one mount serves many guest processes, so
  identity cannot ride the handshake.
- **Responses:** the body begins with `status: I32<LE>` — 0 for success, a
  negated Linux errno otherwise. The op-specific response struct follows
  only when status is 0; an error response carries nothing after status.
- **Variable-length data** (names, paths, symlink targets, xattr blobs, file
  data, dirents) rides in the trailing payload, described by explicit length
  fields in the fixed struct. Byte strings, no NUL termination on the wire.
- **Readdirplus framing:** the response payload is a sequence of entries,
  each a fixed per-entry struct (ino, generation, next-cookie, type, name
  length, attributes) followed by the name bytes; the next-cookie resumes
  enumeration.
- **Setattr** carries a validity bitmask naming which fields apply.
- **Attributes** carry at least: ino, size, blocks, mode, nlink, uid, gid,
  rdev, blksize, and atime/mtime/ctime as `i64` seconds + `u32` nanoseconds.
- **Node ids and handles:** operations name files by session-scoped `u64`
  node ids (see "Inode identity and node ids"); open files are named by
  `u64` handles returned from open/create.
- Per-op request/response struct fields follow FUSE semantics adapted to
  this framing; the crate's rustdoc is the field-level reference, and the
  golden vectors are the ABI lock.

**Session state machine**

- **Handshake:** `Hello` must be the first frame on a connection. It carries
  the protocol version, client flags, and namespace/subpath/auth-blob
  lengths, with the three variable fields in the payload. `HelloReply`
  carries status, the accepted protocol version, server flags,
  `max_frame_len`, and the root node id.
- **Version rule (v1):** the server accepts exactly version 1; a mismatch
  yields a handshake error response, then the server closes.
- **Auth rule:** under `auth.mode: none` — the only v1 mode — a nonempty
  auth blob is a handshake error (EINVAL).
- **Flags fields** (client flags, server flags): must be zero on send;
  unknown bits are ignored on receive (future negotiation space).
- **Size bounds.** Pre-handshake, the server accepts a `Hello` frame of at
  most 4096 bytes (fixed constant); violation closes the connection. Post-
  handshake, `max_frame_len` (announced by the server) bounds the TOTAL
  frame length, header included, in BOTH directions.
- **Protocol errors, two classes.** *Framing errors* — malformed length,
  strict-framing violation, reserved flag bits set, oversized frame,
  request id 0 or a duplicate outstanding id, any frame before handshake
  completion, a repeated Hello, a RESPONSE-flagged frame arriving at the
  server — poison the byte stream; the server closes the connection
  (handles and the node table tear down as on disconnect). *Semantic
  errors* — a well-framed request with an unknown opcode (ENOSYS) or
  invalid arguments — get an error response and the connection lives on;
  this is what makes future protocol extension non-fatal to old servers.

### Acceptance criteria — increment 2 (`voidport-proto`)

Revised 2026-08-12 after the spec review; the earlier criterion set is
retracted.

1. `voidport-proto` compiles as `#![no_std]` and contains no `unsafe` code
   (the workspace denies it).
2. The frame header is exactly 16 bytes with the layout above; the request
   head is exactly 24 bytes; tests assert sizes and field offsets against
   fixed byte vectors.
3. Every wire struct derives zerocopy `FromBytes`/`IntoBytes`/`KnownLayout`/
   `Immutable` and uses little-endian byteorder integer types exclusively;
   no hand-written integer encoding/decoding exists in the crate
   (variable-length regions are walked via zerocopy prefix parsing per the
   contract).
4. The opcode set covers: lookup, forget, getattr, setattr, open, create,
   release, read, write, readdirplus, mkdir, unlink, rmdir, rename, link,
   symlink, readlink, getxattr, setxattr, listxattr, removexattr, flush,
   fsync, statfs, and file locking (getlk/setlk), plus the handshake — each
   with request/response struct types (forget has no response). Numeric
   opcode values are explicitly assigned documented constants, and the
   crate exposes a fallible opcode classification (known vs unknown).
5. The notification opcode range (`0x8000..=0xFFFF`) is defined and
   distinguishable from requests without parsing op-specific bodies; no
   notification message types existed when this increment landed (a
   true record then; amended 2026-08-15 — the share subscription
   increment adds the first ones, at version 1).
6. Handshake messages carry protocol version, namespace, subpath, and auth
   blob per the contract above, including `max_frame_len` and the root node
   id in `HelloReply`.
7. Response status is errno-style `I32<LE>`, 0 = success; an error response
   carries nothing after status, and a test enforces this.
8. Golden byte-vector tests pin the exact encoding of EVERY message type
   (encode → assert exact bytes → decode → equality), not only the frame
   header. `cargo test -p voidport-proto` passes.
9. Rejection tests cover: truncated frames, `len` disagreeing with the
   buffer, unknown opcodes, reserved flag bits set, request id 0 on a
   request, strict-framing violations (declared lengths exceeding the
   payload, overlapping, overflowing, or leaving trailing bytes), and
   error responses carrying a body.
10. Every public item carries rustdoc (`missing_docs` denied in the crate).
11. Frame parsing never panics on arbitrary input bytes (malformed input
    yields typed errors; fuzz-style test over random/truncated buffers).

### Dispositions

- 2026-08-13 (field use, first real workload; corrected the same
  evening — the original three dispositions here were revised, and this
  entry carries the corrected decisions) — An AOSP source tree was
  driven through the mount as a build preparation:
  1. **The quickstart replicates the host hierarchy.** The seed grafts
     at the directory's absolute host path as the namespace path, and
     the printed URL mounts the namespace root; repeated shares compose
     without flattening. (This corrects an interim fix that had pointed
     the URL at a `/<basename>` subtree; replicating the host holds.)
  2. **The ENFILE posture is not settled design.** The
     node-cap-answers-ENFILE choice was an interim disposition taken
     during the increment-5 review, not a settled decision, and is open
     to revision. The bar: the workload works on the host filesystem and
     had never shown this error there, so it must simply work through
     the mount at source-tree scale. Owed: the
     investigation proving which limit fired (synthetic large tree),
     defaults and a startup RLIMIT_NOFILE raise sized for a source-tree
     working set, sizing documentation — and, if the caps-and-limits
     levers cannot honestly carry the scale, revision of the refusal
     itself (eviction, or on-demand reopening instead of a pinned
     descriptor per directory node; that lifecycle question sits in the
     optimization pass's scope).
  3. **The unmapped-callback warnings stay, and the gaps get closed
     and not silenced away**: the two warnings the workload produced did
     not flood anything — they surfaced work. poll is implemented with
     always-ready semantics; the observed ioctl command is investigated
     and decided on evidence.

- 2026-08-13 (seeded-launch review) — The patch surfaced two items
  decided here and folded into the section in place: control-socket precedence
  returns to flag-first (the drafted state-first ordering was an
  accident of wording, not a decision), and `share` seeds a per-user
  control socket beside the state file when neither flag nor document
  names one, with the ctl hint printed in the summary. Ratified as
  built: daemon tracing on stderr so stdout is exactly the copy-paste
  block; the launch summary carrying its own copies of the URL encode
  sets (the client crate cannot be a server dependency; drift is caught
  by the quickstart test parsing the printed URL with the real client
  parser).

### Acceptance criteria — optimization pass (decided 2026-08-13/14)

The scope is the hot-path profiling disposition plus the field-use
fd-lifecycle question; the attribution behind every number is summarized
in PERFORMANCE.md (raw data kept out of tree).

1. Stream splitting is lock-free on both ends of the connection (the
   tokio split() mutex leaves the hot path), and steady-state framing
   costs one read syscall per frame on both ends (buffered coalescing
   of header and body).
2. The per-connection ceiling is re-measured with voidport-bench under
   the same concurrent load as the attribution; the measured change is
   reported honestly against the predicted +60%/+110% bands.
3. A listing pins and stats each entry once (attributes as-of
   materialization, inside the attr-TTL coherence envelope), and
   readdirplus batches size to the frame bound — the compensating-
   FORGET accounting must hold for refused entries, proven under a
   deliberately small kernel buffer.
4. The visibility check may use statx only where the name is a single
   component resolved NOFOLLOW against the pinned parent; the
   containment contract (resolution against pinned ancestors,
   RESOLVE_BENEATH discipline) is explicitly re-verified by review.
5. Intern batching and admission-allocation cuts land; the readdir-loop
   scenario's measured improvement is reported against the predicted
   ~40% band.
6. The descriptor-per-directory-node lifecycle is evaluated WITH
   measurement (the field-use baseline: descriptors track nodes 1:1;
   a source tree holds ~320k). A lifecycle change lands only if the
   containment invariants provably hold through it; otherwise the
   deliverable is a written recommendation with the measured
   trade-off, not a change. (Field data added 2026-08-14,
   informational: a real AOSP walk with a parallel module finder hit
   the handle cap at 16,384 concurrently-open handles, and all cap
   defaults have since been decided unbounded — so the OS descriptor
   table becomes the only bound, and the evaluation's question
   sharpens to whether descriptors-track-nodes survives a multi-
   million-entry working set or on-demand reopening is required.
   Answered 2026-08-15: it does not survive — an AOSP walk exhausted
   the table in the field. On-demand reopening is required and decided
   in the "Node descriptor budget" section.)
7. The wire contract is unchanged; batch sizing is client-internal.
8. No behavioral regressions: the full workspace suite passes and the
   e2e suites run on real mounts.
9. docs/PERFORMANCE.md gains a dated before/after section from fresh
   matrix runs of the affected scenarios.
10. Both gates green: ./check and nix build path:. .

### Dispositions (continued)

- 2026-08-14 (direct I/O option), REWORKED 2026-08-15 — the cache
  bypass is split by operation type. The original shape (bare
  FOPEN_DIRECT_IO, mmap unavailable) is RETRACTED because mmap must
  keep working in every configuration, including behind an opt-in
  option. The reworked decision: the client gains `--direct-io`,
  off by default; when on, every open and create reply sets
  FOPEN_DIRECT_IO, and the mount's INIT handshake negotiates the
  **FUSE_DIRECT_IO_ALLOW_MMAP capability** (bit 36, kernel 6.7+) —
  corrected 2026-08-15 at landing: the earlier wording named a
  per-open FOPEN flag that does not exist; the kernel expresses the
  mmap allowance as an INIT capability negotiated once, and the
  behavior is exactly as decided. This is the by-operation split the
  decision requires: read and write bypass the guest page cache — the
  N-VMs-share-one-host-copy memory win — while mmap keeps working,
  with the kernel caching pages only for actually-mapped ranges, so
  exec and shared-mapping coordination (the SQLite WAL mechanism)
  are preserved. Directory opens are excluded from the flag:
  listings never ride the page cache. Attr/entry TTL metadata caching
  is untouched. Where the guest kernel does not offer ALLOW_MMAP the
  mount falls back to NORMAL caching — no direct I/O at all, the RAM
  cost accepted, with a logged notice — never to mmap-less behavior
  (amended 2026-08-15: where ALLOW_MMAP is unavailable the mount
  falls back to normal caching instead of refusing, accepting the
  RAM cost — this retracts the earlier refuse-the-mount fallback).
  Breaking mmap is excluded absolutely in every configuration.
  Consequences stated in the contract when it lands: unmapped data
  reads become wire-immediate (coherence tightens to per-read
  freshness; re-read throughput drops to wire speed, measured and
  recorded in PERFORMANCE.md), mapped ranges keep page-cache
  coherence semantics, and the increment verifies exec-from-mount
  and WAL-on-mount under the option as acceptance criteria.
  Implementation is next after pattern rules per the 2026-08-15
  priority decision (RAM savings + vsock).

- 2026-08-14 (async lock waits + torture v1) — The waits-are-async
  principle lands in the lock path: a blocking SETLKW no longer parks a
  blocking-pool thread. The server answers the wire request only when
  the lock is acquired (or the connection dies, which cancels the wait
  as the existing contract rules), but the waiting is a future — a
  non-blocking F_OFD_SETLK attempt retried with capped async backoff
  (starting small, e.g. 1-10 ms, capped low enough that acquisition
  latency after a release stays unobtrusive). Guest-visible semantics
  are unchanged; the in-flight accounting treats a parked lock wait as
  it always did. Fairness stays best-effort (retry order is not a
  queue), which POSIX permits and the doc states. With this, the
  torture harness's lock-storm scenario becomes runnable: thousands of
  stacked waiters must hold memory, not threads. Torture v1 ships
  beside it: a long-running load generator over every operation class
  with continuously asserted invariants (throughput never collapses,
  per-class latency ceilings outside break-away, fd/node/memory
  bounded relative to working set, clean shutdown), intensity and
  duration as flags with defaults sized for the reference environment,
  and a minutes-bounded smoke variant in the regular suite.

- 2026-08-14 (reconnect boundary) — The increment landed (both gates
  verified independently); decisions on the build's flagged
  interpretations, all ratified as built. (Corrected same day by the
  boundary patch: an earlier sentence here recorded flush and fsync as
  classified idempotent, but the code as built classifies both
  Replay::Once — exactly what the normative list requires — so that
  sentence misdescribed the tree; the code was right all along and is
  unchanged.) A zero stall
  window degrades immediately with the probe still running (the
  uniform state-machine reading — Degraded is DEFINED as immediate
  errors plus a background probe, and never-recover would contradict
  the resilience posture); the API unmount does not cancel recovery
  first (an EBUSY unmount must leave the mount live and usable; the
  signalled teardown, which exits regardless, does cancel first);
  release across the gap stays moot; the cross-process id-collision
  bound rests on the millisecond epoch and is an accepted v1
  limitation recorded at the allocator (the persisted-epoch
  alternative named there); the e2e suites' process-spawning harness
  deviation from reuse-voidportd::testing is ratified (an in-process
  server cannot be SIGKILLed). The 25 open should-fix and nit findings
  plus the two unverified fixes go to the boundary patch.

- 2026-08-14 (reconnect review) — Independent review, every finding
  accepted; the resilience contract and its criteria reworked
  in place. The blockers: per-session id counters make a stale
  kernel-held id alias a different file after a restart (wrong-file
  reads demonstrated end to end against a conformant server) — ids are
  now generation-disjoint across sessions and restarts with root id 1
  the single exemption; and the universal no-error-within-window
  guarantee was jointly impossible with stateless session replacement —
  criterion 1 now covers path-based operations (which the
  kernel-verified ESTALE-retry healing genuinely carries) while
  identifier-bound operations surface their stale errnos and recover on
  reopen. Also decided in: the single-flight reconnect task with
  connection generations, one monotonic deadline over dial and hello
  with cancellable bounded attempts (a wedged accepting peer was probed
  holding the current client past 6 s), replay linearization points
  with the per-class table collapsed by id disjointness, lock loss as
  EBADF with no client memory, teardown cancelling in-flight attempts,
  configuration-refused hellos keeping Degraded with the probe running,
  the deterministic reply-discarding relay for the double-apply proof,
  and auto-unmount downgraded from guaranteed default to opportunistic
  (fuser refuses AutoUnmount under the owner-only ACL and needs
  fusermount3; the honest split is signal teardown as the primary
  mechanism and umount-recovery as the SIGKILL story).

- 2026-08-14 (optimization boundary) — Decisions on the pass's routed
  items and the adversarial review's probe-verified findings:
  1. **The client's held readdirplus surplus is TTL-bounded.** An
     adversarial probe proved surplus entries deliver attributes frozen
     at batch-fetch time — the same staleness the pass removed
     server-side, reintroduced one layer up, outside the advertised
     coherence envelope. Decided: an entry may be served from held
     surplus only within the attr TTL of its fetch; older surplus is
     dropped with its compensating FORGETs and refetched. Fast
     consumers (build systems) keep the round-trip win; slow walkers
     pay a refetch instead of reading stale attributes.
  2. **Host syscalls leave the node-table guard.** The batched
     admission holds the session's node-table mutex across up to
     hundreds of pins and stats, which the robustness mandate's
     no-starvation posture cannot accept (every other operation of the
     session queues behind a listing batch). Restructure to syscalls
     outside, intern under a short guard — the batching win must come
     from fewer acquisitions, not longer ones.
  3. **The frame readers consolidate onto tokio's BufReader** (the
     alternatives review's proposal): both hand-rolled readers and their
     duplicated tests are replaced by BufReader-wrapped read halves
     with the pre-existing read_frame shape; the one-read-per-frame
     property is re-proven by strace after the change, since that
     measurement is the criterion the readers existed for.
  4. The compensating-FORGET accounting must additionally be proven
     against a real mount with a listing larger than one kernel reply
     buffer (the seam-level proof stands, and the criterion's words
     name the kernel); the unartifacted 2.42-vs-2.34 µs number behind
     the keep-the-pin recommendation is reproduced with a committed
     harness or struck (the other two legs carry the recommendation
     either way).
  5. The pass itself is ratified as landed: lock-free splits,
     buffered framing (2.09 → ~0.9 reads/frame, strace-proven),
     +24.6% on the per-connection ceiling (honestly short of the
     predicted bands), +240% on readdir-loop, statx visibility with
     containment re-verified, and the keep-the-pin recommendation
     with its measured legs. The descriptor-budget-times-sessions
     sizing note dissolves into the unbounded-caps patch, where
     RLIMIT rises to the OS maximum regardless of session count.

- 2026-08-14 (TUI boundary patch) — All review findings closed, both
  gates green, and the Gates decision's owed sandbox defects are dead —
  with their real causes, which were not the assumed /tmp writability:
  a process-global umask window in the socket bind path left
  concurrently-created directories unreadable to the sandbox uid;
  portable-pty chdirs to a $HOME the sandbox lacks; and the sandbox's
  empty RUST_LOG parsed as an enable-nothing filter, silently emptying
  the daemon log (a pre-existing hole; both binaries now treat empty as
  unset). Ratified as built: FromStr + UnknownMode on the mode types in
  voidport-control (the honest-forms fix needs them), the public
  voidport_tui::harness module (one of the two sanctioned consolidation
  shapes), and the dev-only voidport-pty workspace member with vt100.

- 2026-08-13 (TUI spec review) — Independent review of the TUI
  contract before build; every finding accepted, the contract reworked
  in place. The blocker proved by probe: the Overview
  screen required listener data while the contract simultaneously
  forbade new protocol surface and state-file reads — unsatisfiable in
  attach mode. Resolved by retracting the absolute fence: no new
  mutation operations, but server-info gains a read-only bound-listeners
  field (one workspace ships both binaries, so the reply-shape change
  has no cross-version concern in v1). Also decided in: the full terminal
  lifecycle (raw-mode Ctrl-C/Ctrl-Z/SIGTERM semantics, resize,
  too-small placeholder), the serve-and-present failure supervisor,
  client timeouts + capped-backoff reconnection with full re-fetch,
  freshness for every read view (1 s tick + focus), reducer-level
  mutation correlation, list scroll/filter, Help as the canonical
  binding list, explicit per-field protocol coverage, tracing-to-file
  in TUI modes (a log-viewer screen deliberately deferred), the client
  behind a `client` cargo feature in `voidport-control` (keeping the
  crate pure types by default, and consolidating the testing module's
  duplicate client), `portable-pty` as a dev-dependency for
  terminal-lifecycle proofs, and the criterion-4 FUSE gate aligned with
  the sanctioned-skip rule. Criteria revised to twelve.

- 2026-08-13 (hot-path profiling) — The instrumented attribution
  (raw data kept out of tree) settled where the
  measured costs live, and rules the optimization scope:
  1. The per-connection ceiling is the serial one-frame-at-a-time read
     loop at each end: ~13.9 µs/frame, exactly two read syscalls per
     frame, with tokio's split() placing both stream halves behind one
     mutex. **Approved, no decision needed:** lock-free stream splitting
     and one-read-per-frame buffering on both ends.
  2. Readdir's 16.6 µs/entry is server-side host work paid twice (every
     entry pinned and stat'd once in materialization and again in
     readdirplus admission) plus 32 round trips per 1000-entry listing
     from the client's 4 KiB batch bound. **Approved with their
     invariants named:** single stat per entry per listing —
     *(revised 2026-08-14: the original "attributes as-of
     materialization" shape was refuted by measurement — a listing
     taken while a writer extends a file made the next read return the
     stale length, deterministically — so the decided shape is
     identity-as-of-materialization, attributes-as-of-the-reply: the
     materialization stat names the entry's node, the reply reads
     fresh attributes, and what a repeated listing skips is the pin,
     which measurement showed was the cost that mattered)*; larger
     readdirplus batches up to the frame bound (the
     compensating-FORGET accounting must hold for refused entries);
     statx for the visibility check only where the name is a single
     component resolved NOFOLLOW against the pinned parent (the
     containment invariant is that resolution shape, not the O_PATH pin
     itself); intern batching and admission-allocation cuts.
  3. **Deferred:** moving metadata operations off spawn_blocking. It
     shaves per-op latency but does not lift the ceiling, and on a slow
     host filesystem a blocking metadata syscall on the runtime would
     stall unrelated connections — the contract's blocking-pool rule
     stands until measurement on a non-tmpfs backing store says
     otherwise.
  4. The client-side readdir hypothesis recorded in PERFORMANCE.md is
     refuted by measurement (~1% of the cost); the optimization pass
     updates that section with the attribution when it lands.

- 2026-08-13 (increment-6 cleanup) — The cleanup patch closed all sixteen
  queued findings; three fixes were breadth beyond the written contract
  and are ratified here, folded into the Connection paragraph in place:
  the client refuses a handshake whose reply answers another request id,
  whose frame bound is below 4096, or whose root node id is not 1.
  Also ratified: the split-TTL entry replies (fuser's create and
  readdirplus replies have no split form in 0.18 — documented at the
  sites); connection death by shutting down a duplicated socket
  descriptor so teardown never queues behind an in-flight write; the
  shared `voidportd::testing` module (doc-hidden) consolidating the
  three test-suite server runners into one, with per-suite host trees
  kept separate deliberately; and the removal of two public client
  methods nothing called (`Client::endpoint`,
  `MountUrl::subpath_display`).

- 2026-08-13 (increment-6 review) — Decisions on the build's routed
  items; the review closed in one round with no
  must-fix finding and every criterion PASS.
  1. **Ratified as built:** the `rustix` workspace features `mount`
     (client umount) and `thread` (per-thread credentials in the
     non-root e2e case); `percent-encoding` (already decided under
     "dependency scope"); fuser 0.18's `batch_forget` left at its
     default, which expands a batch into one forget per element —
     exactly the required mapping — because the override's parameter type
     is not exported by the library.
  2. **Criterion readings ratified and folded into the criteria in
     place:** mmap-by-exec for criterion 3; bounded EBUSY return for the
     parked-lock unmount in criterion 11 (the descriptor the lock holds
     makes completion physically impossible in v1); client-level
     exercise of the plain-readdir compensations for criterion 13. The
     unmount teardown paragraph now states that the parked-setlk clause
     is reachable only through connection death, and pins the
     runtime-release-after-join order.
  3. **Routed to the hardening roadmap (#7):** client signal handling,
     FUSE INTERRUPT, and the transient-EBUSY unmount UX.
  4. The stale "four crates" table and the missing dependency rows
     (`url`, `percent-encoding`, `libc`) in the Implementation section
     are corrected — both were flagged in review as passing observations.

- 2026-08-13 (increment-6 review, dependency scope) — Review flagged a
  contradiction between the stack decision's "rest is hand-rolled"
  and the client contract's "parsed with the `url` crate" (plus the
  `percent-encoding` crate the implementation uses with it). Decided: the
  two directives compose; they do not conflict. The standing
  directive — no manual parsers anywhere; solved formats use battle-tested
  libraries — covers exactly this case, and URL parsing is a solved
  format. "Rest is hand-rolled" therefore scopes to the system's own
  machinery (framing, rule engine, state, server, client logic), not to
  refusing a vetted parsing utility. `url` and `percent-encoding` are
  ratified as client dependencies; the appendix entry carries a pointer to
  this disposition.

- 2026-08-13 (increment-6 spec review) — Independent review of the FUSE
  client contract before build; all eighteen findings were
  accepted (none refuted) and the contract plus criteria were reworked
  in place. The load-bearing ones, most live-proven on the reference
  environment (kernel 6.18, fuser 0.18):
  1. fuser's default init flags omit `FUSE_DO_READDIRPLUS`,
     `FUSE_POSIX_LOCKS`, and `FUSE_AUTO_INVAL_DATA`; without them the
     kernel sends plain readdir (for which it does no nlookup
     accounting — composing it with wire readdirplus leaks one server
     node per listed entry), satisfies record locks guest-locally (the
     server never sees getlk/setlk, so cross-mount conflicts are
     unobservable), and never invalidates cached pages on a same-size
     overwrite (a held-open descriptor reads stale data indefinitely,
     not TTL-bounded). All three are now negotiated in `init`.
  2. `FUSE_FLOCK_LOCKS` is excluded for v1: fuser 0.18 drops the
     kernel's lk_flags so the flock-vs-record distinction cannot reach
     the client, and the wire `FileLock` has no lock-namespace field —
     negotiating it was live-proven to make a guest flock(2) wrongly
     conflict with a guest record lock. flock stays guest-local per
     mount; a wire lk_flags field is recorded as a post-v1 candidate.
  3. The directory-callback mapping (opendir/releasedir/fsyncdir onto
     generic Open/Release/Fsync), the client-side lookup-count and
     FORGET accounting (including compensating FORGETs for entries the
     kernel never received), response-side protocol faults poisoning
     the connection like transport loss, the no-blocking-dispatch
     concurrency rule, the unmount teardown order, the pinned URL
     grammar (tcp port required; the unix socket path is the
     percent-encoded authority component), `--read-only` as
     `MountOption::RO`, the ENOSYS/EPERM matrix for unmapped
     callbacks, and the no-skip e2e gate where FUSE is usable are all
     specified where the contract was silent.
  4. Probed clean, kept as written: generation 0 (kernel compares for
     equality only), listxattr guest-size composition, lock owner
     passthrough (with the note that a getlk conflict pid surfaces as
     0 in the guest), EIO-until-unmount after transport death, mmap
     read under writethrough, both URL forms parsing with the `url`
     crate. Criterion 4 was reworded per the default_permissions
     reality: non-root callers are refused by the guest kernel's
     presented-bits check and never reach the server.

- 2026-08-13 (increment-5 review) — Decisions on the build's routed
  items:
  1. **The OFD unsafe island is ratified.** rustix 1.1 exposes no
     F_OFD_* commands, and classic POSIX locks are process-owned, so the
     decided per-lock-owner semantics are unreachable without raw fcntl.
     Exactly one module (`voidportd::host::lock`) carries a documented
     `allow(unsafe_code)` for three libc fcntl calls; the workspace
     denial stands everywhere else. libc joins the dependency table for
     this single purpose.
  2. The commented example state file keeps operator-realistic paths and
     is asserted by parse + per-namespace build + round trip, not full
     load — graft pinning at build makes a full load of foreign paths
     impossible by design, and a relocatable example would misrepresent
     real configs. Increment-4 criterion 2's "example loads" is read
     accordingly.
  3. The public-API additions to the rule engine, state layer, registry,
     proto (DuplicateRequestId), and control protocol (session-list) are
     ratified — the contract required each, and each was reported.
  4. **Entry-modifying enforcement** is normative as built: parent
     writable (else EROFS), the name must resolve to an admitted entry
     (else EACCES — hidden names cannot be created or removed), the
     entry's own mode writable (else EROFS), and a re-targeted graft
     root is not creatable/removable through its enclosing directory
     (EPERM). `link` enforces BOTH ends: read-only binds to the inode,
     not the path that reached it.
  5. **Handshake errnos** are normative as built: version mismatch
     EPROTO, nonempty auth EINVAL, unknown namespace ENOENT, malformed
     subpath EINVAL, unresolvable subpath ENOENT, non-directory root
     ENOTDIR, symlink component ELOOP, session cap EMFILE; empty subpath
     is the namespace root.
  6. Ratified: whole-file unlock drops that lock owner's description;
     create/mkdir apply the guest's requested bits explicitly after
     creation (the server's umask must not leak into guest semantics)
     with O_EXCL preventing re-owning existing entries; caps are read at
     startup; TCP_NODELAY is set on data connections (a delayed-ACK
     stall found by the suite).

- 2026-08-13 (increment-5 adversarial review) — Adversarial review found
  two real defects the other reviews missed, both probe-verified; accepted
  as must-fix:
  1. **`link` follows a symlink target out of the graft.** `link`
     hardlinks the target through `/proc/self/fd/N` with
     `AT_SYMLINK_FOLLOW`, which for an admitted symlink node resolves to
     the link's target — so a guest can `symlink` to a path outside the
     graft, `lookup` it, and `link` the outside inode into a writable
     graft. This breaks the "a guest symlink is never followed out"
     containment invariant. Decision: `link` MUST reject a target whose
     node kind is not a regular file or directory (symlinks and specials
     cannot be hardlink targets through this path), in addition to the
     existing both-ends mode enforcement.
  2. **Directory nodes freeze policy context.** The per-lookup registry
     consultation fixed session-level staleness, but a directory node
     still caches its `DirState` (backing + mode), so a directory-level
     graft downgrade / removal / re-target — the operator's canonical
     "cut them off" action — never reaches a mounted session: children
     inherit the frozen mode. This defeats the fresh-lookup decision for
     the case that matters most. Decision: child resolution under a
     host-backed directory node must derive the parent's effective mode
     and backing from the CURRENT snapshot (re-resolve the directory's
     namespace path per operation), not from state frozen at the
     directory node's creation; a directory whose backing is gone or
     re-targeted resolves accordingly. Node identity keying is unchanged;
     only the policy context consulted per child lookup is made live.

- 2026-08-12 (increment-5 blocker) — Review stopped the build on a
  genuine contradiction between authority layers: the settled decision
  (fresh lookups see new policy; open handles keep
  working) versus this document's session-lifecycle text telling sessions
  to keep the handshake-time namespace snapshot for their lifetime, which
  would have made runtime rule edits invisible to mounted guests — the
  opposite of the product's central feature. The decision wins: sessions
  consult the registry's current snapshot per path-resolving operation;
  the handshake snapshot serves only as the deletion tombstone; node
  modes still bind at their admitting lookup. The frozen wording is
  retracted in place here and in the increment-4 lifecycle bullet.

- 2026-08-12 (increment-5 spec review) — Independent review ran kernel
  probes against 6.18. Real findings, all taken into the contract above:
  symlink lookup pins with O_NOFOLLOW and readlink uses the empty-path
  readlinkat form (following is the client kernel's job); OFD locks need
  per-(handle, wire-owner) descriptions because one description's locks
  coalesce; FORGET ids retire on frame acceptance (wire contract
  clarified); resource caps pinned (read-pause backpressure plus
  node/handle/listing/session caps); the unix data socket adopts the
  control-socket bind contract with all-or-nothing listener startup;
  session inspection added to increment 5 (it was promised and specified
  nowhere); the /proc reopen is exempt from the magic-link discipline;
  the synthesized-ino table is server-global and survives snapshot swaps;
  node ids are monotonic per session with the generation field reserved
  at 0. One claimed blocker was REFUTED by direct probe (2026-08-12):
  /proc/self/fd reopen of an O_PATH fd preserves the
  pinned inode through rename-over and works after unlink; the identity
  hole it alleged does not exist, and a second round of probes concurs.

- 2026-08-12 (increment-4 review) — Decisions on the review's routed
  items, ratifying implementation decisions:
  1. The single-instance lock is a sidecar at the canonicalized state
     path (contract reworded in place above).
  2. Relative-path resolution against the state file's directory applies
     to rule **host targets only**; other configured paths (the control
     socket) resolve as the process sees them.
  3. The persist **commit point is the rename**: a directory-fsync
     failure after a successful rename logs a durability warning and the
     mutation still publishes and reports success — failing an operation
     that is already on disk would misreport reality. Failures before the
     rename publish nothing, as decided.
  4. The listener array is spelled `[[server.listeners]]` (nested under
     the server settings table); the bare `[[listener]]` wording above is
     retracted.
  5. The control-socket bind contract includes a sidecar claim
     (`<socket>.lock`) taken before reclaiming a stale socket, so two
     daemons cannot race the reclaim.
  6. `server info` returns version, state file path, and control socket
     path as configured (no absolute-path promise).
  7. The workspace is five crates: `voidport-control` (typed operator
     protocol and source-form policy types, shared by TOML and JSON) is
     ratified as a first-class crate alongside the original four.

- 2026-08-12 (increment-4 spec review) — Independent review found three
  blockers (no JSON implementation in the dependency set; no persistent
  source-of-truth model, so the first mutation would have baked sentinels
  and relative paths into machine-specific values; unsafe validate-swap-
  persist ordering with undefined concurrency) plus schema, durability,
  socket-lifecycle, and namespace-keyspace gaps. Rulings, all reflected
  in the revised contract above: the source/runtime split with persist
  emitting the source form verbatim; serde_json added to the dependency
  set and the `voidport-control` protocol crate introduced; mutations
  linearized with persist-before-swap (no rollback path can exist);
  deny_unknown_fields everywhere with per-mode ownership shapes and the
  static ids the schema previously could not express; durable persist
  (directory fsync, preserved mode) with a single-instance lock; the
  socket bind/reclaim/unlink contract; namespace-name validation; the
  registry/snapshot lifecycle for deletion; a bounded request line; the
  bare-`*` accepted limitation; "modify rule" retracted in favor of
  remove + add.

- 2026-08-12 (increment-3 review) — Three decisions on tensions the
  review and the adversarial pass surfaced:
  1. **Readdir must agree with lookup.** Readdir of a host-backed
     directory is the union of the host children (steps 1–3 applied per
     entry) and that directory's literal-rule children whose names are
     absent from the host listing (re-targeted grafts). The earlier
     sentence enumerating only host children is retracted; a re-targeted
     graft must appear in both `stat` and `ls`.
  2. **Reverse-unmapped fallback is per component**, mirroring forward
     squash: a create with a mapped guest uid and an unmapped guest gid
     lands with the mapped host uid and the server gid. The
     whole-identity reading is retracted.
  3. **A guest id used in a map table must not collide with the squash
     id**; table construction rejects it. Otherwise a mapped host owner
     and every unmapped owner present identically, re-creating the NFS
     ambiguity this project exists to kill.

- 2026-08-12 (increment-3 spec review) — Independent review proved the
  whole-path precedence list jointly unsatisfiable with the component-wise
  API (hidden ancestors, wildcards below grafted parents, alias
  directories) and found the ownership algebra underdefined (non-injective
  maps, static/passthrough reverse, privilege reality, purity of identity
  inputs) plus missing identity contracts (synthesized directories, ino
  allocation). Rulings: resolution is component-wise with policy context in
  the parent directory node (the numbered-step model in "Rule table and
  resolution", which retracts the old list); wildcard beats subtree
  inheritance, literal beats both; unreachable/dead config is rejected at
  table build; maps must be injective; per-mode reverse semantics and the
  CAP_CHOWN privilege model are pinned in "Ownership"; policy binds at
  lookup; synthesized-directory identity and monotonic ino allocation are
  pinned in "Inode identity and node ids" with two dated accepted
  limitations (no cross-restart ino stability; host inode recycling can
  alias, bounded by generations).

- 2026-08-12 (increment-2 review) — Rulings ratifying implementation
  decisions and resolving review findings:
  1. Every request body carries the fixed request head, including `Hello`
     (zeroed where meaningless); uniformity beats a special case.
  2. Entry replies carry no cache-validity TTLs on the wire — v1 caching
     policy is client-side per "Coherence and caching"; server-dictated
     TTLs would be new scope and are not decided.
  3. The listxattr response is the walked per-entry name stream (no NUL
     separators on the wire); its size fields mean the guest-visible
     NUL-separated list size, which deliberately differs from the wire
     stream length. The client rebuilds kernel format.
  4. Response status must lie in `-4095..=-1` (the Linux wire errno
     range) or be 0; out-of-range statuses are framing errors in both
     directions.
  5. ALL reserved fields and flag bits are "must be zero" ENFORCED: a
     nonzero reserved field anywhere in a fixed struct is a framing error
     on parse, and encoders refuse to emit one. The earlier looseness
     (only the request head validated) is retracted; repurposing any
     reserved field requires a PROTOCOL_VERSION bump. Exceptions: the
     handshake client/server negotiation flag fields keep must-be-zero on
     send / ignore-unknown on receive, as already decided; and the write
     request's `write_flags` field, which has carried the same
     must-be-zero-on-send / ignore-unknown-on-receive rule from day one
     and gains its first flag under the 2026-08-17 additive amendment to
     the stability rule (the strictly-enforced `reserved` field beside it
     stays a framing error when nonzero).
  6. Strict framing binds the encoder symmetrically: an encoder must not
     be able to produce a frame the peer's parser rejects, and the
     negotiated `max_frame_len` bounds encoded frames too.

- 2026-08-12 — Spec review (two independent probing passes; one
  compiled probes against the pinned zerocopy 0.8.56 and fuser 0.18.0
  sources) surfaced three blockers and four high-severity gaps. This
  revision resolves them: ino/node-id split with mode-keyed, session-scoped
  node ids plus FORGET and generations (see "Inode identity and node ids");
  a per-request caller-identity head; the ABI pinned via an opcode
  registry, golden vectors for every message type, and the
  PROTOCOL_VERSION-bump rule; pre-handshake size bound and `max_frame_len`
  semantics; the session state machine with a two-class protocol-error
  taxonomy; strict framing with semantic rejection tests. Superseded
  wording was retracted in place, not annotated.

## Control plane

A completely separate listener — unix socket only, never exposed on the
data-plane transport. JSON via serde (low-frequency operator traffic;
human-debuggable on purpose). Operations: create/delete namespace,
add/remove rules (modify = remove + add; a distinct modify operation was
retracted 2026-08-12), set ownership/permission/auth modes, list
namespaces, inspect active sessions. Driven by the `voidport-ctl` CLI.

## Startup and quick sharing (normative; decided 2026-08-13)

Decided 2026-08-13: quick sharing is **not a separate mode** — it is the
ordinary launch path with two conveniences, and there is **no default
bind** anywhere.

- **A missing state file is created, an invalid one is not.** When
  `voidportd --state PATH` names a file that does not exist, the server
  creates it as the empty document (atomically, mode 0600) and starts —
  an empty document is already defined as a server with nothing
  configured. A file that exists but cannot be read or parsed remains a
  startup error exactly as today: only the cleanly-missing case is
  created, so a typo'd path cannot silently shadow a real configuration.
- **Zero listeners is a legal running state.** Such a server serves only
  its control socket; everything else is added through `voidport-ctl`.
  (Amended 2026-08-16, retracting "listeners themselves are
  startup-only in v1": the listener-ops increment makes them
  runtime-mutable through the control plane like everything else —
  see its section.)
- **The control socket path**: the `--control-socket` flag wins, else
  the state file's value, else the compiled default
  `/run/voidport/control.sock`. **`voidport-ctl` without `--socket`
  (decided 2026-08-14) looks in order**: the per-user seeded path
  `$XDG_STATE_HOME/voidport/control.sock`, then
  `/run/voidport/control.sock` — first socket that accepts a connection
  wins, and the error when neither does names both paths. A locally
  seeded instance is therefore controllable with plain `voidport-ctl
  <command>`, no flags.
  (Retracted 2026-08-13: an earlier revision put the state file above
  the flag; an explicit flag losing to a config file surprises every
  operator, and the shipped behavior had always been flag-first.)
- **A seeded launch seeds its control socket too:** when `share` runs
  with no `--control-socket` and the document carries none, the seed
  writes `control_socket = "<state file directory>/control.sock"`
  (absolute) into the document — the compiled default lives under
  `/run/voidport`, which a non-root operator cannot bind, and the
  two-command flow must not require root. The launch summary then
  prints the matching `voidport-ctl --socket …` hint line beside the
  mount commands.
- **`voidportd share <DIR>`** is the seeded launch: identical to a plain
  launch against the same state file, except that before serving it seeds
  initial configuration through the normal validate → persist → swap
  machinery:
  - at least one listener from `--addr HOST:PORT` (tcp), `--unix
    PATH` and/or `--vsock PORT` (amended 2026-08-16 when the decided
    flag landed; all three repeatable) — **required**, there is no
    default bind;
  - a namespace named by `--name` (default `share`), permission
    `passthrough`, auth `none`, ownership `passthrough`;
  - one rule at the **absolute host path of `DIR`, replicated as the
    namespace path** (decided 2026-08-13, retracting the earlier
    `/<basename>` shape and the short-lived subtree-URL variant): the
    quickstart's use case is host-hierarchy replication, so
    `share /srv/media/example-project` grafts at
    `/srv/media/example-project` and
    the guest sees `srv/media/example-project/…` from the mount root, with
    intermediate directories synthesized by the engine as for any deep
    rule. Repeated `share` invocations against the same namespace
    compose without flattening or collision, exactly because each
    replicates its host path. Mode `rw`, or `ro` under `--ro`.
  - `--state` names the file to seed into (created when missing, as
    above); without it, share uses
    `$XDG_STATE_HOME/voidport/state.toml` (`~/.local/state/…` fallback),
    creating parent directories, and logs the path it chose.
  - Seeding is additive and conflict-refusing: a piece that already
    exists with exactly the seeded content is left alone (relaunching the
    same `share` command against the same file is idempotent); a
    namespace or rule of the same name/path with *different* content
    refuses startup with a plain error naming the collision. Nothing is
    ever overwritten.
- **The server prints the mount command.** After binding, a seeded launch
  prints one exact copy-paste `voidport mount …` line per listener
  (percent-encoding the unix socket authority), and one plain line noting
  that auth is `none` when a tcp listener is bound, pointing at
  docs/THREAT-MODEL.md. Machines differ on the reachable address of a
  `0.0.0.0` bind; the printed line uses the configured address verbatim.
  The printed URL names the **namespace root**, and with host-path
  replication the mountpoint then shows the host hierarchy
  (`srv/media/example-project/…`). (A short-lived same-day decision had
  the URL name a graft subtree over a `/<basename>` rule; both were
  retracted — the quickstart replicates the host, it does not flatten.)

## Operator TUI contract (normative for the TUI increment; decided 2026-08-13)

Decided 2026-08-13: a fully featured management TUI, started as
`voidportd --tui`, with the server to talk to specifiable. The decision on
shape: the TUI is **presentation over the existing control protocol** —
it adds no protocol surface, never touches the state file, and lives in
its own crate so the daemon library stays free of UI.

**Sequencing.** This increment builds on the seeded launch ("Startup and
quick sharing" above) landing first: `--tui` composes with `--state` and
`share`, and the Overview screen renders the launch summary that work
introduces.

**Invocation.**

- `voidportd --tui` with no `--state`: **attach mode.** Connects to a
  running server's control socket (`--control-socket PATH`, default
  `/run/voidport/control.sock`). Quitting disconnects and leaves the
  server untouched.
- `voidportd --state X --tui` (and `voidportd share DIR … --tui`):
  **serve-and-present.** The same serving launch with the TUI as the
  foreground; quitting the TUI initiates the server's clean shutdown.
  The seeded launch's mount commands and its auth-none note render in
  the Overview screen instead of stdout.
- A failure before the terminal is taken over (missing socket, refused
  connection, bad flags) prints plainly and exits nonzero. The terminal
  is restored on every exit path, panic included.

**Protocol surface** (retracts the earlier "adds no protocol surface"
sentence, which the spec review proved jointly unsatisfiable with the
Overview screen in attach mode): the TUI adds **no mutation
operations**, but the server-info reply gains a read-only `listeners`
field carrying the server's **bound** endpoints (transport plus the
address as actually bound — a tcp listener configured with port 0
reports the real port). Both binaries ship from one workspace, so the
reply-shape change carries no cross-version concern in v1. The TUI
still never reads or writes the state file.

**Crate shape.** New library crate `voidport-tui` (ratatui + crossterm —
both join the dependency table), consumed by the `voidportd` binary
behind `--tui`. The blocking control-plane client moves from
`voidport-ctl` into `voidport-control` **behind a cargo feature** (e.g.
`client`, default off), so the protocol crate stays pure types for a
consumer that wants only those; `voidport-ctl`, `voidport-tui` and
`voidportd::testing` enable the feature and drive the one shared client
(the testing module's own control client is consolidated onto it). The
moved client gains finite connect/read/write timeouts with stated
defaults — the spec review showed a wedged connection would otherwise
never be detected as lost. The TUI drives the client from a worker
thread so the UI loop never blocks on I/O.

**Terminal lifecycle.** Raw mode changes what the contract may assume,
so it is spelled out: resize redraws (crossterm resize events); Ctrl-C
arrives as a key event, not SIGINT, and maps to quit (attach) or
clean shutdown (serve-and-present); Ctrl-Z restores the terminal,
delivers SIGTSTP, and re-enters raw mode with a full redraw on SIGCONT;
SIGTERM restores the terminal and shuts down cleanly. Below a stated
minimum size the TUI renders a deterministic "terminal too small"
placeholder, not a degraded layout. In TUI modes the daemon's
tracing output never writes to the terminal: it goes to a file beside
the state file (serve-and-present) or wherever `--log-file` points
(either mode); without a destination in attach mode it is discarded. A
log-viewer screen is deliberately out of scope for this increment.

**Serve-and-present supervision.** One contract for every failure after
takeover: restore the terminal first, then initiate shutdown, cancel
the client worker, join the daemon, print the error plainly, exit
nonzero. A daemon that dies while the TUI runs takes the TUI down that
same path; a TUI quit takes the daemon down the clean-shutdown path it
already has.

**Attach-mode reconnection.** Connection loss shows a banner and
retries with capped backoff (500 ms doubling to 5 s, indefinitely);
quit stays responsive throughout. A successful reconnect — including to
a restarted server — invalidates every cached view and re-fetches; a
form in progress is kept, and its eventual submit is judged by the
server like any mutation.

**Screens** — full coverage of the v1 control protocol, nothing beyond
it:

1. **Overview** — server info (version, state file, control socket),
   the server's bound endpoints from the extended server-info reply
   (read-only in the TUI; startup-only when this was written, amended
   2026-08-16 — the listener-ops increment makes them runtime-mutable
   through ctl, and the TUI's panel follows on refresh), session
   count, and in
   serve-and-present mode the launch summary: the exact mount command
   per listener and the auth-none note when tcp is bound.
2. **Namespaces** — list; create (name, permission, auth, ownership
   mode); delete behind a confirmation; show renders the namespace in
   its source form.
3. **Rules** (per selected namespace) — list; add (path, share mode,
   optional target); remove behind a confirmation.
4. **Ownership** (per namespace) — the full policy as one form: mode,
   uid/gid map entries (numeric or the `uid`/`gid` sentinels), unmapped
   policy, squash ids; applied whole, as the protocol applies it.
5. **Permission / Auth** — the two mode setters.
6. **Sessions** — live list, refreshed on a timer (default 1 s) and on
   demand.
7. **Help** — an overlay listing every keybinding; plus a persistent
   status line (socket, server version, last operation outcome).

**Behavior rules.**

- Every mutation goes through the same typed operations `voidport-ctl`
  issues. The server's answer is the truth: no optimistic client state
  (deterministic, reloadable state, as everywhere else in the system).
- **Freshness is defined for every read view, not only sessions:** each
  visible view re-fetches on a shared 1 s tick and on focus entry.
  Selections survive refresh by key where the item still exists; an
  item deleted externally clears the selection with a status-line note.
  Another operator mutating through `voidport-ctl` while the TUI is open
  is therefore visible within one tick.
- Mutation effects carry a correlation id back to the issuing view: the
  view shows pending until the answer arrives, re-fetches on success,
  renders the server's error on rejection — and a re-fetch that itself
  fails renders as a fetch-error state, never as silently stale data.
  All of this is reducer-level behavior, unit-testable.
- Form inputs pre-validate with the shared types where they exist
  (namespace names, id mappings, share modes); everything else is the
  server's verdict. Rendering is byte-honest for names the types allow.
- Every list scrolls with the selection kept visible; `/` filters list
  screens incrementally.
- A rejected operation renders the server's error plainly and changes
  nothing else.
- Keyboard-only operation; the mouse is never required. The Help
  overlay is the **canonical** binding list: a reachable binding absent
  from Help is a defect.
- **Field coverage is explicit:** every field of every operation and
  reply in `voidport-control` is either rendered somewhere or named in a
  deliberate not-shown list carried in the `voidport-tui` crate docs.
  Reviewers verify the mapping against the types.

**Testing.** The UI core is model/update/view: pure reducers take
(model, event) → (model, effects), effects run at the edge. Reducers are
unit-tested (per-screen, covering every Help-listed binding); every
screen renders under ratatui's `TestBackend` with assertions on the
buffer (no terminal in CI); the client/worker layer is
integration-tested against a real in-process server via
`voidportd::testing`; and the terminal-lifecycle paths (restore on quit,
panic, SIGTERM; suspend/resume) are exercised in a PTY the test itself
creates — `portable-pty` joins the dependency table as a
dev-dependency for exactly this.

### Acceptance criteria — TUI increment

Revised 2026-08-13 after the spec review; the earlier set is retracted.

1. Attach mode connects to a live server; every screen is reachable by
   keyboard alone; quitting leaves the server serving. The Overview
   shows the server's bound endpoints in attach mode (via the extended
   server-info reply).
2. Serve-and-present works for both `--state` and `share` launches;
   quitting cleanly shuts the server down; the Overview shows the
   seeded launch's mount commands and auth note. A daemon failure
   injected after takeover restores the terminal, prints the error, and
   exits nonzero.
3. Namespace create and delete round-trip through the server and the
   list reflects them; delete asks for confirmation.
4. Rule add and remove round-trip; a change made through the TUI's
   client layer binds for a mounted guest at its next lookup — proven
   against a real mount where the FUSE preflight passes (the sanctioned
   skip applies elsewhere; where FUSE is usable it executes).
5. The ownership editor round-trips the full policy including map
   entries and sentinels; a policy the server rejects renders its error
   and leaves the view unchanged.
6. Permission and auth setters round-trip.
7. The sessions view shows a new mount within one refresh interval and
   drops it after unmount; every other read view reflects an external
   `voidport-ctl` mutation within one tick (proven with ctl driving a
   change while the model holds the view).
8. Mutation correlation holds at the reducer level: pending until
   answered, re-fetch on success, server error rendered on rejection,
   fetch-failure rendered as such — and a rejection changes nothing
   else client-side.
9. Connection loss in attach mode banners and reconnects with capped
   backoff; quit stays responsive during retry; reconnect re-fetches
   every view (driven through the client against a server restarted
   mid-test). The client's timeouts detect a wedged connection.
10. Every screen has a `TestBackend` render test, including the
    too-small placeholder; every Help-listed binding has a reducer
    test; Help completeness is asserted against the reachable
    bindings; the suite needs no pre-existing terminal.
11. Terminal lifecycle proven in a test-created PTY: restored on quit,
    on panic, and on SIGTERM; suspend/resume re-enters raw mode and
    redraws. A pre-takeover failure prints plainly and exits nonzero.
12. `./check` passes with all of the above executing per their stated
    gates, and `nix build path:.` succeeds — the flake package build
    runs the suite in the nix build sandbox (see Gates in
    the Implementation section), so the PTY harness and every
    socket-binding test must be sandbox-clean.

## State file

- **TOML**, parsed with serde. Loaded once at server startup.
- Runtime mutations through the control plane are applied in memory **and
  persisted back atomically** (write-to-temp + rename); the server owns the
  file. A server restart reproduces the world (deterministic, reloadable
  state).
- External edits while the server runs are not watched and do not refresh
  memory (v1).
- Relative paths resolve against the state file's directory; `host_uid: uid`
  resolves to the invoking user.

### State & control contract (normative for increment 4)

Revised 2026-08-12 after the increment-4 spec review; the earlier
revision of this section is retracted.

**The source/runtime split (the load-bearing model):** the persistent
source of truth is a serde **source document** that retains exactly what
the operator wrote — id sentinels stay sentinels, relative targets stay
relative. Engine state (`RuleTable`, `Ownership`) is **built from** the
source document, resolving sentinels and relative targets at build time
against injected inputs (identity, state-file directory). Persist
re-emits the source form verbatim, so a mutation never bakes a sentinel
into a machine-specific number, and `load(persist(x)) == x` holds on the
source model. Mutations edit the source document and rebuild the affected
namespace. Control-plane mutations may carry sentinels and relative
targets; they resolve at build exactly as load does.

**State file (TOML, serde-parsed — no hand-written parsing anywhere):**

- Schema: server settings (control socket path; a `[[listener]]` array
  parsed and persisted now, served by increment 5 — each entry is
  `transport = "tcp"` with `addr`, `"unix"` with `path`, or `"vsock"`
  with `cid` + `port`) plus a list of namespaces. Each namespace: name,
  ownership, permission mode (`passthrough`), auth mode (`none`), rules.
- Per-mode ownership shapes: `mode = "map"` requires uid/gid map tables
  (host side: a number or the sentinel `"uid"`/`"gid"`, expressed as a
  validated type accepting nothing else); `mode = "static"` requires the
  static uid + gid; `mode = "passthrough"` requires nothing. Squash ids
  optional, default 65534. Serde enum strings are lowercase.
- **Unknown fields are rejected everywhere** (`deny_unknown_fields`); a
  misspelled policy key must fail load, not silently default.
- Namespace names: nonempty UTF-8, at most 255 bytes, no `/`, NUL, or
  control characters; unique — duplicates are a load/create error.
- Load validates every namespace through the engine's build boundary; the
  loader owns error enrichment, composing typed errors that name the
  namespace and offending rule (TOML errors carry line/column; engine
  errors carry rule paths; the loader joins them). A failing file refuses
  startup.
- The loader takes its environment (invoking uid/gid, state-file
  directory) as injected inputs, so sentinel tests are hermetic.
- **Persist is atomic and durable:** write a temporary file in the same
  directory with the state file's mode (0600 on first create, preserved
  on replace), fsync the file, rename over, fsync the directory.
- **Single instance** (reworded 2026-08-12 after review; the original
  "lock on the state file" is retracted — an inode lock is stranded by
  the rename-over persist, and a spelling-keyed sidecar is defeated by
  aliases): the server holds a lock for its lifetime on a **sidecar lock
  file derived from the canonicalized state path** (`<state>.lock`),
  created once and never replaced. A second daemon reaching the same
  state file — including through a symlink — fails startup with a clear
  error. External edits are not watched; the next persist overwrites
  them (decided for v1).
- Accepted v1 limitation (2026-08-12): the wildcard syntax reserves the
  bare `*` rule-path component, so a host file literally named `*` cannot
  carry an individual literal rule (it is still reachable through subtree
  inheritance or a wildcard).

**Control plane:**

- Unix socket only; path from configuration or CLI. **Bind contract:** if
  the path exists and is a live socket (a connection succeeds), startup
  fails — another daemon owns it; if it is a stale socket (connection
  refused), unlink and bind; if it is any other file, startup fails.
  Owner-only permissions (0600) are established race-safely (umask around
  bind, verified after). Clean shutdown unlinks the socket.
- Protocol: newline-delimited JSON — one request object per line, one
  response per line, in order per connection. Request lines are bounded
  (1 MiB); an oversized line is a structured error followed by connection
  close. Malformed JSON or an unknown operation yields a structured error
  and the connection lives on.
- **The typed protocol lives in its own crate, `voidport-control`**, shared
  by server and CLI: a tagged `Request` enum, a response envelope (result
  or `{code, message}` with an error-code enum). `voidport-ctl --json`
  prints the response envelope verbatim — that is the stable script
  interface.
- Operations: namespace list / show / create / delete; rule add / remove;
  ownership set (mode, maps, unmapped, squash); permission-mode set;
  auth-mode set; server info (version, state file path). Session
  inspection lands with increment 5.
- **Mutation semantics: serialized; validate → persist → swap.** All
  mutations are linearized under one state lock held across the whole
  sequence. Validation failure returns the typed error and changes
  nothing. Persist failure likewise returns an error and publishes
  nothing — memory is only swapped after the file is durably renamed, so
  memory and disk cannot diverge and there is no rollback path. Reads
  operate on snapshots and never block behind mutations.
- **Namespace lifecycle** (clarified 2026-08-12): the registry maps
  name → shared immutable namespace state, and every mutation swaps in a
  new snapshot. Sessions (increment 5) hold the namespace NAME and
  consult the current snapshot per lookup — fresh lookups see mutations —
  plus a handshake-time snapshot used only as the deletion tombstone.
  Deleting a namespace removes the registry entry — new handshakes fail
  (exercised in increment 5; a forward contract here) — while existing
  sessions continue on their tombstone until disconnect. Open handles
  grandfather in all cases per the policy-binds-at-lookup rule.
- SIGINT/SIGTERM: shutdown completes any in-flight mutation (the lock),
  unlinks the socket, and exits cleanly.

**`voidportd` binary (this increment):** clap CLI taking the state file and
control socket paths; loads state, builds all namespaces, serves the
control plane, shuts down cleanly. The data plane arrives in increment 5.

**`voidport-ctl`:** one subcommand per control operation, human-readable
output by default and `--json` for scripts, nonzero exit on error.

### Data plane server contract (normative for increment 5)

Drafted 2026-08-12; reviewed by the increment-5 spec review before build.

**Listeners.** Served from the persisted `[[listener]]` config: `tcp` and
`unix` are implemented; `vsock` parses and persists but is refused at
startup with a typed error — accepted v1 limitation (2026-08-12; tokio has
no native vsock listener, and the transport abstraction already
accommodates adding one). (Superseded 2026-08-15: the vsock increment
below serves it — this paragraph stands as the record of the interim
state.)

**Session lifecycle** (corrected 2026-08-12 after a review blocker; the
frozen-snapshot wording is retracted). Accept → read `Hello` under the
pre-handshake bound → resolve the namespace in the registry, keep its
NAME, and capture the current snapshot as the **deletion tombstone** →
component-walk the requested subpath → `HelloReply` with the root node id
1, the accepted version, and `max_frame_len` (server constant, 1 MiB) →
serve. **Every path-resolving operation consults the registry's CURRENT
snapshot for the session's namespace name**, so a fresh lookup observes
control-plane mutations immediately — this is the fresh-lookup decision,
and freezing the handshake snapshot for the session's lifetime
contradicts it. Only when the registry entry is gone (namespace deleted)
does the session fall back to its captured tombstone until disconnect.
Node modes still bind at the lookup that admitted them (handle
grandfathering is unchanged). Connection drop or any framing error tears
down the session: all handles and nodes close.

**Concurrency.** One reader task per connection; each request is served on
the tokio runtime with host filesystem syscalls on the blocking pool
(io_uring is the later upgrade, out of v1 scope); replies may complete out
of order; one writer task serializes response frames. The server holds no
global locks on the request path — sessions share only the immutable
namespace snapshot and the ino allocator.

**Graft pinning and containment.** When namespace state is built (load or
mutation), the server opens every literal rw/ro graft target with
`O_PATH`; a target that fails to open is a typed build error, consistent
with validate-persist-swap. All descent below a pinned fd uses `openat2`
with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`, so a symlink pointing
outside the graft can never be followed out — the hard security invariant.

**Symlink semantics** (decided 2026-08-12 after kernel probes): the
final-component lookup pins with `O_PATH | O_NOFOLLOW`, so a symlink node
is returned as a symlink — never followed server-side — and `readlink` is
served by `readlinkat(fd, "")` on the pinned fd (the empty-path form; a
readlink of the /proc magic link returns the wrong thing). Following a
symlink is the CLIENT kernel's job: it readlinks and re-walks, so an
absolute target resolves inside the guest's own namespace, which is the
correct FUSE model and not a host escape. The handshake subpath walk does
not follow symlinks — a symlink component is a mount error. The openat2
containment flags remain as defense-in-depth (probed: absolute, dot-dot,
and intermediate symlink escapes all fail EXDEV).

**Nodes.** Per-session node table per the decided model: a node holds its
own `O_PATH` fd (obtained via `openat2` from its parent at lookup), the
global synthetic ino, a generation, the effective share mode, and (for
directories) the namespace-path context driving child resolution.
Synthesized directories hold no fd and serve the fixed attribute set.
FORGET decrements the lookup count and drops the node (closing its fd) at
zero; session teardown drops everything.

**Handles.** Open/create reopen a real fd from the node's `O_PATH` fd via
`/proc/self/fd` (the standard reopen idiom), with the open mode checked
against the node's share mode first. Probe-verified 2026-08-12: the magic
link preserves the pinned inode through rename-over and after unlink, and
reopening a pinned symlink node fails ELOOP instead of following out —
one review claim to the contrary was refuted by direct probe. The
reopen is explicitly EXEMPT from the `RESOLVE_NO_MAGICLINKS` discipline
(it is itself a magic link; safety comes from the fd having been obtained
under containment). Directory handles materialize the
merged, policy-filtered listing at opendir (host children + literal-rule
children per the engine, hidden filtered, attributes resolved); readdirplus
cookies index into that materialized listing, and cookie 0 rewinds. This
buys stable cookies over the merged view — accepted memory cost, bounded
by directory size.

**Enforcement.** Share-mode enforcement is server-side and unconditional:
write-class operations (open for write, create, unlink, mkdir, rmdir,
rename, link, symlink, setattr, setxattr/removexattr) through an ro node
fail with EROFS; hidden never resolves. Full POSIX permission-bit
emulation is NOT performed server-side in v1: the client mounts with
default_permissions so the guest kernel enforces the presented bits, and
the host filesystem naturally refuses what the server's own identity
cannot do. The per-request caller identity drives ownership mapping on
create and chown per the ownership contract.

**Operation semantics.** Attributes are read fresh per getattr
(fstatat-class calls; ownership forward-mapped, bits through the
presented-bits function). Read/write are passthrough on the handle's fd at
the requested offset. statfs reports the backing filesystem (fstatfs on
the pinned fd) for host-backed nodes and zeroed synthetic values for
synthesized directories. File locking implements getlk/setlk with OFD
locks on a **per-(handle, wire-owner) lazily reopened description** —
probe-verified 2026-08-12 that locks through one shared description
coalesce instead of conflicting, so distinct wire owners need distinct
open file descriptions; an owner's description drops when its locks are
released. OFD getlk reports pid -1 (the wire pid field is informational). Xattrs are passthrough for the `user.*`
namespace; `trusted.*`, `security.*`, and `system.*` return EOPNOTSUPP —
accepted v1 limitation (2026-08-12; ACL and capability xattrs interact
with privilege in ways the ownership model does not yet rule).
Unsupported/unknown but well-framed requests get ENOSYS per the protocol
error taxonomy. Host errnos otherwise pass through.

**Ino allocation.** The server-global `(host_dev, host_ino) → ino` map and
the synthesized-directory ino space per the identity contract; monotonic
u64, top-bit tag for synthetic inos.

**Resource bounds** (decided 2026-08-12 — with `auth: none`, per-peer caps
are the v1 abuse posture): per-session in-flight requests are capped
(default 64) by **pausing the connection read loop** — natural transport
backpressure, no errno — which also bounds blocking-pool usage and the
reply queue. Per-session caps with errnos — **defaults retracted
2026-08-14: every per-session cap defaults to UNBOUNDED**, because a
limit nobody chose is a bug report waiting. A cap exists only where the
operator configures one (the opt-in throttle for multi-tenant
postures); the numeric defaults that twice refused a real source-tree
walk (nodes at 65,536, then handles at 16,384) are gone. The server
raises RLIMIT_NOFILE to the OS maximum at startup and logs it.
(Retracted 2026-08-15: this decision's original "when the OS ceiling
genuinely binds, the OS's own errno surfaces — a fact, not a policy"
posture. The AOSP field failure proved the ceiling binds not at
genuine exhaustion but at the rate of names-ever-walked, because a
node pinned a descriptor for life — a design artifact, not a machine
fact. The "Node descriptor budget" section now rules that lifecycle;
configured caps keep their errnos: nodes ENFILE, handles EMFILE,
materialized listing entries EOVERFLOW, and honest host exhaustion
still propagates.)
The global session cap follows the same posture — unbounded unless
configured (the stale "default 256" parenthetical is retracted with the
rest); where configured, excess connections are accepted and closed
after an error response. All caps configurable in server settings.

**Data-plane socket lifecycle.** A `unix` data listener follows the SAME
bind contract as the control socket (sidecar claim, stale reclaim, live
refuse, non-socket refuse, 0600, unlink on shutdown). Listener startup is
all-or-nothing: any listener failing to bind fails startup.

**Session inspection** (added 2026-08-12 — promised by the increment-4
contract but previously specified nowhere): `voidport-control` gains a
session-list operation (session id, namespace, subpath, transport/peer,
node and handle counts) served by the control plane and exposed by
`voidport-ctl`.

### Acceptance criteria — increment 5 (data plane server)

1. Handshake paths tested over a real socket: success (root node id 1,
   max_frame_len announced), version mismatch, nonempty auth blob,
   unknown namespace, invalid subpath, subpath landing on a synthesized
   directory, and the pre-handshake size bound.
2. The worked example over the wire: lookup and readdirplus show foo rw,
   bar with write bits stripped, file.txt rw; `secret/` resolves ENOENT
   and never appears in listings; a re-targeted literal graft absent from
   the host listing appears in readdirplus.
3. Read/write round-trips through a rw graft; every write-class operation
   through an ro node fails EROFS (tested per operation); creates apply
   reverse ownership mapping (host-side ownership asserted) and present
   forward-mapped ids.
4. Symlink semantics and containment: lookup of a symlink returns a
   symlink node and readlink returns its target verbatim (including an
   escaping target — reading is not following); server-side resolution
   through an escaping symlink (absolute, dot-dot, and intermediate
   forms) fails without opening anything outside the graft; a symlink in
   a handshake subpath is a mount error; reopen-after-rename-over serves
   the pinned inode, not the replacement.
5. Node identity: ino stable across lookups, hardlinks share an ino,
   FORGET at zero lookups closes the node fd (observed via /proc fd
   count), session teardown closes everything, a node id is never given
   to another file within a session and a forgotten file gets its id back
   (amended 2026-09-22), and the wire generation is 0.
6. Concurrency: overlapping requests complete out of order on one
   session; two sessions (one writer, one reader) observe each other's
   writes through the server.
7. Protocol errors behave per taxonomy on a live session: framing errors
   close the connection; unknown opcodes answer ENOSYS and the session
   lives.
8. Xattr user.* get/set/list/remove round-trip; the reserved namespaces
   return EOPNOTSUPP; lock conflict is observable via getlk, two distinct
   wire owners on ONE handle genuinely conflict, and owner-specific
   unlock releases only that owner's locks.
9. statfs distinguishes host-backed (real fstatfs values) from
   synthesized (zeroed synthetic) nodes.
10. tcp and unix listeners serve sessions in tests; the unix data socket
    passes the bind-contract tests (stale/live/non-socket/unlink); a
    vsock listener entry refuses startup with the typed error; one
    failing listener fails startup.
11. Resource caps are exercised: the in-flight cap pauses reads (observed
    as backpressure, not errors), the node/handle/listing caps return
    their errnos and release resources, and the session cap closes excess
    connections after an error response.
12. Session inspection: session-list reports live sessions with counts
    over the control plane and through `voidport-ctl`, and a FORGET
    high-volume test reuses ids freely (no-response retirement).
13. `./check` passes. Integration tests drive the real server over real
    sockets with a test client built on voidport-proto (no FUSE yet).

### FUSE client contract (normative for increment 6)

Drafted 2026-08-12; reworked 2026-08-13 after the increment-6 spec
review (every finding accepted, most probe-verified live on the
reference environment's kernel 6.18 with fuser 0.18; see Dispositions).

**The `voidport` binary.** `voidport mount <url> <mountpoint> [flags]`
and `voidport umount <mountpoint>`. Flags: `--attr-timeout` /
`--entry-timeout` (seconds, default 1); `--allow-other` (off by
default; maps to fuser's `SessionACL::All`); `--read-only` (sets
fuser's `MountOption::RO` so the kernel itself refuses write-class
operations and reports the mount read-only — in addition to, never
instead of, server-side share modes).

**URL grammar.** Parsed with the `url` crate, then validated; each rule
below rejects with a distinct, clear error (unit-tested without a
server):

- `voidport://host:port/@namespace[/subpath…]` — tcp. The port is
  required (there is no default port). IPv6 hosts use the bracketed
  form.
- `voidport+unix://<socket>/@namespace[/subpath…]` — unix socket. The
  socket path is the authority (host) component, percent-decoded
  exactly once to OS bytes, and must be absolute.
- The first path segment must begin with `@`; its remainder names the
  namespace and must satisfy the server's namespace-name rules. The
  remaining segments form the subpath: each percent-decoded exactly
  once to bytes, joined with `/` and rooted absolute; no segments means
  the namespace root. NUL bytes and empty interior segments are
  rejected.
- userinfo, query, and fragment components are rejected.

**FUSE mapping.** A fuser (0.18) `Filesystem` implementation. The
kernel node id is the server node id; `st_ino` presents the node id per
the accepted fuser-coupling limitation; generation is 0 (probe-verified
legal: the kernel compares generation for equality only, and a node id
is never given to another file). Caller identity (uid/gid/pid) from each fuser
request fills the request head. The mount always sets
`default_permissions` and `fsname=voidport`.

`init` negotiates three capabilities via
`KernelConfig::add_capabilities`, each load-bearing (each was
live-proven absent from fuser's defaults and its absence breaks a
stated guarantee):

- `FUSE_DO_READDIRPLUS` — directory reads arrive as readdirplus, for
  which the kernel does per-entry nlookup accounting matching the
  server's counts. `FUSE_READDIRPLUS_AUTO` is NOT requested: every
  listing goes through readdirplus.
- `FUSE_POSIX_LOCKS` — without it the kernel satisfies record locks
  guest-locally and the server never sees getlk/setlk.
- `FUSE_AUTO_INVAL_DATA` — without it a same-size overwrite from
  another mount or the host is invisible to a held-open descriptor
  indefinitely (cached pages are only invalidated on attr change when
  this is negotiated).

`FUSE_FLOCK_LOCKS` is deliberately NOT negotiated: fuser 0.18 drops the
kernel's `lk_flags` (the flock-vs-record distinction never reaches the
trait) and the wire `FileLock` carries no lock-namespace field, so
routing flock(2) to the server would wrongly conflate it with record
locks. flock(2) therefore stays guest-local per mount in v1 — a
documented limitation; cross-mount conflict coverage is fcntl record
locks. Adding an lk_flags field to the wire is a post-v1 candidate.

Callback matrix (kernel → wire): lookup→Lookup; forget→Forget (one wire
FORGET carrying the nlookup count); batch_forget→one FORGET per
element (the wire has no batch form); getattr→Getattr;
setattr→Setattr; readlink→Readlink; symlink→Symlink; mkdir→Mkdir;
unlink→Unlink; rmdir→Rmdir; rename→Rename; link→Link; open→Open;
read→Read; write→Write; statfs→Statfs; release→Release; fsync→Fsync;
setxattr/getxattr/listxattr/removexattr→the four xattr ops (listxattr
rebuilds the kernel's NUL-separated list from the wire name stream
using the guest-size semantics already on the wire); flush→Flush;
opendir→Open (the returned handle is the directory handle);
readdirplus→Readdirplus; readdir→served from wire Readdirplus with an
immediate compensating FORGET per returned entry (defensive: the
kernel does no nlookup accounting for plain readdir);
releasedir→Release; fsyncdir→Fsync; create→Create; getlk→Getlk;
setlk/setlkw→Setlk with the kernel's lock-owner value passed through. A
getlk conflict pid surfaces to the guest as 0, not the server's -1
(the kernel resolves the pid through its pid namespace and finds
nothing) — tests must not assert a conflict pid. access is never
reached (`default_permissions`). Every other callback replies ENOSYS,
except mknod, which replies EPERM: the namespace holds only regular
files, directories, and symlinks by design, which is a refusal, not a
missing feature. fuser's default per-call warning for unmapped
callbacks **stays** (a same-day quiet-handlers decision was retracted:
the warnings did not flood, and they are what surfaced two
gaps that needed closing, not silencing). Decided 2026-08-13 instead:
**poll is implemented** with the standard always-ready semantics for
regular files and directories, and the specific ioctl command the
first real workload issued is investigated and decided on evidence —
implemented if it is safely proxyable, refused knowingly if not.

**Node lifecycle (client side).** Every counted entry reply — lookup,
create, mkdir, symlink, link, and each readdirplus entry — adds one to
the kernel's lookup count, and the server tracks the same count. The
client forwards `forget(ino, nlookup)` as one wire FORGET and expands
`batch_forget`. The mount root is never forgotten during the session.
When a counted entry cannot be delivered to the kernel — a
`ReplyDirectoryPlus` buffer refuses the entry, or an error path drops
an entry reply — the client immediately sends a compensating FORGET
for the undelivered count, so the server's count always matches the
kernel's. No FORGET flush is owed at unmount: the server clears the
session's nodes at teardown per the data-plane contract.

**Caching (v1 conservative, per "Coherence and caching").**
Writethrough — no writeback cache, and open replies never set
keep_cache. Entry and attr TTLs default 1 second; reads may use the
page cache, which revalidates on attr change under the negotiated
`FUSE_AUTO_INVAL_DATA` (probe-verified: a held-open descriptor
re-reads fresh data after the TTL with the capability, and stays stale
indefinitely without it). mmap reads work through the page cache under
the same bound. fsync/flush pass through. Staleness across mounts is
bounded by the TTLs; the invalidation notification tightens this
later.

**Connection and concurrency.** One connection per mount, many
requests in flight (request ids allocated by the client per the wire
contract; the hello uses id 1 and data requests start above it). The
handshake is validated beyond framing: the hello reply must echo the
hello's request id, announce a frame bound of at least 4096 bytes (a
smaller bound would make reads degenerate), and announce root node id 1
— the only value the kernel will ever use for the mount root. Each
refusal is a distinct mount error. All frames are written through a single serialization
point, and a FORGET's id retires at that point — matching the wire's
stream-order acceptance rule. Callbacks never block the fuser dispatch
loop: every callback hands its work to the mount's async runtime and
replies from there, so a blocked SETLKW cannot stall unrelated
operations on the same mount. Any response-side protocol fault —
invalid frame, unknown or duplicate response id, wrong opcode for the
outstanding id, mid-frame EOF, or a length violation — is treated
exactly like connection loss: the connection is atomically marked
dead, the socket closes, and no further frames are sent on it. What
happens next is the reconnection contract below (retracted 2026-08-14:
an earlier revision made every subsequent operation fail EIO with no
reconnect, deferred post-v1 — reconnection has since been decided the
default; see "Mount resilience").

## Node descriptor budget (normative for the descriptor-budget increment; decided 2026-08-15 after the AOSP field failure)

A node pinned one `O_PATH` descriptor for its whole life, and a node
lives until the guest kernel forgets it — which a kernel without memory
pressure never does. The server's descriptor table therefore filled at
the rate of *names ever resolved*, and a source-tree walk the size of an
AOSP checkout exhausted it: every subsequent host open answered `EMFILE`
to whatever operation needed it. On the host or through a bind mount the
same walk is free, because a dentry cache costs no process's descriptor
table; voidport must not turn the guest kernel's caching into a server
resource it can exhaust.

The rework: **the descriptor is a cache slot, not a lifetime pin.**

(Reworked 2026-08-15 after the spec review — every blocker
accepted. The review probe-proved three things the first draft got
wrong: the budget derivation was impossible at both ends, ext4 reuses
(dev,ino) on the first recreate so the drafted identity check serves
the impostor on the most common filesystem, and the draft's "keeps
every entry it keeps today" was false for directories, which record no
identity at all. The contradicted sentences are retracted in place
below.)

- The node table keeps every entry — ids, namespace path, backing,
  mode, kind. Entries **gain a recorded identity** captured at pin
  time for every host-backed node *including directories*: host
  device, inode, kind, and the `statx` birth time where the
  filesystem supplies one (ext4, btrfs and tmpfs all do on the probed
  kernel). Birth time is what defeats inode reuse: the probe showed
  ext4 handing the identical `(dev, ino)` back on the FIRST recreate,
  20000/20000 cycles, so `(dev, ino, kind)` alone is not an identity.
  Where btime is absent the check falls back to `(dev, ino, kind)`
  and the guarantee is stated best-effort for that filesystem. Only
  the pinned descriptor becomes evictable; `max_nodes` continues to
  bound table entries, and since 1.0.1 it bounds the remembered ids of
  forgotten files by the same number.
- **Budget**: at most N *cache-resident* node descriptors at once,
  across all sessions (the descriptor table is process-wide).
  Default: `clamp(soft RLIMIT_NOFILE / 2 − reserve, 4096, 262144)` —
  the absolute ceiling exists because the startup raise can reach
  `fs.nr_open` (which can be billions on a tuned machine, where half
  would be hundreds of GiB of unswappable slab at the measured
  267.8 bytes per `O_PATH` fd), and 262,144 resident pins cost a
  measured ~70 MiB of
  slab, ample for any working set while harmless to the machine. The
  reserve is the existing `DESCRIPTOR_RESERVE`. Configured:
  `[server] node_descriptor_budget = N`, taken as-is (no floor
  clamp — tests configure hundreds), validated ≥ 16 (one operation's
  simultaneous working set: a rename holds both parents and both
  entries), startup-only like every listener, logged at startup.
- **Accounting, stated precisely** (the first draft's "resident
  descriptors never exceed the budget" was unsatisfiable and is
  retracted): the budget bounds the pins the **cache itself holds**.
  Eviction drops the cache's own reference and is therefore *always
  possible* — the descriptor closes when its last holder drops. A
  descriptor kept alive past eviction by a holder is that holder's,
  by prior decision: the process total decomposes as cache-resident
  (≤ budget) + in-flight checkouts + handle-retained pins (every
  open handle keeps its node's pin for lock descriptions) + graft
  pins + reserve, and handles and in-flight stay unbudgeted per the
  unbounded-caps decision. The server maintains a resident-pin counter
  and exposes it, with the derived budget, as read-only fields in
  the control plane's server info (the mutation surface is
  unchanged) — that is what the criteria and the torture harness
  observe; `/proc/self/fd` cannot attribute a descriptor to a node
  versus a handle.
- **Eviction** is least-recently-used, global across sessions with no
  per-session share in v1 — one session's churn may evict another's
  hot set, which is correct-but-slower, never incorrect: the budget
  closes descriptors, never entries. The ledger is owned by the data
  layer under one lock ordering invariant: the ledger lock is never
  held across a host syscall or a session's table lock, and reopen is
  single-flight per node.
- **Reopen** re-pins by descending from the **currently-published
  namespace snapshot** — the same snapshot a fresh lookup of the
  node's namespace path would use (the first draft said "the rule's
  pinned graft root ... pinned for the life of the rule"; retracted —
  graft pins are owned by namespace snapshots and every accepted
  mutation re-opens targets, so there is no per-rule pin lifetime to
  lean on). The governing principle: **an evicted node's operation
  behaves as it would after a fresh resolution of its namespace
  path**, except that identity verification may answer `ESTALE`
  first. The result must be the same file: identity is verified as
  recorded above, and a mismatch, a missing path, or a containment
  refusal answers `ESTALE`. Never the impostor: a host-side replace
  after eviction must not let an old node id read a new file's bytes,
  on any filesystem with birth-time support.
- **Reopen failures, exhaustively**: `ENOENT`, identity mismatch,
  `EXDEV` and `ELOOP` (containment is re-evaluated at reopen — an
  escaping symlink planted since the original pin is *refused*, a
  security-positive re-check) all answer `ESTALE`; `EMFILE`,
  `ENFILE`, `EACCES` and every other host errno propagate unchanged —
  honest exhaustion stays honest.
- **The server never stales what it renamed itself**: a rename,
  `RENAME_EXCHANGE` or link performed *through the mount* updates the
  affected nodes' recorded backings — including the descendants of a
  renamed directory — so a server-performed mutation never
  manufactures `ESTALE` (mechanism decided 2026-08-15, superseding
  "left to the implementation": between the landed parent-and-name
  chaining and the reviewed full-path shape, the choice is
  **full-path subtree rewrite**, taken for resilience and simpler
  code: every
  entry records its path from its rule's root and re-pins
  independently, deleting the cross-entry references and the
  recursive re-pin cascade; a directory rename rewrites descendants'
  recorded backings per session, the same complexity class as the
  cross-session rebind that already exists. The simplification
  patch converts the landed parent-chain shape under the full
  descriptor suite).
  The `ESTALE` surface is host-side *external* mutation only.
  (Amended 2026-08-15, first landing reviewed: "the affected nodes"
  is unqualified on purpose — it means every session's nodes and
  every namespace alias of the moved entries, not just the renaming
  session's node at the renamed path. One host directory grafted at
  two namespace paths is two nodes, and both moved.)
- **A recipe is one way back, not the only way** (amended 2026-08-15
  after the first landing's review): a re-pin whose recorded recipe
  answers `ENOENT` falls back to re-resolving the node's own
  namespace path under the current rules before giving up — an
  identity match rebinds the recipe and proceeds; anything else
  answers `ESTALE`. This is what keeps a link-then-unlink of the
  original name honest in both directions: a single recorded recipe
  cannot represent two live names, and the namespace path is the name
  the guest is actually holding.
- **Retire-and-remint** (amended 2026-08-15 after the nix gate failed
  on an inode-reusing sandbox filesystem — the empirical form of a
  review finding): when a fresh resolution pins an entry whose
  identity does NOT match the node currently holding that table key —
  the path-keyed directory case, and the inode-keyed case wherever
  the filesystem reuses inode numbers — the held node is **retired**
  (rekeyed out of the table; its id answers `ESTALE` from then on,
  which is exactly criterion 4) and a fresh node is minted for the
  path. Without this the stale node occupies the key and the
  path-addressed retry the semantics bullet promises can never
  succeed: the path heals, the old id stays honest.
- **Semantics under eviction**, stated plainly: an operation by node
  id on an entry whose host path was externally renamed or removed
  since it was last resolved, *and* whose descriptor was evicted,
  answers `ESTALE` where a resident pin would have kept working. A
  path-addressed retry re-resolves and succeeds (the VFS retries
  `ESTALE` from the root once); an fd-addressed operation — `fstat`
  on an open descriptor, `openat` on a directory fd — has no path to
  retry from and surfaces `ESTALE` to the application, exactly as NFS
  does after external truncation of its file handles. This is the
  reconnect contract's identifier-bound criterion applied to
  descriptor pressure, and strictly better than the `EMFILE` collapse
  it replaces. A rule removed at the control plane drops its graft
  pin, so an evicted node under it answers `ESTALE` on next use —
  policy already governs every new open; this extends it to
  node-addressed metadata once the pin is gone.
- **Scope, stated honestly**: this increment bounds *descriptors*.
  The table entry itself remains guest-driven and unbounded —
  measured at scale 2026-08-15 (the RAM attribution pass, 800k-entry
  walk): **1.79 KiB of RSS per name ever resolved** (the earlier
  ~0.8 KiB figure was 2x optimistic; ~4-5 path copies ride each
  entry), so an AOSP-scale walk holds ~2.6 GiB. The same pass found
  the sharper problem: **freeing entries returns no RSS** — a
  drop_caches drained 800k nodes to 1 within seconds, and the
  allocator retained essentially all of it for the process's life,
  even past unmount (glibc arena retention). Bounding entry count
  would need the guest kernel to forget, which the server cannot
  force — but returning freed memory to the OS and thinning the
  per-entry footprint are the server's own to fix; decided as
  follow-ups the same day (allocator reclaim first, entry diet
  second, an entry bound re-priced only if those two leave it
  justified).
- Rejected: raising limits (CAP_SYS_RESOURCE the server does not
  have, and a full checkout out-names any limit); client-driven
  FORGET solicitation (FUSE's NOTIFY_INVAL_ENTRY is best-effort and
  per-name — no reliable bulk mechanism, and one misbehaving guest
  must not be the server's safety); pinning nothing (re-resolving
  every operation forfeits the measured hot-path wins for no need —
  the budget only bites where the old design died).

### Acceptance criteria — descriptor-budget increment

1. A walk that resolves at least ten times the configured budget in
   names completes with zero errors, with the budget set artificially
   small in the test so the suite stays fast.
2. Cache-resident pins never exceed the budget, observed through the
   server's resident-pin counter across the walk (with a one-time
   `/proc/self/fd` readlink-classification cross-check in the test —
   amended 2026-08-15: fdinfo carries no path for an `O_PATH`
   descriptor, so readlink against the pinned tree is the mechanism),
   while table entries grow past the budget freely under an unbounded
   `max_nodes`.
3. An evicted node whose host path is unchanged since its last
   resolution answers its next metadata operation identically to a
   resident one; attribute correctness is asserted across an
   evict-reopen cycle.
4. Identity holds for files AND directories: after eviction, an
   external unlink-and-recreate (or rename-away-and-recreate) at the
   same path answers `ESTALE` to the old node id — proven on an ext4
   loop image, where `(dev, ino)` reuse is immediate and only the
   birth-time check stands between the old id and the impostor's
   bytes. The new file's content is never served through the old id.
5. Open handles survive budget pressure untouched: a file opened,
   its node evicted from the cache, then read/written/locked through
   its handle behaves exactly as before (the handle retains the
   node's pin — that is the accounting's handle-retained term); the
   existing rename-while-open and unlink-while-open suites stay
   green.
6. Live reconfiguration semantics hold as stated: rule removal plus
   eviction answers `ESTALE` on node-addressed use; the existing
   rule-change suites stay green.
7. Mount-side renames never stale: after renaming files and a
   populated directory through the mount, previously-resolved nodes —
   including descendants of the renamed directory — are evicted and
   then reopened without a single spurious `ESTALE`.
8. The torture harness reads the resident-pin counter and asserts it
   never exceeds the budget for the whole run, and asserts process
   descriptors bounded by budget + handles + graft pins + a constant;
   the smoke stays green, and a torture run with a tiny configured
   budget (hundreds) passes all classes.
9. No hot-path regression: the `stat-loop`, `readdir-loop` and
   `small-files` scenarios, plus a `walk` scenario added to
   `voidport-bench` in this increment, are measured at the pre-change
   commit and after, same machine, same repetition discipline, and
   stay within the documented ~±10% spread when the working set fits
   the budget.
10. `EMFILE` is no longer reachable from a tree walk: the e2e that
    previously would have exhausted descriptors (criterion 1) proves
    the build-shaped workload survives.
11. Both gates pass with the new suites executing.

## Share subscription (normative for the subscription increment; decided 2026-08-15)

A guest listens for changes to what its namespace shares, so a mount
manager can mount and unmount directories dynamically. Polling cannot do
this job: the data-plane tree mixes synthesized parents and shared
subtrees, and nothing in it contractually marks where a shared
directory's root begins — the subscription carries that path
explicitly, which is what makes the desired mount set knowable at all.

(Reworked 2026-08-15 after the spec review — both reviews
converged on the same blockers: the share set was not computable as
written, a legal configuration overflowed the frame bound, a slow
subscriber could stall the mount's own I/O, the level-triggered claim
had no resync path, and the version rules made the compatibility
criterion self-contradictory. Every contradicted sentence is replaced
below, in place.)

- **What an entry is, exactly** (the first draft never defined "shared
  directory" and the snapshot was uncomputable): the stream reports
  the namespace's **literal, non-hidden rules** that the session's
  scope and visibility admit — one entry per rule, carrying the
  namespace path, the mode (`rw`/`ro`), and the target kind:
  `directory`, `file`, or `unknown` (amended 2026-08-15 after the
  follow-up review: a kind is reported only where the build already knows it
  without fresh host I/O — a stated target's kind is recorded when
  the graft pins it, and a targetless mode-override island, whose
  derived path is never pinned or checked, reports `unknown`;
  consumers treat `unknown` as try-and-see). Wildcard rules are
  policy defaults, not shares: they are never enumerated (the
  enclosing entry covers the subtree, and the engine cannot name a
  wildcard's children without a host readdir). Hidden rules never
  appear — neither as entries nor as events. A literal mode-override
  island under a graft is a rule, so it is an entry. The set is a
  pure function of the published namespace and the session's subpath.
  Host existence enters exactly where it always has (amended
  2026-08-15, the blanket "not consulted" retracted): a stated
  target must pin at build, as the data-plane contract already
  rules; a derived target is never checked, its entry is still
  reported, and the mount manager's own mount attempt is what meets
  reality. Consequence, stated
  plainly: **the stream tracks control-plane changes only.** A
  host-side chown or mkdir that changes what resolution would show
  produces no event; the ownership-hide filter is likewise not
  re-evaluated per event. That is scope, not accident — the data
  plane is request-driven and no host-watching mechanism exists in
  this design.
- **It rides the data plane.** The guest never holds the control
  socket. This is the first activation of the wire contract's
  reserved server-initiated notification class (opcodes 0x8000 and
  up, request_id 0, no reply — a notification frame bypasses the
  writer's request-id retirement bookkeeping). Payloads are
  zerocopy-typed wire structs with golden byte-vector tests like
  every other message type; JSON appears only in the CLI's output
  rendering, never on the wire.
- **Opt-in per session, resyncable, revocable**: a new Subscribe
  request op enables the stream — the server confirms, then sends
  the snapshot, then deltas. Subscribe on an already-subscribed
  session is legal and is the consumer's resync path: it answers a
  fresh snapshot on the same stream. A new Unsubscribe op ends the
  stream without costing the connection — and unsubscribing a
  session that is not subscribed answers plain success, a no-op
  (amended 2026-08-15: that is what makes it idempotent, including
  replayed against the fresh session a reconnect built). A session
  that never subscribes never receives a notification. Both ops join
  the reconnect contract's idempotent replay list (amended there
  this date): re-issuing either after a reconnect is harmless by
  construction.
- **Snapshot, then stream — chunked, linearized.** A snapshot is a
  bounded sequence: a begin marker, entry-carrying parts each within
  the required frame bound, and an end marker; deltas follow: entry
  added, entry removed, entry changed (a mode change arrives as
  changed when one publish carries it, and as remove-then-add when
  the operator issued two operations — consumers debounce; a
  snapshot supersedes every delta before it). Registration is
  **linearized against publication**: capturing the snapshot's table
  and registering the subscriber happen atomically with respect to
  the mutation path's publish, so every delta a subscriber receives
  postdates its snapshot and none falls between. Every entry is
  encodable by construction: a rule path is capped at 4096 bytes at
  rule-add time (new control-plane validation, aligned with the
  host's own PATH_MAX — a longer path can never resolve against a
  host anyway), and one entry always fits one frame.
- **Failure isolation — a subscriber can only hurt itself.**
  Notifications ride a separate bounded per-session queue, drained by
  the connection's writer alongside replies; the mutation path
  enqueues without ever blocking. When the queue overflows — a slow
  or stalled consumer — the queue is dropped and the subscription is
  marked **lapsed**: once the writer drains, the server sends a
  fresh snapshot unprompted. There is no lapse wire message (amended
  2026-08-15): an unsolicited snapshot-begin — one the consumer did
  not just Subscribe for — IS the lapse signal, and the CLI renders
  it as its `lapsed` line before the snapshot. A lapse costs the
  laggard a resnapshot; it never costs the session its file I/O,
  never blocks the operator's control plane, and never poisons the
  connection. Scope stated honestly (amended 2026-08-15): the queue
  isolates a slow-but-draining consumer; a reader that stops reading
  its socket entirely stalls its own connection by ordinary
  transport backpressure, as any dead peer does — which is why the
  example mount manager subscribes on a dedicated session and not
  on a mount's own. (A write failure on the socket itself tears
  the connection down as any write failure does — transport death,
  not subscription fault.) The confirm reply always precedes the
  first snapshot part.
- **Visibility is the filter.** Every entry and event passes the
  session's scope: a hidden rule never appears, and paths are
  expressed relative to the session's mounted subpath, with events
  on rules strictly outside that subtree omitted. A session mounted
  *inside* a share reports the **innermost** enclosing share as the
  entry `/` — its own mount root, with the mount root's *effective*
  mode (amended 2026-08-15: with nested enclosing rules, only the
  innermost reading makes that sentence true; the effective mode is
  the one the resolution engine gives the mount root, so a wildcard
  governing the root's component decides it) — and an event fires
  on `/` exactly when that effective mode changes: an outer
  ancestor's re-mode that the inner rule overrides changes nothing
  and is silent, because the diff is computed on the session-scoped
  entry set itself. The `/` entry's kind is always `directory`
  (recorded 2026-08-15 as built: the handshake refuses a
  non-directory mount root with `ENOTDIR`, so the fact is already
  known without host I/O — the two rule-entry kind cases do not
  apply to the mount root's own entry). The stream must not become
  a side channel revealing what the rules hide.
- **Namespace lifecycle**: deleting the namespace ends the stream —
  a final `ended` event (reason: namespace removed) and no further
  notifications; the session itself keeps serving on its tombstone
  as the lifecycle rules already state, and a frozen tombstone can
  never change again, so ending the stream is the truthful answer.
  A Subscribe on a tombstoned session is refused. Ownership mutations
  reach subscribers as ordinary deltas where they change the entry
  set, computed from the same published-table diff as every delta.
- **Version and negotiation** (amended in the wire contract this
  date, retracting its blanket sentence in place): adding a request
  opcode in the unassigned range, or activating a reserved
  notification opcode, with no change to any existing message, is
  NOT an ABI change and does not bump `PROTOCOL_VERSION`. Discovery
  is the existing unknown-opcode path: a client probing Subscribe
  against an older server receives `ENOSYS` and the connection
  lives. A v1 client against a newer server never subscribes, never
  receives a notification, and is byte-identical on the wire — both
  directions verified against the shipped code (the client already
  ignores unknown notification frames).
- **Client surface**: `voidport subscribe <url>` prints one JSON
  object per line, LF-terminated, flushed per line, events on
  stdout and diagnostics on stderr. The schema, normative: every
  line carries `"v": 1` and an `"event"` field; `snapshot` carries
  `"entries": [{"path", "mode", "kind"}, ...]` (parts aggregated by
  the client into one line); `added` and `changed` carry `path`,
  `mode`, `kind`; `removed` carries `path`; `lapsed` announces a
  server-forced resync (the following snapshot line replaces
  everything); `disconnected` and `resumed` bracket an outage
  (the CLI uses the mount client's reconnect machinery and its
  stall flag); `ended` carries `reason`. Modes are `"rw"`/`"ro"`;
  kinds are `"directory"`/`"file"`/`"unknown"`. Exit 0 after
  `ended`, nonzero on permanent transport failure. The CLI is built
  ON the library API embedders use — one stream implementation, so
  every CLI test exercises the library. The e2e mount manager of the
  criteria ships as a documented example script in the repository,
  and the docs show it.
- **Operator visibility**: the session list and server info report
  whether a session is subscribed, so a lapsing consumer is
  diagnosable from the control plane and the TUI rides along.
- **Ordering**: events are delivered in order per session; the
  server may coalesce a burst, and a legal coalesce preserves the
  final state per path and never reorders across paths.
- New artifacts this increment builds, named so none is assumed: the
  subscriber registry keyed by session with its per-session
  notification queue; the publish-path diff of consecutive published
  tables fanned out under the publish lock; the rule-table
  enumeration of literal rules; the connection writer's second
  intake; the Subscribe/Unsubscribe ops and the notification message
  structs with their golden vectors; the rule-path length validation;
  the session-list `subscribed` flag; the CLI subcommand and the
  example mount manager. (Recorded 2026-08-15 as built: the
  notification opcodes live in their own registry, separate from
  request opcodes, so a notification opcode is never echoed by an
  error response; the snapshot parts reuse the existing
  stream-entry machinery instead of inventing a second
  variable-length list encoding; the linearization point is the
  published-table write lock, which owns the registry; the graft
  pins record each stated target's file kind at pin time, which is
  where entry kinds come from.)

### Acceptance criteria — subscription increment

1. A subscribed session receives, on every subscribe, a begin/parts/
   end snapshot listing exactly the literal non-hidden rules its
   scope and visibility admit, with modes and kinds — proven equal
   to an independent resolution-side enumeration, including under a
   snapshot large enough to need multiple parts.
2. Adding and removing a rule through the control plane reaches a
   subscribed guest as the corresponding delta; a single-publish
   re-mode arrives as `changed`; a two-operation re-mode arrives as
   remove-then-add; an unsubscribed session receives nothing.
3. Hidden never leaks: hidden-rule churn produces no event, and a
   probe subscribing while hidden rules churn sees nothing it could
   not also resolve (asserted against the resolution itself).
4. Subpath scoping holds: a session mounted below the namespace root
   hears only events within its subtree, relative to its mount root,
   and a session mounted inside a share sees that share as `/`
   including ancestor mode changes.
5. Linearization holds under churn: a subscriber registering while
   the control plane mutates concurrently misses no delta relative
   to its snapshot and receives none that predates it (asserted by
   sequence-reconstruction in the test, many iterations).
6. A slow-but-draining consumer lapses instead of stalling anything
   else: under a burst that overflows the notification queue,
   control-plane mutations and the session's own file I/O proceed
   unimpeded, the consumer receives an unsolicited fresh correct
   snapshot (the CLI renders `lapsed` before it), and the session
   list reports the session as subscribed throughout (the operator-
   visibility flag, asserted here).
7. Reconnect resubscribes: kill and restart the server under an
   active subscription — the stream brackets the outage with
   `disconnected`/`resumed`, resumes with a fresh snapshot, and a
   level-triggered consumer reconciles to the correct final set.
   Subscribe/Unsubscribe replay idempotently across the gap.
8. The CLI emits the documented JSONL exactly (schema-checked), and
   the example mount manager drives real mounts and unmounts from it
   end to end, including a mode change and an `ended` teardown.
9. Wire discipline: notification frames obey the reserved-class
   rules (request_id 0, no reply, ordinary framing validation,
   bypassing reply-id retirement); golden byte vectors cover every
   new message type; a v1 client that never subscribes is
   byte-compatible and a subscribing client against a v1 server
   gets `ENOSYS` and a live connection; `PROTOCOL_VERSION` stays 1.
10. A subscribed session that is also a mounted session shows no I/O
    disturbance from a concurrent event storm with a draining
    consumer (latency assertion in the test); namespace deletion
    ends the stream with `ended` while the tombstoned session keeps
    serving, and a Subscribe against the tombstoned session is
    refused.
11. Rule paths longer than 4096 bytes are refused at add time with a
    clear error; existing state files with such rules (none can
    exist through the control plane, but a hand-written file might)
    refuse startup naming the rule.
12. Both gates pass with the new suites executing.

## Xattr policy and special files (normative for the xattr/mknod increment; contract written 2026-08-15, REWORKED the same day after the spec review)

Two decisions drive this increment (both recorded under "Settled
decisions"): xattr policy is expressed as per-namespace glob rules
allowing or denying attribute names for read and write — never a server
global — defaulting to read-allowed and write-denied outside `user.*`,
and bounded in every case by what the server's own OS credentials can
do; and mknod is built, for FIFOs and unix sockets, once the
waits-are-async rework removed the blocking-pool objection.

(The rework is drastic and the reasons are measured. The first draft
mandated async FIFO-open rendezvous on the server; the review's probe
mounted an instrumented FUSE filesystem and showed the guest kernel
installs its own pipe operations on a FIFO inode — the server sees
mknod and NOTHING else, so the machinery targeted an event that never
occurs and its acceptance test would have passed vacuously. The
probes also showed: cross-guest FIFO IPC is impossible by kernel
construction (two mounts of one host FIFO are two independent
pipes); no security.* name is writable by an unprivileged process on
this kernel, in or out of user namespaces; the reused pattern parser
cannot spell a catch-all and refuses separators that are legal in
xattr names; tie-refusal both over-refuses rules that can never
co-match and forbids the advertised layering; and a valid
system.posix_acl_access blob written through an allow rule silently
rewrites the file MODE — a permission change the namespace model
never sees. Every contradicted sentence is replaced below.)

**Xattr rules, per namespace:**

- A namespace carries xattr rules under its own table (beside
  ownership/permission/auth — never a server global): each rule is a
  **name glob** with a `read` and/or a `write` verdict
  (`allow`/`deny`); a rule may state one verdict or both, and an
  unstated verdict falls through to the next-most-specific matching
  rule, then to the defaults — per-verdict fall-through, which is
  what the layering example requires.
- **The xattr glob is its own parse over the shared automaton** (the
  pattern increment's byte-wise `*` engine reused, its parser not):
  a catch-all `*` is LEGAL (there is no enclosing-directory fallback
  to point an operator at), `/` is an ordinary literal byte (the
  kernel accepts it in xattr names — measured), the engine's
  leading-dot rule is unobservable here (no xattr name can begin
  with a dot; the kernel demands a namespace prefix, so the step
  function's dot handling never fires and need not be parameterized
  out), and a glob longer than 255 bytes is refused at add and load
  as a boundary choice (amended 2026-08-15 after the follow-up review: the
  kernel caps NAMES at 255, and since `*` matches the empty run a
  longer glob could still match a short name — the cap is a sanity
  bound on the rule surface, not a matching impossibility, and the
  refusal names the rule). Globs are TOML strings, so a non-UTF-8
  attribute name cannot be spelled by any rule and simply receives
  the defaults — stated, not hidden.
- **Precedence is specificity with deny-wins ties**: among matching
  rules the longest literal prefix wins per verdict axis; where two
  matching rules tie, **deny wins** — order-independent, safe by
  default, replacing the first draft's tie-refusal, which was
  undefined at validation time (no concrete name exists to co-match
  when a rule is added) and forbade sensible layered policies.
  Validation is thereby linear: no overlap computation exists for
  xattr rules, and the refusals are a duplicate glob and a rule
  stating no verdict at all (amended 2026-08-15 at the tail patch,
  retracting "the one refusal": a verdict-less rule would squat its
  glob key while governing nothing, so it is refused at add and
  load; a rule is keyed by its glob; change = remove then add).
- **Defaults, absent any matching rule**: reads allowed; writes
  allowed for `user.*`, denied otherwise. The old blanket refusals
  (`check_name` answering EOPNOTSUPP and filtering names from
  listings) are retired: the mount behaves like a local filesystem —
  a guest can read a `security.*` label and gets the host kernel's
  own refusal writing it back unprivileged, exactly as on ext4 —
  and the compat change is stated: tools that probed EOPNOTSUPP now
  see real xattrs, and an unprivileged `tar --xattrs` restore fails
  on security labels precisely as it does on any local filesystem.
- **The ACL guard, unconditional**: writes to `system.posix_acl_*`
  answer `EPERM` regardless of rules. Measured: a valid ACL blob
  written by the file's owner silently rewrites the mode bits — a
  permission change the namespace's presented-bits and share-mode
  machinery never sees — so an operator may not hand the permission
  model away by glob. Reads follow policy. This answers the
  standing "ACL and capability xattrs interact with privilege" note
  instead of silently retracting it.
- **Denied reads hide**: a name whose read is denied is absent from
  `listxattr` and answers `ENODATA` on `getxattr`; denial must not
  advertise what it denies. Denied writes answer `EPERM`. Order is
  pinned: the share mode runs first — `setxattr` on an `ro` node
  answers `EROFS` before any xattr policy — and the host's own
  errnos pass through untouched where policy allows the attempt
  (including `EPERM` for `user.*` on FIFOs, sockets and symlinks,
  which the kernel permits only on regular files and directories —
  a legitimate outcome, not a policy denial).
- **The privileged-posture truth, stated**: no `security.*` or
  `trusted.*` name is writable by an unprivileged server on this
  kernel, in or out of user namespaces (the VFS demands
  CAP_SYS_ADMIN in the initial namespace — measured). The driving
  SELinux use case therefore requires a privileged server and is
  recorded as such; what the rule surface buys the unprivileged
  posture is operator control of the guest-visible attribute
  surface and honest passthrough of the host's answers.
- Control plane: xattr rules are runtime-mutable per namespace
  (`voidport-ctl xattr` add/remove/list, keyed by glob), persisted in
  the state file, live at next operation; `docs/state.example.toml`
  and the README semantics section are artifacts of the increment.

**Special files (mknod), cut to what the kernel leaves the server:**

- A new **Mknod wire opcode** (mode, umask, rdev; golden byte
  vector; `PROTOCOL_VERSION` stays 1 under the amended stability
  rule) creates **FIFOs and socket files** on the host — both
  unprivileged host objects, measured. Device nodes answer `EPERM`
  at client and server alike; a privileged opt-in stays future work
  as decided. An elder server answers the opcode `ENOSYS`, which the
  client surfaces as `EPERM`, so `mkfifo` against a v1 server fails
  cleanly. `mknod` on an `ro` namespace answers `EROFS` like every
  creation. The attr model already carries the kinds and `rdev` —
  the opcode is the genuinely new wire surface, named as such.
- **The guest kernel owns special-file I/O — and with that, the
  first draft's entire async-rendezvous contract is retracted**:
  once an entry reply carries `S_IFIFO`, the guest kernel installs
  its own pipe operations and no open, read or write ever reaches
  the server (probe-proven: the complete server callback log for a
  successful rendezvous is two lookups and two mknods). There is
  nothing to park and nothing to make async; the waits-are-async
  principle's "second instance" claim is withdrawn — the principle
  stands, this was never an instance of it.
- **Guest-locality, stated for both kinds**: the host inode is a
  marker. Pipe data lives in the kernel that opened the FIFO, and
  two mounts of one host FIFO are two independent pipes — a writer
  on one and a reader on the other never meet (probe: `ENXIO`).
  AF_UNIX connections resolve in the connecting process's kernel
  the same way. Rendezvous and data flow work between processes of
  ONE guest; nothing crosses guests or reaches host-side peers, and
  the README says so where it documents the semantics.

### Acceptance criteria — xattr/mknod increment

1. Xattr rules round-trip through the state file and `voidport-ctl`
   (add, remove by glob, list); a duplicate glob and a >255-byte
   glob are each refused at add AND at load naming the rule; rules
   live per namespace, never global.
2. Precedence holds through a real mount, pinned cases (amended
   2026-08-15: the `security.*` layering pair is guest-unobservable
   in the unprivileged posture — deny answers `EPERM` and allow
   passes through to the host's own `EPERM` — so the observable pair
   carries the criterion): the layering works on `user.*` names
   (`user.*` deny-write beside `user.selinux` allow-write — the
   longer prefix wins, observably in every posture), and the
   `security.*` pair is additionally asserted where the harness runs
   privileged, per criterion 5's posture conditioning; deny-wins on
   an exact tie (`user.*secret*` deny-read beside `user.*public*`
   allow-read: a name matching both reads denied); per-verdict
   fall-through (a write-only rule leaves reads to the next match,
   then the defaults).
3. Defaults and hiding: with no rules, `user.*` writes land and
   `system.*`/`trusted.*`/`security.*` writes answer the pinned
   chain; a denied-read name is absent from `listxattr` and
   `ENODATA` on get, proven with the hidden-rule no-leak probes;
   denied writes leave the host untouched; `EROFS` precedes policy
   on `ro` nodes.
4. The ACL guard: `system.posix_acl_access` writes are refused
   under an explicit allow-everything rule, and the measured
   mode-rewrite bypass is demonstrated blocked (mode bits unchanged
   after the attempt).
5. Passthrough honesty: under a `security.*` allow-write rule the
   guest receives the host's own answer, asserted per the suite's
   actual posture (an unprivileged server passes through `EPERM`;
   where the harness runs privileged the label lands and reads
   back); the EOPNOTSUPP-filter retirement is pinned by reading a
   pre-existing host xattr through the mount.
6. Special files: `mkfifo` and socket-file `mknod` land real host
   inodes through the new opcode (golden vector; `ENOSYS` from an
   elder server surfaces as `EPERM`); rendezvous and data flow work
   between two processes of one guest; **two mounts of one host
   FIFO are proven isolated** (`ENXIO` — the honest cross-mount
   test); device nodes answer `EPERM`; `ro` answers `EROFS`; the
   client module doc drops its regular-files-only claim.
7. The torture xattr class picks up rule-governed churn and
   special-file creation, tolerating exactly the policy-legitimate
   errnos this section pins (a mid-churn rule change answering
   `EPERM`/`ENODATA` is an outcome, not a failure) without
   weakening its throughput or leak invariants.
8. Both gates pass with the new suites executing; existing suites
   stay green.

## TUI log viewer (normative for the log-viewer increment; contract written 2026-08-16, un-deferring the TUI contract's deliberate deferral)

The TUI already writes the server's tracing to a file in TUI modes
precisely so a log screen could exist later; this is later.

- **A Logs screen** joins the TUI's screens: it tails the tracing
  file, newest at the bottom, in follow mode by default; scrolling
  up leaves follow, a keybinding returns to it; a level filter
  cycles through the tracing levels; the Help screen carries the
  bindings as it does for everything else.
- **The file is the interface — no new server surface.** In
  serve-with-TUI mode the file is the process's own and its path is
  known. In attach mode, server-info gains the read-only log-file
  path field (the resident-pins precedent: read-only info growth,
  mutation surface unchanged); the screen tails it where readable
  and shows an honest placeholder naming the path where not (a
  remote or permission-restricted attach reads logs elsewhere —
  stated, not worked around).
- **Tail discipline**: the screen holds a bounded ring of lines
  (pinned in the implementation, thousands not millions), never
  loads the whole file, survives rotation/truncation by reopening,
  and its refresh rides the TUI's existing tick — no new cadence
  machinery.

### Acceptance criteria — log-viewer increment

1. In serve-with-TUI mode the Logs screen shows lines the server
   just logged, follows new lines, and scrollback + return-to-
   follow work (reducer-level tests per the TUI's testing shape).
2. In attach mode against a same-machine server the path arrives
   via server-info and the screen tails it; against an unreadable
   path the placeholder names it and the TUI stays healthy.
3. The ring is bounded (unit-proven), truncation/rotation reopens
   without a stuck tail, and the level filter shows exactly the
   selected levels.
4. The Help screen documents the bindings; the field-coverage list
   picks up the new server-info field.
5. Both gates pass with the new tests executing.

## Runtime listener operations (normative for the listener-ops increment; contract written 2026-08-16)

Listeners have been startup-only since v1 ("added by editing the
file and restarting"), an accepted limitation, not a principle.
This increment retracts it: listeners join the control plane's
runtime-mutable surface like every other piece of server state.

- **Two control operations**: `listener-add` (transport + its
  fields, exactly the state-file shapes: tcp addr, unix path, vsock
  cid/port) and `listener-remove` (identified by its rendered
  endpoint, the way `voidport-ctl` lists it — which obliges the
  server to keep a live bound-endpoint ↔ document-entry mapping,
  today discarded after startup; amended 2026-08-16 after the
  follow-up review named the gap). Remove closes the listener so no new
  connection lands; sessions already accepted on it keep serving
  and die by the ordinary connection-death rules — removal is not
  an eviction.
- **Ordering, per operation** (amended 2026-08-16 — "persist like
  every control mutation" alone points add at an impossible order):
  ADD is bind-unserved → persist → spawn the accept loop; a bind
  failure is the operation's error with the OS's answer and nothing
  persists; a persist failure drops the just-bound, never-served
  socket — no rollback exists because nothing was published.
  REMOVE is the standard validate → persist → swap, where closing
  the listener IS the swap; a persist failure publishes nothing and
  the listener keeps serving.
- **Persistence**: both operations persist to the state file; a
  restart serves what the file says, as always — with the stated
  ephemeral-port exception: a runtime-added tcp `:0` persists in
  source form and re-resolves to a fresh port on restart, exactly
  as a configured `:0` always has. Startup behavior is unchanged.
- **Validation, as it actually exists** (amended 2026-08-16,
  retracting "the same checks in the same code" — the follow-up review
  found two of three named checks are not checks): the vsock port
  range lives in the settings validation, which the mutation path
  must now invoke (it never did — load-time only); the unix-path
  rules ARE the bind and are exercised by reusing it; duplicate
  -endpoint refusal is NEW code — a pre-bind comparison against
  the live listener set answering an already-exists-class typed
  error naming the endpoint, so a duplicate never turns into a
  confusing `EADDRINUSE` against the server's own socket.
  (Ratified 2026-08-16 at the landing: the comparison keys on the
  SOURCE form — pre-bind, a `:0` request has no endpoint yet — the
  same identity the seed dedups on, and the error names the held
  listener's bound endpoint. Load-bearing, not pedantry: two
  identical source entries would make the endpoint↔document mapping
  one-to-many and leave one entry unremovable.)
- **Surfaces**: `voidport-ctl listener add|remove|list` (list may
  reuse server-info's bound-listeners field, which already exists
  for the TUI); the TUI's listener panel picks up changes on its
  refresh cadence with no new machinery.

### Acceptance criteria — listener-ops increment

1. A listener added at runtime accepts a mount immediately, on all
   three transports (vsock loud-skips without the module); the
   state file carries it; a restart serves it.
2. A bind failure (occupied port, bad unix path) answers the OS
   error to the caller, persists nothing, and leaves every existing
   listener serving.
3. Removing a listener stops new connections on it while existing
   sessions keep serving until their connections die by the
   ordinary rules; the state file no longer carries it; removing
   the last listener leaves a control-socket-only server, which is
   legal as decided.
4. Duplicate adds and removes of unknown endpoints answer typed
   errors naming the endpoint; validation parity with startup is
   asserted (the vsock port case).
5. `voidport-ctl` round-trips all three operations; the TUI shows an
   added and a removed listener within its refresh cadence.
6. Both gates pass with the new suites executing.

## Interrupt handling (contract written 2026-08-16; BLOCKED the same day on the FUSE library — parked, not normative)

**STATUS: parked.** The follow-up review probe found the core premise
unimplementable against the pinned library: fuser 0.18 answers
kernel FUSE_INTERRUPT with `ENOSYS` inside its own dispatch, before
any filesystem callback — the trait has no interrupt method and the
low-level module is private, so there is no escape hatch short of
forking the library or reimplementing its session loop. The kernel
then records `no_interrupt` for the connection and never asks
again; probe-verified, no interrupt has ever reached this client.
The follow-up review also found the draft's Cancel semantics under-specified
against the wire contract (response-ness undefined, with one
reading killing elder-server connections) and the abandoned-reply
machinery it cited nonexistent on a live connection. Options when revived:
patch/vendor fuser, upstream an interrupt callback to fuser, or —
the likely answer — fold it into the v2 kernel module, which owns
the kernel interface natively. Until then a signalled process
blocked in a lock wait stays blocked, exactly as on fuser-based
filesystems generally; the section below is the parked draft.

A guest process signalled while blocked in a FUSE operation has its
kernel send an interrupt for the pending request. Today the client
ignores it: the process stays blocked until the operation settles —
for a blocking lock, potentially forever. The contract:

- **The client honors kernel interrupts**: an interrupted in-flight
  operation answers the kernel `EINTR` promptly, per POSIX for the
  interruptible operations (blocking locks foremost; reads and
  writes signal-interrupt per their own POSIX rules where the
  kernel asks).
- **A new Cancel wire op** (opcode addition under the amended ABI
  rule; `PROTOCOL_VERSION` stays 1) carries the request_id to
  abandon. The server cancels a parked wait it can cancel — the
  async lock wait drops its future exactly as a dying connection
  already does, releasing its in-flight permit — and answers
  nothing for the cancelled request (its reply, if racing, is
  discarded by the client like any abandoned reply). Cancel of an
  unknown or already-answered id is a silent no-op: the race is
  legal and both sides tolerate it. An elder server answers
  `ENOSYS` to Cancel and the client's `EINTR` stands alone — the
  wire request then settles whenever it settles and its reply is
  discarded, which is today's behavior with a name.
- **Scope honesty**: operations already executing a host syscall on
  the blocking pool are not cancellable mid-syscall and are not
  claimed to be; the win is parked futures (lock waits) and queued
  work, which is where unbounded blocking actually lives.

### Acceptance criteria — interrupt increment

1. A guest process blocked in `fcntl(F_SETLKW)` through the mount
   and signalled unblocks with `EINTR` promptly; the server-side
   parked wait is cancelled (its permit released, observed via the
   session's in-flight accounting) and the lock stays free for the
   next taker.
2. The Cancel race is safe both ways: cancel arriving after the
   answer is a no-op; an answer racing the cancel is discarded by
   the client with no state corruption (asserted with the wire
   harness).
3. Elder-server interop: `ENOSYS` on Cancel leaves the client's
   `EINTR` correct and the eventual reply discarded; a v1 client
   never sends Cancel; golden vectors cover the new op.
4. The torture lock class gains signal storms (waiters signalled
   mid-wait) without weakening its invariants.
5. Both gates pass with the new suites executing.

## Multi-connection mounts (contract written 2026-08-16; PARKED the same day — the spec review measurably refuted its premises)

**STATUS: PARKED (2026-08-16)** — the single-connection stack already
extracts 92% of per-connection throughput, field workloads are
metadata-heavy, and the v2 data plane supersedes connection scaling;
revisit only if a real workload hits the bulk ceiling. The spec review's
probes had overturned the numbers this section was built on:

- The "25k→41k ops/s" basis came from FOUR MOUNTS (four FUSE queues,
  four sessions, four client processes), and the operations that
  produced it are metadata operations this section routes to the single
  metadata connection — the design forecloses its own cited win.
- The "~1850 MiB/s vsock transport ceiling" was a PER-CONNECTION
  ceiling: re-probed with N readers on N connections, four vsock
  connections carried 3429 MiB/s — 1.85x the "ceiling" — so bandwidth
  DOES scale with connections; but every vsock number on the rig is
  vsock_loopback with no virtio device or vhost worker in the path, so
  the criterion-6 attribution is unfalsifiable here.
- With the readahead caps unchanged (as this section required), a
  single-handle stream pins ~1 MiB outstanding regardless of connection
  count (Little's law on the measured RTTs): connection scaling needs
  the per-mount in-flight cap to scale and needs multi-handle workloads
  — contradicting two sentences at once.
- Head-of-line: a separate connection recovers only ~40% of the metadata
  latency penalty under bulk load (+20-23% residue remains, measured —
  shared session mutexes, blocking pool, host CPU), so criterion 3's
  "matches idle within noise" is unreachable by connections alone.
- Plus contract holes: AttachConnection reply/refusal semantics
  undefined against the handshake taxonomy; connections-per-session
  unbounded against the session-slot posture.

The alternative this left on the table was to REWORK multi-connection as
an aggregate-bandwidth feature for multi-handle bulk workloads —
per-mount readahead caps scaling with connections, honest ~1.5-2x
aggregate claims at 2-4 connections, modest latency framing, the wire
semantics completed. Parking won: the current single-connection stack
already extracts 92% of per-connection throughput and the two-class
writer took the large half of the latency win, the field workloads are
metadata-heavy, and the v2 virtio shared-memory data plane supersedes
connection scaling entirely. Raw data kept out of tree. The section
below stands as the paused draft, not as authority.

One mount, several connections over one transport: a **metadata
connection** — the original connection, the session's liveness anchor —
plus up to N **bulk connections** that join the same session. Bulk
traffic stops sharing a byte stream with interactive operations, which
removes head-of-line blocking structurally instead of scheduling around
it, and parallelizes server-side processing on the measured 25k→41k
ops/s basis.

- **Wire surface, two new ops** (opcode addition under the amended ABI
  rule; `PROTOCOL_VERSION` stays 1): `ConnectionTicket`, served only on
  the session's metadata connection, answers an unguessable 128-bit
  token bound to the session; `AttachConnection { token }`, sent as a
  new connection's FIRST frame in place of `Hello`, binds that
  connection to the token's session as a bulk connection. The token
  lives and dies with the session; presenting a dead or unknown token
  refuses the connection. The trust posture is the transport's, as
  everywhere: the token is a binding mechanism, not an auth scheme, and
  THREAT-MODEL says so.
- **One session, shared tables**: a bulk connection serves requests
  against the session's node and handle tables exactly as the metadata
  connection does; request ids stay per-connection per the wire
  contract, so connections have independent id spaces by construction.
  Per-session caps span connections (the in-flight sum, not
  per-connection sums). Notifications and the subscription stream ride
  the metadata connection only.
- **Client routing**: reads at or above the bulk threshold and all
  readahead prefetch issue onto bulk connections (least-loaded among
  them); everything else — metadata, small reads, writes, locks — stays
  on the metadata connection. A reply returns on the connection that
  carried its request. `--connections N` configures bulk connections
  (default from this increment's own measurements; `0` disables and is
  exactly today's behavior).
- **Lifecycle**: the metadata connection's death is session death, as it
  is today. A bulk connection dying alone is NOT session death: the
  client re-attaches with the token, and written-unanswered reads on the
  dead connection follow the existing replay discipline (idempotent —
  resent on the replacement or the metadata connection). Session death
  invalidates the token and closes every connection; server-side
  teardown of a session reaps its connections. An elder server answers
  `ConnectionTicket` with `ENOSYS` and the client stays
  single-connection silently — v1 interop in both directions.
- **Composition**: the readahead engine issues prefetch onto bulk
  connections, its caps unchanged; the two-class reply writer stays as
  shipped on every connection (on bulk connections it is naturally
  near-moot, on the metadata connection it still guards the rare large
  reply).
- **The ceiling question, answered by this increment with numbers** (the
  readahead landing measured a ~1850 MiB/s aggregate vsock ceiling and
  could not attribute it): aggregate sequential throughput over 1, 2 and
  4 bulk connections on one vsock device — if it scales with connections
  the cost was per-connection protocol processing; if it stays flat the
  ceiling is the virtio-vsock device/vhost worker itself, and the
  multi-connection throughput claim for vsock is capped accordingly.
  Either answer is recorded in PERFORMANCE.md as measured, and the
  latency win stands regardless.

### Acceptance criteria — multi-connection increment

1. Connection attach and detach work end to end: a mount with
   `--connections 2` holds three connections bound to one session
   (observable via the session list's connection count or equivalent
   surface), a detached bulk connection re-attaches with the token, and
   `--connections 0` is byte-identical to today.
2. Routing holds: under a mixed workload, bulk reads and prefetch
   observably travel bulk connections and metadata stays on the anchor
   (client test-support counters per connection); replies return on
   their request's connection.
3. Head-of-line is eliminated structurally: metadata operation p50 under
   saturated bulk prefetch on bulk connections matches the idle baseline
   within noise — better than the two-class writer's single-connection
   bound, and asserted against it.
4. Lifecycle: killing one bulk connection leaves the session serving and
   that connection re-attached with reads healed per the replay
   discipline; killing the metadata connection is session death exactly
   as it is today; a dead session's token refuses attach;
   no connection or token leaks across session teardown (asserted with
   the teardown suite's shapes).
5. Interop: a v1 client never sends the new ops and is byte-identical;
   this client against an elder server gets `ENOSYS` on
   `ConnectionTicket` and runs single-connection with no user-visible
   difference; golden vectors cover both new message types.
6. The ceiling question is answered: aggregate throughput at 1, 2 and 4
   bulk connections on vsock AND unix, measured and recorded in
   PERFORMANCE.md with the attribution stated.
7. The torture smoke stays green, and a multi-connection torture case
   (mixed classes under `--connections 2`) passes all invariants.
8. Both gates pass with the new suites executing.

## Readahead (normative for the readahead increment; contract written 2026-08-15, REWORKED 2026-08-16 after the spec review)

The decided shape: a 256 MiB evict-unread pool and no per-chunk round
trip, with the negotiated-stream escalation's frame shape pre-agreed.

(The rework is measured, on the live production mounts. The first
draft cited a head-of-line mechanism that does not exist — the
writer's replies-first bias covers notifications, and bulk read
replies share one FIFO queue with metadata replies, measured at
3.2-13x the promised latency bound under prefetch depth. It
mandated 1 MiB chunks whose measured pipelining ceiling is 1.60x —
under the doubling criterion — while 128 KiB measures 2.24x. Its
doubling claim was impossible in cached mode, which is already
bandwidth-saturated and kernel-readahead-served. And it left the
window, cap, in-flight bound, block alignment, TTL mechanism,
reconnect path and truncate invalidation unstated. Every
contradicted sentence is replaced.)

- **Scope: direct data-caching mode only.** The engine activates on
  mounts whose NEGOTIATED data-caching mode is direct (amended
  2026-08-16: keying on the flag alone is wrong — a kernel without
  the mmap capability keeps the flag but falls back to normal
  caching, where the engine must not run), where no kernel
  readahead exists and reads are wire-immediate; cached mounts are
  untouched — the kernel's
  own page cache and readahead already serve them at the measured
  saturation, and client prefetch there would double-buffer for
  nothing.
- **Client-side, no wire change.** Windowed pipelining over the
  existing read operation, with the load-bearing numbers pinned
  from measurement: prefetch chunks are **128 KiB** (the measured
  throughput knee; 1 MiB chunks cap at 1.60x while 128 KiB reaches
  2.24x, and a 128 KiB frame occupies the wire ~120 µs against a
  1 MiB frame's ~1 ms). A per-handle sequential detector
  (consecutive reads at the expected next offset) opens a window at
  4 chunks, doubling while the reader keeps pace (has consumed at
  least half the fetched-but-unread bytes) up to a **coverage cap
  of 4 MiB per handle**, with in-flight requests capped at **8 per
  handle and 16 per mount** — the caps that bound both the measured
  latency interaction and the engine's own contribution to the
  server's reply queue (at most 2 MiB of serialized prefetch
  replies per mount; the application's own in-flight reads are
  outside these caps). "The window reaching EOF"
  means coverage extends to EOF within these caps, never hundreds
  of chunks in flight. Random access or a seek resets the handle's
  window; a short read marks EOF and stops the window.
- **The head-of-line mechanism is built, not assumed**: the server's
  connection writer gains **two reply classes** — bulk read replies
  above a size threshold drain after everything else, FIFO among
  themselves — so a metadata reply never queues behind pipelined
  read replies. With that scheduler and the pinned chunk size, an
  interactive operation's added latency under saturated prefetch is
  bounded by one 128 KiB frame's transmission plus scheduling,
  and the acceptance criterion carries the number.
- **The pool**: one per mount process, default 256 MiB cap,
  configurable (`--readahead N`, `0` disables the engine). The cap
  is a ceiling, not an allocation — an idle mount holds nothing,
  and the pool fills only under sequential load. Blocks live on the
  128 KiB chunk grid; consumption is tracked per block and a block
  evicts when fully consumed (serve-once per byte range — the
  kernel's reads may straddle block boundaries and are served by
  copying across them). Issued prefetch **reserves** its budget at
  issue time, so arrivals never overshoot; a full pool idles the
  prefetcher instead of evicting unread blocks a reader is
  approaching. Each block carries its fetch time, and a block older
  than the mount's attr TTL is dropped instead of served — that is
  the mechanism behind the coherence criterion, not an aspiration.
- **Cancellation, honestly**: closing the handle drops its window,
  stops issuing, and frees its blocks; chunks already in flight
  still cross the wire — bounded by the in-flight cap at ~1 ms of
  link occupancy — and their replies are discarded on arrival.
- **Coherence**: under `--direct-io`, sequentially prefetched bytes
  relax per-read freshness to the mount's attr-TTL bound for
  exactly those bytes, enforced by the block timestamps above. A
  local write through any handle drops the file's blocks; so does
  any setattr that changes size or mtime — truncation included. On
  a reconnect the pool drops entirely (the session's identifiers
  died with it) and windows reset; in-flight prefetch reads are
  ordinary idempotent reads under the required replay discipline, and
  their replies are discarded where the window was cancelled. A
  degraded mount's error on a prefetch read drops the window; the
  reader's own reads meet the resilience contract's surface
  unchanged. `--readahead 0` restores strict wire-immediate reads.
  Documented beside the flag, in the man page and in
  PERFORMANCE.md.
- **The escalation, sketched and deliberately not built now**
  (amended 2026-08-16 after the follow-up review caught the contradiction):
  the negotiated stream mode's earlier "stream id in the request_id
  slot of a notification frame" is RETRACTED as pre-agreed — the
  wire contract requires request_id 0 on notification frames and
  the framing validation poisons a connection that violates it, so
  the escalation would need a taxonomy amendment (a stream frame
  class of its own, or a stream-id field), not a free ride on
  existing slots. The arithmetic that defers it stands: it is built
  only if this increment's measurements show the per-chunk request
  cost mattering, and any such build is its own decided increment
  with its own wire-contract amendment.

### Acceptance criteria — readahead increment

1. Sequential read throughput through a real direct-mode mount at
   least doubles against the pre-change commit, measured with the
   voidport-bench seq-read scenario at its 128 KiB read discipline
   (amended 2026-08-16: the discipline is part of the criterion —
   under a 1 MiB-read discipline the vsock baseline already
   sits against the transport ceiling and no implementation could
   pass), on unix socket AND vsock transports, same machine,
   baseline measured from a read-only worktree, backing store on
   the guest root as every PERFORMANCE.md section uses. Where a
   transport's measured aggregate ceiling (the concurrent-reader
   probe under the pinned caps) sits below twice the baseline, the
   criterion for that transport is reaching at least 85% of that ceiling
   instead (decided 2026-08-16 at the landing: the vsock wire tops
   out at ~1850 MiB/s against a ~950 MiB/s baseline — a 1.95x
   physical maximum — and the engine reached 92% of it; a criterion
   demanding more than the wire carries tests the wire, not the
   work; on a slower backing store, where round trips genuinely
   dominate, both legs measured 3.1-4.3x). The whole-file case
   shows coverage reaching EOF within the caps. (Cached mode is
   exempt by scope: it is measured saturated and the engine does
   not run there — asserted.)
2. The pool never exceeds its cap including reservations, observed
   through the client's own counters (exposed as test-support API —
   no new control surface) while reading a file set larger than the
   pool; per-byte serve-once and full-consumption eviction are
   unit-proven on the pool; an idle mount holds zero pool bytes.
3. Random access is unharmed: rand-read-4k stays within 15% of the
   pre-change commit (a chosen tolerance ~4 points above the
   scenario's documented 11.2% spread — amended 2026-08-16, the
   earlier citation of a documented 15% was false), and a seek
   mid-file resets the window without serving stale positions.
4. Early close: no new prefetch is issued after close (client
   counters), in-flight replies are discarded, blocks freed; the
   residual link occupancy is bounded by the in-flight cap.
5. Coherence holds: a host-side change lands within the attr-TTL
   bound for prefetched bytes (the block-timestamp mechanism,
   unit-proven and e2e-asserted with the directio suite's
   discrimination shape); a local write and a shrinking truncate
   each drop the file's blocks immediately; `--readahead 0`
   restores per-read freshness.
6. Interactive latency under load, with the number: a metadata
   operation issued during saturated prefetch on the same
   connection completes within the op baseline plus 2 ms at the
   pinned chunk size and caps — measured p50 over repeated probes,
   against the two-class writer (whose scheduling is also
   unit-proven: a small reply enqueued after N bulk replies drains
   first).
7. The wire is unchanged: golden vectors untouched, no new opcodes,
   a v1 peer interoperates byte-identically; the two-class writer
   is server-internal scheduling with no frame change.
8. Reconnect composes: kill and restart the server under active
   prefetch — the pool drops, windows reset, and the reader's reads
   behave exactly as the resilience contract rules for handle-bound
   I/O (stale errnos on descriptors held across the gap, success on
   reopen — amended 2026-08-16: "heal" invited a reading the
   contract forbids); no stale pre-reconnect block is ever served
   after (asserted).
9. Both gates pass with the new suites executing, and the README,
   man page and PERFORMANCE.md carry the flag and the numbers.

## Write-path decisions (2026-08-17): what ships in v1, what parks, and the law that decided it

The write-streaming contract below went through its own probing spec
review the day it was written, and the review measured the picture
per transport: on vsock — the deployment transport — the server's
page-cache apply (~2.1 GB/s) does outrun the wire (~1.1 GB/s) and
streaming would pay; on local unix and TCP the wire (6.4-7 GB/s)
outruns the apply and the premise inverts. It also established two
kernel facts that make early acknowledgment unsafe without guards:
a stat racing an unconfirmed write regresses the inode size and can
fault mapped pages, and an mmap page fault inside the
acknowledgment-to-confirmation window caches pre-write bytes with
nothing left to invalidate them. Sound fixes exist — absolute
node-scoped drains, client-side invalidation at confirmation,
sequence-stamped per-handle apply queues — but each is a guard
bolted onto an architecture that fights them.

**The standing design law (decided 2026-08-17)**: hazards of this
kind are fixed through architecture, never through imperative code
layered on top. When a shape accumulates guards, the architecture is
reconsidered instead — whatever better shape that means. Applied
here: **write streaming parks to v2**, whose shared-memory data
plane gives the throughput structurally — the guest writes host
memory, the host kernel owns every coherence question this contract
was accumulating guards for — and vsock, the one transport where
client streaming pays, is exactly what that data plane replaces.

**What ships in v1 from this work**, each its own small increment:

- **The stripping-defect fix**: on a direct-io mount the kernel
  marks every write that must clear privileged bits and delegates
  the clearing; the client forwards the mark (the write request's
  reserved flags field gains its first meaning, an elder server
  ignores it — fail-open for stripping under version skew, stated)
  and the server clears what the mark demands. Verified against the
  kernel and the FUSE library: the mark needs no capability
  negotiation and the library carries its surface. This lands with
  the privileged-bits increment, whose recording it also strips.
- **Parallel direct writes, honestly scoped**: the open reply
  announces the capability so applications using asynchronous I/O
  overlap in-place writes on one file. The kernel still serializes
  append, size-extending, and ever-mmap'd files under its exclusive
  lock — the announcement helps in-place overwrites only, and its
  criterion says so.
- **Host-side direct I/O postures** (the caching model stated as
  decided): a mount's direct-io setting is guest-side presentation —
  it exists to keep the guest from holding a page cache so the
  host's cache is the one cache; the server's backing I/O rides
  that cache. Reaching the storage uncached becomes a per-namespace
  setting with three postures: the cached default; passthrough,
  where a guest handle's O_DIRECT opens the backing file O_DIRECT
  with its alignment demands surfacing as the local filesystem
  gives them; and always, every backing open uncached, under which
  the bound moves from the wire to the storage.

### Acceptance criteria — parallel-direct-writes increment

1. The open reply announces the capability on direct-io mounts and
   an asynchronous-I/O writer doing in-place overwrites of a
   preallocated, never-mapped file measurably exceeds the serial
   baseline on one file; the census proves several writes in
   flight.
2. The honest bounds are pinned: append and size-extending writes
   stay kernel-serialized (census: one in flight), and the
   regression arm proves announcing the capability changed nothing
   for the plain sequential writer.
3. Both gates pass with the new tests executing.

Two facts from the increment's first build pass, folded in dated
2026-08-17: the cached default is a stated CHANGE from the de-facto
tree — the server's open-flag mask passed a guest handle's O_DIRECT
straight to the backing open, unpinned and untested; the decided
caching model masks it by default, so only the postures grant it.
And an uncached posture owes a production contract the first draft
lacked: the server's I/O buffers are not block-aligned, and direct
I/O refuses misaligned buffers regardless of the guest's own
alignment — so **direct backing I/O serves through an aligned path
at the single I/O site**: the server learns the backing file's
direct-I/O alignment (the statx direct-alignment fields, with the
logical block size as the fallback) and bounces direct reads and
writes through buffers aligned to it. An aligned guest request
serves; a request the backing filesystem itself would refuse
answers that refusal.

### Acceptance criteria — host-direct-io-postures increment

1. The per-namespace setting round-trips the state file and the
   control plane's namespace mutation, persisted, live at the next
   open; the default posture masks a guest handle's O_DIRECT, a
   stated change pinned by test, and everything else is
   byte-identical to today.
2. Passthrough: a guest handle opened O_DIRECT gets a backing open
   with O_DIRECT — proven by the backing descriptor's flags — an
   ALIGNED request round-trips real data through the uncached
   descriptor, and a request the backing filesystem refuses
   locally answers the same errno; a handle without O_DIRECT rides
   the host cache unchanged.
3. Always: every backing open in the namespace carries O_DIRECT,
   reads and writes alike, aligned requests serve through the
   bounce path, and the performance report states the measured
   bounce cost and where the throughput bound moved.
4. The artifacts carry the setting: the state example, the README
   semantics section, and the man pages.
5. Both gates pass with the new suites executing.

## The parked write-streaming contract (2026-08-17, parked the same day by the design law above — kept as the record, with its review findings noted in place)

- **Scope: direct-io mounts.** A cached mount already streams through
  the guest page cache. Handles opened `O_SYNC`/`O_DSYNC`/`O_DIRECT`
  are excluded: every such write confirms server-side before the
  guest proceeds, unchanged.
- **The caching model, stated as decided** (clarified 2026-08-17): a
  mount's direct-io setting is guest-side only — it exists to keep
  the guest from holding a page cache so the HOST's page cache is
  the one cache in the system. The server's backing I/O rides that
  host cache as any local program's would, which is precisely why
  the server outruns the wire and the host kernel owns coherence
  and writeback behind it. A guest handle's `O_DIRECT` does not
  reach the backing file today; that is presentation, and the
  posture below is what changes it.
- **Host-side direct I/O is its own namespace setting**, three
  postures: the default rides the host cache as above;
  **passthrough** opens the backing file with `O_DIRECT` exactly
  when the guest handle asked for it, alignment demands and all —
  an unaligned request answers the same error the local filesystem
  gives; **always** opens every backing file uncached, for the
  operator who wants no host caching at all. Under "always" the
  storage, not the wire, may become the bound — streaming stays
  correct (the window, order and barriers are unchanged), the
  throughput expectation moves, and the performance report says so
  where it is measured.
- **Early acknowledgment**: the client answers the kernel's write
  once the frame is queued on the connection — the guest's write
  returns at wire speed the way a local write returns at page-cache
  speed, and durability is the barrier's job, exactly as local
  semantics have it. No data is retained client-side: the transport
  owns the bytes once queued, and there is no replay — the
  resilience posture is unchanged, a reconnect fails whatever was
  outstanding and poisons those handles.
- **The window is a counter**, not a buffer: unconfirmed writes per
  handle, bounded in count and bytes (the bounds measured before
  they are pinned, stated at their constants). A full window makes
  the next write wait — backpressure, never an error. The counter
  bounds the failure blast radius and the barrier drain time.
- **Order is the wire's.** Frames leave in submission order on one
  ordered stream, and the server applies same-handle requests in
  arrival order — a per-handle serialization at the apply site,
  cheap because the apply is a page-cache copy; cross-handle
  concurrency is untouched. Read-after-write, append, and
  overlapping writes on one handle are then correct by
  construction; cross-handle and cross-mount races are exactly what
  they are locally.
- **Node-scoped operations drain first**: a getattr on a node with
  unconfirmed writes, and any setattr touching it, wait for those
  confirmations — size and times read as the guest just wrote them,
  and a truncate cannot pass writes in flight. This is the one
  place the engine holds a non-barrier operation, and it holds it
  for the handle's own unconfirmed tail only.
- **Barriers drain**: fsync, fdatasync, flush and release complete
  only after every outstanding confirmation for the handle arrives,
  then act as today. A failed server write poisons its handle; the
  poisoning errno answers the next write or barrier on that handle
  exactly once. A guest that never syncs still learns at close.
  Teardown joins the accounting: a live server is drained before
  the unmount; a dead one already poisoned the handles.
- **Memory-map writeback rides the same path**: a page flushed by
  the guest kernel is a write like any other, early-acked and
  counted, and the invalidation contract of readahead is kept by
  invalidating after confirmation, not after acknowledgment.
- **Parallel direct writes**: the mount also announces the
  parallel-direct-writes capability, so an application using
  asynchronous I/O issues concurrent writes on one file instead of
  serializing under the guest kernel's per-file direct-write lock.
  With per-handle apply order on the server this is safe by the
  same construction.
- **The server side gains one rule** — the per-handle arrival-order
  apply — and nothing else changes on the wire: same frames, same
  replies, replies still confirm in completion order across
  handles.

### Acceptance criteria — write-streaming increment

1. Sequential write throughput on a direct-io mount reaches a
   stated fraction of the transport's measured bulk ceiling in a
   paired A/B (engine off is today's behavior); the performance
   report carries the numbers per transport.
2. Order is pinned by test: same-handle write-then-read returns the
   new bytes; append through one handle interleaves nothing;
   overlapping same-handle writes end with the later bytes; a
   getattr after a write reports the written size without an
   intervening fsync.
3. Durability barriers hold under fault injection: a server killed
   mid-stream surfaces the failure at the next barrier on every
   affected handle, exactly once per handle; an fsync that returned
   success is proven durable in the backing file; teardown with a
   live server drains before unmounting.
4. Excluded modes are proven excluded: O_SYNC and O_DIRECT handles
   confirm each write before the next departs (opcode census), and
   cached mounts are byte-identical to today.
5. The window bounds are measured and stated; a full window
   backpressures without error; the counter joins the
   signalled-teardown settle accounting.
6. The torture harness's append and churn classes run green against
   the engine with restarts active, and the crash-consistency
   assertions still hold.
7. Both gates pass with the new suites executing; the performance
   report carries the A/B.

## Recorded metadata (normative pattern; decided 2026-08-17 — one design for everything of this kind; first instance PROVEN 2026-08-17 by the privileged-bits landing, its measurement arms recorded as owed in that increment's criteria)

Whenever the guest expects a real filesystem to hold something the
host backing cannot represent — because the server's user lacks the
privilege, or the host would give the value a meaning it must not
have there — the answer is always the same mechanism, never a
special case: the guest truth is **recorded with two roles split**.
In memory, the record store is keyed by the node identity the
descriptor budget proved — device, inode, kind, birth time — which
is what makes hard links correct by construction (one inode, one
record, every name presents it) and is safe within a boot. On
disk, a **per-namespace sidecar file** beside the state file
persists each record as its identity snapshot minus the
boot-unstable device, plus its last known backing location as a
locator; at load every row **revalidates** — the locator is
statted, the row survives only if inode, kind and birth time
match, and rebinds to the fresh full identity. A backing without
birth times drops its rows at reboot, stated: recorded truth is
only ever lost conservatively, never resurrected onto an unrelated
file.

The store is owned by the **registry, per namespace name** — one
instance across every republish. A session captures its store
handle at handshake, beside its namespace resolution, so a deleted
namespace does not take the store from a session still serving;
removal deletes the sidecar with the namespace — recorded truth is
namespace configuration and dies with it — and retires the store,
which accepts no further writes; a re-created name starts a fresh,
empty store. The sidecar is read **once per name**, when the store
is created — server startup for a name the state file holds, or
the namespace-create that introduces one — never at namespace
build, which runs on every control mutation. No two tables ever
race one sidecar. The namespace snapshot stays immutable; reads are an
atomic pointer load of a copy-on-write map — free on every path
including the pinless listing walk, no lock on the request path —
and the rare writers rebuild and swap under the store's own small
mutex — and a strip that finds nothing to clear writes nothing: no
rebuild, no swap, no debounce reschedule, so a chunked write's
repeated marks cost one update at most. Mutation updates the store
immediately and persists the sidecar **debounced** under the
rename-over discipline, with the cadence at its constant; the
daemon flushes every store after both planes stop and before the
instance lock drops; the temporaries ride the orphan sweep's
prefix; the sidecar is the state file's own serde-backed TOML with
the state file's refusal posture when it does not parse; and its
file name is a bounded, injective derivation of the namespace name
under the state file's prefix, since the name grammar is wider
than a filename's. The crash contract is a local filesystem's for
recent metadata, plus the flushes a local filesystem also gives:
the unflushed tail may be lost, the file is always a whole
document, nothing is ever half-written. A rename through the
server updates the locator; a host-side rename leaves it stale,
which the next revalidation drops, conservatively. The same two
switches exist every time — a per-namespace server switch that
disables the feature loudly, and a client mount option that opts a
mount out; enforcement of recorded meaning is always the guest
kernel's, in its own trust domain.

(Decided 2026-08-17 on the fourth shape, after three rejections
the reviews measured or proved structural. Rejected: the per-file
extended attribute — a hiding problem on four xattr paths,
per-session caches needing cross-session invalidation, a per-entry
host syscall on the pinless listing walk, a recording-write
failure mode of its own, and a file-kind restriction from the user
xattr namespace. Rejected: the identity-keyed table inside the
state document — persisted device-and-inode identity measurably
recycles across boots, which would resurrect privileged bits onto
unrelated files, and riding the state document's persist put a
milliseconds-scale global-lock cycle on the data path, against the
no-global-locks law. Rejected: the purely path-keyed sidecar — a
path key cannot follow an inode with two names, so hard links
present and strip inconsistently; several grafts alias one
relative path; and a table living inside the republished namespace
snapshot makes two authorities over one file. The split-role shape
keeps every strength with none of the failures: identity in memory
is link-correct and boot-local, revalidated locators on disk
persist without ever being able to resurrect, and registry
ownership makes the authority single by construction. The trade,
stated: recorded truth does not travel with host-side copies or
renames of the backing file — the server is the bookkeeper, not
the file.)

Known instances of the class, each its own increment on the shared
mechanism:

- **Privileged mode bits** (setuid, setgid) — the first instance,
  contracted below.
- **File capabilities** (the security capability attribute an
  unprivileged server cannot set host-side) — same shape as the
  bits; queued.
- **Device nodes** — mknod for character and block devices, refused
  today under the special-file decision, becomes representable: a
  placeholder on the host, the device identity recorded, the guest
  sees a device node whose meaning its own kernel supplies. This
  deliberately re-opens the earlier deferral when its increment is
  taken up; recorded here so the deferral and the pattern do not
  contradict silently.
- **Ownership beyond the host's reach** — a chown the host refuses
  the server (arbitrary owners under passthrough without
  privilege) could record instead of failing. This one extends the
  decided ownership-mapping design instead of sitting beside it,
  so it needs its own contract against that section before
  anything is built.
- **Privileged extended attributes** (trusted and system
  namespaces) — recordable under the same mechanism; queued behind
  the xattr-rules interaction.

## Privileged bits (normative for the privileged-bits increment; contract written 2026-08-17 — the first instance of the recorded-metadata pattern)

The guest should see a filesystem as close to a real one as
possible: setuid and setgid work, persist, and strip exactly as
local semantics demand — while the host-side backing file never
carries a privileged bit the server's own user set. The two truths
are reconciled by recording, per the pattern above.

Reworked 2026-08-17 four times, each after a probing review; every
decision below is the current rework, built on the pattern's
split-role store.

- **Recording**: the privileged bits a guest sets live in the
  namespace's record store — identity-keyed in memory, so a hard
  link's every name presents and strips the one record; persisted
  through the revalidating sidecar. Every file kind records.
  Presentation ORs the recorded bits into the mode the guest sees
  at the one attribute funnel; a host file genuinely carrying bits
  presents them as-is; the guest's xattr surface is untouched.
  Privileged bits apply to host-backed nodes — a synthesized
  directory has no backing identity and keeps its read-only
  posture.
- **Setting is an assignment, never a merge**: the mode a chmod or
  create delivers has already passed the guest kernel's own
  permission and setgid-clearing logic under the caller's full
  credentials — the wire carries the post-VFS mode, which the
  mount's unconditional default-permissions posture guarantees,
  closing the group-membership predicate no wire field could
  carry. The server takes that mode's privileged bits as the
  record's NEW VALUE — bits present record, bits absent DELETE the
  record, so a plain chmod without them clears exactly as local
  semantics demand and nothing can resurrect through the
  presentation OR — and **masks them out of the host mode it
  applies**, chmod and create through the one shared masking rule
  (a stated change from today, where the host mode received them
  verbatim where the host allowed it). The store update is
  immediate and authoritative; the sidecar follows per the
  pattern's debounce and flush rules.
- **Presentation is a memory merge at the one funnel**: the
  attribute presenter ORs the table's bits into every
  attribute-bearing reply — getattr, lookup, the readdirplus
  entry, the create and mkdir replies, the setattr reply, and the
  namespace root's own attributes. No host syscall, no per-session
  cache, no invalidation: the table is the single point of truth
  and a lookup in it is the whole cost, on every path including
  the pinless listing walk.
- **Stripping follows the kernel's own delegation, with no
  negotiation**: the running kernel marks direct-io writes by
  callers without the file-mode privilege unconditionally — probed
  and measured on the deployment kernel, and the increment's
  census criterion re-proves it before anything lands. The client
  forwards the mark on `write_flags` — the field that has carried
  must-be-zero-on-send, ignore-unknown-on-receive from day one —
  on **every chunk of a split write**, stripping being idempotent.
  The server clears per the mode-only local rule: setuid always,
  setgid when group-execute is set — the kernel's own write-strip
  predicate, fully evaluable from the mode. Clearing is a table
  update and a masked host chmod where host bits are involved. On
  a cached mount the kernel strips through its own paths today —
  the capability probe on writes, its own mode change on truncate
  — and keeps doing so with the table following the mode changes
  it sends; no INIT capability is negotiated, so none of the
  kernel's own stripping is ever turned off. An elder server
  ignores the unknown flag and strips nothing — fail-open for
  stripping under version skew until both sides update; stated,
  not hidden.
- **The operator surface is the house shape**: a per-namespace
  switch in the state file (enabled by default), runtime-mutable
  through the existing namespace mutation of the control plane,
  persisted like every mutation, live at the next operation.
  Disabled, presentation masks privileged bits — recorded and
  host-real alike — and a chmod attempting to set them refuses
  (EPERM). The client mount option does the same for one mount —
  stronger than the classic nosuid, which honors nothing but still
  shows the bits; this masks them. **Under any masked
  presentation — the disabled switch or the mount option — a
  delivered mode neither records nor deletes**: the guest was
  shown a mode without the bits, so a read-modify-write chmod from
  it must not destroy recorded truth other mounts still present.
  Artifacts: the state example, the README semantics section, and
  the man pages carry both switches.
- **Enforcement is the guest kernel's**, in its own trust domain:
  the server presents bits, the guest decides what exec does with
  them — the posture THREAT-MODEL states for every presented
  attribute, extended with one line: a record presents its bits
  even where the host backing sits on a mount whose own kernel
  ignores them.

### Acceptance criteria — privileged-bits increment (reworked 2026-08-17)

1. A guest chmod adding setuid or setgid succeeds on every file
   kind, the bits present through every mount, every
   attribute-bearing reply and a host-backed namespace root,
   survive server restart and remount through the revalidating
   sidecar (a cold listing is complete), present identically
   through every name of a hard link, and the backing file's host
   mode never gains them — through chmod AND through creates
   carrying a privileged mode, pinned by tests that the host mode
   is masked on both paths.
2. Stripping matches local semantics in a paired comparison on
   both mount modes: a write by a caller without the file-mode
   privilege clears setuid and clears setgid when group-execute is
   set (the mode-only predicate), on every chunk of a split write;
   truncate clears through the kernel's own path with the table
   following; a chmod by an out-of-group caller arrives already
   stripped by the guest kernel, pinned by test; the direct-io
   defect case is the regression test.
3. The wire census proves the mark arrives without any INIT
   capability negotiation on the deployment kernel, and that
   negotiating nothing left the kernel's own cached-mount and
   truncate stripping untouched.
4. The disabled namespace masks and refuses per the contract,
   binding at the next operation that reaches the server, with the
   guest's attribute caching bounding the visible lag by the
   mount's attr TTL; the mount option does the same client-side;
   and a delivered mode under masked presentation neither records
   nor deletes, pinned by the read-modify-write test.
5. The wire flag is covered: golden vectors carry it on
   `write_flags`, an elder server ignores it (interop test), the
   version stays 1 under the amended stability rule with the
   reserved-fields clause's exception naming the field, and the
   skew posture is documented.
6. The cost is an atomic-load lookup: a syscall census shows zero
   added host work on any attribute path including the pinless
   listing walk, and no lock joins the request path beyond the
   published-snapshot read the operation already takes, the store
   handle resolved once per operation, never per listing entry.
   The sidecar's debounce cadence is stated at its constant; the
   daemon's teardown flush and the removal deletion are pinned by
   test; the kill test pins the crash window (the unflushed tail
   lost, the file always a whole document, flushed rows revalidate
   and survive); the temporaries ride the orphan sweep; a record
   is deleted when its last bit clears, whichever rule cleared it
   — pinned by the chmod-644 test — while a strip that clears
   setuid off a setgid-without-group-execute record updates it,
   pinned too; a no-op strip writes nothing; a rename through the
   server updates the locator and a host-side rename drops at the
   next revalidation, both pinned by test, the subtree and
   exchange rename forms included; an assignment through one link
   presents and strips through every link, pinned by test.
7. Both gates pass with the new suites executing; THREAT-MODEL
   carries the enforcement posture including the nosuid-host-mount
   line.

## Write-ahead (PAUSED 2026-08-17, the same day it was written — the spec review measured three of its premises false; superseded by the write-streaming contract above; the text below is kept as the record of the shape that was refuted)

The review's measured findings, summarized (full probes kept out of
tree): the capability probe this section proposed removing does not
exist on direct-io mounts — the two round trips per write were a
page-cached census, while the 172 MB/s field figure is direct-io and
already pays one; negotiating the killpriv capability would turn OFF
the kernel-side stripping that works today, and the replacement
signals (the setattr kill bit, the open kill flag) have no surface
in the FUSE library this client uses — the same library-blocked
class as the parked interrupt item; and the pipelining half breaks
guarantees this document holds elsewhere (append atomicity,
read-after-write on a cache-less mount, the readahead invalidation
contract, mmap writeback, teardown settle accounting), each needing
design work the v2 shared-memory data plane makes moot.

The review also surfaced a real defect in the shipped tree, recorded
as its own correctness item: on a direct-io mount the kernel
delegates setuid/setgid stripping to the filesystem through a write
flag, and both the client and the server ignore it — privileged bits
survive a write that strips them locally and on a cached mount.

### The refuted text (kept for the record)

Reads got their streaming engine; writes still pay every round trip
alone. The decided direction: the same streaming idea as readahead,
with the client the one streaming the data. Two round trips per
guest write today — the kernel's security-capability probe and the
write itself — become, in the common case, a fraction of one.

- **Scope: direct-io mounts**, exactly like readahead — a cached
  mount already has kernel writeback, and doubling buffers there
  buys nothing. Handles opened `O_SYNC`/`O_DSYNC` or `O_DIRECT` are
  excluded: every such write confirms server-side before the guest
  proceeds, unchanged.
- **The window**: the client acknowledges a kernel WRITE once the
  frame is on the wire and the data copied into a bounded in-flight
  window, and streams further writes without waiting for server
  confirmations. Bounds mirror readahead's shape: per-handle bytes
  and a per-mount total, both measured before the numbers are
  pinned, the window's memory being the price and the bound. A full
  window makes the next write wait — backpressure, never an error.
- **Ordering is range-scoped**: two in-flight writes on one handle
  with overlapping ranges are forbidden — the second waits for the
  first's confirmation. Non-overlapping positional writes commute
  on the backing filesystem, and the server's concurrent dispatch
  may apply them in any order; overlap is the one case where order
  is meaning, so overlap is the one case that serializes.
- **Barriers drain**: `fsync`/`fdatasync`, `flush`, and `release`
  complete only after every outstanding confirmation for the handle
  has arrived (then act as they do today). A mount teardown drains
  every handle — the signalled-teardown settle already counts what
  the kernel is owed, and the window joins that accounting.
- **Errors surface at the next operation**: a failed server write
  poisons its handle; the poisoning errno answers the next write,
  fsync, flush or release on that handle, exactly once, then the
  handle behaves per its state. Nothing is silently dropped, and a
  guest that never syncs still learns at close.
- **Reconnect does not replay**: a degraded connection fails the
  outstanding window (the handles poison with the transport errno);
  healing restores the mount, not unconfirmed writes. This is the
  readahead posture — the engine never changes what the wire
  promises, it changes when the client waits.
- **The capability probe goes**: the mount negotiates the FUSE
  handle-killpriv capability, so the kernel stops probing
  `security.capability` before every write; the server owns the
  stripping — a write or truncate through a handle whose inode
  carries setuid/setgid bits (or file capabilities) clears them the
  way the local filesystem would, on its own backing path. One
  guest write is then one wire message.
- **Server side is untouched** beyond the stripping: writes apply
  exactly as they arrive, one pwrite each, replies confirm in
  completion order. The engine, like readahead's, lives in the
  client.

### Acceptance criteria — write-ahead increment

1. Sequential write throughput on a direct-io mount improves by a
   measured, stated factor in a paired A/B (engine off = today's
   behavior); the field baseline is 172 MB/s and the fixed
   ~116 us/write cost is the target.
2. A wire opcode census shows one message per guest write — no
   capability probe — and the killpriv stripping is proven end to
   end: a setuid file written through the mount by a non-owner
   loses its bits, and file capabilities are cleared, matching the
   local filesystem's behavior on the same sequence.
3. Durability barriers hold under fault injection: a server killed
   mid-stream surfaces the failure at the next barrier on every
   affected handle; an fsync that returned success is proven
   durable (the data is in the backing file); a close after failed
   writes reports the poisoning errno exactly once.
4. Overlap ordering is pinned: concurrent overlapping writes on one
   handle serialize (a test proves the final bytes are the second
   write's), and non-overlapping writes pipeline (the census proves
   more than one in flight).
5. O_SYNC and O_DIRECT handles bypass the engine (census: each
   write confirmed before the next departs); cached mounts are
   byte-identical to today.
6. The window bounds are measured and stated in the doc comment
   (per-handle and per-mount), a full window backpressures without
   error, and mount teardown drains every window — the torture
   harness's append and churn classes run green against the engine
   with restarts active.
7. Both gates pass with the new suites executing; the performance
   report carries the A/B.

## Vsock transport (normative for the vsock increment; decided 2026-08-15)

Prioritised 2026-08-15 for host-RAM reduction, alongside everything
else that lowers host memory use. Vsock also closes the surface
THREAT-MODEL flags: with
TCP plus `auth: none`, anything that reaches the listener mounts; a
vsock listener is reachable only from the machine's own VMs, no
network stack involved.

- **Server**: the `vsock` listener transport the config already
  parses is served. A listener entry carries the `port` and an
  optional `cid` bind (default: any CID, the vsock wildcard — on a
  host that means its guests). The startup refusal is retired; the
  transport abstraction's existing seam takes the implementation.
  The dependencies for vsock (amended 2026-08-15 after the follow-up review:
  plural — a synchronous vsock crate for the pre-runtime bind the
  listener contract requires, plus tokio-vsock converted at serve
  time from the bound fd; tokio-vsock's own bind panics outside a
  runtime) are ratified with this decision — the exact crates
  and versions are recorded with the increment. **The crate's
  mutex-based owned split is forbidden**: both sides' transport
  contracts require lock-free half-splitting, so the increment
  splits by fd duplication as the TCP and unix transports do.
- **Port range, decided** (amended 2026-08-15 — the follow-up review
  found the hole): vsock ports are 32-bit at the kernel, but the URL
  grammar's port is 16-bit and the no-manual-parsers stance rules out a
  bespoke authority parser. Vsock listener ports are therefore
  constrained to 1..=65535 at schema validation and rule out nothing
  anyone binds in practice; a state file naming a larger port refuses
  startup with a typed error naming the listener, and the URL's typed
  errors cover CID (u32) and port exactly as the other schemes' errors
  do.
- **Client**: the URL scheme `voidport+vsock://CID:PORT/@namespace`
  (subpath rules identical to every scheme; from a guest, the host
  is CID 2 by convention — documented, not hardcoded). `voidport
  mount` and `voidport subscribe` both accept it; the man pages ride
  the existing clap build.
- **Behavior parity is the contract**: vsock is a byte-transport
  under the same wire protocol — handshake, notifications, reconnect
  and teardown behave identically. The mount-resilience machinery is
  transport-agnostic and must be proven so over vsock, not assumed.
- **Testing**: the kernel's `vsock_loopback` module provides the
  local CID for same-machine tests. The e2e suite uses it where
  present and skips LOUDLY where not. "Claims support" is
  self-detecting (amended 2026-08-15 — the follow-up review found no existing
  fail-on-skip mechanism to cite, so this increment builds it): a
  machine whose `/sys/module/vsock_loopback` exists claims support,
  and on such a machine a probe failure is a test FAILURE, never a
  skip — the suite cannot go vacuously green where the module is
  loaded, and the gate host was probed working.
- **Docs**: THREAT-MODEL gains the vsock posture (the guest→host
  network surface disappears; `auth: none` over vsock trusts
  exactly the machine's own guests); README's transport sentence
  updates.

### Acceptance criteria — vsock increment

1. A `vsock` listener entry serves: a real mount over the loopback
   CID lists, reads, writes and unmounts through it end to end
   (skip-loud without the module; the gate host is checked).
2. The URL scheme parses and round-trips in help, man pages and
   errors; a malformed CID or port answers the same typed errors as
   the other schemes.
3. Reconnect parity: kill and restart the server under a live vsock
   mount — stall, resume, and identifier semantics behave exactly
   as the reconnect contract rules over TCP.
4. The subscription stream works over vsock (subscribe, one delta,
   clean end).
5. TCP and unix behavior is byte-for-byte unchanged; the existing
   suites stay green.
6. THREAT-MODEL and README carry the new posture.
7. Both gates pass with the new suite executing.

## Mount resilience (normative for the reconnect increment; decided 2026-08-14, reworked the same day after the spec review — every finding accepted, two blockers among them)

The requirement: the mount must be as robust as the filesystem it
projects. Configurable, with these defaults:

- **Server breaks away** (connection death or protocol fault): the
  mount enters **Reconnecting**. Newly arriving callbacks stall at the
  adapter (requests still queued in the kernel are the kernel's until
  delivered; FUSE_REQUEST_TIMEOUT stays unnegotiated; INTERRUPT stays
  unhandled per the v1 posture). **One reconnect task owns the
  transition** — death observations coalesce onto it, the connection
  carries a generation number, and frames, replies or errors of an old
  generation are discarded so they can never poison the replacement.
  **One monotonic deadline** (default 5 s, `--reconnect-stall`, `0` =
  the old fail-fast) governs every dial, hello write and hello read;
  each attempt is cancellable and bounded by the window's remainder;
  backoff inside the window starts at 100 ms doubling to a 1 s cap
  with jitter. A completed hello IS the probe, and it installs the new
  connection atomically. Crossing the deadline atomically enters
  **Degraded**: stalled and subsequent requests fail EIO immediately
  while the same bounded attempts continue on a 500 ms-to-5 s capped
  backoff (the TUI worker's shape; reuse where it fits). The moment a
  hello completes, the mount returns to **Connected**. A hello the
  server *refuses* for configuration reasons (unknown namespace,
  unresolvable subpath) keeps the mount Degraded with the probe
  running — the configuration may return; the surface stays EIO.
- **Ids are generation-disjoint, and the client remembers nothing.**
  The spec review demonstrated the fatal alternative end to end: with
  per-session counters, a stale kernel-held id aliases a different
  file in the new session and reads silently return wrong data. The
  server therefore allocates node and handle ids so that no id is
  ever reused across sessions of one server lifetime OR across server
  restarts (a generation component derived from a persisted or
  time-based epoch, joined to the session counter; the root node id 1
  is the single eternal exemption). An id the session does not know is
  answered with a plain errno — ESTALE for a node, EBADF for a handle,
  never a framing violation (the build verifies the server actually
  does this today and fixes it where it does not). Healing is then
  exactly the kernel's own machinery, verified against this kernel:
  entries expire on the 1 s TTL, ESTALE makes the VFS retry the path
  walk with revalidation from the root, and a depth-N path rebuilds on
  its first post-reconnect use with no application-visible error.
  Descriptors held open across the gap fail with the stale errno until
  the application reopens — as if the tree had been replaced
  underneath, which it was.
- **Replay discipline, with its linearization points.** A request is
  either *queued* (never written), *written* (its complete frame
  reached the socket — the server never dispatches a partial frame, so
  a partly-written frame is retryable once the old generation's socket
  is closed), or *answered*. After re-handshake: queued requests are
  sent as they are (one addressing a dead-generation id receives its
  honest stale answer); written-but-unanswered requests are re-sent
  only if idempotent (lookup, getattr, read, readdir, xattr reads,
  statfs, readlink, getlk, open without O_CREAT|O_TRUNC|O_EXCL —
  and, added 2026-08-15 with the subscription contract, Subscribe
  and Unsubscribe, idempotent by that contract's own resync rule); a
  written-but-unanswered non-idempotent mutation fails EIO instead of
  risking double application. No-response requests (FORGET) and releases
  addressing a dead generation are dropped as moot — their referents
  died with the session. Request ids are per-connection per the wire
  contract and restart with the new generation. A retained request
  that exceeds the newly negotiated frame bound fails EIO (edge,
  noted).
- **Locks do not survive the server**, and no memory is needed to say
  so: a lock or unlock on a dead-generation handle is answered EBADF,
  which is the loss surfacing on the next lock-dependent operation
  (getlk/setlk on that handle). Applications re-acquire through a
  reopened handle.
- **Client exits or dies**: every exit path the client controls
  attempts the ordered teardown, unmount included — clean returns and
  SIGINT/SIGTERM both (the main thread owns the signal handler and
  drives the teardown; the fuser session is joined per the required
  order). Teardown from Reconnecting or Degraded cancels the in-flight
  attempt and backoff first. A signalled teardown then **answers what
  the kernel is already owed before it unmounts** (refined 2026-08-17,
  when the unimplemented half of this contract was measured as a
  teardown race under load): a callback replies
  from the runtime, so a signal can land between a dispatch loop taking
  a request and the reply going back, and unmounting there answers EIO
  for work that may have completed and meets the kernel's EBUSY,
  because whoever is waiting for that answer is a reference against the
  mountpoint. The wait is bounded (2s) and it is the only thing the
  retry of the unmount is gated on: a mountpoint held by something else
  is refused once and reported. A busy mountpoint still surfaces EBUSY;
  v1 does no lazy or forced unmount. For death the client cannot
  intercept: **auto-unmount is opportunistic, not guaranteed**
  (reworked after the spec review proved the original default
  unbuildable — fuser 0.18 refuses AutoUnmount under the default
  owner-only ACL and requires the fusermount3 helper): where the ACL
  and helper allow it the mount sets it and logs so; where they do
  not, a SIGKILL leaves the documented dead endpoint and `voidport
  umount` recovers the mountpoint. `--no-auto-unmount` opts out
  entirely.

### Acceptance criteria — reconnect increment

Pinned 2026-08-14; reworked the same day with the spec review's
findings. The contract above is the authority they check.

1. A server killed mid-I/O and restarted within the stall window:
   every concurrent **path-based** operation (walks, opens by path,
   creates, statfs) completes correctly with no error surfaced — the
   ESTALE-retry healing carries them — while operations bound to
   dead-generation identifiers (reads and writes on pre-restart open
   descriptors) fail with their plain stale errno and succeed on
   reopen. Proven e2e with a real kill and restart under concurrent
   load, asserting both halves.
2. A server absent past the window: stalled requests fail EIO at the
   window's edge (measured against the deadline, not per-request
   timers); subsequent requests fail immediately; the probe continues
   on capped backoff. A peer that accepts the socket but never
   completes the hello does NOT hold the mount in Reconnecting past
   the deadline (the wedged-peer case, probed in review).
3. A server returning after degradation: requests flow again with no
   remount; a fresh walk from the mount root succeeds and new opens
   work, proven end to end.
4. Id disjointness: after a restart, no node or handle id from the old
   session is ever accepted as valid by the new one — old ids answer
   ESTALE/EBADF as ordinary errnos with the connection surviving, and
   a wrong-file aliasing probe (the spec review's reproduction) runs
   as a regression test and fails on per-session counters.
5. Configuration changed across the gap (a rule removed, re-targeted,
   or downgraded; the namespace itself deleted): fresh walks surface
   ENOENT/EROFS/EACCES per request; a hello refused for configuration
   reasons keeps the mount Degraded with the probe running; nothing
   wedges.
6. Replay discipline holds at its linearization points: a queued
   request is sent after re-handshake; a written-unanswered idempotent
   request is re-sent and completes; a written-unanswered
   non-idempotent mutation fails EIO and is proven NOT applied twice —
   driven deterministically through a test-harness relay that forwards
   the request, discards the server's reply, and kills the server (no
   timing races).
7. A lock held across the gap surfaces its loss as EBADF on the next
   getlk/setlk through the old handle; re-acquisition through a
   reopened handle succeeds.
8. `--reconnect-stall 0` restores fail-fast: connection death fails
   outstanding and subsequent operations immediately.
9. SIGINT/SIGTERM run the ordered teardown including the unmount
   attempt, from Connected, Reconnecting and Degraded alike (the
   in-flight attempt is cancelled first); with a busy mountpoint the
   process still exits and the mountpoint is recoverable.
10. Auto-unmount where the platform allows it: with an ACL and helper
    that permit it, SIGKILL leaves no dead mountpoint; without them,
    the dead endpoint is the documented state and `voidport umount`
    recovers it. Both arms tested as the environment allows, honestly
    gated.
11. Degraded mode is responsive: failures return immediately (measured
    against the stall window), and an unmount from Reconnecting or
    Degraded is clean.
12. Both gates pass with the resilience e2e suites executing against
    real servers and real mounts.


**Unmount.** `voidport umount` performs a normal kernel unmount only —
no lazy or forced modes in v1; a busy mountpoint surfaces the kernel's
EBUSY. Teardown order: initiate the unmount, close the data connection
(which fails outstanding wire requests), reply EIO to any callbacks the
adapter still owns, then join the FUSE session, and only then release
the runtime the callbacks run on. A parked blocking setlk never reaches
this path through a v1 unmount — the descriptor it holds makes the
unmount return EBUSY first; connection death covers that case under the
protocol-fault rules.

**End-to-end suite (the v1 gate).** Lives with the client crate. Skips
are legal only where a single capability preflight proves FUSE
unusable (`/dev/fuse` missing or unopenable); when the preflight
passes, every e2e case must execute and a skip is a failure. The
reference environment passes the preflight and runs everything.

### Acceptance criteria — increment 6 (FUSE client + end-to-end)

Revised 2026-08-13 after the spec review; the earlier set is retracted.

1. URL parsing implements the grammar above: both schemes, namespace and
   subpath extraction, and every listed rejection (missing port,
   relative or non-authority unix socket path, missing `@`, invalid
   namespace name, NUL or empty interior segments, userinfo/query/
   fragment) with clear errors — unit-tested without a server.
2. Mounting over tcp and over a unix socket both work end to end;
   `ls -la` of the worked example shows exactly the documented
   presented modes (`rwx------`, `r-x------`, `rw-------`), and
   `secret/` is ENOENT by direct path and absent from listings.
3. File I/O through the mount: read/write round-trips, append,
   truncate, mmap read (exercised by demand-paging a mapped executable
   from the mount — a literal mmap(2) in the test would need an unsafe
   block outside the one ratified island); contents verified against
   the host side.
4. ro enforcement through the mount, run as guest root so requests
   pass the kernel's presented-bits check and reach the server: every
   write-class operation in a ro graft fails with EROFS. One non-root
   case asserts the kernel's own EACCES on the presented bits.
5. `--read-only`: the mount reports read-only to the kernel and every
   write-class operation fails even in an rw graft.
6. Xattrs through the mount: user.* set/get/list/remove round-trip with
   correct NUL-list reconstruction; reserved namespaces surface
   EOPNOTSUPP.
7. POSIX continuity through the proxy: rename-while-open and
   unlink-while-open keep the open file readable/writable; hardlinks
   share st_ino and report correct nlink; symlink create / readlink /
   follow-within-mount work, and an absolute symlink target resolves in
   the guest's namespace.
8. Ownership mapping is visible end to end: a file created as guest
   root lands host-side owned by the server identity and presents as
   guest uid 0 through the map.
9. Coherence: two mounts of one namespace — a writer's change is
   visible to a reader within the TTLs, including through a descriptor
   the reader already held open (data revalidation), and a host-side
   edit is visible to the guest. One fcntl record-lock conflict is
   observable across the two mounts (flock stays guest-local by
   design and is not tested cross-mount).
10. Runtime reconfiguration end to end: a rule added via `voidport-ctl`
    while mounted becomes visible to new lookups without remounting; a
    downgrade rw→ro applies to fresh opens.
11. Unmount is clean (server session torn down, no leaked fds) and the
    same mountpoint remounts successfully; an unmount issued while a
    blocking lock request is parked returns within a bounded time
    reporting EBUSY — the parked lock necessarily holds an open
    descriptor, so a v1 non-forced unmount cannot complete there — and
    succeeds once the lock is released; a busy mountpoint surfaces
    EBUSY.
12. Concurrency smoke: parallel file operations through one mount
    complete correctly, and while a blocking setlk is outstanding,
    unrelated I/O and the operation that releases the conflicting lock
    both complete through the same mount.
13. Node accounting: under a deliberately low server node cap, repeated
    lookup / readdirplus / forget cycles return the session's node
    count to baseline — no leak; the plain-readdir fallback's
    compensating FORGETs are exercised at the client level over the
    real wire (the path is unreachable through a mount once
    FUSE_DO_READDIRPLUS is negotiated without READDIRPLUS_AUTO).
14. Protocol-fault handling: against a fault-injecting server (wrong
    opcode for an outstanding id, invalid status, mid-frame EOF), the
    client fails outstanding and subsequent operations with EIO and
    sends nothing further on the dead connection.
15. `./check` passes; on the reference environment the e2e preflight
    passes and every e2e case executes (a skip is a failure there).

### Acceptance criteria — increment 4 (state + control plane)

Revised 2026-08-12 after the spec review; the earlier criterion set
is retracted.

1. The source document model round-trips: `load(persist(x)) == x` on the
   source form, with tests proving sentinels and relative targets survive
   an unrelated mutation un-resolved in the file.
2. The TOML schema loads via serde/toml with `deny_unknown_fields`
   everywhere (tested with a misspelled key), lowercase mode strings,
   per-mode ownership shapes (missing/extra per-mode fields are typed
   errors, tested per mode), the sentinel-validated host-id type
   (rejecting arbitrary strings, tested), listener entries for all three
   transports, and namespace-name validation including uniqueness. The
   commented example file exists and loads.
3. Load and mutation validation go through the engine build boundary with
   loader-owned error enrichment naming namespace and rule; tests cover a
   valid file, a dead-config file, a sentinel file (hermetic via injected
   identity), and a duplicate-namespace file.
4. Persist is atomic and durable (temp with preserved mode + fsync file +
   rename + fsync directory), the state file is created 0600, and the
   single-instance lock refuses a second daemon (tested).
5. Every control operation works over the unix socket via the shared
   `voidport-control` types, with an integration test against a live
   server in a temporary directory; malformed JSON, unknown operations,
   and oversized lines behave per the contract (tested).
6. Mutations are serialized validate → persist → swap: a rejected
   mutation changes neither memory nor file; a persist failure (forced in
   a test) publishes nothing; an accepted mutation is visible to the next
   operation and persisted.
7. The socket bind contract is implemented and tested: stale socket
   reclaimed, live socket refused, non-socket path refused, 0600
   established, unlinked on shutdown.
8. `voidport-ctl` covers every operation with human and `--json` output
   and nonzero exit on error; the integration test drives the real binary
   against the real server.
9. `voidportd` starts from a state file and shuts down cleanly on
   SIGINT/SIGTERM (tested).
10. `./check` passes.

## Implementation

Rust (edition 2024), cargo workspace, eight crates (count last
corrected 2026-08-14):

| Crate | Role |
|---|---|
| `voidport-proto` | Wire structs + opcodes. Shared. `no_std`-friendly discipline so a kernel port stays thinkable. |
| `voidport-control` | Typed operator protocol + source-form policy types; the blocking control client behind the `client` feature. |
| `voidportd` | Server: namespaces, rule engine, host I/O, data + control planes. |
| `voidport` | Guest client: FUSE mount via `fuser`. |
| `voidport-ctl` | Operator CLI for the control plane. |
| `voidport-tui` | The operator TUI (library; the `voidportd` binary wires `--tui`). |
| `voidport-bench` | Benchmark harness behind docs/PERFORMANCE.md. Unpublished. |
| `voidport-pty` | Dev-only PTY test harness (vt100-parsed), shared by the TUI and daemon suites. Unpublished. |

Dependencies (all deliberate, everything else hand-rolled):

| Concern | Crate | Why |
|---|---|---|
| Async runtime | `tokio` | Data/control listeners; host FS syscalls on the blocking pool in v1; `io_uring` is the later hot-path upgrade. |
| Wire types | `zerocopy` | Safe fixed-layout reinterpretation, no manual parsing. |
| Syscalls | `rustix` | Safe `openat2`+`RESOLVE_BENEATH`, `O_PATH`, xattrs. |
| FUSE | `fuser` | The maintained Rust FUSE library. |
| Config | `serde` + `toml` + `serde_json` | State file (TOML) and control-plane JSON (corrected 2026-08-12: serde alone implements no format; serde_json is the JSON implementation). |
| CLI | `clap` | |
| Errors/logs | `thiserror`/`anyhow`, `tracing` | |
| URL parsing | `url` + `percent-encoding` | Client mount URLs (decided 2026-08-13, "dependency scope": the no-manual-parsers directive covers solved formats). |
| OFD locks | `libc` | One documented unsafe island in `voidportd::host::lock` (rustix exposes no F_OFD_*). |
| Operator TUI | `ratatui` + `crossterm` | The management TUI (decided 2026-08-13; `voidport-tui` crate only). |
| TUI lifecycle tests | `portable-pty` | Dev-dependency only, in `voidport-tui` and `voidportd` (the real-binary proofs need `CARGO_BIN_EXE_`); decided 2026-08-13. `libc` rides as a `voidport-tui` dev-dependency naming termios flags (no unsafe). `rustix` gains the `event` feature (the poll(2) behind the client's connect timeout). |
| Man pages | `clap_mangen` | Build-time generation of voidportd.1 / voidport.1 / voidport-ctl.1 from the clap definitions, installed by the flake (decided 2026-08-13 for a documented help surface). |
| PTY test consolidation | `vt100` (or equivalent) | Dev-only: the shared PTY harness's ANSI handling must not be a hand-rolled scanner (the no-manual-parsers directive); decided 2026-08-13 with the consolidation. |

**Gates (decided 2026-08-13).** `./check` is the inner-loop gate
(dev shell: fmt, clippy `-D warnings`, full workspace suite). The flake
package build — `nix build path:.`, which runs the suite inside the nix
build sandbox — is **also part of the gate**: the flake is the project's
main entry point, not decoration. Every increment's proof includes both,
so the suite must be sandbox-clean: no test may depend on a resource the
sandbox lacks except through an honest preflight of the FUSE-test kind
(skip only where the resource is provably unavailable — and the sandbox
counts as an environment the test must either work in or provably
detect). Known sandbox defects at the time of this decision, owed by the
TUI increment: the PTY harness child-spawn failure and the launch
summary's socket-bind permission unit-test failure.

Nix flake pins nixpkgs-unstable for toolchain + devshell; `unsafe_code` is
denied workspace-wide (zerocopy and rustix exist precisely so we don't need
it).

## Rejected alternatives

- **Protobuf on the data plane** — cannot do zero-copy payloads (every
  read/write buffer would be copied through the encoder), and forecloses a
  kernel client (no protobuf in kernelspace). Would have been acceptable
  only if the kernel ambition were dropped. Cap'n Proto/flatbuffers share
  the kernel problem and add a schema toolchain for little gain over
  `zerocopy` structs.
- **YAML state file** — `serde_yaml` is archived/unmaintained; TOML
  expresses the rule table fine with a maintained parser.
- **Path-pinned grafts** — break on host renames and, worse, make
  symlink-escape prevention fragile; `O_PATH` fd + `RESOLVE_BENEATH` gives
  rename-survival and containment in one mechanism.
- **List-order rule precedence** — order-dependent configs are a footgun;
  most-specific-wins is deterministic under any serialization.
- **Full glob from day one** — literal paths + single-level `*` fallback
  covers the product; recursive `**` can be added to the resolver later
  without changing the model.
- **Reusing NFS/9p wire protocols** — inherits exactly the semantics and
  performance ceilings this project exists to escape.
- **One server process per share (virtiofsd model)** — kills runtime
  composability and multi-namespace operation; a single long-running server
  is the point.

## Settled decisions

These are settled; a change here requires a new recorded decision.

- Enforcement: ro and hidden are enforced server-side; displayed
  permission bits are presentation only.
- Unmapped uids: configurable, and all three options must be
  specifiable — squash / hide / passthrough.
- Reverse mapping on guest writes: guest-created files land on the host
  owned per the inverse map.
- Policy change vs open handles (2026-08-12): local-filesystem chmod
  semantics — open handles survive a policy downgrade; only new opens
  see the new policy.
- Coherence: reads and writes are passed through to the host; the server
  acts as a multithreaded, highly parallel, low-latency filesystem
  proxy.
- Auth: v1 ships `auth = "none"` only, for simplicity while the
  mechanics are settled; the trust model is the transport.
  Authentication is v2 design scope.
- Graft pinning: fd-pinned plus RESOLVE_BENEATH.
- Synthetic ino keyed by `(host_dev, host_ino)`.
- Wildcards: literal paths plus a single-level `*` fallback in v1.
- Config portability: `host_uid` is settable to the enum value `uid`, so
  it reuses the invoking user id instead of hardcoding one; paths may
  likewise be relative, resolved against the state file.
- State refresh: modifying the file from outside does not refresh the
  in-memory state in v1.
- State persistence: runtime mutations persist by overwriting the state
  file; the server owns it.
- Serialization: zerocopy structs on the data plane; protobuf rejected
  there.
- Stack: tokio, zerocopy, rustix, fuser, serde+toml, clap,
  thiserror/anyhow, tracing are accepted; the rest is hand-rolled.
  (Scope decided 2026-08-13, see Dispositions "dependency scope": this
  composes with the standing no-manual-parsers directive, so vetted
  parsing utilities — `url`, `percent-encoding` — are in scope;
  "hand-rolled" covers the system's own machinery.)
- Quality bar: the code stays clean, scalable, modular, maintainable
  and well-documented.
- Robustness mandate (2026-08-14): nothing may ever starve the server,
  and a torture test is part of the deliverable. voidport must never
  starve, stall (except while the server is broken away), delay, or do
  anything else that amounts to downtime. When every operation class
  runs concurrently in every shape, form and place, the software
  consumes the resources it has instead of giving in: 100% CPU, 99% of
  RAM and 100% of the I/O budget are acceptable outcomes. It must work
  under brutal conditions for hours on end — the AOSP build is the
  reference workload, and so are these development VMs.
- Xattr policy (2026-08-14): the server process runs as an ordinary
  user, so what that user cannot change the guest cannot either — the
  guest gains nothing the server's credentials do not already carry.
  What the server does add is control over which mount may do what:
  wildcard/glob rules that allow or deny xattr names, defaulting to
  deny-write and allow-read, bounded in every case by the server's own
  user. Ownership policy is per-namespace, never a server global.
- Readahead (2026-08-15): client-side readahead is accepted — a
  process-wide 256 MiB readahead buffer that holds prefetched bytes and
  evicts them when they are not read or needed. If a process is going to
  read a whole file anyway, the read can be streamed in one go with the
  reader free to close early; there is no need to round-trip on every
  chunk when the approximate shape of the read is already known.
  Disposition: buildable, queued as the readahead increment (after the
  recipe-simplification and share --vsock patches; full contract and
  spec review when reached). Design direction decided: a process-wide
  bounded readahead pool (256 MiB default, evict-unread-first, bytes
  evict once served) fed by WINDOWED PIPELINING over the existing wire
  read op — sequential-pattern detection per handle grows a prefetch
  window so round trips overlap and never stall the pipe; the whole-file
  case is the window growing to EOF, and a reader closing early drops
  the handle, cancelling outstanding prefetch and evicting its bytes. A
  server-push streaming op is the recorded alternative, deliberately
  deferred: request frames cost ~3% CPU at multi-GB/s and pipelining
  hides all latency, while server-push would need its own flow control —
  add it only if measurement shows the residual per-request cost
  mattering. Invalidation-push stays in the hardening tail, explicitly
  deferred. Follow-up decision, same day — a hybrid was proposed:
  readahead mixed with an efficient direct stream, where client and
  server negotiate a streaming mode carrying large chunks in one go
  under a tightly packed header of the shape `[type][ID][<data>]`, with
  the id minted in advance and known to both sides so that, say, id 2843
  always means one specific stream at a fixed 8 MiB chunk size and
  resolves without encoding overhead on the wire. Disposition: the
  sketch maps onto existing wire slots — the reserved notification class
  is the [type], and the request_id field carries the pre-minted stream
  id, so the negotiated-stream escalation costs ZERO new header bytes
  when built. Pinned facts for that escalation: header overhead is
  already ~0.002% at 1 MiB chunks (the saving of a stream op is the
  per-chunk request, <1% CPU by arithmetic — hence measure-first); the
  binding constraint is head-of-line blocking — chunks are sized
  256 KiB-1 MiB so a metadata reply never waits more than ~a frame's
  transmission, and the connection writer's existing replies-first bias
  extends to stream chunks; a dedicated per-mount data connection is the
  recorded plan-C if measurement still shows stalls (real protocol
  surface: attaching a second connection to a session). Plan-C
  superseded same day: it generalizes to the multi-connection decision
  below.
- Multi-connection mounts (2026-08-15, sequencing confirmed): a mount
  may open several connections over one transport — one low-latency
  metadata connection plus N bulk connections, requests striped, streams
  pinned to bulk connections — killing cross-request head-of-line
  blocking outright and parallelizing server-side processing (measured
  basis: 25k ops/s over one connection, 41k over four). All connections
  share the transport's underlying bandwidth: virtio-vsock is one
  virtqueue pair and one vhost worker per guest. (Amended 2026-08-16
  from the readahead spec review's measurements: a single connection on
  the reference environment's vsock saturates at ~1.0-1.2 GB/s across
  all useful depths, so the earlier "several GB/s, currently headroom"
  was optimistic — whether that ceiling is per-connection protocol cost
  or the vhost worker itself is exactly what this increment's own
  measurements must answer before its throughput claims are written.)
  Wire surface: attach-connection-to-session. Queued AFTER the readahead
  increment (they compose — readahead fills the bulk connections); full
  contract and spec review when reached. In the same exchange the v2
  kernel module's data plane was decided and is recorded in the v2
  mandate: a virtio device with a DAX-style shared-memory window (host
  page cache mapped into the guest, bulk data as zero-copy memory reads,
  control on a queue) — explicitly not SCSI or generic PCIe, whose block
  semantics cannot express per-file policy.
- Pattern rules (2026-08-15): a field report — a tool inside a
  guest writes state to sibling directories of the shared project
  directory, which the share does not cover, so a relaunch erases
  them. Not a voidport fault, but the share needs a way to cover
  the case; two candidate mechanisms were raised: a glob source
  (path/to/project-* covers the siblings) and guest-driven
  directory creation propagating to the host (EBUSY when the
  directory already exists). Disposition:
  the glob lands as PATTERN RULES on the namespace side (see the
  queued sketch below); guest-driven graft creation is REJECTED — the
  data plane must never mutate policy, and grafting the parent
  directory already makes guest mkdir propagate to the host with the
  host's own EEXIST, which is strictly more POSIX than a synthetic
  EBUSY.
- Ownership presentation (2026-08-15): after a field report of a
  foreign-uid 700 directory (container data owned by nobody) denying a
  guest tree walk, dropping squash entirely was weighed — whether squash
  makes sense at all, or whether uids should simply pass through: if the
  host user has no access it is denied anyway, which merely looks
  implausible, and denials for implausible reasons are normal (SELinux
  can deny access even on a 777 file). Passthrough was already the
  default and squash opt-in (map-mode unmapped policy). Decided:
  passthrough stays the default, squash stays strictly opt-in, and no
  guest-root override exists — the server can never grant more than its
  host user can do, so an allow_root-style bypass would be a no-op or a
  lie about enforcement.
- Descriptor exhaustion in the field (2026-08-15): an AOSP build over
  voidport mounts failed with thousands of "too many open files" from
  soong's module-finder walking the source tree, plus a collateral mkdir
  ENOENT in the intermediates, on the then-current HEAD — while the same
  build works on the host filesystem and through docker. Root cause
  confirmed in code: one O_PATH descriptor pinned per node for the
  node's whole lifetime, and a node lives until the guest kernel FORGETs
  it, which an unpressured kernel never does; the torture run had
  already measured fd growth tracking names-ever-named. The standing
  robustness mandate applies: the AOSP build must work.
- Share subscription (2026-08-15): the client needs a subscription
  interface for listening to changes in the server, so a VM can mount
  and unmount its directories dynamically. Design constraints decided with
  it: it must ride the data plane, never the control socket; events must
  pass the same visibility resolution the session is subject to, so
  nothing hidden leaks; snapshot-then-stream on every connection so
  consumers are level-triggered and reconnects self-heal by
  resubscription.
- Naming (2026-08-15): "graft" is compressed jargon that readers may
  struggle with; simple naming — namespace, mount, directory, rule — is
  preferred. "graft" is therefore retired from user-facing surfaces
  (events, CLI, help, man pages, README); internal identifiers migrate
  opportunistically.
- Direct I/O option (2026-08-14): mounting the client with direct_io (no
  guest-side caching of file data) removes the duplication for
  share-backed files entirely. Metadata caching — where voidport wins
  7-11x over 9p — is unaffected, since that is the attr/entry TTL, not
  the data cache. It is a small client-side option with a large memory
  payoff for the VM case specifically, and is added as a client option
  the guest can choose.
- Atomic append (2026-08-14): O_APPEND is investigated, and improving on
  NFS is authorized as long as nothing else breaks.
- Mount resilience (2026-08-14): the mount must be as robust as
  possible, with configurable behavior. By default: when the server
  breaks away the client first stalls current and running requests and
  waits for the server to come back; if it has not returned after 5
  seconds an I/O error (or another appropriate errno) is returned, and
  further errored requests are answered immediately instead of waiting
  again; once the server comes back, errors stop and everything resumes.
  Where the configuration changes and directories break away, each
  request behaves as if the tree had been rm -rf'ed, mv'ed,
  chown/chmod'ed or unmounted — whichever fits that request best — and
  it is always graceful. Corrected the same day, retracting a
  client-side rebuild that had been designed in: the client remembers
  nothing, because it forwards everything to the server anyway and the
  server simply acts normally.
- Tree hygiene (2026-08-14): external files — kernel sources, files from
  other projects — must never enter the git history. (Enforced by the
  pre-commit hygiene hook — top-level allowlist plus a foreign-extension
  block — wired by the devshell and run over every tracked file at the
  head of ./check.)
- Resource caps must not bite by default (2026-08-14): raising the
  numbers is not enough, because a limit nobody chose should not exist
  at all. Decided after the per-session handle cap refused a real
  source-tree walk that the host filesystem carries without complaint.
- The operator CLI finds a local instance without flags (2026-08-14):
  `~/.local/state/voidport/control.sock` is the default socket when none
  is specified, so a locally running instance is controllable through
  `voidport-ctl` without extra flags.
- The flake package build is part of the gate (2026-08-13): the flake is
  the project's main entry point, not decoration, so `nix build` gates
  alongside `./check`.
- Build environment: all dependencies, build rules and scripts live in
  the project and are available through the flake.

## Pattern rules (normative for the pattern-rules increment; sketch decided 2026-08-15, full contract written the same day)

The need: expose a *changing family* of sibling directories —
`project-*` beside a shared project dir — so that new members appear
live and guest-created members land durably on the host.

(Reworked 2026-08-15 after the spec review. The decisive
finding: the first draft embedded globs in the rule path, and a
component merely *containing* `*` is a **literal name today** —
documented, tested, and legal in deployed state files — so the draft
silently changed the meaning of existing configuration, made
`*`-containing host names unnameable, and forced a decision on escaping.
The review also computed that the one-fixture specificity criterion
was unsatisfiable and that "no events" contradicted the decided
subscription `/`-entry. Every contradicted sentence is replaced in
place.)

- **A pattern rule is its own syntax, not a path spelling**: a rule
  carries the literal directory `path` it governs plus a `match`
  field — the glob for child names (`match = "project-*"` under
  `path = "/a"`; `voidport-ctl rule add NS /a --match 'project-*'
  --mode rw`). Rule paths stay literal forever: a path component
  containing `*` keeps meaning the entry with that name, exactly as
  today, so no deployed state file changes meaning, nothing needs
  escaping, and no host name is unnameable. A pattern rule is keyed
  by `(path, match)`; removal names both.
- **The pattern language, pinned to the byte**: `*` matches any run
  of **bytes, including the empty run** (`project-*` covers a child
  named exactly `project-`); names are bytes, never forced through
  UTF-8, and matching is byte-wise. A `*` at the start of a match
  does **not** cover a name beginning with `.` — the shell's rule,
  chosen deliberately so an un-hidden family never accidentally
  exposes `.git`, `.ssh` or `.env`; a match that itself begins with
  a literal `.` covers dotfiles. `?`, `[` and every other byte are
  ordinary literal bytes. A match consisting only of `*`s is refused
  at the boundary: that is the bare-`*` wildcard rule's job, and two
  spellings of match-everything at one level would be the ambiguity
  the overlap rule exists to kill.
- **Pattern rules are mode-only.** They carry no target: they refine
  the visibility and mode of children the enclosing rule's host
  backing already supplies, exactly as bare-`*` rules do today. A
  pattern rule with a target is refused at add time (rejected
  alternative: target templating — substituting the matched name
  into a target pattern — is real machinery for a need nobody has
  stated; it can be added later without breaking mode-only rules).
- **Specificity: the resolution algorithm gains a step, amended in
  its own normative list this date** — literal (step 1), then
  pattern (new step, between literal and wildcard), then bare `*`,
  then what the enclosing rule implies. Stated plainly because the
  review computed it: where a bare `*` governs a directory, the
  enclosing default decides *no* name there — the chain's fourth
  tier is observable only at a wildcard-free directory, and the
  acceptance criterion says so instead of demanding the impossible
  single fixture.
- **Overlap between two pattern rules at one level is refused at the
  boundary**, add time and load, the error naming both rules —
  never adjudicated at lookup. Intersection of `*`-globs is
  decidable and the checker must be a **product construction over
  the two patterns' automata** (or provably equivalent): the probe
  showed a naive literal-run comparison wrong on six of thirteen
  representative pairs, so the criteria pin witness cases a naive
  checker fails — `ab*` vs `*ba` overlap (witness `aba`), `a*b` vs
  `b*a` disjoint, `proj-*` vs `project-*` disjoint, `a*b*c` vs
  `*d*` overlap. The overlap refusal answers the control plane's
  invalid-configuration error carrying both rule spellings (not
  "already exists" — nothing exists twice). Cost, stated honestly:
  the check is quadratic in the patterns at one level and in match
  length, runs per mutation under the mutation lock and once per
  load at startup, and is operator-bounded; the v2 mandate's
  rebuild-cost sentence is amended this date to carry the same fact.
- **Table validation extends to patterns, amended in the normative
  validation list this date**: reachability reuses per-component
  resolution, so a rule beneath a name an admitting pattern covers
  is REACHABLE (the pattern admits it) and a rule beneath a name
  only hidden rules cover is dead configuration, refused — hidden
  patterns cut reachability exactly as hidden wildcards do. A
  pattern rule needs a structurally host-backed directory (same
  refusal as a wildcard on a synthesized parent: nothing to match
  against), and a pattern rule beneath a hidden literal is dead
  configuration like its wildcard analogue.
- **Evaluation is live**, at resolution, like every rule: a host
  directory created after the rule was written is covered at its
  next lookup, TTL-bounded like everything else. Guest `mkdir` of a
  name a `rw` pattern admits creates the real host directory under
  the enclosing backing — durable across relaunches — with the
  host's own `EEXIST` on collision. `mkdir` of a name only hidden
  rules cover answers `EACCES` — stated as the required errno: hidden's
  invisibility governs observation, and creation into a hidden name
  is refused, not allowed-and-hidden, which is the behavior
  the engine already has for wildcard-hidden names.
- **Subscription interplay, carved precisely** (the first draft's
  blanket "no events" contradicted the decided `/`-entry contract):
  pattern rules produce **no subscription entries**, and no events
  for any session whose mount root the pattern does not govern —
  the enclosing literal rule's entry covers the subtree. The one
  decided exception: a session mounted *inside* a pattern-governed
  name follows the subscription contract's own `/`-entry rule — its
  root entry carries the mount root's effective mode, and events on
  `/` follow the subscription contract's own publish shapes (amended
  2026-08-15 after the follow-up review — the first wording promised a
  `changed` on re-mode that the decided lifecycle makes impossible):
  a pattern re-mode is always remove-then-add, two publishes, so
  over a hidden default the `/` entry goes `removed` then `added`,
  and over a visible default each publish emits the `changed` its
  own effective-mode step causes. A single publish that changes the
  root's effective mode — removing the pattern where a non-hidden
  wildcard sits beneath it — emits one `changed`. That is the
  subscription contract keeping its promise, not a pattern leak.
- **Lifecycle, stated**: there is no modify operation and no atomic
  swap of two overlapping patterns — the only legal path is remove
  then add, and the intermediate window (part of the family
  unmatched, invisible under a hidden bare `*`) is real and
  documented, consistent with the control plane's remove-then-add
  re-mode semantics everywhere else.
- New artifacts this increment builds, named so none is assumed: the
  `match` field on the rule schema (state file, control plane,
  `voidport-ctl rule add --match` / `rule remove --match`); the
  pattern matcher and the automata-product overlap checker; the
  resolution step and the reachability extension; the refreshed
  operator surfaces (`docs/state.example.toml` precedence text,
  README semantics bullet, ctl help text); the new suites.
- **The use case composes from existing semantics**: graft the parent
  `rw`, hide its children with a bare-`*` rule, un-hide the family
  with a pattern rule.
- **Rejected — guest-driven graft creation** ("allow the guest to
  create new directories that propagate to the host", EBUSY on
  existing): the data plane mutating the rule table would cross the
  one boundary the design is built on (only the control socket
  reconfigures policy), and the parent-graft composition above
  already delivers the durable-propagation behavior with real POSIX
  errnos instead of invented ones.

Until it lands, the zero-feature workaround is grafting the parent
directory alone — it exposes all siblings, which is exactly what the
pattern filter exists to avoid.

### Acceptance criteria — pattern-rules increment

1. A pattern rule (`path` + `match`) parses, persists and
   round-trips through the state file and `voidport-ctl rule add
   --match`, and `rule remove --match` removes exactly it; a
   pattern rule carrying a target, a match that is only `*`s, and a
   match on a non-host-backed or hidden-literal directory are each
   refused at add time AND at load with a clear error. Rule paths
   containing `*` as literal components keep their exact meaning —
   asserted on a fixture that names a host entry literally called
   `b*` — and bare-`*` wildcard rules behave byte-for-byte as
   before.
2. The specificity chain holds at resolution through a real mount:
   at a directory carrying a literal, a pattern and a bare `*`,
   three names demonstrate literal over pattern over `*`; at a
   wildcard-free sibling directory a fourth name demonstrates
   pattern over the enclosing default, and a fifth the default
   itself. (One name can only ever demonstrate its own winner; the
   chain is proven across names, and the enclosing default is
   observable only where no bare `*` shadows it.)
3. Overlap refusal is exact: `ab*` vs `*ba` is refused with the
   error naming both rules (overlap, witness exists), `a*b*c` vs
   `*d*` is refused, while `a*b` vs `b*a` and `proj-*` vs
   `project-*` coexist (disjoint) — and `*x` vs `.x*` coexist,
   because the leading-dot rule makes them disjoint (a checker whose
   automata ignore the dot rule wrongly refuses them) — at add time
   AND at load. A dotfile probe pins the leading-dot rule at
   resolution too: `*-a` does not cover `.b-a`; a match starting
   with `.` does.
4. Live matching: a host directory created after the rules exist
   appears through the mount at its next lookup under the pattern's
   mode, with no control-plane operation, within the TTL bound; the
   empty-run rule is pinned (`project-*` covers a child named
   exactly `project-`).
5. The motivating composition works end to end: parent shared `rw`,
   children hidden by `*`, family un-hidden by pattern — the guest
   sees exactly the family; `mkdir` of a matching name lands on the
   host durably and a second `mkdir` answers the host's `EEXIST`;
   `mkdir` of a non-matching name answers `EACCES` as decided.
6. A `hidden` pattern hides its matches with full invisibility
   semantics (no entry, no stat, no error that reveals existence,
   the same probes the hidden-rule suite uses), and reachability
   follows resolution: a literal rule beneath a pattern-admitted
   name builds and fires; one beneath a name only hidden rules
   cover is refused as dead configuration at add and load.
7. Subscription: pattern add, re-mode and remove produce no entries
   and no events for a subscriber mounted at the enclosing share,
   while a subscriber mounted inside a pattern-governed name sees
   its `/` entry follow the publish shapes: the two-operation
   re-mode over the hidden composition arrives as `removed` then
   `added`, a single-publish pattern removal over a non-hidden
   wildcard arrives as one `changed`, and removal that hides the
   mount root arrives as `removed` — asserted with two live
   subscribers side by side.
8. Ownership and permission composition for pattern-admitted
   children is identical to wildcard-admitted children today; the
   existing policy suites stay green.
9. Both gates pass with the new suites executing.

## v2 mandate — hyperscale (decided 2026-08-15)

The v2 goal: exabytes at terabytes per second across thousands of
namespaces, rules and clients with millions of open files.

What that implies, stated honestly against the v1 architecture (one
process, one host, tokio + blocking-pool host I/O, FUSE data path):

- **Terabytes per second is a fleet property, not a process
  property.** A single host tops out at its NIC and PCIe bandwidth
  (tens of GB/s). v2 therefore means horizontal scale-out — many
  servers fronting the data, with namespace/rule policy replicated or
  partitioned across them — and that is an architecture phase, not an
  increment.
- **Exabytes is a storage-backend property.** The host filesystem
  stops being the only backing; the graft target abstraction
  (HostTarget behind a rule) is the natural seam for pluggable
  backends. Nothing in the wire names the host filesystem.
- **Millions of concurrently open files** extends the descriptor-
  budget pattern from node pins to handles: real-fd-per-handle
  cannot hold at that scale; a handle fd cache with identity-verified
  reopen (the machinery this increment builds) is the likely shape.
- **Thousands of clients** stresses the per-session tables and any
  process-global locks: the budget ledger and ino allocator must
  shard before they contend. The v1 contracts were written to keep
  critical sections free of syscalls, which is the property sharding
  preserves.
- **Thousands of namespaces and rules** are the cheapest axis: the
  immutable-snapshot rule table rebuilds at O(rules) per mutation
  and resolves per-component; both survive three orders of magnitude.
  (Amended 2026-08-15: pattern-overlap validation adds a term
  quadratic in the patterns at one directory level and in match
  length, per mutation and per load — operator-bounded, and a v2
  scale concern only if per-level pattern populations grow far past
  anything the v1 use cases name.)
- **The FUSE data path is the client-side ceiling** (~GB/s per
  mount). (Amended 2026-08-15 on the bottleneck question: the v2
  client answer is a **kernel module** for the built-image VM case —
  where the whole image is built anyway — while FUSE remains the
  userspace-mount client, io_uring moves to v3, and zero-copy server
  paths plus the metadata-via-FUSE / data-via-direct-transport split
  remain v2 axes.)
- **auth: none does not survive multi-tenancy at scale** —
  authentication is part of v2 design scope, moving from the hardening
  tail to a v2 prerequisite, with vsock for the co-located case. For
  all of v1 the normative state is `auth = "none"` with the transport
  as the trust model, exactly as THREAT-MODEL.md states it.

The design law above all for the kernel work (decided 2026-08-17;
refined the same day): everything is designed robustly from the
start — a hazard is fixed through architecture, never through
imperative code layered on top, and a shape that accumulates guards
is reconsidered instead of patched, whatever better shape that
means: graph-based, event driven, asynchronous, actor-shaped, or
something else entirely. The refinement binds every increment, not
only the kernel: **when a change needs a bolt-on, stop and change
the architecture instead** — hours of refactoring so the new work
slots into the hollow lattice beat any guard or special case. Keep
the branches small and few; where a conditional grows, replace it
with indirection, abstraction, or structure that makes the case
impossible instead of handled.

Kernel-client preparations (decided 2026-08-17, research and
feasibility probes only — module development starts when v1 is fully
done): the client should ideally be **a real filesystem in the
kernel**, writing the missing Rust VFS layer on what the kernel
already provides where needed; its file-data path is the v2
shared-memory window, not the userspace network-fs caching library;
the kernel version policy is **chase newest** (whatever nixpkgs
unstable carries, re-validated per bump — the running dev kernel is
already built with Rust support); upstreaming is not pursued now but
nothing may foreclose it; the module lives in this repository under
a kernel/ directory with GPL-2.0 licensing (forced by the kernel's
Rust runtime exports regardless of preference, compatible with the
recorded license split); testing runs in dedicated KVM guests, and
loading probe modules on the development machine is sanctioned.
Compile-level feasibility is proven: the wire crate builds unmodified
as a kernel crate, and kernel-owned vsock is reachable through plain
exported symbols.

Sequencing (amended 2026-08-15): **v2 does not start until it is
opened deliberately** — no v2 research, design or code before then
(amended 2026-08-17: the kernel-client preparations above are the
deliberate, bounded exception; everything else stays gated).
Until then the work is v1: the field-defect and post-v1 increments
(descriptor budget, subscription, direct-io, xattr/mknod, hardening
tail) land on v1 foundations, each built not to foreclose the v2
shape. When v2 opens, it begins with a dedicated
architecture research and design phase producing its own authority
document — measured bottleneck attribution first, no code before the
design settles.

## Roadmap

1. ~~Scaffold: workspace, flake, this document.~~
2. `voidport-proto`: framing, opcodes, message structs + exhaustive
   round-trip tests.
3. Rule engine in `voidportd`: rule table, resolution algorithm, ownership
   mapping — pure logic, heavy unit tests.
4. State file load/persist + control plane + `voidport-ctl`.
5. Data plane server: sessions, handle table, host I/O passthrough.
6. FUSE client + end-to-end tests (mount, ls, read/write, xattrs, policy
   enforcement, hidden invisibility).
7. Hardening: concurrency stress, io_uring exploration, invalidation
   protocol, auth modes, kernel-client conversation. Scope notes added
   2026-08-12 from external review: AF_VSOCK support is elevated — it
   removes the guest→host network surface that TCP + `auth: none`
   otherwise leaves open (see docs/THREAT-MODEL.md); and FUSE-over-
   io_uring (kernel 6.14+) must be evaluated before any kernel-module
   work, since it may close most of the per-op overhead gap that
   motivates one (gate retired 2026-08-17 as overtaken: the kernel
   client is decided v2 direction on its own merits, the round-trip
   attribution shows the dominant cost is scheduling that a ring only
   partly addresses, and the userspace FUSE library's ring support is
   unestablished — the evaluation would gate nothing that is still
   open). Added 2026-08-13 from the increment-6 spec review: a
   wire `FileLock` lock-namespace (lk_flags) field, prerequisite for
   routing guest flock(2) to the server without conflating it with
   record locks (also blocked on fuser exposing lk_flags). Added
   2026-08-13 from the increment-6 build review: signal handling for the
   foreground `voidport mount` (SIGINT/SIGTERM currently terminate the
   process without the required teardown, leaving the mountpoint to
   `voidport umount`), FUSE INTERRUPT handling (a signal-interrupted
   setlkw leaves the wire request parked), and an unmount UX decision
   for the transient EBUSY that follows closely-spaced file closes
   (FUSE RELEASE completes asynchronously). Added 2026-08-13: an
   operator TUI on top of the existing control protocol —
   `voidport-ctl` remains the scripting surface; a TUI would sit beside
   it, not replace it. Runtime listener add/remove would pair well with
   it (listeners are startup-only in v1). Added 2026-08-14 (refined by
   a decision the same day): a **per-namespace xattr
   policy** — glob rules allowing or denying xattr names for read and
   write, living beside ownership/permission/auth in the namespace
   (never a server global), defaulting to read-allowed and
   write-denied outside `user.*`. The earlier "host security policy"
   rationale for blanket EOPNOTSUPP is retracted: an unprivileged
   server is already bounded by its own OS credentials, so passthrough
   grants the guest nothing the server's user lacks — the deny-write
   default earns its keep only for a privileged server. Per-file
   SELinux labels are the driving use case. Also: **mknod support** —
   FIFOs and unix sockets are unprivileged host objects and cleanly
   supportable (wire node kinds + creation). Opening a FIFO through
   the proxy waits **asynchronously**: O_NONBLOCK opens that never
   block a thread, the POSIX rendezvous emulated by async retry —
   decided 2026-08-14 with the principle it instances: **waits are async
   waits; a blocking-pool thread is never parked indefinitely** (an
   async wait costs bytes and a million of them are cheap, which is the
   scale the design targets; a parked pool thread is a scarce OS thread
   and a few hundred would starve every session's host I/O). Corollary
   recorded the same day: blocking SETLKW parks a pool thread today —
   tolerated under the old bounded caps, a pool-starvation hole under
   unbounded ones — and owes the same async-retry rework, hardening
   scope, before or with the mknod work. Device nodes require a
   privileged server and stay deny-by-default opt-in if ever done
   (they are also the overlayfs-whiteout prerequisite);
   overlayfs-upper enablers and the loop-mounted-image smoke test as
   previously recorded. Added 2026-08-14 (robustness mandate, recorded
   under "Settled decisions"): **the torture harness** — a long-running
   load generator driving every operation class concurrently in every
   shape (parallel tree walks, listing storms, create/delete churn,
   lock storms including stacked blocking waits, append storms, xattr
   churn, rename/unlink-while-open, mount/unmount cycling,
   multi-mount contention; server restarts under full load once the
   resilience contract lands; special-file creation churn once mknod
   lands — amended 2026-08-15: "FIFO rendezvous storms" retracted,
   rendezvous is guest-kernel-local and never reaches the server, so
   mknod churn is what the wire can be stormed with), run for hours
   with invariants asserted throughout:
   throughput sags but never collapses, per-class latency stays under
   a stated ceiling outside break-away windows, no deadlock, no
   descriptor or node or memory leak (bounded relative to working
   set), and a clean shutdown at the end. Degrading by consuming
   resources is conformant; refusing, stalling or wedging is a defect.
   The AOSP build and these development VMs are the reference
   workloads.
