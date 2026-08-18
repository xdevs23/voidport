# voidport

A policy-composed network filesystem for sharing host files with virtual
machines.

The core inversion versus virtiofs, 9p and NFS: **you don't export a
directory, you compose a namespace.** A namespace starts completely empty —
zero resolvable paths — and the operator attaches host directories to it at
runtime, each with its own share mode. What a guest sees is a projection
that never existed on the host as a directory tree, governed by rules that
can change while the guest is mounted.

- **Share modes per path**: `rw`, `ro`, or `hidden` — hidden means the path
  does not exist for the guest: no directory entry, no stat, no error that
  reveals it. Deny by default: what no rule names does not resolve.
- **Ownership mapping per namespace**: present host ids as-is
  (`passthrough`), as one fixed owner (`static`), or through an explicit
  bidirectional table (`map`) with a configurable policy for unmapped ids
  (squash / hide / passthrough). Mapping applies in reverse to files the
  guest creates.
- **Enforcement is server-side.** The permission bits a guest sees are
  presentation; every operation is checked against the live rules on the
  server, so a guest kernel cannot talk its way past a read-only rule.
- **Live reconfiguration**: rules, ownership and modes change through a
  control socket while guests stay mounted; changes bind at the next
  lookup or open, without remounting.
- **Guests can listen**: `voidport subscribe` prints what a namespace shares
  and keeps printing as it changes, so a VM can mount and unmount
  directories the moment the operator adds or removes them.

Current state: v1 is working — server, FUSE client, operator CLI, and an
end-to-end suite that exercises all of the above on real mounts. Transports
served today: TCP, unix sockets and vsock (`voidport+vsock://cid:port/@ns`,
the one that gives a VM guest no network surface at all). Not yet built, by
design order: authentication (`auth = "none"` in v1 — the trust model is the
transport, see `docs/THREAT-MODEL.md`) and cache-invalidation push.

## The pieces

| Binary | Role |
|---|---|
| `voidportd` | The server. Owns a TOML state file, serves the data plane to guests and a control socket to the operator. |
| `voidport` | The guest client: `voidport mount <url> <mountpoint>` (FUSE), and `voidport subscribe <url>` to follow what the namespace shares. |
| `voidport-ctl` | The operator CLI, speaking to the running server's control socket. |

Each ships a manual page — `man voidportd`, `man voidport`, `man voidport-ctl`,
one per subcommand besides — generated from the same command-line definition
the binary parses with, so `--help` and `man` cannot disagree. The flake
installs them into `share/man/man1`.

## Quickstart

Build (the flake carries the whole toolchain):

```console
$ nix develop -c cargo build --release
```

Share a directory. There is no default bind, so name at least one listener:

```console
$ voidportd share /srv/shared/project --addr 0.0.0.0:9000
namespace "share" is being served.

Mount it from the guest:
    voidport mount voidport://0.0.0.0:9000/@share /mnt/share

Reconfigure it from this machine:
    voidport-ctl --socket /home/you/.local/state/voidport/control.sock info

Note: auth is "none" — anything that can reach the tcp listener can mount
this namespace. See docs/THREAT-MODEL.md.
```

Then run the line it printed, from the guest, with the address the guest can
actually reach (the server prints a `0.0.0.0` bind verbatim — which of the
machine's addresses works is a fact about your network) and whatever
mountpoint you want:

```console
$ voidport mount voidport://10.0.2.2:9000/@share /mnt/share
$ ls /mnt/share              # srv/
$ ls /mnt/share/srv/shared   # project/
$ ls /mnt/share/srv/shared/project
README.md  src/
```

The share is attached at **its own absolute host path**, so the guest sees the
hierarchy the directory has on the host — `/srv/shared/project` appears at
`/mnt/share/srv/shared/project`. The directories above it are synthesized by
the server (nothing of `/srv` itself is exposed), and sharing a second
directory adds it at *its* host path, so two shares compose instead of
colliding on a basename.

That is the whole flow. `share` is not a separate mode: it seeds an ordinary
state file — `$XDG_STATE_HOME/voidport/state.toml` unless `--state` says
otherwise, created if missing — and then serves it like any other launch, so
the share survives a restart and is reconfigurable through `voidport-ctl`
below. Repeating the same command changes nothing; one that would give an
existing namespace or rule different content refuses to start instead of
overwriting what you wrote.

Its other flags: `--unix PATH` (serve on a unix socket) and `--vsock PORT`
(serve on a vsock port, which only this machine's VM guests can reach), both
instead of or beside `--addr` and all three repeatable; `--ro` (share
read-only), `--name NAME` (the namespace, default `share`), `--state PATH`,
and `--control-socket PATH`,
which wins over whatever the state file names. A `share` launch that names no
socket, against a state file that carries none, seeds `control.sock` beside
that state file and prints the `voidport-ctl` line for it, as above — so quick
sharing never needs the root-owned `/run/voidport/control.sock` a plain launch
falls back to.

### Full configuration

The state file is the whole configuration, and a plain launch serves it. A
minimal `state.toml`:

```toml
[server]
control_socket = "/run/voidport/control.sock"

[[server.listeners]]
transport = "tcp"
addr = "0.0.0.0:9000"

[[namespaces]]
name = "project"
permission = "passthrough"
auth = "none"

[namespaces.ownership]
mode = "passthrough"

# Attach a host directory to the namespace, read-write. Rules live below
# the root ("/" itself is not a rule path). Relative targets resolve
# against this file's directory.
[[namespaces.rules]]
path = "/src"
mode = "rw"
target = "/srv/shared/project"
```

`docs/state.example.toml` is the fully commented version of this file —
listeners, resource limits, ownership maps, wildcard, pattern and hidden
rules.

Start the server (it owns the file from here on — control-plane changes are
persisted back into it; a file that does not exist yet is created empty, one
that exists and does not parse refuses startup):

```console
$ voidportd --state state.toml
$ voidport mount voidport://10.0.2.2:9000/@project /mnt/project
$ ls /mnt/project        # shows src/
```

A server with no listeners is legal — it serves only its control socket, and
listeners are added while it runs:

```console
$ voidport-ctl listener add --addr 0.0.0.0:9000
listening on tcp 0.0.0.0:9000
$ voidport-ctl listener list
tcp 0.0.0.0:9000
$ voidport-ctl listener remove 0.0.0.0:9000
```

Both are persisted to the state file, so a restart serves what the last command
left. Removing a listener stops new connections landing on it; mounts already
made through it keep serving until they end on their own.

### Mounting

The URL names the namespace after `@`, and may go deeper:
`voidport://host:port/@project/src` mounts that subtree directly. Over a unix socket
the socket path is the (percent-encoded) authority:
`voidport+unix://%2Frun%2Fvoidport%2Fdata.sock/@project`. Over vsock the
authority is `cid:port` — `voidport+vsock://2:1024/@project` — where 2 is the
cid a guest reaches its host at by the vsock convention. The port is always
explicit; there is no default.

Useful mount flags: `--read-only` (kernel-level, on top of server modes),
`--allow-other`, `--attr-timeout` / `--entry-timeout` (seconds, default 1 —
the staleness bound between mounts), `--dispatch-threads` (default 1, which
measures best; see `docs/PERFORMANCE.md`). Unmount with
`voidport umount /mnt/project`.

`--direct-io` (off by default) keeps no copy of file data in the guest page
cache, so N guests reading one host file stop holding N copies of it. `mmap`
keeps working — exec-from-mount and SQLite's WAL are unaffected, the kernel
caches pages only for ranges a process actually mapped — and metadata caching
is untouched, so the `--attr-timeout` win over 9p stands. The cost is that
unmapped re-reads run at wire speed instead of RAM speed — which in practice
means: free for small-file workloads like grepping a source tree (round trips
dominate either way), ~50x on bulk re-reads of the same data (where the cached
mode is native-parity), with metadata staying fast in both modes. Pick
`--direct-io` for large working sets that out-read what a guest could cache;
keep the default for small hot trees. The numbers are in
`docs/PERFORMANCE.md`. It needs a guest kernel of 6.7 or newer; on anything
older the mount logs a notice and keeps caching normally instead of giving up
`mmap`.

`--readahead` (MiB, default 256) is what pays most of that bulk-read cost
back. A direct mount has no guest page cache and therefore no kernel readahead
in front of it, so every read is a round trip the reader waits out; with the
flag on, a mount that notices a sequential reader fetches the bytes in front of
it in 128 KiB chunks and answers out of its own pool. What that buys
depends on what the reader was waiting for. Where the round trip dominates —
the case the mode exists for — it is 3.1–3.4x on both transports, ~250 to
~860 MiB/s. On a rig whose server reads out of RAM the wire itself becomes the
limit: 1.28 to 2.57 GB/s over a unix socket (2.0x), and 0.95 to 1.72 GB/s over
vsock, which is 1.79x of the 1.95x that transport's own measured ceiling
leaves available. The numbers, and the ceiling probe behind that last
sentence, are in `docs/PERFORMANCE.md`. The flag's value is a **ceiling for
the whole mount, not an
allocation**: an idle mount holds nothing, the pool fills only under sequential
load, and random access is untouched. Prefetched bytes are as fresh as
`--attr-timeout` allows and no staler — a block older than that is refetched,
not served, a local write or truncate drops the file's blocks at once,
and a reconnect drops the pool entirely. `--readahead 0` turns the engine off
and restores strictly wire-immediate reads. It does nothing without
`--direct-io`: a page-cached mount is already served by the guest kernel's own
readahead.

`--write-stream` (KiB, default 256, measured; 0 = off) sizes the
write-streaming engine: a write larger than the chunk unit is cut into chunks
that fly concurrently under a bounded window, and the syscall still returns
only when every chunk is answered — durability, barriers and error delivery
are exactly the serial path's. What it buys is overlap: while the server
applies one chunk the next is already in transfer, which measured 7–31%
faster sequential writes at native latency across the three transports, and
exactly even with the serial path everywhere else — under injected latency,
and on writes of one chunk or less. `--write-stream 0` keeps the serial write
path byte for byte, and `--write-stream-per-handle` /
`--write-stream-per-mount` size the window (defaults 8 and 32, also
measured). It does nothing without `--direct-io`. The matrix behind the
numbers is recorded in `docs/WRITESTREAM.md`.

### Following what a namespace shares

A guest that wants to mount directories as the operator adds them cannot work
it out by looking: the projected tree mixes synthesized parents with shared
subtrees, and nothing in it marks where a shared directory begins.
`voidport subscribe` says so explicitly, one JSON object per line:

```console
$ voidport subscribe voidport://10.0.2.2:9000/@project
{"entries":[{"kind":"directory","mode":"rw","path":"/src"}],"event":"snapshot","v":1}
{"event":"added","kind":"directory","mode":"ro","path":"/docs","v":1}
{"event":"removed","path":"/docs","v":1}
```

It rides the data plane — the same connection a mount uses, no control socket
in the guest — and it is **level-triggered**: every subscription opens with a
full `snapshot`, and a reconnect brackets the outage with `disconnected` /
`resumed` and then re-sends one. A consumer therefore reconciles instead of
replaying, and needs to remember nothing across a restart of either side. The
events are `snapshot`, `added`, `changed`, `removed`, `lapsed` (the server
forced a resync; the snapshot after it replaces everything), `disconnected`,
`resumed` and `ended`; every line carries `"v": 1`. Modes are `rw` / `ro`,
kinds are `directory` / `file` / `unknown` — the server reports a kind only
where it already knows one without touching the host, and `unknown` means
try-and-see.

Anything the namespace hides never appears, in a snapshot or in an event: the
stream passes the same visibility the session's own lookups do.

`docs/examples/mount-manager.sh` is a worked consumer: it keeps a directory of
mountpoints in step with the stream, mounting what appears and unmounting what
goes away.

```console
$ docs/examples/mount-manager.sh voidport://10.0.2.2:9000/@project /mnt/project
```

`voidport-ctl session list` reports which sessions are subscribed, so a
consumer that keeps lapsing is visible from the operator's side.

### When the server breaks away

A mount survives its server. If the connection dies, requests **stall** for
`--reconnect-stall` seconds (default 5) while the client re-handshakes in the
background; if the server is back inside that window, work carries on with
nothing surfaced to the application. Past it, requests fail with an I/O error
*immediately* — no request waits a second time — and the mount resumes the
moment the server answers again, with no remount. `--reconnect-stall 0` fails
fast instead.

Identifiers do not survive the gap, and are not meant to: the server's node and
handle ids are disjoint across restarts, so a path rebuilds itself on first use
while a descriptor held open across the gap reports the loss until the
application reopens it — as if the tree had been replaced underneath, which it
was.

`SIGINT` and `SIGTERM` unmount the mountpoint on the way out. For a `SIGKILL`
there is nothing the client can run, so the kernel's `auto_unmount` is used
where the platform allows it (it needs the `fusermount3` helper and
`--allow-other`; the mount logs which way it went, and `--no-auto-unmount` opts
out) — and where it does not, `voidport umount` recovers the mountpoint.

### Reconfiguring

Rules, ownership and modes change while guests stay mounted:

```console
$ voidport-ctl namespace list
$ voidport-ctl rule add project /docs --mode ro --target /srv/shared/docs
$ voidport-ctl rule add project /secrets --mode hidden
$ voidport-ctl rule remove project /docs
$ voidport-ctl xattr add project 'user.*' --write deny
$ voidport-ctl xattr list project
$ voidport-ctl session list
```

`voidport-ctl` groups its operations as `namespace`, `rule`, `xattr`,
`ownership`, `permission`, `direct-io`, `auth`, `session`, and `info`; every
subcommand has `--help`, and `--json` prints the raw response envelope.

**Finding the server takes no flags.** Without `--socket`, `voidport-ctl` tries
`$XDG_STATE_HOME/voidport/control.sock` — the socket a `voidportd share` launch
seeds beside its state file, `~/.local/state/voidport/control.sock` when the
variable is unset — and then `/run/voidport/control.sock`, and talks to the
first one a server answers on; if neither does, the error names both paths.
`--socket PATH` overrides the search entirely. `voidportd --tui`, attaching to
a running server, looks in exactly the same order and `--control-socket PATH`
overrides it the same way.

Anything that can reach the control socket can reconfigure every namespace,
so keep it in a private directory — it is created owner-only (0600).

## Semantics to know before relying on it

- **Most specific rule wins**, order-independent: a literal path beats a
  `match` pattern over child names, which beats a single-level `*` wildcard,
  which beats what the enclosing directory rule implies.
  A rule change behaves like a chmod: existing open handles keep working,
  new opens see the new rule.
- **A family of directories is one rule**: a rule with a `match` governs the
  children of its directory whose names the glob covers
  (`voidport-ctl rule add ns /path --match 'project-*' --mode rw`). `*` matches
  any run of bytes, including none; a leading `*` never covers a name starting
  with `.`, as in a shell. Matching is live, so a directory created on the host
  afterwards is shared at its next lookup, and a guest `mkdir` of a matching
  name lands on the host durably. Two patterns on one directory may not both
  cover a name — that is refused when the rule is added, naming both rules.
- **The host page cache is the one cache, unless a namespace says
  otherwise**: a mount's `--direct-io` is guest-side — it exists so the
  guest holds no second copy of the data, and the server's own reads and
  writes ride the host's cache as any local program's would. Where that
  is not wanted, `direct_io` is a per-namespace setting with three
  postures: `cached` (the default, which masks a guest handle's own
  `O_DIRECT`), `passthrough` — a guest handle opened `O_DIRECT` opens the
  backing file `O_DIRECT` — and `always`, every backing open uncached.
  Under the two uncached postures the server serves through buffers
  aligned to what the backing file demands, so an aligned request
  round-trips its data; a request the backing filesystem itself calls
  misaligned answers the errno it gives locally, and under `always` the
  storage, not the wire, may be what bounds throughput. Changing the
  posture (`voidport-ctl direct-io set ns --posture passthrough`) is
  live at the next open, like a rule change.
- **Coherence**: writethrough caching with short TTLs (default 1 s). A
  writer's change is visible to other mounts within the TTL, including
  through already-open descriptors; fcntl record locks conflict correctly
  across mounts. flock stays local to each mount in v1.
- **Ownership is passed through by default**: files show their host
  uids and gids as-is, including ids that mean nothing in the guest
  (container subuids, `nobody`-owned data directories). A `700`
  directory owned by a foreign uid is exactly as opaque through the
  share as it is on the host, and root in the guest reaches at most
  what the server's host user reaches — a denial can therefore look
  implausible from inside the guest while being the host kernel's
  honest answer. The `static` and `map` ownership modes (including
  squashing unmapped ids) are opt-in per namespace.
- **setuid and setgid work, and the host backing never carries them**: a guest
  chmod that sets one is recorded by the server and merged into what every
  mount of that namespace is shown, on every file kind and through every name
  of a hard link; it survives a server restart, and it strips exactly as local
  semantics demand — a write by a caller without the file-mode privilege clears
  setuid, and clears setgid where group-execute is set. The host file the
  namespace grafts is never given a privileged bit the server's own user set,
  on a chmod or on a create. Enforcement of what the bits mean is the guest
  kernel's, in its own trust domain. Two switches turn it off: per namespace on
  the server (`voidport-ctl privileged-bits disable ns`, which masks the bits
  and refuses a chmod that would set one) and per mount on the guest
  (`voidport mount … --no-privileged-bits`, which is stronger than the classic
  `nosuid` — that honors nothing but still shows the bits, this shows nothing).
  Opting one mount out never destroys what the server recorded for the others.
- **POSIX continuity through the proxy**: rename-while-open,
  unlink-while-open, hardlink identity and symlinks behave as they would
  locally; symlinks resolve in the guest's namespace, never on the host.
- **Extended attributes are rule-governed, per namespace**: with no rules a
  guest reads every attribute and writes only `user.*`, exactly as a local
  filesystem behaves. Globs over attribute names change that
  (`voidport-ctl xattr add ns 'user.*' --write deny`); among the rules covering
  a name the longest literal prefix wins and a tie goes to deny, and a verdict
  a rule leaves out falls through to the next match. A denied read is *hidden*
  — absent from the listing, `ENODATA` on a get — and a denied write answers
  `EPERM` without touching the host. Two things no rule can change: a
  read-only share answers `EROFS` first, and a write to
  `system.posix_acl_access`/`_default` is always refused, because a valid ACL
  blob rewrites a file's permission bits behind the namespace's back.
  Everything is bounded by the server's own host user — `security.*` and
  `trusted.*` writes need privileges an ordinary server does not have, so an
  allow rule there passes the kernel's own refusal back instead of granting
  anything.
- **FIFOs and socket files are guest-local**: `mkfifo` and socket `mknod` make
  real host inodes (device nodes are refused), but the host inode is only a
  marker. Pipe data lives in the kernel that opened the FIFO and `AF_UNIX`
  connections resolve in the connecting process's kernel, so rendezvous and
  data flow work between processes of **one** guest and nothing crosses to
  another guest or to a host-side peer — two mounts of one host FIFO are two
  independent pipes, and a writer on one never meets a reader on the other.
- **Shared mmap works within one mount** — which means SQLite in WAL
  mode runs on the share (its `-shm` coordination file needs
  `MAP_SHARED`, the classic network-filesystem failure that 9p and NFS
  hit): all processes on one guest share one kernel page cache, so the
  coordination is local while the data writes through. Do not share one
  WAL database across two mounts — the mapping cannot coordinate across
  kernels. Appends are atomic at the host, so two mounts appending to
  one log interleave without loss — something offset-based protocols
  cannot promise.
- The full contracts — wire protocol, resolution algorithm, node
  lifecycle, resource limits — live in `docs/DESIGN.md`, which is the
  authority the implementation is reviewed against.

## Documentation map

| Document | Contents |
|---|---|
| `docs/DESIGN.md` | The design authority: architecture, wire contract, rule engine, data plane, FUSE client contract, acceptance criteria, decision log. |
| `docs/state.example.toml` | Commented example configuration. |
| `docs/examples/mount-manager.sh` | A mount manager driven by `voidport subscribe`: mounts and unmounts as the namespace changes. |
| `docs/THREAT-MODEL.md` | Trust boundaries and what v1's `auth = none` does and does not defend. |
| `docs/PERFORMANCE.md` | Measured numbers: per-op costs, comparison against tmpfs and 9p, dispatch configuration. |
| `docs/IO_URING.md` | The FUSE-over-io_uring evaluation and why ring adoption is deferred. |

## Development

```console
$ ./check    # fmt + clippy -D warnings + full workspace test suite
```

The end-to-end suite mounts real FUSE filesystems and needs `/dev/fuse`;
where a preflight shows FUSE is unusable the e2e cases skip, and where it
is usable a skip is treated as a failure, so CI cannot silently lose the
suite. `voidport-bench` is the benchmark harness behind the performance
report.

`voidport-torture` is the other harness: a load generator that drives
every operation class at once — tree walks, listing storms, create/delete
churn, lock storms, append storms, xattr churn, rename and unlink while open,
open/close storms, mount/unmount cycling, multi-mount contention — over real
mounts for as long as it is given, asserting throughout that throughput never
collapses, that no class stalls, that the server's descriptors, threads, nodes
and memory stay bounded, and that the shutdown leaves nothing behind. Its
smoke variant runs in the suite; a soak is

```console
$ voidport-torture --url voidport://127.0.0.1:9000/@share/srv/data \
    --work-dir /var/tmp/torture --duration 3600 --intensity 4
```

## License

Per component, chosen by role (full texts in `LICENSES/`):

| Component | License |
|---|---|
| `voidportd` (the server) | AGPL-3.0-only |
| `voidport`, `voidport-ctl`, `voidport-control`, `voidport-tui`, `voidport-bench`, `voidport-torture`, `voidport-pty` | GPL-3.0-only |
| `voidport-proto` (wire format) | MIT |
| `voidport-session` (session core) | MIT |
| `kernel/probe` (the kernel module) | GPL-2.0-only |

The server carries the AGPL because its value is delivered over a network;
the tools carry the GPL; the wire-format crate is MIT so any client —
the kernel module included — can speak the protocol without license
friction. The session core is MIT for the same reason and by the same
necessity: both clients consume it, and a GPL-2.0-only module cannot link
a GPL-3.0-only crate. The module's own license is not a choice: the kernel's Rust
runtime exports it is built on are GPL-2.0-only, and a GPL-2.0-only module
is what may use them.
